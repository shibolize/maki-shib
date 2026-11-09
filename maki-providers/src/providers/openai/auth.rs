use std::time::Duration;
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use isahc::ReadResponseExt;
use isahc::config::{Configurable, VersionNegotiation};
use maki_storage::StateDir;
use maki_storage::auth::{OAuthTokens, delete_tokens, load_tokens, now_millis, save_tokens};
use serde::Deserialize;
use tracing::{debug, error, warn};

use crate::AgentError;
use crate::providers::oauth_loopback::{self, LoginMethod, Loopback};
use crate::providers::{KeyPool, ResolvedAuth, refreshed_tokens, urlenc};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const PROVIDER: &str = super::SLUG;
const DISPLAY_NAME: &str = "OpenAI";
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const DEVICE_CODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const DEVICE_AUTH_URL: &str = "https://auth.openai.com/codex/device";
const DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
// Registered on the OpenAI client, so the port is not ours to choose.
const REDIRECT_PORT: u16 = 1455;
const REDIRECT_PATH: &str = "/auth/callback";
const SCOPE: &str = "openid profile email offline_access";
const POLL_SAFETY_MARGIN: Duration = Duration::from_secs(3);
const TOKEN_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_auth_id: String,
    user_code: String,
    interval: String,
}

#[derive(Deserialize)]
struct DeviceTokenResponse {
    authorization_code: String,
    code_verifier: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    expires_in: Option<u64>,
}

fn http_client(timeout: Duration) -> Result<isahc::HttpClient, AgentError> {
    isahc::HttpClient::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        // curl carries http2 for OTLP.
        .version_negotiation(VersionNegotiation::http11())
        .build()
        .map_err(|e| AgentError::Config {
            message: format!("http client: {e}"),
        })
}

fn extract_account_id(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;

    claims
        .get("chatgpt_account_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            claims
                .pointer("/https:~1~1api.openai.com~1auth/chatgpt_account_id")
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            claims
                .get("organizations")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|org| org.get("id"))
                .and_then(|v| v.as_str())
        })
        .map(String::from)
}

fn extract_account_id_from_tokens(resp: &TokenResponse) -> Option<String> {
    if let Some(id_token) = &resp.id_token
        && let Some(id) = extract_account_id(id_token)
    {
        return Some(id);
    }
    extract_account_id(&resp.access_token)
}

fn request_device_code() -> Result<DeviceCodeResponse, AgentError> {
    let client = http_client(TOKEN_EXCHANGE_TIMEOUT)?;
    let body = serde_json::json!({"client_id": CLIENT_ID});
    let json_body = serde_json::to_vec(&body)?;

    let request = isahc::Request::builder()
        .method("POST")
        .uri(DEVICE_CODE_URL)
        .header("content-type", "application/json")
        .body(json_body)?;

    let mut resp = client.send(request).map_err(|e| AgentError::Config {
        message: format!("device code request: {e}"),
    })?;

    if resp.status().as_u16() != 200 {
        let body_text = resp.text().unwrap_or_else(|_| "unknown error".into());
        return Err(AgentError::Config {
            message: format!("device code request failed: {body_text}"),
        });
    }

    let body_text = resp.text()?;
    serde_json::from_str(&body_text).map_err(Into::into)
}

fn poll_device_token(device: &DeviceCodeResponse) -> Result<DeviceTokenResponse, AgentError> {
    let client = http_client(POLL_TIMEOUT)?;
    let interval_secs = device.interval.parse::<u64>().unwrap_or(5).max(1);
    let poll_interval = Duration::from_secs(interval_secs) + POLL_SAFETY_MARGIN;
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;

    let body = serde_json::json!({
        "device_auth_id": device.device_auth_id,
        "user_code": device.user_code,
    });
    let json_body = serde_json::to_vec(&body)?;

    loop {
        if std::time::Instant::now() > deadline {
            return Err(AgentError::Config {
                message: "device authorization timed out".into(),
            });
        }

        thread::sleep(poll_interval);

        let request = isahc::Request::builder()
            .method("POST")
            .uri(DEVICE_TOKEN_URL)
            .header("content-type", "application/json")
            .body(json_body.clone())?;

        let mut resp = client.send(request).map_err(|e| AgentError::Config {
            message: format!("device token poll: {e}"),
        })?;

        if resp.status().as_u16() == 200 {
            let body_text = resp.text()?;
            return serde_json::from_str(&body_text).map_err(Into::into);
        }

        let status = resp.status().as_u16();
        if status != 403 && status != 404 {
            let body_text = resp.text().unwrap_or_else(|_| "unknown error".into());
            return Err(AgentError::Config {
                message: format!("device token poll failed ({status}): {body_text}"),
            });
        }
    }
}

fn exchange_authorization_code(
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, AgentError> {
    let client = http_client(TOKEN_EXCHANGE_TIMEOUT)?;

    let form_body = format!(
        "grant_type=authorization_code\
         &code={}\
         &redirect_uri={}\
         &client_id={}\
         &code_verifier={}",
        urlenc(code),
        urlenc(redirect_uri),
        urlenc(CLIENT_ID),
        urlenc(verifier),
    );

    let request = isahc::Request::builder()
        .method("POST")
        .uri(OAUTH_TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body.into_bytes())?;

    let mut resp = client.send(request).map_err(|e| AgentError::Config {
        message: format!("token exchange: {e}"),
    })?;

    if resp.status().as_u16() != 200 {
        let body_text = resp.text().unwrap_or_else(|_| "unknown error".into());
        return Err(AgentError::Config {
            message: format!("token exchange failed: {body_text}"),
        });
    }

    let body_text = resp.text()?;
    serde_json::from_str(&body_text).map_err(Into::into)
}

fn redirect_uri() -> String {
    format!("http://localhost:{REDIRECT_PORT}{REDIRECT_PATH}")
}

fn authorization_url(redirect_uri: &str, challenge: &str, state: &str) -> String {
    format!(
        "{AUTHORIZE_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}&id_token_add_organizations=true&codex_cli_simplified_flow=true&originator=maki",
        urlenc(CLIENT_ID),
        urlenc(redirect_uri),
        urlenc(SCOPE),
        urlenc(challenge),
        urlenc(state),
    )
}

fn into_oauth_tokens(
    resp: TokenResponse,
    fallback_refresh: Option<String>,
    fallback_account_id: Option<String>,
) -> Result<OAuthTokens, AgentError> {
    let account_id = extract_account_id_from_tokens(&resp).or(fallback_account_id);
    let refresh = resp
        .refresh_token
        .filter(|s| !s.is_empty())
        .or(fallback_refresh)
        .ok_or_else(|| AgentError::Config {
            message: "OpenAI token response did not include a refresh token".into(),
        })?;
    let expires = now_millis() + resp.expires_in.unwrap_or(3600) * 1000;
    Ok(OAuthTokens {
        access: resp.access_token,
        refresh,
        expires,
        account_id,
    })
}

pub(crate) fn refresh_tokens(tokens: &OAuthTokens) -> Result<OAuthTokens, AgentError> {
    let expired = tokens.is_expired();
    debug!(expired, "refreshing OpenAI OAuth tokens");

    let client = http_client(TOKEN_EXCHANGE_TIMEOUT)?;
    let form_body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlenc(&tokens.refresh),
        urlenc(CLIENT_ID),
    );

    let request = isahc::Request::builder()
        .method("POST")
        .uri(OAUTH_TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body.into_bytes())?;

    let mut resp = client.send(request).map_err(|e| AgentError::Config {
        message: format!("OpenAI token refresh: {e}"),
    })?;

    if resp.status().as_u16() != 200 {
        let body_text = resp.text().unwrap_or_else(|_| "unknown error".into());
        return Err(AgentError::Config {
            message: format!("OpenAI token refresh failed: {body_text}"),
        });
    }

    let body_text = resp.text()?;
    let token_resp: TokenResponse = serde_json::from_str(&body_text)?;
    into_oauth_tokens(
        token_resp,
        Some(tokens.refresh.clone()),
        tokens.account_id.clone(),
    )
}

pub(crate) const CODING_PLAN_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

pub(crate) fn build_oauth_resolved(tokens: &OAuthTokens) -> Result<ResolvedAuth, AgentError> {
    let mut headers = vec![("authorization".into(), format!("Bearer {}", tokens.access))];
    if let Some(account_id) = &tokens.account_id {
        headers.push(("chatgpt-account-id".into(), account_id.clone()));
    }
    ResolvedAuth::new(PROVIDER, headers)
}

pub(crate) fn is_oauth(dir: &StateDir) -> bool {
    load_tokens(dir, PROVIDER).is_some()
}

pub(crate) fn resolve_with_pool(dir: &StateDir) -> Result<(ResolvedAuth, KeyPool), AgentError> {
    if let Some(tokens) = load_tokens(dir, PROVIDER) {
        if !tokens.is_expired() {
            debug!("using OpenAI OAuth authentication");
            return Ok((build_oauth_resolved(&tokens)?, KeyPool::empty()));
        }
        match refreshed_tokens(dir, PROVIDER, None, refresh_tokens) {
            Ok(fresh) => {
                debug!("using OpenAI OAuth authentication (refreshed)");
                return Ok((build_oauth_resolved(&fresh)?, KeyPool::empty()));
            }
            Err(e) => {
                warn!(error = %e, "OpenAI OAuth refresh failed, clearing stale tokens");
                delete_tokens(dir, PROVIDER).ok();
            }
        }
    }

    if let Ok(pool) = KeyPool::resolve_in(PROVIDER, "OPENAI_API_KEY", Some(dir)) {
        let auth = ResolvedAuth::bearer(PROVIDER, &pool.current())?;
        return Ok((auth, pool));
    }

    Err(AgentError::Config {
        message: "not authenticated, run `maki auth login openai` or set OPENAI_API_KEY".into(),
    })
}

pub fn resolve(dir: &StateDir) -> Result<ResolvedAuth, AgentError> {
    resolve_with_pool(dir).map(|(auth, _)| auth)
}

pub fn login(dir: &StateDir) -> Result<(), AgentError> {
    let token_response = match oauth_loopback::select_login_method(DISPLAY_NAME)? {
        LoginMethod::Browser => browser_login()?,
        LoginMethod::Device => device_login()?,
    };
    let tokens = into_oauth_tokens(token_response, None, None)?;
    save_tokens(dir, PROVIDER, &tokens)?;
    println!("Authenticated successfully.");
    Ok(())
}

fn device_login() -> Result<TokenResponse, AgentError> {
    let device = request_device_code()?;
    println!("Open this URL in your browser:\n\n  {DEVICE_AUTH_URL}\n");
    println!("Enter code: {}\n", device.user_code);
    println!("Waiting for authorization...");
    let device_token = poll_device_token(&device).map_err(|e| {
        error!(error = %e, "OpenAI device authorization failed");
        e
    })?;
    exchange_authorization_code(
        &device_token.authorization_code,
        &device_token.code_verifier,
        DEVICE_REDIRECT_URI,
    )
}

fn browser_login() -> Result<TokenResponse, AgentError> {
    let (verifier, challenge) = oauth_loopback::pkce_pair()?;
    let state = oauth_loopback::random_token()?;
    let server = Loopback {
        port: REDIRECT_PORT,
        fallback_to_ephemeral: false,
        path: REDIRECT_PATH,
        timeout: CALLBACK_TIMEOUT,
        paste_fallback: false,
    }
    .bind()?;

    let redirect_uri = redirect_uri();
    let authorize_url = authorization_url(&redirect_uri, &challenge, &state);
    println!("Open this URL in your browser:\n\n  {authorize_url}\n");
    if let Err(e) = open::that(&authorize_url) {
        warn!(error = %e, "failed to open browser");
    }
    println!("Waiting for OpenAI OAuth callback on {redirect_uri}...");

    let callback = server.wait(&state).map_err(|e| {
        error!(error = %e, "OpenAI browser authorization failed");
        e
    })?;
    if let Some(error) = callback.error {
        return Err(AgentError::Config {
            message: format!("OpenAI authorization failed: {error}"),
        });
    }
    let code = callback.code.ok_or_else(|| AgentError::Config {
        message: "OpenAI authorization failed: no authorization code returned".into(),
    })?;

    exchange_authorization_code(&code, &verifier, &redirect_uri).map_err(|e| {
        error!(error = %e, "OpenAI token exchange failed");
        e
    })
}

pub fn logout(dir: &StateDir) -> Result<(), AgentError> {
    if delete_tokens(dir, PROVIDER)? {
        println!("Logged out of OpenAI.");
    } else {
        println!("Not currently logged in to OpenAI.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    const MISSING_REFRESH_ERROR: &str = "OpenAI token response did not include a refresh token";

    #[test]
    fn extract_account_id_from_jwt() {
        let header = URL_SAFE_NO_PAD.encode(b"{}");
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"chatgpt_account_id": "acct_123"})
                .to_string()
                .as_bytes(),
        );
        let token = format!("{header}.{payload}.sig");
        assert_eq!(extract_account_id(&token).as_deref(), Some("acct_123"));

        assert_eq!(extract_account_id("not.a.jwt"), None);
        assert_eq!(extract_account_id("invalid"), None);
    }

    #[test]
    fn authorization_uses_the_registered_loopback_redirect() {
        let url = authorization_url(&redirect_uri(), "challenge", "state");
        assert!(url.starts_with(AUTHORIZE_URL));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"));
        assert!(url.contains("code_challenge=challenge&code_challenge_method=S256"));
        assert!(url.contains("state=state"));
        assert!(!url.contains("device"));
    }

    #[test_case(
        r#"{"access_token":"acc","refresh_token":"new-ref","expires_in":3600}"#,
        Some("old-ref"),
        Some("acct-fallback"),
        Ok(("new-ref", Some("acct-fallback")))
        ; "uses_response_refresh_and_preserves_fallback_account_id"
    )]
    #[test_case(
        r#"{"access_token":"acc","expires_in":3600}"#,
        Some("old-ref"),
        Some("acct-fallback"),
        Ok(("old-ref", Some("acct-fallback")))
        ; "omitted_refresh_falls_back_to_existing"
    )]
    #[test_case(
        r#"{"access_token":"acc","expires_in":3600}"#,
        None,
        None,
        Err(MISSING_REFRESH_ERROR)
        ; "missing_refresh_without_fallback_errors"
    )]
    fn into_oauth_tokens_handles_optional_refresh_and_account_id(
        json: &str,
        fallback_refresh: Option<&str>,
        fallback_account: Option<&str>,
        expected: Result<(&str, Option<&str>), &str>,
    ) {
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        let result = into_oauth_tokens(
            resp,
            fallback_refresh.map(String::from),
            fallback_account.map(String::from),
        );
        match (result, expected) {
            (Ok(tokens), Ok((exp_ref, exp_acct))) => {
                assert_eq!(tokens.refresh, exp_ref);
                assert_eq!(tokens.account_id.as_deref(), exp_acct);
            }
            (Err(err), Err(exp_err)) => assert_eq!(err.to_string(), exp_err),
            (got, exp) => panic!("mismatch: got={got:?}, expected={exp:?}"),
        }
    }
}
