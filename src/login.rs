//! `postil login` / `postil logout`: device-authorization flow against the
//! Postil web app, modelled on RFC 8628. Chosen because the CLI runs over
//! SSH and in containers where no localhost browser callback is reachable.
//!
//! A successful login writes a credential that `resolve_stored_token` uses
//! when no explicit key environment variable is set, so a first-time user gets
//! working hosted inference with zero configuration.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::credentials::{self, Credentials};
use crate::llm::secure_http_client;

/// Overrides the Postil web app the device-flow calls target. Distinct from
/// `POSTIL_API_BASE`, which (once a token is in hand) points at the
/// inference gateway itself, not the auth endpoints.
const LOGIN_SERVER_ENV: &str = "POSTIL_LOGIN_SERVER";
const DEFAULT_LOGIN_SERVER: &str = "https://postil.dev";

/// The server caps polling at 200 attempts and then returns 410 regardless;
/// this is only a client-side backstop against a stuck loop if that cap is
/// ever missed (a server bug, or a hostile `interval`).
const MAX_POLL_ATTEMPTS: u32 = 220;
const ACCESS_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
const REFRESH_RESPONSE_MAX_BYTES: usize = 16 * 1024;
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

fn login_server() -> String {
    std::env::var(LOGIN_SERVER_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_LOGIN_SERVER.to_string())
}

pub async fn run_login(org: Option<String>) -> Result<i32> {
    let server = login_server();
    let client = secure_http_client(&server).context("building the postil login HTTP client")?;
    let path = credentials::default_path()?;
    login_with(&client, &server, org.as_deref(), &path).await
}

pub async fn run_logout() -> Result<i32> {
    let server = login_server();
    let client = secure_http_client(&server).context("building the postil logout HTTP client")?;
    let path = credentials::default_path()?;
    logout_with(&client, &server, &path).await
}

#[derive(Debug, Deserialize)]
struct DeviceStartResponse {
    #[serde(rename = "deviceCode")]
    device_code: String,
    #[serde(rename = "userCode")]
    user_code: String,
    #[serde(rename = "verificationUri")]
    verification_uri: String,
    #[serde(rename = "verificationUriComplete")]
    verification_uri_complete: String,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenApproved {
    token: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "refreshExpiresAt")]
    refresh_expires_at: Option<String>,
    #[serde(rename = "apiBase")]
    api_base: String,
    org: DeviceTokenOrg,
    model: String,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenResponse {
    token: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "refreshExpiresAt")]
    refresh_expires_at: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenOrg {
    slug: String,
    name: String,
}

async fn login_with(
    client: &reqwest::Client,
    server: &str,
    org: Option<&str>,
    credentials_path: &Path,
) -> Result<i32> {
    let mut start_body = serde_json::json!({ "clientVersion": env!("CARGO_PKG_VERSION") });
    // The device/start contract takes no org field today; sending it as an
    // extra, ignorable JSON key is a forward-compatible hint only. Org
    // membership is actually chosen on the browser approval page, so the
    // hint below is what carries the user's `--org` intent there.
    if let Some(org) = org {
        start_body["org"] = serde_json::Value::String(org.to_string());
    }
    let start_url = format!("{}/api/cli/device/start", server.trim_end_matches('/'));
    let start_response = client
        .post(&start_url)
        .json(&start_body)
        .send()
        .await
        .context("starting postil login")?;
    anyhow::ensure!(
        start_response.status().is_success(),
        "postil login could not start (server responded {})",
        start_response.status()
    );
    let start: DeviceStartResponse = start_response
        .json()
        .await
        .context("parsing postil login start response")?;

    eprintln!("postil: open {}", start.verification_uri_complete);
    eprintln!(
        "postil:   or open {} and enter code {}",
        start.verification_uri, start.user_code
    );
    if let Some(org) = org {
        eprintln!("postil: select organization {org} when prompted");
    }
    eprintln!("postil: waiting for approval...");

    let interval = Duration::from_secs(interval_secs(start.interval));
    let token_url = format!("{}/api/cli/device/token", server.trim_end_matches('/'));
    for _ in 0..MAX_POLL_ATTEMPTS {
        tokio::time::sleep(interval).await;
        let response = client
            .post(&token_url)
            .json(&serde_json::json!({ "deviceCode": start.device_code }))
            .send()
            .await
            .context("polling postil login status")?;
        match response.status().as_u16() {
            200 => {
                let approved: DeviceTokenApproved = response
                    .json()
                    .await
                    .context("parsing postil login approval response")?;
                let DeviceTokenApproved {
                    token,
                    expires_at,
                    refresh_token,
                    refresh_expires_at,
                    api_base,
                    org,
                    model,
                } = approved;
                let renewable = match (refresh_token, refresh_expires_at) {
                    (Some(refresh_token), Some(refresh_expires_at)) => {
                        let credentials = Credentials {
                            version: credentials::CREDENTIALS_VERSION,
                            token,
                            expires_at,
                            refresh_token: Some(refresh_token),
                            refresh_expires_at: Some(refresh_expires_at),
                            api_base,
                            org: org.slug,
                            model,
                        };
                        validate_refresh_response(&credentials)
                            .context("validating postil login approval response")?;
                        credentials
                    }
                    (None, None) => Credentials {
                        version: credentials::LEGACY_CREDENTIALS_VERSION,
                        token,
                        expires_at,
                        refresh_token: None,
                        refresh_expires_at: None,
                        api_base,
                        org: org.slug,
                        model,
                    },
                    _ => anyhow::bail!(
                        "the postil login approval response has incomplete renewable credentials"
                    ),
                };
                let renewable_login = renewable.refresh_token.is_some();
                let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
                credentials::write(credentials_path, &renewable)?;
                if renewable_login {
                    eprintln!(
                        "postil: logged in to {} ({}): renewable until inactive after {}",
                        org.name,
                        renewable.org,
                        renewable
                            .refresh_expires_at
                            .as_deref()
                            .expect("renewable credentials have an expiry")
                    );
                } else {
                    eprintln!(
                        "postil: logged in to {} ({}) with an access-only credential",
                        org.name, renewable.org
                    );
                }
                return Ok(0);
            }
            428 => continue,
            403 => {
                eprintln!("postil: login request was denied");
                return Ok(1);
            }
            410 => {
                eprintln!("postil: login code expired; run `postil login` again");
                return Ok(1);
            }
            other => {
                return Err(anyhow!("postil login failed: server responded {other}"));
            }
        }
    }
    eprintln!("postil: login timed out waiting for approval; run `postil login` again");
    Ok(1)
}

/// Servers are the source of truth for pacing; this only guards against a
/// pathological `interval` (zero, or implausibly long) in a buggy or
/// hostile response.
fn interval_secs(server_interval: u64) -> u64 {
    server_interval.clamp(1, 30)
}

async fn logout_with(
    client: &reqwest::Client,
    server: &str,
    credentials_path: &Path,
) -> Result<i32> {
    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    match credentials::read(credentials_path) {
        Ok(Some(creds)) => {
            let logout_url = format!("{}/api/cli/logout", server.trim_end_matches('/'));
            let request = client.post(&logout_url).bearer_auth(&creds.token);
            let request = if let Some(refresh_token) = creds
                .refresh_token
                .as_deref()
                .filter(|token| !token.trim().is_empty())
            {
                request.json(&serde_json::json!({ "refreshToken": refresh_token }))
            } else {
                request
            };
            match request.send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => eprintln!(
                    "postil: logout request returned {}; removing the local credential anyway",
                    response.status()
                ),
                Err(_) => eprintln!(
                    "postil: could not reach postil to revoke the credential; removing the local credential anyway"
                ),
            }
        }
        Ok(None) => eprintln!("postil: not logged in"),
        Err(_) => eprintln!("postil: stored credentials were unreadable; removing them anyway"),
    }
    // Removal happens regardless of what happened above: a developer running
    // `postil logout` wants the local secret gone even if the network is down.
    credentials::remove(credentials_path)?;
    eprintln!("postil: logged out");
    Ok(0)
}

/// Resolves a stored login for a hosted request. Explicit API-key environment
/// variables are handled by the caller before this function is reached, so a
/// BYOK invocation never reads, locks, or refreshes a local Postil login.
pub(crate) async fn resolve_stored_token(credentials_path: &Path) -> Result<Option<String>> {
    let server = login_server();
    let client = secure_http_client(&server).context("building the postil refresh HTTP client")?;
    resolve_stored_token_with(&client, &server, credentials_path).await
}

async fn resolve_stored_token_with(
    client: &reqwest::Client,
    server: &str,
    credentials_path: &Path,
) -> Result<Option<String>> {
    let Some(credentials) = credentials::read(credentials_path)? else {
        return Ok(None);
    };
    if credentials.refresh_token.is_some() && !credentials.can_refresh() {
        anyhow::bail!("the stored postil login can no longer be renewed; run `postil login` again");
    }
    if !credentials.expires_within(ACCESS_REFRESH_MARGIN) {
        return Ok(Some(credentials.token));
    }

    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    let Some(credentials) = credentials::read(credentials_path)? else {
        return Ok(None);
    };
    if credentials.refresh_token.is_some() && !credentials.can_refresh() {
        anyhow::bail!("the stored postil login can no longer be renewed; run `postil login` again");
    }
    if !credentials.expires_within(ACCESS_REFRESH_MARGIN) {
        return Ok(Some(credentials.token));
    }
    let Some(refresh_token) = credentials.refresh_token.as_deref() else {
        anyhow::bail!("the stored postil login credential expired; run `postil login` again");
    };

    let refreshed = refresh_token_with(client, server, refresh_token).await?;
    let replacement = Credentials {
        version: credentials::CREDENTIALS_VERSION,
        token: refreshed.token,
        expires_at: refreshed.expires_at,
        refresh_token: Some(refreshed.refresh_token),
        refresh_expires_at: Some(refreshed.refresh_expires_at),
        api_base: credentials.api_base,
        org: credentials.org,
        model: credentials.model,
    };
    validate_refresh_response(&replacement)?;
    credentials::write(credentials_path, &replacement)?;
    Ok(Some(replacement.token))
}

async fn refresh_token_with(
    client: &reqwest::Client,
    server: &str,
    refresh_token: &str,
) -> Result<RefreshTokenResponse> {
    let refresh_url = format!("{}/api/cli/token/refresh", server.trim_end_matches('/'));
    let response = tokio::time::timeout(
        REFRESH_REQUEST_TIMEOUT,
        client
            .post(&refresh_url)
            .json(&serde_json::json!({ "refreshToken": refresh_token }))
            .send(),
    )
    .await
    .map_err(|_| anyhow!("could not refresh the stored postil login; try again"))?
    .map_err(|_| anyhow!("could not refresh the stored postil login; try again"))?;
    let status = response.status();
    if status.is_server_error() || matches!(status.as_u16(), 408 | 429) {
        anyhow::bail!("could not refresh the stored postil login; try again");
    }
    if !status.is_success() {
        anyhow::bail!("the stored postil login can no longer be renewed; run `postil login` again");
    }
    match tokio::time::timeout(REFRESH_REQUEST_TIMEOUT, bounded_json(response)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(RefreshResponseError::Invalid)) => {
            anyhow::bail!("the postil refresh response was invalid; run `postil login` again")
        }
        Ok(Err(RefreshResponseError::Transport)) | Err(_) => {
            anyhow::bail!("could not refresh the stored postil login; try again")
        }
    }
}

enum RefreshResponseError {
    Transport,
    Invalid,
}

async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
) -> std::result::Result<T, RefreshResponseError> {
    let expected_length = response.content_length();
    if expected_length.is_some_and(|length| length > REFRESH_RESPONSE_MAX_BYTES as u64) {
        return Err(RefreshResponseError::Invalid);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RefreshResponseError::Transport)?
    {
        if bytes.len().saturating_add(chunk.len()) > REFRESH_RESPONSE_MAX_BYTES {
            return Err(RefreshResponseError::Invalid);
        }
        bytes.extend_from_slice(&chunk);
    }
    if expected_length.is_some_and(|length| length != bytes.len() as u64) {
        return Err(RefreshResponseError::Transport);
    }
    serde_json::from_slice(&bytes).map_err(|_| RefreshResponseError::Invalid)
}

fn validate_refresh_response(credentials: &Credentials) -> Result<()> {
    anyhow::ensure!(
        !credentials.token.trim().is_empty()
            && credentials
                .refresh_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty())
            && !credentials.is_expired()
            && credentials.can_refresh(),
        "refresh response did not contain usable credentials"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Returns the i-th `(status, body)` pair on each successive request,
    /// repeating the last one past the end. Mirrors the codebase's existing
    /// `SequentialReviewResponder` (see `tests/e2e.rs`) so a poll loop can be
    /// driven through pending -> approved deterministically, rather than
    /// relying on wiremock's mount-order/priority tie-breaking across
    /// otherwise-identical requests.
    #[derive(Clone)]
    struct SequentialTokenResponder {
        calls: Arc<AtomicUsize>,
        responses: Arc<Vec<(u16, serde_json::Value)>>,
    }

    impl Respond for SequentialTokenResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .responses
                .get(index)
                .or_else(|| self.responses.last())
                .cloned()
                .expect("sequential responder requires at least one response");
            ResponseTemplate::new(status).set_body_json(body)
        }
    }

    fn approved_body() -> serde_json::Value {
        serde_json::json!({
            "status": "approved",
            "token": "pcli_test-token-not-a-real-secret",
            "expiresAt": "2999-01-01T00:00:00.000Z",
            "refreshToken": "fixture-refresh-not-a-credential",
            "refreshExpiresAt": "2999-12-01T00:00:00.000Z",
            "apiBase": "https://postil.dev/api/inference/v1",
            "org": {"slug": "runatlas-is", "name": "RunAtlas"},
            "model": "z-ai/glm-5.2",
        })
    }

    fn legacy_approved_body() -> serde_json::Value {
        let mut body = approved_body();
        let object = body
            .as_object_mut()
            .expect("approved response fixture is an object");
        object.remove("refreshToken");
        object.remove("refreshExpiresAt");
        body
    }

    fn start_body() -> serde_json::Value {
        serde_json::json!({
            "deviceCode": "test-device-code",
            "userCode": "WDJF-3K9Q",
            "verificationUri": "https://postil.dev/cli/authorize",
            "verificationUriComplete": "https://postil.dev/cli/authorize?code=WDJF-3K9Q",
            "expiresIn": 600,
            "interval": 1,
        })
    }

    #[tokio::test]
    async fn login_writes_credentials_on_immediate_approval() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(approved_body()))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let exit = login_with(
            &reqwest::Client::new(),
            &server.uri(),
            None,
            &credentials_path,
        )
        .await
        .unwrap();
        assert_eq!(exit, 0);
        let stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(stored.token, "pcli_test-token-not-a-real-secret");
        assert_eq!(stored.org, "runatlas-is");
        assert_eq!(stored.model, "z-ai/glm-5.2");
        assert_eq!(
            stored.refresh_expires_at.as_deref(),
            Some("2999-12-01T00:00:00.000Z")
        );
    }

    #[tokio::test]
    async fn login_waits_for_an_in_progress_stored_login_mutation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(approved_body()))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let held_lock = credentials::CredentialLock::acquire(&credentials_path)
            .await
            .unwrap();
        let task_path = credentials_path.clone();
        let server_uri = server.uri();
        let login = tokio::spawn(async move {
            login_with(&reqwest::Client::new(), &server_uri, None, &task_path).await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!login.is_finished());
        assert!(!credentials_path.exists());
        drop(held_lock);

        let exit = tokio::time::timeout(Duration::from_secs(2), login)
            .await
            .expect("login should resume after the stored login lock is released")
            .unwrap()
            .unwrap();
        assert_eq!(exit, 0);
        assert!(credentials::read(&credentials_path).unwrap().is_some());
    }

    #[tokio::test]
    async fn login_accepts_a_legacy_access_only_approval_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(legacy_approved_body()))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        assert_eq!(
            login_with(
                &reqwest::Client::new(),
                &server.uri(),
                None,
                &credentials_path,
            )
            .await
            .unwrap(),
            0
        );

        let stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert!(stored.refresh_token.is_none());
        assert!(stored.refresh_expires_at.is_none());
    }

    #[tokio::test]
    async fn login_polls_through_pending_before_approval() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        let responder = SequentialTokenResponder {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(vec![
                (428, serde_json::json!({"status": "pending"})),
                (428, serde_json::json!({"status": "pending"})),
                (200, approved_body()),
            ]),
        };
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(responder.clone())
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let exit = login_with(
            &reqwest::Client::new(),
            &server.uri(),
            None,
            &credentials_path,
        )
        .await
        .unwrap();
        assert_eq!(exit, 0);
        assert_eq!(responder.calls.load(Ordering::SeqCst), 3);
        assert!(credentials::read(&credentials_path).unwrap().is_some());
    }

    #[tokio::test]
    async fn login_reports_denial_and_writes_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({"status": "denied"})),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let exit = login_with(
            &reqwest::Client::new(),
            &server.uri(),
            None,
            &credentials_path,
        )
        .await
        .unwrap();
        assert_eq!(exit, 1);
        assert!(credentials::read(&credentials_path).unwrap().is_none());
    }

    #[tokio::test]
    async fn login_reports_expiry_and_writes_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/token"))
            .respond_with(
                ResponseTemplate::new(410).set_body_json(serde_json::json!({"status": "expired"})),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let exit = login_with(
            &reqwest::Client::new(),
            &server.uri(),
            None,
            &credentials_path,
        )
        .await
        .unwrap();
        assert_eq!(exit, 1);
        assert!(credentials::read(&credentials_path).unwrap().is_none());
    }

    #[tokio::test]
    async fn logout_removes_credentials_even_when_the_server_call_fails() {
        // No mock mounted for /api/cli/logout at all: every request to this
        // server 404s, standing in for "the network call failed."
        let server = MockServer::start().await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &Credentials {
                version: credentials::CREDENTIALS_VERSION,
                token: "pcli_test-token-not-a-real-secret".to_string(),
                expires_at: "2999-01-01T00:00:00.000Z".to_string(),
                refresh_token: Some("fixture-refresh-not-a-credential".to_string()),
                refresh_expires_at: Some("2999-12-01T00:00:00.000Z".to_string()),
                api_base: "https://postil.dev/api/inference/v1".to_string(),
                org: "runatlas-is".to_string(),
                model: "z-ai/glm-5.2".to_string(),
            },
        )
        .unwrap();

        let exit = logout_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
            .await
            .unwrap();
        assert_eq!(exit, 0);
        assert!(!credentials_path.exists());
    }

    #[tokio::test]
    async fn logout_is_a_no_op_success_when_never_logged_in() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");

        let exit = logout_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
            .await
            .unwrap();
        assert_eq!(exit, 0);
        assert!(!credentials_path.exists());
    }

    #[tokio::test]
    async fn logout_waits_for_an_in_progress_stored_login_mutation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/logout"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &stored_credentials("2999-01-01T00:00:00.000Z"),
        )
        .unwrap();
        let held_lock = credentials::CredentialLock::acquire(&credentials_path)
            .await
            .unwrap();
        let task_path = credentials_path.clone();
        let server_uri = server.uri();
        let logout = tokio::spawn(async move {
            logout_with(&reqwest::Client::new(), &server_uri, &task_path).await
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!logout.is_finished());
        assert!(credentials_path.exists());
        drop(held_lock);

        let exit = tokio::time::timeout(Duration::from_secs(2), logout)
            .await
            .expect("logout should resume after the stored login lock is released")
            .unwrap()
            .unwrap();
        assert_eq!(exit, 0);
        assert!(!credentials_path.exists());
    }

    fn stored_credentials(expires_at: &str) -> Credentials {
        Credentials {
            version: credentials::CREDENTIALS_VERSION,
            token: "pcli_test-old-access-not-a-real-secret".to_string(),
            expires_at: expires_at.to_string(),
            refresh_token: Some("fixture-old-refresh-not-a-credential".to_string()),
            refresh_expires_at: Some("2999-12-01T00:00:00.000Z".to_string()),
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
        }
    }

    fn write_legacy_credentials(path: &Path, credentials: &Credentials) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_string(credentials).unwrap()).unwrap();
    }

    fn refresh_body() -> serde_json::Value {
        serde_json::json!({
            "token": "pcli_test-new-access-not-a-real-secret",
            "expiresAt": "2999-01-01T00:00:00.000Z",
            "refreshToken": "fixture-new-refresh-not-a-credential",
            "refreshExpiresAt": "2999-12-01T00:00:00.000Z"
        })
    }

    #[tokio::test]
    async fn refreshes_a_near_expiry_access_token_and_persists_rotation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(refresh_body()))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &stored_credentials("2020-01-01T00:00:00.000Z"),
        )
        .unwrap();

        let resolved =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some("pcli_test-new-access-not-a-real-secret")
        );
        let stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(stored.token, "pcli_test-new-access-not-a-real-secret");
        assert_eq!(
            stored.refresh_token.as_deref(),
            Some("fixture-new-refresh-not-a-credential")
        );
    }

    #[tokio::test]
    async fn refreshes_inside_the_proactive_access_margin() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(refresh_body()))
            .expect(1)
            .mount(&server)
            .await;
        let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::minutes(2))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(&credentials_path, &stored_credentials(&expires_at)).unwrap();

        resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_resolvers_share_one_refresh_rotation() {
        #[derive(Clone)]
        struct DelayedRefreshResponder {
            calls: Arc<AtomicUsize>,
        }

        impl Respond for DelayedRefreshResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                self.calls.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(refresh_body())
                    .set_delay(Duration::from_millis(100))
            }
        }

        let server = MockServer::start().await;
        let responder = DelayedRefreshResponder {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(responder.clone())
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &stored_credentials("2020-01-01T00:00:00.000Z"),
        )
        .unwrap();
        let client = reqwest::Client::new();
        let server_uri = server.uri();

        let (first, second) = tokio::join!(
            resolve_stored_token_with(&client, &server_uri, &credentials_path),
            resolve_stored_token_with(&client, &server_uri, &credentials_path)
        );
        assert_eq!(
            first.unwrap().as_deref(),
            Some("pcli_test-new-access-not-a-real-secret")
        );
        assert_eq!(
            second.unwrap().as_deref(),
            Some("pcli_test-new-access-not-a-real-secret")
        );
        assert_eq!(responder.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_the_previous_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(503).set_body_string("not shown"))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("a failed refresh must fail closed");
        assert!(error.to_string().contains("try again"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn malformed_refresh_response_requires_relogin_without_leaking_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("server body must stay private"),
            )
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("a malformed response must not be accepted");
        assert!(error.to_string().contains("postil login"));
        assert!(!error.to_string().contains("server body must stay private"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn rejected_refresh_requires_relogin_without_leaking_the_server_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(401).set_body_string("refresh replay details"))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("a replayed refresh token must require login");
        assert!(error.to_string().contains("postil login"));
        assert!(!error.to_string().contains("refresh replay details"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn expired_v1_login_requires_relogin() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy = stored_credentials("2020-01-01T00:00:00.000Z");
        legacy.version = 1;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        write_legacy_credentials(&credentials_path, &legacy);

        let error = resolve_stored_token_with(
            &reqwest::Client::new(),
            "http://127.0.0.1:9",
            &credentials_path,
        )
        .await
        .expect_err("expired legacy credentials must require login");
        assert!(error.to_string().contains("postil login"));
    }

    #[tokio::test]
    async fn unexpired_v1_login_remains_usable_without_a_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy = stored_credentials("2999-01-01T00:00:00.000Z");
        legacy.version = 1;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        write_legacy_credentials(&credentials_path, &legacy);

        let resolved = resolve_stored_token_with(
            &reqwest::Client::new(),
            "http://127.0.0.1:9",
            &credentials_path,
        )
        .await
        .unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some("pcli_test-old-access-not-a-real-secret")
        );
    }

    #[tokio::test]
    async fn expired_refresh_inactivity_requires_relogin() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut expired = stored_credentials("2999-01-01T00:00:00.000Z");
        expired.refresh_expires_at = Some("2020-01-01T00:00:00.000Z".to_string());
        credentials::write(&credentials_path, &expired).unwrap();

        let error = resolve_stored_token_with(
            &reqwest::Client::new(),
            "http://127.0.0.1:9",
            &credentials_path,
        )
        .await
        .expect_err("expired refresh inactivity must require login");
        assert!(error.to_string().contains("postil login"));
    }

    #[tokio::test]
    async fn logout_sends_refresh_token_even_after_access_expiry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/logout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &stored_credentials("2020-01-01T00:00:00.000Z"),
        )
        .unwrap();

        logout_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
            .await
            .unwrap();
        assert!(!credentials_path.exists());
        let requests = server.received_requests().await.unwrap();
        let request = requests.first().unwrap();
        assert!(request.headers.contains_key("authorization"));
        assert!(
            std::str::from_utf8(&request.body)
                .unwrap()
                .contains("refreshToken")
        );
    }

    #[tokio::test]
    async fn legacy_logout_uses_its_access_bearer_without_a_null_refresh_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/logout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy = stored_credentials("2999-01-01T00:00:00.000Z");
        legacy.version = 1;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        credentials::write(&credentials_path, &legacy).unwrap();

        assert_eq!(
            logout_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .unwrap(),
            0
        );
        assert!(!credentials_path.exists());
        let requests = server.received_requests().await.unwrap();
        assert!(requests.first().unwrap().body.is_empty());
    }

    #[tokio::test]
    async fn rate_limited_refresh_keeps_the_previous_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(429).set_body_string("retry later"))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("rate-limited refreshes must fail closed without relogin");
        assert!(error.to_string().contains("try again"));
        assert!(!error.to_string().contains("run `postil login` again"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn request_timeout_refresh_keeps_the_previous_credential() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/token/refresh"))
            .respond_with(ResponseTemplate::new(408).set_body_string("retry later"))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("request-timeout refreshes must retain the credential");
        assert!(error.to_string().contains("try again"));
        assert!(!error.to_string().contains("run `postil login` again"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn truncated_successful_refresh_response_is_retryable_and_preserves_the_credential() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4_096];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n{\"token\":\"committed-but-truncated\"",
                )
                .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials("2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error = resolve_stored_token_with(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            &credentials_path,
        )
        .await
        .expect_err("a truncated committed response must be retried with the old credential");

        server.join().unwrap();
        assert!(error.to_string().contains("try again"));
        assert!(!error.to_string().contains("run `postil login` again"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }
}
