//! `postil login` / `postil logout`: device-authorization flow against the
//! Postil web app, modelled on RFC 8628. Chosen because the CLI runs over
//! SSH and in containers where no localhost browser callback is reachable.
//!
//! A successful login writes a credential the API-key resolver
//! (`api_key::resolve_effective`) falls back to when no explicit key env var
//! is set, so a first-time user gets working hosted inference with zero
//! configuration.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

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
    #[serde(rename = "apiBase")]
    api_base: String,
    org: DeviceTokenOrg,
    model: String,
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
                let creds = Credentials {
                    version: credentials::CREDENTIALS_VERSION,
                    token: approved.token,
                    expires_at: approved.expires_at,
                    api_base: approved.api_base,
                    org: approved.org.slug,
                    model: approved.model,
                };
                credentials::write(credentials_path, &creds)?;
                eprintln!(
                    "postil: logged in to {} ({}) -- credential expires {}",
                    approved.org.name, creds.org, creds.expires_at
                );
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
    match credentials::read(credentials_path) {
        Ok(Some(creds)) => {
            let logout_url = format!("{}/api/cli/logout", server.trim_end_matches('/'));
            match client
                .post(&logout_url)
                .bearer_auth(&creds.token)
                .send()
                .await
            {
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
            "apiBase": "https://postil.dev/api/inference/v1",
            "org": {"slug": "runatlas-is", "name": "RunAtlas"},
            "model": "z-ai/glm-5.2",
        })
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
}
