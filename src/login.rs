//! `postil login` / `postil logout`: device-authorization flow against the
//! Postil web app, modelled on RFC 8628. Chosen because the CLI runs over
//! SSH and in containers where no localhost browser callback is reachable.
//!
//! A successful login writes a credential that `resolve_stored_token` uses
//! when no explicit key environment variable is set, so a first-time user gets
//! working hosted inference with zero configuration.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config::normalize_api_base;
use crate::credentials::{self, Credentials, PendingRevocation};
use crate::llm::secure_http_client_async;

/// Overrides the Postil web app the device-flow calls target. Distinct from
/// `POSTIL_API_BASE`, which (once a token is in hand) points at the
/// inference gateway itself, not the auth endpoints.
const LOGIN_SERVER_ENV: &str = "POSTIL_LOGIN_SERVER";
const DEFAULT_LOGIN_SERVER: &str = "https://postil.dev";
const DEFAULT_LOGIN_API_BASE: &str = "https://postil.dev/api/inference/v1";

/// The server caps polling at 200 attempts and then returns 410 regardless;
/// this is only a client-side backstop against a stuck loop if that cap is
/// ever missed (a server bug, or a hostile `interval`).
const MAX_POLL_ATTEMPTS: u32 = 220;
const ACCESS_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
const REFRESH_RESPONSE_MAX_BYTES: usize = 16 * 1024;
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const REVOCATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
enum TransientRefreshError {
    Retry,
    RetryAfter(u64),
}

impl fmt::Display for TransientRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry => {
                formatter.write_str("could not refresh the stored postil login; try again")
            }
            Self::RetryAfter(seconds) => write!(
                formatter,
                "could not refresh the stored postil login; retry after {seconds} seconds"
            ),
        }
    }
}

impl std::error::Error for TransientRefreshError {}

pub(crate) fn token_resolution_retry_delay(error: &anyhow::Error) -> Option<Duration> {
    error
        .downcast_ref::<TransientRefreshError>()
        .map(|error| match error {
            TransientRefreshError::Retry => Duration::ZERO,
            TransientRefreshError::RetryAfter(seconds) => Duration::from_secs(*seconds),
        })
}

fn canonicalize_issuer(value: &str) -> Result<String> {
    anyhow::ensure!(
        !value.trim().is_empty(),
        "login server URL must not be empty"
    );
    let mut url =
        reqwest::Url::parse(value.trim()).context("login server must be an absolute URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "login server must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "login server must not contain credentials"
    );
    anyhow::ensure!(
        url.host_str().is_some_and(|hostname| !hostname.is_empty()),
        "login server must include a hostname"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "login server must not contain a query or fragment"
    );
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn login_server_override() -> Result<Option<String>> {
    let Some(_) = std::env::var_os(LOGIN_SERVER_ENV) else {
        return Ok(None);
    };
    let value = std::env::var(LOGIN_SERVER_ENV)
        .with_context(|| format!("{LOGIN_SERVER_ENV} must contain a valid URL"))?;
    canonicalize_issuer(&value)
        .with_context(|| format!("invalid {LOGIN_SERVER_ENV}"))
        .map(Some)
}

fn login_server() -> Result<String> {
    login_server_override()?.map_or_else(|| canonicalize_issuer(DEFAULT_LOGIN_SERVER), Ok)
}

pub(crate) fn stored_issuer(credentials: &Credentials) -> Result<String> {
    if let Some(issuer) = credentials.issuer.as_deref() {
        return canonicalize_issuer(issuer)
            .context("the stored login issuer is invalid; run `postil login` again");
    }

    let stored_api_base = normalize_api_base(&credentials.api_base)
        .context("the stored login API base is invalid; run `postil login` again")?;
    let canonical_api_base = normalize_api_base(DEFAULT_LOGIN_API_BASE)
        .expect("the embedded Postil API base must be valid");
    anyhow::ensure!(
        stored_api_base == canonical_api_base,
        "the stored legacy login has no issuing server and its API base is not the canonical Postil endpoint; run `postil login` again"
    );
    canonicalize_issuer(DEFAULT_LOGIN_SERVER)
}

fn require_matching_issuer(
    credentials: &Credentials,
    configured_issuer: Option<&str>,
) -> Result<String> {
    let issuer = stored_issuer(credentials)?;
    if let Some(configured_issuer) = configured_issuer {
        let configured_issuer = canonicalize_issuer(configured_issuer)
            .with_context(|| format!("invalid {LOGIN_SERVER_ENV}"))?;
        anyhow::ensure!(
            configured_issuer == issuer,
            "{LOGIN_SERVER_ENV} does not match the stored login issuer; unset it to use this login, or run `postil login` to replace the login for that server"
        );
    }
    Ok(issuer)
}

fn require_matching_api_base(credentials: &Credentials, resolved_api_base: &str) -> Result<()> {
    let stored_api_base = normalize_api_base(&credentials.api_base)
        .context("the stored login API base is invalid; run `postil login` again")?;
    let resolved_api_base =
        normalize_api_base(resolved_api_base).context("the resolved model API base is invalid")?;
    if stored_api_base != resolved_api_base {
        let key_names = crate::api_key::names_text();
        anyhow::bail!(
            "the stored postil login is bound to {}; the resolved model API base is {}. Set an explicit key with {}, or remove the API base override to use this login",
            credentials.api_base,
            resolved_api_base,
            key_names
        );
    }
    Ok(())
}

pub async fn run_login(org: Option<String>) -> Result<i32> {
    let server = login_server()?;
    let client = secure_http_client_async(&server)
        .await
        .context("building the postil login HTTP client")?;
    let path = credentials::default_path()?;
    login_with(&client, &server, org.as_deref(), &path).await
}

pub async fn run_logout() -> Result<i32> {
    let configured_issuer = login_server_override()?;
    let path = credentials::default_path()?;
    logout_with_mode(ClientMode::Secure, configured_issuer.as_deref(), &path).await
}

#[derive(Clone, Copy)]
enum ClientMode<'a> {
    Secure,
    #[cfg(test)]
    Provided(&'a reqwest::Client),
    Reuse {
        client: &'a reqwest::Client,
        issuer: &'a str,
    },
}

impl ClientMode<'_> {
    async fn for_issuer(self, issuer: &str) -> Result<reqwest::Client> {
        match self {
            #[cfg(test)]
            Self::Provided(client) => Ok(client.clone()),
            Self::Reuse {
                client,
                issuer: client_issuer,
            } if client_issuer == issuer => Ok(client.clone()),
            Self::Secure | Self::Reuse { .. } => secure_http_client_async(issuer)
                .await
                .context("building an HTTP client for stored login issuer"),
        }
    }
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
    let server = canonicalize_issuer(server)?;
    let mut start_body = serde_json::json!({ "clientVersion": env!("CARGO_PKG_VERSION") });
    // The device/start contract takes no org field today; sending it as an
    // extra, ignorable JSON key is a forward-compatible hint only. Org
    // membership is actually chosen on the browser approval page, so the
    // hint below is what carries the user's `--org` intent there.
    if let Some(org) = org {
        start_body["org"] = serde_json::Value::String(org.to_string());
    }
    let start_url = format!("{server}/api/cli/device/start");
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
    let token_url = format!("{server}/api/cli/device/token");
    for _ in 0..MAX_POLL_ATTEMPTS {
        tokio::time::sleep(interval).await;
        let response = match client
            .post(&token_url)
            .json(&serde_json::json!({ "deviceCode": start.device_code }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => continue,
        };
        match response.status().as_u16() {
            200 => {
                let approved: DeviceTokenApproved = match response.json().await {
                    Ok(approved) => approved,
                    Err(_) => continue,
                };
                let DeviceTokenApproved {
                    token,
                    expires_at,
                    refresh_token,
                    refresh_expires_at,
                    api_base,
                    org,
                    model,
                } = approved;
                let mut renewable = match (refresh_token, refresh_expires_at) {
                    (Some(refresh_token), Some(refresh_expires_at)) => {
                        let credentials = Credentials {
                            version: credentials::CREDENTIALS_VERSION,
                            issuer: Some(server.clone()),
                            token,
                            expires_at,
                            refresh_token: Some(refresh_token),
                            refresh_expires_at: Some(refresh_expires_at),
                            api_base,
                            org: org.slug,
                            model,
                            pending_revocations: Vec::new(),
                        };
                        validate_refresh_response(&credentials)
                            .context("validating postil login approval response")?;
                        credentials
                    }
                    (None, None) => Credentials {
                        version: credentials::CREDENTIALS_VERSION,
                        issuer: Some(server.clone()),
                        token,
                        expires_at,
                        refresh_token: None,
                        refresh_expires_at: None,
                        api_base,
                        org: org.slug,
                        model,
                        pending_revocations: Vec::new(),
                    },
                    _ => anyhow::bail!(
                        "the postil login approval response has incomplete renewable credentials"
                    ),
                };
                let renewable_login = renewable.refresh_token.is_some();
                let pending_count = persist_approved_login_with(
                    ClientMode::Reuse {
                        client,
                        issuer: &server,
                    },
                    credentials_path,
                    &mut renewable,
                    credentials::write,
                )
                .await?;
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
                if pending_count > 0 {
                    eprintln!("postil: a previous login is pending revocation and will be retried");
                }
                return Ok(0);
            }
            428 => continue,
            408 | 429 | 500..=599 => continue,
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

#[cfg(test)]
async fn logout_with(
    client: &reqwest::Client,
    configured_issuer: &str,
    credentials_path: &Path,
) -> Result<i32> {
    logout_with_mode(
        ClientMode::Provided(client),
        Some(configured_issuer),
        credentials_path,
    )
    .await
}

async fn logout_with_mode(
    client_mode: ClientMode<'_>,
    configured_issuer: Option<&str>,
    credentials_path: &Path,
) -> Result<i32> {
    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    let Some(mut stored) = credentials::read(credentials_path)? else {
        let mut pending = credentials::read_pending(credentials_path)?;
        if pending.is_empty() {
            eprintln!("postil: not logged in");
            return Ok(0);
        }
        let remaining =
            drain_pending_without_active_locked(client_mode, credentials_path, &mut pending)
                .await?;
        if remaining == 0 {
            eprintln!("postil: pending session revocations completed; no login is stored");
            return Ok(0);
        }
        eprintln!("postil: a previous session could not be revoked; run `postil logout` again");
        return Ok(1);
    };

    let issuer = require_matching_issuer(&stored, configured_issuer)?;
    let mut detached = credentials::read_pending(credentials_path)?;
    if !detached.is_empty() {
        stored.pending_revocations.append(&mut detached);
        deduplicate_revocations(&mut stored.pending_revocations);
        credentials::write(credentials_path, &stored)?;
    }

    let current = revocation_for(&stored)?;
    if !revoke(client_mode, &current).await {
        eprintln!(
            "postil: could not revoke the stored login at its issuing server; credentials were kept. Run `postil logout` again"
        );
        return Ok(1);
    }

    debug_assert_eq!(issuer, current.issuer);
    let remaining =
        drain_pending_for_active_locked(client_mode, credentials_path, &mut stored).await?;
    if remaining == 0 {
        credentials::remove(credentials_path)?;
        credentials::write_pending(credentials_path, &[])?;
        eprintln!("postil: logged out");
        return Ok(0);
    }

    credentials::write_pending(credentials_path, &stored.pending_revocations)?;
    credentials::remove(credentials_path)?;
    eprintln!(
        "postil: the current login was revoked, but a previous session is still pending revocation; run `postil logout` again"
    );
    Ok(1)
}

/// Resolves a stored login for a hosted request. Explicit API-key environment
/// variables are handled by the caller before this function is reached, so a
/// BYOK invocation never reads, locks, or refreshes a local Postil login.
pub(crate) async fn resolve_stored_token(
    credentials_path: &Path,
    resolved_api_base: &str,
) -> Result<Option<String>> {
    let configured_issuer = login_server_override()?;
    let result = resolve_stored_token_with_mode(
        ClientMode::Secure,
        configured_issuer.as_deref(),
        credentials_path,
        resolved_api_base,
    )
    .await;
    if result.is_ok() {
        spawn_pending_revocation_drain(credentials_path);
    }
    result
}

#[derive(Debug)]
pub(crate) struct StoredAlertSession {
    pub issuer: String,
    pub token: String,
}

/// Returns an issuer and renewable access token from one coherent stored-login
/// generation. A concurrent login replacement retries instead of pairing the
/// replacement token with the prior issuer.
pub(crate) async fn resolve_stored_alert_session(
    credentials_path: &Path,
) -> Result<Option<StoredAlertSession>> {
    for _ in 0..3 {
        let Some(snapshot) = credentials::read(credentials_path)? else {
            return Ok(None);
        };
        let Some(token) = resolve_stored_token(credentials_path, &snapshot.api_base).await? else {
            return Ok(None);
        };
        let Some(current) = credentials::read(credentials_path)? else {
            continue;
        };
        if current.api_base != snapshot.api_base || current.token != token {
            continue;
        }
        anyhow::ensure!(
            current.version == credentials::CREDENTIALS_VERSION
                && current.issuer.is_some()
                && current.can_refresh(),
            "operator alert notifications require a renewable login; run `postil login` again"
        );
        return Ok(Some(StoredAlertSession {
            issuer: stored_issuer(&current)?,
            token,
        }));
    }
    anyhow::bail!("the stored postil login changed while connecting; try again")
}

#[cfg(test)]
async fn resolve_stored_token_with(
    client: &reqwest::Client,
    configured_issuer: &str,
    credentials_path: &Path,
) -> Result<Option<String>> {
    let resolved_api_base = credentials::read(credentials_path)?
        .map(|credentials| credentials.api_base)
        .unwrap_or_default();
    resolve_stored_token_with_mode(
        ClientMode::Provided(client),
        Some(configured_issuer),
        credentials_path,
        &resolved_api_base,
    )
    .await
}

async fn resolve_stored_token_with_mode(
    client_mode: ClientMode<'_>,
    configured_issuer: Option<&str>,
    credentials_path: &Path,
    resolved_api_base: &str,
) -> Result<Option<String>> {
    let Some(credentials) = credentials::read(credentials_path)? else {
        return Ok(None);
    };
    require_matching_api_base(&credentials, resolved_api_base)?;
    if credentials.refresh_token.is_none() {
        if credentials.is_expired() {
            anyhow::bail!("the stored postil login credential expired; run `postil login` again");
        }
        return Ok(Some(credentials.token));
    }
    require_matching_issuer(&credentials, configured_issuer)?;
    if !credentials.can_refresh() {
        anyhow::bail!("the stored postil login can no longer be renewed; run `postil login` again");
    }
    if !credentials.expires_within(ACCESS_REFRESH_MARGIN) {
        return Ok(Some(credentials.token));
    }

    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    let Some(credentials) = credentials::read(credentials_path)? else {
        return Ok(None);
    };
    require_matching_api_base(&credentials, resolved_api_base)?;
    let issuer = require_matching_issuer(&credentials, configured_issuer)?;
    if !credentials.can_refresh() {
        anyhow::bail!("the stored postil login can no longer be renewed; run `postil login` again");
    }
    if !credentials.expires_within(ACCESS_REFRESH_MARGIN) {
        return Ok(Some(credentials.token));
    }
    let Some(refresh_token) = credentials.refresh_token.as_deref() else {
        anyhow::bail!("the stored postil login credential expired; run `postil login` again");
    };

    let client = client_mode.for_issuer(&issuer).await?;
    let refreshed = refresh_token_with(&client, &issuer, refresh_token).await?;
    let replacement = Credentials {
        version: credentials::CREDENTIALS_VERSION,
        issuer: Some(issuer),
        token: refreshed.token,
        expires_at: refreshed.expires_at,
        refresh_token: Some(refreshed.refresh_token),
        refresh_expires_at: Some(refreshed.refresh_expires_at),
        api_base: credentials.api_base,
        org: credentials.org,
        model: credentials.model,
        pending_revocations: credentials.pending_revocations,
    };
    validate_refresh_response(&replacement)?;
    credentials::write(credentials_path, &replacement)?;
    Ok(Some(replacement.token))
}

fn revocation_for(credentials: &Credentials) -> Result<PendingRevocation> {
    anyhow::ensure!(
        !credentials.token.trim().is_empty(),
        "the stored login cannot be revoked because its access credential is invalid; run `postil login` again"
    );
    Ok(PendingRevocation {
        issuer: stored_issuer(credentials)?,
        token: credentials.token.clone(),
        refresh_token: credentials
            .refresh_token
            .as_deref()
            .filter(|token| !token.trim().is_empty())
            .map(str::to_string),
    })
}

fn deduplicate_revocations(revocations: &mut Vec<PendingRevocation>) {
    let mut unique = Vec::with_capacity(revocations.len());
    for revocation in revocations.drain(..) {
        if !unique.contains(&revocation) {
            unique.push(revocation);
        }
    }
    *revocations = unique;
}

async fn persist_approved_login_with<F>(
    client_mode: ClientMode<'_>,
    credentials_path: &Path,
    approved: &mut Credentials,
    write_active: F,
) -> Result<usize>
where
    F: FnOnce(&Path, &Credentials) -> Result<()>,
{
    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    let new_revocation = revocation_for(approved)?;
    let mut pending = credentials::read_pending(credentials_path)?;
    pending.push(new_revocation.clone());
    deduplicate_revocations(&mut pending);
    if let Err(write_error) = credentials::write_pending(credentials_path, &pending) {
        if revoke(client_mode, &new_revocation).await {
            return Err(write_error)
                .context("could not retain the new login locally; its remote session was revoked");
        }
        return Err(write_error).context(
            "could not retain the new login or its revocation handle locally; the remote session may remain active",
        );
    }
    if let Some(existing) = credentials::read(credentials_path)? {
        pending.extend(existing.pending_revocations.iter().cloned());
        pending.push(revocation_for(&existing)?);
    }
    deduplicate_revocations(&mut pending);
    credentials::write_pending(credentials_path, &pending)?;
    approved.pending_revocations = pending;
    write_active(credentials_path, approved)?;
    let pending_count =
        match drain_pending_for_active_locked(client_mode, credentials_path, approved).await {
            Ok(count) => count,
            Err(_) => approved.pending_revocations.len(),
        };
    Ok(pending_count)
}

fn revocation_matches_active(revocation: &PendingRevocation, active: &Credentials) -> Result<bool> {
    if canonicalize_issuer(&revocation.issuer)? != stored_issuer(active)? {
        return Ok(false);
    }
    if revocation.token == active.token {
        return Ok(true);
    }
    Ok(revocation
        .refresh_token
        .as_deref()
        .is_some_and(|pending| active.refresh_token.as_deref() == Some(pending)))
}

async fn revoke(client_mode: ClientMode<'_>, revocation: &PendingRevocation) -> bool {
    if revocation.token.trim().is_empty() {
        return false;
    }
    let Ok(issuer) = canonicalize_issuer(&revocation.issuer) else {
        return false;
    };
    let Ok(client) = client_mode.for_issuer(&issuer).await else {
        return false;
    };
    let logout_url = format!("{issuer}/api/cli/logout");
    let request = client.post(&logout_url).bearer_auth(&revocation.token);
    let request = if let Some(refresh_token) = revocation
        .refresh_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
    {
        request.json(&serde_json::json!({ "refreshToken": refresh_token }))
    } else {
        request
    };
    matches!(
        tokio::time::timeout(REVOCATION_REQUEST_TIMEOUT, request.send()).await,
        Ok(Ok(response)) if response.status().is_success()
    )
}

async fn drain_pending_for_active_locked(
    client_mode: ClientMode<'_>,
    credentials_path: &Path,
    active: &mut Credentials,
) -> Result<usize> {
    let mut detached = credentials::read_pending(credentials_path)?;
    if !detached.is_empty() {
        active.pending_revocations.append(&mut detached);
        deduplicate_revocations(&mut active.pending_revocations);
        credentials::write(credentials_path, active)?;
        let _ = credentials::write_pending(credentials_path, &[]);
    }

    for revocation in active.pending_revocations.clone() {
        match revocation_matches_active(&revocation, active) {
            Ok(true) => {
                active
                    .pending_revocations
                    .retain(|item| item != &revocation);
                credentials::write(credentials_path, active)?;
                continue;
            }
            Ok(false) => {}
            Err(_) => continue,
        }
        if revoke(client_mode, &revocation).await {
            active
                .pending_revocations
                .retain(|item| item != &revocation);
            credentials::write(credentials_path, active)?;
        }
    }
    Ok(active.pending_revocations.len())
}

async fn drain_pending_without_active_locked(
    client_mode: ClientMode<'_>,
    credentials_path: &Path,
    pending: &mut Vec<PendingRevocation>,
) -> Result<usize> {
    deduplicate_revocations(pending);
    for revocation in pending.clone() {
        if revoke(client_mode, &revocation).await {
            pending.retain(|item| item != &revocation);
            credentials::write_pending(credentials_path, pending)?;
        }
    }
    Ok(pending.len())
}

fn spawn_pending_revocation_drain(credentials_path: &Path) {
    let credentials_path = credentials_path.to_path_buf();
    tokio::spawn(async move {
        let _ = drain_pending_revocations(&credentials_path).await;
    });
}

async fn drain_pending_revocations(credentials_path: &Path) -> Result<()> {
    let _lock = credentials::CredentialLock::acquire(credentials_path).await?;
    match credentials::read(credentials_path)? {
        Some(mut active) => {
            drain_pending_for_active_locked(ClientMode::Secure, credentials_path, &mut active)
                .await?;
        }
        None => {
            let mut pending = credentials::read_pending(credentials_path)?;
            drain_pending_without_active_locked(ClientMode::Secure, credentials_path, &mut pending)
                .await?;
        }
    }
    Ok(())
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
    .map_err(|_| TransientRefreshError::Retry)?
    .map_err(|_| TransientRefreshError::Retry)?;
    let status = response.status();
    if status.as_u16() == 429 {
        if let Some(retry_after) = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| {
                !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && value.parse::<u64>().is_ok()
            })
        {
            return Err(TransientRefreshError::RetryAfter(
                retry_after
                    .parse()
                    .expect("numeric Retry-After was validated above"),
            )
            .into());
        }
        return Err(TransientRefreshError::Retry.into());
    }
    if status.is_server_error() || status.as_u16() == 408 {
        return Err(TransientRefreshError::Retry.into());
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
            Err(TransientRefreshError::Retry.into())
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
        assert_eq!(stored.issuer.as_deref(), Some(server.uri().as_str()));
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
        assert_eq!(stored.version, credentials::CREDENTIALS_VERSION);
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
    async fn login_retries_an_ambiguous_server_failure_with_the_same_device_code() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(start_body()))
            .mount(&server)
            .await;
        let responder = SequentialTokenResponder {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(vec![
                (500, serde_json::json!({"status": "uncertain"})),
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
        assert_eq!(responder.calls.load(Ordering::SeqCst), 2);
        let requests = server.received_requests().await.unwrap();
        let device_codes = requests
            .iter()
            .filter(|request| request.url.path() == "/api/cli/device/token")
            .map(|request| request.body_json::<serde_json::Value>().unwrap()["deviceCode"].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            device_codes,
            vec![
                serde_json::json!("test-device-code"),
                serde_json::json!("test-device-code")
            ]
        );
    }

    #[tokio::test]
    async fn login_write_failure_retains_the_new_family_revocation_handle() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut approved = stored_credentials_at(&server.uri(), "2999-01-01T00:00:00.000Z");
        approved.token = "pcli_test-token-not-a-real-secret".to_string();
        approved.refresh_token = Some("fixture-refresh-not-a-credential".to_string());
        let client = reqwest::Client::new();
        let error = persist_approved_login_with(
            ClientMode::Provided(&client),
            &credentials_path,
            &mut approved,
            |_path, _credentials| anyhow::bail!("simulated active credential write failure"),
        )
        .await
        .expect_err("installing the active credential should fail");

        assert!(
            error
                .to_string()
                .contains("simulated active credential write failure")
        );
        assert!(credentials::read(&credentials_path).unwrap().is_none());
        let pending = credentials::read_pending(&credentials_path).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].issuer, server.uri());
        assert_eq!(pending[0].token, "pcli_test-token-not-a-real-secret");
        assert_eq!(
            pending[0].refresh_token.as_deref(),
            Some("fixture-refresh-not-a-credential")
        );
    }

    #[tokio::test]
    async fn relogin_retains_a_failed_old_family_revocation_until_retry_succeeds() {
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
        let revocations = SequentialTokenResponder {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(vec![
                (503, serde_json::json!({"status": "retry"})),
                (200, serde_json::json!({"status": "revoked"})),
            ]),
        };
        Mock::given(method("POST"))
            .and(path("/api/cli/logout"))
            .respond_with(revocations.clone())
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &stored_credentials_at(&server.uri(), "2999-01-01T00:00:00.000Z"),
        )
        .unwrap();
        let client = reqwest::Client::new();

        assert_eq!(
            login_with(&client, &server.uri(), None, &credentials_path)
                .await
                .unwrap(),
            0
        );
        let mut stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(stored.token, "pcli_test-token-not-a-real-secret");
        assert_eq!(stored.pending_revocations.len(), 1);
        assert_eq!(
            stored.pending_revocations[0].refresh_token.as_deref(),
            Some("fixture-old-refresh-not-a-credential")
        );
        assert_eq!(stored.pending_revocations[0].issuer, server.uri());

        let _lock = credentials::CredentialLock::acquire(&credentials_path)
            .await
            .unwrap();
        assert_eq!(
            drain_pending_for_active_locked(
                ClientMode::Provided(&client),
                &credentials_path,
                &mut stored,
            )
            .await
            .unwrap(),
            0
        );
        assert!(
            credentials::read(&credentials_path)
                .unwrap()
                .unwrap()
                .pending_revocations
                .is_empty()
        );
        assert_eq!(revocations.calls.load(Ordering::SeqCst), 2);
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

    #[test]
    fn issuer_normalization_removes_default_ports_and_trailing_slashes() {
        assert_eq!(
            canonicalize_issuer(" HTTPS://Example.COM:443/auth/// ").unwrap(),
            "https://example.com/auth"
        );
        assert_eq!(
            canonicalize_issuer("http://Example.COM:80/").unwrap(),
            "http://example.com"
        );
    }

    #[tokio::test]
    async fn transient_logout_failure_preserves_the_revocation_handle() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/cli/logout"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        credentials::write(
            &credentials_path,
            &Credentials {
                version: credentials::CREDENTIALS_VERSION,
                issuer: Some(server.uri()),
                token: "pcli_test-token-not-a-real-secret".to_string(),
                expires_at: "2999-01-01T00:00:00.000Z".to_string(),
                refresh_token: Some("fixture-refresh-not-a-credential".to_string()),
                refresh_expires_at: Some("2999-12-01T00:00:00.000Z".to_string()),
                api_base: "https://postil.dev/api/inference/v1".to_string(),
                org: "runatlas-is".to_string(),
                model: "z-ai/glm-5.2".to_string(),
                pending_revocations: Vec::new(),
            },
        )
        .unwrap();

        let exit = logout_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
            .await
            .unwrap();
        assert_eq!(exit, 1);
        assert!(credentials_path.exists());
        let stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(
            stored.refresh_token.as_deref(),
            Some("fixture-refresh-not-a-credential")
        );
    }

    #[tokio::test]
    async fn explicit_issuer_conflict_sends_no_refresh_or_logout_credential() {
        let issuing_server = MockServer::start().await;
        let conflicting_server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials_at(&issuing_server.uri(), "2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();
        let client = reqwest::Client::new();
        let conflicting_issuer = format!("{}/", conflicting_server.uri());

        let refresh_error = resolve_stored_token_with_mode(
            ClientMode::Provided(&client),
            Some(&conflicting_issuer),
            &credentials_path,
            &original.api_base,
        )
        .await
        .expect_err("a conflicting issuer must stop refresh");
        let logout_error = logout_with_mode(
            ClientMode::Provided(&client),
            Some(&conflicting_issuer),
            &credentials_path,
        )
        .await
        .expect_err("a conflicting issuer must stop logout");

        assert!(refresh_error.to_string().contains(LOGIN_SERVER_ENV));
        assert!(refresh_error.to_string().contains("postil login"));
        assert!(logout_error.to_string().contains(LOGIN_SERVER_ENV));
        assert!(issuing_server.received_requests().await.unwrap().is_empty());
        assert!(
            conflicting_server
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn api_base_conflict_sends_no_stored_credential() {
        let issuing_server = MockServer::start().await;
        let other_api = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials_at(&issuing_server.uri(), "2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error = resolve_stored_token_with_mode(
            ClientMode::Provided(&reqwest::Client::new()),
            None,
            &credentials_path,
            &other_api.uri(),
        )
        .await
        .expect_err("a stored bearer must remain bound to its API base");

        let message = error.to_string();
        assert!(message.contains("bound to"));
        assert!(message.contains("explicit key"));
        assert!(issuing_server.received_requests().await.unwrap().is_empty());
        assert!(other_api.received_requests().await.unwrap().is_empty());
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
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
            &stored_credentials_at(&server.uri(), "2999-01-01T00:00:00.000Z"),
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
            issuer: Some(DEFAULT_LOGIN_SERVER.to_string()),
            token: "pcli_test-old-access-not-a-real-secret".to_string(),
            expires_at: expires_at.to_string(),
            refresh_token: Some("fixture-old-refresh-not-a-credential".to_string()),
            refresh_expires_at: Some("2999-12-01T00:00:00.000Z".to_string()),
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
            pending_revocations: Vec::new(),
        }
    }

    fn stored_credentials_at(issuer: &str, expires_at: &str) -> Credentials {
        let mut credentials = stored_credentials(expires_at);
        credentials.issuer = Some(canonicalize_issuer(issuer).unwrap());
        credentials
    }

    #[tokio::test]
    async fn alert_session_returns_one_renewable_issuer_token_generation() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let stored = stored_credentials("2999-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &stored).unwrap();

        let session = resolve_stored_alert_session(&credentials_path)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.issuer, DEFAULT_LOGIN_SERVER);
        assert_eq!(session.token, stored.token);
    }

    #[tokio::test]
    async fn alert_session_rejects_an_access_only_login() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut stored = stored_credentials("2999-01-01T00:00:00.000Z");
        stored.version = credentials::LEGACY_CREDENTIALS_VERSION;
        stored.issuer = None;
        stored.refresh_token = None;
        stored.refresh_expires_at = None;
        credentials::write(&credentials_path, &stored).unwrap();

        let error = resolve_stored_alert_session(&credentials_path)
            .await
            .expect_err("operator notifications require renewable credentials");
        assert!(error.to_string().contains("renewable login"));
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
            &stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z"),
        )
        .unwrap();

        let client = reqwest::Client::new();
        let resolved = resolve_stored_token_with_mode(
            ClientMode::Provided(&client),
            None,
            &credentials_path,
            "https://postil.dev/api/inference/v1",
        )
        .await
        .unwrap();
        assert_eq!(
            resolved.as_deref(),
            Some("pcli_test-new-access-not-a-real-secret")
        );
        let stored = credentials::read(&credentials_path).unwrap().unwrap();
        assert_eq!(stored.issuer.as_deref(), Some(server.uri().as_str()));
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
        credentials::write(
            &credentials_path,
            &stored_credentials_at(&server.uri(), &expires_at),
        )
        .unwrap();

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
            &stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z"),
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
        let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("a failed refresh must fail closed");
        assert!(error.to_string().contains("try again"));
        assert_eq!(token_resolution_retry_delay(&error), Some(Duration::ZERO));
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
        let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
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
        let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("a replayed refresh token must require login");
        assert!(error.to_string().contains("postil login"));
        assert_eq!(token_resolution_retry_delay(&error), None);
        assert!(!error.to_string().contains("refresh replay details"));
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn refresh_record_without_issuer_is_bound_to_the_public_default() {
        let override_server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy_refresh = stored_credentials("2020-01-01T00:00:00.000Z");
        legacy_refresh.version = credentials::LEGACY_REFRESH_CREDENTIALS_VERSION;
        legacy_refresh.issuer = None;
        credentials::write(&credentials_path, &legacy_refresh).unwrap();

        assert_eq!(
            stored_issuer(&legacy_refresh).unwrap(),
            DEFAULT_LOGIN_SERVER
        );
        let error = resolve_stored_token_with(
            &reqwest::Client::new(),
            &override_server.uri(),
            &credentials_path,
        )
        .await
        .expect_err("an old refresh credential must not follow an issuer override");

        assert!(error.to_string().contains(LOGIN_SERVER_ENV));
        assert!(error.to_string().contains("postil login"));
        assert!(
            override_server
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            legacy_refresh
        );
    }

    #[tokio::test]
    async fn custom_refresh_record_without_issuer_fails_before_network() {
        let custom_server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy_refresh = stored_credentials("2020-01-01T00:00:00.000Z");
        legacy_refresh.version = credentials::LEGACY_REFRESH_CREDENTIALS_VERSION;
        legacy_refresh.issuer = None;
        legacy_refresh.api_base = format!("{}/api/inference/v1", custom_server.uri());
        credentials::write(&credentials_path, &legacy_refresh).unwrap();

        let error = resolve_stored_token_with_mode(
            ClientMode::Provided(&reqwest::Client::new()),
            None,
            &credentials_path,
            &legacy_refresh.api_base,
        )
        .await
        .expect_err("an issuer-free custom refresh credential must require login");

        assert!(error.to_string().contains("no issuing server"));
        assert!(error.to_string().contains("postil login"));
        assert!(custom_server.received_requests().await.unwrap().is_empty());
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            legacy_refresh
        );
    }

    #[tokio::test]
    async fn custom_access_record_without_issuer_refuses_logout_before_network() {
        let custom_server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy_access = stored_credentials("2999-01-01T00:00:00.000Z");
        legacy_access.version = 1;
        legacy_access.issuer = None;
        legacy_access.refresh_token = None;
        legacy_access.refresh_expires_at = None;
        legacy_access.api_base = format!("{}/api/inference/v1", custom_server.uri());
        write_legacy_credentials(&credentials_path, &legacy_access);

        let error = logout_with_mode(
            ClientMode::Provided(&reqwest::Client::new()),
            None,
            &credentials_path,
        )
        .await
        .expect_err("an issuer-free custom access credential must require login");

        assert!(error.to_string().contains("no issuing server"));
        assert!(error.to_string().contains("postil login"));
        assert!(custom_server.received_requests().await.unwrap().is_empty());
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            legacy_access
        );
    }

    #[tokio::test]
    async fn expired_v1_login_requires_relogin() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let mut legacy = stored_credentials("2020-01-01T00:00:00.000Z");
        legacy.version = 1;
        legacy.issuer = None;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        write_legacy_credentials(&credentials_path, &legacy);

        let error = resolve_stored_token_with(
            &reqwest::Client::new(),
            DEFAULT_LOGIN_SERVER,
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
        legacy.issuer = None;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        write_legacy_credentials(&credentials_path, &legacy);

        let resolved = resolve_stored_token_with(
            &reqwest::Client::new(),
            "https://self-hosted.example.test",
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
            DEFAULT_LOGIN_SERVER,
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
            &stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z"),
        )
        .unwrap();

        let client = reqwest::Client::new();
        logout_with_mode(ClientMode::Provided(&client), None, &credentials_path)
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
        let mut legacy = stored_credentials_at(&server.uri(), "2999-01-01T00:00:00.000Z");
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
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "3527")
                    .set_body_string("retry later"),
            )
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
        credentials::write(&credentials_path, &original).unwrap();

        let error =
            resolve_stored_token_with(&reqwest::Client::new(), &server.uri(), &credentials_path)
                .await
                .expect_err("rate-limited refreshes must fail closed without relogin");
        assert!(error.to_string().contains("retry after 3527 seconds"));
        assert!(!error.to_string().contains("run `postil login` again"));
        assert_eq!(
            token_resolution_retry_delay(&error),
            Some(Duration::from_secs(3527))
        );
        assert_eq!(
            credentials::read(&credentials_path).unwrap().unwrap(),
            original
        );
    }

    #[tokio::test]
    async fn malformed_or_missing_retry_after_uses_a_safe_generic_error() {
        for retry_after in [None, Some("tomorrow"), Some("18446744073709551616")] {
            let server = MockServer::start().await;
            let response = ResponseTemplate::new(429).set_body_string("retry later");
            let response = match retry_after {
                Some(value) => response.insert_header("Retry-After", value),
                None => response,
            };
            Mock::given(method("POST"))
                .and(path("/api/cli/token/refresh"))
                .respond_with(response)
                .mount(&server)
                .await;
            let dir = tempfile::tempdir().unwrap();
            let credentials_path = dir.path().join("postil").join("credentials.json");
            let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
            credentials::write(&credentials_path, &original).unwrap();

            let error = resolve_stored_token_with(
                &reqwest::Client::new(),
                &server.uri(),
                &credentials_path,
            )
            .await
            .expect_err("an unusable Retry-After must fail safely");
            assert!(error.to_string().contains("try again"));
            assert_eq!(token_resolution_retry_delay(&error), Some(Duration::ZERO));
            assert!(!error.to_string().contains("retry after"));
            assert_eq!(
                credentials::read(&credentials_path).unwrap().unwrap(),
                original
            );
        }
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
        let original = stored_credentials_at(&server.uri(), "2020-01-01T00:00:00.000Z");
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
        let original =
            stored_credentials_at(&format!("http://{address}"), "2020-01-01T00:00:00.000Z");
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
