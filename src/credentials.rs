//! Stored `postil login` credentials.
//!
//! Lives outside any repository, at
//! `${XDG_CONFIG_HOME:-~/.config}/postil/credentials.json`, because it is a
//! developer secret bound to one machine, not project configuration. The
//! bearer token inside spends an organization's hosted-inference
//! entitlement, so both the containing directory (0700) and the file itself
//! (0600) get their final permission bits set at creation time, never
//! `chmod`'d afterward, so there is no window where the token is briefly
//! world-readable.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

pub const CREDENTIALS_VERSION: u32 = 3;
pub const LEGACY_CREDENTIALS_VERSION: u32 = 1;
pub const LEGACY_REFRESH_CREDENTIALS_VERSION: u32 = 2;
const PENDING_REVOCATIONS_VERSION: u32 = 1;
const ALERT_CURSOR_VERSION: u32 = 1;
const POSTGRES_MAX_SEQUENCE: u64 = i64::MAX as u64;
// The refresh exchange has separately bounded send and body-read phases. A
// second local process waits long enough for both before asking the caller to
// retry, so concurrent agent runs converge on one token rotation.
const CREDENTIAL_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(45);
const CREDENTIAL_LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRevocation {
    pub issuer: String,
    pub token: String,
    #[serde(
        default,
        rename = "refreshToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(
        default,
        rename = "refreshToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_token: Option<String>,
    #[serde(
        default,
        rename = "refreshExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_expires_at: Option<String>,
    #[serde(rename = "apiBase")]
    pub api_base: String,
    pub org: String,
    pub model: String,
    #[serde(
        default,
        rename = "pendingRevocations",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub pending_revocations: Vec<PendingRevocation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingRevocations {
    version: u32,
    revocations: Vec<PendingRevocation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlertCursor {
    version: u32,
    issuer: String,
    sequence: u64,
}

impl Credentials {
    /// Fails closed: an `expiresAt` that will not parse is treated as
    /// already expired rather than trusted, so a corrupted file never grants
    /// silent access.
    pub fn is_expired(&self) -> bool {
        self.expires_within(std::time::Duration::ZERO)
    }

    pub fn expires_within(&self, margin: std::time::Duration) -> bool {
        let Ok(margin) = time::Duration::try_from(margin) else {
            return true;
        };
        match parse_timestamp(&self.expires_at) {
            Ok(expires_at) => expires_at <= time::OffsetDateTime::now_utc() + margin,
            Err(_) => true,
        }
    }

    pub fn refresh_is_expired(&self) -> bool {
        match self.refresh_expires_at.as_deref().map(parse_timestamp) {
            Some(Ok(expires_at)) => expires_at <= time::OffsetDateTime::now_utc(),
            Some(Err(_)) | None => true,
        }
    }

    pub fn can_refresh(&self) -> bool {
        self.refresh_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty())
            && !self.refresh_is_expired()
    }
}

fn parse_timestamp(value: &str) -> Result<time::OffsetDateTime, time::error::Parse> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
}

/// The real, XDG-resolved path used by `postil login`/`postil logout` and by
/// runtime credential resolution. `dirs::config_dir()` is deliberately not
/// used here: on macOS it resolves to `~/Library/Application Support`, but
/// the login contract fixes the location at `${XDG_CONFIG_HOME:-~/.config}`
/// on every platform, matching how other developer CLIs (not just desktop
/// apps) place their config on a Mac. Tests exercise `read`/`write`/`remove`
/// directly against a temp-directory path instead of calling this, so
/// nothing about credential handling itself depends on process-wide state.
pub fn default_path() -> Result<PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .context("cannot determine a config directory: set XDG_CONFIG_HOME or HOME")?;
    Ok(config_dir.join("postil").join("credentials.json"))
}

/// `Ok(None)` when no credential is stored yet; `Err` only for a file that
/// exists but cannot be read or parsed.
pub fn read(path: &Path) -> Result<Option<Credentials>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let credentials: Credentials =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    anyhow::ensure!(
        matches!(
            credentials.version,
            LEGACY_CREDENTIALS_VERSION | LEGACY_REFRESH_CREDENTIALS_VERSION | CREDENTIALS_VERSION
        ),
        "unsupported credentials version {}; run `postil login` again",
        credentials.version
    );
    anyhow::ensure!(
        credentials.version != CREDENTIALS_VERSION
            || credentials
                .issuer
                .as_deref()
                .is_some_and(|issuer| !issuer.trim().is_empty()),
        "credentials version {} is missing its issuer; run `postil login` again",
        credentials.version
    );
    Ok(Some(credentials))
}

/// Writes atomically: the temp file is created with its final permission
/// bits already set, filled, `fsync`'d, then renamed into place, so a reader
/// never observes a partially written or briefly world-readable file.
pub fn write(path: &Path, credentials: &Credentials) -> Result<()> {
    anyhow::ensure!(
        matches!(
            credentials.version,
            LEGACY_CREDENTIALS_VERSION | LEGACY_REFRESH_CREDENTIALS_VERSION | CREDENTIALS_VERSION
        ),
        "unsupported credentials version {}",
        credentials.version
    );
    anyhow::ensure!(
        credentials.version != CREDENTIALS_VERSION
            || credentials
                .issuer
                .as_deref()
                .is_some_and(|issuer| !issuer.trim().is_empty()),
        "credentials version {} is missing its issuer",
        credentials.version
    );
    write_private_json(path, credentials, "credentials")
}

pub fn read_pending(credentials_path: &Path) -> Result<Vec<PendingRevocation>> {
    let path = pending_path(credentials_path)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    let pending: PendingRevocations =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    anyhow::ensure!(
        pending.version == PENDING_REVOCATIONS_VERSION,
        "unsupported pending revocations version {}",
        pending.version
    );
    Ok(pending.revocations)
}

pub fn write_pending(credentials_path: &Path, revocations: &[PendingRevocation]) -> Result<()> {
    let path = pending_path(credentials_path)?;
    if revocations.is_empty() {
        return remove(&path);
    }
    write_private_json(
        &path,
        &PendingRevocations {
            version: PENDING_REVOCATIONS_VERSION,
            revocations: revocations.to_vec(),
        },
        "pending revocations",
    )
}

pub fn read_alert_cursor(credentials_path: &Path, issuer: &str) -> Result<Option<u64>> {
    let path = alert_cursor_path(credentials_path)?;
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let cursor: AlertCursor =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    anyhow::ensure!(
        cursor.version == ALERT_CURSOR_VERSION,
        "unsupported operator alert cursor version {}",
        cursor.version
    );
    anyhow::ensure!(
        cursor.sequence <= POSTGRES_MAX_SEQUENCE,
        "operator alert cursor sequence is out of range"
    );
    if cursor.issuer != issuer {
        return Ok(None);
    }
    Ok(Some(cursor.sequence))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertCursorDelivery {
    Delivered(u64),
    AlreadyRecorded(u64),
    SessionChanged,
}

/// Delivers one alert and advances its cursor while holding the stored-login
/// lock. Delivery is intentionally at-least-once: a crash after the callback
/// flushes but before the cursor rename can replay the alert, while advancing
/// first could silently lose it.
pub async fn deliver_alert_with_cursor<F>(
    credentials_path: &Path,
    issuer: &str,
    expected_token: &str,
    sequence: u64,
    deliver: F,
) -> Result<AlertCursorDelivery>
where
    F: FnOnce() -> Result<()>,
{
    anyhow::ensure!(
        sequence <= POSTGRES_MAX_SEQUENCE,
        "operator alert cursor sequence is out of range"
    );
    let _lock = CredentialLock::acquire(credentials_path).await?;
    let Some(active) = read(credentials_path)? else {
        return Ok(AlertCursorDelivery::SessionChanged);
    };
    if active.version != CREDENTIALS_VERSION
        || active.issuer.as_deref() != Some(issuer)
        || active.token != expected_token
        || !active.can_refresh()
    {
        return Ok(AlertCursorDelivery::SessionChanged);
    }
    if let Some(current) = read_alert_cursor(credentials_path, issuer)?
        && current >= sequence
    {
        return Ok(AlertCursorDelivery::AlreadyRecorded(current));
    }
    deliver()?;
    let path = alert_cursor_path(credentials_path)?;
    write_private_json(
        &path,
        &AlertCursor {
            version: ALERT_CURSOR_VERSION,
            issuer: issuer.to_string(),
            sequence,
        },
        "operator alert cursor",
    )?;
    Ok(AlertCursorDelivery::Delivered(sequence))
}

fn pending_path(credentials_path: &Path) -> Result<PathBuf> {
    let parent = credentials_path
        .parent()
        .context("credentials path must have a parent directory")?;
    Ok(parent.join("pending-revocations.json"))
}

fn alert_cursor_path(credentials_path: &Path) -> Result<PathBuf> {
    let parent = credentials_path
        .parent()
        .context("credentials path must have a parent directory")?;
    Ok(parent.join("operator-alert-cursor.json"))
}

fn write_private_json<T: Serialize>(path: &Path, value: &T, description: &str) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{description} path must have a parent directory"))?;
    create_private_dir(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{description} path must have a file name"))?;
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp_path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temp_path)
            .with_context(|| format!("creating private {description} file"))?;
        serde_json::to_writer_pretty(&mut file, value)
            .with_context(|| format!("serializing {description}"))?;
        file.write_all(b"\n")
            .with_context(|| format!("writing {description}"))?;
        file.sync_all()
            .with_context(|| format!("syncing {description}"))?;
        fs::rename(&temp_path, path).with_context(|| format!("installing {description} file"))?;
        sync_parent_dir(parent).with_context(|| format!("syncing {description} directory"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> Result<()> {
    Ok(())
}

/// A kernel-backed, cross-process lock shared by every stored-login mutation.
/// Keeping the lock file in place avoids stale-file recovery: the operating
/// system releases the exclusive lock when the handle closes or its process
/// exits.
pub struct CredentialLock {
    _file: File,
}

/// A singleton lock held for the lifetime of one operator alert watcher.
pub struct AlertWatchLock {
    _file: File,
}

impl AlertWatchLock {
    pub fn acquire(credentials_path: &Path) -> Result<Self> {
        let parent = credentials_path
            .parent()
            .context("credentials path must have a parent directory")?;
        create_private_dir(parent)?;
        let path = parent.join(".operator-alert-watch.lock");
        let file = open_private_lock_file(&path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { _file: file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::bail!("another postil operator alert watcher is already running")
            }
            Err(error) => Err(error).context("locking operator alert watcher"),
        }
    }
}

impl CredentialLock {
    pub async fn acquire(credentials_path: &Path) -> Result<Self> {
        let parent = credentials_path
            .parent()
            .context("credentials path must have a parent directory")?;
        create_private_dir(parent)?;
        let file_name = credentials_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("credentials path must have a file name")?;
        let path = parent.join(format!(".{file_name}.refresh.lock"));
        let file = open_private_lock_file(&path)?;
        let deadline = tokio::time::Instant::now() + CREDENTIAL_LOCK_WAIT;

        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if tokio::time::Instant::now() >= deadline {
                        anyhow::bail!(
                            "another postil process is updating the stored login; try again"
                        );
                    }
                    tokio::time::sleep(CREDENTIAL_LOCK_RETRY).await;
                }
                Err(error) => return Err(error).context("locking stored login"),
            }
        }
    }
}

fn open_private_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).context("creating stored login lock")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        file.set_permissions(permissions)
            .context("securing stored login lock")?;
    }
    Ok(file)
}
/// Idempotent: removing an already-absent file is success, matching the
/// server-side logout endpoint's own idempotence.
pub fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(expires_at: &str) -> Credentials {
        Credentials {
            version: CREDENTIALS_VERSION,
            issuer: Some("https://postil.dev".to_string()),
            token: "pcli_test-token-not-a-real-secret".to_string(),
            expires_at: expires_at.to_string(),
            refresh_token: Some("fixture-refresh-not-a-credential".to_string()),
            refresh_expires_at: Some("2999-01-01T00:00:00.000Z".to_string()),
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
            pending_revocations: Vec::new(),
        }
    }

    #[test]
    fn round_trips_through_a_temp_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        let credentials = sample("2999-01-01T00:00:00.000Z");
        write(&path, &credentials).unwrap();
        let read_back = read(&path).unwrap().expect("credentials were written");
        assert_eq!(read_back, credentials);
    }

    #[test]
    fn read_of_a_missing_file_is_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        assert!(read(&path).unwrap().is_none());
    }

    #[test]
    fn remove_of_a_missing_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        remove(&path).unwrap();
    }

    #[test]
    fn remove_deletes_a_written_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        write(&path, &sample("2999-01-01T00:00:00.000Z")).unwrap();
        assert!(path.exists());
        remove(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn written_file_has_owner_only_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        write(&path, &sample("2999-01-01T00:00:00.000Z")).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "credentials file must be mode 0600, got {mode:o}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn created_directory_has_owner_only_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let credentials_dir = dir.path().join("postil");
        let path = credentials_dir.join("credentials.json");
        write(&path, &sample("2999-01-01T00:00:00.000Z")).unwrap();
        let mode = fs::metadata(&credentials_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "credentials directory must be mode 0700, got {mode:o}"
        );
    }

    #[test]
    fn future_expiry_is_not_expired() {
        assert!(!sample("2999-01-01T00:00:00.000Z").is_expired());
    }

    #[test]
    fn past_expiry_is_expired() {
        assert!(sample("2020-01-01T00:00:00.000Z").is_expired());
    }

    #[test]
    fn unparsable_expiry_fails_closed_as_expired() {
        assert!(sample("not-a-timestamp").is_expired());
    }
    #[test]
    fn reads_a_v1_access_only_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        fs::write(
            &path,
            r#"{"version":1,"token":"pcli_test-token-not-a-real-secret","expiresAt":"2999-01-01T00:00:00.000Z","apiBase":"https://postil.dev/api/inference/v1","org":"runatlas-is","model":"z-ai/glm-5.2"}"#,
        )
        .unwrap();
        let credentials = read(&path).unwrap().unwrap();
        assert_eq!(credentials.version, 1);
        assert!(credentials.issuer.is_none());
        assert!(credentials.refresh_token.is_none());
        assert!(credentials.refresh_expires_at.is_none());
        assert!(credentials.pending_revocations.is_empty());
    }

    #[test]
    fn reads_a_v2_refresh_credential_without_an_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        fs::write(
            &path,
            r#"{"version":2,"token":"pcli_test-token-not-a-real-secret","expiresAt":"2999-01-01T00:00:00.000Z","refreshToken":"fixture-refresh-not-a-credential","refreshExpiresAt":"2999-12-01T00:00:00.000Z","apiBase":"https://postil.dev/api/inference/v1","org":"runatlas-is","model":"z-ai/glm-5.2"}"#,
        )
        .unwrap();
        let credentials = read(&path).unwrap().unwrap();
        assert_eq!(credentials.version, LEGACY_REFRESH_CREDENTIALS_VERSION);
        assert!(credentials.issuer.is_none());
        assert!(credentials.can_refresh());
    }

    #[test]
    fn rejects_a_current_refresh_credential_without_an_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        fs::write(
            &path,
            format!(
                r#"{{"version":{CREDENTIALS_VERSION},"token":"pcli_test-token-not-a-real-secret","expiresAt":"2999-01-01T00:00:00.000Z","refreshToken":"fixture-refresh-not-a-credential","refreshExpiresAt":"2999-12-01T00:00:00.000Z","apiBase":"https://postil.dev/api/inference/v1","org":"runatlas-is","model":"z-ai/glm-5.2"}}"#
            ),
        )
        .unwrap();

        let error = read(&path).expect_err("current credentials must carry their issuer");
        assert!(error.to_string().contains("missing its issuer"));
        assert!(error.to_string().contains("postil login"));
    }

    #[test]
    fn preserves_v1_for_an_access_only_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("postil").join("credentials.json");
        let mut credentials = sample("2999-01-01T00:00:00.000Z");
        credentials.version = 1;
        credentials.issuer = None;
        credentials.refresh_token = None;
        credentials.refresh_expires_at = None;
        write(&path, &credentials).unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("\"version\": 1"));
        assert!(!raw.contains("refreshToken"));
        assert!(!raw.contains("issuer"));
    }

    #[test]
    fn rejects_unknown_future_credential_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let mut credentials = sample("2999-01-01T00:00:00.000Z");
        credentials.version = CREDENTIALS_VERSION + 1;
        fs::write(&path, serde_json::to_string(&credentials).unwrap()).unwrap();
        let error = read(&path).expect_err("future credential versions must fail closed");
        assert!(
            error
                .to_string()
                .contains("unsupported credentials version")
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stored_login_lock_file_has_owner_only_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        write(&credentials_path, &sample("2999-01-01T00:00:00.000Z")).unwrap();
        let lock = CredentialLock::acquire(&credentials_path).await.unwrap();
        drop(lock);
        let lock_path = credentials_path
            .parent()
            .unwrap()
            .join(".credentials.json.refresh.lock");
        let mode = fs::metadata(lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "stored login lock file must be mode 0600, got {mode:o}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn pending_revocations_are_private_and_atomically_replaced() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let first = PendingRevocation {
            issuer: "https://postil.dev".to_string(),
            token: "pcli_first-access-not-a-real-secret".to_string(),
            refresh_token: Some("fixture-first-refresh-not-a-credential".to_string()),
        };
        let replacement = PendingRevocation {
            issuer: "https://login.example.test".to_string(),
            token: "pcli_second-access-not-a-real-secret".to_string(),
            refresh_token: None,
        };

        write_pending(&credentials_path, std::slice::from_ref(&first)).unwrap();
        write_pending(&credentials_path, std::slice::from_ref(&replacement)).unwrap();

        assert_eq!(read_pending(&credentials_path).unwrap(), vec![replacement]);
        let pending_path = credentials_path
            .parent()
            .unwrap()
            .join("pending-revocations.json");
        let mode = fs::metadata(&pending_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "pending revocations file must be mode 0600, got {mode:o}"
        );
        let temp_name = format!(".pending-revocations.json.{}.tmp", std::process::id());
        assert!(!pending_path.parent().unwrap().join(temp_name).exists());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn operator_alert_cursor_is_private_atomic_monotonic_and_issuer_bound() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let stored = sample("2999-01-01T00:00:00.000Z");
        let token = stored.token.clone();
        write(&credentials_path, &stored).unwrap();
        let deliveries = std::cell::Cell::new(0_u32);
        assert_eq!(
            deliver_alert_with_cursor(&credentials_path, "https://postil.dev", &token, 41, || {
                deliveries.set(deliveries.get() + 1);
                Ok(())
            })
            .await
            .unwrap(),
            AlertCursorDelivery::Delivered(41)
        );
        assert_eq!(
            deliver_alert_with_cursor(&credentials_path, "https://postil.dev", &token, 42, || {
                deliveries.set(deliveries.get() + 1);
                Ok(())
            })
            .await
            .unwrap(),
            AlertCursorDelivery::Delivered(42)
        );
        assert_eq!(
            deliver_alert_with_cursor(&credentials_path, "https://postil.dev", &token, 40, || {
                deliveries.set(deliveries.get() + 1);
                Ok(())
            })
            .await
            .unwrap(),
            AlertCursorDelivery::AlreadyRecorded(42)
        );
        assert_eq!(
            deliver_alert_with_cursor(
                &credentials_path,
                "https://other.example.test",
                &token,
                43,
                || {
                    deliveries.set(deliveries.get() + 1);
                    Ok(())
                },
            )
            .await
            .unwrap(),
            AlertCursorDelivery::SessionChanged
        );
        let mut replacement = stored.clone();
        replacement.token = "pcli_replacement-access-not-a-real-secret".to_string();
        write(&credentials_path, &replacement).unwrap();
        assert_eq!(
            deliver_alert_with_cursor(&credentials_path, "https://postil.dev", &token, 43, || {
                deliveries.set(deliveries.get() + 1);
                Ok(())
            })
            .await
            .unwrap(),
            AlertCursorDelivery::SessionChanged
        );
        assert_eq!(deliveries.get(), 2);

        assert_eq!(
            read_alert_cursor(&credentials_path, "https://postil.dev").unwrap(),
            Some(42)
        );
        assert_eq!(
            read_alert_cursor(&credentials_path, "https://other.example.test").unwrap(),
            None
        );
        let cursor_path = credentials_path
            .parent()
            .unwrap()
            .join("operator-alert-cursor.json");
        let mode = fs::metadata(&cursor_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let temp_name = format!(".operator-alert-cursor.json.{}.tmp", std::process::id());
        assert!(!cursor_path.parent().unwrap().join(temp_name).exists());
    }

    #[tokio::test]
    async fn operator_alert_cursor_rejects_out_of_range_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        assert!(
            deliver_alert_with_cursor(
                &credentials_path,
                "https://postil.dev",
                "unused",
                i64::MAX as u64 + 1,
                || Ok(())
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn operator_alert_cursor_compares_and_writes_while_holding_the_login_lock() {
        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let stored = sample("2999-01-01T00:00:00.000Z");
        let token = stored.token.clone();
        write(&credentials_path, &stored).unwrap();
        deliver_alert_with_cursor(&credentials_path, "https://postil.dev", &token, 41, || {
            Ok(())
        })
        .await
        .unwrap();

        let held_lock = CredentialLock::acquire(&credentials_path).await.unwrap();
        let waiting_path = credentials_path.clone();
        let waiting_token = token.clone();
        let deliveries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waiting_deliveries = deliveries.clone();
        let waiting_write = tokio::spawn(async move {
            deliver_alert_with_cursor(
                &waiting_path,
                "https://postil.dev",
                &waiting_token,
                42,
                move || {
                    waiting_deliveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                },
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        assert!(!waiting_write.is_finished());

        write_private_json(
            &alert_cursor_path(&credentials_path).unwrap(),
            &AlertCursor {
                version: ALERT_CURSOR_VERSION,
                issuer: "https://postil.dev".to_string(),
                sequence: 43,
            },
            "operator alert cursor",
        )
        .unwrap();
        drop(held_lock);
        assert_eq!(
            waiting_write.await.unwrap().unwrap(),
            AlertCursorDelivery::AlreadyRecorded(43)
        );
        assert_eq!(deliveries.load(std::sync::atomic::Ordering::Relaxed), 0);

        assert_eq!(
            read_alert_cursor(&credentials_path, "https://postil.dev").unwrap(),
            Some(43)
        );
    }

    #[test]
    #[cfg(unix)]
    fn operator_alert_watcher_lock_is_private_and_singleton() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let credentials_path = dir.path().join("postil").join("credentials.json");
        let first = AlertWatchLock::acquire(&credentials_path).unwrap();
        assert!(AlertWatchLock::acquire(&credentials_path).is_err());
        let path = credentials_path
            .parent()
            .unwrap()
            .join(".operator-alert-watch.lock");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(first);
        AlertWatchLock::acquire(&credentials_path).unwrap();
    }
}
