//! `postil doctor`: validate the whole setup with actionable messages.
//!
//! The anti-goal is the silently-misconfigured self-hosted reviewer: wrong env
//! var, unreachable endpoint, model name typo — discovered only when a review
//! silently does nothing. Doctor checks each link in the chain and says
//! exactly what to fix. Secret values are never printed.

use crate::api_key;
use crate::config::Config;
use crate::credentials;
use crate::llm::LlmClient;
use crate::login;
use anyhow::Result;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

pub async fn run(cfg: &Config) -> Result<Vec<Check>> {
    let mut checks = Vec::new();

    checks.push(Check {
        name: "config",
        ok: true,
        detail: format!(
            "loaded from {} (model: {}, gate failOn: {}, minConfidence: {})",
            cfg.source,
            cfg.model,
            cfg.gate_fail_on.as_str(),
            cfg.min_confidence
        ),
    });

    let git_ok = tokio::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    checks.push(Check {
        name: "git",
        ok: git_ok,
        detail: if git_ok {
            "inside a git work tree".to_string()
        } else {
            "not a git repository (local modes --staged/--base need one)".to_string()
        },
    });

    let credentials_path = credentials::default_path();
    checks.push(match credentials_path.as_ref() {
        Ok(path) => login_status_at(path),
        Err(error) => {
            login_status_error(format!("cannot inspect the stored login path: {error:#}"))
        }
    });

    let key_names = api_key::names_text();
    let key_lookup = if let Some(key) = api_key::resolve_from_process_env() {
        Ok(Some(key))
    } else {
        match credentials_path.as_ref() {
            Ok(path) => login::resolve_stored_token(path, &cfg.api_base).await,
            Err(error) => Err(anyhow::anyhow!("{error:#}")),
        }
    };
    let (key_ok, key_detail, key) = match key_lookup {
        Ok(Some(k)) => (
            true,
            format!("resolved from {key_names}, or a stored login credential (value not shown)"),
            Some(k),
        ),
        Ok(None) => (
            false,
            format!("set {key_names}, or run `postil login`; Postil never proxies inference"),
            None,
        ),
        Err(e) => (false, format!("{e:#}"), None),
    };
    checks.push(Check {
        name: "api key",
        ok: key_ok,
        detail: key_detail,
    });

    // Live probe: a 1-token response proves base URL + key + model + selected
    // API format in one shot. LlmClient also applies optional endpoint auth and
    // redacts both secrets from any provider error body.
    if let Some(key) = key {
        let (ok, detail) = match LlmClient::doctor_probe(cfg, key).await {
            Ok(()) => (
                true,
                format!(
                    "{} answered for model {} using {}",
                    cfg.api_base,
                    cfg.model,
                    cfg.api_format.as_str()
                ),
            ),
            Err(error) => (
                false,
                format!(
                    "cannot use {} as {} ({error:#}); check model.apiBase, model.apiFormat, credentials, and model name",
                    cfg.api_base,
                    cfg.api_format.as_str()
                ),
            ),
        };
        checks.push(Check {
            name: "model endpoint",
            ok,
            detail,
        });
    }

    let gh = std::env::var("GITHUB_TOKEN").is_ok();
    let gl = std::env::var("GITLAB_TOKEN").is_ok();
    checks.push(Check {
        name: "forge tokens",
        ok: true,
        detail: format!(
            "presence only: GITHUB_TOKEN {}, GITLAB_TOKEN {} (only needed for remote review)",
            if gh { "set" } else { "unset" },
            if gl { "set" } else { "unset" }
        ),
    });

    Ok(checks)
}

/// The non-secret login state shown by both `postil doctor` and `postil
/// config`. It deliberately reads without refreshing so configuration
/// inspection never rotates a credential.
pub fn login_status() -> Check {
    match credentials::default_path() {
        Ok(path) => login_status_at(&path),
        Err(error) => {
            login_status_error(format!("cannot inspect the stored login path: {error:#}"))
        }
    }
}

fn login_status_error(detail: String) -> Check {
    Check {
        name: "login",
        ok: false,
        detail,
    }
}

fn login_status_at(credentials_path: &std::path::Path) -> Check {
    let stored_login = match credentials::read(credentials_path) {
        Ok(stored_login) => stored_login,
        Err(error) => {
            return login_status_error(format!(
                "stored login is unreadable; run `postil login` again ({error:#})"
            ));
        }
    };
    match stored_login {
        None => Check {
            name: "login",
            ok: true,
            detail: "not logged in; `postil login` gives zero-config hosted inference".to_string(),
        },
        Some(c) if c.refresh_token.is_none() && c.refresh_expires_at.is_none() => Check {
            name: "login",
            ok: !c.is_expired(),
            detail: if c.is_expired() {
                format!(
                    "legacy access-only login for org {} expired at {}; run `postil login` again",
                    c.org, c.expires_at
                )
            } else {
                format!(
                    "legacy access-only login for org {} (access expires {})",
                    c.org, c.expires_at
                )
            },
        },
        Some(c) if !c.can_refresh() => Check {
            name: "login",
            ok: false,
            detail: format!(
                "renewable login for org {} has refresh inactivity expiry {}; run `postil login` again",
                c.org,
                c.refresh_expires_at
                    .as_deref()
                    .unwrap_or("that is missing or invalid")
            ),
        },
        Some(c) => Check {
            name: "login",
            ok: true,
            detail: format!(
                "renewable login for org {} (access expires {}; refresh inactivity expires {})",
                c.org,
                c.expires_at,
                c.refresh_expires_at
                    .as_deref()
                    .expect("renewable login has an expiry")
            ),
        },
    }
}

pub fn print_report(checks: &[Check]) -> bool {
    let mut all_ok = true;
    for c in checks {
        let mark = if c.ok { "ok  " } else { "FAIL" };
        eprintln!("[{mark}] {:<16} {}", c.name, c.detail);
        all_ok &= c.ok;
    }
    if all_ok {
        eprintln!("\npostil doctor: ready.");
    } else {
        eprintln!("\npostil doctor: fix the failures above and re-run.");
    }
    all_ok
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, Credentials};

    fn stored_login() -> Credentials {
        Credentials {
            version: credentials::CREDENTIALS_VERSION,
            issuer: Some("https://postil.dev".to_string()),
            token: "pcli_test-access-not-a-real-secret".to_string(),
            expires_at: "2999-01-01T00:00:00.000Z".to_string(),
            refresh_token: Some("fixture-refresh-not-a-credential".to_string()),
            refresh_expires_at: Some("2999-12-01T00:00:00.000Z".to_string()),
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
            pending_revocations: Vec::new(),
        }
    }

    #[test]
    fn status_distinguishes_a_renewable_login_and_its_expiries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        credentials::write(&path, &stored_login()).unwrap();
        let check = login_status_at(&path);
        assert!(check.ok);
        assert!(check.detail.contains("renewable login"));
        assert!(check.detail.contains("access expires"));
        assert!(check.detail.contains("refresh inactivity expires"));
    }

    #[test]
    fn status_distinguishes_a_legacy_access_only_login() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let mut legacy = stored_login();
        legacy.version = 1;
        legacy.refresh_token = None;
        legacy.refresh_expires_at = None;
        credentials::write(&path, &legacy).unwrap();
        let check = login_status_at(&path);
        assert!(check.ok);
        assert!(check.detail.contains("legacy access-only"));
    }

    #[test]
    fn status_reports_refresh_inactivity_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let mut expired = stored_login();
        expired.refresh_expires_at = Some("2020-01-01T00:00:00.000Z".to_string());
        credentials::write(&path, &expired).unwrap();
        let check = login_status_at(&path);
        assert!(!check.ok);
        assert!(check.detail.contains("refresh inactivity expiry"));
    }

    #[test]
    fn unreadable_login_is_unhealthy_without_exposing_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        std::fs::write(&path, "private credential contents that are not JSON").unwrap();

        let check = login_status_at(&path);

        assert!(!check.ok);
        assert!(check.detail.contains("stored login is unreadable"));
        assert!(check.detail.contains("postil login"));
        assert!(!check.detail.contains("private credential contents"));
    }
}
