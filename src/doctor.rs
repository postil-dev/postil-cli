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
    let stored_login = credentials_path
        .as_ref()
        .ok()
        .and_then(|path| credentials::read(path).ok().flatten());
    checks.push(Check {
        name: "login",
        ok: stored_login.as_ref().is_none_or(|c| !c.is_expired()),
        detail: match &stored_login {
            None => "not logged in; `postil login` gives zero-config hosted inference".to_string(),
            Some(c) if c.is_expired() => format!(
                "credential for org {} expired at {}; run `postil login` again",
                c.org, c.expires_at
            ),
            Some(c) => format!("logged in to org {} (expires {})", c.org, c.expires_at),
        },
    });

    let key_names = api_key::names_text();
    let key_lookup = credentials_path
        .as_ref()
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .and_then(|path| api_key::resolve_effective(path));
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
