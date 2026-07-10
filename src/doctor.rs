//! `postil doctor`: validate the whole setup with actionable messages.
//!
//! The anti-goal is the silently-misconfigured self-hosted reviewer: wrong env
//! var, unreachable endpoint, model name typo — discovered only when a review
//! silently does nothing. Doctor checks each link in the chain and says
//! exactly what to fix. Secret values are never printed.

use anyhow::Result;
use serde_json::json;

use crate::api_key;
use crate::config::Config;

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

    let key = api_key::resolve_from_process_env();
    let key_names = api_key::names_text();
    checks.push(Check {
        name: "api key",
        ok: key.is_some(),
        detail: match &key {
            Some(_) => format!("{key_names} is set (value not shown)"),
            None => format!("set {key_names}; Postil never proxies inference"),
        },
    });

    // Live probe: a 1-token completion proves base URL + key + model in one shot.
    if let Some(key) = key {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let url = format!("{}/chat/completions", cfg.api_base.trim_end_matches('/'));
        let resp = http
            .post(&url)
            .bearer_auth(&key)
            .json(&json!({
                "model": cfg.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            }))
            .send()
            .await;
        let (ok, detail) = match resp {
            Ok(r) if r.status().is_success() => (
                true,
                format!("{} answered for model {}", cfg.api_base, cfg.model),
            ),
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(200).collect();
                let hint = match status.as_u16() {
                    401 | 403 => " (key rejected: wrong key for this endpoint?)",
                    404 => " (404: wrong apiBase path or unknown model name?)",
                    _ => "",
                };
                (false, format!("{status}{hint}: {snippet}"))
            }
            Err(e) => (
                false,
                format!(
                    "cannot reach {} ({e}); check model.apiBase — for Ollama use http://localhost:11434/v1",
                    cfg.api_base
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
