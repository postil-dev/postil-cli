//! Review orchestration. The only top-level "what does Postil do" function.
//!
//! Flow:
//!   1. Resolve source (PR / staged / base / file).
//!   2. Fetch the unified diff. Truncate to `diff_limit`.
//!   3. Load per-repo config (from the head SHA on remote, working tree on
//!      local). Build the system prompt from doctrine + reviewer hints.
//!   4. Create the GitHub check-run if remote and not pre-created.
//!   5. Call OpenRouter with the model cascade. JSON-repair once on bad
//!      output; if everything fails, synthesise a fail-closed envelope.
//!   6. Post-filter findings against repo policy and diff grounding.
//!   7. Post inline review (or APPROVE on clean if `onClean: approve`).
//!   8. Complete the check-run with the envelope-derived conclusion.
//!   9. Write `--output-json` if requested.
//!  10. Return the exit code for `fail_on`.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::cli::ReviewArgs;
use crate::config::{RuntimeConfig, Source};
use crate::diff;
use crate::envelope::Envelope;
use crate::filter;
use crate::github::{CheckConclusion, GitHub, envelope_to_conclusion};
use crate::local;
use crate::openrouter::{OpenRouter, ReviewError};
use crate::output;
use crate::prompt;
use crate::repo_config::{self, OnClean, RepoConfig};

pub struct ReviewOutcome {
    pub envelope: Envelope,
    pub exit_code: i32,
}

pub async fn run(args: &ReviewArgs) -> Result<ReviewOutcome> {
    let cfg = RuntimeConfig::resolve(args).context("resolving runtime config")?;

    // Materialize the diff.
    let raw_diff = match &cfg.source {
        Source::Staged => local::staged_diff().await?,
        Source::LocalBase { base } => local::base_diff(base).await?,
        Source::DiffFile { path } => local::diff_from_file(path).await?,
        Source::GithubPr { repo, pr, .. } => {
            let gh = github_client(&cfg)?;
            gh.fetch_pr_diff(repo, *pr).await?
        }
    };

    if raw_diff.trim().is_empty() {
        let env = Envelope {
            summary: "No changes to review.".into(),
            findings: vec![],
            usage: Default::default(),
            model_used: None,
            cli_version: Some(env!("CARGO_PKG_VERSION").into()),
        };
        finalize_local_clean(&cfg, &env)?;
        return Ok(ReviewOutcome {
            envelope: env,
            exit_code: 0,
        });
    }

    let diff_to_model = truncate_diff(&raw_diff, cfg.diff_limit);
    let parsed_diff = diff::parse(&raw_diff);

    // Load repo config.
    let repo_cfg = load_repo_config(&cfg, &parsed_diff).await?;

    if !repo_cfg.is_enabled() {
        info!("Postil is disabled for this repo via .postil.yaml — exiting silently");
        let env = Envelope {
            summary: "".into(),
            findings: vec![],
            usage: Default::default(),
            model_used: None,
            cli_version: Some(env!("CARGO_PKG_VERSION").into()),
        };
        return Ok(ReviewOutcome {
            envelope: env,
            exit_code: 0,
        });
    }

    let system_prompt = prompt::build_system_prompt(&repo_cfg.reviewer);
    let user_prompt = match &cfg.source {
        Source::GithubPr { repo, pr, .. } => {
            prompt::build_user_prompt(&diff_to_model, Some(repo), Some(*pr))
        }
        _ => prompt::build_user_prompt(&diff_to_model, None, None),
    };

    // Pre-create the check-run if remote and not already passed in.
    let mut check_run_id = cfg.check_run_id;
    if cfg.is_remote()
        && check_run_id.is_none()
        && let Source::GithubPr { repo, sha, .. } = &cfg.source
    {
        match github_client(&cfg) {
            Ok(gh) => match gh.create_check_run(repo, sha, &cfg.check_name).await {
                Ok(id) => check_run_id = Some(id),
                Err(e) => warn!(error = %e, "could not create check-run; continuing without"),
            },
            Err(e) => {
                warn!(error = %e, "github client unavailable; continuing without check-run")
            }
        }
    }

    // Call the model.
    let api_key = cfg
        .openrouter_api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("OPENROUTER_API_KEY is required"))?;
    let or = OpenRouter::new(&cfg.openrouter_api_url, api_key)?;
    let mut envelope = match or
        .review(
            &cfg.review_model,
            &cfg.model_cascade,
            &system_prompt,
            &user_prompt,
        )
        .await
    {
        Ok(result) => result.envelope,
        Err(ReviewError::InvalidEnvelope(detail)) => Envelope::model_output_error(detail),
        Err(other) => {
            // Network / provider failures fail closed too — Postil never
            // silently approves on infrastructure errors.
            warn!(error = %other, "all OpenRouter attempts failed; failing closed");
            Envelope::model_output_error(format!("provider failure: {other}"))
        }
    };
    envelope.cli_version = Some(env!("CARGO_PKG_VERSION").into());

    // Post-filter.
    let _report = filter::apply(&mut envelope, &repo_cfg, &parsed_diff);

    // Output paths.
    if let Some(path) = &cfg.output_json {
        output::write_json(&envelope, path)?;
    }
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = output::render_terminal(&envelope, &mut lock);
    let _ = lock.flush();

    let conclusion = envelope_to_conclusion(&envelope, cfg.fail_on);

    // Post to GitHub if remote.
    if let Source::GithubPr { repo, pr, sha } = &cfg.source {
        let gh = github_client(&cfg)?;
        let clean = envelope.findings.is_empty();

        if !cfg.no_inline {
            if clean {
                if matches!(repo_cfg.review.on_clean, OnClean::Approve)
                    && let Err(e) = gh.approve_pr(repo, *pr, sha).await
                {
                    warn!(error = %e, "approve PR failed");
                }
            } else if let Err(e) = gh.post_inline_review(repo, *pr, sha, &envelope).await {
                warn!(error = %e, "posting inline review failed");
            }
        }

        if let Some(id) = check_run_id {
            let title = check_title(&envelope, conclusion);
            let body = crate::github::render_review_body(&envelope);
            let text = build_check_text(&envelope);
            if let Err(e) = gh
                .complete_check_run(repo, id, conclusion, &title, &body, &text)
                .await
            {
                warn!(error = %e, "completing check-run failed");
            }
        }
    }

    let exit_code = match conclusion {
        CheckConclusion::Failure => 1,
        _ => 0,
    };
    Ok(ReviewOutcome {
        envelope,
        exit_code,
    })
}

fn finalize_local_clean(_cfg: &RuntimeConfig, env: &Envelope) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = output::render_terminal(env, &mut lock);
    let _ = lock.flush();
    Ok(())
}

fn github_client(cfg: &RuntimeConfig) -> Result<GitHub> {
    let token = cfg
        .github_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("GITHUB_TOKEN is required for remote review"))?;
    GitHub::new(&cfg.github_api_url, token)
}

fn truncate_diff(diff: &str, limit: usize) -> String {
    if diff.len() <= limit {
        return diff.to_string();
    }
    let truncated = &diff[..limit];
    // Cut at last newline to avoid partial hunk lines.
    let cut = truncated.rfind('\n').unwrap_or(truncated.len());
    let mut out = diff[..cut].to_string();
    out.push_str(&format!(
        "\n\n... [diff truncated: {} bytes > {} limit] ...\n",
        diff.len(),
        limit
    ));
    out
}

async fn load_repo_config(cfg: &RuntimeConfig, _parsed: &diff::ParsedDiff) -> Result<RepoConfig> {
    match &cfg.source {
        Source::GithubPr { repo, sha, .. } => {
            let gh = match github_client(cfg) {
                Ok(g) => g,
                Err(_) => return Ok(RepoConfig::default()),
            };
            for name in repo_config::precedence_order() {
                if let Ok(Some(text)) = gh.read_file_at(repo, name, sha).await {
                    return repo_config::load_from_text(&text, name);
                }
            }
            Ok(RepoConfig::default())
        }
        _ => repo_config::load_from_dir(Path::new(".")),
    }
}

fn check_title(env: &Envelope, conclusion: CheckConclusion) -> String {
    match conclusion {
        CheckConclusion::Success => "Postil — no merge-relevant findings".to_string(),
        CheckConclusion::Neutral => {
            format!("Postil — {} advisory finding(s)", env.findings.len())
        }
        CheckConclusion::Failure => format!(
            "Postil — {} merge-blocking finding(s)",
            env.findings
                .iter()
                .filter(|f| f.severity == crate::envelope::Severity::Error)
                .count()
        ),
    }
}

fn build_check_text(env: &Envelope) -> String {
    if env.findings.is_empty() {
        return env.summary.clone();
    }
    let mut out = String::new();
    if !env.summary.trim().is_empty() {
        out.push_str(env.summary.trim());
        out.push_str("\n\n");
    }
    for f in &env.findings {
        out.push_str(&format!(
            "### {} `{}:{}`\n\n{}\n\n",
            f.severity.glyph(),
            f.path,
            f.line,
            f.body
        ));
    }
    if let Some(model) = &env.model_used {
        out.push_str(&format!("\n_Model: `{}`_\n", model));
    }
    out
}
