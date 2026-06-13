//! Review orchestration: one engine for local, CI, and hosted runs.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use crate::config::{Config, GateLevel, OnError};
use crate::diff::{self, DiffIndex};
use crate::envelope::{Envelope, Finding, Gate, Usage, fail_closed_finding};
use crate::filter;
use crate::forge::{
    CheckState, Forge, PrMeta, azure::Azure, bitbucket::Bitbucket, check_summary, github::GitHub,
    gitlab::GitLab,
};
use crate::llm::LlmClient;
use crate::local::{self, LocalSource};
use crate::output;
use crate::prompt::{self, PrContext};

const MAX_DIFF_BYTES: usize = 400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeKind {
    GitHub,
    GitLab,
    Bitbucket,
    Azure,
    Local,
}

pub struct ReviewArgs {
    pub forge: ForgeKind,
    pub repo: Option<String>,
    pub pr: Option<u64>,
    pub sha: Option<String>,
    pub staged: bool,
    pub base: Option<String>,
    pub diff_file: Option<PathBuf>,
    pub check_run_id: Option<String>,
    pub gate_check_run_id: Option<String>,
    pub since_sha: Option<String>,
    pub baseline: Option<PathBuf>,
    pub output_json: bool,
    pub sarif: Option<PathBuf>,
    pub fail_on: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    pub no_post: bool,
}

pub async fn run(args: ReviewArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let mut cfg = Config::load(&cwd, args.config.as_deref())?;
    if let Some(m) = &args.model {
        cfg.model = m.clone();
    }
    if let Some(fo) = &args.fail_on {
        cfg.gate_fail_on =
            GateLevel::parse(fo).ok_or_else(|| anyhow!("invalid --fail-on {fo:?}"))?;
    }

    match args.forge {
        ForgeKind::Local => run_local(&args, &cfg).await,
        ForgeKind::GitHub => {
            let repo = require_repo(&args)?;
            let forge = GitHub::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo).await
        }
        ForgeKind::GitLab => {
            let repo = require_repo(&args)?;
            let forge = GitLab::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo).await
        }
        ForgeKind::Bitbucket => {
            let repo = require_repo(&args)?;
            let forge = Bitbucket::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo).await
        }
        ForgeKind::Azure => {
            let repo = require_repo(&args)?;
            let forge = Azure::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo).await
        }
    }
}

fn require_repo(args: &ReviewArgs) -> Result<String> {
    args.repo
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .ok_or_else(|| anyhow!("--repo owner/name is required for remote review"))
}

fn require_pr(args: &ReviewArgs) -> Result<u64> {
    args.pr
        .ok_or_else(|| anyhow!("--pr <number> is required for remote review"))
}

async fn run_local(args: &ReviewArgs, cfg: &Config) -> Result<i32> {
    let source = if let Some(path) = &args.diff_file {
        LocalSource::DiffFile(path.clone())
    } else if args.staged {
        LocalSource::Staged
    } else if let Some(base) = &args.base {
        LocalSource::Base(base.clone())
    } else {
        return Err(anyhow!(
            "local review needs one of --staged, --base <ref>, or --diff-file <path>"
        ));
    };
    let diff_text = local::acquire(&source).await?;
    let head_sha = local::head_sha().await;
    let envelope = review_diff(cfg, &diff_text, None, args, head_sha, None).await?;
    finish(args, cfg, envelope, None::<&GitHub>).await
}

async fn run_remote<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
) -> Result<i32> {
    let meta = forge.fetch_pr_meta().await?;
    let head_sha = args.sha.clone().unwrap_or_else(|| meta.head_sha.clone());

    // Own the check-runs early so a crash can still be reported against them.
    let checks = if args.no_post {
        None
    } else if let (Some(a), Some(g)) = (&args.check_run_id, &args.gate_check_run_id) {
        Some((a.clone(), g.clone()))
    } else {
        match forge.start_checks(&head_sha).await {
            Ok(ids) => Some(ids),
            Err(e) => {
                // CI tokens without checks:write still get review + exit code.
                eprintln!("postil: cannot create check runs ({e:#}); continuing without");
                None
            }
        }
    };

    let result = remote_review(args, cfg, forge, repo, &meta, &head_sha).await;
    match result {
        Ok(envelope) => {
            if let Some((a, g)) = &checks {
                let gate_state = if envelope.gate.failing {
                    CheckState::Failure
                } else {
                    CheckState::Success
                };
                // An operational failure inside the review (provider outage,
                // unusable output) must stay visible on the advisory check —
                // green-on-green would make an outage look like a clean pass
                // when the gate stands aside under `gate.onError: advisory`.
                let operational = envelope.findings.iter().any(|f| {
                    f.path == crate::envelope::OPERATIONAL_PATH
                        || f.path == crate::envelope::PROVIDER_PATH
                });
                let advisory_state = if operational {
                    CheckState::Neutral
                } else {
                    CheckState::Success
                };
                forge
                    .complete_checks(a, g, advisory_state, gate_state, &envelope)
                    .await?;
            }
            finish(args, cfg, envelope, Some(forge)).await
        }
        Err(e) => {
            // Fail closed by default: an errored run must never read as a silent
            // pass. `gate.onError: advisory` opts a repo out of blocking on
            // operational errors (provider outage) — the advisory check still
            // shows the error; only the gate stands aside.
            if let Some((a, g)) = &checks {
                let envelope = error_envelope(cfg, &e, &head_sha, &meta);
                let gate_state = match cfg.gate_on_error {
                    OnError::Block => CheckState::Failure,
                    OnError::Advisory => CheckState::Success,
                };
                let _ = forge
                    .complete_checks(a, g, CheckState::Neutral, gate_state, &envelope)
                    .await;
            }
            Err(e)
        }
    }
}

async fn remote_review<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
    meta: &PrMeta,
    head_sha: &str,
) -> Result<Envelope> {
    let incremental = args.since_sha.as_deref();
    let diff_text = match incremental {
        Some(since) if since != head_sha => forge
            .fetch_diff_since(since, head_sha)
            .await
            .context("incremental diff fetch")?,
        Some(_) => String::new(),
        None => forge.fetch_diff().await.context("diff fetch")?,
    };
    review_diff(
        cfg,
        &diff_text,
        Some(meta),
        args,
        Some(head_sha.to_string()),
        Some(repo),
    )
    .await
}

/// Core engine: diff text in, envelope out. No forge I/O.
async fn review_diff(
    cfg: &Config,
    diff_text: &str,
    meta: Option<&PrMeta>,
    args: &ReviewArgs,
    head_sha: Option<String>,
    repo: Option<&str>,
) -> Result<Envelope> {
    let baseline: Vec<Finding> = match &args.baseline {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading baseline {}", path.display()))?;
            let env: Envelope = serde_json::from_str(&raw).context("parsing baseline envelope")?;
            env.findings
        }
        None => Vec::new(),
    };

    let review_started = std::time::Instant::now();
    let parsed = diff::parse(diff_text);
    let index = DiffIndex::build(&parsed);
    let incremental = args.since_sha.is_some();

    let mut summary = String::new();
    let mut model_used = "none (empty diff)".to_string();
    let mut usage = Usage::default();
    let mut suppressed = 0u32;
    let mut ungrounded = 0u32;
    let mut findings: Vec<Finding> = Vec::new();

    if !cfg.enabled {
        model_used = "none (disabled by config)".to_string();
    } else if !parsed.is_empty() {
        let (annotated, truncated) = diff::render_annotated(&parsed, MAX_DIFF_BYTES);
        let ctx = PrContext {
            repo,
            title: meta.map(|m| m.title.as_str()),
            body: meta.map(|m| m.body.as_str()),
            incremental,
        };
        let system = prompt::system_prompt(cfg);
        let mut user = prompt::user_prompt(&ctx, &annotated, cfg.max_findings);
        if truncated {
            user.push_str(
                "\n\n[NOTE: the diff was truncated at the size limit; review only what \
                 is shown above.]",
            );
        }
        let client = LlmClient::from_env(cfg)?;
        match client.review(cfg, &system, &user).await {
            Ok(model_review) => {
                let raw_findings = model_review.findings.len();
                let outcome = filter::apply(cfg, &index, model_review.findings)?;
                model_used = model_review.model_used;
                usage = model_review.usage;
                suppressed = outcome.suppressed;
                ungrounded = outcome.ungrounded;
                if outcome.all_ungrounded {
                    findings = vec![fail_closed_finding(&format!(
                        "model reported {} finding(s), none grounded in the diff",
                        outcome.ungrounded
                    ))];
                } else if raw_findings == 0 && !model_review.summary.trim().is_empty() {
                    // Risk narrated in prose with zero structured findings
                    // (post-retry). Passing this as clean is the predecessor
                    // product's worst failure mode; fail closed instead and
                    // carry the narration into the finding so it is not lost.
                    findings = vec![crate::envelope::narrated_risk_finding(
                        &model_review.summary,
                    )];
                } else {
                    summary = model_review.summary;
                    findings = outcome.kept;
                }
            }
            Err(e) => {
                model_used = cfg.model_chain().join(" -> ");
                let detail = format!("{e:#}");
                // Provider-class failures (outage, timeout) are the only ones
                // `gate.onError: advisory` may stand aside for; unusable model
                // content is attacker-influenceable and always fails closed.
                findings = vec![if e.downcast_ref::<crate::llm::ProviderError>().is_some() {
                    crate::envelope::provider_error_finding(&detail)
                } else {
                    fail_closed_finding(&detail)
                }];
            }
        }
        // A truncated review must never read as a full pass: the unreviewed
        // tail is surfaced as an explicit uncertainty finding.
        if truncated {
            findings.push(Finding {
                path: ".postil/diff".to_string(),
                line: 1,
                end_line: None,
                severity: crate::envelope::Severity::Info,
                kind: crate::envelope::Kind::Uncertainty,
                confidence: 1.0,
                title: "Diff truncated at the review size limit".to_string(),
                body: format!(
                    "This change exceeds the {} KB review limit; only the first part was \
                     reviewed. Files beyond the cut were not assessed. Split the change \
                     or review the remainder manually.",
                    MAX_DIFF_BYTES / 1000
                ),
            });
        }
    }

    // Reconcile against the previous review (incremental or full re-review).
    let rec = filter::reconcile(&baseline, &index, &findings);
    findings.extend(rec.carried);

    // Operational findings (model unreachable/unusable) fail the gate by default
    // — fail closed. `gate.onError: advisory` lets the gate stand aside on a
    // provider outage so a blip does not freeze every merge; the finding still
    // shows in the output and the advisory check goes neutral. Unusable model
    // output (OPERATIONAL_PATH) never bypasses the gate: a malicious diff can
    // induce it via prompt injection.
    let advisory_on_error = cfg.gate_on_error == OnError::Advisory;
    let gate_failing = findings.iter().any(|f| {
        cfg.gate_fail_on.fails(f.severity)
            && !(advisory_on_error && f.path == crate::envelope::PROVIDER_PATH)
    });
    let silent = findings.is_empty();
    let mut counts = Envelope::counts_of(&findings, suppressed);
    counts.ungrounded = ungrounded;
    let buckets = Envelope::buckets_of(&findings);

    Ok(Envelope {
        version: 1,
        summary: if silent { String::new() } else { summary },
        silent,
        findings,
        resolved: rec.resolved,
        counts,
        confidence_buckets: buckets,
        gate: Gate {
            fail_on: cfg.gate_fail_on.as_str().to_string(),
            failing: gate_failing,
        },
        model_used,
        usage,
        duration_ms: review_started.elapsed().as_millis() as u64,
        base_sha: meta.map(|m| m.base_sha.clone()),
        head_sha,
        since_sha: args.since_sha.clone(),
    })
}

async fn finish<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    envelope: Envelope,
    forge: Option<&F>,
) -> Result<i32> {
    // Persist artifacts before any forge I/O: a posting hiccup must not
    // discard the completed review's SARIF or envelope output.
    if let Some(path) = &args.sarif {
        let sarif = crate::sarif::to_sarif(&envelope);
        std::fs::write(path, serde_json::to_string_pretty(&sarif)?)
            .with_context(|| format!("writing SARIF to {}", path.display()))?;
    }

    if args.output_json {
        output::print_envelope_json(&envelope)?;
    } else {
        output::print_pretty(&envelope);
    }

    if let Some(forge) = forge
        && !args.no_post
    {
        let should_comment =
            !envelope.silent || matches!(cfg.on_clean, crate::config::OnClean::Comment);
        if should_comment {
            let rich = forge.rich_markdown();
            let summary = if envelope.silent {
                let icon = if rich {
                    format!("{} ", crate::forge::icon_md("pass"))
                } else {
                    String::new()
                };
                format!(
                    "{icon}Postil reviewed this change and found nothing that affects the \
                     merge decision."
                )
            } else {
                check_summary(&envelope, rich)
            };
            let head = envelope.head_sha.clone().unwrap_or_default();
            forge
                .post_review(&summary, &envelope.findings, &head)
                .await
                .context("posting review")?;
        }
    }
    Ok(if envelope.gate.failing { 1 } else { 0 })
}

fn error_envelope(cfg: &Config, err: &anyhow::Error, head_sha: &str, meta: &PrMeta) -> Envelope {
    // Pre-review failures (PR meta or diff fetch) are forge transport errors,
    // not model content — provider class. A PR author can induce a subset
    // (merge-conflict PRs, >20k-file change lists), so advisory mode bypasses
    // those too; accepted because a conflicted PR cannot merge anyway and a
    // 20k-file PR is conspicuous, but revisit if either proves abusable.
    let findings = vec![crate::envelope::provider_error_finding(&format!("{err:#}"))];
    let counts = Envelope::counts_of(&findings, 0);
    let buckets = Envelope::buckets_of(&findings);
    let blocking = cfg.gate_on_error == OnError::Block;
    Envelope {
        version: 1,
        summary: if blocking {
            "Postil could not complete this review and is failing closed.".to_string()
        } else {
            "Postil could not complete this review. The gate is passing because this \
             repository sets gate.onError: advisory; the error is shown on postil/review."
                .to_string()
        },
        silent: false,
        findings,
        resolved: vec![],
        counts,
        confidence_buckets: buckets,
        gate: Gate {
            fail_on: cfg.gate_fail_on.as_str().to_string(),
            failing: blocking,
        },
        model_used: cfg.model_chain().join(" -> "),
        usage: Usage::default(),
        duration_ms: 0,
        base_sha: Some(meta.base_sha.clone()),
        head_sha: Some(head_sha.to_string()),
        since_sha: None,
    }
}
