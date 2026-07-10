//! Review orchestration: one engine for local, CI, and hosted runs.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use crate::config::{Config, GateLevel, OnError};
use crate::diff::{self, DiffIndex};
use crate::envelope::{Envelope, Finding, Gate, Usage, fail_closed_finding};
use crate::filter;
use crate::forge::{
    CheckState, Forge, PrMeta, azure::Azure, bitbucket::Bitbucket, check_summary,
    clean_review_message, github::GitHub, gitlab::GitLab,
};
use crate::llm::LlmClient;
use crate::local::{self, LocalSource};
use crate::output;
use crate::prompt::{self, PrContext};

const MAX_DIFF_BYTES: usize = 400_000;
/// Hard cap on the raw fetched diff text before parsing. A generous multiple of
/// the render cap so ordinary changes are never affected, but bounds the work a
/// pathologically large fetched diff can force. Over the cap, the raw text is
/// truncated at a line boundary and the review is flagged truncated so the
/// uncertainty finding fires (a truncated review must not read as a full pass).
const MAX_RAW_DIFF_BYTES: usize = MAX_DIFF_BYTES * 4;

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

struct ReviewInput<'a> {
    diff_text: &'a str,
    meta: Option<&'a PrMeta>,
    head_sha: Option<String>,
    repo: Option<&'a str>,
    baseline: Vec<Finding>,
    scope: filter::ReconcileScope,
    force_model: bool,
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
    let baseline = load_baseline(args)?;
    let scope = if args.since_sha.is_some() {
        filter::ReconcileScope::Incremental
    } else {
        filter::ReconcileScope::Full { trustworthy: false }
    };
    let envelope = review_diff(
        cfg,
        args,
        ReviewInput {
            diff_text: &diff_text,
            meta: None,
            head_sha,
            repo: None,
            baseline,
            scope,
            force_model: false,
        },
    )
    .await?;
    finish(args, cfg, envelope, None::<&GitHub>).await
}

async fn run_remote<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
) -> Result<i32> {
    let review_started = std::time::Instant::now();
    // Full-review metadata and diff fetches are independent forge reads. Fetch
    // the diff while metadata is loading and check ownership is established;
    // hosted runs with pre-created check IDs save the metadata RTT, while CLI-
    // created checks also overlap their startup writes. Incremental diffs still
    // wait for metadata because they depend on the selected head SHA.
    let setup = async {
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
        Ok::<_, anyhow::Error>((meta, head_sha, checks))
    };
    let prefetch_diff = async {
        if args.since_sha.is_none() {
            Some(forge.fetch_diff().await)
        } else {
            None
        }
    };
    let (setup, prefetched_diff) = tokio::join!(setup, prefetch_diff);
    let (meta, head_sha, checks) = setup?;

    let result = remote_review(args, cfg, forge, repo, &meta, &head_sha, prefetched_diff).await;
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
                // A transient forge outage here (rate limit, timeout) must not
                // discard the review this far along: log and keep going so the
                // envelope/SARIF output and exit code below still land. Mirrors
                // the Err(e) arm below, which best-effort's this same call.
                if let Err(e) = forge
                    .complete_checks(a, g, advisory_state, gate_state, &envelope)
                    .await
                {
                    eprintln!("postil: could not update check runs ({e:#})");
                }
            }
            finish(args, cfg, envelope, Some(forge)).await
        }
        Err(e) => {
            // Fail closed by default: an errored run must never read as a silent
            // pass. `gate.onError: advisory` opts a repo out of blocking on
            // operational errors (provider outage) — the advisory check still
            // shows the error; only the gate stands aside.
            //
            // Build the error envelope and route it through the SAME output path
            // (finish) as a successful run: emitting the envelope/SARIF and
            // deriving the exit code from the gate. Propagating Err here instead
            // would map to exit 2 with no machine output — contradicting advisory
            // policy (which wants exit 0) and losing the envelope/SARIF.
            let envelope = error_envelope(
                cfg,
                &e,
                &head_sha,
                &meta,
                review_started.elapsed().as_millis() as u64,
            );
            if let Some((a, g)) = &checks {
                let gate_state = if envelope.gate.failing {
                    CheckState::Failure
                } else {
                    CheckState::Success
                };
                let _ = forge
                    .complete_checks(a, g, CheckState::Neutral, gate_state, &envelope)
                    .await;
            }
            // Emit envelope/SARIF and derive the exit code from the gate.
            // `finish` itself already downgrades forge posting failures
            // (complete_checks/post_review) to warnings on stderr without
            // touching its return value, so this only remains as a fallback
            // for a local I/O failure inside `finish` (e.g. writing SARIF) on
            // this already-errored path; even that must not mask the derived
            // exit code, so it is downgraded to the gate-derived code rather
            // than propagated as exit 2.
            let code = if envelope.gate.failing { 1 } else { 0 };
            match finish(args, cfg, envelope, Some(forge)).await {
                Ok(c) => Ok(c),
                Err(post_err) => {
                    eprintln!("postil: could not post the error review ({post_err:#})");
                    Ok(code)
                }
            }
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
    prefetched_diff: Option<Result<String>>,
) -> Result<Envelope> {
    let baseline = load_baseline(args)?;
    let has_carryable_baseline = baseline.iter().any(|f| !f.path.starts_with(".postil/"));
    let incremental = args.since_sha.as_deref();
    let (diff_text, scope, force_model) = match incremental {
        Some(since) if since != head_sha => forge
            .fetch_diff_since(since, head_sha)
            .await
            .context("incremental diff fetch")
            .map(|diff| (diff, filter::ReconcileScope::Incremental, false))?,
        Some(_) => (String::new(), filter::ReconcileScope::Incremental, false),
        None => (
            match prefetched_diff {
                Some(diff) => diff.context("diff fetch")?,
                None => forge.fetch_diff().await.context("diff fetch")?,
            },
            filter::ReconcileScope::Full { trustworthy: false },
            false,
        ),
    };

    // A same-head re-run has no incremental diff. If a real baseline finding
    // remains open, an empty run can never clear it, so retry as a full review.
    // Empty incremental runs without carryable findings remain model-free.
    let (diff_text, scope, force_model) = if cfg.enabled
        && has_carryable_baseline
        && matches!(scope, filter::ReconcileScope::Incremental)
        && diff_text.trim().is_empty()
    {
        (
            forge
                .fetch_diff()
                .await
                .context("full diff fallback fetch")?,
            filter::ReconcileScope::Full { trustworthy: false },
            true,
        )
    } else {
        (diff_text, scope, force_model)
    };
    review_diff(
        cfg,
        args,
        ReviewInput {
            diff_text: &diff_text,
            meta: Some(meta),
            head_sha: Some(head_sha.to_string()),
            repo: Some(repo),
            baseline,
            scope,
            force_model,
        },
    )
    .await
}

fn load_baseline(args: &ReviewArgs) -> Result<Vec<Finding>> {
    match &args.baseline {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading baseline {}", path.display()))?;
            let env: Envelope = serde_json::from_str(&raw).context("parsing baseline envelope")?;
            Ok(env.findings)
        }
        None => Ok(Vec::new()),
    }
}

/// Core engine: diff text in, envelope out. No forge I/O.
async fn review_diff(cfg: &Config, args: &ReviewArgs, input: ReviewInput<'_>) -> Result<Envelope> {
    let ReviewInput {
        diff_text,
        meta,
        head_sha,
        repo,
        baseline,
        scope,
        force_model,
    } = input;
    let review_started = std::time::Instant::now();
    // Cap the raw diff before parsing so an oversized fetched diff cannot force
    // unbounded parse work; a cut here forces the truncated path below.
    let (diff_text, raw_truncated) = diff::cap_raw_diff(diff_text, MAX_RAW_DIFF_BYTES);
    let parsed = diff::parse(diff_text);
    let mut index = DiffIndex::build(&parsed);
    let incremental = matches!(scope, filter::ReconcileScope::Incremental);

    // When content policy is active, render the PR title/description as a
    // numbered, groundable block and register its line range so a title/body
    // content-policy finding can ground against the reserved path. Only meaningful
    // for full reviews with a body; incremental reviews scope to the pushed diff.
    let content_policy_active = cfg.enabled && cfg.content_policy.is_some() && !incremental;
    let pr_desc_lines = if content_policy_active {
        let (_, count) = prompt::render_pr_description(
            meta.map(|m| m.title.as_str()),
            meta.map(|m| m.body.as_str()),
        );
        count
    } else {
        0
    };
    if pr_desc_lines > 0 {
        index.add_content_policy_path(crate::envelope::PR_DESCRIPTION_PATH, pr_desc_lines);
    }

    let mut summary = String::new();
    let mut model_used = "none (empty diff)".to_string();
    let mut usage = Usage::default();
    let mut suppressed = 0u32;
    let mut ungrounded = 0u32;
    let mut findings: Vec<Finding> = Vec::new();
    let mut full_review_trustworthy = false;

    // Run the model when there is a diff to review, or when content policy is
    // active and there is a PR title/description to review (an empty diff should
    // still get its prose checked).
    if !cfg.enabled {
        model_used = "none (disabled by config)".to_string();
    } else if force_model || !parsed.is_empty() || pr_desc_lines > 0 {
        let (annotated, render_truncated) = diff::render_annotated(&parsed, MAX_DIFF_BYTES);
        // Either the raw input was capped or the rendered output hit the limit;
        // both mean the model did not see the full change.
        let truncated = render_truncated || raw_truncated;
        let ctx = PrContext {
            repo,
            title: meta.map(|m| m.title.as_str()),
            body: meta.map(|m| m.body.as_str()),
            incremental,
            content_policy: content_policy_active,
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
                } else if outcome.kept.is_empty() && !model_review.summary.trim().is_empty() {
                    // Risk narrated in prose while NO finding survives to the
                    // gate. Passing this as clean is the predecessor product's
                    // worst failure mode; fail closed instead and carry the
                    // narration into the finding so it is not lost.
                    //
                    // Keyed on the POST-FILTER kept set, not raw_findings: the
                    // hole this closes is a model that returns findings which are
                    // all removed by min_confidence/severity/ignore suppression
                    // (so raw_findings != 0) while the summary still narrates
                    // risk — that previously slipped through silently. The
                    // all_ungrounded case is handled above, so this branch only
                    // fires for the genuinely-empty-after-policy case and does
                    // not double-fire.
                    findings = vec![crate::envelope::narrated_risk_finding(
                        &model_review.summary,
                    )];
                } else {
                    full_review_trustworthy = true;
                    summary = model_review.summary;
                    findings = outcome.kept;
                }
            }
            Err(e) => {
                model_used = cfg.model_chain().join(" -> ");
                usage = e.usage();
                let detail = format!("{e:#}");
                // Provider-class failures (outage, timeout) are the only ones
                // `gate.onError: advisory` may stand aside for; unusable model
                // content is attacker-influenceable and always fails closed.
                findings = vec![if e.is_provider() {
                    crate::envelope::provider_error_finding(&detail)
                } else {
                    fail_closed_finding(&detail)
                }];
            }
        }
        // A truncated review must never read as a full pass: the unreviewed
        // tail is surfaced as an explicit uncertainty finding.
        if truncated {
            full_review_trustworthy = false;
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
    // Skip entirely when review is disabled: a repo that set `enabled: false`
    // must not have a supplied baseline carry Errors that fail the gate. With
    // review off there is no fresh signal to reconcile against, so honoring the
    // disable means dropping the baseline carry-forward too.
    let rec = if cfg.enabled {
        let scope = match scope {
            filter::ReconcileScope::Incremental => filter::ReconcileScope::Incremental,
            filter::ReconcileScope::Full { .. } => filter::ReconcileScope::Full {
                trustworthy: full_review_trustworthy,
            },
        };
        filter::reconcile(&baseline, &index, &findings, scope)
    } else {
        filter::Reconciliation {
            resolved: vec![],
            carried: vec![],
        }
    };
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
        let duplicate_of_baseline = load_baseline(args)
            .ok()
            .is_some_and(|baseline| visible_finding_sets_equal(&baseline, &envelope.findings));
        let should_comment = (!envelope.silent
            || matches!(cfg.on_clean, crate::config::OnClean::Comment))
            && !duplicate_of_baseline;
        if should_comment {
            let rich = forge.rich_markdown();
            let summary = if envelope.silent {
                let icon = if rich {
                    format!("{} ", crate::forge::icon_md("pass"))
                } else {
                    String::new()
                };
                format!("{icon}{}", clean_review_message(&envelope))
            } else {
                check_summary(&envelope, rich)
            };
            let head = envelope.head_sha.clone().unwrap_or_default();
            // A posting failure here (rate limit, transient 5xx, network blip)
            // must not discard a review that already computed and persisted its
            // envelope/SARIF/stdout output above. Log it and keep going — the
            // exit code always derives from the gate below, never from whether
            // the forge comment made it out.
            if let Err(e) = forge.post_review(&summary, &envelope.findings, &head).await {
                eprintln!("postil: could not post review comment ({e:#})");
            }
        }
    }
    Ok(if envelope.gate.failing { 1 } else { 0 })
}

fn visible_finding_sets_equal(previous: &[Finding], current: &[Finding]) -> bool {
    // Synthetic findings represent this run's operational state and must stay
    // visible even if an earlier run failed in the same way.
    if previous.is_empty()
        || current.is_empty()
        || previous.len() != current.len()
        || previous
            .iter()
            .chain(current)
            .any(|f| f.path.starts_with(".postil/"))
    {
        return false;
    }

    let mut matched = vec![false; current.len()];
    previous.iter().all(|old| {
        current
            .iter()
            .enumerate()
            .find(|(i, new)| !matched[*i] && same_visible_finding(old, new))
            .is_some_and(|(i, _)| {
                matched[i] = true;
                true
            })
    })
}

fn same_visible_finding(a: &Finding, b: &Finding) -> bool {
    a.path == b.path
        && a.line == b.line
        && a.end_line == b.end_line
        && a.severity == b.severity
        && a.kind == b.kind
        && a.confidence.to_bits() == b.confidence.to_bits()
        && a.title == b.title
        && visible_body(&a.body) == visible_body(&b.body)
}

fn visible_body(body: &str) -> &str {
    body.strip_prefix(filter::CARRIED_MARKER)
        .map(str::trim_start)
        .unwrap_or(body)
}

fn error_envelope(
    cfg: &Config,
    err: &anyhow::Error,
    head_sha: &str,
    meta: &PrMeta,
    duration_ms: u64,
) -> Envelope {
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
        duration_ms,
        base_sha: Some(meta.base_sha.clone()),
        head_sha: Some(head_sha.to_string()),
        since_sha: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Kind, Severity};

    fn finding(path: &str, line: u32, body: &str) -> Finding {
        Finding {
            path: path.to_string(),
            line,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.9,
            title: "Finding".to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn visible_finding_comparison_ignores_carry_marker_and_order() {
        let previous = vec![finding("a.rs", 10, "first"), finding("b.rs", 20, "second")];
        let current = vec![
            finding("b.rs", 20, "[carried from previous review]\n\nsecond"),
            finding("a.rs", 10, "[carried from previous review]\n\nfirst"),
        ];
        assert!(visible_finding_sets_equal(&previous, &current));
    }

    #[test]
    fn visible_finding_comparison_detects_changes_and_fresh_synthetic_state() {
        let previous = vec![finding("a.rs", 10, "first")];
        assert!(!visible_finding_sets_equal(
            &previous,
            &[finding("a.rs", 11, "first")]
        ));
        assert!(!visible_finding_sets_equal(
            &[crate::envelope::provider_error_finding("old")],
            &[crate::envelope::provider_error_finding("old")]
        ));
    }
}
