//! Review orchestration: one engine for local, CI, and hosted runs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;

use crate::config::{Config, GateLevel, OnError};
use crate::diff;
use crate::durable_plan::{DurablePlanRegistrar, DurableReviewPlan};
use crate::envelope::{
    Envelope, Finding, Gate, Kind, ModelIncident, ModelIncidentCategory, ModelUsage,
    ReviewAdmission, ReviewCoverage, ReviewCoverageMode, ReviewCoverageReceipt, Usage,
    fail_closed_finding,
};
use crate::filter;
use crate::forge::{
    CheckState, Forge, PrMeta, azure::Azure, bitbucket::Bitbucket, github::GitHub, gitlab::GitLab,
};
use crate::llm::{FindingScore, LlmClient, ReviewValidationFailure, add_usage};
use crate::local::{self, LocalSource};
use crate::output::{self, OutputFormat};
use crate::prompt::{self, PrContext};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Each model request stays bounded. Large reviews continue through sequential
/// source windows; actual provider-attempt, deadline, and spend guards remain
/// enforced by `LlmClient` while raw diff size never decides reviewability.
// JSON can expand one control byte to a six-byte escape. Reserving two more
// factors leaves fixed room for the system prompt and request shape across
// OpenAI-compatible and native Anthropic providers.
pub(crate) const MAX_REVIEW_BATCH_BYTES: usize = crate::llm::MAX_PROVIDER_REQUEST_BYTES / 8;
#[cfg(test)]
pub(crate) const MAX_HOSTED_REVIEW_BATCH_BYTES: usize = MAX_REVIEW_BATCH_BYTES;
pub(crate) const MAX_REVIEW_MANIFEST_BYTES: usize = 24_000;
pub(crate) const MAX_HOSTED_SELECTED_BATCHES: usize = 5;
pub(crate) const MAX_LARGE_DIFF_SELECTED_BATCHES: usize = 24;
pub(crate) const MAX_LARGE_DIFF_CONCURRENCY: usize = 4;
const LARGE_SOURCE_REVIEW_MAX_TOKENS: u32 = 6_000;
const SYNTHESIS_REVIEW_MAX_TOKENS: u32 = 2_000;
pub(crate) const MAX_HOSTED_PLANNER_CANDIDATES: usize = 96;
pub(crate) const MAX_MODELS_PER_REQUEST: usize = 3;
pub(crate) const MAX_SCORER_PROMPT_BYTES: usize = 56_000;
const MAX_STREAMED_CANDIDATE_MULTIPLIER: usize = 8;
const MAX_STREAMED_SUMMARY_BYTES: usize = 64_000;
const MAX_REVIEW_VALIDATION_REASON_BYTES: usize = 16_384;
const HOSTED_WORKER_WATCHDOG_SECS: u64 = 600;
pub(crate) const HOSTED_LLM_TOTAL_TIMEOUT_SECS: u64 = 540;
/// Ordinary hosted reviews retain one long primary attempt plus a bounded
/// timeout retry inside the review phase.
pub(crate) const HOSTED_LLM_REQUEST_TIMEOUT_SECS: u64 = 240;
/// Large reviews run at most six waves of four 60-second calls. The review
/// phase keeps a final 60-second reserve for one bounded transient retry; the
/// remaining 120 seconds of the total LLM budget belongs to scoring.
pub(crate) const LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS: u64 = 60;
pub(crate) const HOSTED_LLM_REVIEW_TIMEOUT_SECS: u64 = 420;
const FORGE_READ_TIMEOUT_SECS: u64 = 60;
const FORGE_DIFF_MAX_TIMEOUT_SECS: u64 = 300;
const CHECK_START_TIMEOUT_SECS: u64 = 30;
const CHECK_COMPLETION_TIMEOUT_SECS: u64 = 30;
const REVIEW_POST_TIMEOUT_SECS: u64 = 20;
pub(crate) const SCORER_TIMEOUT_SECS: u64 = 120;

fn review_output_token_limit(synthesis: bool, deterministic_large_review: bool) -> u32 {
    if synthesis {
        SYNTHESIS_REVIEW_MAX_TOKENS
    } else if deterministic_large_review {
        LARGE_SOURCE_REVIEW_MAX_TOKENS
    } else {
        crate::llm::REVIEW_MAX_TOKENS
    }
}

fn hosted_request_timeout_secs(deterministic_large_review: bool) -> u64 {
    if deterministic_large_review {
        LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS
    } else {
        HOSTED_LLM_REQUEST_TIMEOUT_SECS
    }
}

fn full_diff_timeout_secs(snapshot: &PrMeta) -> u64 {
    let files = snapshot.changed_files.unwrap_or(480) as u64;
    let waves = files.div_ceil(8);
    FORGE_READ_TIMEOUT_SECS
        .saturating_add(waves.saturating_mul(2))
        .min(FORGE_DIFF_MAX_TIMEOUT_SECS)
}

async fn snapshot_is_current<F: Forge>(
    forge: &F,
    expected: &PrMeta,
    review_started: Instant,
) -> Result<bool> {
    run_with_hosted_budget(
        Some(review_started),
        FORGE_READ_TIMEOUT_SECS,
        forge.snapshot_is_current(expected),
        "verifying pull request snapshot before publication",
    )
    .await
}

fn conservative_context_tokens(model: &str) -> usize {
    let model = model.to_ascii_lowercase();
    if ["gpt-5", "gemma-3", "qwen3", "deepseek-v4", "mistral-small"]
        .iter()
        .any(|known| model.contains(known))
    {
        128_000
    } else {
        // Unknown BYOK endpoints get a conservative floor rather than an
        // optimistic provider-specific assumption.
        32_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewBatchValidationReason {
    category: &'static str,
    repair_detail: String,
}

fn review_batch_validation_reason(
    finding: &Finding,
    annotated: &str,
    content_policy_prompt: Option<&str>,
) -> Option<ReviewBatchValidationReason> {
    if let Err(reason) = crate::envelope::validate_finding_publication(finding) {
        return Some(ReviewBatchValidationReason {
            category: "publicationContract",
            repair_detail: format!(
                "finding at {}:{} violates the publication contract: {reason}",
                finding.path, finding.line
            ),
        });
    }

    if diff::review_batch_contains_exact_evidence(
        annotated,
        &finding.path,
        finding.line,
        finding.evidence.as_deref(),
    ) || content_policy_prompt.is_some_and(|prompt| {
        diff::review_batch_contains_exact_evidence(
            prompt,
            &finding.path,
            finding.line,
            finding.evidence.as_deref(),
        )
    }) {
        return None;
    }

    let evidence_source = content_policy_prompt
        .filter(|prompt| {
            diff::review_batch_has_evidence_anchor(prompt, &finding.path, finding.line)
        })
        .or_else(|| {
            diff::review_batch_has_evidence_anchor(annotated, &finding.path, finding.line)
                .then_some(annotated)
        });

    let Some(evidence_source) = evidence_source else {
        return Some(ReviewBatchValidationReason {
            category: "missingEvidenceAnchor",
            repair_detail: format!(
                "finding at {}:{} does not cite a non-empty new-side line displayed in this review input; retract it or cite a displayed new-side line",
                finding.path, finding.line
            ),
        });
    };
    let Some(expected) =
        diff::review_batch_expected_evidence(evidence_source, &finding.path, finding.line)
    else {
        return Some(ReviewBatchValidationReason {
            category: "ambiguousEvidence",
            repair_detail: format!(
                "finding at {}:{} has multiple displayed new-side evidence strings; copy the exact supporting string or retract it",
                finding.path, finding.line
            ),
        });
    };
    Some(ReviewBatchValidationReason {
        category: "evidenceMismatch",
        repair_detail: format!(
            "finding at {}:{} must set `evidence` to the exact JSON string {}",
            finding.path,
            finding.line,
            serde_json::to_string(&expected).expect("evidence string is JSON-serializable")
        ),
    })
}

fn review_batch_validation_reasons(
    findings: &[Finding],
    annotated: &str,
    content_policy_prompt: Option<&str>,
) -> Option<ReviewValidationFailure> {
    let mut reasons = String::new();
    let mut category_counts = HashMap::<&'static str, usize>::new();
    let validation_reasons = findings
        .iter()
        .filter_map(|finding| {
            review_batch_validation_reason(
                finding,
                annotated,
                (finding.kind == crate::envelope::Kind::ContentPolicy)
                    .then_some(content_policy_prompt)
                    .flatten(),
            )
        })
        .collect::<Vec<_>>();
    for reason in &validation_reasons {
        *category_counts.entry(reason.category).or_default() += 1;
    }
    for reason in validation_reasons {
        let separator = if reasons.is_empty() { "" } else { "; " };
        let remaining = MAX_REVIEW_VALIDATION_REASON_BYTES.saturating_sub(reasons.len());
        if separator.len().saturating_add(reason.repair_detail.len()) <= remaining {
            reasons.push_str(separator);
            reasons.push_str(&reason.repair_detail);
            continue;
        }
        if remaining > separator.len() {
            reasons.push_str(separator);
            let available = remaining - separator.len();
            let end = reason
                .repair_detail
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|index| *index <= available)
                .last()
                .unwrap_or(0);
            reasons.push_str(&reason.repair_detail[..end]);
        }
        break;
    }
    if reasons.is_empty() {
        return None;
    }
    let safe_detail = [
        "publicationContract",
        "missingEvidenceAnchor",
        "ambiguousEvidence",
        "evidenceMismatch",
    ]
    .into_iter()
    .filter_map(|category| {
        category_counts
            .get(category)
            .map(|count| format!("{category}={count}"))
    })
    .collect::<Vec<_>>()
    .join(",");
    Some(ReviewValidationFailure::new(reasons, safe_detail))
}

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
    pub base_sha: Option<String>,
    pub staged: bool,
    pub base: Option<String>,
    pub diff_file: Option<PathBuf>,
    pub check_run_id: Option<String>,
    pub gate_check_run_id: Option<String>,
    pub since_sha: Option<String>,
    pub baseline: Option<PathBuf>,
    pub output: Option<OutputFormat>,
    pub output_file: Option<PathBuf>,
    pub output_json: bool,
    pub sarif: Option<PathBuf>,
    pub fail_on: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    pub bounded: bool,
    pub no_post: bool,
    pub defer_gate_check: bool,
}

impl ReviewArgs {
    fn resolved_output_format(&self) -> Option<OutputFormat> {
        if self.output_json {
            Some(OutputFormat::Json)
        } else {
            self.output
        }
    }
}

struct ReviewInput<'a> {
    diff_snapshot: &'a diff::DiffSnapshot,
    meta: Option<&'a PrMeta>,
    head_sha: Option<String>,
    repo: Option<&'a str>,
    baseline: Vec<Finding>,
    scope: filter::ReconcileScope,
    force_model: bool,
    llm_budget_started_at: Option<Instant>,
}

struct RemoteReviewInput<'a> {
    meta: &'a PrMeta,
    review_started: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewFailureKind {
    Provider,
    InvalidOutput,
}

fn classify_exhausted_scorer_failure(
    incidents: &[ModelIncident],
    final_error_is_provider: bool,
) -> ReviewFailureKind {
    if incidents.iter().any(|incident| {
        !incident.recovered && incident.category == ModelIncidentCategory::InvalidOutput
    }) {
        ReviewFailureKind::InvalidOutput
    } else if final_error_is_provider {
        ReviewFailureKind::Provider
    } else {
        ReviewFailureKind::InvalidOutput
    }
}

#[derive(Debug)]
struct ReviewFailure {
    kind: ReviewFailureKind,
    detail: String,
    model_used: String,
    scorer_model: Option<String>,
    scorer_error: Option<String>,
    usage: Usage,
    model_usage: Vec<ModelUsage>,
    model_incidents: Vec<ModelIncident>,
    review_coverage: Option<ReviewCoverage>,
    review_admission: Option<ReviewAdmission>,
    usage_accounting_complete: bool,
}

impl std::fmt::Display for ReviewFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ReviewFailure {}

pub async fn run(args: ReviewArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    if args.output_json {
        eprintln!("warning: --output-json is deprecated; use --output json instead");
    }
    if args.output_file.is_some() && args.resolved_output_format().is_none() {
        return Err(anyhow!("--output-file requires --output or --output-json"));
    }
    let mut cfg = Config::load(&cwd, args.config.as_deref())?;
    if let Some(m) = &args.model {
        cfg.model = m.clone();
    }
    cfg.require_model()?;
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
    let diff_snapshot = local::acquire(&source).await?;
    let head_sha = local::head_sha().await;
    let baseline = load_baseline(args)?;
    // This is a fail-closed placeholder, not the completed review's trust.
    // review_diff replaces it with Failed, Bounded, or Exhaustive after the
    // selected requests finish; an early model failure deliberately keeps it.
    let scope = if args.since_sha.is_some() {
        filter::ReconcileScope::Incremental {
            trust: filter::ReviewTrust::Failed,
        }
    } else {
        filter::ReconcileScope::Full {
            trust: filter::ReviewTrust::Failed,
        }
    };
    let envelope = review_diff(
        cfg,
        args,
        ReviewInput {
            diff_snapshot: &diff_snapshot,
            meta: None,
            head_sha,
            repo: None,
            baseline,
            scope,
            force_model: false,
            llm_budget_started_at: None,
        },
    )
    .await?;
    finish(args, cfg, envelope, None::<&GitHub>, None, None, false).await
}

async fn run_remote<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
) -> Result<i32> {
    let review_started = std::time::Instant::now();
    let strict_publication = strict_hosted_github_publication(args);
    let meta = run_with_hosted_budget(
        Some(review_started),
        FORGE_READ_TIMEOUT_SECS,
        forge.fetch_pr_meta(),
        "fetching PR metadata",
    )
    .await?;
    if let Some(event_sha) = args.sha.as_deref() {
        anyhow::ensure!(
            event_sha == meta.head_sha,
            "requested review head {event_sha} is no longer the pull request head {}",
            meta.head_sha
        );
    }
    if let Some(event_base_sha) = args.base_sha.as_deref() {
        let target_sha = meta
            .target_sha
            .as_deref()
            .ok_or_else(|| anyhow!("--base-sha is not supported for the selected forge"))?;
        anyhow::ensure!(
            event_base_sha == target_sha,
            "requested review target {event_base_sha} is no longer the pull request target {target_sha}"
        );
    }
    let head_sha = meta.head_sha.clone();

    // Own the check-runs early so a crash can still be reported against them.
    let checks = if args.no_post {
        None
    } else if let (Some(a), Some(g)) = (&args.check_run_id, &args.gate_check_run_id) {
        Some((a.clone(), g.clone()))
    } else {
        match run_with_hosted_budget(
            Some(review_started),
            CHECK_START_TIMEOUT_SECS,
            forge.start_checks(&head_sha),
            "creating check runs",
        )
        .await
        {
            Ok(ids) => Some(ids),
            Err(e) => {
                if crate::forge::is_repository_identity_failure(&e) {
                    return Err(e).context("creating check runs");
                }
                // CI tokens without checks:write still get review + exit code.
                eprintln!("postil: cannot create check runs ({e:#}); continuing without");
                None
            }
        }
    };

    let result = remote_review(
        args,
        cfg,
        forge,
        repo,
        RemoteReviewInput {
            meta: &meta,
            review_started,
        },
    )
    .await;
    match result {
        Ok(envelope) => {
            let check_completion = if let Some((a, g)) = &checks {
                let gate_state = if envelope.gate.failing {
                    CheckState::Failure
                } else {
                    CheckState::Success
                };
                // An operational failure inside the review (provider outage,
                // unusable output) must stay visible on the advisory check.
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
                complete_remote_checks(
                    forge,
                    a,
                    g,
                    advisory_state,
                    (!args.defer_gate_check).then_some(gate_state),
                    &envelope,
                    &meta,
                    review_started,
                )
                .await
            } else {
                Ok(())
            };
            let check_failure = retain_publication_failure(
                strict_publication,
                check_completion,
                "could not update check runs",
            )?;
            let finish_result = finish(
                args,
                cfg,
                envelope,
                Some(forge),
                Some(review_started),
                Some(&meta),
                strict_publication,
            )
            .await;
            combine_required_publication(check_failure, finish_result)
        }
        Err(e) => {
            eprintln!("postil: review failed before completion ({e:#})");
            // Fail closed by default: an errored run must never read as a silent
            // pass. `gate.onError: advisory` opts a repo out of blocking on
            // operational errors (provider outage). The advisory check still
            // shows the error; only the gate stands aside.
            //
            // Build the error envelope and route it through the SAME output path
            // (finish) as a successful run: emitting the envelope/SARIF and
            // deriving the exit code from the gate. Propagating Err here instead
            // would map to exit 2 with no machine output, contradicting advisory
            // policy (which wants exit 0) and losing the envelope/SARIF.
            let envelope = error_envelope(
                cfg,
                &e,
                &head_sha,
                &meta,
                review_started.elapsed().as_millis() as u64,
            );
            let check_completion = if let Some((a, g)) = &checks {
                let gate_state = if envelope.gate.failing {
                    CheckState::Failure
                } else {
                    CheckState::Success
                };
                complete_remote_checks(
                    forge,
                    a,
                    g,
                    CheckState::Neutral,
                    (!args.defer_gate_check).then_some(gate_state),
                    &envelope,
                    &meta,
                    review_started,
                )
                .await
            } else {
                Ok(())
            };
            let check_failure = retain_publication_failure(
                strict_publication,
                check_completion,
                "could not update check runs",
            )?;
            // Emit the envelope and SARIF before delivery. Hosted GitHub runs
            // require every applicable publication step; other invocations
            // retain their gate-derived result when the forge is unavailable.
            let code = if envelope.gate.failing { 1 } else { 0 };
            let finish_result = finish(
                args,
                cfg,
                envelope,
                Some(forge),
                Some(review_started),
                Some(&meta),
                strict_publication,
            )
            .await;
            let finish_result = match finish_result {
                Ok(c) => Ok(c),
                Err(post_err) => {
                    if crate::forge::is_repository_identity_failure(&post_err) {
                        return Err(post_err);
                    }
                    if strict_publication {
                        Err(post_err)
                    } else {
                        eprintln!("postil: could not post the error review ({post_err:#})");
                        Ok(code)
                    }
                }
            };
            combine_required_publication(check_failure, finish_result)
        }
    }
}

fn strict_hosted_github_publication(args: &ReviewArgs) -> bool {
    crate::config::hosted_mode() && args.forge == ForgeKind::GitHub && !args.no_post
}

async fn require_current_snapshot<F: Forge>(
    forge: &F,
    expected: &PrMeta,
    review_started: Instant,
    publication: &str,
) -> Result<()> {
    match snapshot_is_current(forge, expected, review_started).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(anyhow!(
            "{publication} skipped because the pull request snapshot changed after review"
        )),
        Err(error) => Err(error).with_context(|| {
            format!("{publication} skipped because snapshot freshness could not be verified")
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn complete_remote_checks<F: Forge>(
    forge: &F,
    advisory_id: &str,
    gate_id: &str,
    advisory: CheckState,
    gate: Option<CheckState>,
    envelope: &Envelope,
    snapshot: &PrMeta,
    review_started: Instant,
) -> Result<()> {
    require_current_snapshot(forge, snapshot, review_started, "check completion").await?;
    run_with_hosted_budget(
        Some(review_started),
        CHECK_COMPLETION_TIMEOUT_SECS,
        forge.complete_checks(advisory_id, gate_id, advisory, gate, envelope, snapshot),
        "completing check runs",
    )
    .await
}

fn retain_publication_failure(
    required: bool,
    result: Result<()>,
    warning: &str,
) -> Result<Option<anyhow::Error>> {
    match result {
        Ok(()) => Ok(None),
        Err(error) if required => Ok(Some(error)),
        Err(error) if crate::forge::is_repository_identity_failure(&error) => Err(error),
        Err(error) => {
            eprintln!("postil: {warning} ({error:#})");
            Ok(None)
        }
    }
}

fn combine_required_publication(
    check_failure: Option<anyhow::Error>,
    finish_result: Result<i32>,
) -> Result<i32> {
    match (check_failure, finish_result) {
        (None, result) => result,
        (Some(check_error), Ok(_)) => {
            Err(check_error).context("required hosted check publication failed")
        }
        (Some(check_error), Err(review_error)) => Err(anyhow!(
            "required hosted publication failed: check completion: {check_error:#}; review delivery: {review_error:#}"
        )),
    }
}

async fn remote_review<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
    input: RemoteReviewInput<'_>,
) -> Result<Envelope> {
    let RemoteReviewInput {
        meta,
        review_started,
    } = input;
    let head_sha = meta.head_sha.as_str();
    let baseline = load_baseline(args)?;
    let has_carryable_baseline = baseline_has_carryable_findings(&baseline);
    let incremental = args.since_sha.as_deref();
    let (diff_snapshot, scope, force_model) = match incremental {
        Some(since) if since != head_sha => run_with_hosted_budget(
            Some(review_started),
            FORGE_READ_TIMEOUT_SECS,
            forge.fetch_diff_since(since, head_sha),
            "fetching incremental diff",
        )
        .await
        .map_err(crate::forge::classify_review_input_error)
        .context("incremental diff fetch")
        .map(|diff| {
            (
                diff,
                filter::ReconcileScope::Incremental {
                    trust: filter::ReviewTrust::Failed,
                },
                false,
            )
        })?,
        Some(_) => (
            diff::DiffSnapshot::from_bytes(b"")?,
            filter::ReconcileScope::Incremental {
                trust: filter::ReviewTrust::Failed,
            },
            false,
        ),
        None => (
            run_with_hosted_budget(
                Some(review_started),
                full_diff_timeout_secs(meta),
                forge.fetch_diff(meta),
                "fetching diff",
            )
            .await
            .map_err(crate::forge::classify_review_input_error)
            .context("diff fetch")?,
            filter::ReconcileScope::Full {
                trust: filter::ReviewTrust::Failed,
            },
            false,
        ),
    };

    // A same-head re-run has no incremental diff. If a real baseline finding
    // remains open, an empty run can never clear it, so retry as a full review.
    // Empty incremental runs without carryable findings remain model-free.
    let (diff_snapshot, scope, force_model) = if cfg.enabled
        && has_carryable_baseline
        && matches!(scope, filter::ReconcileScope::Incremental { .. })
        && diff_snapshot.as_str().trim().is_empty()
    {
        (
            run_with_hosted_budget(
                Some(review_started),
                full_diff_timeout_secs(meta),
                forge.fetch_diff(meta),
                "fetching full fallback diff",
            )
            .await
            .map_err(crate::forge::classify_review_input_error)
            .context("full diff fallback fetch")?,
            filter::ReconcileScope::Full {
                trust: filter::ReviewTrust::Failed,
            },
            true,
        )
    } else {
        (diff_snapshot, scope, force_model)
    };
    review_diff(
        cfg,
        args,
        ReviewInput {
            diff_snapshot: &diff_snapshot,
            meta: Some(meta),
            head_sha: Some(head_sha.to_string()),
            repo: Some(repo),
            baseline,
            scope,
            force_model,
            llm_budget_started_at: Some(review_started),
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
/// Generate stable IDs. Source findings are scoped to the reviewed head;
/// change-metadata findings use their exact semantic content so an unrelated
/// metadata entry reusing the same synthetic line cannot supersede them.
fn generate_finding_ids(findings: &mut [Finding], head_sha: Option<&str>) {
    for finding in findings.iter_mut() {
        if finding.id.is_some() {
            continue;
        }
        // Normalize the finding data
        let normalized_path = finding.path.to_lowercase();
        let normalized_title = finding.title.trim().to_lowercase();
        let identity = if let Some(evidence) = finding.evidence.as_deref() {
            format!(
                "evidence\x00{}\x00{}\x00{}\x00{}",
                finding.kind.as_str(),
                normalized_path,
                normalized_title,
                evidence
            )
        } else if finding.path == crate::envelope::CHANGE_METADATA_PATH {
            format!(
                "change-metadata\x00{}\x00{}\x00{}\x00{}",
                finding.kind.as_str(),
                finding.severity.as_str(),
                normalized_title,
                visible_body(&finding.body).trim()
            )
        } else {
            let Some(head_sha) = head_sha else { continue };
            format!(
                "{head_sha}\x00{}\x00{}\x00{}\x00{}",
                finding.kind.as_str(),
                normalized_path,
                finding.line,
                normalized_title
            )
        };

        // Generate SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(identity.as_bytes());
        let result = hasher.finalize();
        let hex_id = result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        finding.id = Some(hex_id);
    }
}

fn scorer_inputs(
    parsed: &diff::Diff,
    review_batches: &[String],
    findings: &[Finding],
) -> Vec<prompt::ScorerPromptFinding> {
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| prompt::ScorerPromptFinding {
            index,
            path: prompt::sanitize_scorer_input(&finding.path),
            line: finding.line,
            severity: finding.severity.as_str().to_string(),
            title: prompt::sanitize_scorer_input(&finding.title),
            body: prompt::sanitize_scorer_input(&finding.body),
            diff_hunk: prompt::sanitize_scorer_input(
                &diff::render_hunk_context(parsed, &finding.path, finding.line, 20)
                    .or_else(|| {
                        review_batches.iter().find_map(|batch| {
                            diff::render_review_batch_context(
                                batch,
                                &finding.path,
                                finding.line,
                                8,
                                24_000,
                            )
                        })
                    })
                    .unwrap_or_else(|| {
                        "No diff evidence is available for this cited location.".to_string()
                    }),
            ),
        })
        .collect()
}

fn apply_scorer_scores(cfg: &Config, findings: &mut [Finding], scores: Vec<FindingScore>) -> u32 {
    let mut disagreements = 0u32;
    for score in scores {
        let Some(finding) = findings.get_mut(score.index) else {
            continue;
        };
        let generator_confidence = finding.confidence;
        let generator_kind = finding.kind;
        let large_confidence_disagreement = (generator_confidence - score.confidence).abs() >= 0.4;
        let kind_disagreement = generator_kind != score.kind;
        if large_confidence_disagreement || kind_disagreement {
            disagreements += 1;
        }

        finding.generator_confidence = Some(generator_confidence);
        finding.scorer_confidence = Some(score.confidence);
        finding.generator_kind = Some(generator_kind);
        finding.scorer_kind = Some(score.kind);
        if !score.reason.is_empty() {
            finding.scorer_reason = Some(score.reason);
        }
        finding.confidence = generator_confidence.min(score.confidence);

        let generator_blocks = cfg.block_on_kinds.contains(&generator_kind);
        let scorer_blocks = cfg.block_on_kinds.contains(&score.kind);
        if scorer_blocks && !generator_blocks {
            finding.kind = score.kind;
        }

        if large_confidence_disagreement && !cfg.block_on_kinds.contains(&finding.kind) {
            finding.kind = Kind::Uncertainty;
        }
    }
    disagreements
}

fn suppress_below_min_confidence(
    cfg: &Config,
    findings: &mut Vec<Finding>,
) -> Vec<crate::envelope::SuppressedFinding> {
    let mut suppressed = Vec::new();
    findings.retain(|finding| {
        if finding.confidence >= cfg.min_confidence {
            true
        } else {
            suppressed.push(crate::envelope::SuppressedFinding {
                finding: finding.clone(),
                reason: crate::envelope::SuppressionReason::BelowConfidence,
            });
            false
        }
    });
    suppressed
}

fn sort_findings_for_display(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.total_cmp(&a.confidence))
    });
}

struct ReviewBatchPromptContext<'a> {
    cfg: &'a Config,
    repo: Option<&'a str>,
    meta: Option<&'a PrMeta>,
    incremental: bool,
    content_policy_active: bool,
    bounded_selection: bool,
    multiple: bool,
}

fn review_batch_prompt(
    context: &ReviewBatchPromptContext<'_>,
    mut annotated: String,
    first: bool,
) -> (String, String, bool) {
    let synthesis = annotated.starts_with("Cross-window semantic digests")
        || annotated.starts_with("Cross-batch semantic digests");
    if context.bounded_selection {
        let kind = if synthesis { "synthesis" } else { "source" };
        annotated.insert_str(0, &format!(
            "This {kind} batch was selected from a larger diff. Review only the supplied grounded evidence. Do not claim literal examination of every changed line. Boundary, risk, and synthesis evidence are reviewed as separate requests.\n\n"
        ));
    }
    let prompt_context = PrContext {
        repo: context.repo,
        title: if !context.content_policy_active || first {
            context.meta.map(|value| value.title.as_str())
        } else {
            None
        },
        body: if !context.content_policy_active || first {
            context.meta.map(|value| value.body.as_str())
        } else {
            None
        },
        incremental: context.incremental,
        content_policy: first && context.content_policy_active,
    };
    let mut user = prompt::user_prompt(&prompt_context, &annotated, context.cfg.max_findings);
    if synthesis {
        user.push_str(
            "\n\nThis bounded synthesis window joins semantic evidence from adjacent source windows. Look specifically for merge-relevant relationships such as caller/API, config/consumer, validation/sink, and lifecycle pairs. Cite the exact numbered path and line retained in the digest.",
        );
    } else if context.multiple {
        user.push_str(
            "\n\nReview this selected source batch independently. Other selected source batches are reviewed separately.",
        );
    }
    (annotated, user, synthesis)
}

async fn review_diff(cfg: &Config, args: &ReviewArgs, input: ReviewInput<'_>) -> Result<Envelope> {
    let ReviewInput {
        diff_snapshot,
        meta,
        head_sha,
        repo,
        baseline,
        scope,
        force_model,
        llm_budget_started_at,
    } = input;
    let review_started = std::time::Instant::now();
    let mut prepared = diff::prepare_review(diff_snapshot)?;
    let input_incomplete = prepared.reserved_anchor;
    let mut index = std::mem::take(&mut prepared.index);
    let incremental = matches!(scope, filter::ReconcileScope::Incremental { .. });

    // When content policy is active, render the PR title/description as a
    // numbered, groundable block and register its line range so a title/body
    // content-policy finding can ground against the reserved path. Only meaningful
    // for full reviews with a body; incremental reviews scope to the pushed diff.
    let content_policy_active = cfg.enabled && cfg.content_policy.is_some() && !incremental;
    let (pr_description, pr_desc_lines) = if content_policy_active {
        prompt::render_pr_description(
            meta.map(|m| m.title.as_str()),
            meta.map(|m| m.body.as_str()),
        )
    } else {
        (String::new(), 0)
    };
    if pr_desc_lines > 0 {
        index.add_content_policy_evidence(crate::envelope::PR_DESCRIPTION_PATH, &pr_description);
    }

    let mut summary = String::new();
    let mut model_used = "none (empty diff)".to_string();
    let mut usage = Usage::default();
    let mut model_usage: Vec<ModelUsage> = Vec::new();
    let mut model_incidents = Vec::new();
    let mut review_coverage = None;
    let mut review_admission = None;
    let mut usage_accounting_complete = true;
    let mut suppressed = 0u32;
    let mut ungrounded = 0u32;
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed_findings = Vec::new();
    let mut review_trust = filter::ReviewTrust::Failed;
    let mut scorer_model: Option<String> = None;
    let mut scorer_error: Option<String> = None;
    let mut scorer_disagreements: Option<u32> = None;
    let mut scorer_failure_kind: Option<ReviewFailureKind> = None;

    // Run the model when there is a diff to review, or when content policy is
    // active and there is a PR title/description to review (an empty diff should
    // still get its prose checked).
    if !cfg.enabled {
        model_used = "none (disabled by config)".to_string();
    } else if force_model
        || input_incomplete
        || prepared.has_source
        || !prepared.lockfiles.is_empty()
        || !prepared.compacted_artifacts.is_empty()
        || pr_desc_lines > 0
    {
        let system = prompt::system_prompt(cfg);
        let chain = cfg.model_chain();
        let active_model_count = if cfg.consensus > 1 {
            cfg.consensus.min(chain.len())
        } else {
            chain.len()
        };
        let context_tokens = chain
            .iter()
            .take(active_model_count)
            .map(|model| conservative_context_tokens(model))
            .min()
            .unwrap_or(32_000);
        let review_output_tokens = crate::llm::REVIEW_MAX_TOKENS as usize;
        // Serialized UTF-8 bytes conservatively upper-bound the corresponding
        // input token count. This intentionally under-fills the model context
        // rather than relying on a provider-specific tokenizer.
        let shared_context_token_upper_bound =
            system.len() + meta.map_or(0, |value| value.title.len() + value.body.len()) + 4096;
        let batch_budget = context_tokens
            .saturating_sub(review_output_tokens)
            .saturating_sub(shared_context_token_upper_bound)
            .min(MAX_REVIEW_BATCH_BYTES);
        let invalid_input = input_incomplete
            || batch_budget < 4_096
            || active_model_count == 0
            || active_model_count > MAX_MODELS_PER_REQUEST;

        if invalid_input {
            eprintln!(
                "postil: review input is malformed or the configured model fan-out is invalid (models {active_model_count}/{MAX_MODELS_PER_REQUEST})",
            );
            model_used = "none (invalid review input)".to_string();
            findings = vec![crate::envelope::incomplete_review_finding()];
        } else {
            let mut batches = diff::spool_model_batches(
                &mut prepared,
                batch_budget,
                MAX_REVIEW_MANIFEST_BYTES.min(batch_budget / 3),
                force_model || pr_desc_lines > 0,
            )?;
            index.add_change_metadata(batches.metadata_count);
            if batches.count == 0 {
                model_used = "none (empty diff)".to_string();
                review_trust = filter::ReviewTrust::Exhaustive;
            } else {
                let large_diff_receipt = (batches.source_count > MAX_LARGE_DIFF_SELECTED_BATCHES)
                    .then(|| batches.deterministic_bounded_receipt(MAX_LARGE_DIFF_SELECTED_BATCHES))
                    .transpose()?;
                if let Some(receipt) = &large_diff_receipt {
                    eprintln!(
                        "postil: deterministic large-review plan={} direct_hunks={} semantic_hunks={} unreviewed_hunks={} selected_batches={}/{} concurrency={} request_timeout={}s review_budget={}s",
                        receipt.plan_sha256,
                        receipt.direct_hunks(),
                        receipt.semantic_hunks(),
                        receipt.unreviewed_hunks(),
                        receipt.selected_batch_ids.len(),
                        batches.count,
                        MAX_LARGE_DIFF_CONCURRENCY,
                        LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS,
                        HOSTED_LLM_REVIEW_TIMEOUT_SECS,
                    );
                }
                let large_receipt_summary = large_diff_receipt
                    .as_ref()
                    .map(|receipt| -> Result<ReviewCoverageReceipt> {
                        Ok(ReviewCoverageReceipt {
                            plan_sha256: receipt.plan_sha256.clone(),
                            total_hunks: u32::try_from(receipt.entries.len())
                                .context("coverage receipt hunk count exceeds envelope range")?,
                            direct_hunks: u32::try_from(receipt.direct_hunks())
                                .context("direct hunk count exceeds envelope range")?,
                            semantic_hunks: u32::try_from(receipt.semantic_hunks())
                                .context("semantic hunk count exceeds envelope range")?,
                            unreviewed_hunks: u32::try_from(receipt.unreviewed_hunks())
                                .context("unreviewed hunk count exceeds envelope range")?,
                        })
                    })
                    .transpose()?;
                let deterministic_large_review = large_diff_receipt.is_some();
                if let Some(registrar) = DurablePlanRegistrar::from_env()? {
                    let durable_plan = if let Some(receipt) = &large_diff_receipt {
                        DurableReviewPlan::new(
                            receipt.plan_sha256.clone(),
                            u32::try_from(receipt.direct_hunks())
                                .context("direct hunk count exceeds durable plan range")?,
                            u32::try_from(receipt.semantic_hunks())
                                .context("semantic hunk count exceeds durable plan range")?,
                            u32::try_from(receipt.unreviewed_hunks())
                                .context("unreviewed hunk count exceeds durable plan range")?,
                            u32::try_from(receipt.selected_batch_ids.len())
                                .context("selected batch count exceeds durable plan range")?,
                            u32::try_from(batches.count)
                                .context("total batch count exceeds durable plan range")?,
                            u32::try_from(MAX_LARGE_DIFF_CONCURRENCY)
                                .context("review concurrency exceeds durable plan range")?,
                            u32::try_from(LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS)
                                .context("request timeout exceeds durable plan range")?,
                            u32::try_from(HOSTED_LLM_REVIEW_TIMEOUT_SECS)
                                .context("review budget exceeds durable plan range")?,
                        )?
                    } else {
                        let inventory = batches.durable_request_plan()?;
                        DurableReviewPlan::new(
                            inventory.plan_sha256,
                            u32::try_from(inventory.direct_hunks)
                                .context("direct hunk count exceeds durable plan range")?,
                            0,
                            0,
                            u32::try_from(inventory.selected_batches)
                                .context("selected batch count exceeds durable plan range")?,
                            u32::try_from(inventory.total_batches)
                                .context("total batch count exceeds durable plan range")?,
                            1,
                            u32::try_from(HOSTED_LLM_REQUEST_TIMEOUT_SECS)
                                .context("request timeout exceeds durable plan range")?,
                            u32::try_from(HOSTED_LLM_REVIEW_TIMEOUT_SECS)
                                .context("review budget exceeds durable plan range")?,
                        )?
                    };
                    registrar.register(&durable_plan).await?;
                }
                let bounded_candidates = if large_diff_receipt.is_none()
                    && (args.bounded || crate::config::bounded_review_selection_mode())
                    && batches.count > MAX_HOSTED_SELECTED_BATCHES
                {
                    Some(batches.hosted_candidates(
                        MAX_HOSTED_SELECTED_BATCHES,
                        MAX_HOSTED_PLANNER_CANDIDATES,
                    )?)
                } else {
                    None
                };
                let client = match llm_budget_started_at {
                    Some(started_at) => LlmClient::from_env_for_remote_review(
                        cfg,
                        started_at,
                        Duration::from_secs(hosted_request_timeout_secs(
                            deterministic_large_review,
                        )),
                        Duration::from_secs(HOSTED_LLM_REVIEW_TIMEOUT_SECS),
                        Duration::from_secs(HOSTED_LLM_TOTAL_TIMEOUT_SECS),
                    )?,
                    None => LlmClient::from_env(cfg)?,
                };
                let planned_batch_count = large_diff_receipt.as_ref().map_or_else(
                    || {
                        bounded_candidates
                            .as_ref()
                            .map_or(batches.count, |_| MAX_HOSTED_SELECTED_BATCHES)
                    },
                    |receipt| receipt.selected_batch_ids.len(),
                );
                let preflight_prompt_context = ReviewBatchPromptContext {
                    cfg,
                    repo,
                    meta,
                    incremental,
                    content_policy_active,
                    bounded_selection: bounded_candidates.is_some() || deterministic_large_review,
                    multiple: planned_batch_count > 1,
                };
                if crate::config::hosted_runtime_mode() {
                    let preflight_ids = if let Some(receipt) = &large_diff_receipt {
                        receipt.selected_batch_ids.clone()
                    } else if let Some(candidates) = &bounded_candidates {
                        candidates
                            .candidate_ids
                            .iter()
                            .chain(&candidates.mandatory_ids)
                            .copied()
                            .collect::<std::collections::BTreeSet<_>>()
                    } else {
                        (1..=batches.count).collect()
                    };
                    let preflight_batches = batches.selected_batches(&preflight_ids)?;
                    let candidate_prompts = preflight_batches
                        .into_iter()
                        .map(|batch| {
                            let (_, first, synthesis) =
                                review_batch_prompt(&preflight_prompt_context, batch.clone(), true);
                            let (_, later, _) =
                                review_batch_prompt(&preflight_prompt_context, batch, false);
                            let max_tokens =
                                review_output_token_limit(synthesis, deterministic_large_review);
                            (first, later, max_tokens)
                        })
                        .collect::<Vec<_>>();
                    let candidate_first_users = candidate_prompts
                        .iter()
                        .map(|(first, _, _)| first.clone())
                        .collect::<Vec<_>>();
                    let candidate_output_tokens = candidate_prompts
                        .iter()
                        .map(|(_, _, max_tokens)| *max_tokens)
                        .collect::<Vec<_>>();
                    let candidate_later_users = candidate_prompts
                        .into_iter()
                        .map(|(_, later, _)| later)
                        .collect::<Vec<_>>();
                    let planner = bounded_candidates.as_ref().and_then(|candidates| {
                        let remaining = MAX_HOSTED_SELECTED_BATCHES
                            .saturating_sub(candidates.mandatory_ids.len());
                        (remaining > 0
                            && candidates
                                .candidate_ids
                                .iter()
                                .any(|id| !candidates.mandatory_ids.contains(id)))
                        .then_some((candidates.manifest.as_str(), remaining))
                    });
                    let admission = if candidate_output_tokens
                        .iter()
                        .all(|max_tokens| *max_tokens == crate::llm::REVIEW_MAX_TOKENS)
                    {
                        client.preflight_review_plan(
                            cfg,
                            planned_batch_count,
                            &system,
                            &candidate_first_users,
                            &candidate_later_users,
                            planner,
                        )?
                    } else {
                        client.preflight_review_plan_with_output_limits(
                            cfg,
                            planned_batch_count,
                            &system,
                            crate::llm::ReviewPreflightPrompts {
                                first_users: &candidate_first_users,
                                later_users: &candidate_later_users,
                                output_tokens: &candidate_output_tokens,
                            },
                            planner,
                        )?
                    };
                    review_admission = Some(admission);
                    if crate::config::qualification_plan_only() {
                        let bounded = bounded_candidates.is_some() || large_diff_receipt.is_some();
                        let source_count = batches.source_count;
                        let selected_count = if let Some(receipt) = &large_diff_receipt {
                            batches.selected_source_count(&receipt.selected_batch_ids)
                        } else if bounded {
                            source_count
                                .min(MAX_HOSTED_SELECTED_BATCHES.saturating_sub(1))
                                .min(source_count.saturating_sub(1))
                        } else {
                            source_count
                        };
                        return Ok(qualification_plan_envelope(
                            cfg,
                            meta,
                            head_sha,
                            args.since_sha.clone(),
                            admission,
                            ReviewCoverage {
                                mode: if bounded {
                                    ReviewCoverageMode::Bounded
                                } else {
                                    ReviewCoverageMode::Exhaustive
                                },
                                selected_batches: u32::try_from(selected_count).context(
                                    "planned selected batch count exceeds envelope range",
                                )?,
                                total_batches: u32::try_from(source_count)
                                    .context("planned total batch count exceeds envelope range")?,
                                planner_fallback: false,
                                receipt: large_receipt_summary.clone(),
                            },
                            review_started.elapsed().as_millis() as u64,
                        ));
                    }
                }
                let mut selected_batches = None;
                let total_source_batches = batches.source_count;
                let mut selected_source_batches = total_source_batches;
                let mut planner_fallback = false;
                if let Some(receipt) = large_diff_receipt {
                    selected_source_batches =
                        batches.selected_source_count(&receipt.selected_batch_ids);
                    let selected = batches.selected_batches(&receipt.selected_batch_ids)?;
                    anyhow::ensure!(
                        selected.len() <= MAX_LARGE_DIFF_SELECTED_BATCHES,
                        "deterministic large-review plan exceeded its request bound"
                    );
                    selected_batches = Some(selected.into_iter());
                } else if let Some(candidates) = bounded_candidates {
                    anyhow::ensure!(
                        candidates.source_batch_count == total_source_batches,
                        "bounded planner source-batch inventory changed during selection"
                    );
                    let remaining =
                        MAX_HOSTED_SELECTED_BATCHES.saturating_sub(candidates.mandatory_ids.len());
                    let mut additional_candidates = candidates.candidate_ids.clone();
                    for id in &candidates.mandatory_ids {
                        additional_candidates.remove(id);
                    }
                    let mut ids = candidates
                        .mandatory_ids
                        .into_iter()
                        .collect::<std::collections::BTreeSet<_>>();
                    if remaining > 0 && !additional_candidates.is_empty() {
                        let plan = client
                            .plan_review_batches(
                                cfg,
                                &candidates.manifest,
                                &additional_candidates,
                                remaining,
                            )
                            .await?;
                        usage.prompt_tokens =
                            usage.prompt_tokens.saturating_add(plan.usage.prompt_tokens);
                        usage.completion_tokens = usage
                            .completion_tokens
                            .saturating_add(plan.usage.completion_tokens);
                        model_usage.extend(plan.model_usage);
                        model_incidents.extend(plan.model_incidents);
                        usage_accounting_complete &= plan.usage_accounting_complete;
                        planner_fallback = plan.fallback_used;
                        for id in plan.batch_ids {
                            if ids.len() >= MAX_HOSTED_SELECTED_BATCHES {
                                break;
                            }
                            ids.insert(id);
                        }
                    }
                    selected_source_batches = batches.selected_source_count(&ids);
                    let selected = batches.selected_batches(&ids)?;
                    let selected_synthesis_requests =
                        selected.len().saturating_sub(selected_source_batches);
                    eprintln!(
                        "postil: bounded selection uses {selected_source_batches} of {total_source_batches} source batches and {selected_synthesis_requests} synthesis requests (planner fallback={planner_fallback})",
                    );
                    selected_batches = Some(selected.into_iter());
                }
                let total_requests = selected_batches
                    .as_ref()
                    .map_or(batches.count, |selected| selected.len());
                let risk_selected_review = selected_batches.is_some();
                let coverage_incomplete = large_receipt_summary
                    .as_ref()
                    .is_some_and(|receipt| receipt.unreviewed_hunks > 0);
                let runtime_prompt_context = ReviewBatchPromptContext {
                    multiple: total_requests > 1,
                    ..preflight_prompt_context
                };
                review_coverage = Some(ReviewCoverage {
                    mode: if risk_selected_review {
                        ReviewCoverageMode::Bounded
                    } else {
                        ReviewCoverageMode::Exhaustive
                    },
                    selected_batches: u32::try_from(selected_source_batches)
                        .context("selected review batch count exceeds envelope range")?,
                    total_batches: u32::try_from(total_source_batches)
                        .context("total review batch count exceeds envelope range")?,
                    planner_fallback,
                    receipt: large_receipt_summary,
                });
                let mut raw_findings = Vec::new();
                let mut summary_parts = Vec::new();
                let mut finding_contexts = Vec::new();
                let mut batch_models = Vec::new();
                let mut batch_failed = false;
                let mut batch_failure = None;
                if coverage_incomplete {
                    batch_failed = true;
                    batch_failure = Some(fail_closed_finding(
                        "deterministic large-review coverage left one or more normalized hunks unreviewed",
                    ));
                }
                let mut batch_ungrounded = 0u32;
                let mut request_index = 0usize;
                let mut batch_requests = Vec::with_capacity(total_requests);
                loop {
                    let next = if let Some(selected) = selected_batches.as_mut() {
                        selected.next()
                    } else {
                        batches.next_batch()?
                    };
                    let Some(batch) = next else { break };
                    let first = request_index == 0;
                    let (annotated, user, cross_window_synthesis) =
                        review_batch_prompt(&runtime_prompt_context, batch, first);
                    // Synthesis digests can ground new cross-window findings, but
                    // they are lossy summaries rather than direct source coverage.
                    // Only selected source requests may retire baseline evidence.
                    if !cross_window_synthesis {
                        index.add_rendered_evidence(&annotated);
                    }
                    eprintln!(
                        "postil: queued {} request {}/{} ({} bytes)",
                        if cross_window_synthesis {
                            "synthesis"
                        } else {
                            "source"
                        },
                        request_index + 1,
                        total_requests,
                        annotated.len()
                    );
                    batch_requests.push((
                        request_index,
                        annotated,
                        user,
                        cross_window_synthesis,
                        first,
                    ));
                    request_index += 1;
                }
                let concurrency = if deterministic_large_review {
                    MAX_LARGE_DIFF_CONCURRENCY
                } else {
                    1
                };
                let cfg_owned = cfg.clone();
                let system_owned = system.clone();
                let mut outcomes = futures::stream::iter(batch_requests.into_iter().map(
                    |(index, annotated, user, cross_window_synthesis, first)| {
                        let client = client.clone();
                        let cfg = cfg_owned.clone();
                        let system = system_owned.clone();
                        async move {
                            eprintln!(
                                "postil: reviewing {} request {}/{} ({} bytes)",
                                if cross_window_synthesis {
                                    "synthesis"
                                } else {
                                    "source"
                                },
                                index + 1,
                                total_requests,
                                annotated.len()
                            );
                            let validation_annotated = annotated.clone();
                            let validation_user = user.clone();
                            let max_tokens = review_output_token_limit(
                                cross_window_synthesis,
                                deterministic_large_review,
                            );
                            let result = client
                                .review_validated_with_safe_output_limit(
                                    &cfg,
                                    &system,
                                    &user,
                                    max_tokens,
                                    move |review| {
                                        review_batch_validation_reasons(
                                            &review.findings,
                                            &validation_annotated,
                                            first.then_some(validation_user.as_str()),
                                        )
                                        .map_or(Ok(()), Err)
                                    },
                                )
                                .await;
                            (
                                index,
                                annotated,
                                user,
                                cross_window_synthesis,
                                first,
                                result,
                            )
                        }
                    },
                ))
                .buffer_unordered(concurrency)
                .collect::<Vec<_>>()
                .await;
                outcomes.sort_by_key(|(index, ..)| *index);
                for (_index, annotated, user, _cross_window_synthesis, first, result) in outcomes {
                    match result {
                        Ok(mut model_review) => {
                            add_usage(&mut usage, model_review.usage);
                            model_usage.extend(model_review.model_usage);
                            model_incidents.extend(model_review.model_incidents);
                            usage_accounting_complete &= model_review.usage_accounting_complete;
                            if !batch_models.contains(&model_review.model_used) {
                                batch_models.push(model_review.model_used);
                            }
                            if !model_review.summary.trim().is_empty()
                                && summary_parts.iter().map(String::len).sum::<usize>()
                                    < MAX_STREAMED_SUMMARY_BYTES
                            {
                                summary_parts.push(model_review.summary);
                            }
                            for finding in &mut model_review.findings {
                                if finding.end_line.is_some_and(|end| {
                                    !diff::review_batch_contains_range(
                                        &annotated,
                                        &finding.path,
                                        finding.line,
                                        end,
                                    )
                                }) {
                                    finding.end_line = None;
                                }
                            }
                            let before = model_review.findings.len();
                            model_review.findings.retain_mut(|finding| {
                                let canonical_evidence = diff::review_batch_canonical_evidence(
                                    &annotated,
                                    &finding.path,
                                    finding.line,
                                    finding.evidence.as_deref(),
                                )
                                .or_else(|| {
                                    (first && finding.kind == crate::envelope::Kind::ContentPolicy)
                                        .then(|| {
                                            diff::review_batch_canonical_evidence(
                                                &user,
                                                &finding.path,
                                                finding.line,
                                                finding.evidence.as_deref(),
                                            )
                                        })
                                        .flatten()
                                });
                                if let Some(evidence) = canonical_evidence {
                                    finding.evidence = Some(evidence);
                                    true
                                } else {
                                    false
                                }
                            });
                            for finding in &mut model_review.findings {
                                finding.path = diff::canonical_prompt_path(&finding.path)
                                    .expect("grounded prompt paths are reversible");
                            }
                            let candidate_limit = cfg
                                .max_findings
                                .saturating_mul(MAX_STREAMED_CANDIDATE_MULTIPLIER)
                                .max(cfg.max_findings);
                            if !model_review.findings.is_empty()
                                && finding_contexts.len() < candidate_limit
                            {
                                finding_contexts.push(annotated.clone());
                            }
                            batch_ungrounded += (before - model_review.findings.len()) as u32;
                            raw_findings.extend(model_review.findings);
                            if raw_findings.len() > candidate_limit {
                                sort_findings_for_display(&mut raw_findings);
                                raw_findings.truncate(candidate_limit);
                            }
                        }
                        Err(e) => {
                            add_usage(&mut usage, e.usage());
                            model_usage.extend_from_slice(e.model_usage());
                            model_incidents.extend_from_slice(e.model_incidents());
                            usage_accounting_complete &= e.usage_accounting_complete();
                            let detail = format!("{e:#}");
                            if batch_failure.is_none() {
                                batch_failure = Some(if e.is_provider() {
                                    crate::envelope::provider_error_finding(&detail)
                                } else {
                                    fail_closed_finding(&detail)
                                });
                            }
                            if batch_models.is_empty() {
                                model_used = cfg.model_chain().join(" -> ");
                            }
                            batch_failed = true;
                        }
                    }
                }
                if !batch_models.is_empty() {
                    model_used = batch_models.join(", ");
                }
                if total_requests > 0 {
                    let mut deduplicated = Vec::<Finding>::new();
                    let mut positions: HashMap<_, usize> = HashMap::new();
                    for finding in raw_findings {
                        let key = (
                            finding.path.clone(),
                            finding.kind.as_str().to_string(),
                            finding.title.trim().to_ascii_lowercase(),
                            finding.evidence.clone(),
                        );
                        if let Some(position) = positions.get(&key).copied() {
                            let existing = &mut deduplicated[position];
                            if (finding.severity, finding.confidence)
                                > (existing.severity, existing.confidence)
                            {
                                *existing = finding;
                            }
                        } else {
                            positions.insert(key, deduplicated.len());
                            deduplicated.push(finding);
                        }
                    }
                    let raw_findings = deduplicated;
                    let grounded_candidate_count = raw_findings.len();
                    let outcome = filter::apply(cfg, &index, raw_findings)?;
                    suppressed = outcome.suppressed;
                    suppressed_findings = outcome.suppressed_findings;
                    ungrounded = outcome.ungrounded + batch_ungrounded;
                    if outcome.all_ungrounded
                        || (grounded_candidate_count == 0 && batch_ungrounded > 0)
                    {
                        findings = vec![fail_closed_finding(&format!(
                            "model reported {} finding(s), none grounded in the diff",
                            ungrounded
                        ))];
                    } else if outcome.kept.is_empty() && !summary_parts.is_empty() {
                        // Risk narrated in prose while NO finding survives to the
                        // gate. Passing this as clean is the predecessor product's
                        // worst failure mode; fail closed instead and carry the
                        // narration into the finding so it is not lost.
                        //
                        // Keyed on the POST-FILTER kept set, not raw_findings: the
                        // hole this closes is a model that returns findings which are
                        // all removed by min_confidence/severity/ignore suppression
                        // (so raw_findings != 0) while the summary still narrates
                        // risk. That previously slipped through silently. The
                        // all_ungrounded case is handled above, so this branch only
                        // fires for the genuinely-empty-after-policy case and does
                        // not double-fire.
                        findings = vec![crate::envelope::narrated_risk_finding(
                            &summary_parts.join("\n\n"),
                        )];
                    } else {
                        // Bounded mode reviews deterministic direct evidence and
                        // lossy synthesis, not every source batch. Reconciliation
                        // carries baseline evidence outside the selected input.
                        // A changed citation expires only when a completed model
                        // request covered its coordinate and did not reproduce it.
                        review_trust = if batch_failed {
                            filter::ReviewTrust::Failed
                        } else if risk_selected_review {
                            filter::ReviewTrust::Bounded
                        } else {
                            filter::ReviewTrust::Exhaustive
                        };
                        summary = summary_parts.join("\n\n");
                        let mut kept = outcome.kept;
                        if !kept.is_empty() && cfg.scorer_enabled() {
                            let inputs =
                                scorer_inputs(&diff::Diff::default(), &finding_contexts, &kept);
                            let scorer_system = prompt::scorer_system_prompt(cfg);
                            let scorer_user = prompt::scorer_user_prompt(&inputs);
                            if scorer_system.len().saturating_add(scorer_user.len())
                                > MAX_SCORER_PROMPT_BYTES
                            {
                                scorer_error = Some(
                                    "scorer skipped because its bounded input budget was exceeded"
                                        .to_string(),
                                );
                                scorer_failure_kind = Some(ReviewFailureKind::InvalidOutput);
                            } else {
                                let scored = client
                                    .score_findings(
                                        cfg,
                                        &scorer_system,
                                        &scorer_user,
                                        inputs.len(),
                                        std::time::Duration::from_secs(SCORER_TIMEOUT_SECS),
                                    )
                                    .await;
                                match scored {
                                    Ok(scored) => {
                                        let disagreements =
                                            apply_scorer_scores(cfg, &mut kept, scored.scores);
                                        let scorer_suppressed =
                                            suppress_below_min_confidence(cfg, &mut kept);
                                        suppressed += scorer_suppressed.len() as u32;
                                        suppressed_findings.extend(scorer_suppressed);
                                        scorer_model = Some(scored.model_used);
                                        add_usage(&mut usage, scored.usage);
                                        model_usage.extend(scored.model_usage);
                                        model_incidents.extend(scored.model_incidents);
                                        usage_accounting_complete &=
                                            scored.usage_accounting_complete;
                                        scorer_disagreements = Some(disagreements);
                                        sort_findings_for_display(&mut kept);
                                    }
                                    Err(e) => {
                                        let detail = format!("{e:#}");
                                        eprintln!(
                                            "postil: scorer failed open after all scorer models failed"
                                        );
                                        let scorer_usage = e.usage();
                                        add_usage(&mut usage, scorer_usage);
                                        model_usage.extend_from_slice(e.model_usage());
                                        model_incidents.extend_from_slice(e.model_incidents());
                                        usage_accounting_complete &= e.usage_accounting_complete();
                                        scorer_failure_kind =
                                            Some(classify_exhausted_scorer_failure(
                                                e.model_incidents(),
                                                e.is_provider(),
                                            ));
                                        scorer_error = Some(detail);
                                    }
                                }
                            }
                            if scorer_failure_blocks_hosted(
                                crate::config::hosted_runtime_mode(),
                                scorer_error.is_some(),
                            ) {
                                return Err(ReviewFailure {
                                    kind: scorer_failure_kind
                                        .unwrap_or(ReviewFailureKind::InvalidOutput),
                                    detail: "hosted scorer could not complete the admitted profile"
                                        .to_string(),
                                    model_used: model_used.clone(),
                                    scorer_model: Some(cfg.scorer_chain().join(" -> ")),
                                    scorer_error: scorer_error.clone(),
                                    usage,
                                    model_usage,
                                    model_incidents,
                                    review_coverage,
                                    review_admission,
                                    usage_accounting_complete,
                                }
                                .into());
                            }
                        }
                        findings = kept;
                    }
                }
                if let Some(failure) = batch_failure {
                    findings.push(failure);
                }
            }
        }
    }

    // Fresh metadata IDs must exist before reconciliation: synthetic line
    // numbers are presentation positions, not issue identity.
    generate_finding_ids(&mut findings, head_sha.as_deref());

    // Reconcile against the previous review (incremental or full re-review).
    // Skip entirely when review is disabled: a repo that set `enabled: false`
    // must not have a supplied baseline carry Errors that fail the gate. With
    // review off there is no fresh signal to reconcile against, so honoring the
    // disable means dropping the baseline carry-forward too.
    let rec = if cfg.enabled {
        let scope = match scope {
            filter::ReconcileScope::Incremental { .. } => filter::ReconcileScope::Incremental {
                trust: review_trust,
            },
            filter::ReconcileScope::Full { .. } => filter::ReconcileScope::Full {
                trust: review_trust,
            },
        };
        filter::reconcile(&baseline, &index, &findings, scope)
    } else {
        filter::Reconciliation {
            resolved: vec![],
            carried: vec![],
        }
    };
    // Carried findings are durable historical state and are excluded from all
    // forge publication sinks. They may predate the current prose contract, so
    // keep them open without revalidating them as fresh model output. Fresh
    // findings are validated before they can reach reconciliation.
    findings.extend(rec.carried);

    // Operational findings (model unreachable/unusable) fail the gate by default
    // and fail closed. `gate.onError: advisory` lets the gate stand aside on a
    // provider outage so a blip does not freeze every merge; the finding still
    // shows in the output and the advisory check goes neutral. Unusable model
    // output (OPERATIONAL_PATH) never bypasses the gate: a malicious diff can
    // induce it via prompt injection.
    let advisory_on_error = cfg.gate_on_error == OnError::Advisory;
    let gate_fail_on = cfg.gate_fail_on.as_str();
    let gate_disabled = gate_fail_on.eq_ignore_ascii_case("never");
    let gate_block_on_kinds: Vec<String> = cfg
        .block_on_kinds
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect();
    let gate_failing = findings.iter().any(|f| {
        if gate_disabled {
            false
        } else if f.path == crate::envelope::OPERATIONAL_PATH {
            true
        } else if f.path == crate::envelope::PROVIDER_PATH {
            !advisory_on_error
        } else {
            crate::envelope::finding_blocks_gate(f, gate_fail_on, &gate_block_on_kinds, false)
        }
    });
    let silent = findings.is_empty();
    let mut counts = Envelope::counts_of(&findings, suppressed);
    counts.ungrounded = ungrounded;
    let buckets = Envelope::buckets_of(&findings);

    // Generate stable IDs for findings
    generate_finding_ids(&mut findings, head_sha.as_deref());
    model_usage.sort_by_key(|entry| entry.call_ordinal.unwrap_or(u32::MAX));

    Ok(Envelope {
        version: 1,
        summary: if silent { String::new() } else { summary },
        silent,
        findings,
        suppressed_findings,
        resolved: rec.resolved,
        counts,
        confidence_buckets: buckets,
        gate: Gate {
            fail_on: cfg.gate_fail_on.as_str().to_string(),
            failing: gate_failing,
            block_on_kinds: gate_block_on_kinds,
        },
        model_used,
        scorer_model,
        scorer_error,
        scorer_disagreements,
        usage,
        model_usage,
        model_incidents,
        review_coverage,
        review_admission,
        usage_accounting_complete,
        duration_ms: review_started.elapsed().as_millis() as u64,
        base_sha: meta.map(|m| m.base_sha.clone()),
        head_sha,
        since_sha: args.since_sha.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn qualification_plan_envelope(
    cfg: &Config,
    meta: Option<&PrMeta>,
    head_sha: Option<String>,
    since_sha: Option<String>,
    review_admission: ReviewAdmission,
    review_coverage: ReviewCoverage,
    duration_ms: u64,
) -> Envelope {
    Envelope {
        version: 1,
        summary: String::new(),
        silent: true,
        findings: vec![],
        suppressed_findings: vec![],
        resolved: vec![],
        counts: Default::default(),
        confidence_buckets: [0; 5],
        gate: Gate {
            fail_on: cfg.gate_fail_on.as_str().to_string(),
            failing: false,
            block_on_kinds: cfg
                .block_on_kinds
                .iter()
                .map(|kind| kind.as_str().to_string())
                .collect(),
        },
        model_used: "none (qualification plan)".to_string(),
        scorer_model: None,
        scorer_error: None,
        scorer_disagreements: None,
        usage: Usage::default(),
        model_usage: vec![],
        model_incidents: vec![],
        review_coverage: Some(review_coverage),
        review_admission: Some(review_admission),
        usage_accounting_complete: true,
        duration_ms,
        base_sha: meta.map(|value| value.base_sha.clone()),
        head_sha,
        since_sha,
    }
}

fn scorer_failure_blocks_hosted(hosted: bool, scorer_failed: bool) -> bool {
    hosted && scorer_failed
}

async fn finish<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    envelope: Envelope,
    forge: Option<&F>,
    hosted_budget_started_at: Option<Instant>,
    expected_snapshot: Option<&PrMeta>,
    strict_publication: bool,
) -> Result<i32> {
    // Persist artifacts before any forge I/O: a posting hiccup must not
    // discard the completed review's SARIF or envelope output.
    if let Some(path) = &args.sarif {
        let sarif = crate::sarif::to_sarif(&envelope);
        std::fs::write(path, serde_json::to_string_pretty(&sarif)?)
            .with_context(|| format!("writing SARIF to {}", path.display()))?;
    }

    if let Some(format) = args.resolved_output_format() {
        output::write_envelope(&envelope, format, args.output_file.as_deref())?;
    }
    if args.resolved_output_format().is_none() || args.output_file.is_some() {
        output::print_pretty(&envelope);
    }

    if let Some(forge) = forge
        && !args.no_post
    {
        let expected_snapshot =
            expected_snapshot.context("remote publication is missing its immutable PR snapshot")?;
        let duplicate_of_baseline = load_baseline(args)
            .ok()
            .is_some_and(|baseline| visible_finding_sets_equal(&baseline, &envelope.findings));
        let intentional_no_comment = crate::forge::only_operational_findings(&envelope.findings)
            || (!envelope.findings.is_empty() && envelope.findings.iter().all(filter::is_carried));
        let should_comment = (!envelope.silent
            || matches!(cfg.on_clean, crate::config::OnClean::Comment))
            && !duplicate_of_baseline
            && !intentional_no_comment;
        if !should_comment {
            let mut receipt = forge.plan_review_publication(&envelope, expected_snapshot);
            if duplicate_of_baseline {
                for finding in &mut receipt.findings {
                    if matches!(
                        finding.initial_outcome,
                        crate::forge::FindingPublicationOutcome::Inline
                            | crate::forge::FindingPublicationOutcome::SummaryOnly
                    ) {
                        finding.initial_outcome = crate::forge::FindingPublicationOutcome::Carried;
                        finding.inline_rejected = false;
                        finding.comment_id = None;
                    }
                }
            }
            crate::forge::write_review_publication_receipt_from_env(&receipt)?;
            return Ok(if envelope.gate.failing { 1 } else { 0 });
        }
        let freshness = if let Some(started_at) = hosted_budget_started_at {
            snapshot_is_current(forge, expected_snapshot, started_at).await
        } else {
            forge.snapshot_is_current(expected_snapshot).await
        };
        match freshness {
            Ok(true) => {}
            Ok(false) if strict_publication => {
                return Err(anyhow!(
                    "required review publication skipped because the pull request snapshot changed after review"
                ));
            }
            Ok(false) => {
                eprintln!(
                    "postil: publication skipped because the pull request snapshot changed after review"
                );
                return Ok(if envelope.gate.failing { 1 } else { 0 });
            }
            Err(error) if strict_publication => {
                return Err(error).context(
                    "required review publication skipped because snapshot freshness could not be verified",
                );
            }
            Err(error) => {
                eprintln!(
                    "postil: publication skipped because snapshot freshness could not be verified ({error:#})"
                );
                return Ok(if envelope.gate.failing { 1 } else { 0 });
            }
        }
        let posted = run_with_hosted_budget(
            hosted_budget_started_at,
            REVIEW_POST_TIMEOUT_SECS,
            forge.post_review(&envelope, expected_snapshot),
            "posting review comment",
        )
        .await;
        match posted {
            Ok(receipt) => {
                crate::forge::write_review_publication_receipt_from_env(&receipt)?;
            }
            Err(e) => {
                if crate::forge::is_repository_identity_failure(&e) {
                    return Err(e);
                }
                if strict_publication {
                    return Err(e).context("required hosted review publication failed");
                }
                eprintln!("postil: could not post review comment ({e:#})");
            }
        }
    }
    Ok(if envelope.gate.failing { 1 } else { 0 })
}

async fn run_with_hosted_budget<T>(
    hosted_budget_started_at: Option<Instant>,
    cap_secs: u64,
    future: impl std::future::Future<Output = Result<T>>,
    operation: &str,
) -> Result<T> {
    let Some(started_at) = hosted_budget_started_at else {
        return future.await;
    };
    let Some(remaining) = hosted_worker_remaining(started_at) else {
        return Err(anyhow!(
            "hosted watchdog budget exhausted before {operation}"
        ));
    };
    let timeout = remaining.min(Duration::from_secs(cap_secs));
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "{operation} timed out after {}s of hosted budget",
            timeout.as_secs()
        )),
    }
}

fn hosted_worker_remaining(started_at: Instant) -> Option<Duration> {
    (started_at + Duration::from_secs(HOSTED_WORKER_WATCHDOG_SECS))
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

fn visible_finding_sets_equal(previous: &[Finding], current: &[Finding]) -> bool {
    // Operational findings represent this run's health and must stay visible
    // even if an earlier run produced the same marker. Reviewable virtual
    // anchors participate in ordinary duplicate suppression.
    if previous.is_empty()
        || current.is_empty()
        || previous.len() != current.len()
        || previous
            .iter()
            .chain(current)
            .any(|f| crate::envelope::is_ephemeral_anchor(&f.path))
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

fn baseline_has_carryable_findings(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|finding| !crate::envelope::is_ephemeral_anchor(&finding.path))
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
    let incomplete_input = crate::forge::is_incomplete_review_input(err);
    let review_failure = err.downcast_ref::<ReviewFailure>();
    let invalid_output =
        review_failure.is_some_and(|failure| failure.kind == ReviewFailureKind::InvalidOutput);
    let findings = vec![if incomplete_input {
        crate::envelope::incomplete_review_finding()
    } else if invalid_output {
        fail_closed_finding(
            review_failure
                .and_then(|failure| failure.scorer_error.as_deref())
                .unwrap_or("scorer output did not satisfy the admitted contract"),
        )
    } else {
        crate::envelope::provider_error_finding(&format!("{err:#}"))
    }];
    let counts = Envelope::counts_of(&findings, 0);
    let buckets = Envelope::buckets_of(&findings);
    let gate_disabled = cfg.gate_fail_on.as_str().eq_ignore_ascii_case("never");
    let blocking = !gate_disabled
        && (incomplete_input || invalid_output || cfg.gate_on_error == OnError::Block);
    let mut model_usage = review_failure
        .map(|failure| failure.model_usage.clone())
        .unwrap_or_default();
    model_usage.sort_by_key(|entry| entry.call_ordinal.unwrap_or(u32::MAX));
    Envelope {
        version: 1,
        summary: if blocking {
            "Postil could not complete this review and is failing closed.".to_string()
        } else if gate_disabled {
            "Postil could not complete this review. The merge gate is disabled; the error is shown on postil/review."
                .to_string()
        } else {
            "Postil could not complete this review. The gate is passing because this \
             repository sets gate.onError: advisory; the error is shown on postil/review."
                .to_string()
        },
        silent: false,
        findings,
        suppressed_findings: vec![],
        resolved: vec![],
        counts,
        confidence_buckets: buckets,
        gate: Gate {
            fail_on: cfg.gate_fail_on.as_str().to_string(),
            failing: blocking,
            block_on_kinds: cfg
                .block_on_kinds
                .iter()
                .map(|k| k.as_str().to_string())
                .collect(),
        },
        model_used: review_failure.map_or_else(
            || cfg.model_chain().join(" -> "),
            |failure| failure.model_used.clone(),
        ),
        scorer_model: review_failure.and_then(|failure| failure.scorer_model.clone()),
        scorer_error: review_failure.and_then(|failure| failure.scorer_error.clone()),
        scorer_disagreements: None,
        usage: review_failure.map_or_else(Usage::default, |failure| failure.usage),
        model_usage,
        model_incidents: review_failure
            .map(|failure| failure.model_incidents.clone())
            .unwrap_or_default(),
        review_coverage: review_failure.and_then(|failure| failure.review_coverage.clone()),
        review_admission: review_failure.and_then(|failure| failure.review_admission),
        usage_accounting_complete: review_failure
            .is_none_or(|failure| failure.usage_accounting_complete),
        duration_ms,
        base_sha: Some(meta.base_sha.clone()),
        head_sha: Some(head_sha.to_string()),
        since_sha: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_and_runtime_share_large_review_output_limits() {
        assert_eq!(review_output_token_limit(false, true), 6_000);
        assert_eq!(review_output_token_limit(true, true), 2_000);
        assert_eq!(
            review_output_token_limit(false, false),
            crate::llm::REVIEW_MAX_TOKENS
        );
        assert_eq!(review_output_token_limit(true, false), 2_000);
    }

    #[test]
    fn hosted_scorer_failure_blocks_unscored_output() {
        assert!(scorer_failure_blocks_hosted(true, true));
        assert!(!scorer_failure_blocks_hosted(true, false));
        assert!(!scorer_failure_blocks_hosted(false, true));
    }
    use crate::envelope::{Kind, Severity};

    fn pr_meta() -> PrMeta {
        PrMeta {
            title: "Fixture".to_string(),
            body: String::new(),
            head_sha: "head".to_string(),
            base_sha: "base".to_string(),
            target_sha: Some("target".to_string()),
            changed_files: Some(1),
        }
    }

    #[test]
    fn disabled_gate_keeps_provider_error_envelopes_nonblocking() {
        let cfg = Config {
            gate_fail_on: crate::config::GateLevel::Never,
            gate_on_error: OnError::Block,
            ..Config::default()
        };
        let envelope = error_envelope(
            &cfg,
            &anyhow::anyhow!("provider unavailable"),
            "head",
            &pr_meta(),
            1,
        );
        assert!(!envelope.gate.failing);
        assert!(envelope.summary.contains("merge gate is disabled"));
    }

    fn rich_scorer_failure(kind: ReviewFailureKind) -> anyhow::Error {
        ReviewFailure {
            kind,
            detail: "hosted scorer could not complete the admitted profile".to_string(),
            model_used: "generator-model".to_string(),
            scorer_model: Some("scorer-model".to_string()),
            scorer_error: Some("scorer output invalid after schema repair".to_string()),
            usage: Usage {
                prompt_tokens: 130,
                completion_tokens: 60,
                cost_micros: Some(168),
                provider_cost: crate::envelope::ProviderCost::parse("0.000168"),
            },
            model_usage: vec![
                serde_json::from_value(serde_json::json!({
                    "model": "scorer-model",
                    "role": "findingScorer",
                    "phase": "initial",
                    "callOrdinal": 2,
                    "attempt": 1,
                    "promptTokens": 30,
                    "completionTokens": 10,
                    "costMicros": 45,
                    "costProviderDecimal": "0.000045",
                    "costSource": "providerReported",
                    "accountingComplete": true
                }))
                .unwrap(),
                serde_json::from_value(serde_json::json!({
                    "model": "generator-model",
                    "role": "reviewGenerator",
                    "phase": "initial",
                    "callOrdinal": 1,
                    "attempt": 1,
                    "promptTokens": 100,
                    "completionTokens": 50,
                    "costMicros": 123,
                    "costProviderDecimal": "0.000123",
                    "costSource": "providerReported",
                    "accountingComplete": true
                }))
                .unwrap(),
            ],
            model_incidents: vec![ModelIncident {
                phase: crate::envelope::ModelIncidentPhase::Scorer,
                category: if kind == ReviewFailureKind::Provider {
                    crate::envelope::ModelIncidentCategory::ProviderError
                } else {
                    crate::envelope::ModelIncidentCategory::InvalidOutput
                },
                recovered: false,
                recovery: None,
            }],
            review_coverage: Some(ReviewCoverage {
                mode: ReviewCoverageMode::Bounded,
                selected_batches: 5,
                total_batches: 9,
                planner_fallback: false,
                receipt: None,
            }),
            review_admission: Some(ReviewAdmission {
                provider_attempts: 12,
                serialized_input_bytes: 34_000,
                output_tokens: 8_800,
                projected_cost_micros: 900_000,
            }),
            usage_accounting_complete: true,
        }
        .into()
    }

    #[test]
    fn invalid_scorer_failure_is_blocking_under_advisory_and_preserves_audit_state() {
        let cfg = Config {
            gate_on_error: OnError::Advisory,
            ..Config::default()
        };
        let error = rich_scorer_failure(ReviewFailureKind::InvalidOutput);
        let envelope = error_envelope(&cfg, &error, "head", &pr_meta(), 99);
        assert_eq!(envelope.findings[0].path, crate::envelope::OPERATIONAL_PATH);
        assert!(envelope.gate.failing);
        assert_eq!(envelope.model_used, "generator-model");
        assert_eq!(envelope.scorer_model.as_deref(), Some("scorer-model"));
        assert_eq!(
            envelope.scorer_error.as_deref(),
            Some("scorer output invalid after schema repair")
        );
        assert_eq!(
            envelope.usage.provider_cost.unwrap().to_string(),
            "0.000168"
        );
        assert_eq!(envelope.model_usage.len(), 2);
        assert_eq!(envelope.model_usage[0].model, "generator-model");
        assert_eq!(
            envelope.model_usage[1].cost_provider_decimal.as_deref(),
            Some("0.000045")
        );
        assert_eq!(envelope.model_incidents.len(), 1);
        assert_eq!(envelope.review_coverage.unwrap().total_batches, 9);
        assert_eq!(envelope.review_admission.unwrap().provider_attempts, 12);
        assert!(envelope.usage_accounting_complete);
    }

    #[test]
    fn provider_scorer_failure_uses_provider_path_and_advisory_gate() {
        let cfg = Config {
            gate_on_error: OnError::Advisory,
            ..Config::default()
        };
        let error = rich_scorer_failure(ReviewFailureKind::Provider);
        let envelope = error_envelope(&cfg, &error, "head", &pr_meta(), 99);
        assert_eq!(envelope.findings[0].path, crate::envelope::PROVIDER_PATH);
        assert!(!envelope.gate.failing);
        assert_eq!(envelope.model_usage.len(), 2);
        assert_eq!(envelope.review_admission.unwrap().provider_attempts, 12);
    }

    #[test]
    fn invalid_output_anywhere_in_exhausted_scorer_chain_dominates_provider_failure() {
        let incidents = vec![
            ModelIncident {
                phase: crate::envelope::ModelIncidentPhase::Scorer,
                category: ModelIncidentCategory::InvalidOutput,
                recovered: false,
                recovery: None,
            },
            ModelIncident {
                phase: crate::envelope::ModelIncidentPhase::Scorer,
                category: ModelIncidentCategory::ProviderError,
                recovered: false,
                recovery: None,
            },
        ];
        let kind = classify_exhausted_scorer_failure(&incidents, true);
        assert_eq!(kind, ReviewFailureKind::InvalidOutput);
        let cfg = Config {
            gate_on_error: OnError::Advisory,
            ..Config::default()
        };
        let envelope = error_envelope(&cfg, &rich_scorer_failure(kind), "head", &pr_meta(), 99);
        assert_eq!(envelope.findings[0].path, crate::envelope::OPERATIONAL_PATH);
        assert!(envelope.gate.failing);

        let recovered_invalid = vec![
            ModelIncident {
                recovered: true,
                recovery: Some(crate::envelope::ModelIncidentRecovery::Fallback),
                ..incidents[0].clone()
            },
            incidents[1].clone(),
        ];
        assert_eq!(
            classify_exhausted_scorer_failure(&recovered_invalid, true),
            ReviewFailureKind::Provider
        );
    }

    #[test]
    fn disabled_gate_keeps_incomplete_input_envelopes_nonblocking() {
        let cfg = Config {
            gate_fail_on: crate::config::GateLevel::Never,
            ..Config::default()
        };
        let error = crate::forge::classify_review_input_error(anyhow::anyhow!("invalid diff"));
        let envelope = error_envelope(&cfg, &error, "head", &pr_meta(), 1);
        assert!(!envelope.gate.failing);
        assert!(envelope.summary.contains("merge gate is disabled"));
    }

    fn finding(path: &str, line: u32, body: &str) -> Finding {
        finding_with_title(path, line, "Finding", body)
    }

    fn finding_with_title(path: &str, line: u32, title: &str, body: &str) -> Finding {
        Finding {
            path: path.to_string(),
            line,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: title.to_string(),
            body: body.to_string(),
            evidence: None,
            id: None,
        }
    }

    fn expected_finding_id(finding: &Finding, head_sha: &str, _duplicate_index: usize) -> String {
        let hash_input = format!(
            "{}\x00{}\x00{}\x00{}\x00{}",
            head_sha,
            finding.kind.as_str(),
            finding.path.to_lowercase(),
            finding.line,
            finding.title.trim().to_lowercase()
        );
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn assigned_id(findings: &[Finding], path: &str, line: u32, title: &str) -> String {
        findings
            .iter()
            .find(|finding| finding.path == path && finding.line == line && finding.title == title)
            .and_then(|finding| finding.id.clone())
            .expect("finding should have an assigned ID")
    }

    #[test]
    fn default_llm_timeouts_fit_inside_hosted_worker_watchdog() {
        const PROCESS_OVERHEAD_SECS: u64 = 10;

        assert_eq!(HOSTED_LLM_REQUEST_TIMEOUT_SECS, 240);
        assert_eq!(LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS, 60);
        assert_eq!(hosted_request_timeout_secs(false), 240);
        assert_eq!(hosted_request_timeout_secs(true), 60);
        assert_eq!(HOSTED_LLM_REVIEW_TIMEOUT_SECS, 420);
        assert_eq!(
            HOSTED_LLM_REVIEW_TIMEOUT_SECS,
            LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS * 6 + 60
        );
        assert_eq!(
            HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            HOSTED_LLM_REVIEW_TIMEOUT_SECS + SCORER_TIMEOUT_SECS
        );
        assert_eq!(
            HOSTED_WORKER_WATCHDOG_SECS - HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            CHECK_COMPLETION_TIMEOUT_SECS + REVIEW_POST_TIMEOUT_SECS + PROCESS_OVERHEAD_SECS
        );
    }

    #[tokio::test]
    async fn required_check_completion_timeout_overrides_a_gate_derived_success() {
        let started_at = Instant::now() - Duration::from_secs(HOSTED_WORKER_WATCHDOG_SECS)
            + Duration::from_millis(20);
        let completion = run_with_hosted_budget(
            Some(started_at),
            CHECK_COMPLETION_TIMEOUT_SECS,
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            },
            "completing check runs",
        )
        .await;
        let retained = retain_publication_failure(true, completion, "fixture warning")
            .unwrap()
            .expect("strict hosted publication retains the timeout");
        let error = combine_required_publication(Some(retained), Ok(0)).unwrap_err();

        assert!(format!("{error:#}").contains("completing check runs timed out"));
        assert!(
            error
                .to_string()
                .contains("required hosted check publication failed")
        );
    }

    #[test]
    fn stable_ids_do_not_share_duplicate_buckets_across_path_line_boundaries() {
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let abc_line_12 = finding_with_title("abc", 12, "Boundary collision", "first");
        let abc1_line_2 = finding_with_title("abc1", 2, "Boundary collision", "second");
        let expected_abc_line_12 = expected_finding_id(&abc_line_12, head_sha, 0);
        let expected_abc1_line_2 = expected_finding_id(&abc1_line_2, head_sha, 0);

        let mut findings = vec![abc_line_12.clone(), abc1_line_2.clone()];
        generate_finding_ids(&mut findings, Some(head_sha));
        assert_eq!(
            assigned_id(&findings, "abc", 12, "Boundary collision"),
            expected_abc_line_12
        );
        assert_eq!(
            assigned_id(&findings, "abc1", 2, "Boundary collision"),
            expected_abc1_line_2
        );

        let mut reversed = vec![abc1_line_2, abc_line_12];
        generate_finding_ids(&mut reversed, Some(head_sha));
        assert_eq!(
            assigned_id(&reversed, "abc", 12, "Boundary collision"),
            expected_abc_line_12
        );
        assert_eq!(
            assigned_id(&reversed, "abc1", 2, "Boundary collision"),
            expected_abc1_line_2
        );
    }

    #[test]
    fn stable_ids_do_not_share_duplicate_buckets_across_titles_on_same_line() {
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let sql_finding = finding_with_title("src/service.rs", 42, "SQL injection risk", "first");
        let auth_finding = finding_with_title("src/service.rs", 42, "Missing auth guard", "second");
        let expected_sql_id = expected_finding_id(&sql_finding, head_sha, 0);
        let expected_auth_id = expected_finding_id(&auth_finding, head_sha, 0);

        let mut findings = vec![sql_finding.clone(), auth_finding.clone()];
        generate_finding_ids(&mut findings, Some(head_sha));
        assert_eq!(
            assigned_id(&findings, "src/service.rs", 42, "SQL injection risk"),
            expected_sql_id
        );
        assert_eq!(
            assigned_id(&findings, "src/service.rs", 42, "Missing auth guard"),
            expected_auth_id
        );

        let mut reversed = vec![auth_finding, sql_finding];
        generate_finding_ids(&mut reversed, Some(head_sha));
        assert_eq!(
            assigned_id(&reversed, "src/service.rs", 42, "SQL injection risk"),
            expected_sql_id
        );
        assert_eq!(
            assigned_id(&reversed, "src/service.rs", 42, "Missing auth guard"),
            expected_auth_id
        );
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
        let metadata = finding(crate::envelope::CHANGE_METADATA_PATH, 1, "dependency risk");
        let metadata_slice = std::slice::from_ref(&metadata);
        assert!(visible_finding_sets_equal(metadata_slice, metadata_slice));
    }

    #[test]
    fn baseline_carries_reviewable_virtual_findings_but_not_operational_state() {
        assert!(baseline_has_carryable_findings(&[finding(
            crate::envelope::CHANGE_METADATA_PATH,
            1,
            "dependency risk",
        )]));
        assert!(baseline_has_carryable_findings(&[finding(
            crate::envelope::PR_DESCRIPTION_PATH,
            1,
            "content policy finding",
        )]));
        assert!(!baseline_has_carryable_findings(&[
            crate::envelope::provider_error_finding("fixture provider failure"),
        ]));
    }

    fn score(index: usize, confidence: f64, kind: Kind) -> FindingScore {
        FindingScore {
            index,
            confidence,
            kind,
            reason: "scored independently".to_string(),
        }
    }

    #[test]
    fn scorer_lower_confidence_becomes_final_and_both_values_are_stored() {
        let cfg = Config::default();
        let mut findings = vec![finding("a.rs", 10, "body")];

        let disagreements =
            apply_scorer_scores(&cfg, &mut findings, vec![score(0, 0.7, Kind::Risk)]);

        assert_eq!(disagreements, 0);
        assert_eq!(findings[0].confidence, 0.7);
        assert_eq!(findings[0].generator_confidence, Some(0.9));
        assert_eq!(findings[0].scorer_confidence, Some(0.7));
        assert_eq!(findings[0].kind, Kind::Risk);
        assert_eq!(findings[0].generator_kind, Some(Kind::Risk));
        assert_eq!(findings[0].scorer_kind, Some(Kind::Risk));
    }

    #[test]
    fn scorer_confidence_below_policy_is_suppressed_after_calibration() {
        let cfg = Config {
            min_confidence: 0.6,
            ..Config::default()
        };
        let mut findings = vec![finding("low.rs", 10, "low"), finding("kept.rs", 20, "kept")];

        apply_scorer_scores(
            &cfg,
            &mut findings,
            vec![score(0, 0.1, Kind::Risk), score(1, 0.8, Kind::Risk)],
        );
        let suppressed = suppress_below_min_confidence(&cfg, &mut findings);

        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].reason,
            crate::envelope::SuppressionReason::BelowConfidence
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "kept.rs");
        assert_eq!(findings[0].generator_confidence, Some(0.9));
        assert_eq!(findings[0].scorer_confidence, Some(0.8));
    }

    #[test]
    fn scorer_kind_can_escalate_into_a_blocking_kind() {
        let cfg = Config::default();
        let mut findings = vec![finding("a.rs", 10, "body")];

        let disagreements = apply_scorer_scores(
            &cfg,
            &mut findings,
            vec![score(0, 0.9, Kind::HumanEscalation)],
        );

        assert_eq!(disagreements, 1);
        assert_eq!(findings[0].kind, Kind::HumanEscalation);
        assert_eq!(findings[0].generator_kind, Some(Kind::Risk));
        assert_eq!(findings[0].scorer_kind, Some(Kind::HumanEscalation));
    }

    #[test]
    fn scorer_kind_deescalation_out_of_blocking_kind_is_ignored() {
        let cfg = Config::default();
        let mut finding = finding("a.rs", 10, "body");
        finding.kind = Kind::HumanEscalation;
        let mut findings = vec![finding];

        let disagreements =
            apply_scorer_scores(&cfg, &mut findings, vec![score(0, 0.9, Kind::Risk)]);

        assert_eq!(disagreements, 1);
        assert_eq!(findings[0].kind, Kind::HumanEscalation);
        assert_eq!(findings[0].generator_kind, Some(Kind::HumanEscalation));
        assert_eq!(findings[0].scorer_kind, Some(Kind::Risk));
    }

    #[test]
    fn large_confidence_disagreement_escalates_to_uncertainty_when_not_blocking() {
        let cfg = Config::default();
        let mut findings = vec![finding("a.rs", 10, "body")];

        let disagreements =
            apply_scorer_scores(&cfg, &mut findings, vec![score(0, 0.49, Kind::Risk)]);

        assert_eq!(disagreements, 1);
        assert_eq!(findings[0].confidence, 0.49);
        assert_eq!(findings[0].kind, Kind::Uncertainty);
    }

    #[test]
    fn batch_validation_exposes_exact_evidence_for_one_correction() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 +   changed();\n";
        let mut finding = finding("src/lib.rs", 7, "This change is unsafe.");
        finding.evidence = Some("changed approximately".to_string());

        let reason = review_batch_validation_reason(&finding, annotated, None).unwrap();
        assert_eq!(
            reason.repair_detail,
            "finding at src/lib.rs:7 must set `evidence` to the exact JSON string \"  changed();\""
        );
        assert_eq!(reason.category, "evidenceMismatch");

        finding.evidence = Some("  changed();".to_string());
        assert_eq!(
            review_batch_validation_reason(&finding, annotated, None),
            None
        );
    }

    #[test]
    fn batch_validation_reports_publication_failure_before_grounding() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 + changed();\n";
        let mut finding = finding("src/lib.rs", 7, "This sentence is cut off");
        finding.evidence = Some("changed();".to_string());

        assert_eq!(
            review_batch_validation_reason(&finding, annotated, None)
                .map(|reason| reason.repair_detail),
            Some(
                "finding at src/lib.rs:7 violates the publication contract: finding body must end with sentence punctuation".to_string()
            )
        );
    }

    #[test]
    fn batch_validation_reports_every_invalid_finding_for_one_correction() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 + first();\n    8 + second();\n";
        let mut first = finding("src/lib.rs", 7, "The first change is unsafe.");
        first.evidence = Some("approximate first".to_string());
        let mut second = finding("src/lib.rs", 8, "The second change is unsafe.");
        second.evidence = Some("approximate second".to_string());

        let reason = review_batch_validation_reasons(&[first, second], annotated, None).unwrap();

        assert!(reason.repair_detail().contains("src/lib.rs:7"));
        assert!(
            reason
                .repair_detail()
                .contains("exact JSON string \"first();\"")
        );
        assert!(reason.repair_detail().contains("src/lib.rs:8"));
        assert!(
            reason
                .repair_detail()
                .contains("exact JSON string \"second();\"")
        );
        assert_eq!(reason.safe_detail(), "evidenceMismatch=2");
        assert!(!reason.safe_detail().contains("src/lib.rs"));
        assert!(!reason.safe_detail().contains("first();"));
    }

    #[test]
    fn content_policy_evidence_may_come_from_policy_prompt_on_an_overlapping_line() {
        let annotated = "### .postil/content-policy.md\n@@ diff @@\n    7 + repository text\n";
        let policy = "### .postil/content-policy.md\n@@ policy @@\n    7 + policy text\n";
        let mut finding = finding(
            ".postil/content-policy.md",
            7,
            "The proposed text violates the configured policy.",
        );
        finding.kind = Kind::ContentPolicy;
        finding.evidence = Some("policy text".to_string());

        assert_eq!(
            review_batch_validation_reason(&finding, annotated, Some(policy)),
            None
        );
    }

    #[test]
    fn batch_validation_does_not_choose_between_distinct_duplicate_slices() {
        let annotated = "### src/lib.rs\n@@ first @@\n    7 + first slice\n@@ second @@\n    7 + second slice\n";
        let mut finding = finding("src/lib.rs", 7, "This change is unsafe.");
        finding.evidence = Some("approximate evidence".to_string());

        assert_eq!(
            review_batch_validation_reason(&finding, annotated, None)
                .map(|reason| reason.repair_detail),
            Some(
                "finding at src/lib.rs:7 has multiple displayed new-side evidence strings; copy the exact supporting string or retract it".to_string()
            )
        );
    }
}
