//! Review orchestration: one engine for local, CI, and hosted runs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;

use crate::config::{Config, FindingPresentation, GateLevel, OnError};
use crate::diff;
use crate::durable_plan::{DurablePlanRegistrar, DurableReviewPlan};
use crate::envelope::{
    Envelope, Finding, Gate, Kind, ModelIncident, ModelIncidentCategory, ModelIncidentPhase,
    ModelUsage, ReviewAdmission, ReviewCoverage, ReviewCoverageMode, ReviewCoverageReceipt,
    SuppressedFinding, SuppressionReason, Usage, fail_closed_finding,
};
use crate::filter;
use crate::forge::{
    CheckState, Forge, PrMeta, azure::Azure, bitbucket::Bitbucket, github::GitHub, gitlab::GitLab,
};
use crate::llm::{FindingScore, LlmClient, ReviewValidationFailure, add_usage};
use crate::local::{self, LocalSource};
use crate::output::{self, OutputFormat};
use crate::prompt::{self, PrContext};
use crate::repository_search::RepositorySource;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use time::{Date, OffsetDateTime};

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
// Synthesis requests join evidence from several source windows. Reasoning
// models need room for both analysis and the final structured review. The
// single exhausted-output retry may expand this to 8,000 tokens, and hosted
// admission prices that full exposure before any provider request begins.
const SYNTHESIS_REVIEW_MAX_TOKENS: u32 = 4_000;
pub(crate) const MAX_HOSTED_PLANNER_CANDIDATES: usize = 96;
pub(crate) const MAX_MODELS_PER_REQUEST: usize = 3;
pub(crate) const MAX_SCORER_PROMPT_BYTES: usize = 56_000;
const MAX_SCORER_EVIDENCE_BYTES: usize = 24_000;
const MAX_SCORER_EVIDENCE_CORPUS_BYTES: usize = 384 * 1024;
const MAX_SCORER_BATCH_EVIDENCE_BYTES: usize = 32 * 1024;
const MAX_STREAMED_CANDIDATE_MULTIPLIER: usize = 8;
const MAX_REVIEW_VALIDATION_REASON_BYTES: usize = 16_384;
const HOSTED_WORKER_WATCHDOG_SECS: u64 = 600;
pub(crate) const HOSTED_LLM_TOTAL_TIMEOUT_SECS: u64 = 540;
/// A provider attempt may use this timeout outside the bounded review-model
/// operation. Hosted review generation applies the shorter operation slot
/// below across the primary attempt, retries, and correction call together.
pub(crate) const HOSTED_LLM_REQUEST_TIMEOUT_SECS: u64 = 240;
/// Every hosted review-model operation, including retries and correction, is
/// bounded by this slot. Admission prices complete batch waves and sequential
/// cascades against the review-phase deadline.
pub(crate) const LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS: u64 = 60;
pub(crate) const HOSTED_LLM_REVIEW_TIMEOUT_SECS: u64 = 420;
pub(crate) const HOSTED_REVIEW_SCHEDULING_RESERVE_SECS: u64 = 30;
const FORGE_READ_TIMEOUT_SECS: u64 = 60;
const FORGE_DIFF_MAX_TIMEOUT_SECS: u64 = 300;
const CHECK_START_TIMEOUT_SECS: u64 = 30;
const CHECK_COMPLETION_TIMEOUT_SECS: u64 = 30;
const REVIEW_POST_TIMEOUT_SECS: u64 = 20;
pub(crate) const SCORER_TIMEOUT_SECS: u64 = 120;
pub(crate) const POSTPROCESSING_PHASE_TIMEOUT_SECS: u64 = 60;
pub(crate) const FINDING_ADJUDICATION_TIMEOUT_SECS: u64 = 60;

/// The hosted LLM deadline is shared by generation and every mandatory
/// post-generation phase. Keep this ledger as the single source for both the
/// generator deadline and deterministic large-review admission capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostedReviewPhaseBudgets {
    generator: u64,
    scorer: u64,
    resolution: u64,
    brevity: u64,
    adjudication: u64,
}

impl HostedReviewPhaseBudgets {
    #[cfg(test)]
    fn total(self) -> u64 {
        self.generator
            .saturating_add(self.scorer)
            .saturating_add(self.resolution)
            .saturating_add(self.brevity)
            .saturating_add(self.adjudication)
    }
}

fn hosted_review_phase_budgets(cfg: &Config) -> HostedReviewPhaseBudgets {
    let scorer = if cfg.scorer_enabled() {
        SCORER_TIMEOUT_SECS
    } else {
        0
    };
    let resolution = if cfg.uncertainty_resolution {
        POSTPROCESSING_PHASE_TIMEOUT_SECS
    } else {
        0
    };
    let brevity = if cfg.concise_findings {
        POSTPROCESSING_PHASE_TIMEOUT_SECS
    } else {
        0
    };
    let adjudication = FINDING_ADJUDICATION_TIMEOUT_SECS;
    let generator = HOSTED_LLM_REVIEW_TIMEOUT_SECS.min(
        HOSTED_LLM_TOTAL_TIMEOUT_SECS
            .saturating_sub(scorer)
            .saturating_sub(resolution)
            .saturating_sub(brevity)
            .saturating_sub(adjudication),
    );

    HostedReviewPhaseBudgets {
        generator,
        scorer,
        resolution,
        brevity,
        adjudication,
    }
}

pub(crate) fn hosted_review_timeout_secs(cfg: &Config) -> u64 {
    hosted_review_phase_budgets(cfg).generator
}

fn review_output_token_limit(synthesis: bool, deterministic_large_review: bool) -> u32 {
    if synthesis {
        SYNTHESIS_REVIEW_MAX_TOKENS
    } else if deterministic_large_review {
        LARGE_SOURCE_REVIEW_MAX_TOKENS
    } else {
        crate::llm::REVIEW_MAX_TOKENS
    }
}

pub(crate) fn large_diff_batch_concurrency(cfg: &Config) -> usize {
    let consensus_width = if cfg.consensus > 1 {
        cfg.consensus
            .min(cfg.model_chain().len())
            .min(MAX_MODELS_PER_REQUEST)
    } else {
        1
    };
    (MAX_LARGE_DIFF_CONCURRENCY / consensus_width).max(1)
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
    if let Some(category) = crate::envelope::publication_evidence_boundary_category(finding) {
        let repair = match category {
            "delegatedEvidenceCollection" => {
                "if the cited changed line already establishes the defect, state it directly and omit `repositoryContext`; otherwise do not delegate repository inspection to a human, declare the exact absence or mismatch through `repositoryContext` so Postil can search the complete reviewed head, or retract the finding"
            }
            "reviewArtifactPhrase" | "reviewArtifactBoundary" => {
                "remove review-process terms such as `diff`, `patch`, `PR`, `MR`, `review input`, and `provided context`, state the defect directly from the concrete repository construct with an actionable fix, and retract the finding if the supplied evidence is insufficient"
            }
            _ => {
                "state the defect directly from the concrete repository construct with an actionable fix, or retract the finding"
            }
        };
        return Some(ReviewBatchValidationReason {
            category,
            repair_detail: format!(
                "finding at {}:{} uses review-process language; {repair}",
                finding.path, finding.line,
            ),
        });
    }
    if let Err(reason) = crate::envelope::validate_finding_publication(finding) {
        return Some(ReviewBatchValidationReason {
            category: "publicationContract",
            repair_detail: format!(
                "finding at {}:{} violates the publication contract: {reason}",
                finding.path, finding.line
            ),
        });
    }
    if crate::repository_search::prose_requires_repository_search(finding)
        && finding.repository_claim.is_none()
    {
        return Some(ReviewBatchValidationReason {
            category: "repositoryClaim",
            repair_detail: format!(
                "finding at {}:{} makes a repository-wide absence or mismatch claim without a bounded repositoryContext declaration",
                finding.path, finding.line
            ),
        });
    }
    if let Some(claim) = finding.repository_claim.as_ref()
        && !crate::repository_search::claim_is_valid(claim)
    {
        return Some(ReviewBatchValidationReason {
            category: "repositoryClaim",
            repair_detail: format!(
                "finding at {}:{} has an invalid or empty repositoryContext search declaration",
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
        "reviewArtifactPhrase",
        "delegatedEvidenceCollection",
        "reviewArtifactBoundary",
        "repositoryClaim",
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
    pub publication_plan_output: Option<PathBuf>,
    pub publication_generation: Option<String>,
    pub publication_input_identity: Option<String>,
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
    repository_revision: Option<String>,
    repo: Option<&'a str>,
    baseline: Vec<Finding>,
    scope: filter::ReconcileScope,
    force_model: bool,
    llm_budget_started_at: Option<Instant>,
    repository_source: RepositorySource<'a>,
}

struct RemoteReviewInput<'a> {
    meta: &'a PrMeta,
    review_started: Instant,
    repository_source: RepositorySource<'a>,
}

struct RemoteReviewResult {
    envelope: Envelope,
    /// Complete pull-request diff retained for forge placement fallback. An
    /// incremental review cannot establish the complete PR file surface.
    publication_diff: Option<diff::Diff>,
}

#[derive(Clone, Copy)]
struct PublicationContext<'a> {
    snapshot: &'a PrMeta,
    diff: Option<&'a diff::Diff>,
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
    if args.publication_plan_output.is_some() {
        anyhow::ensure!(
            args.forge == ForgeKind::GitHub
                && args.repo.is_some()
                && args.pr.is_some()
                && args.sha.is_some()
                && args.base_sha.is_some()
                && !args.staged
                && args.base.is_none()
                && args.diff_file.is_none(),
            "--publication-plan-output requires a remote GitHub pull request with explicit --repo, --pr, --sha, and --base-sha"
        );
        anyhow::ensure!(
            args.no_post
                && args.check_run_id.is_none()
                && args.gate_check_run_id.is_none()
                && !args.defer_gate_check,
            "--publication-plan-output cannot be combined with forge mutation options"
        );
        let generation = args
            .publication_generation
            .as_deref()
            .context("--publication-plan-output requires --publication-generation")?;
        crate::forge::ensure_publication_decimal_identifier("controller generation", generation)
            .context("invalid --publication-generation")?;
        let input_identity = args
            .publication_input_identity
            .as_deref()
            .context("--publication-plan-output requires --publication-input-identity")?;
        crate::forge::ensure_publication_sha256_identity("input identity", input_identity)
            .context("invalid --publication-input-identity")?;
    } else {
        anyhow::ensure!(
            args.publication_generation.is_none(),
            "--publication-generation requires --publication-plan-output"
        );
        anyhow::ensure!(
            args.publication_input_identity.is_none(),
            "--publication-input-identity requires --publication-plan-output"
        );
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
    if !args.no_post
        && cfg.finding_presentation == FindingPresentation::CheckAnnotations
        && args.forge != ForgeKind::GitHub
    {
        return Err(anyhow!(
            "review.findingPresentation checkAnnotations requires GitHub publication"
        ));
    }

    match args.forge {
        ForgeKind::Local => run_local(&args, &cfg, &cwd).await,
        ForgeKind::GitHub => {
            let repo = require_repo(&args)?;
            let forge = GitHub::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo, RepositorySource::GitHub(&forge)).await
        }
        ForgeKind::GitLab => {
            let repo = require_repo(&args)?;
            let forge = GitLab::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo, RepositorySource::Unavailable).await
        }
        ForgeKind::Bitbucket => {
            let repo = require_repo(&args)?;
            let forge = Bitbucket::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo, RepositorySource::Unavailable).await
        }
        ForgeKind::Azure => {
            let repo = require_repo(&args)?;
            let forge = Azure::new(&repo, require_pr(&args)?)?;
            run_remote(&args, &cfg, &forge, &repo, RepositorySource::Unavailable).await
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

async fn run_local(args: &ReviewArgs, cfg: &Config, repo_root: &Path) -> Result<i32> {
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
    let head_sha = local::head_sha().await;
    let local_snapshot = local::acquire(&source, head_sha.as_deref(), repo_root).await?;
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
    let review_started = std::time::Instant::now();
    let result = review_diff(
        cfg,
        args,
        ReviewInput {
            diff_snapshot: &local_snapshot.diff,
            meta: None,
            head_sha: head_sha.clone(),
            repository_revision: local_snapshot.repository_revision.clone(),
            repo: None,
            baseline,
            scope,
            force_model: false,
            llm_budget_started_at: None,
            repository_source: if local_snapshot.repository_revision.is_some() {
                RepositorySource::Local(repo_root)
            } else {
                RepositorySource::Unavailable
            },
        },
    )
    .await;
    let envelope = match result {
        Ok(envelope) => envelope,
        // Only a completed review that failed operationally has enough
        // review state to produce a truthful error envelope. Input,
        // planning, registration, and client-construction failures occur
        // before provider access and retain the CLI error contract (exit 2).
        Err(error) if error.downcast_ref::<ReviewFailure>().is_some() => {
            eprintln!("postil: review failed before completion ({error:#})");
            error_envelope(
                cfg,
                &error,
                head_sha.as_deref().unwrap_or("local-review"),
                None,
                review_started.elapsed().as_millis() as u64,
            )
        }
        Err(error) => return Err(error),
    };
    finish(args, cfg, envelope, None::<&GitHub>, None, None, false).await
}

async fn run_remote<F: Forge>(
    args: &ReviewArgs,
    cfg: &Config,
    forge: &F,
    repo: &str,
    repository_source: RepositorySource<'_>,
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
                if cfg.finding_presentation == FindingPresentation::CheckAnnotations {
                    return Err(e).context(
                        "creating check runs required by review.findingPresentation checkAnnotations",
                    );
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
            repository_source,
        },
    )
    .await;
    match result {
        Ok(review) => {
            let RemoteReviewResult {
                envelope,
                publication_diff,
            } = review;
            let (review_state, gate_state) = remote_check_states(&envelope);
            let check_completion = if let Some((a, g)) = &checks {
                complete_remote_checks(
                    forge,
                    a,
                    g,
                    review_state,
                    (!args.defer_gate_check).then_some(gate_state),
                    &envelope,
                    &meta,
                    cfg.finding_presentation == FindingPresentation::CheckAnnotations,
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
                Some(PublicationContext {
                    snapshot: &meta,
                    diff: publication_diff.as_ref(),
                }),
                strict_publication,
            )
            .await;
            combine_required_publication(check_failure, finish_result)
        }
        Err(e) => {
            eprintln!("postil: review failed before completion ({e:#})");
            // Fail closed by default: an errored run must never read as a silent
            // pass. `gate.onError: advisory` opts a repo out of blocking on
            // operational errors (provider outage). The review check still
            // fails truthfully; only the merge gate stands aside.
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
                Some(&meta),
                review_started.elapsed().as_millis() as u64,
            );
            let (review_state, gate_state) = remote_check_states(&envelope);
            let check_completion = if let Some((a, g)) = &checks {
                complete_remote_checks(
                    forge,
                    a,
                    g,
                    review_state,
                    (!args.defer_gate_check).then_some(gate_state),
                    &envelope,
                    &meta,
                    cfg.finding_presentation == FindingPresentation::CheckAnnotations,
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
                Some(PublicationContext {
                    snapshot: &meta,
                    diff: None,
                }),
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

fn remote_check_states(envelope: &Envelope) -> (CheckState, CheckState) {
    let operational = envelope.findings.iter().any(|finding| {
        finding.path == crate::envelope::OPERATIONAL_PATH
            || finding.path == crate::envelope::PROVIDER_PATH
    });
    let advisory = if operational {
        CheckState::Failure
    } else {
        CheckState::Success
    };
    let gate = if envelope.gate.failing {
        CheckState::Failure
    } else {
        CheckState::Success
    };
    (advisory, gate)
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
    annotate_findings: bool,
    review_started: Instant,
) -> Result<()> {
    require_current_snapshot(forge, snapshot, review_started, "check completion").await?;
    run_with_hosted_budget(
        Some(review_started),
        CHECK_COMPLETION_TIMEOUT_SECS,
        forge.complete_checks(
            crate::forge::CheckRunIds {
                advisory: advisory_id,
                gate: gate_id,
            },
            advisory,
            gate,
            envelope,
            snapshot,
            annotate_findings,
        ),
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
) -> Result<RemoteReviewResult> {
    let RemoteReviewInput {
        meta,
        review_started,
        repository_source,
    } = input;
    let head_sha = meta.head_sha.as_str();
    let baseline = load_baseline(args)?;
    let has_carryable_baseline = baseline_has_carryable_findings(&baseline);
    let incremental = args.since_sha.as_deref();
    let (diff_snapshot, scope, force_model) = match incremental {
        Some(since) if since != head_sha => {
            let incremental_diff = run_with_hosted_budget(
                Some(review_started),
                FORGE_READ_TIMEOUT_SECS,
                forge.fetch_diff_since(since, head_sha),
                "fetching incremental diff",
            )
            .await
            .map_err(crate::forge::classify_review_input_error)
            .context("incremental diff fetch");
            match incremental_diff {
                Ok(diff) => (
                    diff,
                    filter::ReconcileScope::Incremental {
                        trust: filter::ReviewTrust::Failed,
                    },
                    false,
                ),
                // The baseline itself is unusable: the head no longer descends
                // from it (a rebase or force-push), or the forge truncated the
                // compare. Retrying cannot recover a baseline that is gone, and
                // the incremental path must keep refusing a diff that would
                // understate coverage, so review the complete change at the
                // same head instead of failing the run.
                Err(error) if crate::forge::is_incremental_diff_unavailable(&error) => {
                    eprintln!(
                        "postil: incremental baseline {since} is unusable ({error:#}); reviewing the complete change instead"
                    );
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
                }
                Err(error) => return Err(error),
            }
        }
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
    let publication_diff = matches!(scope, filter::ReconcileScope::Full { .. })
        .then(|| diff::parse(diff_snapshot.as_str()));
    let envelope = review_diff(
        cfg,
        args,
        ReviewInput {
            diff_snapshot: &diff_snapshot,
            meta: Some(meta),
            head_sha: Some(head_sha.to_string()),
            repository_revision: Some(head_sha.to_string()),
            repo: Some(repo),
            baseline,
            scope,
            force_model,
            llm_budget_started_at: Some(review_started),
            repository_source,
        },
    )
    .await?;
    Ok(RemoteReviewResult {
        envelope,
        publication_diff,
    })
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
    finding_batches: &[String],
    evidence_corpus: &[String],
    findings: &[Finding],
    total_evidence_budget: usize,
) -> Vec<prompt::ScorerPromptFinding> {
    let per_finding_budget = total_evidence_budget / findings.len().max(1);
    let local_budget = per_finding_budget.min(8_000) / 3;
    let related_budget = per_finding_budget.saturating_sub(local_budget);
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let mut query = format!("{}\n{}\n{}", finding.path, finding.title, finding.body);
            if let Some(evidence) = finding.evidence.as_deref() {
                query.push('\n');
                query.push_str(evidence);
            }
            let diff_hunk = finding_batches
                .iter()
                .find_map(|batch| {
                    diff::render_review_batch_context(
                        batch,
                        &finding.path,
                        finding.line,
                        8,
                        local_budget,
                    )
                })
                .unwrap_or_else(|| {
                    "No diff evidence is available for this cited location.".to_string()
                });
            let related_evidence = diff::render_related_scorer_evidence(
                evidence_corpus,
                &finding.path,
                &query,
                related_budget,
            );
            prompt::ScorerPromptFinding {
                index,
                path: prompt::sanitize_scorer_input(&finding.path),
                line: finding.line,
                severity: finding.severity.as_str().to_string(),
                title: prompt::sanitize_scorer_input(&finding.title),
                body: prompt::sanitize_scorer_input(&finding.body),
                cited_evidence: finding
                    .evidence
                    .as_deref()
                    .map(prompt::sanitize_scorer_input),
                diff_hunk: prompt::sanitize_scorer_input(&diff_hunk),
                related_evidence: related_evidence
                    .as_deref()
                    .map(prompt::sanitize_scorer_input),
            }
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

fn summary_from_findings(findings: &[Finding]) -> String {
    const DISPLAYED_TITLES: usize = 3;

    let mut sentences = findings
        .iter()
        .take(DISPLAYED_TITLES)
        .map(|finding| {
            let mut title = crate::envelope::forge_safe_finding_publication_text(finding)
                .title
                .trim()
                .to_string();
            if !title.ends_with(['.', '!', '?', '\u{3002}', '\u{ff01}', '\u{ff1f}']) {
                title.push('.');
            }
            title
        })
        .collect::<Vec<_>>();
    let remaining = findings.len().saturating_sub(sentences.len());
    if remaining > 0 {
        sentences.push(format!("{remaining} more."));
    }
    sentences.join(" ")
}

struct ReviewBatchPromptContext<'a> {
    max_findings: usize,
    repo: Option<&'a str>,
    meta: Option<&'a PrMeta>,
    incremental: bool,
    content_policy_active: bool,
    bounded_selection: bool,
    multiple: bool,
}

const BOUNDED_SOURCE_BATCH_CONTEXT: &str = "This source batch is one bounded view of a larger diff. Review only supplied evidence; do not claim examination of omitted lines. Other boundary, risk, and synthesis batches are reviewed separately.\n\n";
const BOUNDED_SYNTHESIS_BATCH_CONTEXT: &str = "This is bounded synthesis from a larger diff. Review only supplied evidence; do not claim omitted-line coverage. Other batches are separate.\n\n";
const SYNTHESIS_BATCH_CONTEXT: &str = "\n\nTrace merge-relevant caller/API, config/consumer, validation/sink, and lifecycle relationships. Cite retained numbered paths and lines.";
const MULTIPLE_BATCH_CONTEXT: &str =
    "\n\nReview this source batch independently; other selected batches are separate.";

fn review_batch_prompt(
    context: &ReviewBatchPromptContext<'_>,
    mut annotated: String,
    first: bool,
) -> (String, String, bool) {
    let exact_semantic = annotated.starts_with("Exact low-risk semantic evidence:");
    let synthesis = exact_semantic
        || annotated.starts_with("Cross-window semantic digests")
        || annotated.starts_with("Cross-batch semantic digests");
    if context.bounded_selection {
        if synthesis {
            annotated.insert_str(0, BOUNDED_SYNTHESIS_BATCH_CONTEXT);
        } else {
            annotated.insert_str(0, BOUNDED_SOURCE_BATCH_CONTEXT);
        }
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
    let mut user = prompt::user_prompt(&prompt_context, &annotated, context.max_findings);
    if exact_semantic {
        user.push_str(
            "\n\nThis bounded semantic proof batch contains exact low-risk hunk evidence. Each credited hunk retains its repository path, stable identity, and a non-empty added line. Cite only the exact numbered path and line displayed in this request.",
        );
    } else if synthesis {
        user.push_str(SYNTHESIS_BATCH_CONTEXT);
    } else if context.multiple {
        user.push_str(MULTIPLE_BATCH_CONTEXT);
    }
    (annotated, user, synthesis)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReviewBatchBudgets {
    source: usize,
    synthesis: usize,
}

impl ReviewBatchBudgets {
    fn minimum(self) -> usize {
        self.source.min(self.synthesis)
    }

    fn stabilized_for_rendering(self) -> Self {
        let ceiling = diff::MIN_REVIEW_BATCH_BYTES.saturating_mul(2);
        let stabilize = |budget| {
            if budget < ceiling {
                diff::MIN_REVIEW_BATCH_BYTES
            } else {
                budget
            }
        };
        Self {
            source: stabilize(self.source),
            synthesis: stabilize(self.synthesis),
        }
    }
}

fn serialized_review_batch_budget_for_shape(
    cfg: &Config,
    max_findings: usize,
    models: &[String],
    system: &str,
    context: &PrContext<'_>,
    batch_context: &str,
    suffix: &str,
) -> Result<usize> {
    let review_output_tokens = crate::llm::REVIEW_MAX_OUTPUT_TOKENS as usize;
    let mut admission_user = prompt::user_prompt(context, batch_context, max_findings);
    admission_user.push_str(suffix);
    models
        .iter()
        .map(|model| {
            crate::llm::serialized_review_request_bytes(
                cfg,
                model,
                system,
                &admission_user,
                crate::llm::REVIEW_MAX_OUTPUT_TOKENS,
            )
            .map(|input_bytes| {
                // Serialized UTF-8 bytes are the established tokenizer-independent
                // upper bound on input tokens. Convert the measured request into
                // that conservative token bound before combining it with the
                // model context and output-token limits.
                let input_token_upper_bound = input_bytes;
                crate::llm::conservative_context_tokens(model)
                    .saturating_sub(review_output_tokens)
                    .saturating_sub(input_token_upper_bound)
                    .min(MAX_REVIEW_BATCH_BYTES)
            })
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .min()
        .context("review admission has no active model")
}

fn serialized_review_batch_budgets(
    cfg: &Config,
    max_findings: usize,
    models: &[String],
    system: &str,
    context: &PrContext<'_>,
) -> Result<ReviewBatchBudgets> {
    Ok(ReviewBatchBudgets {
        source: serialized_review_batch_budget_for_shape(
            cfg,
            max_findings,
            models,
            system,
            context,
            BOUNDED_SOURCE_BATCH_CONTEXT,
            MULTIPLE_BATCH_CONTEXT,
        )?,
        synthesis: serialized_review_batch_budget_for_shape(
            cfg,
            max_findings,
            models,
            system,
            context,
            BOUNDED_SYNTHESIS_BATCH_CONTEXT,
            SYNTHESIS_BATCH_CONTEXT,
        )?,
    })
}

fn review_batch_budgets_are_usable(batch_budgets: ReviewBatchBudgets) -> bool {
    batch_budgets.minimum() >= diff::MIN_REVIEW_BATCH_BYTES
}

async fn review_diff(cfg: &Config, args: &ReviewArgs, input: ReviewInput<'_>) -> Result<Envelope> {
    review_diff_at(cfg, args, input, OffsetDateTime::now_utc().date()).await
}

async fn review_diff_at(
    cfg: &Config,
    args: &ReviewArgs,
    input: ReviewInput<'_>,
    current_utc_date: Date,
) -> Result<Envelope> {
    let ReviewInput {
        diff_snapshot,
        meta,
        head_sha,
        repository_revision,
        repo,
        mut baseline,
        scope,
        force_model,
        llm_budget_started_at,
        repository_source,
    } = input;
    let review_started = std::time::Instant::now();
    let mut prepared = diff::prepare_review_with_ignore(diff_snapshot, &cfg.ignore)?;
    let input_incomplete = prepared.reserved_anchor;
    let mut index = std::mem::take(&mut prepared.index);
    let incremental = matches!(scope, filter::ReconcileScope::Incremental { .. });
    let baseline_adjudication_reserve = baseline_adjudication_reserve(&baseline, &index, scope);

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
    let mut repository_search = None;
    let mut adjudication_resolved = Vec::new();
    let mut adjudication_preserved_baseline = Vec::new();
    let mut adjudication_failure = None;
    let mut adjudication_incomplete = false;

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
        anyhow::ensure!(
            baseline_adjudication_reserve < crate::adjudication::MAX_ADJUDICATION_CANDIDATES,
            "complete finding adjudication reserves {} baseline candidates, exhausting its {}-candidate bound; no provider request was made",
            baseline_adjudication_reserve,
            crate::adjudication::MAX_ADJUDICATION_CANDIDATES,
        );
        let generator_max_findings = cfg.max_findings.min(
            crate::adjudication::MAX_ADJUDICATION_CANDIDATES
                .saturating_sub(baseline_adjudication_reserve),
        );
        let system = prompt::system_prompt(cfg, current_utc_date);
        let chain = cfg.model_chain();
        let active_model_count = if cfg.consensus > 1 {
            cfg.consensus.min(chain.len())
        } else {
            chain.len()
        };
        let preliminary_invalid_input = if input_incomplete {
            Some((
                crate::envelope::IncompleteReviewReason::ReservedInput,
                "review input is incomplete or contains reserved evidence; no provider request was made"
                    .to_string(),
            ))
        } else if active_model_count == 0 || active_model_count > MAX_MODELS_PER_REQUEST {
            Some((
                crate::envelope::IncompleteReviewReason::InvalidModelFanOut,
                format!(
                    "configured model fan-out is invalid (models {active_model_count}/{MAX_MODELS_PER_REQUEST}); no provider request was made"
                ),
            ))
        } else {
            None
        };
        let batch_budgets = if preliminary_invalid_input.is_some() {
            ReviewBatchBudgets {
                source: 0,
                synthesis: 0,
            }
        } else {
            // Admission serializes the complete request builder used for provider
            // contact. Remaining UTF-8 batch bytes conservatively upper-bound
            // input tokens without relying on a provider-specific tokenizer.
            let admission_context = PrContext {
                repo,
                title: meta.map(|value| value.title.as_str()),
                body: meta.map(|value| value.body.as_str()),
                incremental,
                content_policy: content_policy_active,
            };
            serialized_review_batch_budgets(
                cfg,
                generator_max_findings,
                &chain[..active_model_count],
                &system,
                &admission_context,
            )?
        };
        let invalid_input = if let Some(invalid_input) = preliminary_invalid_input {
            Some(invalid_input)
        } else if !review_batch_budgets_are_usable(batch_budgets) {
            Some((
                crate::envelope::IncompleteReviewReason::InsufficientContextBudget,
                format!(
                    "review context budget is insufficient after serialized shared context (batch budget {} bytes; requires at least {}); no provider request was made",
                    batch_budgets.minimum(),
                    diff::MIN_REVIEW_BATCH_BYTES,
                ),
            ))
        } else {
            None
        };

        if let Some((reason, diagnostic)) = invalid_input {
            eprintln!("postil: {diagnostic}");
            model_used = "none (invalid review input)".to_string();
            findings = vec![crate::envelope::incomplete_review_finding(reason)];
        } else {
            // Small environment-dependent request decorations must not shift
            // near-floor batch boundaries and therefore planner candidates.
            // Admission still uses each exact raw serialized-request budget.
            let batch_budgets = batch_budgets.stabilized_for_rendering();
            let large_diff_selected_limit = if crate::config::hosted_runtime_mode() {
                MAX_LARGE_DIFF_SELECTED_BATCHES
                    .min(crate::llm::max_hosted_review_batches(cfg, false)?)
            } else {
                MAX_LARGE_DIFF_SELECTED_BATCHES
            };
            let mut batches = diff::spool_model_batches_with_synthesis_budget(
                &mut prepared,
                batch_budgets.source,
                batch_budgets.synthesis,
                MAX_REVIEW_MANIFEST_BYTES.min(batch_budgets.source / 3),
                force_model || pr_desc_lines > 0,
                large_diff_selected_limit,
            )?;
            index.add_change_metadata(batches.metadata_count);
            if batches.count == 0 {
                model_used = "none (empty diff)".to_string();
                review_trust = filter::ReviewTrust::Exhaustive;
            } else {
                let large_diff_receipt = (batches.count > large_diff_selected_limit)
                    .then(|| batches.deterministic_bounded_receipt(large_diff_selected_limit))
                    .transpose()?;
                if let Some(receipt) = &large_diff_receipt {
                    anyhow::ensure!(
                        receipt.unreviewed_hunks() == 0,
                        "deterministic large-review plan leaves {} normalized hunks unreviewed within its {large_diff_selected_limit}-request limit; no provider request was made",
                        receipt.unreviewed_hunks()
                    );
                    eprintln!(
                        "postil: deterministic large-review plan={} direct_hunks={} semantic_hunks={} unreviewed_hunks={} selected_batches={}/{} concurrency={} request_timeout={}s review_budget={}s",
                        receipt.plan_sha256,
                        receipt.direct_hunks(),
                        receipt.semantic_hunks(),
                        receipt.unreviewed_hunks(),
                        receipt.selected_batch_ids.len(),
                        batches.count,
                        large_diff_batch_concurrency(cfg),
                        LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS,
                        hosted_review_timeout_secs(cfg),
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
                let mut durable_plan_registration =
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
                                u32::try_from(large_diff_batch_concurrency(cfg))
                                    .context("review concurrency exceeds durable plan range")?,
                                u32::try_from(LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS)
                                    .context("request timeout exceeds durable plan range")?,
                                u32::try_from(hosted_review_timeout_secs(cfg))
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
                                u32::try_from(hosted_review_timeout_secs(cfg))
                                    .context("review budget exceeds durable plan range")?,
                            )?
                        };
                        Some((registrar, durable_plan))
                    } else {
                        None
                    };
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
                        Duration::from_secs(hosted_review_timeout_secs(cfg)),
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
                    max_findings: generator_max_findings,
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
                    // Batch requests carry their own prompts and are collected by
                    // index, so nothing orders them. `max_hosted_review_batches`
                    // already prices capacity at this concurrency; running them
                    // one at a time instead divides the phase by the batch count
                    // and puts each batch under a slot the review model's tail
                    // latency does not fit.
                    let admitted_concurrency = large_diff_batch_concurrency(cfg);
                    let scorer_system = prompt::scorer_system_prompt(cfg, current_utc_date);
                    let admission = client.preflight_review_plan_with_output_limits(
                        cfg,
                        planned_batch_count,
                        &system,
                        crate::llm::ReviewPreflightPrompts {
                            first_users: &candidate_first_users,
                            later_users: &candidate_later_users,
                            output_tokens: &candidate_output_tokens,
                            scorer_system: &scorer_system,
                            current_utc_date,
                        },
                        crate::llm::ReviewPlanSchedule {
                            planner,
                            batch_concurrency: admitted_concurrency,
                        },
                    )?;
                    review_admission = Some(admission);
                    if let Some((registrar, durable_plan)) = durable_plan_registration.take() {
                        registrar.register(&durable_plan).await?;
                    }
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
                            incremental.then(|| args.since_sha.clone()).flatten(),
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
                if let Some((registrar, durable_plan)) = durable_plan_registration.take() {
                    registrar.register(&durable_plan).await?;
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
                        selected.len() <= large_diff_selected_limit,
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
                                current_utc_date,
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
                let mut finding_contexts = Vec::new();
                let mut scorer_evidence_corpus = Vec::new();
                let mut batch_models = Vec::new();
                let mut batch_failed = false;
                let mut batch_failure = None;
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
                // Must match the concurrency admission priced the schedule at,
                // or the phase is divided into a different number of waves than
                // the plan was checked against.
                let concurrency = large_diff_batch_concurrency(cfg);
                let scorer_batch_evidence_budget = (MAX_SCORER_EVIDENCE_CORPUS_BYTES
                    / total_requests.max(1))
                .min(MAX_SCORER_BATCH_EVIDENCE_BYTES);
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
                                    if cross_window_synthesis {
                                        crate::llm::ReviewRequestRoute::Synthesis
                                    } else {
                                        crate::llm::ReviewRequestRoute::Source
                                    },
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
                for (_index, annotated, user, cross_window_synthesis, first, result) in outcomes {
                    if !cross_window_synthesis {
                        let bounded = diff::bounded_scorer_batch_evidence(
                            &annotated,
                            scorer_batch_evidence_budget,
                        );
                        if !bounded.is_empty() {
                            scorer_evidence_corpus.push(bounded);
                        }
                    }
                    match result {
                        Ok(mut model_review) => {
                            add_usage(&mut usage, model_review.usage);
                            model_usage.extend(model_review.model_usage);
                            model_incidents.extend(model_review.model_incidents);
                            usage_accounting_complete &= model_review.usage_accounting_complete;
                            if !batch_models.contains(&model_review.model_used) {
                                batch_models.push(model_review.model_used);
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
                    let mut generator_filter_cfg = cfg.clone();
                    generator_filter_cfg.max_findings = generator_max_findings;
                    let outcome = filter::apply(&generator_filter_cfg, &index, raw_findings)?;
                    suppressed = outcome.suppressed;
                    suppressed_findings = outcome.suppressed_findings;
                    ungrounded = outcome.ungrounded + batch_ungrounded;
                    if outcome.all_ungrounded
                        || (grounded_candidate_count == 0 && batch_ungrounded > 0)
                    {
                        findings = vec![ungrounded_findings_failure(ungrounded)];
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
                        let mut kept = outcome.kept;
                        let mut preserved_baseline_publications = Vec::new();

                        let resolution = crate::resolve::resolve_uncertainties(
                            cfg,
                            &client,
                            &repository_source,
                            crate::resolve::ResolutionRevisions {
                                head: repository_revision.as_deref(),
                                timeout: Duration::from_secs(POSTPROCESSING_PHASE_TIMEOUT_SECS),
                                current_utc_date,
                            },
                            &finding_contexts,
                            diff_snapshot.as_str(),
                            &mut kept,
                        )
                        .await;
                        suppressed += resolution.suppressed_findings.len() as u32;
                        suppressed_findings.extend(resolution.suppressed_findings);
                        add_usage(&mut usage, resolution.usage);
                        model_usage.extend(resolution.model_usage);
                        model_incidents.extend(resolution.model_incidents);
                        usage_accounting_complete &= resolution.usage_accounting_complete;
                        let brevity = crate::brevity::compress_findings(
                            cfg,
                            &client,
                            current_utc_date,
                            &mut kept,
                            Duration::from_secs(POSTPROCESSING_PHASE_TIMEOUT_SECS),
                        )
                        .await;
                        add_usage(&mut usage, brevity.usage);
                        model_usage.extend(brevity.model_usage);
                        model_incidents.extend(brevity.model_incidents);
                        usage_accounting_complete &= brevity.usage_accounting_complete;

                        let full_rereview = matches!(scope, filter::ReconcileScope::Full { .. });
                        let mut all_adjudication_candidates = kept.clone();
                        let fresh_candidate_count = all_adjudication_candidates.len();
                        let mut baseline_candidate_indices = Vec::new();
                        if full_rereview {
                            for (baseline_index, previous) in baseline.iter().enumerate() {
                                // The complete direct diff may prove an exact citation was
                                // deleted even when bounded source selection omitted its batch.
                                // A removal followed by the same addition remains current and
                                // must not be retired from semantic coverage alone.
                                let applicable = baseline_may_enter_adjudication(previous, &index)
                                    && !kept
                                        .iter()
                                        .any(|fresh| same_visible_finding(fresh, previous));
                                if applicable {
                                    baseline_candidate_indices.push(baseline_index);
                                    all_adjudication_candidates.push(previous.clone());
                                }
                            }
                        }

                        if !all_adjudication_candidates.is_empty() {
                            anyhow::ensure!(
                                all_adjudication_candidates.len()
                                    <= crate::adjudication::MAX_ADJUDICATION_CANDIDATES,
                                "complete finding adjudication needs {} candidates, exceeding its {}-candidate bound; no adjudication request was made",
                                all_adjudication_candidates.len(),
                                crate::adjudication::MAX_ADJUDICATION_CANDIDATES,
                            );
                            let snapshot_id = crate::adjudication::reviewed_snapshot_identity(
                                repository_revision.as_deref(),
                                diff_snapshot.as_str(),
                            );
                            let adjudication_model = cfg
                                .scorer_chain()
                                .into_iter()
                                .next()
                                .or_else(|| cfg.model_chain().into_iter().next())
                                .ok_or_else(|| {
                                    anyhow!(
                                        "complete finding adjudication requires one provider identity"
                                    )
                                })?;
                            let candidate_ids = crate::adjudication::stable_candidate_ids(
                                &snapshot_id,
                                &all_adjudication_candidates,
                            );
                            let mut diff_receipt = crate::adjudication::build_diff_corpus_receipt(
                                &snapshot_id,
                                diff_snapshot.as_str(),
                                &all_adjudication_candidates,
                                &candidate_ids,
                                fresh_candidate_count,
                            );
                            let receipt = crate::repository_search::search(
                                &repository_source,
                                repository_revision.as_deref(),
                                all_adjudication_candidates.iter(),
                            )
                            .await;
                            repository_search = Some(receipt);
                            let receipt = repository_search
                                .as_ref()
                                .expect("repository search receipt was just assigned");
                            let adjudication_system =
                                crate::adjudication::system_prompt(current_utc_date);
                            let adjudication_user = crate::adjudication::user_prompt(
                                &snapshot_id,
                                &all_adjudication_candidates,
                                &candidate_ids,
                                &mut diff_receipt,
                                receipt,
                            );
                            let adjudicated = match adjudication_user {
                                Ok(adjudication_user) => Some(
                                    client
                                        .adjudicate_findings(
                                            &adjudication_model,
                                            &adjudication_system,
                                            &adjudication_user,
                                            all_adjudication_candidates.len(),
                                            Duration::from_secs(FINDING_ADJUDICATION_TIMEOUT_SECS),
                                        )
                                        .await,
                                ),
                                Err(error) => {
                                    adjudication_incomplete = true;
                                    review_trust = filter::ReviewTrust::Failed;
                                    adjudication_failure = Some(fail_closed_finding(
                                        "finding adjudication input exceeded its admitted bound",
                                    ));
                                    eprintln!(
                                        "postil: finding adjudication input exceeded its admitted bound; preserving all generated findings: {error:#}"
                                    );
                                    None
                                }
                            };
                            let mut application = match adjudicated {
                                Some(Ok(adjudicated)) => {
                                    add_usage(&mut usage, adjudicated.usage);
                                    model_usage.extend(adjudicated.model_usage);
                                    model_incidents.extend(adjudicated.model_incidents);
                                    usage_accounting_complete &=
                                        adjudicated.usage_accounting_complete;
                                    match crate::adjudication::apply_results(
                                        &snapshot_id,
                                        all_adjudication_candidates.clone(),
                                        candidate_ids.clone(),
                                        adjudicated.results,
                                        diff_snapshot.as_str(),
                                        &diff_receipt,
                                        receipt,
                                    ) {
                                        Ok(application) => application,
                                        Err(error) => {
                                            adjudication_incomplete = true;
                                            review_trust = filter::ReviewTrust::Failed;
                                            eprintln!(
                                                "postil: finding adjudication validation failed; preserving all generated findings: {error:#}"
                                            );
                                            model_incidents.push(ModelIncident {
                                                phase: ModelIncidentPhase::Scorer,
                                                category: ModelIncidentCategory::InvalidOutput,
                                                recovered: false,
                                                recovery: None,
                                            });
                                            adjudication_failure = Some(fail_closed_finding(
                                                "finding adjudication output did not satisfy its admitted contract",
                                            ));
                                            preserve_unadjudicated_findings(
                                                all_adjudication_candidates,
                                            )
                                        }
                                    }
                                }
                                Some(Err(error)) => {
                                    adjudication_incomplete = true;
                                    review_trust = filter::ReviewTrust::Failed;
                                    eprintln!(
                                        "postil: finding adjudication unavailable; preserving all generated findings"
                                    );
                                    add_usage(&mut usage, error.usage());
                                    model_usage.extend_from_slice(error.model_usage());
                                    model_incidents.extend_from_slice(error.model_incidents());
                                    usage_accounting_complete &= error.usage_accounting_complete();
                                    adjudication_failure = Some(if error.is_provider() {
                                        crate::envelope::provider_error_finding(
                                            "finding adjudication did not complete",
                                        )
                                    } else {
                                        fail_closed_finding(
                                            "finding adjudication output did not satisfy its admitted contract",
                                        )
                                    });
                                    preserve_unadjudicated_findings(all_adjudication_candidates)
                                }
                                None => {
                                    preserve_unadjudicated_findings(all_adjudication_candidates)
                                }
                            };
                            suppress_fresh_unresolved_repository_claims(
                                &mut application,
                                fresh_candidate_count,
                            );
                            for (candidate_index, finding) in application
                                .kept_indices
                                .iter()
                                .copied()
                                .zip(&mut application.kept)
                            {
                                let Some(candidate_id) = candidate_ids.get(candidate_index) else {
                                    continue;
                                };
                                let receipt_incomplete = diff_receipt
                                    .candidate_citations
                                    .iter()
                                    .find(|receipt| &receipt.candidate_id == candidate_id)
                                    .is_none_or(|receipt| !receipt.queries_complete);
                                if receipt_incomplete {
                                    finding.severity = crate::envelope::Severity::Error;
                                }
                            }
                            debug_assert!(application.kept_indices.iter().all(|index| *index
                                < fresh_candidate_count + baseline_candidate_indices.len()));
                            for candidate_index in &application.resolved_indices {
                                let Some(baseline_offset) =
                                    candidate_index.checked_sub(fresh_candidate_count)
                                else {
                                    continue;
                                };
                                let baseline_index = baseline_candidate_indices[baseline_offset];
                                adjudication_resolved.push(baseline[baseline_index].clone());
                            }
                            // A baseline finding leaves the ledger only through
                            // an adjudicator's explicit refutation or duplicate
                            // disposition. Deterministic evidence checks can
                            // demote a fresh candidate, but they leave a
                            // full-rereview baseline open for later review.
                            for (baseline_offset, baseline_index) in
                                baseline_candidate_indices.iter().copied().enumerate()
                            {
                                let candidate_index = fresh_candidate_count + baseline_offset;
                                if application.resolved_indices.contains(&candidate_index)
                                    || application.kept_indices.contains(&candidate_index)
                                {
                                    continue;
                                }
                                application.kept_indices.push(candidate_index);
                                application.kept.push(baseline[baseline_index].clone());
                                application.suppressed.retain(|suppressed| {
                                    !same_visible_finding(
                                        &suppressed.finding,
                                        &baseline[baseline_index],
                                    )
                                });
                            }
                            suppressed += application.suppressed.len() as u32;
                            suppressed_findings.extend(application.suppressed);
                            kept.clear();
                            for (candidate_index, finding) in
                                application.kept_indices.into_iter().zip(application.kept)
                            {
                                if candidate_index >= fresh_candidate_count {
                                    adjudication_preserved_baseline.push(finding.clone());
                                    preserved_baseline_publications.push(finding);
                                } else {
                                    kept.push(finding);
                                }
                            }
                            if !baseline_candidate_indices.is_empty() {
                                let removed = baseline_candidate_indices
                                    .into_iter()
                                    .collect::<std::collections::BTreeSet<_>>();
                                baseline = baseline
                                    .into_iter()
                                    .enumerate()
                                    .filter_map(|(index, finding)| {
                                        (!removed.contains(&index)).then_some(finding)
                                    })
                                    .collect();
                            }
                        }
                        if !kept.is_empty() && cfg.scorer_enabled() && !adjudication_incomplete {
                            let scorer_system = prompt::scorer_system_prompt(cfg, current_utc_date);
                            let mut evidence_budget = MAX_SCORER_EVIDENCE_BYTES;
                            let (inputs, scorer_user) = loop {
                                let inputs = scorer_inputs(
                                    &finding_contexts,
                                    &scorer_evidence_corpus,
                                    &kept,
                                    evidence_budget,
                                );
                                let scorer_user = prompt::scorer_user_prompt(&inputs);
                                let prompt_bytes =
                                    scorer_system.len().saturating_add(scorer_user.len());
                                if prompt_bytes <= MAX_SCORER_PROMPT_BYTES || evidence_budget == 0 {
                                    break (inputs, scorer_user);
                                }
                                let excess = prompt_bytes.saturating_sub(MAX_SCORER_PROMPT_BYTES);
                                evidence_budget = evidence_budget
                                    .saturating_sub(excess.max(evidence_budget / 4).max(1));
                            };
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
                        kept.extend(preserved_baseline_publications);
                        sort_findings_for_display(&mut kept);
                        findings = kept;
                    }
                }
                if let Some(failure) = batch_failure {
                    findings.push(failure);
                }
            }
        }
    }

    // A complete full review makes ephemeral anchors from a prior envelope
    // obsolete. They are presentation metadata rather than durable defects,
    // so record the retirement as non-actionable instead of carrying an
    // anchor that no longer exists in the reviewed input.
    if review_trust == filter::ReviewTrust::Exhaustive
        && matches!(scope, filter::ReconcileScope::Full { .. })
    {
        let mut durable_baseline = Vec::with_capacity(baseline.len());
        for finding in baseline {
            if crate::envelope::is_reserved_anchor(&finding.path) {
                suppressed = suppressed.saturating_add(1);
                suppressed_findings.push(SuppressedFinding {
                    finding,
                    reason: SuppressionReason::NonActionable,
                });
            } else {
                durable_baseline.push(finding);
            }
        }
        baseline = durable_baseline;
    }

    let repository_search = match repository_search {
        Some(receipt) => receipt,
        None => {
            crate::repository_search::search(
                &repository_source,
                repository_revision.as_deref(),
                findings.iter().chain(baseline.iter()),
            )
            .await
        }
    };
    let repository_suppressed = suppress_refuted_repository_claims(
        &mut findings,
        &repository_search,
        &adjudication_preserved_baseline,
    );
    suppressed = suppressed.saturating_add(repository_suppressed.len() as u32);
    suppressed_findings.extend(repository_suppressed);

    // A question the reviewer never answered cannot block a merge. This runs
    // after uncertainty resolution so a finding that went and checked keeps the
    // severity it earned.
    crate::filter::demote_deferred_verification(&mut findings);

    // Fresh metadata IDs must exist before reconciliation: synthetic line
    // numbers are presentation positions, not issue identity.
    generate_finding_ids(&mut findings, head_sha.as_deref());

    // Explicitly adjudicated baseline resolutions are authoritative. Remove
    // them before fail-closed reconciliation so they cannot be carried back
    // into the open ledger alongside their resolution record.
    baseline.retain(|finding| {
        !adjudication_resolved
            .iter()
            .any(|resolved| same_visible_finding(finding, resolved))
    });

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
    if let Some(failure) = adjudication_failure {
        findings.push(failure);
    }

    for finding in findings
        .iter()
        .filter(|finding| crate::envelope::is_ephemeral_anchor(&finding.path))
    {
        crate::envelope::validate_finding_public_language(finding).map_err(anyhow::Error::msg)?;
    }

    // Operational findings (model unreachable/unusable) fail the gate by default
    // and fail closed. `gate.onError: advisory` lets the gate stand aside on a
    // provider outage so a blip does not freeze every merge; the finding still
    // shows in the output and the review check fails. Unusable model
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
    // Raw summaries are validated for agreement with raw structured output,
    // then discarded. Presentation is derived from the final reconciled set so
    // suppressed, deduplicated, truncated, or resolved findings cannot leave
    // stale risk prose behind.
    let summary = summary_from_findings(&findings);
    let mut counts = Envelope::counts_of(&findings, suppressed);
    counts.ungrounded = ungrounded;
    let buckets = Envelope::buckets_of(&findings);

    // Generate stable IDs for findings
    generate_finding_ids(&mut findings, head_sha.as_deref());
    model_usage.sort_by_key(|entry| entry.call_ordinal.unwrap_or(u32::MAX));

    let mut resolved = rec.resolved;
    resolved.extend(adjudication_resolved);

    Ok(Envelope {
        version: 1,
        summary,
        silent,
        findings,
        suppressed_findings,
        resolved,
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
        repository_search,
        usage_accounting_complete,
        duration_ms: review_started.elapsed().as_millis() as u64,
        base_sha: meta.map(|m| m.base_sha.clone()),
        head_sha,
        // `sinceSha` names the baseline this review was measured against, so it
        // is absent on a full review. A requested baseline that the run could
        // not use is not the reviewed baseline.
        since_sha: incremental.then(|| args.since_sha.clone()).flatten(),
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
        repository_search: crate::repository_search::unavailable(head_sha.as_deref()),
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
    publication: Option<PublicationContext<'_>>,
    strict_publication: bool,
) -> Result<i32> {
    let publication_plan_to_stdout =
        args.publication_plan_output.as_deref() == Some(Path::new("-"));
    // Persist artifacts before any forge I/O: a posting hiccup must not
    // discard the completed review's SARIF or envelope output.
    if let Some(path) = &args.sarif {
        let sarif = crate::sarif::to_sarif(&envelope);
        std::fs::write(path, serde_json::to_string_pretty(&sarif)?)
            .with_context(|| format!("writing SARIF to {}", path.display()))?;
    }

    if let Some(format) = args.resolved_output_format()
        && (args.output_file.is_some() || !publication_plan_to_stdout)
    {
        output::write_envelope(&envelope, format, args.output_file.as_deref())?;
    }
    if !publication_plan_to_stdout
        && (args.resolved_output_format().is_none() || args.output_file.is_some())
    {
        output::print_pretty(&envelope);
    }

    let duplicate_of_baseline = load_baseline(args)
        .ok()
        .is_some_and(|baseline| visible_finding_sets_equal(&baseline, &envelope.findings));
    let intentional_no_comment = crate::forge::only_operational_findings(&envelope.findings)
        || (!envelope.findings.is_empty() && envelope.findings.iter().all(filter::is_carried));
    let should_comment = (!envelope.silent
        || matches!(cfg.on_clean, crate::config::OnClean::Comment))
        && !duplicate_of_baseline
        && !intentional_no_comment;

    if let Some(path) = &args.publication_plan_output {
        let forge = forge.context("publication planning requires a GitHub forge")?;
        let PublicationContext {
            snapshot: expected_snapshot,
            diff: publication_diff,
        } = publication.context("publication planning is missing its immutable PR snapshot")?;
        let (advisory, gate) = remote_check_states(&envelope);
        let plan = forge
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: args
                    .publication_generation
                    .as_deref()
                    .context("publication planning is missing its generation identity")?,
                input_identity: args
                    .publication_input_identity
                    .as_deref()
                    .context("publication planning is missing its input identity")?,
                envelope: &envelope,
                snapshot: expected_snapshot,
                publication_diff,
                should_comment,
                duplicate_of_baseline,
                annotate_findings: cfg.finding_presentation
                    == FindingPresentation::CheckAnnotations,
                advisory,
                gate,
            })
            .await?;
        if publication_plan_to_stdout {
            crate::forge::write_github_publication_plan_to_writer(std::io::stdout().lock(), &plan)?;
        } else {
            crate::forge::write_github_publication_plan(path, &plan)?;
        }
        return Ok(if envelope.gate.failing { 1 } else { 0 });
    }

    if let Some(forge) = forge
        && !args.no_post
    {
        let PublicationContext {
            snapshot: expected_snapshot,
            diff: publication_diff,
        } = publication.context("remote publication is missing its immutable PR snapshot")?;
        if cfg.finding_presentation == FindingPresentation::CheckAnnotations {
            let mut receipt = forge.plan_review_publication(&envelope, expected_snapshot);
            receipt.channel = crate::forge::ReviewPublicationChannel::CheckAnnotations;
            for finding in &mut receipt.findings {
                if finding.initial_outcome == crate::forge::FindingPublicationOutcome::Inline {
                    finding.initial_outcome =
                        crate::forge::FindingPublicationOutcome::CheckAnnotation;
                    finding.inline_rejected = false;
                    finding.comment_id = None;
                }
            }
            crate::forge::write_review_publication_receipt_from_env(&receipt)?;
            return Ok(if envelope.gate.failing { 1 } else { 0 });
        }
        if !should_comment {
            let mut receipt = forge.plan_review_publication(&envelope, expected_snapshot);
            if duplicate_of_baseline {
                for finding in &mut receipt.findings {
                    if matches!(
                        finding.initial_outcome,
                        crate::forge::FindingPublicationOutcome::Inline
                            | crate::forge::FindingPublicationOutcome::FileComment
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
            forge.post_review(&envelope, expected_snapshot, publication_diff),
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

/// Reserve every baseline finding that could enter full re-review adjudication
/// before generating fresh findings. The later candidate set can be smaller
/// when a fresh finding supersedes a baseline entry, but it must never be
/// larger than this conservative admission reservation.
fn baseline_adjudication_reserve(
    baseline: &[Finding],
    index: &diff::DiffIndex,
    scope: filter::ReconcileScope,
) -> usize {
    if !matches!(scope, filter::ReconcileScope::Full { .. }) {
        return 0;
    }
    baseline
        .iter()
        .filter(|finding| {
            let exact_citation_deleted = index.old_evidence_matches(finding)
                && index.remap_current_evidence(finding).is_none();
            (index.may_render_baseline_coordinate(finding) || exact_citation_deleted)
                && !crate::envelope::is_reserved_anchor(&finding.path)
        })
        .count()
}

fn baseline_may_enter_adjudication(finding: &Finding, index: &diff::DiffIndex) -> bool {
    let exact_citation_deleted =
        index.old_evidence_matches(finding) && index.remap_current_evidence(finding).is_none();
    (index.contains_reviewed_baseline_coordinate(finding) || exact_citation_deleted)
        && !crate::envelope::is_reserved_anchor(&finding.path)
}

/// A complete receipt can refute a fresh repository claim. Baseline candidates
/// preserved by adjudication remain open until that adjudication explicitly
/// resolves them. Any unavailable, exhausted, incomplete, or unrelated receipt
/// leaves a finding open rather than converting uncertainty into a clean review.
fn suppress_refuted_repository_claims(
    findings: &mut Vec<Finding>,
    receipt: &crate::envelope::RepositorySearchReceipt,
    adjudication_preserved_baseline: &[Finding],
) -> Vec<SuppressedFinding> {
    let mut preserved = Vec::new();
    let mut candidates = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        if adjudication_preserved_baseline
            .iter()
            .any(|baseline| same_visible_finding(baseline, &finding))
        {
            preserved.push(finding);
        } else {
            candidates.push(finding);
        }
    }
    let suppressed = crate::repository_search::enforce_receipt(&mut candidates, receipt);
    preserved.append(&mut candidates);
    *findings = preserved;
    suppressed
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

fn ungrounded_findings_failure(count: u32) -> Finding {
    fail_closed_finding(&format!(
        "model reported {count} finding(s) without a valid code-evidence citation."
    ))
}

fn preserve_unadjudicated_findings(
    findings: Vec<Finding>,
) -> crate::adjudication::AdjudicationApplication {
    crate::adjudication::AdjudicationApplication {
        kept_indices: (0..findings.len()).collect(),
        kept: findings,
        unresolved_indices: Vec::new(),
        resolved_indices: Vec::new(),
        suppressed: Vec::new(),
    }
}

fn suppress_fresh_unresolved_repository_claims(
    application: &mut crate::adjudication::AdjudicationApplication,
    fresh_candidate_count: usize,
) {
    let mut kept = Vec::with_capacity(application.kept.len());
    let mut kept_indices = Vec::with_capacity(application.kept_indices.len());
    for (candidate_index, finding) in application
        .kept_indices
        .drain(..)
        .zip(application.kept.drain(..))
    {
        let unsupported = candidate_index < fresh_candidate_count
            && application.unresolved_indices.contains(&candidate_index)
            && finding.repository_claim.is_some();
        if unsupported {
            application.suppressed.push(SuppressedFinding {
                finding,
                reason: SuppressionReason::RepositoryClaimUnsupported,
            });
        } else {
            kept_indices.push(candidate_index);
            kept.push(finding);
        }
    }
    application.kept = kept;
    application.kept_indices = kept_indices;
    application
        .unresolved_indices
        .retain(|index| application.kept_indices.contains(index));
}

fn error_envelope(
    cfg: &Config,
    err: &anyhow::Error,
    head_sha: &str,
    meta: Option<&PrMeta>,
    duration_ms: u64,
) -> Envelope {
    let incomplete_input = crate::forge::is_incomplete_review_input(err);
    let review_failure = err.downcast_ref::<ReviewFailure>();
    let invalid_output =
        review_failure.is_some_and(|failure| failure.kind == ReviewFailureKind::InvalidOutput);
    let advisory_operational_error = review_failure
        .is_some_and(|failure| failure.kind == ReviewFailureKind::Provider)
        || err.downcast_ref::<crate::llm::ProviderError>().is_some()
        || err.chain().any(|cause| {
            cause
                .downcast_ref::<crate::forge::ForgeServiceFailure>()
                .is_some()
        })
        || err.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_connect() || error.is_timeout())
        });
    let findings = vec![if incomplete_input {
        crate::envelope::incomplete_review_finding(
            crate::envelope::IncompleteReviewReason::IncompleteInput,
        )
    } else if invalid_output || !advisory_operational_error {
        // Only a recorded scorer error is genuinely about model output. Every
        // other failure here reaches this branch with its cause in `err`, so
        // report that instead of asserting a scorer contract that may never
        // have been exercised.
        match review_failure.and_then(|failure| failure.scorer_error.as_deref()) {
            Some(scorer_error) => fail_closed_finding(scorer_error),
            None => crate::envelope::operational_failure_finding(&format!("{err:#}")),
        }
    } else {
        crate::envelope::provider_error_finding(&format!("{err:#}"))
    }];
    let counts = Envelope::counts_of(&findings, 0);
    let buckets = Envelope::buckets_of(&findings);
    let gate_disabled = cfg.gate_fail_on.as_str().eq_ignore_ascii_case("never");
    let blocking =
        !gate_disabled && (!advisory_operational_error || cfg.gate_on_error == OnError::Block);
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
        repository_search: crate::repository_search::unavailable(Some(head_sha)),
        usage_accounting_complete: review_failure
            .is_none_or(|failure| failure.usage_accounting_complete),
        duration_ms,
        base_sha: meta.map(|value| value.base_sha.clone()),
        head_sha: Some(head_sha.to_string()),
        since_sha: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_serialized_shared_context_admits_local_and_ci_batch_edges() {
        let cfg = Config {
            model: "postil-bench/recorded".to_string(),
            api_base: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let models = vec![cfg.model.clone()];
        let system = prompt::system_prompt(
            &cfg,
            Date::from_calendar_date(2026, time::Month::August, 10).unwrap(),
        );
        let batch_budgets_for_title = |title: &str| {
            serialized_review_batch_budgets(
                &cfg,
                cfg.max_findings,
                &models,
                &system,
                &PrContext {
                    repo: Some("benchmark/example-fixtures"),
                    title: Some(title),
                    body: Some(""),
                    incremental: false,
                    content_policy: true,
                },
            )
            .unwrap()
        };

        let local_edge = format!("Benchmark pull request{}", "x".repeat(42));
        let ci_edge = format!("Benchmark pull request{}", "x".repeat(58));
        let below_floor = format!("Benchmark pull request{}", "x".repeat(442));

        let local_budgets = batch_budgets_for_title(&local_edge);
        assert_eq!(local_budgets.synthesis, 4_227);
        assert_eq!(local_budgets.source, 4_228);
        assert!(review_batch_budgets_are_usable(local_budgets));
        let ci_budgets = batch_budgets_for_title(&ci_edge);
        assert_eq!(ci_budgets.synthesis, 4_211);
        assert_eq!(ci_budgets.source, 4_212);
        assert!(review_batch_budgets_are_usable(ci_budgets));
        assert_eq!(
            ci_budgets.stabilized_for_rendering(),
            ReviewBatchBudgets {
                source: diff::MIN_REVIEW_BATCH_BYTES,
                synthesis: diff::MIN_REVIEW_BATCH_BYTES,
            }
        );
        let below_floor_budgets = batch_budgets_for_title(&below_floor);
        assert_eq!(
            below_floor_budgets.synthesis,
            diff::MIN_REVIEW_BATCH_BYTES - 269
        );
        assert!(!review_batch_budgets_are_usable(below_floor_budgets));
    }

    #[test]
    fn preflight_and_runtime_share_large_review_output_limits() {
        assert_eq!(review_output_token_limit(false, true), 6_000);
        assert_eq!(review_output_token_limit(true, true), 4_000);
        assert_eq!(
            review_output_token_limit(false, false),
            crate::llm::REVIEW_MAX_TOKENS
        );
        assert_eq!(review_output_token_limit(true, false), 4_000);
    }

    #[test]
    fn large_review_batch_concurrency_caps_consensus_provider_fanout() {
        let config = |consensus, cascade: Vec<&str>| Config {
            model: "provider/primary".to_string(),
            consensus,
            cascade: cascade.into_iter().map(str::to_string).collect(),
            ..Config::default()
        };
        assert_eq!(large_diff_batch_concurrency(&config(1, vec![])), 4);
        assert_eq!(
            large_diff_batch_concurrency(&config(2, vec!["provider/second"])),
            2
        );
        assert_eq!(
            large_diff_batch_concurrency(&config(3, vec!["provider/second", "provider/third"])),
            1
        );
    }

    #[test]
    fn hosted_scorer_failure_blocks_unscored_output() {
        assert!(scorer_failure_blocks_hosted(true, true));
        assert!(!scorer_failure_blocks_hosted(true, false));
        assert!(!scorer_failure_blocks_hosted(false, true));
    }
    use crate::envelope::{
        Kind, RepositoryClaim, RepositoryClaimKind, RepositorySearchMatch, RepositorySearchQuery,
        RepositorySearchReceipt, RepositorySearchState, Severity,
    };

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
    fn non_model_failures_report_their_own_cause() {
        let envelope = error_envelope(
            &Config::default(),
            &anyhow::anyhow!(
                "hosted review admission projects 11455328 micro-dollars of provider \
                 exposure, exceeding the 1000000 micro-dollar operation cap"
            ),
            "head",
            Some(&pr_meta()),
            1,
        );
        let finding = &envelope.findings[0];
        assert_eq!(finding.path, crate::envelope::OPERATIONAL_PATH);
        assert_eq!(finding.title, "Review could not be completed");
        assert!(
            finding.body.contains("micro-dollar operation cap"),
            "the real cause must reach the reader: {}",
            finding.body
        );
        assert!(
            !finding.body.contains("scorer"),
            "a failure that never ran the scorer must not blame it: {}",
            finding.body
        );
        assert!(envelope.gate.failing);
    }

    #[test]
    fn recorded_scorer_failures_still_report_the_scorer() {
        let envelope = error_envelope(
            &Config::default(),
            &rich_scorer_failure(ReviewFailureKind::InvalidOutput),
            "head",
            Some(&pr_meta()),
            1,
        );
        let finding = &envelope.findings[0];
        assert_eq!(finding.title, "Model output could not be validated");
        assert!(
            finding
                .body
                .contains("scorer output invalid after schema repair"),
            "the recorded scorer error must be preserved: {}",
            finding.body
        );
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
            Some(&pr_meta()),
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
        let envelope = error_envelope(&cfg, &error, "head", Some(&pr_meta()), 99);
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
        let envelope = error_envelope(&cfg, &error, "head", Some(&pr_meta()), 99);
        assert_eq!(envelope.findings[0].path, crate::envelope::PROVIDER_PATH);
        assert!(!envelope.gate.failing);
        assert_eq!(envelope.model_usage.len(), 2);
        assert_eq!(envelope.review_admission.unwrap().provider_attempts, 12);
    }

    #[test]
    fn planning_failure_remains_blocking_under_advisory_provider_policy() {
        let cfg = Config {
            gate_on_error: OnError::Advisory,
            ..Config::default()
        };
        let error = anyhow::anyhow!("complete hosted review exceeds its watchdog plan");
        let envelope = error_envelope(&cfg, &error, "head", Some(&pr_meta()), 1);
        assert_eq!(envelope.findings[0].path, crate::envelope::OPERATIONAL_PATH);
        assert!(envelope.gate.failing);
        assert!(envelope.summary.contains("failing closed"));
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
        let envelope = error_envelope(
            &cfg,
            &rich_scorer_failure(kind),
            "head",
            Some(&pr_meta()),
            99,
        );
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
        let envelope = error_envelope(&cfg, &error, "head", Some(&pr_meta()), 1);
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
            repository_claim: None,
            title: title.to_string(),
            body: body.to_string(),
            evidence: None,
            id: None,
        }
    }

    #[test]
    fn summaries_neutralize_malformed_historical_titles() {
        let malformed = finding_with_title(
            "src/lib.rs",
            1,
            "Unsafe title\n# forged heading",
            "Complete historical finding body.",
        );

        let summary = summary_from_findings(&[malformed]);

        assert!(!summary.contains('\n'));
        assert!(!summary.contains('#'));
        assert_eq!(summary, "Unsafe title forged heading.");
    }

    #[test]
    fn summaries_preserve_terminal_title_punctuation() {
        for (title, expected) in [
            (
                "Could this bypass authentication?",
                "Could this bypass authentication?",
            ),
            ("Stop unsafe publication!", "Stop unsafe publication!"),
            ("認証を確認する？", "認証を確認する？"),
        ] {
            let finding =
                finding_with_title("src/lib.rs", 1, title, "Complete historical finding body.");
            assert_eq!(summary_from_findings(&[finding]), expected);
        }
    }

    #[test]
    fn summaries_compose_multiple_titles_as_sentences() {
        let findings = vec![
            finding_with_title(
                "src/first.rs",
                1,
                "Could this bypass authentication?",
                "Complete first finding body.",
            ),
            finding_with_title(
                "src/second.rs",
                2,
                "Stop unsafe publication!",
                "Complete second finding body.",
            ),
            finding_with_title(
                "src/third.rs",
                3,
                "Plain title",
                "Complete third finding body.",
            ),
        ];

        assert_eq!(
            summary_from_findings(&findings),
            "Could this bypass authentication? Stop unsafe publication! Plain title."
        );
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
            (HOSTED_LLM_REVIEW_TIMEOUT_SECS - HOSTED_REVIEW_SCHEDULING_RESERVE_SECS)
                / LARGE_DIFF_LLM_REQUEST_TIMEOUT_SECS,
            6
        );
        assert_eq!(
            HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            HOSTED_LLM_REVIEW_TIMEOUT_SECS + SCORER_TIMEOUT_SECS
        );
        assert_eq!(
            HOSTED_WORKER_WATCHDOG_SECS - HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            CHECK_COMPLETION_TIMEOUT_SECS + REVIEW_POST_TIMEOUT_SECS + PROCESS_OVERHEAD_SECS
        );

        let scorer_disabled = Config {
            scorer_enabled: false,
            uncertainty_resolution: true,
            concise_findings: true,
            model: "provider/generator".into(),
            ..Config::default()
        };
        let scorer_enabled = Config {
            scorer: "provider/scorer".into(),
            scorer_enabled: true,
            ..scorer_disabled.clone()
        };

        let scorer_disabled_budgets = hosted_review_phase_budgets(&scorer_disabled);
        assert_eq!(
            scorer_disabled_budgets,
            HostedReviewPhaseBudgets {
                generator: 360,
                scorer: 0,
                resolution: POSTPROCESSING_PHASE_TIMEOUT_SECS,
                brevity: POSTPROCESSING_PHASE_TIMEOUT_SECS,
                adjudication: FINDING_ADJUDICATION_TIMEOUT_SECS,
            }
        );
        assert_eq!(
            scorer_disabled_budgets.total(),
            HOSTED_LLM_TOTAL_TIMEOUT_SECS
        );
        assert_eq!(hosted_review_timeout_secs(&scorer_disabled), 360);
        assert_eq!(
            crate::llm::max_hosted_review_batches(&scorer_disabled, false).unwrap(),
            20
        );

        let scorer_enabled_budgets = hosted_review_phase_budgets(&scorer_enabled);
        assert_eq!(
            scorer_enabled_budgets,
            HostedReviewPhaseBudgets {
                generator: 240,
                scorer: SCORER_TIMEOUT_SECS,
                resolution: POSTPROCESSING_PHASE_TIMEOUT_SECS,
                brevity: POSTPROCESSING_PHASE_TIMEOUT_SECS,
                adjudication: FINDING_ADJUDICATION_TIMEOUT_SECS,
            }
        );
        assert_eq!(
            scorer_enabled_budgets.total(),
            HOSTED_LLM_TOTAL_TIMEOUT_SECS
        );
        assert_eq!(hosted_review_timeout_secs(&scorer_enabled), 240);
        assert_eq!(
            crate::llm::max_hosted_review_batches(&scorer_enabled, false).unwrap(),
            12
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

    #[test]
    fn only_fresh_unresolved_repository_claims_are_suppressed() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec!["widget".into()],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        let mut fresh_repository_claim = finding("src/fresh.rs", 1, "widget is absent");
        fresh_repository_claim.repository_claim = Some(claim.clone());
        let fresh_local_finding = finding("src/local.rs", 2, "authorization is bypassed");
        let mut baseline_repository_claim = finding("src/baseline.rs", 3, "widget is absent");
        baseline_repository_claim.repository_claim = Some(claim);
        let mut application = crate::adjudication::AdjudicationApplication {
            kept: vec![
                fresh_repository_claim.clone(),
                fresh_local_finding.clone(),
                baseline_repository_claim.clone(),
            ],
            kept_indices: vec![0, 1, 2],
            unresolved_indices: vec![0, 1, 2],
            resolved_indices: vec![],
            suppressed: vec![],
        };

        suppress_fresh_unresolved_repository_claims(&mut application, 2);

        assert_eq!(application.kept_indices, vec![1, 2]);
        assert_eq!(application.unresolved_indices, vec![1, 2]);
        assert_eq!(application.kept.len(), 2);
        assert!(same_visible_finding(
            &application.kept[0],
            &fresh_local_finding
        ));
        assert!(same_visible_finding(
            &application.kept[1],
            &baseline_repository_claim
        ));
        assert_eq!(application.suppressed.len(), 1);
        assert!(same_visible_finding(
            &application.suppressed[0].finding,
            &fresh_repository_claim
        ));
        assert_eq!(
            application.suppressed[0].reason,
            SuppressionReason::RepositoryClaimUnsupported
        );
    }

    #[test]
    fn adjudication_preserved_baseline_survives_a_deterministic_refutation_receipt() {
        let snapshot_id = "a".repeat(40);
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec!["widget".into()],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        let terms = crate::repository_search::search_terms(std::iter::once(&claim)).unwrap();
        let query = terms[0].query_sha256.clone();
        let receipt = RepositorySearchReceipt {
            head_sha: Some(snapshot_id.clone()),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            queries: vec![RepositorySearchQuery {
                kind: terms[0].kind,
                query_sha256: query.clone(),
            }],
            matched_query_sha256: vec![query.clone()],
            matches: vec![RepositorySearchMatch {
                query_sha256: query,
                path: "src/dependencies.txt".into(),
                occurrences: 1,
            }],
            match_count: 1,
            ..RepositorySearchReceipt::default()
        };
        let mut baseline = finding("src/db.rs", 10, "missing widget");
        baseline.repository_claim = Some(claim);

        let mut preserved = vec![baseline.clone()];
        assert!(
            suppress_refuted_repository_claims(&mut preserved, &receipt, &[baseline.clone()],)
                .is_empty()
        );
        assert_eq!(preserved.len(), 1);
        assert!(same_visible_finding(&preserved[0], &baseline));

        let mut fresh = vec![baseline];
        assert!(suppress_refuted_repository_claims(&mut fresh, &receipt, &[]).is_empty());
        assert_eq!(fresh.len(), 1);
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
    fn batch_validation_requires_typed_queries_for_universal_repository_claims() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 + changed();\n";
        let mut finding = finding(
            "src/lib.rs",
            7,
            "No other caller accepts this identifier; add a compatible caller.",
        );
        finding.evidence = Some("changed();".to_string());

        let reason = review_batch_validation_reason(&finding, annotated, None).unwrap();
        assert_eq!(reason.category, "repositoryClaim");

        finding.repository_claim = Some(crate::envelope::RepositoryClaim {
            kind: crate::envelope::RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["identifier".into()],
        });
        assert_eq!(
            review_batch_validation_reason(&finding, annotated, None),
            None
        );
    }

    #[test]
    fn batch_validation_rejects_public_evidence_boundary_language() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 + changed();\n";
        let mut finding = finding(
            "src/lib.rs",
            7,
            "In the diff this is unsafe; verify that the unchanged callers agree.",
        );
        finding.evidence = Some("changed();".to_string());

        let reason = review_batch_validation_reason(&finding, annotated, None).unwrap();
        assert_eq!(reason.category, "reviewArtifactPhrase");
        assert!(reason.repair_detail.contains("remove review-process terms such as `diff`, `patch`, `PR`, `MR`, `review input`, and `provided context`"));
        assert!(
            reason
                .repair_detail
                .contains("retract the finding if the supplied evidence is insufficient")
        );

        let failure = review_batch_validation_reasons(&[finding], annotated, None).unwrap();
        assert_eq!(failure.safe_detail(), "reviewArtifactPhrase=1");
    }

    #[test]
    fn delegated_evidence_repair_preserves_directly_established_defects() {
        let annotated = "### src/lib.rs\n@@ fixture @@\n    7 + changed();\n";
        let mut finding = finding(
            "src/lib.rs",
            7,
            "Verify that `applyBulkEdit` internally enforces the permission check.",
        );
        finding.evidence = Some("changed();".to_string());

        let reason = review_batch_validation_reason(&finding, annotated, None).unwrap();

        assert_eq!(reason.category, "delegatedEvidenceCollection");
        assert!(reason.repair_detail.contains(
            "if the cited changed line already establishes the defect, state it directly and omit `repositoryContext`"
        ));
        assert!(
            reason
                .repair_detail
                .contains("declare the exact absence or mismatch through `repositoryContext`")
        );
    }

    #[test]
    fn all_ungrounded_failure_uses_public_evidence_validation_language() {
        let finding = ungrounded_findings_failure(3);
        assert_eq!(
            finding.body,
            "Postil could not validate the configured model response against cited code evidence. No clean verdict was issued.\n\nDetail: model reported 3 finding(s) without a valid code-evidence citation."
        );
        assert_eq!(
            crate::envelope::validate_finding_public_language(&finding),
            Ok(())
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
