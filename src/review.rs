//! Review orchestration: one engine for local, CI, and hosted runs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};

use crate::config::{Config, GateLevel, OnError};
use crate::diff::{self, DiffIndex};
use crate::envelope::{Envelope, Finding, Gate, Kind, ModelUsage, Usage, fail_closed_finding};
use crate::filter;
use crate::forge::{
    CheckState, Forge, PrMeta, azure::Azure, bitbucket::Bitbucket, github::GitHub, gitlab::GitLab,
};
use crate::llm::{FindingScore, LlmClient};
use crate::local::{self, LocalSource};
use crate::output::{self, OutputFormat};
use crate::prompt::{self, PrContext};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Each model request and the aggregate review stay bounded. Exhausting any
/// limit produces an internal fail-closed result rather than a partial pass.
const MAX_REVIEW_BATCH_BYTES: usize = 120_000;
const MAX_SOURCE_BATCHES: usize = 8;
const MAX_REVIEW_REQUESTS: usize = MAX_SOURCE_BATCHES + 1;
const MAX_REVIEW_PROJECTED_INPUT_TOKENS: usize = 1_000_000;
const MAX_REVIEW_MANIFEST_BYTES: usize = 24_000;
const MAX_MODELS_PER_REQUEST: usize = 3;
const MAX_SCORER_INPUT_TOKENS: usize = 64_000;
const HOSTED_WORKER_WATCHDOG_SECS: u64 = 600;
pub(crate) const HOSTED_LLM_TOTAL_TIMEOUT_SECS: u64 = 540;
/// Hosted reviews get a 240s primary attempt plus one timeout retry capped at
/// 90s. The entire review-model phase stops at 420s, leaving 120s of the total
/// LLM budget for scoring.
pub(crate) const HOSTED_LLM_REQUEST_TIMEOUT_SECS: u64 = 240;
pub(crate) const HOSTED_LLM_REVIEW_TIMEOUT_SECS: u64 = 420;
const FORGE_READ_TIMEOUT_SECS: u64 = 60;
const CHECK_START_TIMEOUT_SECS: u64 = 30;
const CHECK_COMPLETION_TIMEOUT_SECS: u64 = 30;
const REVIEW_POST_TIMEOUT_SECS: u64 = 20;
pub(crate) const SCORER_TIMEOUT_SECS: u64 = 120;

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
    pub output: Option<OutputFormat>,
    pub output_file: Option<PathBuf>,
    pub output_json: bool,
    pub sarif: Option<PathBuf>,
    pub fail_on: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    pub no_post: bool,
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
    diff_text: &'a str,
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
    head_sha: &'a str,
    prefetched_diff: Option<Result<String>>,
    review_started: Instant,
}

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
            llm_budget_started_at: None,
        },
    )
    .await?;
    finish(args, cfg, envelope, None::<&GitHub>, None).await
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
        let meta = run_with_hosted_budget(
            Some(review_started),
            FORGE_READ_TIMEOUT_SECS,
            forge.fetch_pr_meta(),
            "fetching PR metadata",
        )
        .await?;
        let head_sha = args.sha.clone().unwrap_or_else(|| meta.head_sha.clone());

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
            Some(
                run_with_hosted_budget(
                    Some(review_started),
                    FORGE_READ_TIMEOUT_SECS,
                    forge.fetch_diff(),
                    "fetching diff",
                )
                .await,
            )
        } else {
            None
        }
    };
    let (setup, prefetched_diff) = tokio::join!(setup, prefetch_diff);
    let (meta, head_sha, checks) = setup?;

    let result = remote_review(
        args,
        cfg,
        forge,
        repo,
        RemoteReviewInput {
            meta: &meta,
            head_sha: &head_sha,
            prefetched_diff,
            review_started,
        },
    )
    .await;
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
                let completed = run_with_hosted_budget(
                    Some(review_started),
                    CHECK_COMPLETION_TIMEOUT_SECS,
                    forge.complete_checks(a, g, advisory_state, gate_state, &envelope),
                    "completing check runs",
                )
                .await;
                if let Err(e) = completed {
                    eprintln!("postil: could not update check runs ({e:#})");
                }
            }
            finish(args, cfg, envelope, Some(forge), Some(review_started)).await
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
                let _ = run_with_hosted_budget(
                    Some(review_started),
                    CHECK_COMPLETION_TIMEOUT_SECS,
                    forge.complete_checks(a, g, CheckState::Neutral, gate_state, &envelope),
                    "completing check runs",
                )
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
            match finish(args, cfg, envelope, Some(forge), Some(review_started)).await {
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
    input: RemoteReviewInput<'_>,
) -> Result<Envelope> {
    let RemoteReviewInput {
        meta,
        head_sha,
        prefetched_diff,
        review_started,
    } = input;
    let baseline = load_baseline(args)?;
    let has_carryable_baseline = baseline
        .iter()
        .any(|f| !crate::envelope::is_ephemeral_anchor(&f.path));
    let incremental = args.since_sha.as_deref();
    let (diff_text, scope, force_model) = match incremental {
        Some(since) if since != head_sha => run_with_hosted_budget(
            Some(review_started),
            FORGE_READ_TIMEOUT_SECS,
            forge.fetch_diff_since(since, head_sha),
            "fetching incremental diff",
        )
        .await
        .context("incremental diff fetch")
        .map(|diff| (diff, filter::ReconcileScope::Incremental, false))?,
        Some(_) => (String::new(), filter::ReconcileScope::Incremental, false),
        None => (
            match prefetched_diff {
                Some(diff) => diff.context("diff fetch")?,
                None => run_with_hosted_budget(
                    Some(review_started),
                    FORGE_READ_TIMEOUT_SECS,
                    forge.fetch_diff(),
                    "fetching diff",
                )
                .await
                .context("diff fetch")?,
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
            run_with_hosted_budget(
                Some(review_started),
                FORGE_READ_TIMEOUT_SECS,
                forge.fetch_diff(),
                "fetching full fallback diff",
            )
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
    let mut id_map: HashMap<String, usize> = HashMap::new();

    for finding in findings.iter_mut() {
        if finding.id.is_some() {
            continue;
        }
        // Normalize the finding data
        let normalized_path = finding.path.to_lowercase();
        let normalized_line = finding.line.to_string();
        let normalized_title = finding.title.trim().to_lowercase();
        let identity = if finding.path == crate::envelope::CHANGE_METADATA_PATH {
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
                normalized_line,
                normalized_title
            )
        };

        // Create a pre-hash key to track duplicates.
        let prehash_key = identity.clone();
        let duplicate_index = id_map
            .entry(prehash_key)
            .and_modify(|count| *count += 1)
            .or_insert(0);

        // Build the hash input
        let hash_input = format!("{identity}\x00{duplicate_index}");

        // Generate SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
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
            path: finding.path.clone(),
            line: finding.line,
            severity: finding.severity.as_str().to_string(),
            title: finding.title.clone(),
            body: finding.body.clone(),
            diff_hunk: diff::render_hunk_context(parsed, &finding.path, finding.line, 20)
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

async fn review_diff(cfg: &Config, args: &ReviewArgs, input: ReviewInput<'_>) -> Result<Envelope> {
    let ReviewInput {
        diff_text,
        meta,
        head_sha,
        repo,
        baseline,
        scope,
        force_model,
        llm_budget_started_at,
    } = input;
    let review_started = std::time::Instant::now();
    let prepared = diff::prepare_diff(diff_text, diff::MAX_RAW_DIFF_INPUT_BYTES);
    let parsed = diff::parse(prepared.source.as_deref().unwrap_or_default());
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
    let mut model_usage: Vec<ModelUsage> = Vec::new();
    let mut model_incidents = Vec::new();
    let mut usage_accounting_complete = true;
    let mut suppressed = 0u32;
    let mut ungrounded = 0u32;
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed_findings = Vec::new();
    let mut full_review_trustworthy = false;
    let mut scorer_model: Option<String> = None;
    let mut scorer_error: Option<String> = None;
    let mut scorer_disagreements: Option<u32> = None;

    // Run the model when there is a diff to review, or when content policy is
    // active and there is a PR title/description to review (an empty diff should
    // still get its prose checked).
    if !cfg.enabled {
        model_used = "none (disabled by config)".to_string();
    } else if force_model
        || prepared.incomplete
        || parsed.has_review_evidence()
        || !prepared.lockfiles.is_empty()
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
        let shared_context_tokens =
            system.len() + meta.map_or(0, |value| value.title.len() + value.body.len()) + 4096;
        let batch_budget = context_tokens
            .saturating_sub(crate::llm::REVIEW_MAX_TOKENS as usize)
            .saturating_sub(shared_context_tokens)
            .min(MAX_REVIEW_BATCH_BYTES);
        let mut plan = if prepared.incomplete || batch_budget < 4_096 {
            diff::ReviewBatchPlan {
                incomplete: true,
                ..Default::default()
            }
        } else {
            diff::render_review_batches(
                &parsed,
                &prepared.lockfiles,
                batch_budget,
                MAX_SOURCE_BATCHES,
                MAX_REVIEW_MANIFEST_BYTES.min(batch_budget / 3),
            )
        };
        index.add_change_metadata(plan.metadata_count);
        if plan.batches.is_empty() && (force_model || pr_desc_lines > 0) {
            plan.batches.push(String::new());
        }
        let request_count = plan.batches.len() + usize::from(plan.synthesis.is_some());
        let projected_input_bytes = plan
            .projected_input_bytes
            .saturating_add(shared_context_tokens.saturating_mul(request_count));
        // One UTF-8 byte per token is deliberately pessimistic across BPE
        // tokenizers and avoids the unsafe bytes/4 approximation.
        let projected_input_tokens = projected_input_bytes;
        let attempts_per_request =
            active_model_count.saturating_mul((crate::llm::TRANSIENT_RETRIES as usize + 1) * 2);
        let scorer_attempts = usize::from(cfg.scorer_enabled())
            .saturating_mul(MAX_MODELS_PER_REQUEST)
            .saturating_mul((crate::llm::TRANSIENT_RETRIES as usize + 1) * 2);
        let projected_attempts = request_count
            .saturating_mul(attempts_per_request)
            .saturating_add(scorer_attempts);
        let review_exposure = projected_input_tokens
            .saturating_add(request_count.saturating_mul(crate::llm::REVIEW_MAX_TOKENS as usize))
            .saturating_mul(attempts_per_request);
        let scorer_exposure =
            scorer_attempts.saturating_mul(MAX_SCORER_INPUT_TOKENS.saturating_add(4_096));
        let projected_token_exposure = review_exposure.saturating_add(scorer_exposure);
        let budget_exhausted = plan.incomplete
            || request_count > MAX_REVIEW_REQUESTS
            || active_model_count == 0
            || active_model_count > MAX_MODELS_PER_REQUEST
            || projected_input_tokens > MAX_REVIEW_PROJECTED_INPUT_TOKENS
            || projected_attempts > crate::llm::MAX_PROVIDER_ATTEMPTS
            || projected_token_exposure > crate::llm::MAX_REPORTED_TOKEN_SPEND;

        if budget_exhausted {
            eprintln!(
                "postil: review incomplete before model calls (requests {request_count}/{MAX_REVIEW_REQUESTS}, models {active_model_count}/{MAX_MODELS_PER_REQUEST}, projected input <= {projected_input_tokens} tokens, attempts {projected_attempts}/{}, token exposure {projected_token_exposure}/{})",
                crate::llm::MAX_PROVIDER_ATTEMPTS,
                crate::llm::MAX_REPORTED_TOKEN_SPEND,
            );
            model_used = "none (review budget exhausted)".to_string();
            findings = vec![crate::envelope::incomplete_review_finding()];
        } else if plan.batches.is_empty() {
            model_used = "none (empty diff)".to_string();
            full_review_trustworthy = true;
        } else {
            let client = match llm_budget_started_at {
                Some(started_at) => LlmClient::from_env_for_remote_review(
                    cfg,
                    started_at,
                    Duration::from_secs(HOSTED_LLM_REQUEST_TIMEOUT_SECS),
                    Duration::from_secs(HOSTED_LLM_REVIEW_TIMEOUT_SECS),
                    Duration::from_secs(HOSTED_LLM_TOTAL_TIMEOUT_SECS),
                )?,
                None => LlmClient::from_env(cfg)?,
            };
            let total_requests = request_count;
            let mut raw_findings = Vec::new();
            let mut summary_parts = Vec::new();
            let mut batch_models = Vec::new();
            let mut batch_failed = false;
            let mut batch_ungrounded = 0u32;
            let requests = plan
                .batches
                .iter()
                .map(|batch| (batch, false))
                .chain(plan.synthesis.iter().map(|batch| (batch, true)));
            for (request_index, (annotated, synthesis)) in requests.enumerate() {
                eprintln!(
                    "postil: reviewing {} request {}/{} ({} bytes)",
                    if synthesis { "synthesis" } else { "source" },
                    request_index + 1,
                    total_requests,
                    annotated.len()
                );
                let first = request_index == 0;
                let ctx = PrContext {
                    repo,
                    title: if !content_policy_active || first {
                        meta.map(|m| m.title.as_str())
                    } else {
                        None
                    },
                    body: if !content_policy_active || first {
                        meta.map(|m| m.body.as_str())
                    } else {
                        None
                    },
                    incremental,
                    content_policy: first && content_policy_active,
                };
                let mut user = prompt::user_prompt(&ctx, annotated, cfg.max_findings);
                if synthesis {
                    user.push_str(
                        "\n\nThis is the final bounded synthesis request. Look only for merge-relevant relationships across the structured semantic digests. Every digest entry retains its exact groundable path and line. Do not repeat a batch-local finding unless the cross-batch relationship materially changes its impact.",
                    );
                } else if plan.batches.len() > 1 {
                    user.push_str(&format!(
                        "\n\nThis is source batch {} of {}. Review this batch independently; \
                     other source batches are reviewed separately.",
                        request_index + 1,
                        plan.batches.len()
                    ));
                }
                match client.review(cfg, &system, &user).await {
                    Ok(mut model_review) => {
                        usage.prompt_tokens += model_review.usage.prompt_tokens;
                        usage.completion_tokens += model_review.usage.completion_tokens;
                        model_usage.extend(model_review.model_usage);
                        model_incidents.extend(model_review.model_incidents);
                        usage_accounting_complete &= model_review.usage_accounting_complete;
                        if !batch_models.contains(&model_review.model_used) {
                            batch_models.push(model_review.model_used);
                        }
                        if !model_review.summary.trim().is_empty() {
                            summary_parts.push(model_review.summary);
                        }
                        for finding in &mut model_review.findings {
                            if finding.end_line.is_some_and(|end| {
                                !diff::review_batch_contains_range(
                                    annotated,
                                    &finding.path,
                                    finding.line,
                                    end,
                                )
                            }) {
                                finding.end_line = None;
                            }
                        }
                        let before = model_review.findings.len();
                        model_review.findings.retain(|finding| {
                            diff::review_batch_contains_range(
                                annotated,
                                &finding.path,
                                finding.line,
                                finding.line,
                            ) || (first
                                && finding.kind == crate::envelope::Kind::ContentPolicy
                                && index.contains_content_policy(&finding.path, finding.line))
                        });
                        for finding in &mut model_review.findings {
                            finding.path = diff::canonical_prompt_path(&finding.path)
                                .expect("grounded prompt paths are reversible");
                        }
                        batch_ungrounded += (before - model_review.findings.len()) as u32;
                        raw_findings.extend(model_review.findings);
                    }
                    Err(e) => {
                        usage.prompt_tokens += e.usage().prompt_tokens;
                        usage.completion_tokens += e.usage().completion_tokens;
                        model_usage.extend_from_slice(e.model_usage());
                        model_incidents.extend_from_slice(e.model_incidents());
                        usage_accounting_complete &= e.usage_accounting_complete();
                        let detail = format!("{e:#}");
                        findings = vec![if e.is_provider() {
                            crate::envelope::provider_error_finding(&detail)
                        } else {
                            fail_closed_finding(&detail)
                        }];
                        if batch_models.is_empty() {
                            model_used = cfg.model_chain().join(" -> ");
                        }
                        batch_failed = true;
                        break;
                    }
                }
            }
            if !batch_models.is_empty() {
                model_used = batch_models.join(", ");
            }
            if !batch_failed && !plan.batches.is_empty() {
                let mut deduplicated = Vec::<Finding>::new();
                let mut positions: HashMap<_, usize> = HashMap::new();
                for finding in raw_findings {
                    let key = (
                        finding.path.clone(),
                        finding.line,
                        finding.end_line,
                        finding.kind.as_str().to_string(),
                        finding.title.clone(),
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
                if outcome.all_ungrounded || (grounded_candidate_count == 0 && batch_ungrounded > 0)
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
                    full_review_trustworthy = true;
                    summary = summary_parts.join("\n\n");
                    let mut kept = outcome.kept;
                    if !kept.is_empty() && cfg.scorer_enabled() {
                        let inputs = scorer_inputs(&parsed, &plan.batches, &kept);
                        let scorer_system = prompt::scorer_system_prompt(cfg);
                        let scorer_user = prompt::scorer_user_prompt(&inputs);
                        if scorer_system.len().saturating_add(scorer_user.len())
                            > MAX_SCORER_INPUT_TOKENS
                        {
                            scorer_error = Some(
                                "scorer skipped because its bounded input budget was exceeded"
                                    .to_string(),
                            );
                        } else {
                            let scored = tokio::time::timeout(
                                std::time::Duration::from_secs(SCORER_TIMEOUT_SECS),
                                client.score_findings(
                                    cfg,
                                    &scorer_system,
                                    &scorer_user,
                                    inputs.len(),
                                ),
                            )
                            .await;
                            match scored {
                                Ok(Ok(scored)) => {
                                    let disagreements =
                                        apply_scorer_scores(cfg, &mut kept, scored.scores);
                                    let scorer_suppressed =
                                        suppress_below_min_confidence(cfg, &mut kept);
                                    suppressed += scorer_suppressed.len() as u32;
                                    suppressed_findings.extend(scorer_suppressed);
                                    scorer_model = Some(scored.model_used);
                                    usage.prompt_tokens += scored.usage.prompt_tokens;
                                    usage.completion_tokens += scored.usage.completion_tokens;
                                    model_usage.extend(scored.model_usage);
                                    model_incidents.extend(scored.model_incidents);
                                    usage_accounting_complete &= scored.usage_accounting_complete;
                                    scorer_disagreements = Some(disagreements);
                                    sort_findings_for_display(&mut kept);
                                }
                                Ok(Err(e)) => {
                                    let detail = format!("{e:#}");
                                    eprintln!(
                                        "postil: scorer failed open after all scorer models failed"
                                    );
                                    let scorer_usage = e.usage();
                                    usage.prompt_tokens += scorer_usage.prompt_tokens;
                                    usage.completion_tokens += scorer_usage.completion_tokens;
                                    model_usage.extend_from_slice(e.model_usage());
                                    model_incidents.extend_from_slice(e.model_incidents());
                                    usage_accounting_complete &= e.usage_accounting_complete();
                                    scorer_error = Some(detail);
                                }
                                Err(_) => {
                                    usage_accounting_complete = false;
                                    let detail =
                                        format!("scorer timed out after {SCORER_TIMEOUT_SECS}s");
                                    eprintln!("postil: scorer failed open: {detail}");
                                    scorer_error = Some(detail);
                                    model_incidents.push(crate::envelope::ModelIncident {
                                        phase: crate::envelope::ModelIncidentPhase::Scorer,
                                        category: crate::envelope::ModelIncidentCategory::Timeout,
                                        recovered: false,
                                        recovery: None,
                                    });
                                }
                            }
                        }
                    }
                    findings = kept;
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
    let gate_fail_on = cfg.gate_fail_on.as_str();
    let gate_block_on_kinds: Vec<String> = cfg
        .block_on_kinds
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect();
    let gate_failing = findings.iter().any(|f| {
        if f.path == crate::envelope::OPERATIONAL_PATH {
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
        usage_accounting_complete,
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
    hosted_budget_started_at: Option<Instant>,
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
        let duplicate_of_baseline = load_baseline(args)
            .ok()
            .is_some_and(|baseline| visible_finding_sets_equal(&baseline, &envelope.findings));
        let should_comment = (!envelope.silent
            || matches!(cfg.on_clean, crate::config::OnClean::Comment))
            && !duplicate_of_baseline;
        if should_comment {
            let summary = forge.review_summary(&envelope);
            let head = envelope.head_sha.clone().unwrap_or_default();
            // A posting failure here (rate limit, transient 5xx, network blip)
            // must not discard a review that already computed and persisted its
            // envelope/SARIF/stdout output above. Log it and keep going — the
            // exit code always derives from the gate below, never from whether
            // the forge comment made it out.
            let posted = run_with_hosted_budget(
                hosted_budget_started_at,
                REVIEW_POST_TIMEOUT_SECS,
                forge.post_review(&summary, &envelope.findings, &head),
                "posting review comment",
            )
            .await;
            if let Err(e) = posted {
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
        model_used: cfg.model_chain().join(" -> "),
        scorer_model: None,
        scorer_error: None,
        scorer_disagreements: None,
        usage: Usage::default(),
        model_usage: vec![],
        model_incidents: vec![],
        usage_accounting_complete: true,
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
            id: None,
        }
    }

    fn expected_finding_id(finding: &Finding, head_sha: &str, duplicate_index: usize) -> String {
        let hash_input = format!(
            "{}\x00{}\x00{}\x00{}\x00{}\x00{}",
            head_sha,
            finding.kind.as_str(),
            finding.path.to_lowercase(),
            finding.line,
            finding.title.trim().to_lowercase(),
            duplicate_index
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
        assert_eq!(HOSTED_LLM_REVIEW_TIMEOUT_SECS, 420);
        assert_eq!(
            HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            HOSTED_LLM_REVIEW_TIMEOUT_SECS + SCORER_TIMEOUT_SECS
        );
        assert_eq!(
            HOSTED_WORKER_WATCHDOG_SECS - HOSTED_LLM_TOTAL_TIMEOUT_SECS,
            CHECK_COMPLETION_TIMEOUT_SECS + REVIEW_POST_TIMEOUT_SECS + PROCESS_OVERHEAD_SECS
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
}
