//! Forge abstraction: everything Postil needs from a code host.
//!
//! Ships GitHub, GitLab, Bitbucket Cloud, and Azure DevOps. GitHub, GitLab, and
//! Azure cover self-managed variants through a custom base URL.

pub mod azure;
pub mod bitbucket;
pub mod github;
pub mod gitlab;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::diff::DiffSnapshot;
use crate::envelope::{Envelope, Finding, Severity, SuppressionReason};

pub const MAX_FORGE_METADATA_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FORGE_CHANGED_FILES: usize = 20_000;
pub const PUBLICATION_RECEIPT_PATH_ENV: &str = "POSTIL_PUBLICATION_RECEIPT_PATH";
pub const GITHUB_PUBLICATION_PLAN_CONTRACT: &str = "github-publication-v1";

pub fn checked_metadata_total(current: usize, additional: usize, context: &str) -> Result<usize> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| anyhow::anyhow!("{context} metadata byte count overflowed"))?;
    ensure!(
        total <= MAX_FORGE_METADATA_BYTES,
        "{context} metadata exceeds the {MAX_FORGE_METADATA_BYTES} byte aggregate limit"
    );
    Ok(total)
}

#[derive(Debug)]
pub struct ForgeServiceFailure(pub String);

impl std::fmt::Display for ForgeServiceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ForgeServiceFailure {}

#[derive(Debug)]
pub struct IncompleteReviewInput;

impl std::fmt::Display for IncompleteReviewInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("review input was incomplete or malformed")
    }
}

impl std::error::Error for IncompleteReviewInput {}

/// Marks a refusal that is specific to the requested incremental baseline: the
/// head no longer descends from it, or the forge truncated the compare. The
/// complete change at the same head is still reviewable, so a caller may
/// recover by falling back to a full review instead of failing the run.
#[derive(Debug)]
pub struct IncrementalDiffUnavailable;

impl std::fmt::Display for IncrementalDiffUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("incremental diff is unavailable for this baseline")
    }
}

impl std::error::Error for IncrementalDiffUnavailable {}

pub fn incremental_diff_unavailable(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(IncrementalDiffUnavailable).context(message.into())
}

pub fn is_incremental_diff_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<IncrementalDiffUnavailable>().is_some())
}

#[derive(Debug)]
pub struct RepositoryIdentityFailure(pub String);

impl std::fmt::Display for RepositoryIdentityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RepositoryIdentityFailure {}

pub fn repository_identity_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RepositoryIdentityFailure(message.into()))
}

pub fn is_repository_identity_failure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RepositoryIdentityFailure>().is_some())
}

pub fn service_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ForgeServiceFailure(message.into()))
}

pub fn http_failure(status: reqwest::StatusCode, message: impl Into<String>) -> anyhow::Error {
    let message = message.into();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        service_failure(message)
    } else {
        anyhow::anyhow!(message)
    }
}

pub fn classify_review_input_error(error: anyhow::Error) -> anyhow::Error {
    let service_failure = error.chain().any(|cause| {
        cause.downcast_ref::<ForgeServiceFailure>().is_some()
            || cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_connect() || error.is_timeout())
    });
    if service_failure {
        error
    } else {
        error.context(IncompleteReviewInput)
    }
}

pub fn is_incomplete_review_input(error: &anyhow::Error) -> bool {
    error.downcast_ref::<IncompleteReviewInput>().is_some()
        || error
            .chain()
            .any(|cause| cause.downcast_ref::<IncompleteReviewInput>().is_some())
}

pub fn valid_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

pub async fn bounded_response_text(
    mut response: reqwest::Response,
    context: &str,
) -> Result<String> {
    bounded_response_text_with_limit(
        &mut response,
        context,
        crate::diff::MAX_FORGE_RESPONSE_BYTES,
    )
    .await
}

pub async fn bounded_response_text_with_limit(
    response: &mut reqwest::Response,
    context: &str,
    limit: usize,
) -> Result<String> {
    ensure!(
        response.status() != reqwest::StatusCode::PARTIAL_CONTENT,
        "{context} returned partial content"
    );
    for header in ["x-diff-truncated", "x-content-truncated", "x-truncated"] {
        if response
            .headers()
            .get(header)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
        {
            return Err(anyhow::anyhow!("{context} reported truncated content"));
        }
    }
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit as u64,
            "{context} exceeds the {} byte acquisition limit",
            limit
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading {context}"))?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "{context} exceeds the {} byte acquisition limit",
            limit
        );
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).with_context(|| format!("{context} is not valid UTF-8"))
}

pub async fn bounded_response_bytes_with_limit(
    response: &mut reqwest::Response,
    context: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    ensure!(
        response.status() != reqwest::StatusCode::PARTIAL_CONTENT,
        "{context} returned partial content"
    );
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit as u64,
            "{context} exceeds the {limit} byte limit"
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading {context}"))?
    {
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("{context} byte count overflowed"))?;
        ensure!(next <= limit, "{context} exceeds the {limit} byte limit");
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Stream a complete UTF-8 forge response to a file-backed immutable snapshot.
/// This is used for individual source files whose size is not a review-scope
/// decision. Transport truncation remains fatal, while heap use stays bounded
/// by the response chunk size.
pub async fn response_snapshot(response: reqwest::Response, context: &str) -> Result<DiffSnapshot> {
    response_snapshot_in(response, context, crate::diff::WorkspaceBudget::new(), None).await
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceExpectation {
    pub size: Option<u64>,
    pub sha256: Option<String>,
}

pub async fn response_snapshot_in(
    mut response: reqwest::Response,
    context: &str,
    workspace: crate::diff::WorkspaceBudget,
    authoritative: Option<SourceExpectation>,
) -> Result<DiffSnapshot> {
    ensure!(
        response.status() != reqwest::StatusCode::PARTIAL_CONTENT,
        "{context} returned partial content"
    );
    for header in ["x-diff-truncated", "x-content-truncated", "x-truncated"] {
        if response
            .headers()
            .get(header)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
        {
            return Err(anyhow::anyhow!("{context} reported truncated content"));
        }
    }
    let declared_size = response.content_length();
    if let (Some(declared), Some(expected)) = (
        declared_size,
        authoritative.as_ref().and_then(|value| value.size),
    ) {
        ensure!(
            declared == expected,
            "{context} declared {declared} bytes but forge metadata requires {expected}"
        );
    }
    let mut spool = crate::diff::DiffSpool::new_in(workspace)?;
    let mut received = 0u64;
    let mut digest = authoritative
        .as_ref()
        .and_then(|value| value.sha256.as_ref())
        .map(|_| Sha256::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading {context}"))?
    {
        received = received
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("{context} byte count overflowed"))?;
        if let Some(digest) = &mut digest {
            digest.update(&chunk);
        }
        spool
            .write_all(&chunk)
            .with_context(|| format!("spooling {context}"))?;
    }
    if let Some(declared) = declared_size {
        ensure!(
            received == declared,
            "{context} ended after {received} of {declared} declared bytes"
        );
    }
    if let Some(expected) = authoritative.as_ref().and_then(|value| value.size) {
        ensure!(
            received == expected,
            "{context} ended after {received} bytes but forge metadata requires {expected}"
        );
    }
    if let (Some(expected), Some(actual)) = (
        authoritative
            .as_ref()
            .and_then(|value| value.sha256.as_ref()),
        digest.map(|value| {
            value
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        }),
    ) {
        ensure!(
            expected.eq_ignore_ascii_case(&actual),
            "{context} content hash does not match forge metadata"
        );
    }
    spool.finish_source()
}

pub async fn bounded_response_json<T: DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T> {
    let text = bounded_response_text(response, context).await?;
    serde_json::from_str(&text).with_context(|| format!("decoding {context}"))
}

/// Stable, non-reversible diagnostic for an opaque provider request id.
pub fn opaque_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

pub fn response_request_id(response: &reqwest::Response) -> Option<String> {
    ["x-request-id", "x-github-request-id", "x-trace-id"]
        .iter()
        .find_map(|name| response.headers().get(*name))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(opaque_id)
}

/// Base URL for the brand status icons rendered in PR comments and check
/// summaries. The four icons (error, warn, info, pass) are served by the
/// marketing site and mirror the product-page statusline.
pub const STATUS_ICON_BASE: &str = "https://postil.dev/status";

/// Markdown `<img>` for a named status icon, sized to sit inline with text.
pub fn icon_md(name: &str) -> String {
    format!(
        "<img src=\"{STATUS_ICON_BASE}/{name}.svg\" width=\"14\" height=\"14\" \
         alt=\"{name}\" align=\"text-bottom\">"
    )
}

pub fn severity_icon(severity: Severity) -> String {
    icon_md(match severity {
        Severity::Error => "error",
        Severity::Warn => "warn",
        Severity::Info => "info",
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrMeta {
    pub title: String,
    pub body: String,
    pub head_sha: String,
    /// Exact merge base selected for this review snapshot. This is never the
    /// moving target-branch tip when the forge exposes a distinct merge base.
    pub base_sha: String,
    /// Target branch commit observed with this snapshot. This is distinct from
    /// `base_sha`, which is the merge base used to construct the review diff.
    pub target_sha: Option<String>,
    /// Authoritative changed-file count when the forge exposes one cheaply.
    /// It is used only to size a bounded acquisition deadline.
    pub changed_files: Option<usize>,
}

/// Check conclusions, mapped per-forge. Postil semantics:
/// - advisory check (`postil/review`): success unless the run itself failed.
/// - gate check (`postil/gate`): failure iff gate-level findings exist (or the
///   run failed, so fail closed). Never `neutral` for the gate: a grey square
///   that reads as "didn't fail" is the GitHub Copilot mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Success,
    Failure,
    /// Operational error on the advisory check only.
    Neutral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckRunIds<'a> {
    pub advisory: &'a str,
    pub gate: &'a str,
}

/// What a `respond` thread number points at. GitHub's issues API covers both,
/// so it ignores this; GitLab/Bitbucket/Azure key issues and PRs on different
/// endpoints, so they branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadKind {
    /// A pull request / merge request.
    Pull,
    /// An issue / work item on the forge's issue tracker.
    Issue,
}

/// Versioned result of one review publication attempt. Finding outcomes are
/// keyed by the envelope's stable finding ID so the hosted service can join
/// the immutable delivery result to later thread lifecycle observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReviewPublicationChannel {
    ReviewComments,
    CheckAnnotations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewPublicationReceipt {
    pub version: u8,
    pub channel: ReviewPublicationChannel,
    pub receipt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
    pub findings: Vec<FindingPublicationReceipt>,
}

impl ReviewPublicationReceipt {
    pub const VERSION: u8 = 2;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingPublicationReceipt {
    pub finding_id: String,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub stable_identity: bool,
    pub initial_outcome: FindingPublicationOutcome,
    #[serde(default, skip_serializing_if = "is_false")]
    pub inline_rejected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_id: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingPublicationOutcome {
    Inline,
    CheckAnnotation,
    SummaryOnly,
    Carried,
    Resolved,
    Suppressed,
    /// Delivery succeeded, but the forge response could not establish the
    /// per-finding publication channel.
    Unknown,
    /// The finding was published as a review comment attached to the changed
    /// file rather than to one line in that file.
    FileComment,
}

/// Immutable desired GitHub state emitted for the service-owned publication
/// controller. The digest covers the complete canonical intent except for the
/// digest field itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitHubPublicationPlan {
    pub version: u8,
    pub forge: String,
    pub controller_generation: String,
    pub input_identity: String,
    pub review_output_digest: String,
    pub repository: PublicationPlanRepository,
    pub pull_request_number: String,
    pub reviewed_snapshot: PublicationPlanSnapshot,
    pub lifecycle_receipt: PublicationPlanLifecycleReceipt,
    pub operation_count: u32,
    pub operation_manifest_digest: String,
    pub operations: Vec<PublicationPlanOperation>,
    pub gate_analysis: PublicationPlanGateAnalysis,
    pub intent_digest: String,
}

pub struct GitHubPublicationPlanRequest<'a> {
    pub controller_generation: &'a str,
    pub input_identity: &'a str,
    pub envelope: &'a Envelope,
    pub snapshot: &'a PrMeta,
    pub publication_diff: Option<&'a crate::diff::Diff>,
    pub should_comment: bool,
    pub duplicate_of_baseline: bool,
    pub annotate_findings: bool,
    pub advisory: CheckState,
    pub gate: CheckState,
}

pub(crate) struct GitHubPublicationPlanIdentity {
    pub controller_generation: String,
    pub input_identity: String,
    pub review_output_digest: String,
    pub repository: PublicationPlanRepository,
    pub pull_request_number: String,
    pub reviewed_snapshot: PublicationPlanSnapshot,
}

impl GitHubPublicationPlan {
    pub const VERSION: u8 = 1;
    pub const MAX_OPERATIONS: usize = 126;
    pub const MAX_DEPENDENCY_EDGES: usize = 1_024;

    pub(crate) fn new(
        identity: GitHubPublicationPlanIdentity,
        lifecycle_receipt: PublicationPlanLifecycleReceipt,
        operations: Vec<PublicationPlanOperation>,
        gate_analysis: PublicationPlanGateAnalysis,
    ) -> Result<Self> {
        let GitHubPublicationPlanIdentity {
            controller_generation,
            input_identity,
            review_output_digest,
            repository,
            pull_request_number,
            reviewed_snapshot,
        } = identity;
        ensure_publication_decimal_identifier("repository id", &repository.id)?;
        ensure_publication_decimal_identifier("pull request number", &pull_request_number)?;
        ensure_publication_decimal_identifier("controller generation", &controller_generation)?;
        ensure_publication_sha256_identity("input identity", &input_identity)?;
        ensure_publication_sha256_identity("review output digest", &review_output_digest)?;
        ensure!(
            operations.len() <= Self::MAX_OPERATIONS,
            "publication-plan operation count must not exceed {}",
            Self::MAX_OPERATIONS
        );
        let dependency_edge_count = operations.iter().try_fold(0usize, |count, operation| {
            count
                .checked_add(operation.dependencies.len())
                .context("publication-plan dependency edge count overflowed")
        })?;
        ensure!(
            dependency_edge_count <= Self::MAX_DEPENDENCY_EDGES,
            "publication-plan dependency edge count must not exceed {}",
            Self::MAX_DEPENDENCY_EDGES
        );
        ensure!(
            lifecycle_receipt.input_identity == input_identity,
            "publication-plan lifecycle receipt input identity must match the plan input identity"
        );
        ensure!(
            lifecycle_receipt.recompute_digest()? == lifecycle_receipt.digest,
            "publication-plan lifecycle receipt digest does not match its canonical content"
        );
        for operation in &operations {
            ensure!(
                publication_plan_desired_digest(&operation.desired)? == operation.desired_digest,
                "publication-plan operation {} desired digest does not match its canonical payload",
                operation.operation_key
            );
        }
        validate_publication_operation_graph(&operations)?;
        let operation_count = u32::try_from(operations.len())
            .context("publication-plan operation count exceeds the contract limit")?;
        let operation_manifest_digest = operation_manifest_digest(&operations)?;
        let mut plan = Self {
            version: Self::VERSION,
            forge: "github".to_string(),
            controller_generation,
            input_identity,
            review_output_digest,
            repository,
            pull_request_number,
            reviewed_snapshot,
            lifecycle_receipt,
            operation_count,
            operation_manifest_digest,
            operations,
            gate_analysis,
            intent_digest: String::new(),
        };
        plan.intent_digest = plan.canonical_intent_digest()?;
        Ok(plan)
    }

    fn canonical_intent_digest(&self) -> Result<String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CanonicalIntent<'a> {
            version: u8,
            forge: &'a str,
            controller_generation: &'a str,
            input_identity: &'a str,
            review_output_digest: &'a str,
            repository: &'a PublicationPlanRepository,
            pull_request_number: &'a str,
            reviewed_snapshot: &'a PublicationPlanSnapshot,
            lifecycle_receipt: &'a PublicationPlanLifecycleReceipt,
            operation_count: u32,
            operation_manifest_digest: &'a str,
            operations: &'a [PublicationPlanOperation],
            gate_analysis: &'a PublicationPlanGateAnalysis,
        }

        let canonical = serde_json::to_vec(&CanonicalIntent {
            version: self.version,
            forge: &self.forge,
            controller_generation: &self.controller_generation,
            input_identity: &self.input_identity,
            review_output_digest: &self.review_output_digest,
            repository: &self.repository,
            pull_request_number: &self.pull_request_number,
            reviewed_snapshot: &self.reviewed_snapshot,
            lifecycle_receipt: &self.lifecycle_receipt,
            operation_count: self.operation_count,
            operation_manifest_digest: &self.operation_manifest_digest,
            operations: &self.operations,
            gate_analysis: &self.gate_analysis,
        })
        .context("serializing canonical GitHub publication intent")?;
        Ok(format!(
            "sha256:{}",
            crate::repository_search::hex_digest(Sha256::digest(canonical))
        ))
    }

    pub fn recompute_intent_digest(&self) -> Result<String> {
        self.canonical_intent_digest()
    }

    pub fn recompute_operation_manifest_digest(&self) -> Result<String> {
        operation_manifest_digest(&self.operations)
    }
}

fn operation_manifest_digest(operations: &[PublicationPlanOperation]) -> Result<String> {
    let canonical = serde_json::to_vec(operations)
        .context("serializing canonical GitHub publication operation manifest")?;
    Ok(format!(
        "sha256:{}",
        crate::repository_search::hex_digest(Sha256::digest(canonical))
    ))
}

fn validate_publication_operation_graph(operations: &[PublicationPlanOperation]) -> Result<()> {
    let mut ordinals_by_key = std::collections::HashMap::with_capacity(operations.len());
    for (index, operation) in operations.iter().enumerate() {
        ensure!(
            operation.ordinal as usize == index + 1,
            "publication-plan operation ordinals must be contiguous and one-based"
        );
        ensure!(
            !operation.operation_key.is_empty(),
            "publication-plan operation keys must not be empty"
        );
        ensure!(
            ordinals_by_key
                .insert(operation.operation_key.as_str(), operation.ordinal)
                .is_none(),
            "publication-plan operation keys must be unique"
        );
    }

    for operation in operations {
        let mut declared_dependencies = std::collections::HashSet::new();
        for dependency in &operation.dependencies {
            ensure!(
                declared_dependencies.insert(dependency.as_str()),
                "publication-plan operation dependencies must be unique"
            );
            let dependency_ordinal =
                ordinals_by_key.get(dependency.as_str()).with_context(|| {
                    format!(
                        "publication-plan operation {} depends on missing operation {dependency}",
                        operation.operation_key
                    )
                })?;
            ensure!(
                *dependency_ordinal < operation.ordinal,
                "publication-plan operation {} has a forward, self, or cyclic dependency on {dependency}",
                operation.operation_key
            );
        }
        ensure!(
            !operation.activation.any_of.is_empty(),
            "publication-plan operations require at least one activation condition"
        );
        for condition in &operation.activation.any_of {
            let referenced_keys: &[String] = match condition {
                PublicationPlanActivationCondition::SemanticPlacementRejected {
                    dependency_operation_key,
                    ..
                }
                | PublicationPlanActivationCondition::PartialReviewObserved {
                    dependency_operation_key,
                    ..
                } => std::slice::from_ref(dependency_operation_key),
                PublicationPlanActivationCondition::ReviewSelectionTerminal {
                    selected_review_operation_keys,
                } => selected_review_operation_keys,
                PublicationPlanActivationCondition::Always
                | PublicationPlanActivationCondition::MarkerAbsent { .. }
                | PublicationPlanActivationCondition::FindingContentDiffers { .. } => &[],
            };
            for referenced_key in referenced_keys {
                ensure!(
                    declared_dependencies.contains(referenced_key.as_str()),
                    "publication-plan activation for {} references undeclared dependency {referenced_key}",
                    operation.operation_key
                );
            }
        }
        match &operation.desired {
            PublicationPlanOperationKind::AdvisoryCheckComplete { created_check, .. } => {
                ensure!(
                    declared_dependencies.contains(created_check.dependency_operation_key.as_str()),
                    "publication-plan advisory completion references undeclared create dependency {}",
                    created_check.dependency_operation_key
                );
            }
            PublicationPlanOperationKind::ReviewSummaryUpdate {
                terminal_operations,
                cases,
                ..
            } => {
                for terminal in terminal_operations {
                    ensure!(
                        declared_dependencies.contains(terminal.operation_key.as_str()),
                        "publication-plan review summary references undeclared terminal dependency {}",
                        terminal.operation_key
                    );
                }
                for case in cases {
                    ensure!(
                        declared_dependencies.contains(case.selected_review_operation_key.as_str()),
                        "publication-plan review summary references undeclared selected review dependency {}",
                        case.selected_review_operation_key
                    );
                }
            }
            PublicationPlanOperationKind::ReviewCreate { .. }
            | PublicationPlanOperationKind::FileCommentFallback { .. }
            | PublicationPlanOperationKind::FindingCommentUpdate { .. }
            | PublicationPlanOperationKind::AdvisoryCheckCreate { .. } => {}
        }
    }
    Ok(())
}

pub(crate) fn ensure_publication_decimal_identifier(name: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value != "0"
            && !value.starts_with('0')
            && value.parse::<i64>().is_ok(),
        "publication-plan {name} must be a positive canonical decimal string within signed 64-bit storage"
    );
    Ok(())
}

pub(crate) fn ensure_publication_sha256_identity(name: &str, value: &str) -> Result<()> {
    ensure!(
        value.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "publication-plan {name} must be sha256: followed by 64 lowercase hexadecimal characters"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanRepository {
    pub id: String,
    pub full_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanSnapshot {
    pub head_sha: String,
    pub merge_base_sha: String,
    pub target_sha: String,
    pub pull_request_title_sha256: String,
    pub pull_request_body_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanOperation {
    pub ordinal: u32,
    pub operation_key: String,
    pub dependencies: Vec<String>,
    pub activation: PublicationPlanOperationActivation,
    pub reconciliation: PublicationPlanOperationReconciliation,
    pub desired_digest: String,
    #[serde(flatten)]
    pub desired: PublicationPlanOperationKind,
}

impl PublicationPlanOperation {
    pub(crate) fn new(
        ordinal: u32,
        operation_key: String,
        dependencies: Vec<String>,
        activation: PublicationPlanOperationActivation,
        reconciliation: PublicationPlanOperationReconciliation,
        desired: PublicationPlanOperationKind,
    ) -> Result<Self> {
        if let Some(observed_remote_id) = reconciliation.observed_remote_id.as_deref() {
            ensure_publication_decimal_identifier("observed remote id", observed_remote_id)?;
        }
        if let PublicationPlanOperationKind::FindingCommentUpdate {
            observed_comment_id,
            ..
        } = &desired
        {
            ensure_publication_decimal_identifier("observed comment id", observed_comment_id)?;
        }
        let desired_digest = publication_plan_desired_digest(&desired)?;
        Ok(Self {
            ordinal,
            operation_key,
            dependencies,
            activation,
            reconciliation,
            desired_digest,
            desired,
        })
    }
}

fn publication_plan_desired_digest(desired: &PublicationPlanOperationKind) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        crate::repository_search::hex_digest(Sha256::digest(serde_json::to_vec(desired)?))
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PublicationPlanOperationKind {
    ReviewCreate {
        attempt: PublicationPlanReviewAttemptKind,
        logical_review_identity: String,
        payload: PublicationPlanReviewCreatePayload,
    },
    FileCommentFallback {
        finding_id: String,
        payload: PublicationPlanFileComment,
    },
    FindingCommentUpdate {
        finding_id: String,
        observed_comment_id: String,
        expected_markers: Vec<String>,
        body: String,
        body_sha256: String,
    },
    ReviewSummaryUpdate {
        logical_review_identity: String,
        terminal_operations: Vec<PublicationPlanTerminalOperation>,
        cases: Vec<PublicationPlanReviewSummaryCase>,
    },
    AdvisoryCheckCreate {
        name: String,
        head_sha: String,
        status: PublicationPlanCheckStatus,
        external_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details_url: Option<String>,
    },
    AdvisoryCheckComplete {
        name: String,
        head_sha: String,
        created_check: PublicationPlanOperationResultReference,
        conclusion: PublicationPlanCheckConclusion,
        title: String,
        summary: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        annotations: Vec<PublicationPlanCheckAnnotation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        details_url: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanOperationResultReference {
    pub dependency_operation_key: String,
    pub result_field: PublicationPlanOperationResultField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanOperationResultField {
    RemoteId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationPlanCheckStatus {
    InProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationPlanCheckConclusion {
    Success,
    Failure,
    Neutral,
}

impl From<CheckState> for PublicationPlanCheckConclusion {
    fn from(state: CheckState) -> Self {
        match state {
            CheckState::Success => Self::Success,
            CheckState::Failure => Self::Failure,
            CheckState::Neutral => Self::Neutral,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanGateAnalysis {
    pub ownership: PublicationPlanGateOwnership,
    pub authoritative: bool,
    pub organization_gate_mode_required: bool,
    pub name: String,
    pub head_sha: String,
    pub analyzed_conclusion: PublicationPlanCheckConclusion,
    pub title: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanGateOwnership {
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanReviewCreatePayload {
    pub commit_id: String,
    pub event: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<PublicationPlanReviewComment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanReviewSummaryCase {
    pub selected_review_operation_key: String,
    pub selected_review_outcomes: Vec<PublicationPlanReviewCreateOutcome>,
    pub file_comment_count: u32,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanReviewCreateOutcome {
    Created,
    ReconciledExisting,
    PartialObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanReviewAttemptKind {
    Initial,
    RelocatedInline,
    SummaryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanTerminalOutcome {
    Applied,
    ReconciledExisting,
    NotRequiredMarkerPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanTerminalOperation {
    pub operation_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub requires_remote_id: bool,
    pub accepted_outcomes: Vec<PublicationPlanTerminalOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanOperationActivation {
    pub any_of: Vec<PublicationPlanActivationCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "condition",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PublicationPlanActivationCondition {
    Always,
    MarkerAbsent {
        guard: PublicationPlanMarkerAbsenceGuard,
    },
    SemanticPlacementRejected {
        dependency_operation_key: String,
        http_status: u16,
        classification: PublicationPlanPlacementClassification,
        marker_absence: PublicationPlanMarkerAbsenceGuard,
    },
    PartialReviewObserved {
        dependency_operation_key: String,
        review_markers: Vec<String>,
        finding_marker_absence: PublicationPlanMarkerAbsenceGuard,
    },
    FindingContentDiffers {
        observed_comment_id: String,
        expected_markers: Vec<String>,
    },
    ReviewSelectionTerminal {
        selected_review_operation_keys: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanOperationReconciliation {
    pub logical_identity: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_remote_id: Option<String>,
    pub exclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanReviewComment {
    pub path: String,
    pub line: u32,
    pub side: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_side: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanFileComment {
    pub body: String,
    pub commit_id: String,
    pub path: String,
    pub subject_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanFinding {
    pub finding_id: String,
    pub stable_identity: bool,
    pub path: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub initial_outcome: FindingPublicationOutcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_intent: Vec<PublicationPlanFindingFallback>,
    pub content_digest: String,
    pub marker: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compatible_markers: Vec<String>,
    pub desired_body: String,
    pub desired_body_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_comment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_body_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_outcome: Option<FindingPublicationOutcome>,
    pub reconciliation: PublicationPlanFindingReconciliation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<SuppressionReason>,
    pub duplicate_provenance: PublicationPlanDuplicateProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanFindingFallback {
    RelocatedInline,
    FileComment,
    SummaryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanFindingReconciliation {
    Create,
    Retain,
    Replace,
    Omit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanDuplicateProvenance {
    None,
    Baseline,
    SuppressedRootCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationPlanPlacementClassification {
    InvalidReviewCommentPlacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanMarkerAbsenceGuard {
    pub markers: Vec<String>,
    pub head_sha: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanLifecycleReceipt {
    pub version: u8,
    pub input_identity: String,
    pub channel: ReviewPublicationChannel,
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compatible_receipt_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_review_id: Option<String>,
    pub duplicate_of_baseline: bool,
    pub findings: Vec<PublicationPlanFinding>,
    pub digest: String,
}

impl PublicationPlanLifecycleReceipt {
    pub const VERSION: u8 = 1;

    pub(crate) fn new(
        input_identity: String,
        channel: ReviewPublicationChannel,
        receipt_id: String,
        mut compatible_receipt_ids: Vec<String>,
        observed_review_id: Option<String>,
        duplicate_of_baseline: bool,
        mut findings: Vec<PublicationPlanFinding>,
    ) -> Result<Self> {
        ensure_publication_sha256_identity("lifecycle input identity", &input_identity)?;
        if let Some(observed_review_id) = observed_review_id.as_deref() {
            ensure_publication_decimal_identifier("observed review id", observed_review_id)?;
        }
        for finding in &findings {
            if let Some(observed_comment_id) = finding.observed_comment_id.as_deref() {
                ensure_publication_decimal_identifier("observed comment id", observed_comment_id)?;
            }
        }
        compatible_receipt_ids.sort();
        compatible_receipt_ids.dedup();
        findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        let mut receipt = Self {
            version: Self::VERSION,
            input_identity,
            channel,
            receipt_id,
            compatible_receipt_ids,
            observed_review_id,
            duplicate_of_baseline,
            findings,
            digest: String::new(),
        };
        receipt.digest = receipt.recompute_digest()?;
        Ok(receipt)
    }

    pub fn recompute_digest(&self) -> Result<String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CanonicalLifecycleReceipt<'a> {
            version: u8,
            input_identity: &'a str,
            channel: ReviewPublicationChannel,
            receipt_id: &'a str,
            compatible_receipt_ids: &'a [String],
            observed_review_id: &'a Option<String>,
            duplicate_of_baseline: bool,
            findings: &'a [PublicationPlanFinding],
        }
        let canonical = serde_json::to_vec(&CanonicalLifecycleReceipt {
            version: self.version,
            input_identity: &self.input_identity,
            channel: self.channel,
            receipt_id: &self.receipt_id,
            compatible_receipt_ids: &self.compatible_receipt_ids,
            observed_review_id: &self.observed_review_id,
            duplicate_of_baseline: self.duplicate_of_baseline,
            findings: &self.findings,
        })?;
        Ok(format!(
            "sha256:{}",
            crate::repository_search::hex_digest(Sha256::digest(canonical))
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPlanCheckAnnotation {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub annotation_level: String,
    pub title: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReviewPublicationSummary {
    pub active_inline: usize,
    pub file_comments: usize,
    pub summary_only: usize,
    pub rejected_inline: usize,
    pub carried: usize,
}

pub fn untracked_review_publication_receipt(
    forge: &str,
    envelope: &Envelope,
    head_sha: &str,
) -> ReviewPublicationReceipt {
    let mut findings = Vec::new();
    for finding in envelope
        .findings
        .iter()
        .chain(envelope.resolved.iter())
        .chain(
            envelope
                .suppressed_findings
                .iter()
                .map(|suppressed| &suppressed.finding),
        )
    {
        let (finding_id, stable_identity) = if let Some(id) = finding.id.as_deref() {
            (id.to_string(), true)
        } else {
            let mut digest = Sha256::new();
            digest.update(finding.path.as_bytes());
            digest.update(finding.line.to_be_bytes());
            digest.update(finding.title.as_bytes());
            (
                format!(
                    "legacy-v2:{}",
                    crate::repository_search::hex_digest(digest.finalize())
                ),
                false,
            )
        };
        findings.push(FindingPublicationReceipt {
            finding_id,
            stable_identity,
            initial_outcome: FindingPublicationOutcome::Unknown,
            inline_rejected: false,
            comment_id: None,
        });
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let mut digest = Sha256::new();
    digest.update(b"review-receipt-v2\0");
    digest.update(forge.as_bytes());
    digest.update(head_sha.as_bytes());
    for finding in &findings {
        digest.update(finding.finding_id.as_bytes());
    }
    ReviewPublicationReceipt {
        version: ReviewPublicationReceipt::VERSION,
        channel: ReviewPublicationChannel::ReviewComments,
        receipt_id: format!(
            "{forge}-review-v2:{}",
            crate::repository_search::hex_digest(digest.finalize())
        ),
        review_id: None,
        findings,
    }
}

pub(crate) fn publication_finding_sort_key(finding: &Finding) -> String {
    finding.id.clone().unwrap_or_else(|| {
        format!(
            "{}\0{:010}\0{:010}\0{}\0{}",
            finding.path,
            finding.line,
            finding.end_line.unwrap_or(finding.line),
            finding.kind.as_str(),
            finding.title,
        )
    })
}

pub fn write_review_publication_receipt_from_env(receipt: &ReviewPublicationReceipt) -> Result<()> {
    let Some(path) = std::env::var_os(PUBLICATION_RECEIPT_PATH_ENV) else {
        return Ok(());
    };
    ensure!(
        !path.is_empty(),
        "{PUBLICATION_RECEIPT_PATH_ENV} must not be empty"
    );
    write_review_publication_receipt(Path::new(&path), receipt)
}

fn write_review_publication_receipt(path: &Path, receipt: &ReviewPublicationReceipt) -> Result<()> {
    write_private_json_atomically(path, receipt, "publication receipt")
}

pub fn write_github_publication_plan(path: &Path, plan: &GitHubPublicationPlan) -> Result<()> {
    write_private_json_atomically(path, plan, "GitHub publication plan")
}

pub(crate) fn write_github_publication_plan_to_writer(
    mut writer: impl Write,
    plan: &GitHubPublicationPlan,
) -> Result<()> {
    let bytes = serialize_json_artifact(plan, "GitHub publication plan")?;
    writer
        .write_all(&bytes)
        .context("writing GitHub publication plan")?;
    writer.flush().context("flushing GitHub publication plan")
}

fn write_private_json_atomically<T: Serialize>(
    path: &Path,
    value: &T,
    artifact: &str,
) -> Result<()> {
    let bytes = serialize_json_artifact(value, artifact)?;
    write_private_bytes_atomically(path, &bytes, artifact)
}

fn serialize_json_artifact<T: Serialize>(value: &T, artifact: &str) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).with_context(|| format!("serializing {artifact}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_private_bytes_atomically(path: &Path, bytes: &[u8], artifact: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{artifact} path must name a file"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    ensure!(parent.is_dir(), "{artifact} directory does not exist");
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "{artifact} path must not be a symlink"
        );
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{artifact} path must name a file"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("creating private {artifact}"))?;
        file.write_all(bytes)
            .with_context(|| format!("writing {artifact}"))?;
        file.sync_all()
            .with_context(|| format!("syncing {artifact}"))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("atomically publishing {artifact}"))?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("syncing {artifact} directory"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[allow(async_fn_in_trait)]
pub trait Forge {
    /// True when the forge renders inline HTML `<img>` in markdown comments
    /// (GitHub, GitLab). Forges that show raw HTML get text-only statuslines.
    fn rich_markdown(&self) -> bool {
        false
    }
    /// Compose the top-level review body. Forges can add validated links to the
    /// otherwise forge-neutral envelope metadata.
    fn review_summary(&self, envelope: &Envelope) -> String {
        check_summary(envelope, self.rich_markdown(), SummaryContext::from_env())
    }
    fn plan_review_publication(
        &self,
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> ReviewPublicationReceipt {
        untracked_review_publication_receipt("forge", envelope, &snapshot.head_sha)
    }
    async fn build_publication_plan(
        &self,
        _request: GitHubPublicationPlanRequest<'_>,
    ) -> Result<GitHubPublicationPlan> {
        anyhow::bail!("publication planning is not supported for this forge")
    }
    async fn fetch_pr_meta(&self) -> Result<PrMeta>;
    /// Unified diff of the immutable snapshot returned by `fetch_pr_meta`.
    /// Implementations must not re-read a moving PR head or target tip.
    async fn fetch_diff(&self, snapshot: &PrMeta) -> Result<DiffSnapshot>;
    /// Unified diff covering `since_sha..head_sha` only (incremental reviews).
    /// `head_sha` is the SHA the caller is reviewing, not whatever the PR's
    /// head happens to be at fetch time. A later push must not widen the diff.
    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<DiffSnapshot>;
    /// Post the batched review against the acquired snapshot. Implementations
    /// revalidate the snapshot immediately before writing to the forge.
    async fn post_review(
        &self,
        envelope: &Envelope,
        snapshot: &PrMeta,
        publication_diff: Option<&crate::diff::Diff>,
    ) -> Result<ReviewPublicationReceipt>;
    /// Ensure both check runs exist (in_progress); returns (advisory_id, gate_id).
    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)>;
    /// Complete the advisory check and, when supplied, the gate check only
    /// while the acquired snapshot remains current.
    async fn complete_checks(
        &self,
        check_ids: CheckRunIds<'_>,
        advisory: CheckState,
        gate: Option<CheckState>,
        envelope: &Envelope,
        snapshot: &PrMeta,
        annotate_findings: bool,
    ) -> Result<()>;

    /// Confirm that publication still targets the snapshot that was reviewed.
    /// The caller checks this before publishing either comments or conclusions.
    async fn snapshot_is_current(&self, expected: &PrMeta) -> Result<bool> {
        let current = self.fetch_pr_meta().await?;
        Ok(current.title == expected.title
            && current.body == expected.body
            && current.head_sha == expected.head_sha
            && current.base_sha == expected.base_sha
            && current.target_sha == expected.target_sha)
    }

    /// Title and body of the issue/PR/MR a maintainer mentioned Postil on, used
    /// to ground the answer (`postil respond`). `kind` disambiguates the number
    /// for forges whose issues and pulls live on different endpoints.
    async fn fetch_thread(&self, number: u64, kind: ThreadKind) -> Result<(String, String)>;

    /// Post a top-level comment (Postil's reply to a mention). `kind` selects the
    /// issue- vs pull-level endpoint where the forge separates them.
    async fn post_comment(&self, number: u64, kind: ThreadKind, body: &str) -> Result<()>;
}

/// GitHub rejects a check-run `output.summary` over 65535 chars and a `title`
/// over 255 with HTTP 422, which would abort posting both checks. These caps
/// keep composed strings safely under those limits. Shared so every forge that
/// PATCHes check output can apply the same bound.
pub const MAX_CHECK_SUMMARY: usize = 60_000;
pub const MAX_CHECK_TITLE: usize = 255;

/// Truncate `s` to at most `max` characters, appending an explicit marker when
/// anything is cut so the reader knows the output is not complete. The marker is
/// counted against the budget, so the result never exceeds `max` characters.
pub fn cap_text(s: &str, max: usize, marker: &str) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let budget = max.saturating_sub(marker.chars().count());
    let mut out: String = s.chars().take(budget).collect();
    out.push_str(marker);
    out
}

#[cfg(test)]
pub(crate) fn wrap_plain_text(text: &str, width: usize) -> String {
    if width == 0 {
        return text.to_string();
    }

    let mut wrapped = Vec::new();
    for line in text.split('\n') {
        wrap_plain_line(line, width, &mut wrapped);
    }
    wrapped.join("\n")
}

#[cfg(test)]
fn wrap_plain_line(mut line: &str, width: usize, wrapped: &mut Vec<String>) {
    if line.is_empty() {
        wrapped.push(String::new());
        return;
    }

    while line.chars().count() > width {
        let (break_at, split_on_space) = wrap_break(line, width);
        let chunk = &line[..break_at];
        wrapped.push(if split_on_space {
            chunk.trim_end_matches(' ').to_string()
        } else {
            chunk.to_string()
        });
        line = if split_on_space {
            line[break_at..].trim_start_matches(' ')
        } else {
            &line[break_at..]
        };

        if line.is_empty() {
            return;
        }
    }

    wrapped.push(line.to_string());
}

#[cfg(test)]
fn wrap_break(line: &str, width: usize) -> (usize, bool) {
    let mut hard_break = line.len();
    let mut last_space = None;
    // Only break on a space that follows a word: breaking inside leading
    // indentation would select an all-space chunk, which trims to an empty
    // line and drops the indentation from the remainder.
    let mut seen_word = false;

    for (column, (idx, ch)) in line.char_indices().enumerate() {
        if ch == ' ' {
            if seen_word {
                last_space = Some(idx);
            }
        } else {
            seen_word = true;
        }
        if column == width {
            hard_break = idx;
            break;
        }
    }

    if let Some(idx) = last_space {
        (idx, true)
    } else {
        (hard_break, false)
    }
}

/// Cap a check-run summary to a size GitHub accepts, with a truncation marker.
pub fn cap_check_summary(s: &str) -> String {
    cap_text(
        s,
        MAX_CHECK_SUMMARY,
        "\n\n[output truncated at the check-run size limit]",
    )
}

/// Cap a check-run title to a size GitHub accepts.
pub fn cap_check_title(s: &str) -> String {
    cap_text(s, MAX_CHECK_TITLE, "…")
}

/// True when a finding's path is a synthetic Postil anchor (e.g. the reserved
/// PR-description path or the fail-closed/provider markers) rather than a real
/// file line. These cannot be posted as inline code annotations or review
/// comments; they are surfaced in the check-run summary and PR comment body.
pub fn is_synthetic_path(path: &str) -> bool {
    crate::envelope::is_reserved_anchor(path)
}

pub fn is_operational_path(path: &str) -> bool {
    matches!(
        path,
        crate::envelope::OPERATIONAL_PATH | crate::envelope::PROVIDER_PATH
    )
}

pub fn only_operational_findings(findings: &[Finding]) -> bool {
    !findings.is_empty()
        && findings
            .iter()
            .all(|finding| is_operational_path(&finding.path))
}

pub fn valid_details_url(value: Option<String>) -> Option<String> {
    value.filter(|value| {
        reqwest::Url::parse(value)
            .map(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
            .unwrap_or(false)
    })
}

pub fn check_title(envelope: &Envelope) -> String {
    if envelope.silent {
        if envelope
            .review_coverage
            .as_ref()
            .is_some_and(|coverage| coverage.mode == crate::envelope::ReviewCoverageMode::Bounded)
        {
            "No findings in risk-selected changes".to_string()
        } else {
            "No merge-relevant findings".to_string()
        }
    } else {
        let c = &envelope.counts;
        format!("{} error, {} warn, {} info", c.error, c.warn, c.info)
    }
}

/// Truthful clean-result wording for review comments and check summaries.
/// Some silent runs intentionally make no model call.
pub fn clean_review_message(envelope: &Envelope) -> String {
    match envelope.model_used.as_str() {
        "none (disabled by config)" => "Review disabled by configuration.".to_string(),
        "none (empty diff)" => "No reviewable diff; no model call was made.".to_string(),
        _ if envelope.review_coverage.as_ref().is_some_and(|coverage| {
            coverage.mode == crate::envelope::ReviewCoverageMode::Bounded
        }) =>
        {
            "No issues were found in the risk-selected changes reviewed.".to_string()
        }
        _ => "Postil reviewed this change and found nothing that affects the merge decision."
            .to_string(),
    }
}

#[derive(Default)]
pub struct SummaryContext {
    pub details_url: Option<String>,
    pub prevention_hint: bool,
    pub prevention_commands: Vec<String>,
    pub publication: Option<ReviewPublicationSummary>,
}

impl SummaryContext {
    pub fn from_env() -> Self {
        Self {
            details_url: valid_details_url(std::env::var("POSTIL_DETAILS_URL").ok()),
            prevention_hint: std::env::var("POSTIL_PREVENTION_HINT").as_deref() == Ok("1"),
            prevention_commands: prevention_commands_from_env(),
            publication: None,
        }
    }
}

fn prevention_commands_from_env() -> Vec<String> {
    let Ok(raw) = std::env::var("POSTIL_PREVENTION_COMMANDS_JSON") else {
        return Vec::new();
    };
    parse_prevention_commands(&raw)
}

fn parse_prevention_commands(raw: &str) -> Vec<String> {
    if raw.len() > 4_096 {
        return Vec::new();
    }
    let Ok(commands) = serde_json::from_str::<Vec<String>>(raw) else {
        return Vec::new();
    };
    commands
        .into_iter()
        .take(5)
        .filter_map(|command| {
            let command = command.trim();
            (!command.is_empty()
                && command.chars().count() <= 200
                && !command.chars().any(|ch| ch.is_control() || ch == '`'))
            .then(|| command.to_string())
        })
        .collect()
}

fn summary_count(
    rich: bool,
    status: &str,
    count: usize,
    singular: &str,
    plural_label: &str,
) -> String {
    let label = plural(count, singular, plural_label);
    if rich {
        format!("{} **{count} {label}**", icon_md(status))
    } else {
        format!("{status}: **{count} {label}**")
    }
}

pub fn check_summary(envelope: &Envelope, rich: bool, context: SummaryContext) -> String {
    let mut s = String::new();
    let operational = only_operational_findings(&envelope.findings);
    let has_operational = envelope
        .findings
        .iter()
        .any(|finding| is_operational_path(&finding.path));

    if operational {
        if envelope.gate.failing {
            s.push_str(
                "Postil could not complete this review, so no review verdict exists. The merge check remains blocked.",
            );
        } else {
            s.push_str(
                "Postil could not complete this review, so no review verdict exists. This repository treats review outages as advisory.",
            );
        }
        s.push('\n');
    } else if envelope.silent {
        if envelope.resolved.is_empty() {
            s.push_str(&clean_review_message(envelope));
        } else {
            s.push_str(&summary_count(
                rich,
                "pass",
                envelope.resolved.len(),
                "resolved finding",
                "resolved findings",
            ));
        }
        s.push('\n');
    } else {
        let open_visible = envelope
            .findings
            .iter()
            .filter(|finding| !is_operational_path(&finding.path))
            .count();
        let open_blocking = envelope
            .findings
            .iter()
            .filter(|finding| !is_operational_path(&finding.path))
            .filter(|finding| {
                crate::envelope::finding_blocks_gate(
                    finding,
                    &envelope.gate.fail_on,
                    &envelope.gate.block_on_kinds,
                    false,
                )
            })
            .count();
        let open_advisory = open_visible.saturating_sub(open_blocking);
        let mut counts = Vec::new();
        if has_operational {
            counts.push(if rich {
                format!("{} **review incomplete**", icon_md("warn"))
            } else {
                "warn: **review incomplete**".to_string()
            });
        }
        if open_blocking > 0 {
            counts.push(summary_count(
                rich,
                "error",
                open_blocking,
                "blocking finding open",
                "blocking findings open",
            ));
        }
        if open_advisory > 0 {
            counts.push(summary_count(
                rich,
                "info",
                open_advisory,
                "advisory finding open",
                "advisory findings open",
            ));
        }
        if !envelope.resolved.is_empty() {
            counts.push(summary_count(
                rich,
                "pass",
                envelope.resolved.len(),
                "resolved finding",
                "resolved findings",
            ));
        }
        if !counts.is_empty() {
            s.push_str(&counts.join(" · "));
            s.push('\n');
        }

        if let Some(publication) = context.publication {
            let mut delivery = Vec::new();
            if publication.active_inline > 0 {
                delivery.push(format!(
                    "{} {} posted inline",
                    publication.active_inline,
                    plural(publication.active_inline, "finding", "findings"),
                ));
            }
            if publication.file_comments > 0 {
                delivery.push(format!(
                    "{} {} posted as file-level review {}",
                    publication.file_comments,
                    plural(publication.file_comments, "finding", "findings"),
                    plural(publication.file_comments, "comment", "comments"),
                ));
            }
            if publication.rejected_inline > 0 {
                if publication.summary_only > publication.rejected_inline {
                    if context.details_url.is_some() {
                        delivery.push(format!(
                            "{} {} in review details, including {} that could not be placed on the changed lines",
                            publication.summary_only,
                            plural(publication.summary_only, "finding", "findings"),
                            publication.rejected_inline,
                        ));
                    } else {
                        delivery.push(format!(
                            "{} {} were not posted inline, including {} that could not be placed on the changed lines",
                            publication.summary_only,
                            plural(publication.summary_only, "finding", "findings"),
                            publication.rejected_inline,
                        ));
                    }
                } else {
                    let details_direction = if context.details_url.is_some() {
                        "; see review details"
                    } else {
                        ""
                    };
                    delivery.push(format!(
                        "{} {} could not be placed on the changed lines{}",
                        publication.rejected_inline,
                        plural(publication.rejected_inline, "finding", "findings"),
                        details_direction,
                    ));
                }
            } else if publication.summary_only > 0 {
                delivery.push(format!(
                    "{} {} in review details",
                    publication.summary_only,
                    plural(publication.summary_only, "finding", "findings"),
                ));
            }
            if !delivery.is_empty() {
                s.push_str(&delivery.join(" · "));
                s.push('\n');
            }
        }
    }

    // PR-level policy findings use a synthetic anchor because no changed file
    // line exists for an inline comment. Unlike operational sentinels, these
    // are actionable review results, so keep their bounded detail visible in
    // the review summary instead of reducing them to a count and dashboard
    // link.
    let mut synthetic_findings: Vec<_> = envelope
        .findings
        .iter()
        .filter(|finding| is_synthetic_path(&finding.path))
        .filter(|finding| !is_operational_path(&finding.path))
        .filter(|finding| !crate::filter::is_carried(finding))
        .collect();
    synthetic_findings.sort_by_key(|finding| publication_finding_sort_key(finding));
    synthetic_findings.truncate(3);
    if !synthetic_findings.is_empty() {
        s.push('\n');
        for finding in &synthetic_findings {
            let publication = crate::envelope::forge_safe_finding_publication_text(finding);
            let location = if finding.path == crate::envelope::PR_DESCRIPTION_PATH {
                "pull request description".to_string()
            } else {
                format!("`{}`", safe_code_text(&finding.path))
            };
            s.push_str(&format!(
                "- **{}** in {}: {}\n",
                publication.title, location, publication.body,
            ));
        }
        let undisclosed = envelope
            .findings
            .iter()
            .filter(|finding| is_synthetic_path(&finding.path))
            .filter(|finding| !is_operational_path(&finding.path))
            .filter(|finding| !crate::filter::is_carried(finding))
            .count()
            .saturating_sub(synthetic_findings.len());
        if undisclosed > 0 {
            s.push_str(&format!(
                "- {} more PR-level {} in the review details.\n",
                undisclosed,
                plural(undisclosed, "finding is", "findings are"),
            ));
        }
    }
    let mut eligible: Vec<_> = envelope
        .suppressed_findings
        .iter()
        .filter(|suppressed| {
            !matches!(
                suppressed.reason,
                SuppressionReason::Ignored | SuppressionReason::RepositoryClaimUnsupported
            ) && !crate::envelope::is_ephemeral_anchor(&suppressed.finding.path)
        })
        .collect();
    eligible.sort_by_key(|suppressed| publication_finding_sort_key(&suppressed.finding));
    let disclosed: Vec<_> = eligible.iter().take(5).copied().collect();
    if !disclosed.is_empty() {
        if rich {
            s.push_str(&format!(
                "\n<details><summary>{} {} suppressed{}</summary>\n\n",
                icon_md("info"),
                eligible.len(),
                if eligible.len() > disclosed.len() {
                    format!(" (showing {})", disclosed.len())
                } else {
                    String::new()
                },
            ));
        } else {
            s.push_str(&format!(
                "\ninfo: {} suppressed{}:\n",
                eligible.len(),
                if eligible.len() > disclosed.len() {
                    format!(" (showing {})", disclosed.len())
                } else {
                    String::new()
                },
            ));
        }
        for suppressed in disclosed {
            let publication =
                crate::envelope::forge_safe_finding_publication_text(&suppressed.finding);
            s.push_str(&format!(
                "- **{}** at `{}`:{}: {}; severity {}, confidence {}. {}\n",
                publication.title,
                safe_code_text(&suppressed.finding.path),
                suppressed.finding.line,
                suppression_reason(suppressed.reason),
                suppressed.finding.severity.as_str(),
                format_confidence(suppressed.finding.confidence),
                publication.body,
            ));
        }
        if rich {
            s.push_str("\n</details>\n");
        }
    }

    let prevention_applies = context
        .publication
        .is_none_or(|publication| publication.active_inline > 0);
    if context.prevention_hint && prevention_applies && !operational && !envelope.silent {
        if rich {
            s.push_str("\n<details><summary>Before the next push</summary>\n\n");
        } else {
            s.push_str("\nBefore the next push:\n");
        }
        s.push_str("Run `postil review --staged`.\n");
        if rich {
            s.push_str("\n</details>\n");
        }
    }

    if let Some(details_url) = context.details_url {
        if rich {
            s.push_str(&format!("\n<sub>[Review details]({details_url})</sub>\n"));
        } else {
            s.push_str(&format!("\n[Review details]({details_url})\n"));
        }
    }
    s
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn suppression_reason(reason: SuppressionReason) -> &'static str {
    match reason {
        SuppressionReason::NonActionable => "deterministically non-actionable",
        SuppressionReason::Ignored => "ignored by repository policy",
        SuppressionReason::BelowSeverity => "below the configured severity threshold",
        SuppressionReason::BelowConfidence => "below the configured confidence threshold",
        SuppressionReason::MaxFindings => "outside the configured finding cap",
        SuppressionReason::AnchorMismatch => "cites a line the named construct does not sit on",
        SuppressionReason::DuplicateRootCause => {
            "restates a retained finding about another location"
        }
        SuppressionReason::DerivedFromSuppressed => "built on a finding suppressed as mis-anchored",
        SuppressionReason::RepositoryClaimUnsupported => "repository-wide claim is not publishable",
    }
}

fn safe_code_text(value: &str) -> String {
    value
        .replace(['\r', '\n', '`'], "")
        .chars()
        .take(300)
        .collect()
}

/// The body of one inline finding comment: icon (rich forges), bold title,
/// severity / confidence / kind statusline, then the finding body.
pub fn finding_comment_body(f: &Finding, rich: bool) -> String {
    let publication = crate::envelope::forge_safe_finding_publication_text(f);
    let icon = if rich {
        format!("{} ", severity_icon(f.severity))
    } else {
        String::new()
    };
    format!(
        "{}**{}**\n`{}` · confidence {} · kind: {}\n\n{}",
        icon,
        publication.title,
        f.severity.as_str(),
        format_confidence(f.confidence),
        f.kind.as_str(),
        publication.body
    )
}

/// Confidence rendered as the product statusline shows it: a bare decimal
/// probability ("0.91"), not a percentage.
pub fn format_confidence(c: f64) -> String {
    format!("{:.2}", c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Kind, Severity};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn raw_http_server(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4_096];
            let _ = stream.read(&mut request);
            stream.write_all(&response).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn forge_metadata_limit_is_aggregate_and_overflow_safe() {
        assert_eq!(
            checked_metadata_total(MAX_FORGE_METADATA_BYTES - 7, 7, "pages").unwrap(),
            MAX_FORGE_METADATA_BYTES
        );
        assert!(
            checked_metadata_total(MAX_FORGE_METADATA_BYTES, 1, "pages")
                .unwrap_err()
                .to_string()
                .contains("aggregate limit")
        );
        assert!(checked_metadata_total(usize::MAX, 1, "pages").is_err());
    }

    #[test]
    fn publication_receipt_is_atomically_written_as_private_versioned_json() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("publication.json");
        let receipt = ReviewPublicationReceipt {
            version: ReviewPublicationReceipt::VERSION,
            channel: ReviewPublicationChannel::ReviewComments,
            receipt_id: "github-review-v2:test".into(),
            review_id: Some("77".into()),
            findings: vec![FindingPublicationReceipt {
                finding_id: "finding-1".into(),
                stable_identity: true,
                initial_outcome: FindingPublicationOutcome::Inline,
                inline_rejected: false,
                comment_id: Some("501".into()),
            }],
        };

        write_review_publication_receipt(&path, &receipt).unwrap();
        let stored: ReviewPublicationReceipt =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored, receipt);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    fn sample_publication_plan(
        head_sha: &str,
        review_body: &str,
        finding_id: &str,
        gate_conclusion: PublicationPlanCheckConclusion,
    ) -> GitHubPublicationPlan {
        let finding = PublicationPlanFinding {
            finding_id: finding_id.into(),
            stable_identity: true,
            path: "src/lib.rs".into(),
            line: 10,
            end_line: None,
            initial_outcome: FindingPublicationOutcome::Inline,
            fallback_intent: vec![PublicationPlanFindingFallback::FileComment],
            content_digest: "sha256:finding".into(),
            marker: "<!-- postil-finding:v2:finding -->".into(),
            compatible_markers: vec![],
            desired_body: "Finding body".into(),
            desired_body_sha256: "sha256:body".into(),
            observed_comment_id: None,
            observed_body_sha256: None,
            observed_outcome: None,
            reconciliation: PublicationPlanFindingReconciliation::Create,
            suppression_reason: None,
            duplicate_provenance: PublicationPlanDuplicateProvenance::None,
        };
        let lifecycle_receipt = PublicationPlanLifecycleReceipt::new(
            format!("sha256:{}", "1".repeat(64)),
            ReviewPublicationChannel::ReviewComments,
            "github-review-v2:receipt".into(),
            vec![],
            None,
            false,
            vec![finding.clone()],
        )
        .unwrap();
        let review_operation = PublicationPlanOperation::new(
            1,
            "review-key".into(),
            vec![],
            PublicationPlanOperationActivation {
                any_of: vec![PublicationPlanActivationCondition::Always],
            },
            PublicationPlanOperationReconciliation {
                logical_identity: "review-identity".into(),
                markers: vec!["<!-- postil-review:v2:review -->".into()],
                observed_remote_id: None,
                exclusive: true,
            },
            PublicationPlanOperationKind::ReviewCreate {
                attempt: PublicationPlanReviewAttemptKind::Initial,
                logical_review_identity: "review-identity".into(),
                payload: PublicationPlanReviewCreatePayload {
                    commit_id: head_sha.into(),
                    event: "COMMENT".into(),
                    body: review_body.into(),
                    comments: vec![],
                },
            },
        )
        .unwrap();
        GitHubPublicationPlan::new(
            GitHubPublicationPlanIdentity {
                controller_generation: "1".into(),
                input_identity: format!("sha256:{}", "1".repeat(64)),
                review_output_digest: format!("sha256:{}", "2".repeat(64)),
                repository: PublicationPlanRepository {
                    id: "42".into(),
                    full_name: "acme/api".into(),
                },
                pull_request_number: "7".into(),
                reviewed_snapshot: PublicationPlanSnapshot {
                    head_sha: head_sha.into(),
                    merge_base_sha: "bbbbbbbb".into(),
                    target_sha: "cccccccc".into(),
                    pull_request_title_sha256: "sha256:title".into(),
                    pull_request_body_sha256: "sha256:body".into(),
                },
            },
            lifecycle_receipt,
            vec![review_operation],
            PublicationPlanGateAnalysis {
                ownership: PublicationPlanGateOwnership::Service,
                authoritative: false,
                organization_gate_mode_required: true,
                name: "postil/gate".into(),
                head_sha: head_sha.into(),
                analyzed_conclusion: gate_conclusion,
                title: "Merge gate".into(),
                summary: "Gate summary".into(),
                details_url: None,
            },
        )
        .unwrap()
    }

    fn rebuild_publication_plan(
        template: &GitHubPublicationPlan,
        operations: Vec<PublicationPlanOperation>,
    ) -> Result<GitHubPublicationPlan> {
        GitHubPublicationPlan::new(
            GitHubPublicationPlanIdentity {
                controller_generation: template.controller_generation.clone(),
                input_identity: template.input_identity.clone(),
                review_output_digest: template.review_output_digest.clone(),
                repository: template.repository.clone(),
                pull_request_number: template.pull_request_number.clone(),
                reviewed_snapshot: template.reviewed_snapshot.clone(),
            },
            template.lifecycle_receipt.clone(),
            operations,
            template.gate_analysis.clone(),
        )
    }

    fn dependent_publication_operation(
        template: &PublicationPlanOperation,
        operation_key: &str,
        dependency_operation_key: &str,
    ) -> PublicationPlanOperation {
        let mut operation = template.clone();
        operation.ordinal = 2;
        operation.operation_key = operation_key.into();
        operation.dependencies = vec![dependency_operation_key.into()];
        operation.activation = PublicationPlanOperationActivation {
            any_of: vec![
                PublicationPlanActivationCondition::ReviewSelectionTerminal {
                    selected_review_operation_keys: vec![dependency_operation_key.into()],
                },
            ],
        };
        operation.reconciliation.logical_identity = format!("{operation_key}-identity");
        operation
    }

    fn bounded_publication_operations(
        template: &PublicationPlanOperation,
        operation_count: usize,
        dependency_edge_count: usize,
    ) -> Vec<PublicationPlanOperation> {
        let mut remaining_edges = dependency_edge_count;
        let mut operations = Vec::with_capacity(operation_count);
        for index in 0..operation_count {
            let operation_key = format!("operation-{index}");
            let edge_count = remaining_edges.min(index);
            let dependencies = (0..edge_count)
                .map(|dependency_index| format!("operation-{dependency_index}"))
                .collect();
            remaining_edges -= edge_count;

            let mut operation = template.clone();
            operation.ordinal = u32::try_from(index + 1).unwrap();
            operation.operation_key = operation_key.clone();
            operation.dependencies = dependencies;
            operation.activation = PublicationPlanOperationActivation {
                any_of: vec![PublicationPlanActivationCondition::Always],
            };
            operation.reconciliation.logical_identity = format!("{operation_key}-identity");
            operations.push(operation);
        }
        assert_eq!(remaining_edges, 0, "fixture has enough dependency capacity");
        operations
    }

    #[test]
    fn publication_plan_is_private_atomic_deterministic_and_intent_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("publication-plan.json");
        let plan = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Failure,
        );
        write_github_publication_plan(&path, &plan).unwrap();
        let first = std::fs::read(&path).unwrap();
        write_github_publication_plan(&path, &plan).unwrap();
        let second = std::fs::read(&path).unwrap();
        assert_eq!(first, second);
        let mut piped = Vec::new();
        write_github_publication_plan_to_writer(&mut piped, &plan).unwrap();
        assert_eq!(piped, first);
        assert_eq!(piped.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<GitHubPublicationPlan>(&first).unwrap(),
            plan
        );
        let serialized: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(serialized["repository"]["id"], "42");
        assert_eq!(serialized["pullRequestNumber"], "7");
        assert_eq!(
            serialized["inputIdentity"],
            format!("sha256:{}", "1".repeat(64))
        );
        assert_eq!(
            serialized["reviewOutputDigest"],
            format!("sha256:{}", "2".repeat(64))
        );
        assert_eq!(serialized["operationCount"], 1);
        assert_eq!(plan.operation_count, plan.operations.len() as u32);
        assert_eq!(
            plan.recompute_operation_manifest_digest().unwrap(),
            plan.operation_manifest_digest
        );
        assert!(plan.intent_digest.starts_with("sha256:"));
        assert_eq!(plan.intent_digest.len(), "sha256:".len() + 64);
        assert_eq!(plan.recompute_intent_digest().unwrap(), plan.intent_digest);
        assert_eq!(
            plan.lifecycle_receipt.recompute_digest().unwrap(),
            plan.lifecycle_receipt.digest
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        for changed in [
            sample_publication_plan(
                "dddddddd",
                "Review body",
                "finding-1",
                PublicationPlanCheckConclusion::Failure,
            ),
            sample_publication_plan(
                "aaaaaaaa",
                "Changed body",
                "finding-1",
                PublicationPlanCheckConclusion::Failure,
            ),
            sample_publication_plan(
                "aaaaaaaa",
                "Review body",
                "finding-2",
                PublicationPlanCheckConclusion::Failure,
            ),
            sample_publication_plan(
                "aaaaaaaa",
                "Review body",
                "finding-1",
                PublicationPlanCheckConclusion::Success,
            ),
        ] {
            assert_ne!(changed.intent_digest, plan.intent_digest);
        }

        let mut stored_digest_only = plan.clone();
        stored_digest_only.intent_digest = "sha256:untrusted".into();
        assert_eq!(
            stored_digest_only.recompute_intent_digest().unwrap(),
            plan.intent_digest,
            "the stored intent digest is outside its own canonical boundary"
        );
        let mut repository_changed = plan.clone();
        repository_changed.repository.id = "43".into();
        assert_ne!(
            repository_changed.recompute_intent_digest().unwrap(),
            plan.intent_digest
        );
        let mut pull_request_changed = plan.clone();
        pull_request_changed.pull_request_number = "8".into();
        assert_ne!(
            pull_request_changed.recompute_intent_digest().unwrap(),
            plan.intent_digest
        );
        let mut lifecycle_changed = plan.clone();
        lifecycle_changed.lifecycle_receipt.findings[0].desired_body = "Changed finding".into();
        assert_ne!(
            lifecycle_changed
                .lifecycle_receipt
                .recompute_digest()
                .unwrap(),
            plan.lifecycle_receipt.digest
        );
        assert_ne!(
            lifecycle_changed.recompute_intent_digest().unwrap(),
            plan.intent_digest
        );
        let mut operation_changed = plan.clone();
        let PublicationPlanOperationKind::ReviewCreate { payload, .. } =
            &mut operation_changed.operations[0].desired
        else {
            panic!("sample plan must contain a review create");
        };
        payload.body = "Changed operation payload".into();
        assert_ne!(
            operation_changed
                .recompute_operation_manifest_digest()
                .unwrap(),
            plan.operation_manifest_digest
        );
        let mut stored_manifest_only = plan.clone();
        stored_manifest_only.operation_manifest_digest = "sha256:untrusted".into();
        assert_eq!(
            stored_manifest_only
                .recompute_operation_manifest_digest()
                .unwrap(),
            plan.operation_manifest_digest,
            "the stored manifest digest is outside its own canonical boundary"
        );
        assert_ne!(
            stored_manifest_only.recompute_intent_digest().unwrap(),
            plan.intent_digest,
            "the manifest seal is inside the plan intent boundary"
        );
    }

    #[test]
    fn publication_plan_rejects_noncanonical_numeric_identifiers() {
        for repository_id in ["", "0", "01", "9223372036854775808", "18446744073709551615"] {
            assert!(ensure_publication_decimal_identifier("repository id", repository_id).is_err());
        }
        for pull_request_number in ["", "0", "07", "-7"] {
            assert!(
                ensure_publication_decimal_identifier("pull request number", pull_request_number)
                    .is_err()
            );
        }
        assert!(
            ensure_publication_decimal_identifier("repository id", "9223372036854775807").is_ok()
        );
        assert!(
            ensure_publication_sha256_identity(
                "input identity",
                &format!("sha256:{}", "a".repeat(64)),
            )
            .is_ok()
        );
        for identity in [
            "",
            "sha256:",
            &format!("sha256:{}", "a".repeat(63)),
            &format!("sha256:{}", "A".repeat(64)),
            &format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(ensure_publication_sha256_identity("input identity", identity).is_err());
        }

        let plan = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Failure,
        );
        assert!(
            GitHubPublicationPlan::new(
                GitHubPublicationPlanIdentity {
                    controller_generation: "generation-1".into(),
                    input_identity: plan.input_identity.clone(),
                    review_output_digest: plan.review_output_digest.clone(),
                    repository: plan.repository.clone(),
                    pull_request_number: plan.pull_request_number.clone(),
                    reviewed_snapshot: plan.reviewed_snapshot.clone(),
                },
                plan.lifecycle_receipt.clone(),
                plan.operations.clone(),
                plan.gate_analysis.clone(),
            )
            .is_err()
        );

        assert!(
            PublicationPlanLifecycleReceipt::new(
                plan.input_identity.clone(),
                plan.lifecycle_receipt.channel,
                plan.lifecycle_receipt.receipt_id.clone(),
                plan.lifecycle_receipt.compatible_receipt_ids.clone(),
                Some("9223372036854775808".into()),
                plan.lifecycle_receipt.duplicate_of_baseline,
                plan.lifecycle_receipt.findings.clone(),
            )
            .is_err()
        );
        let mut finding_with_oversized_id = plan.lifecycle_receipt.findings[0].clone();
        finding_with_oversized_id.observed_comment_id = Some("9223372036854775808".into());
        assert!(
            PublicationPlanLifecycleReceipt::new(
                plan.input_identity.clone(),
                plan.lifecycle_receipt.channel,
                plan.lifecycle_receipt.receipt_id.clone(),
                vec![],
                None,
                false,
                vec![finding_with_oversized_id],
            )
            .is_err()
        );
    }

    #[test]
    fn publication_plan_constructor_accepts_only_a_sealed_topological_operation_graph() {
        let template = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Success,
        );
        let first = template.operations[0].clone();
        let second = dependent_publication_operation(&first, "summary-key", "review-key");
        let valid = rebuild_publication_plan(&template, vec![first.clone(), second.clone()])
            .expect("a contiguous topological operation graph is valid");
        assert_eq!(valid.operation_count, 2);
        assert_eq!(
            valid.recompute_operation_manifest_digest().unwrap(),
            valid.operation_manifest_digest
        );
        assert_eq!(
            valid.recompute_intent_digest().unwrap(),
            valid.intent_digest
        );

        let mut duplicate = second.clone();
        duplicate.operation_key = first.operation_key.clone();
        assert!(
            rebuild_publication_plan(&template, vec![first.clone(), duplicate])
                .unwrap_err()
                .to_string()
                .contains("keys must be unique")
        );

        let mut missing = second.clone();
        missing.dependencies = vec!["missing-key".into()];
        missing.activation = PublicationPlanOperationActivation {
            any_of: vec![PublicationPlanActivationCondition::Always],
        };
        assert!(
            rebuild_publication_plan(&template, vec![first.clone(), missing])
                .unwrap_err()
                .to_string()
                .contains("depends on missing operation")
        );

        let mut forward_first = first.clone();
        forward_first.dependencies = vec![second.operation_key.clone()];
        assert!(
            rebuild_publication_plan(&template, vec![forward_first, second.clone()])
                .unwrap_err()
                .to_string()
                .contains("forward, self, or cyclic dependency")
        );

        let mut cyclic_first = first.clone();
        cyclic_first.dependencies = vec![second.operation_key.clone()];
        let mut cyclic_second = second.clone();
        cyclic_second.dependencies = vec![first.operation_key.clone()];
        assert!(
            rebuild_publication_plan(&template, vec![cyclic_first, cyclic_second])
                .unwrap_err()
                .to_string()
                .contains("forward, self, or cyclic dependency")
        );

        let mut self_dependent = first.clone();
        self_dependent.dependencies = vec![first.operation_key.clone()];
        assert!(
            rebuild_publication_plan(&template, vec![self_dependent])
                .unwrap_err()
                .to_string()
                .contains("forward, self, or cyclic dependency")
        );

        let mut undeclared_activation = second.clone();
        undeclared_activation.dependencies.clear();
        assert!(
            rebuild_publication_plan(&template, vec![first.clone(), undeclared_activation])
                .unwrap_err()
                .to_string()
                .contains("references undeclared dependency")
        );

        let mut empty_activation = first.clone();
        empty_activation.activation.any_of.clear();
        assert!(
            rebuild_publication_plan(&template, vec![empty_activation])
                .unwrap_err()
                .to_string()
                .contains("require at least one activation condition")
        );

        let mut stale_desired_digest = first.clone();
        let PublicationPlanOperationKind::ReviewCreate { payload, .. } =
            &mut stale_desired_digest.desired
        else {
            panic!("sample plan must contain a review create");
        };
        payload.body = "Changed without resealing".into();
        assert!(
            rebuild_publication_plan(&template, vec![stale_desired_digest])
                .unwrap_err()
                .to_string()
                .contains("desired digest does not match")
        );

        let advisory_completion = PublicationPlanOperation::new(
            2,
            "advisory-complete".into(),
            vec![],
            PublicationPlanOperationActivation {
                any_of: vec![PublicationPlanActivationCondition::Always],
            },
            PublicationPlanOperationReconciliation {
                logical_identity: "advisory-complete".into(),
                markers: vec![],
                observed_remote_id: None,
                exclusive: true,
            },
            PublicationPlanOperationKind::AdvisoryCheckComplete {
                name: "postil/review".into(),
                head_sha: "aaaaaaaa".into(),
                created_check: PublicationPlanOperationResultReference {
                    dependency_operation_key: first.operation_key.clone(),
                    result_field: PublicationPlanOperationResultField::RemoteId,
                },
                conclusion: PublicationPlanCheckConclusion::Success,
                title: "Review".into(),
                summary: "Review complete.".into(),
                annotations: vec![],
                details_url: None,
            },
        )
        .unwrap();
        assert!(
            rebuild_publication_plan(&template, vec![first.clone(), advisory_completion])
                .unwrap_err()
                .to_string()
                .contains("undeclared create dependency")
        );

        let mut ordinal_zero = first.clone();
        ordinal_zero.ordinal = 0;
        assert!(
            rebuild_publication_plan(&template, vec![ordinal_zero])
                .unwrap_err()
                .to_string()
                .contains("contiguous and one-based")
        );

        let mut ordinal_gap = second;
        ordinal_gap.ordinal = 3;
        assert!(
            rebuild_publication_plan(&template, vec![first, ordinal_gap])
                .unwrap_err()
                .to_string()
                .contains("contiguous and one-based")
        );
    }

    #[test]
    fn publication_plan_enforces_operation_and_dependency_edge_bounds() {
        let template = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Success,
        );
        let operation_template = &template.operations[0];

        let maximum_operations = bounded_publication_operations(
            operation_template,
            GitHubPublicationPlan::MAX_OPERATIONS,
            0,
        );
        assert_eq!(
            rebuild_publication_plan(&template, maximum_operations)
                .unwrap()
                .operation_count,
            126
        );
        let too_many_operations = bounded_publication_operations(
            operation_template,
            GitHubPublicationPlan::MAX_OPERATIONS + 1,
            0,
        );
        assert!(
            rebuild_publication_plan(&template, too_many_operations)
                .unwrap_err()
                .to_string()
                .contains("operation count must not exceed 126")
        );

        let maximum_edges = bounded_publication_operations(
            operation_template,
            GitHubPublicationPlan::MAX_OPERATIONS,
            GitHubPublicationPlan::MAX_DEPENDENCY_EDGES,
        );
        assert!(rebuild_publication_plan(&template, maximum_edges).is_ok());
        let too_many_edges = bounded_publication_operations(
            operation_template,
            GitHubPublicationPlan::MAX_OPERATIONS,
            GitHubPublicationPlan::MAX_DEPENDENCY_EDGES + 1,
        );
        assert!(
            rebuild_publication_plan(&template, too_many_edges)
                .unwrap_err()
                .to_string()
                .contains("dependency edge count must not exceed 1024")
        );
    }

    #[test]
    fn publication_plan_check_wire_values_are_closed_enums() {
        assert_eq!(
            serde_json::to_value(PublicationPlanCheckStatus::InProgress).unwrap(),
            serde_json::json!("in_progress")
        );
        assert_eq!(
            serde_json::to_value(PublicationPlanCheckConclusion::Success).unwrap(),
            serde_json::json!("success")
        );
        assert_eq!(
            serde_json::to_value(PublicationPlanCheckConclusion::Failure).unwrap(),
            serde_json::json!("failure")
        );
        assert_eq!(
            serde_json::to_value(PublicationPlanCheckConclusion::Neutral).unwrap(),
            serde_json::json!("neutral")
        );
        assert!(serde_json::from_str::<PublicationPlanCheckStatus>("\"queued\"").is_err());
        assert!(serde_json::from_str::<PublicationPlanCheckConclusion>("\"cancelled\"").is_err());
    }

    #[test]
    fn publication_operation_manifest_seals_complete_ordered_records() {
        let plan = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Failure,
        );
        let baseline = plan.operation_manifest_digest.clone();
        let assert_changed = |changed: &GitHubPublicationPlan| {
            assert_ne!(
                changed.recompute_operation_manifest_digest().unwrap(),
                baseline
            );
        };

        let mut changed = plan.clone();
        changed.operations[0].ordinal = 2;
        assert_changed(&changed);

        let mut changed = plan.clone();
        changed.operations[0].operation_key.push_str("-changed");
        assert_changed(&changed);

        let mut changed = plan.clone();
        changed.operations[0]
            .dependencies
            .push("dependency-key".into());
        assert_changed(&changed);

        let mut changed = plan.clone();
        changed.operations[0].activation.any_of.clear();
        assert_changed(&changed);

        let mut changed = plan.clone();
        changed.operations[0]
            .reconciliation
            .logical_identity
            .push_str("-changed");
        assert_changed(&changed);

        let mut changed = plan.clone();
        changed.operations[0].desired_digest = "sha256:changed".into();
        assert_changed(&changed);

        let mut changed = plan.clone();
        let PublicationPlanOperationKind::ReviewCreate {
            attempt,
            logical_review_identity,
            ..
        } = &mut changed.operations[0].desired
        else {
            panic!("sample plan must contain a review create");
        };
        *attempt = PublicationPlanReviewAttemptKind::SummaryOnly;
        logical_review_identity.push_str("-changed");
        assert_changed(&changed);
    }

    #[cfg(unix)]
    #[test]
    fn publication_plan_refuses_symlink_and_directory_targets() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let plan = sample_publication_plan(
            "aaaaaaaa",
            "Review body",
            "finding-1",
            PublicationPlanCheckConclusion::Failure,
        );
        let destination = directory.path().join("destination.json");
        std::fs::write(&destination, "unchanged").unwrap();
        let link = directory.path().join("publication-plan.json");
        symlink(&destination, &link).unwrap();
        let error = write_github_publication_plan(&link, &plan).unwrap_err();
        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "unchanged");

        let target_directory = directory.path().join("target-directory");
        std::fs::create_dir(&target_directory).unwrap();
        assert!(write_github_publication_plan(&target_directory, &plan).is_err());
    }

    #[tokio::test]
    async fn source_snapshot_streams_above_page_limit_with_complete_length() {
        let server = MockServer::start().await;
        let body = vec![b'x'; crate::diff::MAX_FORGE_RESPONSE_BYTES + 1];
        Mock::given(method("GET"))
            .and(path("/large-source"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let response = reqwest::get(format!("{}/large-source", server.uri()))
            .await
            .unwrap();
        let snapshot = response_snapshot(response, "large forge source")
            .await
            .unwrap();

        assert_eq!(snapshot.len(), body.len() as u64);
        assert_eq!(snapshot.as_bytes().first(), Some(&b'x'));
        assert_eq!(snapshot.as_bytes().last(), Some(&b'x'));
    }

    #[tokio::test]
    async fn source_snapshot_accepts_complete_chunked_response_without_length() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n5\r\n body\r\n0\r\n\r\n".to_vec();
        let (url, server) = raw_http_server(response);
        let response = reqwest::get(url).await.unwrap();
        assert_eq!(response.content_length(), None);

        let snapshot = response_snapshot(response, "chunked forge source")
            .await
            .unwrap();

        server.join().unwrap();
        assert_eq!(snapshot.as_bytes(), b"safe body");
    }

    #[tokio::test]
    async fn source_snapshot_enforces_workspace_quota_without_declared_length() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nsafe\r\n5\r\n body\r\n0\r\n\r\n".to_vec();
        let (url, server) = raw_http_server(response);
        let response = reqwest::get(url).await.unwrap();

        let error = match response_snapshot_in(
            response,
            "quota-bound chunked source",
            crate::diff::WorkspaceBudget::with_limit(8),
            None,
        )
        .await
        {
            Ok(_) => panic!("chunked source must respect the shared workspace quota"),
            Err(error) => error,
        };

        server.join().unwrap();
        assert!(format!("{error:#}").contains("operation quota"));
    }

    #[tokio::test]
    async fn source_snapshot_rejects_transport_truncation() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort".to_vec();
        let (url, server) = raw_http_server(response);
        let response = reqwest::get(url).await.unwrap();

        let error = match response_snapshot(response, "truncated forge source").await {
            Ok(_) => panic!("truncated response must be rejected"),
            Err(error) => error,
        };

        server.join().unwrap();
        assert!(error.to_string().contains("reading truncated forge source"));
    }

    #[tokio::test]
    async fn source_snapshot_verifies_authoritative_size_and_hash() {
        let body = b"complete source";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/source"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(2)
            .mount(&server)
            .await;

        let expected_hash = Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let valid = response_snapshot_in(
            reqwest::get(format!("{}/source", server.uri()))
                .await
                .unwrap(),
            "verified forge source",
            crate::diff::WorkspaceBudget::new(),
            Some(SourceExpectation {
                size: Some(body.len() as u64),
                sha256: Some(expected_hash),
            }),
        )
        .await
        .unwrap();
        assert_eq!(valid.as_bytes(), body);

        let error = match response_snapshot_in(
            reqwest::get(format!("{}/source", server.uri()))
                .await
                .unwrap(),
            "mismatched forge source",
            crate::diff::WorkspaceBudget::new(),
            Some(SourceExpectation {
                size: Some(body.len() as u64),
                sha256: Some("0".repeat(64)),
            }),
        )
        .await
        {
            Ok(_) => panic!("hash mismatch must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("content hash"));
    }

    #[test]
    fn only_typed_service_failures_remain_advisory_eligible() {
        let outage = classify_review_input_error(service_failure("upstream unavailable"));
        assert!(!is_incomplete_review_input(&outage));

        let malformed = classify_review_input_error(anyhow::anyhow!(
            "forge returned truncated pagination metadata"
        ));
        assert!(is_incomplete_review_input(&malformed));

        let unauthorized = classify_review_input_error(http_failure(
            reqwest::StatusCode::UNAUTHORIZED,
            "forge rejected credentials",
        ));
        assert!(is_incomplete_review_input(&unauthorized));
    }

    #[test]
    fn incremental_baseline_refusals_stay_recognizable_after_classification() {
        let refusal = incremental_diff_unavailable(
            "GitHub incremental compare no longer descends from the requested baseline",
        );
        assert!(is_incremental_diff_unavailable(&refusal));
        assert!(
            refusal
                .to_string()
                .contains("no longer descends from the requested baseline")
        );

        // The caller inspects the error only after classification wraps it, so
        // the marker has to survive the added context layers.
        let classified = classify_review_input_error(refusal).context("incremental diff fetch");
        assert!(is_incremental_diff_unavailable(&classified));
        assert!(is_incomplete_review_input(&classified));

        // A forge outage is not a baseline problem and must still fail the run.
        let outage = classify_review_input_error(service_failure("compare fetch failed"));
        assert!(!is_incremental_diff_unavailable(&outage));
    }

    #[test]
    fn forge_summary_keeps_incomplete_review_reasons_generic() {
        for reason in [
            crate::envelope::IncompleteReviewReason::IncompleteInput,
            crate::envelope::IncompleteReviewReason::LocalIncrementalFullComparisonUnavailable,
            crate::envelope::IncompleteReviewReason::ReservedInput,
            crate::envelope::IncompleteReviewReason::InsufficientContextBudget,
            crate::envelope::IncompleteReviewReason::InvalidModelFanOut,
        ] {
            let finding = crate::envelope::incomplete_review_finding(reason);
            let reason_body = finding.body.clone();
            let summary = check_summary(
                &envelope_with_findings(vec![finding]),
                false,
                Default::default(),
            );

            assert!(summary.starts_with(
                "Postil could not complete this review, so no review verdict exists."
            ));
            assert!(!summary.contains(&reason_body));
        }
    }

    fn finding() -> Finding {
        Finding {
            path: "src/auth.rs".into(),
            line: 41,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.91,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: None,
            title: "Unsanitized input reaches query".into(),
            body: "user_input flows into exec_query.".into(),
            evidence: None,
            id: None,
        }
    }

    fn envelope_with_findings(findings: Vec<Finding>) -> Envelope {
        Envelope {
            version: 1,
            summary: String::new(),
            silent: findings.is_empty(),
            counts: Envelope::counts_of(&findings, 0),
            confidence_buckets: Envelope::buckets_of(&findings),
            findings,
            suppressed_findings: vec![],
            resolved: vec![],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: true,
                block_on_kinds: vec!["humanEscalation".into()],
            },
            model_used: "review-model".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        }
    }

    #[test]
    fn rich_comment_carries_brand_icon_and_statusline() {
        let body = finding_comment_body(&finding(), true);
        assert!(body.contains("https://postil.dev/status/error.svg"));
        assert!(body.contains("confidence 0.91 · kind: risk"));
    }

    #[test]
    fn unsafe_finding_text_is_rejected_before_the_comment_wrapper() {
        let mut unsafe_finding = finding();
        unsafe_finding.title.clear();
        unsafe_finding.body = "**@octocat <img> [`code`]**\n\nKeep `useful()` formatting.".into();

        assert!(crate::envelope::validate_finding_publication(&unsafe_finding).is_err());
    }

    #[test]
    fn public_summary_omits_unsupported_repository_claims() {
        let mut env = envelope_with_findings(vec![]);
        let mut unsupported = finding();
        unsupported.title = "Private repository claim".into();
        unsupported.body = "Repository-only detail that must remain diagnostic.".into();
        env.suppressed_findings
            .push(crate::envelope::SuppressedFinding {
                finding: unsupported,
                reason: SuppressionReason::RepositoryClaimUnsupported,
            });
        let summary = check_summary(&env, true, Default::default());
        assert!(!summary.contains("Private repository claim"));
        assert!(!summary.contains("Repository-only detail"));
        assert_eq!(env.suppressed_findings.len(), 1);
    }

    #[test]
    fn public_summary_omits_suppressed_ephemeral_findings() {
        let mut env = envelope_with_findings(vec![]);
        let mut operational = crate::envelope::fail_closed_finding("private model detail");
        operational.title = "Private operational title".into();
        operational.body = "Private operational detail that must remain diagnostic.".into();
        env.suppressed_findings
            .push(crate::envelope::SuppressedFinding {
                finding: operational,
                reason: SuppressionReason::NonActionable,
            });

        let summary = check_summary(&env, true, Default::default());

        assert!(!summary.contains("Private operational title"));
        assert!(!summary.contains("Private operational detail"));
        assert_eq!(env.suppressed_findings.len(), 1);
    }

    #[test]
    fn only_exact_virtual_anchors_are_synthetic() {
        assert!(is_synthetic_path(crate::envelope::PROVIDER_PATH));
        assert!(is_synthetic_path(crate::envelope::OPERATIONAL_PATH));
        assert!(is_synthetic_path(crate::envelope::PR_DESCRIPTION_PATH));
        assert!(is_synthetic_path(crate::envelope::CHANGE_METADATA_PATH));
        assert!(is_synthetic_path(crate::envelope::DIFF_PATH));
        assert!(!is_synthetic_path(".postil/content-policy.md"));
        assert!(!is_synthetic_path(".postil/guardrails.md"));
    }

    #[test]
    fn summary_is_explicit_path_free_and_marks_weak_escalations_non_blocking() {
        let mut escalation = finding();
        escalation.kind = Kind::HumanEscalation;
        escalation.confidence = 0.05;
        let mut suppressed_findings = (0..6)
            .map(|index| crate::envelope::SuppressedFinding {
                finding: Finding {
                    title: format!("Lower confidence concern {index}"),
                    body: "Evidence from the changed branch shows the value can be lost.".into(),
                    ..finding()
                },
                reason: crate::envelope::SuppressionReason::BelowConfidence,
            })
            .collect::<Vec<_>>();
        suppressed_findings.push(crate::envelope::SuppressedFinding {
            finding: Finding {
                title: "Ignored generated file".into(),
                ..finding()
            },
            reason: crate::envelope::SuppressionReason::Ignored,
        });
        let env = Envelope {
            version: 1,
            summary: "A weak signal needs review.".into(),
            silent: false,
            findings: vec![escalation],
            suppressed_findings,
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [1, 0, 0, 0, 0],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec!["humanEscalation".into()],
            },
            model_used: "review-model".into(),
            scorer_model: Some("scorer-model".into()),
            scorer_error: None,
            scorer_disagreements: Some(1),
            usage: crate::envelope::Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                ..Default::default()
            },
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 1_250,
            base_sha: None,
            head_sha: Some("abcdef123456".into()),
            since_sha: None,
        };

        let summary = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                prevention_hint: true,
                prevention_commands: vec!["cargo test --lib".into()],
                publication: None,
            },
        );

        assert!(summary.starts_with(&format!("{} **1 advisory finding open**", icon_md("info"))));
        assert!(!summary.contains("does not block"));
        assert!(!summary.contains("Unsanitized input reaches query"));
        assert!(!summary.contains("src/auth.rs:41"));
        assert!(!summary.contains("Review metadata"));
        assert!(!summary.contains("abcdef1"));
        assert!(summary.contains(&format!(
            "<details><summary>{} 6 suppressed (showing 5)</summary>",
            icon_md("info")
        )));
        assert!(summary.contains("Lower confidence concern 0"));
        assert!(summary.contains("severity error, confidence 0.91"));
        assert!(summary.contains("Evidence from the changed branch"));
        assert!(!summary.contains("Ignored generated file"));
        assert!(summary.contains("postil review --staged"));
        assert!(!summary.contains("postil hook install"));
        assert!(
            summary
                .contains("<sub>[Review details](https://postil.dev/orgs/acme/runs/run-1)</sub>")
        );

        let plain = check_summary(&env, false, Default::default());
        assert!(plain.contains("info: 6 suppressed (showing 5):"));
        assert!(!plain.contains("<details>"));
    }

    #[test]
    fn summary_counts_cover_blocking_advisory_resolved_and_suppressed() {
        let blocking = envelope_with_findings(vec![finding()]);
        let blocking_summary = check_summary(&blocking, true, Default::default());
        assert!(blocking_summary.starts_with(&format!(
            "{} **1 blocking finding open**\n",
            icon_md("error"),
        )));
        let blocking_plural = envelope_with_findings(vec![finding(), finding()]);
        assert!(
            check_summary(&blocking_plural, true, Default::default()).starts_with(&format!(
                "{} **2 blocking findings open**\n",
                icon_md("error"),
            ))
        );

        let mut advisory_one = finding();
        advisory_one.severity = Severity::Warn;
        let mut advisory_two = advisory_one.clone();
        advisory_two.line = 42;
        let mut advisory = envelope_with_findings(vec![advisory_one, advisory_two]);
        advisory.gate.failing = false;
        let advisory_summary = check_summary(&advisory, true, Default::default());
        assert!(advisory_summary.starts_with(&format!(
            "{} **2 advisory findings open**\n",
            icon_md("info")
        )));

        let mut carried = finding();
        carried.body = format!("{}\n\n{}", crate::filter::CARRIED_MARKER, carried.body);
        let mut operational = finding();
        operational.path = crate::envelope::OPERATIONAL_PATH.into();
        operational.title = "Model output could not be validated".into();
        let carried_summary = check_summary(
            &envelope_with_findings(vec![carried, operational]),
            true,
            Default::default(),
        );
        assert!(carried_summary.starts_with(&format!(
            "{} **review incomplete** · {} **1 blocking finding open**\n",
            icon_md("warn"),
            icon_md("error")
        )));

        let mut resolved_singular = envelope_with_findings(vec![finding()]);
        resolved_singular.resolved = vec![finding()];
        assert!(
            check_summary(&resolved_singular, true, Default::default())
                .contains(&format!("{} **1 resolved finding**\n", icon_md("pass")))
        );

        let mut resolution_only = envelope_with_findings(vec![]);
        resolution_only.resolved = vec![finding(), finding()];
        let resolution_only_summary = check_summary(&resolution_only, true, Default::default());
        assert_eq!(
            resolution_only_summary,
            format!("{} **2 resolved findings**\n", icon_md("pass"))
        );

        let mut detail_counts = envelope_with_findings(vec![finding()]);
        detail_counts.resolved = vec![finding(), finding()];
        detail_counts.suppressed_findings = vec![crate::envelope::SuppressedFinding {
            finding: finding(),
            reason: SuppressionReason::BelowConfidence,
        }];
        let detail_summary = check_summary(&detail_counts, true, Default::default());
        assert!(detail_summary.contains(&format!("{} **2 resolved findings**\n", icon_md("pass"))));
        assert!(detail_summary.contains(&format!(
            "<details><summary>{} 1 suppressed</summary>",
            icon_md("info")
        )));
        assert!(!detail_summary.contains("earlier finding"));
    }

    #[test]
    fn publication_text_preserves_exact_227_character_finding_body() {
        let evidence = format!("{}.", "a".repeat(226));
        let mut finding = finding();
        finding.body = evidence.clone();
        let publication = crate::envelope::forge_safe_finding_publication_text(&finding);
        assert_eq!(publication.body, evidence);
        assert_eq!(publication.body.chars().count(), 227);
    }

    #[test]
    fn review_details_are_subordinate_when_present_and_absent_when_unset() {
        let env = envelope_with_findings(vec![finding()]);
        let with_details = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                ..Default::default()
            },
        );
        assert!(
            with_details.ends_with(
                "<sub>[Review details](https://postil.dev/orgs/acme/runs/run-1)</sub>\n"
            )
        );

        let without_details = check_summary(&env, true, Default::default());
        assert!(!without_details.contains("Review details"));
        assert!(!without_details.contains("<sub>"));
    }

    #[test]
    fn publication_summary_explains_unplaced_findings_without_duplicate_counts() {
        let env = envelope_with_findings(vec![finding(), finding()]);
        let unplaced_only = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                publication: Some(ReviewPublicationSummary {
                    summary_only: 2,
                    rejected_inline: 2,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(
            unplaced_only.contains(
                "2 findings could not be placed on the changed lines; see review details"
            )
        );
        assert!(!unplaced_only.contains("inline placement unavailable"));
        assert!(!unplaced_only.contains("2 findings in review details"));

        let unplaced_without_details_link = check_summary(
            &env,
            true,
            SummaryContext {
                publication: Some(ReviewPublicationSummary {
                    summary_only: 2,
                    rejected_inline: 2,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(
            unplaced_without_details_link
                .contains("2 findings could not be placed on the changed lines")
        );
        assert!(!unplaced_without_details_link.contains("see review details"));

        let mixed = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                publication: Some(ReviewPublicationSummary {
                    active_inline: 1,
                    summary_only: 2,
                    rejected_inline: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(mixed.contains(
            "2 findings in review details, including 1 that could not be placed on the changed lines"
        ));
        assert!(mixed.contains("1 finding posted inline"));
        assert!(!mixed.contains("inline placement unavailable"));

        let mixed_without_details_link = check_summary(
            &env,
            true,
            SummaryContext {
                publication: Some(ReviewPublicationSummary {
                    summary_only: 2,
                    rejected_inline: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(mixed_without_details_link.contains(
            "2 findings were not posted inline, including 1 that could not be placed on the changed lines"
        ));
        assert!(!mixed_without_details_link.contains("review details"));

        let file_level = check_summary(
            &env,
            true,
            SummaryContext {
                publication: Some(ReviewPublicationSummary {
                    file_comments: 2,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(file_level.contains("2 findings posted as file-level review comments"));
    }

    #[test]
    fn review_coverage_stays_out_of_compact_pull_request_summaries() {
        let mut env = envelope_with_findings(vec![finding()]);
        env.review_coverage = Some(crate::envelope::ReviewCoverage {
            mode: crate::envelope::ReviewCoverageMode::Bounded,
            selected_batches: 5,
            total_batches: 19,
            planner_fallback: true,
            receipt: None,
        });

        let rich = check_summary(&env, true, Default::default());
        let plain = check_summary(&env, false, Default::default());
        for summary in [rich, plain] {
            assert!(!summary.contains("source batches"));
            assert!(!summary.contains("planner fallback"));
        }
    }

    #[test]
    fn pr_description_finding_is_visible_without_exposing_operational_detail() {
        let mut pr_description = finding();
        pr_description.path = crate::envelope::PR_DESCRIPTION_PATH.into();
        pr_description.title = "Required disclosure is missing".into();
        pr_description.body =
            "Add the compatibility impact to the pull request description.".into();
        let mut provider = finding();
        provider.path = crate::envelope::PROVIDER_PATH.into();
        provider.title = "private provider title".into();
        provider.body = "private provider body".into();
        let mut env = envelope_with_findings(vec![pr_description, provider]);
        env.silent = false;

        let summary = check_summary(&env, true, Default::default());

        assert!(summary.contains("Required disclosure is missing"));
        assert!(summary.contains("in pull request description"));
        assert!(summary.contains("Add the compatibility impact"));
        assert!(!summary.contains("private provider title"));
        assert!(!summary.contains("private provider body"));
    }

    #[test]
    fn prevention_commands_remain_bounded_and_markdown_safe() {
        let parsed = parse_prevention_commands(
            r#"["cargo test --lib","bun test","bad`command","line\nbreak","","one","two","three","four"]"#,
        );
        assert_eq!(parsed, vec!["cargo test --lib", "bun test"]);
        assert!(parse_prevention_commands(&"x".repeat(4_097)).is_empty());
    }

    #[test]
    fn prevention_coaching_requires_a_fresh_inline_publication() {
        let env = envelope_with_findings(vec![finding()]);
        let summary_only = check_summary(
            &env,
            true,
            SummaryContext {
                prevention_hint: true,
                publication: Some(ReviewPublicationSummary {
                    summary_only: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(!summary_only.contains("Before the next push"));

        let inline = check_summary(
            &env,
            true,
            SummaryContext {
                prevention_hint: true,
                publication: Some(ReviewPublicationSummary {
                    active_inline: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(inline.contains("Before the next push"));
        assert!(inline.contains("postil review --staged"));
        assert!(!inline.contains("cargo test"));
    }

    #[test]
    fn compact_summary_hides_model_metadata_and_raw_scorer_errors() {
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "review-model".into(),
            scorer_model: None,
            scorer_error: Some("[click me](https://attacker.invalid)".into()),
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        let summary = check_summary(&env, false, Default::default());

        assert!(summary.contains("Postil reviewed this change"));
        assert!(!summary.contains("<details>"));
        assert!(!summary.contains("Scorer"));
        assert!(!summary.contains("attacker.invalid"));
    }

    #[test]
    fn plain_comment_has_statusline_without_html() {
        let body = finding_comment_body(&finding(), false);
        assert!(!body.contains("<img"));
        assert!(body.contains("`error` · confidence 0.91 · kind: risk"));
    }

    #[test]
    fn check_output_caps_stay_within_github_limits() {
        // A summary far over the limit is truncated below 65535 with a marker.
        let long = "x".repeat(200_000);
        let capped = cap_check_summary(&long);
        assert!(capped.chars().count() <= MAX_CHECK_SUMMARY);
        assert!(capped.contains("[output truncated"));
        // A short summary is passed through unchanged.
        assert_eq!(cap_check_summary("brief"), "brief");
        // Titles cap at 255 with an ellipsis marker; short ones pass through.
        let long_title = "t".repeat(1000);
        let capped_title = cap_check_title(&long_title);
        assert!(capped_title.chars().count() <= MAX_CHECK_TITLE);
        assert!(capped_title.ends_with('…'));
        assert_eq!(
            cap_check_title("2 error, 0 warn, 1 info"),
            "2 error, 0 warn, 1 info"
        );
    }

    #[test]
    fn silent_summary_is_plain_and_compact_for_all_forges() {
        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        assert!(!check_summary(&env, true, Default::default()).contains("status/pass.svg"));
        assert!(!check_summary(&env, false, Default::default()).contains("<img"));

        env.review_coverage = Some(crate::envelope::ReviewCoverage {
            mode: crate::envelope::ReviewCoverageMode::Bounded,
            selected_batches: 5,
            total_batches: 19,
            planner_fallback: false,
            receipt: None,
        });
        let summary = check_summary(&env, true, Default::default());
        assert!(summary.starts_with("No issues were found in the risk-selected changes reviewed."));
        assert_eq!(check_title(&env), "No findings in risk-selected changes");
        assert!(!summary.contains("source batches"));
        assert!(!summary.contains("planner"));
    }

    #[test]
    fn silent_summary_distinguishes_reviews_from_no_model_runs() {
        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "none (disabled by config)".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };

        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("Review disabled by configuration.")
        );

        env.model_used = "none (empty diff)".into();
        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("No reviewable diff; no model call was made.")
        );

        env.model_used = "review-model".into();
        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("Postil reviewed this change")
        );
    }

    #[test]
    fn wrap_plain_text_leaves_short_text_unchanged() {
        assert_eq!(wrap_plain_text("short text", 100), "short text");
    }

    #[test]
    fn wrap_plain_text_wraps_long_paragraph_without_splitting_words() {
        let text = (0..40)
            .map(|n| format!("word{n:02}"))
            .collect::<Vec<_>>()
            .join(" ");

        let wrapped = wrap_plain_text(&text, 100);

        assert_ne!(wrapped, text);
        assert!(wrapped.lines().all(|line| line.chars().count() <= 100));
        assert_eq!(
            wrapped.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn wrap_plain_text_preserves_existing_newlines_and_blank_lines() {
        let text = "alpha\n\nsecond line needs wrapping here\nthird";

        assert_eq!(
            wrap_plain_text(text, 20),
            "alpha\n\nsecond line needs\nwrapping here\nthird"
        );
    }

    #[test]
    fn wrap_plain_text_hard_breaks_single_word_longer_than_width() {
        let text = "x".repeat(150);
        let wrapped = wrap_plain_text(&text, 100);
        let lines = wrapped.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].chars().count(), 100);
        assert_eq!(lines[1].chars().count(), 50);
    }

    #[test]
    fn wrap_plain_text_keeps_indented_overlong_lines_intact() {
        // A code-snippet line: leading indentation, then content past the
        // width. Must not emit an empty chunk or drop the indent.
        let text = format!("    let value = {};", "y".repeat(120));
        let wrapped = wrap_plain_text(&text, 100);

        assert!(wrapped.lines().all(|l| !l.trim().is_empty()));
        assert!(wrapped.starts_with("    let value"));
        assert!(wrapped.lines().all(|l| l.chars().count() <= 100));
    }
}
