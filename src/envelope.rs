//! The review envelope: Postil's stable output contract (version 1).
//!
//! The hosted worker, the Action, and `postil plan` all consume this format,
//! so changes here are breaking changes for the whole product.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "low" | "note" | "notice" => Some(Severity::Info),
            "warn" | "warning" | "medium" => Some(Severity::Warn),
            "error" | "high" | "critical" | "blocker" => Some(Severity::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Risk,
    HumanEscalation,
    Guardrail,
    Uncertainty,
    /// Violates the content policy: a fabricated/contradicted doc claim, a
    /// self-contradiction the same PR creates, authoring-process or AI
    /// narration residue, leaked conversation/transcript text, or (low
    /// severity) stale temporal/TODO residue and house style. Only emitted when
    /// `contentPolicy` is active for the repo.
    ContentPolicy,
}

/// Minimum confidence at which a human-escalation finding can block a merge.
///
/// Escalations are intentionally kept visible below this floor so reviewers can
/// inspect weak signals, but a very weak escalation must not turn into a hard
/// gate merely because of its kind or severity. A 0.30 floor is conservative:
/// it filters the near-zero boilerplate observed in production while retaining
/// uncertain but concrete concerns for human attention.
pub const HUMAN_ESCALATION_GATE_MIN_CONFIDENCE: f64 = 0.30;

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "risk" => Some(Kind::Risk),
            "humanescalation" => Some(Kind::HumanEscalation),
            "guardrail" => Some(Kind::Guardrail),
            "uncertainty" => Some(Kind::Uncertainty),
            "contentpolicy" => Some(Kind::ContentPolicy),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Risk => "risk",
            Kind::HumanEscalation => "humanEscalation",
            Kind::Guardrail => "guardrail",
            Kind::Uncertainty => "uncertainty",
            Kind::ContentPolicy => "contentPolicy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub path: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub severity: Severity,
    pub kind: Kind,
    pub confidence: f64,
    /// Original generator confidence before independent scorer calibration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub generator_confidence: Option<f64>,
    /// Independent scorer confidence. Final `confidence` is the lower value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_confidence: Option<f64>,
    /// Original generator kind before safe scorer escalation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub generator_kind: Option<Kind>,
    /// Independent scorer kind. It can only move final `kind` toward configured
    /// blocking kinds; de-escalation is ignored.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_kind: Option<Kind>,
    /// Short scorer rationale for confidence/kind calibration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_reason: Option<String>,
    /// Structured declaration for a finding whose conclusion depends on the
    /// complete repository at the reviewed head. Fresh model output must
    /// explicitly distinguish these claims from diff-local findings.
    #[serde(
        rename = "repositoryContext",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub repository_claim: Option<RepositoryClaim>,
    /// Optional deterministic source premise that Postil can verify against
    /// the immutable reviewed repository without compiling or executing it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub machine_claim: Option<MachineClaim>,
    /// Carried machine claims stay visible when current source cannot settle
    /// them, but they do not block until a fresh supported receipt exists.
    #[serde(skip_serializing_if = "is_false", default)]
    pub machine_claim_deferred: bool,
    pub title: String,
    pub body: String,
    /// Exact new-side text canonicalized from the cited prompt line. This is
    /// both the grounding proof and the durable fingerprint used across
    /// incremental runs.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence: Option<String>,
    /// Stable, engine-generated finding ID for deduplication and approval tracking.
    /// Hash of (head_sha, kind, normalized_path, normalized_line, normalized_title, duplicate_index).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MachineClaimKind {
    #[serde(rename = "rust.copy_move_out")]
    RustCopyMoveOut,
    #[serde(rename = "symbol.absent")]
    SymbolAbsent,
    #[serde(rename = "signature.mismatch")]
    SignatureMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MachineReceiver {
    None,
    Shared,
    Mutable,
    Value,
}

/// Bounded function shape accepted by `signature.mismatch`.
///
/// Parameter and return types use a deliberately small Rust type grammar:
/// paths, references without explicit lifetimes, tuples, slices, and generic
/// type arguments composed from those forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineSignature {
    pub receiver: MachineReceiver,
    #[serde(default)]
    pub parameters: Vec<String>,
    pub returns: String,
    #[serde(rename = "async", default, skip_serializing_if = "is_false")]
    pub is_async: bool,
    #[serde(rename = "unsafe", default, skip_serializing_if = "is_false")]
    pub is_unsafe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineClaim {
    pub kind: MachineClaimKind,
    /// Exact regular Rust source file in the immutable repository tree.
    pub path: String,
    /// Exact `crate::`-qualified type, item, trait member, or inherent method.
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected_signature: Option<MachineSignature>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaimVerificationState {
    Complete,
    Exhausted,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaimVerificationVerdict {
    Supported,
    Refuted,
    Unresolved,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaimEvidenceRole {
    CopyDerive,
    CopyImplementation,
    SymbolDefinition,
    Signature,
    SourceScope,
}

/// Hash-only source evidence. No repository source text is serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimVerificationEvidence {
    pub role: ClaimEvidenceRole,
    pub path_sha256: String,
    pub source_sha256: String,
    pub span_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedMachineClaim {
    pub claim_input_sha256: String,
    pub verdict: ClaimVerificationVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ClaimVerificationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimVerificationReceipt {
    pub verifier: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub head_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tree_sha256: Option<String>,
    pub state: ClaimVerificationState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<VerifiedMachineClaim>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepositoryClaimKind {
    Absence,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryClaim {
    #[serde(rename = "claim")]
    pub kind: RepositoryClaimKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<String>,
}

impl RepositoryClaim {
    pub fn typed_values(&self) -> impl Iterator<Item = (RepositorySearchQueryKind, &str)> {
        self.resources
            .iter()
            .map(|value| (RepositorySearchQueryKind::Resource, value.as_str()))
            .chain(
                self.values
                    .iter()
                    .map(|value| (RepositorySearchQueryKind::Value, value.as_str())),
            )
            .chain(
                self.versions
                    .iter()
                    .map(|value| (RepositorySearchQueryKind::Version, value.as_str())),
            )
            .chain(
                self.paths
                    .iter()
                    .map(|value| (RepositorySearchQueryKind::Path, value.as_str())),
            )
            .chain(
                self.identifiers
                    .iter()
                    .map(|value| (RepositorySearchQueryKind::Identifier, value.as_str())),
            )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepositorySearchState {
    Complete,
    #[default]
    Unavailable,
    Exhausted,
}

impl RepositorySearchState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Unavailable => "unavailable",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepositorySearchQueryKind {
    Resource,
    Value,
    Version,
    Path,
    Identifier,
}

impl RepositorySearchQueryKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Value => "value",
            Self::Version => "version",
            Self::Path => "path",
            Self::Identifier => "identifier",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositorySearchQuery {
    pub kind: RepositorySearchQueryKind,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositorySearchMatch {
    pub query_sha256: String,
    pub path: String,
    pub occurrences: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RepositorySearchEvidence {
    pub path: String,
    pub line: u32,
    pub source: String,
    pub query_sha256: Vec<String>,
}

/// Review-wide proof that repository-dependent claims were checked against one
/// immutable head snapshot. The receipt records outcomes, never operational
/// limit values or provider diagnostics that could leak into public output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositorySearchReceipt {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub head_sha: Option<String>,
    pub state: RepositorySearchState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tree_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<RepositorySearchQuery>,
    #[serde(default)]
    pub searched_blobs: u64,
    #[serde(default)]
    pub searched_bytes: u64,
    #[serde(default)]
    pub match_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_query_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<RepositorySearchMatch>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub matches_truncated: bool,
    #[serde(skip)]
    pub(crate) evidence: Vec<RepositorySearchEvidence>,
    #[serde(skip)]
    pub(crate) evidence_truncated: bool,
}

pub const FINDING_PUBLIC_TITLE_MAX_CHARS: usize = 160;
pub const FINDING_PUBLIC_BODY_MAX_CHARS: usize = 1_200;
pub const FINDING_PUBLIC_BODY_MAX_LINES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPublicationText {
    pub title: String,
    pub body: String,
}

/// Lossless publication projection for already-validated finding prose.
///
/// Validation happens before a finding is accepted. Publication sinks must not
/// repair, rewrite, or truncate model text because doing so can turn a complete
/// finding into misleading partial prose.
pub fn finding_publication_text(title: &str, body: &str) -> FindingPublicationText {
    FindingPublicationText {
        title: title.to_string(),
        body: body.to_string(),
    }
}

/// Forge-safe publication text for envelopes created under an older contract.
///
/// Fresh model findings are validated before they enter an envelope, so this
/// returns their text unchanged. Historical carried findings can predate that
/// validation. Those findings are neutralized at the publication boundary,
/// without shortening a sentence or changing the stored review record.
pub fn forge_safe_finding_publication_text(finding: &Finding) -> FindingPublicationText {
    if validate_finding_publication(finding).is_ok() {
        return finding_publication_text(&finding.title, &finding.body);
    }

    let mut normalized = finding.clone();
    normalize_finding_publication(&mut normalized);
    if validate_finding_publication(&normalized).is_ok() {
        return finding_publication_text(&normalized.title, &normalized.body);
    }

    let title = if normalized.title.is_empty()
        || normalized.title.chars().count() > FINDING_PUBLIC_TITLE_MAX_CHARS
    {
        "Review finding".to_string()
    } else {
        normalized.title
    };
    let body = normalized.body;
    let body_is_publishable = !body.is_empty()
        && body.trim() == body
        && body.chars().count() <= FINDING_PUBLIC_BODY_MAX_CHARS
        && body.lines().count() <= FINDING_PUBLIC_BODY_MAX_LINES
        && body
            .chars()
            .last()
            .is_some_and(|character| matches!(character, '.' | '!' | '?' | '。' | '！' | '？'));
    let body = if body_is_publishable {
        body
    } else {
        "This carried finding does not satisfy the publication contract. Open Review details for the complete record.".to_string()
    };

    let publication = FindingPublicationText { title, body };
    let mut projected = finding.clone();
    projected.title.clone_from(&publication.title);
    projected.body.clone_from(&publication.body);
    if validate_finding_publication(&projected).is_ok() {
        publication
    } else {
        FindingPublicationText {
            title: "Review finding".to_string(),
            body: "This carried finding does not satisfy the publication contract. Open Review details for the complete record.".to_string(),
        }
    }
}

pub fn validate_finding_publication(finding: &Finding) -> Result<(), String> {
    validate_finding_public_language(finding)?;
    let title = &finding.title;
    if title.is_empty() || title.trim() != title {
        return Err("finding title must be non-empty without surrounding whitespace".to_string());
    }
    if title.chars().count() > FINDING_PUBLIC_TITLE_MAX_CHARS {
        return Err(format!(
            "finding title exceeds {FINDING_PUBLIC_TITLE_MAX_CHARS} characters"
        ));
    }
    if title.contains(['\r', '\n']) || sanitize_publication_title(title) != *title {
        return Err("finding title must be safe single-line plain text".to_string());
    }

    let body = &finding.body;
    if body.is_empty() || body.trim() != body {
        return Err("finding body must be non-empty without surrounding whitespace".to_string());
    }
    if body.contains('\r') {
        return Err("finding body must use LF line endings".to_string());
    }
    if body.chars().count() > FINDING_PUBLIC_BODY_MAX_CHARS {
        return Err(format!(
            "finding body exceeds {FINDING_PUBLIC_BODY_MAX_CHARS} characters"
        ));
    }
    if body.lines().count() > FINDING_PUBLIC_BODY_MAX_LINES {
        return Err(format!(
            "finding body exceeds {FINDING_PUBLIC_BODY_MAX_LINES} lines"
        ));
    }
    if !body
        .chars()
        .last()
        .is_some_and(|character| matches!(character, '.' | '!' | '?' | '。' | '！' | '？'))
    {
        return Err("finding body must end with sentence punctuation".to_string());
    }
    for (index, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if line.chars().any(char::is_control)
            || sanitize_publication_line(line) != line
            || neutralize_unmatched_backticks(line) != line
            || markdown_fence_line(trimmed)
            || markdown_atx_heading(trimmed)
            || markdown_thematic_break(trimmed)
            || (index > 0 && markdown_setext_delimiter(trimmed))
            || markdown_table_delimiter(trimmed)
        {
            return Err("finding body contains unsafe publication markup".to_string());
        }
    }
    Ok(())
}

pub(crate) fn validate_finding_public_language(finding: &Finding) -> Result<(), String> {
    if publication_exposes_evidence_boundary(finding) {
        return Err(
            "finding text must state the concrete defect and correction without describing evidence-collection boundaries"
                .to_string(),
        );
    }
    Ok(())
}

pub(crate) fn publication_exposes_evidence_boundary(finding: &Finding) -> bool {
    publication_evidence_boundary_category(finding).is_some()
}

pub(crate) fn publication_evidence_boundary_category(finding: &Finding) -> Option<&'static str> {
    let prose = format!("{}. {}", finding.title, finding.body).to_ascii_lowercase();
    prose_evidence_boundary_category(&prose)
}

fn prose_exposes_evidence_boundary(prose: &str) -> bool {
    prose_evidence_boundary_category(prose).is_some()
}

fn prose_evidence_boundary_category(prose: &str) -> Option<&'static str> {
    let prose = prose.to_ascii_lowercase();
    if [
        "diff-grounded",
        "grounded in the diff",
        "in the diff",
        "in this diff",
        "the diff shows",
        "this diff shows",
        "the diff adds",
        "this diff adds",
        "the diff does not",
        "this diff does not",
        "the diff contains",
        "this diff contains",
        "supplied diff",
        "provided diff",
        "provided changes",
        "supplied changes",
        "available context",
        "supplied context",
    ]
    .iter()
    .any(|phrase| prose.contains(phrase))
    {
        Some("reviewArtifactPhrase")
    } else if prose_delegates_evidence_collection(&prose) {
        Some("delegatedEvidenceCollection")
    } else if prose_exposes_review_artifact_boundary(&prose) {
        Some("reviewArtifactBoundary")
    } else {
        None
    }
}

fn prose_delegates_evidence_collection(prose: &str) -> bool {
    prose
        .split(['.', '!', '?', ';', ':', '\n'])
        .map(|clause| {
            clause.trim_start_matches(|character: char| {
                character.is_whitespace()
                    || matches!(character, '-' | '*' | '+' | ')' | ']' | '`')
                    || character.is_ascii_digit()
            })
        })
        .filter(|clause| !clause.is_empty())
        .any(|clause| {
            let direct_search = clause.split(',').any(|segment| {
                let segment = segment.trim_start();
                let segment = segment
                    .strip_prefix("or ")
                    .or_else(|| segment.strip_prefix("and "))
                    .unwrap_or(segment);
                [
                    "search the repository",
                    "search the codebase",
                    "grep for ",
                    "run rg ",
                    "run `rg` ",
                    "inspect the repository",
                    "inspect the codebase",
                    "inspect the deployment manifest",
                ]
                .iter()
                .any(|phrase| segment.starts_with(phrase))
            });
            if direct_search {
                return true;
            }

            let delegated = [
                "please check",
                "please confirm",
                "please inspect",
                "please search",
                "please verify",
                "you should check",
                "you should confirm",
                "you should inspect",
                "you should search",
                "you should verify",
                "the author should check",
                "the author should confirm",
                "the author should inspect",
                "the author should search",
                "the author should verify",
                "reviewers should check",
                "reviewers should confirm",
                "reviewers should inspect",
                "reviewers should search",
                "reviewers should verify",
            ]
            .iter()
            .any(|phrase| clause.contains(phrase));
            if delegated {
                return true;
            }

            let investigative_scope = [
                " caller",
                " callers",
                " consumer",
                " consumers",
                " counterpart",
                " counterparts",
                " repository",
                " codebase",
                " unchanged",
                " elsewhere",
                " call path",
                " internally",
                " location",
                " other file",
                " other manifest",
                " whether",
            ]
            .iter()
            .any(|marker| clause.contains(marker));
            let imperative_investigation = clause.split(',').any(|segment| {
                let segment = segment.trim_start();
                let segment = segment
                    .strip_prefix("or ")
                    .or_else(|| segment.strip_prefix("and "))
                    .unwrap_or(segment);
                [
                    "check ",
                    "confirm ",
                    "inspect ",
                    "verify ",
                    "search for ",
                    "look for ",
                ]
                .iter()
                .any(|phrase| segment.starts_with(phrase))
            });
            investigative_scope && imperative_investigation
        })
}

fn prose_exposes_review_artifact_boundary(prose: &str) -> bool {
    let normalized = prose
        .replace(['’', '‘'], "'")
        .replace("doesn't", "does not")
        .replace("didn't", "did not")
        .replace("hasn't", "has not")
        .replace("haven't", "have not")
        .replace("isn't", "is not")
        .replace("can't", "cannot")
        .replace("couldn't", "could not")
        .replace("shouldn't", "should not")
        .replace("won't", "will not")
        .replace("wouldn't", "would not");
    normalized
        .split(['.', '!', '?', ';', ':', '\n'])
        .any(|clause| {
            let words = clause
                .split(|character: char| !character.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>();
            if words.contains(&"changeset")
                || words.windows(2).any(|pair| {
                    pair == ["change", "set"]
                        || pair == ["review", "input"]
                        || pair == ["review", "material"]
                })
            {
                return true;
            }
            let is_product_field = |word: Option<&str>| {
                word.is_some_and(|word| {
                    matches!(
                        word,
                        "api"
                            | "body"
                            | "description"
                            | "document"
                            | "endpoint"
                            | "event"
                            | "events"
                            | "handler"
                            | "metadata"
                            | "media"
                            | "method"
                            | "number"
                            | "operation"
                            | "parser"
                            | "request"
                            | "response"
                            | "representation"
                            | "route"
                            | "title"
                            | "type"
                            | "validation"
                            | "webhook"
                    )
                })
            };
            let is_http_patch_field = |word: Option<&str>| {
                word.is_some_and(|word| {
                    matches!(
                        word,
                        "api"
                            | "body"
                            | "document"
                            | "endpoint"
                            | "handler"
                            | "media"
                            | "method"
                            | "operation"
                            | "request"
                            | "response"
                            | "representation"
                            | "route"
                            | "type"
                            | "webhook"
                    )
                })
            };
            let artifact_suffix = |index: usize| {
                let index = if words.get(index) == Some(&"s") {
                    index + 1
                } else {
                    index
                };
                words.get(index).copied()
            };
            words.iter().enumerate().any(|(index, word)| {
                let patch_product_context = *word == "patch"
                    && (is_http_patch_field(artifact_suffix(index + 1))
                        || words.get(index + 1).is_some_and(|next| {
                            matches!(
                                *next,
                                "decoder"
                                    | "encoder"
                                    | "format"
                                    | "level"
                                    | "parser"
                                    | "release"
                                    | "series"
                                    | "version"
                            )
                        })
                        || words.get(index.wrapping_sub(1)).is_some_and(|previous| {
                            matches!(
                                *previous,
                                "dependency"
                                    | "http"
                                    | "json"
                                    | "kernel"
                                    | "merge"
                                    | "release"
                                    | "security"
                            )
                        }));
                let patch_artifact_context = *word == "patch"
                    && !patch_product_context
                    && (words.get(index + 1) == Some(&"s")
                        || words.get(index.wrapping_sub(1)).is_some_and(|previous| {
                            matches!(*previous, "a" | "current" | "the" | "this")
                        })
                        || words.get(index + 1).is_some_and(|next| {
                            matches!(
                                *next,
                                "adds"
                                    | "changes"
                                    | "contains"
                                    | "does"
                                    | "includes"
                                    | "omits"
                                    | "shows"
                                    | "updates"
                            )
                        }));
                patch_artifact_context
                    || (matches!(*word, "mr" | "pr")
                        && !is_product_field(artifact_suffix(index + 1)))
                    || (matches!(*word, "pull" | "merge")
                        && words.get(index + 1) == Some(&"request")
                        && !is_product_field(artifact_suffix(index + 2)))
            })
        })
}

/// Normalize presentation-only hazards in fresh model prose before admission.
///
/// This projection does not truncate prose or repair semantic requirements
/// such as sentence completeness and size limits. Those remain validation
/// errors.
pub(crate) fn normalize_finding_publication(finding: &mut Finding) {
    if matches!(
        prose_evidence_boundary_category(&finding.title),
        Some("reviewArtifactPhrase" | "reviewArtifactBoundary")
    ) {
        finding.title = normalize_review_artifact_references(&finding.title);
    }
    if matches!(
        prose_evidence_boundary_category(&finding.body),
        Some("reviewArtifactPhrase" | "reviewArtifactBoundary")
    ) {
        finding.body = normalize_review_artifact_references(&finding.body);
    }
    finding.title = sanitize_publication_title(&finding.title);
    finding.body = finding
        .body
        .lines()
        .enumerate()
        .map(|(index, line)| normalize_publication_body_line(line, index))
        .collect::<Vec<_>>()
        .join("\n");
}

fn normalize_review_artifact_references(value: &str) -> String {
    [
        ("grounded in the diff", "established by the changed code"),
        ("in this diff", "in this change"),
        ("in the diff", "in the changed code"),
        ("this diff", "this change"),
        ("the diff", "the changed code"),
        ("supplied diff", "changed code"),
        ("provided diff", "changed code"),
        ("provided changes", "changed code"),
        ("supplied changes", "changed code"),
        ("available context", "changed code"),
        ("supplied context", "changed code"),
        ("diff-grounded", "directly evidenced"),
        ("this pull request", "this change"),
        ("the pull request", "the change"),
        ("a pull request", "a change"),
        ("this merge request", "this change"),
        ("the merge request", "the change"),
        ("a merge request", "a change"),
        ("this patch", "this change"),
        ("the patch", "the change"),
        ("a current patch", "the current change"),
        ("current patch", "current change"),
        ("this pr", "this change"),
        ("the pr", "the change"),
        ("a pr", "a change"),
        ("this mr", "this change"),
        ("the mr", "the change"),
        ("a mr", "a change"),
        ("changeset", "change"),
        ("change-set", "change"),
        ("change set", "change"),
        ("review input", "changed code"),
        ("review material", "changed code"),
    ]
    .into_iter()
    .fold(value.to_string(), |text, (phrase, replacement)| {
        replace_review_artifact_reference(&text, phrase, replacement)
    })
}

fn replace_review_artifact_reference(value: &str, needle: &str, replacement: &str) -> String {
    let lowercase = value.to_ascii_lowercase();
    let mut output = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let needle_bytes = needle.as_bytes();
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut output_cursor = 0usize;
    let mut search_cursor = 0usize;
    while let Some(relative) = lowercase[search_cursor..].find(needle) {
        let start = search_cursor + relative;
        let end = start + needle.len();
        let starts_inside_word = needle_bytes.first().copied().is_some_and(is_word)
            && start > 0
            && bytes.get(start - 1).copied().is_some_and(is_word);
        let ends_inside_word = needle_bytes.last().copied().is_some_and(is_word)
            && bytes.get(end).copied().is_some_and(is_word);
        if starts_inside_word || ends_inside_word {
            search_cursor = start + 1;
            continue;
        }
        if review_artifact_reference_has_product_suffix(value, needle, end) {
            search_cursor = end;
            continue;
        }
        output.push_str(&value[output_cursor..start]);
        let starts_sentence = value[..start]
            .chars()
            .rev()
            .find(|character| !character.is_whitespace())
            .is_none_or(|character| matches!(character, '.' | '!' | '?' | '。' | '！' | '？'));
        if starts_sentence {
            let mut characters = replacement.chars();
            if let Some(first) = characters.next() {
                output.push(first.to_ascii_uppercase());
                output.extend(characters);
            }
        } else {
            output.push_str(replacement);
        }
        output_cursor = end;
        search_cursor = end;
    }
    output.push_str(&value[output_cursor..]);
    output
}

fn review_artifact_reference_has_product_suffix(value: &str, needle: &str, end: usize) -> bool {
    let artifact = needle.split_ascii_whitespace().last().unwrap_or_default();
    if !matches!(artifact, "patch" | "pr" | "mr" | "request") {
        return false;
    }
    let mut suffix = value[end..].trim_start();
    let lowercase_suffix = suffix.to_ascii_lowercase();
    if lowercase_suffix.starts_with("'s") {
        suffix = suffix[2..].trim_start();
    } else if lowercase_suffix.starts_with("’s") {
        suffix = suffix["’s".len()..].trim_start();
    }
    let word = suffix
        .trim_start_matches(|character: char| !character.is_ascii_alphanumeric())
        .split(|character: char| !character.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        word.as_str(),
        "api"
            | "body"
            | "decoder"
            | "description"
            | "document"
            | "encoder"
            | "endpoint"
            | "event"
            | "events"
            | "format"
            | "handler"
            | "level"
            | "media"
            | "metadata"
            | "method"
            | "number"
            | "operation"
            | "parser"
            | "release"
            | "request"
            | "response"
            | "representation"
            | "route"
            | "series"
            | "title"
            | "type"
            | "validation"
            | "version"
            | "webhook"
    )
}

fn normalize_publication_body_line(value: &str, index: usize) -> String {
    let line = neutralize_unmatched_backticks(&sanitize_publication_line(value));
    let trimmed = line.trim();
    let block_markup = markdown_fence_line(trimmed)
        || markdown_atx_heading(trimmed)
        || markdown_thematic_break(trimmed)
        || (index > 0 && markdown_setext_delimiter(trimmed))
        || markdown_table_delimiter(trimmed);
    if !block_markup {
        return line;
    }

    let first_content = line
        .char_indices()
        .find_map(|(offset, character)| (!character.is_whitespace()).then_some(offset))
        .unwrap_or(line.len());
    let mut normalized = String::with_capacity(line.len() + 1);
    normalized.push_str(&line[..first_content]);
    normalized.push('\\');
    normalized.push_str(&line[first_content..]);
    neutralize_unmatched_backticks(&sanitize_publication_line(&normalized))
}

fn sanitize_publication_title(value: &str) -> String {
    let single_line = value
        .chars()
        .map(|character| {
            if character.is_whitespace() || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let line =
        sanitize_publication_plain_line(&single_line).replace(['`', '*', '[', ']', '#'], " ");
    let characters = line.chars().collect::<Vec<_>>();
    let line = characters
        .iter()
        .enumerate()
        .map(|(index, character)| {
            if *character != '_'
                || (index > 0
                    && index + 1 < characters.len()
                    && characters[index - 1].is_alphanumeric()
                    && characters[index + 1].is_alphanumeric())
            {
                *character
            } else {
                ' '
            }
        })
        .collect::<String>();
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sanitize_publication_line(value: &str) -> String {
    let text = escape_unsafe_unicode(value)
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .replace('@', "＠");
    let text = escape_html_outside_inline_code(&text);
    neutralize_markdown_images(&text)
}

fn sanitize_publication_plain_line(value: &str) -> String {
    let text = escape_unsafe_unicode(value)
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .replace('@', "＠")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    neutralize_markdown_images(&text)
}

fn escape_html_outside_inline_code(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < characters.len() {
        if characters[cursor] != '`' {
            match characters[cursor] {
                '<' => output.push_str("&lt;"),
                '>' => output.push_str("&gt;"),
                character => output.push(character),
            }
            cursor += 1;
            continue;
        }

        let preceding_backslashes = characters[..cursor]
            .iter()
            .rev()
            .take_while(|character| **character == '\\')
            .count();
        let width = characters[cursor..]
            .iter()
            .take_while(|character| **character == '`')
            .count();
        if preceding_backslashes % 2 == 1 {
            output.extend(characters[cursor..cursor + width].iter());
            cursor += width;
            continue;
        }

        let mut candidate = cursor + width;
        let mut closing = None;
        while candidate < characters.len() {
            if characters[candidate] != '`' {
                candidate += 1;
                continue;
            }
            let candidate_width = characters[candidate..]
                .iter()
                .take_while(|character| **character == '`')
                .count();
            if candidate_width == width {
                closing = Some(candidate + width);
                break;
            }
            candidate += candidate_width;
        }
        if let Some(end) = closing {
            output.extend(characters[cursor..end].iter());
            cursor = end;
        } else {
            output.extend(characters[cursor..cursor + width].iter());
            cursor += width;
        }
    }
    output
}

fn escape_unsafe_unicode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        ) {
            output.push_str(&format!("[U+{:04X}]", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn neutralize_markdown_images(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut output = String::with_capacity(value.len());
    for (index, character) in characters.iter().enumerate() {
        if *character == '!' && characters.get(index + 1) == Some(&'[') {
            let preceding_backslashes = characters[..index]
                .iter()
                .rev()
                .take_while(|candidate| **candidate == '\\')
                .count();
            if preceding_backslashes % 2 == 0 {
                output.push('\\');
            }
        }
        output.push(*character);
    }
    output
}

fn markdown_fence_line(value: &str) -> bool {
    let value = value.trim_start();
    value.starts_with("```") || value.starts_with("~~~")
}

fn markdown_atx_heading(value: &str) -> bool {
    let hashes = value
        .chars()
        .take_while(|character| *character == '#')
        .count();
    (1..=6).contains(&hashes) && value.chars().nth(hashes).is_some_and(char::is_whitespace)
}

fn markdown_setext_delimiter(value: &str) -> bool {
    value.len() >= 3
        && (value.chars().all(|character| character == '=')
            || value.chars().all(|character| character == '-'))
}

fn markdown_thematic_break(value: &str) -> bool {
    for marker in ['-', '*', '_'] {
        let mut count = 0usize;
        let valid = value.chars().all(|character| {
            if character == marker {
                count += 1;
                true
            } else {
                character == ' ' || character == '\t'
            }
        });
        if valid && count >= 3 {
            return true;
        }
    }
    false
}

fn markdown_table_delimiter(value: &str) -> bool {
    let value = value.strip_prefix('|').unwrap_or(value);
    let value = value.strip_suffix('|').unwrap_or(value);
    let cells: Vec<&str> = value.split('|').collect();
    cells.len() >= 2
        && cells.iter().all(|cell| {
            let cell = cell.trim();
            let cell = cell.strip_prefix(':').unwrap_or(cell);
            let cell = cell.strip_suffix(':').unwrap_or(cell);
            cell.len() >= 3 && cell.chars().all(|character| character == '-')
        })
}

fn neutralize_unmatched_backticks(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < characters.len() {
        if characters[cursor] != '`' {
            output.push(characters[cursor]);
            cursor += 1;
            continue;
        }
        let width = characters[cursor..]
            .iter()
            .take_while(|character| **character == '`')
            .count();
        let mut candidate = cursor + width;
        let mut closing = None;
        while candidate < characters.len() {
            if characters[candidate] != '`' {
                candidate += 1;
                continue;
            }
            let candidate_width = characters[candidate..]
                .iter()
                .take_while(|character| **character == '`')
                .count();
            if candidate_width == width {
                closing = Some(candidate + width);
                break;
            }
            candidate += candidate_width;
        }
        if let Some(end) = closing {
            output.extend(characters[cursor..end].iter());
            cursor = end;
        } else {
            let preceding_backslashes = characters[..cursor]
                .iter()
                .rev()
                .take_while(|character| **character == '\\')
                .count();
            if preceding_backslashes % 2 == 0 {
                output.push('\\');
            }
            output.extend(characters[cursor..cursor + width].iter());
            cursor += width;
        }
    }
    output
}

/// Why an otherwise grounded finding did not reach the public review.
///
/// This additive v1 field lets trusted dashboards and compact forge summaries
/// explain policy decisions without reconstructing them from mutable config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SuppressionReason {
    NonActionable,
    Ignored,
    BelowSeverity,
    BelowConfidence,
    MaxFindings,
    /// The finding's prose names a construct that the diff places elsewhere on
    /// the same path than the line it cites. A reader cannot verify a claim
    /// against the wrong code, so the finding is not publishable as written.
    AnchorMismatch,
    /// The finding restates a claim that another, retained finding already
    /// makes about a different location. Only the retained copy is published,
    /// and it names the other affected locations.
    DuplicateRootCause,
    /// A content-policy claim built on top of a finding that was itself
    /// suppressed as mis-anchored. It inherits the misreading and cannot stand
    /// on its own.
    DerivedFromSuppressed,
    /// A repository-wide absence or mismatch claim was not supported by one
    /// complete immutable-head receipt, or a positive counterexample refuted it.
    RepositoryClaimUnsupported,
    /// A deterministic exact-head source proof contradicted the claim.
    MachineClaimRefuted,
    /// The source verifier could not produce a bounded conclusive proof.
    MachineClaimUnverified,
    /// Compact lockfile metadata cannot establish the claimed platform, OS,
    /// CPU architecture, ABI, or runtime support conclusion.
    LockfilePlatformEvidenceInsufficient,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub reason: SuppressionReason,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
    pub suppressed: u32,
    /// Findings the model reported that did not cite a changed line and were
    /// dropped. Nonzero values are a model-quality signal worth tracking.
    #[serde(default)]
    pub ungrounded: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gate {
    /// Severity at or above which the gate check fails. "never" disables the gate.
    pub fail_on: String,
    pub failing: bool,
    /// Finding kinds that block the gate regardless of severity.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub block_on_kinds: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Exact provider-billed cost represented by this in-memory aggregate.
    /// Durable attribution is emitted per model through `ModelUsage`.
    #[serde(skip)]
    pub cost_micros: Option<u64>,
    /// Exact provider-reported decimal dollars. This remains in memory for
    /// aggregation; durable call records serialize its canonical decimal text.
    #[serde(skip)]
    pub provider_cost: Option<ProviderCost>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCost {
    coefficient: u128,
    scale: u32,
}

impl ProviderCost {
    const MAX_INPUT_BYTES: usize = 128;
    const MAX_SCALE: u32 = 18;

    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty()
            || raw.len() > Self::MAX_INPUT_BYTES
            || raw.starts_with('-')
            || raw.starts_with('+')
        {
            return None;
        }
        let (base, exponent) =
            raw.split_once(['e', 'E'])
                .map_or((raw, 0i32), |(base, exponent)| {
                    exponent
                        .parse::<i32>()
                        .ok()
                        .map(|value| (base, value))
                        .unwrap_or(("", 0))
                });
        if base.is_empty() {
            return None;
        }
        let mut digits = String::new();
        let mut fractional = 0i32;
        let mut seen_dot = false;
        for character in base.chars() {
            match character {
                '0'..='9' => {
                    digits.push(character);
                    if seen_dot {
                        fractional = fractional.checked_add(1)?;
                    }
                }
                '.' if !seen_dot => seen_dot = true,
                _ => return None,
            }
        }
        if digits.is_empty() {
            return None;
        }
        let mut coefficient = digits.parse::<u128>().ok()?;
        if coefficient == 0 {
            return Some(Self {
                coefficient: 0,
                scale: 0,
            });
        }
        let adjusted_scale = fractional.checked_sub(exponent)?;
        let mut scale = if adjusted_scale < 0 {
            let zeros = u32::try_from(-adjusted_scale).ok()?;
            coefficient = coefficient.checked_mul(10u128.checked_pow(zeros)?)?;
            0
        } else {
            u32::try_from(adjusted_scale).ok()?
        };
        while scale > 0 && coefficient % 10 == 0 {
            coefficient /= 10;
            scale -= 1;
        }
        if scale > Self::MAX_SCALE {
            return None;
        }
        Some(Self { coefficient, scale })
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let scale = self.scale.max(other.scale);
        let left = self
            .coefficient
            .checked_mul(10u128.checked_pow(scale - self.scale)?)?;
        let right = other
            .coefficient
            .checked_mul(10u128.checked_pow(scale - other.scale)?)?;
        let mut value = Self {
            coefficient: left.checked_add(right)?,
            scale,
        };
        while value.scale > 0 && value.coefficient.is_multiple_of(10) {
            value.coefficient /= 10;
            value.scale -= 1;
        }
        Some(value)
    }

    pub fn micros_rounded(self) -> Option<u64> {
        let micros = if self.scale <= 6 {
            self.coefficient
                .checked_mul(10u128.checked_pow(6 - self.scale)?)?
        } else {
            let divisor = 10u128.checked_pow(self.scale - 6)?;
            let quotient = self.coefficient / divisor;
            let remainder = self.coefficient % divisor;
            quotient.checked_add(u128::from(remainder.saturating_mul(2) >= divisor))?
        };
        u64::try_from(micros).ok()
    }

    pub fn micros_ceiling(self) -> Option<u64> {
        let micros = if self.scale <= 6 {
            self.coefficient
                .checked_mul(10u128.checked_pow(6 - self.scale)?)?
        } else {
            let divisor = 10u128.checked_pow(self.scale - 6)?;
            self.coefficient.div_ceil(divisor)
        };
        u64::try_from(micros).ok()
    }
}

impl std::fmt::Display for ProviderCost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scale == 0 {
            return write!(formatter, "{}", self.coefficient);
        }
        let digits = self.coefficient.to_string();
        let scale = self.scale as usize;
        if digits.len() <= scale {
            write!(
                formatter,
                "0.{}{}",
                "0".repeat(scale - digits.len()),
                digits
            )
        } else {
            let split = digits.len() - scale;
            write!(formatter, "{}.{}", &digits[..split], &digits[split..])
        }
    }
}

/// Token usage attributed to one provider call. Entries include successful
/// generation/scoring calls and failed calls, so audit and hosted accounting
/// preserve the exact call boundary instead of folding repairs and retries
/// into a model-level total.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    pub model: String,
    /// Product role that caused this provider call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ModelUsageRole>,
    /// Logical stage within the role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ModelUsagePhase>,
    /// One-based provider HTTP call across this role/model invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_ordinal: Option<u32>,
    /// One-based transport attempt within the logical phase call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Exact provider-billed cost when supplied by the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micros: Option<u64>,
    /// Canonical provider-reported decimal dollars, without binary floating-
    /// point conversion. `costMicros` remains a rounded display/index value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_provider_decimal: Option<String>,
    /// Explains whether cost came from the provider or is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_source: Option<ModelUsageCostSource>,
    /// False when the provider call returned no authoritative usage record.
    #[serde(default)]
    pub accounting_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelUsageRole {
    ReviewPlanner,
    ReviewGenerator,
    FindingScorer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelUsagePhase {
    Initial,
    SchemaRepair,
    SemanticRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelUsageCostSource {
    ProviderReported,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelIncidentPhase {
    Planner,
    Review,
    Scorer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelIncidentCategory {
    ProviderError,
    InvalidOutput,
    Timeout,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelIncidentRecovery {
    Repair,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelIncident {
    pub phase: ModelIncidentPhase,
    pub category: ModelIncidentCategory,
    pub recovered: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recovery: Option<ModelIncidentRecovery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReviewCoverageMode {
    Exhaustive,
    Bounded,
}

impl ReviewCoverageMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::Bounded => "bounded",
        }
    }
}

/// Audit record for the source-evidence batches sent to review models. Synthesis
/// requests are excluded from both counts. This additive v1 field lets stored
/// envelopes without coverage accounting deserialize with `review_coverage = None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewCoverage {
    pub mode: ReviewCoverageMode,
    pub selected_batches: u32,
    pub total_batches: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub planner_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReviewCoverageReceipt>,
}

/// Compact durable commitment to the deterministic large-review plan. The
/// hunk-level receipt remains internal and bounded; these counts plus its hash
/// make the exact plan auditable without inflating every stored envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewCoverageReceipt {
    pub plan_sha256: String,
    pub total_hunks: u32,
    pub direct_hunks: u32,
    pub semantic_hunks: u32,
    pub unreviewed_hunks: u32,
}

impl ReviewCoverage {
    pub fn not_reviewed_directly_batches(&self) -> u32 {
        if self.mode == ReviewCoverageMode::Bounded {
            self.total_batches.saturating_sub(self.selected_batches)
        } else {
            0
        }
    }
}

/// Conservative logical hosted-provider exposure reserved before the first model call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewAdmission {
    pub provider_attempts: u32,
    pub serialized_input_bytes: u64,
    pub output_tokens: u64,
    pub projected_cost_micros: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub version: u32,
    pub summary: String,
    pub silent: bool,
    pub findings: Vec<Finding>,
    /// Grounded findings hidden by review policy. Older v1 envelopes omit this
    /// field, so readers must treat an absent value as an empty list.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub resolved: Vec<Finding>,
    pub counts: Counts,
    /// Counts of finding confidences in [0-.2, .2-.4, .4-.6, .6-.8, .8-1].
    pub confidence_buckets: [u32; 5],
    pub gate: Gate,
    pub model_used: String,
    /// Independent second-model scorer used for kept findings.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_model: Option<String>,
    /// Nonempty when scoring was attempted but all scorer models errored.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_error: Option<String>,
    /// Findings where scorer confidence differed by >= 0.4 or kind disagreed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scorer_disagreements: Option<u32>,
    pub usage: Usage,
    /// Per-model usage for exact provider pricing. Older v1 envelopes omit
    /// this additive field and are handled conservatively by the control plane.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_usage: Vec<ModelUsage>,
    /// Safe operational model signals for monitoring. No raw provider detail
    /// or model-generated content is stored here.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_incidents: Vec<ModelIncident>,
    /// Source-evidence batch selection used for this review. An absent value
    /// represents a v1 envelope without coverage accounting.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub review_coverage: Option<ReviewCoverage>,
    /// Conservative hosted exposure computed from the exact serialized request
    /// plan. It is absent for BYOK and historical envelopes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub review_admission: Option<ReviewAdmission>,
    /// Complete-head repository search performed for structured absence and
    /// mismatch claims. Historical v1 envelopes deserialize as unavailable.
    #[serde(default)]
    pub repository_search: RepositorySearchReceipt,
    /// Bounded deterministic source verification for typed machine claims.
    /// Historical v1 envelopes omit this additive field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub claim_verification: Option<ClaimVerificationReceipt>,
    /// False when any sent provider request can have unknown billed usage,
    /// including timeouts and ambiguous transport failures.
    #[serde(default)]
    pub usage_accounting_complete: bool,
    /// Wall-clock duration of the review engine run in milliseconds.
    #[serde(default)]
    pub duration_ms: u64,
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub since_sha: Option<String>,
}

impl Envelope {
    pub fn counts_of(findings: &[Finding], suppressed: u32) -> Counts {
        let mut c = Counts {
            suppressed,
            ..Default::default()
        };
        for f in findings {
            match f.severity {
                Severity::Info => c.info += 1,
                Severity::Warn => c.warn += 1,
                Severity::Error => c.error += 1,
            }
        }
        c
    }

    pub fn buckets_of(findings: &[Finding]) -> [u32; 5] {
        let mut b = [0u32; 5];
        for f in findings {
            let idx = (f.confidence.clamp(0.0, 1.0) * 5.0).floor() as usize;
            b[idx.min(4)] += 1;
        }
        b
    }
}

/// Apply the serialized gate contract to one finding.
///
/// Keeping this beside the envelope makes live reviews, stored-envelope replay,
/// and forge summaries share exactly the same blocking semantics.
pub fn finding_blocks_gate(
    finding: &Finding,
    fail_on: &str,
    block_on_kinds: &[String],
    provider_error_is_advisory: bool,
) -> bool {
    if finding.machine_claim_deferred {
        return false;
    }
    if fail_on.eq_ignore_ascii_case("never") {
        return false;
    }
    if finding.kind == Kind::HumanEscalation
        && finding.confidence < HUMAN_ESCALATION_GATE_MIN_CONFIDENCE
    {
        return false;
    }

    let severity_blocks = if provider_error_is_advisory {
        false
    } else {
        Severity::parse(fail_on).is_some_and(|threshold| finding.severity >= threshold)
    };
    let kind_blocks = block_on_kinds
        .iter()
        .any(|kind| Kind::parse(kind).is_some_and(|kind| kind == finding.kind));
    severity_blocks || kind_blocks
}

/// Path marker for synthetic unusable-output findings (the model answered but
/// the output could not be validated). A malicious diff can induce this class
/// via prompt injection, so it always fails the gate, even under
/// `gate.onError: advisory`.
pub const OPERATIONAL_PATH: &str = ".postil/model-output";

/// Path marker for synthetic provider findings (endpoint unreachable, HTTP
/// errors, timeouts): outage-class failures the diff content cannot induce.
/// This is the only class `gate.onError: advisory` lets stand aside.
pub const PROVIDER_PATH: &str = ".postil/provider";

/// Reserved synthetic path for content-policy findings against the PR
/// title/description. The title/body are not part of the diff, so they have no
/// real (path, line) to ground against; when content policy is active they are
/// rendered as a numbered block under this path and grounded against its line
/// range. Only `kind: contentPolicy` findings may cite it. Findings here cannot
/// be posted as inline code annotations (there is no file line); they are
/// surfaced in the check-run summary and PR comment body instead.
pub const PR_DESCRIPTION_PATH: &str = ".postil/pr-description";
/// Reserved path for numbered change metadata that has no valid new-side line,
/// including deletions, binary changes, renames, mode changes, and compact
/// lockfile evidence.
pub const CHANGE_METADATA_PATH: &str = ".postil/change-metadata";
pub const DIFF_PATH: &str = ".postil/diff";

/// Exact virtual anchors emitted by Postil itself. Repository files under the
/// `.postil/` directory are ordinary reviewable files and must never be swept
/// into this classification by prefix.
pub fn is_reserved_anchor(path: &str) -> bool {
    matches!(
        path,
        OPERATIONAL_PATH | PROVIDER_PATH | PR_DESCRIPTION_PATH | CHANGE_METADATA_PATH | DIFF_PATH
    )
}

/// Virtual findings that describe only the current run's operational state.
/// These never carry into a later review. Reviewable PR and change metadata
/// anchors are reserved for forge publication but remain durable baselines.
pub fn is_ephemeral_anchor(path: &str) -> bool {
    matches!(path, OPERATIONAL_PATH | PROVIDER_PATH | DIFF_PATH)
}

/// Internal reason a review stopped before it could issue a trustworthy
/// verdict. Forge adapters expose only generic check text for these findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncompleteReviewReason {
    IncompleteInput,
    LocalIncrementalFullComparisonUnavailable,
    ReservedInput,
    InsufficientContextBudget,
    InvalidModelFanOut,
}

pub(crate) fn incomplete_review_finding(reason: IncompleteReviewReason) -> Finding {
    let body = match reason {
        IncompleteReviewReason::IncompleteInput => {
            "Postil could not acquire the complete immutable change from the forge, so no clean verdict was issued. Retry after the forge can supply it."
        }
        IncompleteReviewReason::LocalIncrementalFullComparisonUnavailable => {
            "An incremental local review touched the file of a carried error finding, but this input cannot reconstruct the complete comparison needed to re-adjudicate it. No clean verdict was issued. Review the pull request or rerun locally with `--base <ref>` without `--since-sha`."
        }
        IncompleteReviewReason::ReservedInput => {
            "The change uses a path reserved for Postil's synthetic review evidence, so repository content cannot be separated safely from operational findings. No clean verdict was issued. Rename the conflicting path before retrying."
        }
        IncompleteReviewReason::InsufficientContextBudget => {
            "The serialized shared review context leaves insufficient room for reviewable change evidence within the configured model's conservative context limit. No clean verdict was issued. Reduce the shared review context or select a model with a larger context before retrying."
        }
        IncompleteReviewReason::InvalidModelFanOut => {
            "The configured model fan-out is empty or exceeds Postil's per-request model limit. No clean verdict was issued. Configure a supported review model fan-out before retrying."
        }
    };
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Review incomplete".to_string(),
        body: body.to_string(),
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

/// The synthetic finding emitted when a deterministic large review runs its
/// complete selected schedule but the hard request limit leaves normalized
/// hunks without direct or exact semantic coverage.
pub(crate) fn incomplete_large_review_finding(unreviewed_hunks: u32) -> Finding {
    let noun = if unreviewed_hunks == 1 {
        "hunk"
    } else {
        "hunks"
    };
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Large review coverage is incomplete".to_string(),
        body: format!(
            "Deterministic large-review coverage left {unreviewed_hunks} normalized {noun} \
             unreviewed within the hard request limit. Findings from completed requests \
             remain available, but this result cannot be trusted as a pass."
        ),
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

/// The synthetic finding emitted when a review stopped before producing a
/// verdict for a reason that is not model output: an admission limit, a
/// configuration problem, or an unexpected internal error. Postil still fails
/// closed, but the cause is reported as itself. Attributing such a failure to
/// model output sends every reader looking at the model when the model was
/// never called.
pub fn operational_failure_finding(detail: &str) -> Finding {
    let detail = detail.trim();
    let opening = "Postil could not complete this review, so no verdict was issued.";
    let body = if detail.is_empty() || prose_exposes_evidence_boundary(detail) {
        opening.to_string()
    } else {
        format!("{opening}\n\nDetail: {detail}")
    };
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Review could not be completed".to_string(),
        body,
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

/// The synthetic finding emitted when the model produced unusable output.
/// Postil fails closed: a review that could not be trusted is an error, not a pass.
pub fn fail_closed_finding(detail: &str) -> Finding {
    let detail = if prose_exposes_evidence_boundary(detail) {
        "The model response did not satisfy the evidence-validation contract."
    } else {
        detail
    };
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Model output could not be validated".to_string(),
        body: format!(
            "Postil could not validate the configured model response against cited code \
             evidence. No clean verdict was issued.\n\nDetail: {detail}"
        ),
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

/// The synthetic finding emitted when the model narrated merge-relevant risk
/// in its summary while reporting zero structured findings. The contradiction
/// means the output cannot be trusted as a pass; the narration is preserved so
/// the concern is not silently dropped. Uses OPERATIONAL_PATH: a malicious
/// diff can induce this shape via prompt injection, so it never bypasses the
/// gate.
pub fn narrated_risk_finding(summary: &str) -> Finding {
    let quoted: String = summary.lines().map(|l| format!("> {l}\n")).collect();
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Model narrated risk without structured findings".to_string(),
        body: format!(
            "The model's summary describes merge-relevant risk but it reported no \
             structured findings, so the review cannot be trusted as a pass. Postil is \
             failing closed instead of posting a clean status above contradictory prose.\n\n\
             Narrated summary:\n\n{quoted}\n\
             Re-run the review. If the contradiction persists, keep the gate failed and \
             obtain an independent review before merging."
        ),
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

/// The synthetic finding emitted when the provider could not be reached at all.
pub fn provider_error_finding(_detail: &str) -> Finding {
    Finding {
        path: PROVIDER_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Model provider unavailable".to_string(),
        body: "Postil could not complete the model request and is failing closed rather \
             than passing unreviewed code. The failure is available to Postil operators."
            .to_string(),
        evidence: None,
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
        repository_claim: None,
        machine_claim: None,
        machine_claim_deferred: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_review_reasons_have_distinct_operational_guidance() {
        let cases = [
            (
                IncompleteReviewReason::IncompleteInput,
                "complete immutable change",
            ),
            (
                IncompleteReviewReason::LocalIncrementalFullComparisonUnavailable,
                "complete comparison",
            ),
            (IncompleteReviewReason::ReservedInput, "path reserved"),
            (
                IncompleteReviewReason::InsufficientContextBudget,
                "serialized shared review context",
            ),
            (IncompleteReviewReason::InvalidModelFanOut, "model fan-out"),
        ];

        for (reason, expected) in cases {
            let finding = incomplete_review_finding(reason);
            assert_eq!(finding.title, "Review incomplete");
            assert!(finding.body.contains(expected), "body: {}", finding.body);
            assert!(!finding.body.contains("change did not fit"));
        }
    }

    #[test]
    fn fail_closed_finding_uses_concrete_evidence_validation_language() {
        let finding = fail_closed_finding(
            "model reported 2 finding(s) without a valid code-evidence citation.",
        );
        assert_eq!(
            finding.body,
            "Postil could not validate the configured model response against cited code evidence. No clean verdict was issued.\n\nDetail: model reported 2 finding(s) without a valid code-evidence citation."
        );
        assert_eq!(validate_finding_public_language(&finding), Ok(()));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn incomplete_large_review_finding_is_publishable_and_fail_closed() {
        let finding = incomplete_large_review_finding(3);
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.path, OPERATIONAL_PATH);
        assert!(finding.body.contains("left 3 normalized hunks unreviewed"));
        assert_eq!(validate_finding_public_language(&finding), Ok(()));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn fail_closed_finding_neutralizes_evidence_boundary_details() {
        let finding = fail_closed_finding("none grounded in the diff");
        assert_eq!(
            finding.body,
            "Postil could not validate the configured model response against cited code evidence. No clean verdict was issued.\n\nDetail: The model response did not satisfy the evidence-validation contract."
        );
        assert_eq!(validate_finding_public_language(&finding), Ok(()));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn publication_rejects_review_material_synonyms() {
        let bodies = [
            "The patch does not demonstrate that the guard runs before execution; move it above `exec()`.",
            "This changeset shows only the call; restore the authorization guard.",
            "The pull request does not contain the required deny rule; add it last.",
            "The merge request does not contain the required deny rule; add it last.",
            "The MR does not contain the required deny rule; add it last.",
            "The PR does not show the matching deployment update; align the versions.",
            "The PR includes only the call; restore the authorization guard.",
            "The PR omits unchanged callers; preserve their contract.",
            "The pull-request doesn't show callers; preserve their contract.",
            "The change-set doesn't contain the required guard.",
            "The review-material can't establish ordering.",
            "A current patch doesn't show the deployment update.",
            "The patch's description omits rollback steps; add them.",
            "The patch’s description omits rollback steps; add them.",
            "The PR updates only the backup image while CephCluster remains on v19.2.3.",
        ];

        for body in bodies {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = body.into();
            assert!(
                publication_exposes_evidence_boundary(&finding),
                "body: {body}"
            );
            assert!(
                validate_finding_publication(&finding).is_err(),
                "body: {body}"
            );
            let safe = forge_safe_finding_publication_text(&finding);
            assert!(!safe.body.to_ascii_lowercase().contains("patch"));
            let mut projected = finding.clone();
            projected.title = safe.title;
            projected.body = safe.body;
            assert_eq!(validate_finding_publication(&projected), Ok(()));
        }
    }

    #[test]
    fn publication_allows_pull_request_product_fields() {
        let bodies = [
            "The PR description does not mention rollback steps; add them.",
            "The PR's description does not mention rollback steps; add them.",
            "The PR’s description does not mention rollback steps; add them.",
            "Add the compatibility impact to the pull request description.",
            "The pull request webhook accepts an unsigned payload; verify its signature first.",
            "The pull request's webhook accepts an unsigned payload; verify its signature first.",
            "The HTTP PATCH handler accepts an unsigned payload; verify its signature first.",
            "The HTTP PATCH request accepts an unsigned payload; verify its signature first.",
            "The JSON Patch encoder drops null values; preserve explicit removals.",
            "The patch release changes persisted state without migrating it; add the migration.",
            "The security patch omits the certificate check; restore it.",
            "The patch parser drops null values; preserve explicit removals.",
        ];

        for body in bodies {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = body.into();
            assert!(
                !publication_exposes_evidence_boundary(&finding),
                "body: {body}"
            );
            assert_eq!(
                validate_finding_publication(&finding),
                Ok(()),
                "body: {body}"
            );
        }
    }

    #[test]
    fn publication_distinguishes_product_verification_from_delegated_search_work() {
        let allowed = [
            "The TLS path does not verify that the certificate matches the host; compare the SAN before accepting it.",
            "The database search for active users omits the tenant predicate; bind `tenant_id` in the query.",
            "The handler should confirm that the signature covers the raw body before parsing it.",
            "The caller does not verify the response signature; validate it before use.",
            "The handler cannot search the repository after pagination; preserve the index cursor.",
            "The search limit is applied before tenant filtering; apply the tenant predicate first.",
            "Search for active users crosses tenant boundaries because the query omits `tenant_id`.",
        ];
        for body in allowed {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = body.into();
            assert_eq!(validate_finding_publication(&finding), Ok(()), "{body}");
        }

        let rejected = [
            "Search the repository for other callers before changing this API.",
            "Please verify that the unchanged consumer accepts this value.",
            "Check whether another manifest still uses version 19.2.3.",
            "Before merging, search the codebase for other callers.",
            "Inspect other callers before merging.",
            "Reviewers should verify the unchanged consumer.",
        ];
        for body in rejected {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = body.into();
            assert!(validate_finding_publication(&finding).is_err(), "{body}");
        }
    }

    fn finding(sev: Severity, conf: f64) -> Finding {
        Finding {
            path: "a.rs".into(),
            line: 1,
            end_line: None,
            severity: sev,
            kind: Kind::Risk,
            confidence: conf,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: None,
            machine_claim: None,
            machine_claim_deferred: false,
            title: "t".into(),
            body: "b".into(),
            evidence: None,
            id: None,
        }
    }

    #[test]
    fn buckets_clamp_and_distribute() {
        let fs = vec![
            finding(Severity::Info, 0.0),
            finding(Severity::Info, 0.19),
            finding(Severity::Warn, 0.5),
            finding(Severity::Error, 1.0),
            finding(Severity::Error, 1.5),
        ];
        assert_eq!(Envelope::buckets_of(&fs), [2, 0, 1, 0, 2]);
        let c = Envelope::counts_of(&fs, 3);
        assert_eq!((c.info, c.warn, c.error, c.suppressed), (2, 1, 2, 3));
    }

    #[test]
    fn severity_parse_aliases() {
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Error));
        assert_eq!(Severity::parse("warning"), Some(Severity::Warn));
        assert_eq!(Severity::parse("note"), Some(Severity::Info));
        assert_eq!(Severity::parse("nope"), None);
    }

    #[test]
    fn kind_parse() {
        assert_eq!(Kind::parse("risk"), Some(Kind::Risk));
        assert_eq!(Kind::parse("humanescalation"), Some(Kind::HumanEscalation));
        assert_eq!(Kind::parse("guardrail"), Some(Kind::Guardrail));
        assert_eq!(Kind::parse("uncertainty"), Some(Kind::Uncertainty));
        assert_eq!(Kind::parse("contentpolicy"), Some(Kind::ContentPolicy));
        assert_eq!(Kind::parse("unknown"), None);
    }

    #[test]
    fn finding_publication_preserves_exact_227_character_body() {
        let body = format!("{}.", "a".repeat(226));
        let publication = finding_publication_text("Exact evidence", &body);
        assert_eq!(publication.body, body);
        assert_eq!(publication.body.chars().count(), 227);

        let mut finding = finding(Severity::Warn, 0.9);
        finding.title = publication.title;
        finding.body = publication.body;
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn fresh_finding_normalization_neutralizes_markup_without_truncation() {
        let mut finding = finding(Severity::Warn, 0.9);
        finding.title = "Use `POSTIL_PRIVATE_MONITOR_DATABASE_URL` safely".into();
        finding.body =
            "# Impact\n@operator must not publish <details> or an unmatched ` marker.".into();

        normalize_finding_publication(&mut finding);

        assert_eq!(
            finding.title,
            "Use POSTIL_PRIVATE_MONITOR_DATABASE_URL safely"
        );
        assert!(finding.body.starts_with("\\# Impact\n"));
        assert!(finding.body.contains("＠operator"));
        assert!(finding.body.contains("&lt;details&gt;"));
        assert!(finding.body.contains("unmatched \\` marker."));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn fresh_finding_normalization_preserves_operators_in_inline_code() {
        let mut finding = finding(Severity::Warn, 0.9);
        finding.body = "The expression `time() - kube_pod_start_time > 60d` measures pod age, while <details> remains markup.".into();

        normalize_finding_publication(&mut finding);

        assert!(
            finding
                .body
                .contains("`time() - kube_pod_start_time > 60d`")
        );
        assert!(!finding.body.contains("&gt; 60d`"));
        assert!(finding.body.contains("&lt;details&gt;"));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn fresh_finding_normalization_states_review_artifacts_as_code_changes() {
        let mut finding = finding(Severity::Error, 0.9);
        finding.title = "This patch removes the authorization guard".into();
        finding.body = "The previous implementation was safe. In the diff, the PR removes the authorization guard before `applyBulkEdit`; restore the guard before applying privileged changes.".into();

        normalize_finding_publication(&mut finding);

        assert_eq!(finding.title, "This change removes the authorization guard");
        assert_eq!(
            finding.body,
            "The previous implementation was safe. In the changed code, the change removes the authorization guard before `applyBulkEdit`; restore the guard before applying privileged changes."
        );
        assert_eq!(validate_finding_publication(&finding), Ok(()));
        assert!(!publication_exposes_evidence_boundary(&finding));
    }

    #[test]
    fn fresh_finding_normalization_does_not_hide_delegated_repository_work() {
        for body in [
            "Please inspect the repository to verify whether other callers retain the guard.",
            "Verify that `applyBulkEdit` internally enforces the same permission check.",
            "No defect is established, or verify all callers preserve `currency`.",
            "The parser does not drop `currency`. Verify all callers preserve it, or add a follow-up task for manual review.",
        ] {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = body.into();
            let original = finding.body.clone();

            normalize_finding_publication(&mut finding);

            assert_eq!(finding.body, original);
            assert_eq!(
                publication_evidence_boundary_category(&finding),
                Some("delegatedEvidenceCollection")
            );
            assert!(validate_finding_publication(&finding).is_err());
        }
    }

    #[test]
    fn fresh_finding_normalization_keeps_manifest_inspection_unpublishable() {
        let mut finding = finding(Severity::Warn, 0.9);
        finding.body =
            "No sibling update appears in this diff; inspect the deployment manifest.".into();

        normalize_finding_publication(&mut finding);

        assert_eq!(
            finding.body,
            "No sibling update appears in this change; inspect the deployment manifest."
        );
        assert_eq!(
            publication_evidence_boundary_category(&finding),
            Some("delegatedEvidenceCollection")
        );
        assert!(validate_finding_publication(&finding).is_err());
    }

    #[test]
    fn fresh_finding_normalization_keeps_delegated_alternatives_unpublishable() {
        let mut finding = finding(Severity::Error, 0.9);
        finding.body = "The response dropped `currency`, which breaks the response contract. Verify all callers no longer reference `currency`, or reintroduce `currency` behind a versioned endpoint.".into();
        let original = finding.body.clone();

        normalize_finding_publication(&mut finding);

        assert_eq!(finding.body, original);
        assert_eq!(
            publication_evidence_boundary_category(&finding),
            Some("delegatedEvidenceCollection")
        );
        assert!(validate_finding_publication(&finding).is_err());
    }

    #[test]
    fn fresh_finding_normalization_preserves_product_artifact_terms() {
        for (body, expected) in [
            (
                "The PR API requires `head_sha`, and this patch removes the field.",
                "The PR API requires `head_sha`, and this change removes the field.",
            ),
            (
                "THE PR'S API requires `head_sha`, and this patch removes the field.",
                "THE PR'S API requires `head_sha`, and this change removes the field.",
            ),
            (
                "THE PR’S API requires `head_sha`, and this patch removes the field.",
                "THE PR’S API requires `head_sha`, and this change removes the field.",
            ),
        ] {
            let mut finding = finding(Severity::Error, 0.9);
            finding.title = "This patch removes the authorization guard".into();
            finding.body = body.into();

            normalize_finding_publication(&mut finding);

            assert_eq!(finding.title, "This change removes the authorization guard");
            assert_eq!(finding.body, expected);
            assert_eq!(validate_finding_publication(&finding), Ok(()));
        }
    }

    #[test]
    fn fresh_finding_normalization_is_idempotent_for_fence_shaped_code() {
        let mut finding = finding(Severity::Warn, 0.9);
        finding.body = "``` <details> ```.".into();

        normalize_finding_publication(&mut finding);
        let normalized = finding.body.clone();

        assert_eq!(normalized, "\\``` &lt;details&gt; ```.");
        assert_eq!(validate_finding_publication(&finding), Ok(()));
        normalize_finding_publication(&mut finding);
        assert_eq!(finding.body, normalized);
    }

    #[test]
    fn fresh_finding_normalization_does_not_hide_semantic_contract_failures() {
        let mut incomplete = finding(Severity::Warn, 0.9);
        incomplete.body = "Sentence remains cut off".into();
        normalize_finding_publication(&mut incomplete);
        assert_eq!(
            validate_finding_publication(&incomplete),
            Err("finding body must end with sentence punctuation".to_string())
        );

        let mut over_limit = finding(Severity::Warn, 0.9);
        over_limit.body = format!("{}.", "x".repeat(FINDING_PUBLIC_BODY_MAX_CHARS));
        let original = over_limit.body.clone();
        normalize_finding_publication(&mut over_limit);
        assert_eq!(over_limit.body, original);
        assert!(validate_finding_publication(&over_limit).is_err());
    }

    #[test]
    fn normalization_exposes_directional_and_zero_width_controls() {
        let mut finding = finding(Severity::Warn, 0.9);
        finding.title = "Visible\u{202e}title".into();
        finding.body = "The value contains x\u{200b}y and \u{2066}isolated\u{2069} text.".into();

        normalize_finding_publication(&mut finding);

        assert_eq!(finding.title, "Visible U+202E title");
        assert!(finding.body.contains("x[U+200B]y"));
        assert!(finding.body.contains("[U+2066]isolated[U+2069]"));
        assert_eq!(validate_finding_publication(&finding), Ok(()));
    }

    #[test]
    fn normalization_escapes_thematic_breaks_on_every_line() {
        for separator in ["---", "- - -", "* * *", "_ _ _"] {
            let mut finding = finding(Severity::Warn, 0.9);
            finding.body = format!("{separator}\nComplete explanation.");
            normalize_finding_publication(&mut finding);
            assert!(finding.body.starts_with('\\'), "{separator:?}");
            assert_eq!(validate_finding_publication(&finding), Ok(()));
        }
    }

    #[test]
    fn over_limit_body_fails_without_word_boundary_truncation() {
        let body = format!("word {}.", "complete ".repeat(150));
        assert!(body.chars().count() > FINDING_PUBLIC_BODY_MAX_CHARS);
        let publication = finding_publication_text("Keep complete prose", &body);
        assert_eq!(publication.body, body);
        assert!(!publication.body.ends_with('…'));

        let mut finding = finding(Severity::Warn, 0.9);
        finding.title = publication.title;
        finding.body = publication.body;
        assert!(validate_finding_publication(&finding).is_err());
    }

    #[test]
    fn forge_projection_neutralizes_legacy_markup_without_cutting_valid_prose() {
        let mut legacy = finding(Severity::Warn, 0.9);
        legacy.title = "@octocat <img> Unsafe finding".into();
        legacy.body = "@octocat <details>Inspect this complete sentence.</details>.".into();

        let publication = forge_safe_finding_publication_text(&legacy);
        assert!(!publication.title.contains('@'));
        assert!(!publication.title.contains('<'));
        assert!(!publication.body.contains('@'));
        assert!(!publication.body.contains("<details>"));
        assert!(publication.body.ends_with("&lt;/details&gt;."));
    }

    #[test]
    fn forge_projection_reuses_complete_normalization_and_revalidates() {
        let mut legacy = finding(Severity::Warn, 0.9);
        legacy.title = "Use `SAFE_VALUE`".into();
        legacy.body = "---\n@operator sees x\u{202e}y and an unmatched ` marker.".into();

        let publication = forge_safe_finding_publication_text(&legacy);
        legacy.title.clone_from(&publication.title);
        legacy.body.clone_from(&publication.body);

        assert_eq!(legacy.title, "Use SAFE_VALUE");
        assert!(legacy.body.starts_with("\\---\n"));
        assert!(legacy.body.contains("＠operator"));
        assert!(legacy.body.contains("x[U+202E]y"));
        assert!(legacy.body.contains("unmatched \\` marker."));
        assert_eq!(validate_finding_publication(&legacy), Ok(()));
    }

    #[test]
    fn forge_projection_replaces_over_limit_legacy_body_with_complete_notice() {
        let mut legacy = finding(Severity::Warn, 0.9);
        legacy.body = format!("{}.", "complete ".repeat(10_000));

        let publication = forge_safe_finding_publication_text(&legacy);
        assert_eq!(
            publication.body,
            "This carried finding does not satisfy the publication contract. Open Review details for the complete record."
        );
        assert!(publication.body.ends_with('.'));
        assert!(!publication.body.ends_with('…'));
    }

    #[test]
    fn weak_human_escalation_never_blocks_but_floor_does() {
        let mut escalation = finding(Severity::Error, 0.05);
        escalation.kind = Kind::HumanEscalation;
        let block_on_kinds = vec!["humanEscalation".to_string()];

        assert!(!finding_blocks_gate(
            &escalation,
            "error",
            &block_on_kinds,
            false
        ));

        escalation.severity = Severity::Warn;
        escalation.confidence = HUMAN_ESCALATION_GATE_MIN_CONFIDENCE;
        assert!(finding_blocks_gate(
            &escalation,
            "error",
            &block_on_kinds,
            false
        ));
        assert!(!finding_blocks_gate(
            &escalation,
            "never",
            &block_on_kinds,
            false
        ));
    }

    #[test]
    fn envelope_serializes_camel_case() {
        let mut contextual_finding = finding(Severity::Warn, 0.8);
        contextual_finding.repository_claim = Some(RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec!["19.2.5".into()],
            paths: vec![],
            identifiers: vec![],
        });
        let contextual_value = serde_json::to_value(&contextual_finding).unwrap();
        assert_eq!(contextual_value["repositoryContext"]["claim"], "absence");
        assert!(contextual_value.get("repositoryClaim").is_none());

        let mut machine_finding = finding(Severity::Warn, 0.8);
        machine_finding.machine_claim = Some(MachineClaim {
            kind: MachineClaimKind::RustCopyMoveOut,
            path: "src/identity.rs".into(),
            symbol: "crate::identity::IdentityFailure".into(),
            expected_signature: None,
        });
        let machine_value = serde_json::to_value(&machine_finding).unwrap();
        assert_eq!(machine_value["machineClaim"]["kind"], "rust.copy_move_out");
        assert!(machine_value.get("machineClaimDeferred").is_none());
        let mut legacy_machine_value = machine_value;
        legacy_machine_value
            .as_object_mut()
            .unwrap()
            .remove("machineClaim");
        let legacy_machine_finding: Finding = serde_json::from_value(legacy_machine_value).unwrap();
        assert!(legacy_machine_finding.machine_claim.is_none());
        assert!(!legacy_machine_finding.machine_claim_deferred);

        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Counts::default(),
            confidence_buckets: [0; 5],
            gate: Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            repository_search: RepositorySearchReceipt::default(),
            claim_verification: None,
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        env.model_incidents.push(ModelIncident {
            phase: ModelIncidentPhase::Scorer,
            category: ModelIncidentCategory::InvalidOutput,
            recovered: true,
            recovery: Some(ModelIncidentRecovery::Repair),
        });
        let mut v = serde_json::to_value(&env).unwrap();
        assert!(v.get("confidenceBuckets").is_some());
        assert!(v.get("modelUsed").is_some());
        assert_eq!(v["gate"]["failOn"], "error");
        assert!(v.get("suppressedFindings").is_none());
        assert_eq!(v["modelIncidents"][0]["phase"], "scorer");
        assert_eq!(v["modelIncidents"][0]["category"], "invalidOutput");
        assert_eq!(v["modelIncidents"][0]["recovery"], "repair");
        assert_eq!(v["repositorySearch"]["state"], "unavailable");

        env.review_coverage = Some(ReviewCoverage {
            mode: ReviewCoverageMode::Bounded,
            selected_batches: 5,
            total_batches: 17,
            planner_fallback: true,
            receipt: None,
        });
        let mut with_coverage = serde_json::to_value(&env).unwrap();
        assert_eq!(with_coverage["reviewCoverage"]["mode"], "bounded");
        assert_eq!(with_coverage["reviewCoverage"]["selectedBatches"], 5);
        assert_eq!(with_coverage["reviewCoverage"]["totalBatches"], 17);
        assert_eq!(with_coverage["reviewCoverage"]["plannerFallback"], true);

        with_coverage
            .as_object_mut()
            .unwrap()
            .remove("reviewCoverage");
        with_coverage
            .as_object_mut()
            .unwrap()
            .remove("repositorySearch");
        let historical: Envelope = serde_json::from_value(with_coverage).unwrap();
        assert!(historical.review_coverage.is_none());
        assert_eq!(
            historical.repository_search.state,
            RepositorySearchState::Unavailable
        );
        assert!(historical.claim_verification.is_none());

        v.as_object_mut().unwrap().remove("modelIncidents");
        let decoded: Envelope = serde_json::from_value(v).unwrap();
        assert!(decoded.suppressed_findings.is_empty());
        assert!(decoded.model_incidents.is_empty());
    }

    #[test]
    fn provider_cost_preserves_decimal_precision_and_derives_micros() {
        let first = ProviderCost::parse("0.00000049").unwrap();
        let second = ProviderCost::parse("1.2300e-6").unwrap();
        assert_eq!(first.to_string(), "0.00000049");
        assert_eq!(first.micros_rounded(), Some(0));
        assert_eq!(first.micros_ceiling(), Some(1));
        assert_eq!(second.to_string(), "0.00000123");
        assert_eq!(first.checked_add(second).unwrap().to_string(), "0.00000172");
        assert!(ProviderCost::parse("-0.1").is_none());
        assert!(ProviderCost::parse("NaN").is_none());
        assert!(ProviderCost::parse("1e-2147483647").is_none());
        assert_eq!(
            ProviderCost::parse("0e-2147483647").unwrap().to_string(),
            "0"
        );
        assert_eq!(
            ProviderCost::parse("0e2147483647").unwrap().to_string(),
            "0"
        );
        assert_eq!(
            ProviderCost::parse("1e-18").unwrap().to_string(),
            "0.000000000000000001"
        );
        assert!(ProviderCost::parse("1e-19").is_none());
        assert!(ProviderCost::parse(&format!("0.{}1", "0".repeat(128))).is_none());
    }
}
