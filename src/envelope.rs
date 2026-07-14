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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub title: String,
    pub body: String,
    /// Stable, engine-generated finding ID for deduplication and approval tracking.
    /// Hash of (head_sha, kind, normalized_path, normalized_line, normalized_title, duplicate_index).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

pub const FINDING_PUBLIC_TITLE_MAX_CHARS: usize = 160;
pub const FINDING_PUBLIC_BODY_MAX_CHARS: usize = 1_200;
pub const FINDING_PUBLIC_BODY_MAX_LINES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPublicationText {
    pub title: String,
    pub body: String,
}

/// Deterministic publication boundary for model-authored finding prose.
///
/// Findings keep useful inline-code, lists, and links, but cannot turn a code
/// review into an article, ping GitHub users, inject HTML/images, or open a
/// Markdown block that consumes the rest of the review. Callers normalize at
/// ingestion and again at forge sinks so imported/baseline envelopes receive
/// the same protection.
pub fn finding_publication_text(title: &str, body: &str) -> FindingPublicationText {
    let normalized_body = body.replace("\r\n", "\n").replace('\r', "\n");
    let source_lines: Vec<&str> = normalized_body.lines().collect();
    let mut lines = Vec::new();
    let mut omitted = source_lines.len() > FINDING_PUBLIC_BODY_MAX_LINES;
    for (index, source) in source_lines
        .iter()
        .take(FINDING_PUBLIC_BODY_MAX_LINES)
        .enumerate()
    {
        let mut line = sanitize_publication_line(source);
        let trimmed = line.trim();
        if markdown_fence_line(trimmed) {
            if let Some(position) = line.find(['`', '~']) {
                line.insert(position, '\\');
            }
        } else if markdown_atx_heading(trimmed) {
            line = trimmed
                .trim_start_matches('#')
                .trim_start()
                .trim_end_matches('#')
                .trim_end()
                .to_string();
        } else if index > 0 && markdown_setext_delimiter(trimmed) {
            line = "…".to_string();
        } else if markdown_table_delimiter(trimmed) {
            line = line.replace('|', "\\|");
        }
        lines.push(neutralize_unmatched_backticks(&line));
    }
    if lines.is_empty() {
        lines.push("Inspect the cited line and verify this finding before merging.".to_string());
    } else if omitted {
        if lines.len() == FINDING_PUBLIC_BODY_MAX_LINES {
            lines.pop();
        }
        lines.push("…".to_string());
    }

    let joined = lines.join("\n");
    let (body, body_truncated) = cap_publication_text(&joined, FINDING_PUBLIC_BODY_MAX_CHARS);
    omitted |= body_truncated;
    let body = if omitted && !body.ends_with('…') {
        let reserve = FINDING_PUBLIC_BODY_MAX_CHARS.saturating_sub(1);
        format!(
            "{}…",
            body.chars().take(reserve).collect::<String>().trim_end()
        )
    } else {
        body
    };
    let body = neutralize_unmatched_backticks(body.trim());
    let body = if body.is_empty() {
        "Inspect the cited line and verify this finding before merging.".to_string()
    } else {
        body
    };

    let requested_title = sanitize_publication_title(title);
    let title = if requested_title.is_empty() {
        sanitize_publication_title(body.lines().next().unwrap_or("Finding"))
    } else {
        requested_title
    };
    let (title, _) = cap_publication_text(&title, FINDING_PUBLIC_TITLE_MAX_CHARS);

    FindingPublicationText { title, body }
}

pub fn normalize_finding_publication(finding: &mut Finding) {
    let publication = finding_publication_text(&finding.title, &finding.body);
    finding.title = publication.title;
    finding.body = publication.body;
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
    let line = sanitize_publication_line(&single_line).replace(['`', '*', '_', '[', ']', '#'], " ");
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sanitize_publication_line(value: &str) -> String {
    let text = value
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .replace('@', "＠")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    neutralize_markdown_images(&text)
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

fn cap_publication_text(value: &str, max: usize) -> (String, bool) {
    if value.chars().count() <= max {
        return (value.to_string(), false);
    }
    let prefix: String = value.chars().take(max.saturating_sub(1)).collect();
    (format!("{}…", prefix.trim_end()), true)
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
    Ignored,
    BelowSeverity,
    BelowConfidence,
    MaxFindings,
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
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('-') || raw.starts_with('+') {
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
    ReviewGenerator,
    FindingScorer,
    MentionResponder,
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
    Review,
    Scorer,
    Respond,
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
    if finding.kind == Kind::HumanEscalation
        && finding.confidence < HUMAN_ESCALATION_GATE_MIN_CONFIDENCE
    {
        return false;
    }

    let severity_blocks = if provider_error_is_advisory || fail_on.eq_ignore_ascii_case("never") {
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

/// A complete, trustworthy review could not fit inside Postil's bounded local
/// resource and provider-request budget. This is an internal fail-closed state;
/// forge adapters expose only generic check text for operational findings.
pub fn incomplete_review_finding() -> Finding {
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Review incomplete".to_string(),
        body: "The complete change did not fit within Postil's bounded review budget. No clean verdict was issued. Split the change or run focused local reviews before retrying.".to_string(),
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
    }
}

/// The synthetic finding emitted when the model produced unusable output.
/// Postil fails closed: a review that could not be trusted is an error, not a pass.
pub fn fail_closed_finding(detail: &str) -> Finding {
    Finding {
        path: OPERATIONAL_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Model output could not be validated".to_string(),
        body: format!(
            "Postil could not obtain a valid, diff-grounded review from the configured \
             model(s) and is failing closed rather than passing unreviewed code.\n\nDetail: {detail}"
        ),
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
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
             Re-run the review; if the contradiction persists, inspect the areas the \
             summary names and address them or record findings manually."
        ),
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
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
        id: None,
        generator_confidence: None,
        scorer_confidence: None,
        generator_kind: None,
        scorer_kind: None,
        scorer_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            title: "t".into(),
            body: "b".into(),
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
    fn finding_publication_is_bounded_and_neutralizes_unsafe_markdown() {
        let body = [
            "# Summary",
            "Ping @octocat and open <details>hidden</details>.",
            "![remote](https://attacker.invalid/pixel.png)",
            "```mermaid",
            "flowchart LR",
            "```",
            "A | B",
            "--- | ---",
            "Keep `useful_code()` and [the docs](https://example.test).",
        ]
        .into_iter()
        .chain(std::iter::repeat_n("extra line", 20))
        .collect::<Vec<_>>()
        .join("\n");
        let publication = finding_publication_text(
            "**Huge** @octocat <img> title that must remain plain",
            &body,
        );

        assert!(publication.title.chars().count() <= FINDING_PUBLIC_TITLE_MAX_CHARS);
        assert!(publication.body.chars().count() <= FINDING_PUBLIC_BODY_MAX_CHARS);
        assert!(publication.body.lines().count() <= FINDING_PUBLIC_BODY_MAX_LINES);
        assert!(!publication.title.contains('@'));
        assert!(!publication.title.contains('<'));
        assert!(!publication.body.contains("@octocat"));
        assert!(!publication.body.contains("<details>"));
        assert!(
            !publication
                .body
                .lines()
                .any(|line| line.trim_start().starts_with("!["))
        );
        assert!(!publication.body.lines().any(|line| line.starts_with('#')));
        assert!(!publication.body.lines().any(|line| line.starts_with("```")));
        assert!(!publication.body.contains("--- | ---"));
        assert!(publication.body.contains("`useful_code()`"));
        assert!(
            publication
                .body
                .contains("[the docs](https://example.test)")
        );
        assert!(publication.body.ends_with('…'));
        assert_eq!(
            finding_publication_text(&publication.title, &publication.body),
            publication,
        );
        assert!(!finding_publication_text("", "\n\n").body.is_empty());
    }

    #[test]
    fn finding_publication_title_replaces_line_breaks_and_control_whitespace() {
        let publication = finding_publication_text(
            "First\r\nsecond\rthird\nfourth\tfifth\u{000B}sixth\0seventh",
            "Body",
        );

        assert_eq!(
            publication.title,
            "First second third fourth fifth sixth seventh"
        );
        assert!(!publication.title.chars().any(char::is_control));
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
    }

    #[test]
    fn envelope_serializes_camel_case() {
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
    }
}
