//! OpenAI-compatible and native Anthropic chat client with model cascade, one JSON-repair retry,
//! optional multi-model consensus, and fail-closed semantics.
//!
//! OpenAI-compatible endpoints use `POST {base}/chat/completions` by default.
//! Native Anthropic endpoints use `POST {base}/messages` when explicitly selected.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api_key;
use crate::config::{ApiFormat, Config, HOSTED_OPERATION_COST_CAP_MICROS, ModelPriceBound};
use crate::envelope::{
    Finding, Kind, ModelIncident, ModelIncidentCategory, ModelIncidentPhase, ModelIncidentRecovery,
    ModelUsage, ModelUsageCostSource, ModelUsagePhase, ModelUsageRole, ProviderCost,
    ReviewAdmission, Usage,
};
use crate::prompt::{
    SCORER_REASON_JSON_PATTERN, SCORER_REASON_MAX_BYTES, SCORER_REASON_PROMPT_MAX_BYTES,
    SCORER_REASON_SCHEMA_MAX_CHARS,
};

#[derive(Debug, Clone)]
pub struct ModelReview {
    pub summary: String,
    pub findings: Vec<Finding>,
    pub model_used: String,
    pub usage: Usage,
    pub model_usage: Vec<ModelUsage>,
    pub model_incidents: Vec<ModelIncident>,
    pub usage_accounting_complete: bool,
}

#[derive(Debug, Clone)]
pub struct FindingScore {
    pub index: usize,
    pub confidence: f64,
    pub kind: Kind,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ScorerReview {
    pub scores: Vec<FindingScore>,
    pub model_used: String,
    pub usage: Usage,
    pub model_usage: Vec<ModelUsage>,
    pub model_incidents: Vec<ModelIncident>,
    pub usage_accounting_complete: bool,
}

#[cfg(feature = "qualification-candidate")]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtomicAttributionReview {
    pub same_defect: bool,
    pub reason: String,
    pub model_used: String,
    pub provider_used: String,
    pub response_identities: Vec<AtomicAttributionResponseIdentity>,
    pub raw_responses: Vec<String>,
    pub model_usage: Vec<ModelUsage>,
    pub usage_accounting_complete: bool,
}

#[cfg(feature = "qualification-candidate")]
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtomicAttributionResponseIdentity {
    pub model: String,
    pub provider: String,
}

#[cfg(feature = "qualification-candidate")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAtomicAttribution {
    same_defect: bool,
    reason: String,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub content: String,
    pub model_used: String,
    pub usage: Usage,
    pub models: Vec<ModelUsage>,
    pub usage_accounting_complete: bool,
}

#[derive(Debug)]
pub struct ModelError {
    error: anyhow::Error,
    usage: Usage,
    model_usage: Vec<ModelUsage>,
    model_incidents: Vec<ModelIncident>,
    usage_accounting_complete: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AtomicAttributionIdentityFailure {
    Missing,
    Mismatch,
}

impl std::fmt::Display for AtomicAttributionIdentityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("atomic attribution response identity is missing"),
            Self::Mismatch => {
                formatter.write_str("atomic attribution response identity does not match")
            }
        }
    }
}

impl std::error::Error for AtomicAttributionIdentityFailure {}

#[cfg(feature = "qualification-candidate")]
#[derive(Debug)]
struct AtomicAttributionInvalidOutput;

#[cfg(feature = "qualification-candidate")]
impl std::fmt::Display for AtomicAttributionInvalidOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("atomic attribution output is invalid after schema repair")
    }
}

#[cfg(feature = "qualification-candidate")]
impl std::error::Error for AtomicAttributionInvalidOutput {}

#[cfg(feature = "qualification-candidate")]
#[derive(Debug)]
struct AtomicAttributionRequestTooLarge;

#[cfg(feature = "qualification-candidate")]
impl std::fmt::Display for AtomicAttributionRequestTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("atomic attribution provider request is too large")
    }
}

#[cfg(feature = "qualification-candidate")]
impl std::error::Error for AtomicAttributionRequestTooLarge {}

#[derive(Debug)]
struct ProviderHttpFailure(reqwest::StatusCode);

impl std::fmt::Display for ProviderHttpFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "model endpoint returned {}", self.0)
    }
}

impl std::error::Error for ProviderHttpFailure {}

impl ModelError {
    fn new(error: anyhow::Error, usage: Usage, usage_accounting_complete: bool) -> Self {
        Self {
            error,
            usage,
            model_usage: Vec::new(),
            model_incidents: Vec::new(),
            usage_accounting_complete,
        }
    }

    pub fn usage(&self) -> Usage {
        self.usage
    }

    pub fn model_usage(&self) -> &[ModelUsage] {
        &self.model_usage
    }

    pub fn usage_accounting_complete(&self) -> bool {
        self.usage_accounting_complete
    }

    pub fn model_incidents(&self) -> &[ModelIncident] {
        &self.model_incidents
    }

    fn incident(&self, phase: ModelIncidentPhase) -> ModelIncident {
        let category = if self.is_deadline_exceeded() {
            ModelIncidentCategory::Deadline
        } else if self.is_timeout() {
            ModelIncidentCategory::Timeout
        } else if self.is_provider() {
            ModelIncidentCategory::ProviderError
        } else {
            ModelIncidentCategory::InvalidOutput
        };
        ModelIncident {
            phase,
            category,
            recovered: false,
            recovery: None,
        }
    }

    pub fn is_provider(&self) -> bool {
        self.error.downcast_ref::<ProviderError>().is_some()
            || self
                .error
                .chain()
                .any(|cause| cause.downcast_ref::<ProviderHttpFailure>().is_some())
    }

    fn is_timeout(&self) -> bool {
        self.error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
                || cause.downcast_ref::<RequestTimedOut>().is_some()
                || cause.downcast_ref::<DeadlineExceeded>().is_some()
                || cause
                    .downcast_ref::<ProviderHttpFailure>()
                    .is_some_and(|failure| timeout_status(failure.0.as_u16()))
        })
    }

    fn is_deadline_exceeded(&self) -> bool {
        self.error.downcast_ref::<DeadlineExceeded>().is_some()
    }

    #[cfg(feature = "qualification-candidate")]
    pub(crate) fn atomic_attribution_terminal_diagnostic(
        &self,
    ) -> crate::attribution::AttributionTerminalDiagnostic {
        use crate::attribution::{
            AttributionTerminalCategory as Category, AttributionTerminalDiagnostic,
        };

        let category = if let Some(status) = self.error.downcast_ref::<ProviderHttpFailure>() {
            Category::ProviderHttp {
                status: status.0.as_u16(),
            }
        } else if self
            .error
            .downcast_ref::<AtomicAttributionRequestTooLarge>()
            .is_some()
        {
            Category::ProviderRequestTooLarge
        } else if let Some(identity) = self
            .error
            .downcast_ref::<AtomicAttributionIdentityFailure>()
        {
            match identity {
                AtomicAttributionIdentityFailure::Missing => Category::ResponseIdentityMissing,
                AtomicAttributionIdentityFailure::Mismatch => Category::ResponseIdentityMismatch,
            }
        } else if self
            .error
            .downcast_ref::<AtomicAttributionInvalidOutput>()
            .is_some()
        {
            Category::OutputInvalidAfterSchemaRepair
        } else if self.error.chain().any(|cause| {
            cause
                .downcast_ref::<ModelContentFailure>()
                .and_then(ModelContentFailure::nonterminal_reason)
                .is_some_and(|reason| reason == "length")
        }) {
            Category::OutputNonterminalLength
        } else if self.is_deadline_exceeded() {
            Category::ProviderDeadline
        } else if self.is_timeout() {
            Category::ProviderTimeout
        } else if self.error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_connect)
        }) {
            Category::ProviderTransport
        } else if self.error.downcast_ref::<ModelContentFailure>().is_some() {
            Category::InvalidOutput
        } else {
            Category::ProviderUnclassified
        };
        let identity = self
            .error
            .downcast_ref::<AtomicAttributionIdentityFailure>();
        let terminal_usage = self.model_usage.last();
        AttributionTerminalDiagnostic {
            version: 1,
            category,
            phase: crate::attribution::AttributionTerminalPhase::Attribution,
            provider_attempt_count: Some(self.model_usage.len()),
            identity_present: identity
                .map(|failure| matches!(failure, AtomicAttributionIdentityFailure::Mismatch)),
            identity_matched: identity.and_then(|failure| match failure {
                AtomicAttributionIdentityFailure::Missing => None,
                AtomicAttributionIdentityFailure::Mismatch => Some(false),
            }),
            usage_present: terminal_usage.map(|usage| {
                usage.prompt_tokens > 0
                    || usage.completion_tokens > 0
                    || usage.cost_provider_decimal.is_some()
            }),
            usage_accounting_complete: terminal_usage.map(|usage| usage.accounting_complete),
        }
    }
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{:#}", self.error)
        } else {
            write!(f, "{}", self.error)
        }
    }
}

impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

pub(crate) fn add_usage(total: &mut Usage, usage: Usage) {
    if usage.prompt_tokens == 0
        && usage.completion_tokens == 0
        && usage.cost_micros.is_none()
        && usage.provider_cost.is_none()
    {
        return;
    }
    let total_was_empty =
        total.prompt_tokens == 0 && total.completion_tokens == 0 && total.provider_cost.is_none();
    total.prompt_tokens = total.prompt_tokens.saturating_add(usage.prompt_tokens);
    total.completion_tokens = total
        .completion_tokens
        .saturating_add(usage.completion_tokens);
    total.cost_micros = match (total.cost_micros, usage.cost_micros) {
        (Some(left), Some(right)) => left.checked_add(right),
        (None, Some(value)) if total_was_empty => Some(value),
        (None, Some(_)) | (Some(_), None) => None,
        (None, None) => None,
    };
    total.provider_cost = match (total.provider_cost, usage.provider_cost) {
        (Some(left), Some(right)) => left.checked_add(right),
        (None, Some(value)) if total_was_empty => Some(value),
        (None, Some(_)) | (Some(_), None) => None,
        (None, None) => None,
    };
}

fn has_billable_usage(usage: Usage) -> bool {
    usage.prompt_tokens > 0 || usage.completion_tokens > 0 || usage.provider_cost.is_some()
}

fn add_response_usage(
    usage: &mut Usage,
    prompt_tokens: u64,
    completion_tokens: u64,
    cost: Option<ProviderCost>,
) {
    add_usage(
        usage,
        Usage {
            prompt_tokens,
            completion_tokens,
            cost_micros: cost.and_then(ProviderCost::micros_rounded),
            provider_cost: cost,
        },
    );
}

fn elapsed_text(elapsed: Duration) -> String {
    if elapsed < Duration::from_secs(1) {
        format!("{}ms", elapsed.as_millis())
    } else {
        format!("{:.1}s", elapsed.as_secs_f64())
    }
}

fn log_text(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

fn safe_model_error_category(error: &ModelError) -> &'static str {
    if error.is_deadline_exceeded() {
        "deadline"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_provider() {
        "provider"
    } else {
        "invalid-output"
    }
}

fn safe_anyhow_category(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<DeadlineExceeded>().is_some() {
        "deadline"
    } else if reqwest_error(error).is_some_and(reqwest::Error::is_timeout)
        || error.downcast_ref::<RequestTimedOut>().is_some()
    {
        "timeout"
    } else if error.downcast_ref::<ProviderError>().is_some() {
        "provider"
    } else {
        "invalid-output"
    }
}

/// Raw shape we ask the model for. Findings are validated leniently here and
/// strictly (grounding, ranges) by the caller.
#[derive(Debug, Deserialize)]
struct RawReview {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    findings: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawFinding {
    path: String,
    line: u32,
    #[serde(default)]
    end_line: Option<u32>,
    severity: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default = "default_confidence")]
    confidence: f64,
    #[serde(default)]
    title: String,
    body: String,
    #[serde(default)]
    evidence: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScore {
    confidence: f64,
    kind: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawBatchSelection {
    batch_ids: Vec<usize>,
}

pub struct BatchPlannerResult {
    pub batch_ids: Vec<usize>,
    pub usage: Usage,
    pub model_usage: Vec<ModelUsage>,
    pub model_incidents: Vec<ModelIncident>,
    pub usage_accounting_complete: bool,
    pub fallback_used: bool,
}

fn default_confidence() -> f64 {
    0.5
}

#[derive(Clone)]
pub struct LlmClient {
    http: Arc<Mutex<Option<reqwest::Client>>>,
    api_base: String,
    request_api_base: String,
    api_key: String,
    api_format: ApiFormat,
    endpoint_auth: Option<EndpointAuth>,
    require_openrouter_privacy: bool,
    request_timeout: Duration,
    timeout_retry_timeout: Duration,
    review_deadline: Option<Instant>,
    scorer_deadline: Option<Instant>,
    total_deadline: Option<Instant>,
    admission: Arc<Mutex<ProviderAdmission>>,
    hosted_price_bounds: Option<Arc<HashMap<String, ModelPriceBound>>>,
    pinned_upstream_provider: Option<String>,
    call_ordinal: Arc<AtomicU32>,
}

#[derive(Debug, Default)]
struct ProviderAdmission {
    attempts: usize,
    input_bytes: usize,
    output_token_exposure: usize,
    token_exposure_upper_bound: usize,
    reported_token_spend: usize,
    reported_cost_micros: u64,
    projected_cost_exposure_micros: u64,
}

#[derive(Clone)]
struct EndpointAuth {
    name: HeaderName,
    value: HeaderValue,
}

#[derive(Debug, Clone, Copy)]
struct LlmTimeouts {
    request: Duration,
    total: Option<Duration>,
}

/// Retries per model on transient provider errors before the cascade moves on.
pub(crate) const TRANSIENT_RETRIES: u32 = 2;
/// A fresh request can recover when the caller's request timeout, rather than
/// the provider's response, ended an otherwise viable routed completion. The
/// shared total deadline remains authoritative, so this cannot extend a hosted
/// review beyond its worker budget.
const TIMEOUT_RETRIES: u32 = 1;
const EMPTY_RESPONSE_RETRIES: u32 = 1;
const EXHAUSTED_OUTPUT_RETRIES: u32 = 1;
const TIMEOUT_RETRY_CAP_SECS: u64 = 90;
const EMPTY_RESPONSE_RETRY_TIMEOUT_SECS: u64 = 30;
const EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS: u32 = 16_000;
const PROVIDER_RETRY_DELAY_CAP_SECS: u64 = 30;

/// Unqualified models receive a bounded review budget. A larger bound belongs
/// in explicit admitted-model metadata after that model proves it needs one.
pub(crate) const REVIEW_MAX_TOKENS: u32 = 8_000;
pub(crate) const MAX_PROVIDER_ATTEMPTS: usize = 216;
pub(crate) const MAX_REPORTED_TOKEN_SPEND: usize = 20_000_000;
const MAX_PROVIDER_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_PROVIDER_REQUEST_BYTES: usize = 256 * 1024;
pub(crate) const MAX_PROVIDER_OUTPUT_TOKEN_EXPOSURE: usize = 2_000_000;
// Five selected review batches and one planner request, each across at most
// three generator models with one shared correction call, consume 36 logical calls. The two
// scorer models with one repair consume four more. Any larger plan diverges
// from the bounded hosted workflow that fits under the phase deadlines.
const MAX_HOSTED_PLANNED_CALLS_BY_WATCHDOG: usize = 40;
const MAX_LOGICAL_CALLS_PER_REVIEW_MODEL: usize = 2;
const MAX_LOGICAL_CALLS_PER_SCORER_MODEL: usize = 2;
const MAX_TRANSPORT_ATTEMPTS_PER_CALL: usize = TRANSIENT_RETRIES as usize + 1;
const MAX_MODEL_RESPONSE_BYTES: usize = 512 * 1024;
const SCORER_BASE_MAX_TOKENS: u32 = 256;
const SCORER_MAX_TOKENS_PER_FINDING: u32 = 144;
const SCORER_REPAIR_BYTES_PER_OUTPUT_TOKEN: usize = 4;
pub(crate) const SCORER_MAX_FINDINGS: usize = 20;
const REPAIR_ERROR_MAX_BYTES: usize = 1_024;
// The publication contract targets 1,200 characters and hard-stops at 2,400.
// Keep generation bounded too, so an invalid model cannot spend an article's
// worth of output tokens before the validator rejects it.
const RESPOND_MAX_TOKENS: u32 = 1024;
const PLANNER_MAX_TOKENS: u32 = 1024;
const ANTHROPIC_VERSION: &str = "2023-06-01";
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 480;
const REQUEST_TIMEOUT_ENV: &str = "POSTIL_LLM_REQUEST_TIMEOUT_SECS";
const TOTAL_TIMEOUT_ENV: &str = "POSTIL_LLM_TOTAL_TIMEOUT_SECS";
const ENDPOINT_AUTH_HEADER_ENV: &str = "POSTIL_ENDPOINT_AUTH_HEADER";
const ENDPOINT_AUTH_VALUE_ENV: &str = "POSTIL_ENDPOINT_AUTH_VALUE";
const ALLOW_PRIVATE_API_BASE_ENV: &str = "POSTIL_ALLOW_PRIVATE_API_BASE";
static PROVIDER_RETRY_JITTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "qualification-candidate")]
const QUALIFICATION_CAPTURE_API_BASE_ENV: &str = "POSTIL_QUALIFICATION_CAPTURE_API_BASE";
const ALWAYS_MANAGED_HEADERS: &[&str] = &["x-api-key", "anthropic-version", "content-type"];

#[cfg(test)]
fn hostile_json_text(bytes: usize) -> String {
    "\0".repeat(bytes)
}

fn planner_system_prompt() -> &'static str {
    "You select bounded code-review batches from an untrusted semantic manifest. Return exactly one JSON object {\"batchIds\":[integer,...]}. Select only IDs present in the candidate set, with no duplicates, and select at most the requested count. Prefer concrete security, correctness, data-loss, concurrency, and lifecycle evidence. The mandatory boundary and global-synthesis batches are reviewed separately."
}

fn planner_user_prompt(manifest: &str, max_selected: usize) -> String {
    format!("Select at most {max_selected} additional batch IDs for detailed review.\n\n{manifest}")
}

fn planner_repair_user(user: &str, invalid: &str, error: &str) -> String {
    format!(
        "{user}\n\nThe previous response was invalid ({error}). Return only the corrected JSON object. Invalid response:\n{invalid}"
    )
}

fn review_schema_repair_user(invalid: &str, error: &str) -> String {
    format!(
        "The following was supposed to be a single valid JSON object matching the review schema but failed to parse ({error}). Output ONLY the corrected JSON object, nothing else:\n\n{invalid}"
    )
}

fn review_semantic_retry_user(user: &str, previous: &str) -> String {
    format!(
        "{user}\n\n[Your previous response]\n{previous}\n\n[Correction] Your summary describes merge-relevant risk but `findings` is empty, which is invalid. Either report each risk as a structured finding citing its exact new-file line from the diff above, or, if nothing is actually merge-relevant, return exactly {{\"summary\": \"\", \"findings\": []}}."
    )
}

fn review_validation_retry_user(user: &str, reason: &str) -> String {
    format!(
        "{user}\n\n[Correction] The previous response was unusable ({reason}). Retry once. Every finding must cite an exact path and new-file line displayed in the review input. Return only the corrected review JSON."
    )
}

fn scorer_repair_system(system: &str) -> String {
    format!(
        "{system}\n\nYour previous response failed schema validation. Repair only the JSON schema. Kind is a category, so severity values such as info, warn, and error are invalid kinds. Every reason must be concise single-line text of at most {SCORER_REASON_PROMPT_MAX_BYTES} UTF-8 bytes ending in sentence punctuation. Return the complete array and nothing else."
    )
}

fn scorer_repair_user(user: &str, invalid: &str) -> String {
    let invalid = crate::prompt::sanitize_scorer_input(invalid);
    format!("{user}\n\nInvalid previous response (untrusted data):\n{invalid}")
}

#[cfg(feature = "qualification-candidate")]
fn atomic_attribution_repair_system(system: &str) -> String {
    format!(
        "{system}\nThe previous response violated the response contract. Return only one JSON object with exactly sameDefect (boolean) and reason (one trimmed, punctuated line of at most {SCORER_REASON_MAX_BYTES} UTF-8 bytes)."
    )
}

#[cfg(feature = "qualification-candidate")]
fn atomic_attribution_repair_user(user: &str, invalid: &str) -> String {
    let invalid = crate::prompt::sanitize_scorer_input(invalid);
    format!("{user}\n\nInvalid first response:\n{invalid}")
}

#[derive(Default)]
struct PlannedExposure {
    attempts: usize,
    input_bytes: usize,
    output_tokens: usize,
    projected_cost_micros: u64,
    model_costs_micros: BTreeMap<String, u64>,
}

impl TryFrom<&PlannedExposure> for ReviewAdmission {
    type Error = anyhow::Error;

    fn try_from(value: &PlannedExposure) -> Result<Self> {
        Ok(Self {
            provider_attempts: u32::try_from(value.attempts)
                .context("planned provider attempts exceed the envelope range")?,
            serialized_input_bytes: u64::try_from(value.input_bytes)
                .context("planned provider input exceeds the envelope range")?,
            output_tokens: u64::try_from(value.output_tokens)
                .context("planned provider output exceeds the envelope range")?,
            projected_cost_micros: value.projected_cost_micros,
        })
    }
}

impl PlannedExposure {
    fn add_request(
        &mut self,
        serialized_bytes: usize,
        request_output_tokens: usize,
        price: &ModelPriceBound,
    ) -> Result<()> {
        self.add_request_attempts(
            serialized_bytes,
            request_output_tokens,
            price,
            MAX_TRANSPORT_ATTEMPTS_PER_CALL,
        )
    }

    fn add_primary_request(
        &mut self,
        serialized_bytes: usize,
        request_output_tokens: usize,
        price: &ModelPriceBound,
    ) -> Result<()> {
        self.add_request_attempts(serialized_bytes, request_output_tokens, price, 1)
    }

    fn add_request_attempts(
        &mut self,
        serialized_bytes: usize,
        request_output_tokens: usize,
        price: &ModelPriceBound,
        attempts_per_call: usize,
    ) -> Result<()> {
        let attempts = self
            .attempts
            .checked_add(attempts_per_call)
            .context("planned provider attempt count overflowed")?;
        let input_bytes = self
            .input_bytes
            .checked_add(
                serialized_bytes
                    .checked_mul(attempts_per_call)
                    .context("planned provider input exposure overflowed")?,
            )
            .context("planned provider input exposure overflowed")?;
        let output_tokens = self
            .output_tokens
            .checked_add(
                request_output_tokens
                    .checked_mul(attempts_per_call)
                    .context("planned provider output exposure overflowed")?,
            )
            .context("planned provider output exposure overflowed")?;
        let request_cost =
            projected_request_cost_micros(serialized_bytes, request_output_tokens, price)?
                .checked_mul(attempts_per_call as u64)
                .context("planned provider cost exposure overflowed")?;
        let projected_cost_micros = self
            .projected_cost_micros
            .checked_add(request_cost)
            .context("planned provider cost exposure overflowed")?;
        let model_cost_micros = self
            .model_costs_micros
            .get(&price.model)
            .copied()
            .unwrap_or_default()
            .checked_add(request_cost)
            .context("planned model cost exposure overflowed")?;
        self.attempts = attempts;
        self.input_bytes = input_bytes;
        self.output_tokens = output_tokens;
        self.projected_cost_micros = projected_cost_micros;
        self.model_costs_micros
            .insert(price.model.clone(), model_cost_micros);
        Ok(())
    }
}

fn projected_request_cost_micros(
    input_token_upper_bound: usize,
    output_token_upper_bound: usize,
    price: &ModelPriceBound,
) -> Result<u64> {
    fn priced_tokens(tokens: usize, micros_per_million: u64) -> Result<u128> {
        let numerator = (tokens as u128)
            .checked_mul(u128::from(micros_per_million))
            .ok_or_else(|| anyhow!("hosted model price projection overflowed"))?;
        numerator
            .checked_add(999_999)
            .map(|rounded| rounded / 1_000_000)
            .ok_or_else(|| anyhow!("hosted model price projection overflowed"))
    }
    let input = priced_tokens(
        input_token_upper_bound,
        price.input_micros_per_million_tokens,
    )?;
    let output = priced_tokens(
        output_token_upper_bound,
        price.output_micros_per_million_tokens,
    )?;
    u64::try_from(
        input
            .checked_add(output)
            .ok_or_else(|| anyhow!("hosted model price projection overflowed"))?,
    )
    .context("hosted model price projection does not fit micro-dollar accounting")
}

fn serialized_provider_request_bytes(body: &serde_json::Value, context: &str) -> Result<usize> {
    let bytes = serde_json::to_vec(body).with_context(|| context.to_string())?;
    ensure!(
        bytes.len() <= MAX_PROVIDER_REQUEST_BYTES,
        "model provider request needs {} serialized bytes, exceeding the {MAX_PROVIDER_REQUEST_BYTES} byte per-request cap",
        bytes.len()
    );
    Ok(bytes.len())
}

pub(crate) fn scorer_max_tokens(expected_len: usize) -> Option<u32> {
    (expected_len <= SCORER_MAX_FINDINGS)
        .then(|| SCORER_BASE_MAX_TOKENS + expected_len as u32 * SCORER_MAX_TOKENS_PER_FINDING)
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn validate_batch_selection(
    content: &str,
    allowed_ids: &BTreeSet<usize>,
    max_selected: usize,
) -> Result<Vec<usize>> {
    let raw: RawBatchSelection = serde_json::from_str(content.trim())
        .context("planner response is not the exact batch-selection JSON object")?;
    ensure!(
        raw.batch_ids.len() <= max_selected,
        "planner selected more than {max_selected} batches"
    );
    let original_len = raw.batch_ids.len();
    let selected = raw.batch_ids.into_iter().collect::<BTreeSet<_>>();
    ensure!(
        selected.len() == original_len,
        "planner batch selection contains duplicates"
    );
    ensure!(
        selected.iter().all(|id| allowed_ids.contains(id)),
        "planner selected a batch ID outside the grounded candidate set"
    );
    Ok(selected.into_iter().collect())
}
/// Marker context attached to transport/provider-level failures (endpoint
/// unreachable, HTTP error status, timeout, malformed HTTP envelope), the
/// class a malicious diff cannot induce. `gate.onError: advisory` stands aside
/// only for errors carrying this marker; unusable model *content* (which
/// prompt injection can cause) always fails closed.
#[derive(Debug, Clone, Copy)]
pub struct ProviderError;

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("model provider request failed")
    }
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 529)
}

fn provider_retry_delay(retry: u32) -> Duration {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let sequence = PROVIDER_RETRY_JITTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let sample = elapsed.as_secs().rotate_left(17)
        ^ u64::from(elapsed.subsec_nanos())
        ^ u64::from(std::process::id()).rotate_left(32)
        ^ sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    provider_retry_delay_with_sample(retry, sample)
}

fn provider_retry_delay_with_sample(retry: u32, sample: u64) -> Duration {
    let ceiling_ms = 2_000_u64.saturating_mul(u64::from(retry.max(1)));
    let floor_ms = ceiling_ms / 2;
    let jitter_ms = sample % (ceiling_ms - floor_ms + 1);
    Duration::from_millis(floor_ms + jitter_ms)
}

fn timeout_status(status: u16) -> bool {
    matches!(status, 408 | 504)
}

fn reqwest_error(error: &anyhow::Error) -> Option<&reqwest::Error> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LlmPhase {
    Planner,
    Review,
    Scorer {
        expected_len: usize,
    },
    #[cfg_attr(not(feature = "qualification-candidate"), allow(dead_code))]
    Attribution,
    Respond,
    #[cfg_attr(not(test), allow(dead_code))]
    Total,
}

#[derive(Debug, Clone, Copy)]
enum LlmCallPhase {
    Initial,
    SchemaRepair,
    SemanticRetry,
}

impl LlmPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Review => "review",
            Self::Scorer { .. } => "scorer",
            Self::Attribution => "attribution",
            Self::Respond => "respond",
            Self::Total => "total",
        }
    }

    fn usage_role(self) -> ModelUsageRole {
        match self {
            Self::Planner => ModelUsageRole::ReviewPlanner,
            Self::Review | Self::Total => ModelUsageRole::ReviewGenerator,
            Self::Scorer { .. } => ModelUsageRole::FindingScorer,
            Self::Attribution => ModelUsageRole::FindingScorer,
            Self::Respond => ModelUsageRole::MentionResponder,
        }
    }

    fn exhausted_output_retry_max_tokens(self, initial_max_tokens: u32) -> u32 {
        if matches!(self, Self::Scorer { .. } | Self::Attribution)
            || initial_max_tokens >= EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS
        {
            initial_max_tokens
        } else {
            initial_max_tokens
                .saturating_mul(2)
                .min(EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS)
        }
    }
}

impl LlmCallPhase {
    fn usage_phase(self) -> ModelUsagePhase {
        match self {
            Self::Initial => ModelUsagePhase::Initial,
            Self::SchemaRepair => ModelUsagePhase::SchemaRepair,
            Self::SemanticRetry => ModelUsagePhase::SemanticRetry,
        }
    }
}

struct ModelHttpResponse {
    status: reqwest::StatusCode,
    text: String,
    retry_after: Option<Duration>,
    request_id: Option<String>,
}

#[derive(Default)]
struct SafeResponseSummary {
    response_id: Option<String>,
    returned_model: Option<String>,
    provider: Option<String>,
    finish_reason: Option<String>,
    reasoning_tokens: Option<u64>,
    error_type: Option<String>,
    choices: Option<usize>,
    usage: Option<Usage>,
}

#[cfg_attr(not(feature = "qualification-candidate"), allow(dead_code))]
struct ChatSuccess {
    content: String,
    returned_model: Option<String>,
    provider: Option<String>,
}

#[derive(Debug)]
// Every failure derived from assistant content in a successful provider
// response belongs here. The classifier treats this enum as operational and
// treats every other unmarked chat error as a provider failure.
enum ModelContentFailure {
    Empty,
    MissingChoices,
    NonTerminal { reason: String },
}

impl ModelContentFailure {
    #[cfg_attr(not(any(test, feature = "qualification-candidate")), allow(dead_code))]
    fn nonterminal_reason(&self) -> Option<&str> {
        match self {
            Self::NonTerminal { reason } => Some(reason),
            Self::Empty | Self::MissingChoices => None,
        }
    }

    fn retryable_empty(&self) -> bool {
        matches!(self, Self::Empty | Self::MissingChoices)
    }
}

impl std::fmt::Display for ModelContentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("model response had no choices/content"),
            Self::MissingChoices => formatter.write_str("model response had no choices"),
            Self::NonTerminal { reason } => {
                write!(formatter, "model response was nonterminal ({reason})")
            }
        }
    }
}

impl std::error::Error for ModelContentFailure {}

fn classify_chat_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<ModelContentFailure>().is_some() {
        error
    } else {
        error.context(ProviderError)
    }
}

#[derive(Debug, Clone, Copy)]
struct DeadlineExceeded(LlmPhase);

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            LlmPhase::Planner => f.write_str("LLM planner deadline exceeded"),
            LlmPhase::Review => f.write_str("LLM review deadline exceeded"),
            LlmPhase::Scorer { .. }
            | LlmPhase::Attribution
            | LlmPhase::Respond
            | LlmPhase::Total => f.write_str("LLM total deadline exceeded"),
        }
    }
}

impl std::error::Error for DeadlineExceeded {}

#[derive(Debug, Clone, Copy)]
struct RequestTimedOut;

impl std::fmt::Display for RequestTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LLM request timed out")
    }
}

impl std::error::Error for RequestTimedOut {}

impl LlmClient {
    fn planned_request_bytes(
        &self,
        model: &str,
        system: &str,
        user: &str,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
    ) -> Result<usize> {
        serialized_provider_request_bytes(
            &self.request_body(model, system, user, max_tokens, temperature, phase),
            "serializing hosted request for preflight",
        )
    }

    fn planned_request_exposure(
        &self,
        model: &str,
        system: &str,
        user: &str,
        initial_max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
    ) -> Result<(usize, usize)> {
        let output_tokens = phase.exhausted_output_retry_max_tokens(initial_max_tokens);
        Ok((
            self.planned_request_bytes(model, system, user, output_tokens, temperature, phase)?,
            output_tokens as usize,
        ))
    }

    fn validate_hosted_exposure(
        &self,
        operation: &str,
        exposure: &PlannedExposure,
    ) -> Result<ReviewAdmission> {
        ensure!(
            exposure.attempts <= MAX_PROVIDER_ATTEMPTS,
            "hosted {operation} admission needs {} provider attempts, exceeding the {MAX_PROVIDER_ATTEMPTS}-attempt cap",
            exposure.attempts
        );
        ensure!(
            exposure.input_bytes <= MAX_PROVIDER_INPUT_BYTES,
            "hosted {operation} admission needs {} bytes of serialized provider input, exceeding the {MAX_PROVIDER_INPUT_BYTES} byte cap",
            exposure.input_bytes
        );
        ensure!(
            exposure.output_tokens <= MAX_PROVIDER_OUTPUT_TOKEN_EXPOSURE,
            "hosted {operation} admission needs {} output tokens of exposure, exceeding the {MAX_PROVIDER_OUTPUT_TOKEN_EXPOSURE} token cap",
            exposure.output_tokens
        );
        let token_exposure = exposure
            .input_bytes
            .checked_add(exposure.output_tokens)
            .context("planned token exposure overflowed")?;
        ensure!(
            token_exposure <= MAX_REPORTED_TOKEN_SPEND,
            "hosted {operation} admission needs {token_exposure} tokens of exposure, exceeding the {MAX_REPORTED_TOKEN_SPEND} token cap"
        );
        let model_costs = exposure
            .model_costs_micros
            .iter()
            .map(|(model, cost)| format!("{:?}={cost}", log_text(model)))
            .collect::<Vec<_>>()
            .join(", ");
        ensure!(
            exposure.projected_cost_micros <= HOSTED_OPERATION_COST_CAP_MICROS,
            "hosted {operation} admission projects {} micro-dollars of provider exposure across {} attempts, {} serialized input bytes, and {} output tokens (per-model micro-dollars: {model_costs}), exceeding the {HOSTED_OPERATION_COST_CAP_MICROS} micro-dollar operation cap",
            exposure.projected_cost_micros,
            exposure.attempts,
            exposure.input_bytes,
            exposure.output_tokens
        );
        ReviewAdmission::try_from(exposure)
    }

    pub(crate) fn preflight_respond_plan(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
    ) -> Result<ReviewAdmission> {
        let Some(bounds) = &self.hosted_price_bounds else {
            return Ok(ReviewAdmission::default());
        };
        let models = cfg.model_chain();
        ensure!(!models.is_empty(), "hosted respond has no admitted model");
        let mut exposure = PlannedExposure::default();
        for model in models {
            let price = bounds.get(&model).ok_or_else(|| {
                anyhow!("hosted respond model {model:?} has no admitted price bound")
            })?;
            let (request, output_tokens) = self.planned_request_exposure(
                &model,
                system,
                user,
                RESPOND_MAX_TOKENS,
                0.1,
                LlmPhase::Respond,
            )?;
            exposure.add_request(request, output_tokens, price)?;
        }
        self.validate_hosted_exposure("respond", &exposure)
    }

    pub async fn plan_review_batches(
        &self,
        cfg: &Config,
        manifest: &str,
        allowed_ids: &BTreeSet<usize>,
        max_selected: usize,
    ) -> Result<BatchPlannerResult> {
        if max_selected == 0 || allowed_ids.is_empty() {
            return Ok(BatchPlannerResult {
                batch_ids: Vec::new(),
                usage: Usage::default(),
                model_usage: Vec::new(),
                model_incidents: Vec::new(),
                usage_accounting_complete: true,
                fallback_used: false,
            });
        }
        let system = planner_system_prompt();
        let user = planner_user_prompt(manifest, max_selected);
        let mut aggregate_usage = Usage::default();
        let mut aggregate_model_usage = Vec::new();
        let mut aggregate_incidents: Vec<ModelIncident> = Vec::new();
        let mut accounting_complete = true;
        let planner_models = if cfg.consensus > 1 {
            cfg.model_chain()
                .into_iter()
                .take(cfg.consensus)
                .collect::<Vec<_>>()
        } else {
            cfg.model_chain()
        };
        for model in planner_models {
            match self
                .plan_with_model(&model, system, &user, allowed_ids, max_selected)
                .await
            {
                Ok(mut result) => {
                    result.fallback_used |= !aggregate_incidents.is_empty();
                    add_usage(&mut result.usage, aggregate_usage);
                    result.model_usage.splice(0..0, aggregate_model_usage);
                    for incident in &mut aggregate_incidents {
                        incident.recovered = true;
                        incident.recovery = Some(ModelIncidentRecovery::Fallback);
                    }
                    result.model_incidents.splice(0..0, aggregate_incidents);
                    result.usage_accounting_complete &= accounting_complete;
                    return Ok(result);
                }
                Err(error) => {
                    let incident = error.incident(ModelIncidentPhase::Planner);
                    accounting_complete &= error.usage_accounting_complete;
                    add_usage(&mut aggregate_usage, error.usage);
                    aggregate_incidents.extend(error.model_incidents.clone());
                    aggregate_model_usage.extend(error.model_usage);
                    aggregate_incidents.push(incident);
                }
            }
        }
        for incident in &mut aggregate_incidents {
            incident.recovered = true;
            incident.recovery = Some(ModelIncidentRecovery::Fallback);
        }
        Ok(BatchPlannerResult {
            batch_ids: Vec::new(),
            usage: aggregate_usage,
            model_usage: aggregate_model_usage,
            model_incidents: aggregate_incidents,
            usage_accounting_complete: accounting_complete,
            fallback_used: true,
        })
    }

    async fn plan_with_model(
        &self,
        model: &str,
        system: &str,
        user: &str,
        allowed_ids: &BTreeSet<usize>,
        max_selected: usize,
    ) -> std::result::Result<BatchPlannerResult, ModelError> {
        let mut usage = Usage::default();
        let mut model_usage = Vec::new();
        let mut model_incidents = Vec::new();
        let mut accounting_complete = true;
        let content = self
            .chat(
                model,
                system,
                user,
                &mut usage,
                &mut model_usage,
                &mut accounting_complete,
                PLANNER_MAX_TOKENS,
                LlmPhase::Planner,
                LlmCallPhase::Initial,
            )
            .await
            .map_err(|error| {
                let mut error = ModelError::new(error, usage, accounting_complete);
                error.model_usage = model_usage.clone();
                error
            })?;
        let selected = match validate_batch_selection(&content, allowed_ids, max_selected) {
            Ok(selected) => selected,
            Err(first_error) => {
                let incident = ModelIncident {
                    phase: ModelIncidentPhase::Planner,
                    category: ModelIncidentCategory::InvalidOutput,
                    recovered: false,
                    recovery: None,
                };
                let invalid = truncate_utf8_bytes(&content, 8_192);
                let first_error = first_error.to_string();
                let repair_user = planner_repair_user(
                    user,
                    invalid,
                    truncate_utf8_bytes(&first_error, REPAIR_ERROR_MAX_BYTES),
                );
                let repaired = self
                    .chat(
                        model,
                        "Repair the batch-selection JSON. Return only {\"batchIds\":[integer,...]}.",
                        &repair_user,
                        &mut usage,
                        &mut model_usage,
                        &mut accounting_complete,
                        PLANNER_MAX_TOKENS,
                        LlmPhase::Planner,
                        LlmCallPhase::SchemaRepair,
                    )
                    .await
                    .map_err(|error| {
                        let mut error = ModelError::new(error, usage, accounting_complete);
                        error.model_usage = model_usage.clone();
                        error.model_incidents.push(incident.clone());
                        error
                    })?;
                let selected = validate_batch_selection(&repaired, allowed_ids, max_selected)
                    .map_err(|error| {
                        let mut error = ModelError::new(
                            error.context("planner output invalid after schema repair"),
                            usage,
                            accounting_complete,
                        );
                        error.model_usage = model_usage.clone();
                        error.model_incidents.push(incident.clone());
                        error
                    })?;
                model_incidents.push(ModelIncident {
                    recovered: true,
                    recovery: Some(ModelIncidentRecovery::Repair),
                    ..incident
                });
                selected
            }
        };
        Ok(BatchPlannerResult {
            batch_ids: selected,
            usage,
            model_usage,
            model_incidents,
            usage_accounting_complete: accounting_complete,
            fallback_used: false,
        })
    }

    pub(crate) fn preflight_review_plan(
        &self,
        cfg: &Config,
        batch_count: usize,
        system: &str,
        candidate_first_users: &[String],
        candidate_later_users: &[String],
        planner: Option<(&str, usize)>,
    ) -> Result<ReviewAdmission> {
        let Some(bounds) = &self.hosted_price_bounds else {
            anyhow::bail!("hosted review preflight has no admitted price bounds");
        };
        ensure!(
            candidate_first_users.len() >= batch_count
                && candidate_first_users.len() == candidate_later_users.len(),
            "hosted preflight has fewer candidate prompts than selectable batches"
        );
        let review_models = if cfg.consensus > 1 {
            cfg.model_chain()
                .into_iter()
                .take(cfg.consensus)
                .collect::<Vec<_>>()
        } else {
            cfg.model_chain()
        };
        let scorer_models = if cfg.scorer_enabled() {
            cfg.scorer_chain()
        } else {
            Vec::new()
        };
        let review_logical_calls = batch_count
            .checked_mul(review_models.len())
            .and_then(|value| value.checked_mul(MAX_LOGICAL_CALLS_PER_REVIEW_MODEL))
            .context("planned review call count overflowed")?;
        let scorer_logical_calls = scorer_models
            .len()
            .checked_mul(MAX_LOGICAL_CALLS_PER_SCORER_MODEL)
            .context("planned scorer call count overflowed")?;
        let planner = planner.filter(|(_, max_selected)| *max_selected > 0);
        let planner_logical_calls = planner
            .map(|_| {
                review_models
                    .len()
                    .checked_mul(MAX_LOGICAL_CALLS_PER_REVIEW_MODEL)
                    .context("planned planner call count overflowed")
            })
            .transpose()?
            .unwrap_or(0);
        let logical_calls = review_logical_calls
            .checked_add(scorer_logical_calls)
            .and_then(|value| value.checked_add(planner_logical_calls))
            .context("planned model call count overflowed")?;
        anyhow::ensure!(
            logical_calls <= MAX_HOSTED_PLANNED_CALLS_BY_WATCHDOG,
            "complete hosted review needs {logical_calls} logical model calls, exceeding the {MAX_HOSTED_PLANNED_CALLS_BY_WATCHDOG}-call watchdog plan"
        );
        // Admission proves that the normal path can finish within the operation
        // cap. Repairs and transport retries reserve their actual request cost
        // atomically before each network call and stop at the same hard cap.
        let mut exposure = PlannedExposure::default();
        for model in &review_models {
            let price = bounds
                .get(model)
                .ok_or_else(|| anyhow!("hosted model {model:?} has no admitted price bound"))?;
            let request_for = |user: &str| -> Result<(usize, usize)> {
                self.planned_request_exposure(
                    model,
                    system,
                    user,
                    REVIEW_MAX_TOKENS,
                    0.1,
                    LlmPhase::Review,
                )
            };
            let first_requests = candidate_first_users
                .iter()
                .map(|user| request_for(user))
                .collect::<Result<Vec<_>>>()?;
            let later_requests = candidate_later_users
                .iter()
                .map(|user| request_for(user))
                .collect::<Result<Vec<_>>>()?;
            let mut worst_requests = Vec::new();
            let mut worst_bytes = 0usize;
            for (first_index, first) in first_requests.iter().copied().enumerate() {
                let mut requests = later_requests
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(index, _)| *index != first_index)
                    .map(|(_, request)| request)
                    .collect::<Vec<_>>();
                requests.sort_unstable_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
                requests.truncate(batch_count.saturating_sub(1));
                requests.push(first);
                let bytes = requests.iter().try_fold(0usize, |sum, (request, _)| {
                    sum.checked_add(*request)
                        .context("planned review path size overflowed")
                })?;
                if bytes > worst_bytes {
                    worst_bytes = bytes;
                    worst_requests = requests;
                }
            }
            for (request, output_tokens) in worst_requests {
                exposure.add_primary_request(request, output_tokens, price)?;
            }
        }

        for model in &scorer_models {
            let price = bounds
                .get(model)
                .ok_or_else(|| anyhow!("hosted scorer {model:?} has no admitted price bound"))?;
            let scorer_system = crate::prompt::scorer_system_prompt(cfg);
            let scorer_user_bytes =
                crate::review::MAX_SCORER_PROMPT_BYTES.saturating_sub(scorer_system.len());
            let scorer_user = "\"".repeat(scorer_user_bytes);
            let max_tokens = scorer_max_tokens(SCORER_MAX_FINDINGS)
                .expect("maximum scorer finding count has a token bound");
            let (initial, output_tokens) = self.planned_request_exposure(
                model,
                &scorer_system,
                &scorer_user,
                max_tokens,
                0.0,
                LlmPhase::Scorer {
                    expected_len: SCORER_MAX_FINDINGS,
                },
            )?;
            exposure.add_primary_request(initial, output_tokens, price)?;
        }

        if let Some((manifest, max_selected)) = planner {
            let user = planner_user_prompt(manifest, max_selected);
            for model in &review_models {
                let price = bounds.get(model).ok_or_else(|| {
                    anyhow!("hosted planner model {model:?} has no admitted price bound")
                })?;
                let (initial, output_tokens) = self.planned_request_exposure(
                    model,
                    planner_system_prompt(),
                    &user,
                    PLANNER_MAX_TOKENS,
                    0.1,
                    LlmPhase::Planner,
                )?;
                exposure.add_primary_request(initial, output_tokens, price)?;
            }
        }
        self.validate_hosted_exposure("review", &exposure)
    }

    pub(crate) async fn doctor_probe(cfg: &Config, api_key: String) -> Result<()> {
        let client = Self::build(cfg, api_key, Duration::from_secs(30), None, None)?;
        let body = client.request_body(&cfg.model, "", "ping", 1, 0.0, LlmPhase::Review);
        let response = tokio::time::timeout(Duration::from_secs(30), client.request_once(&body))
            .await
            .map_err(|_| RequestTimedOut)??;
        if !response.status.is_success() {
            let summary = safe_response_summary(
                &response.text,
                client.api_format,
                is_canonical_openrouter_base(&client.api_base),
            );
            return Err(anyhow!(provider_http_status_detail(
                response.status,
                &summary,
                response.request_id.as_deref(),
            )));
        }
        client.parse_response(&response.text, &mut Usage::default())?;
        Ok(())
    }

    /// Local and interactive clients have no built-in total deadline. They only
    /// get one when POSTIL_LLM_TOTAL_TIMEOUT_SECS is explicitly set.
    pub fn from_env(cfg: &Config) -> Result<Self> {
        let api_key = resolve_api_key()?;
        let timeouts = LlmTimeouts::from_env(DEFAULT_REQUEST_TIMEOUT_SECS, None)?;
        let total_deadline = timeouts.total.map(|duration| Instant::now() + duration);
        Self::build(
            cfg,
            api_key,
            timeouts.request,
            total_deadline,
            total_deadline,
        )
    }

    pub(crate) fn from_env_for_remote_review(
        cfg: &Config,
        total_budget_started_at: Instant,
        default_request_timeout: Duration,
        default_review_timeout: Duration,
        default_total_timeout: Duration,
    ) -> Result<Self> {
        let api_key = resolve_api_key()?;
        let timeouts = LlmTimeouts::from_env(
            default_request_timeout.as_secs(),
            Some(default_total_timeout.as_secs()),
        )?;
        let total_deadline = timeouts
            .total
            .map(|duration| total_budget_started_at + duration);
        let review_deadline = Some(total_budget_started_at + default_review_timeout)
            .map(|deadline| total_deadline.map_or(deadline, |total| deadline.min(total)));
        Self::build(
            cfg,
            api_key,
            timeouts.request,
            review_deadline,
            total_deadline,
        )
    }

    fn build(
        cfg: &Config,
        api_key: String,
        request_timeout: Duration,
        review_deadline: Option<Instant>,
        total_deadline: Option<Instant>,
    ) -> Result<Self> {
        let endpoint_auth = endpoint_auth_from_env(cfg.api_format)?;
        let screening_profile = crate::config::benchmark_screening_profile_for_config(cfg)?;
        let hosted_price_bounds = if crate::config::hosted_runtime_mode() {
            ensure_hosted_provider_contract(cfg.api_format, &cfg.api_base)?;
            Some(Arc::new(
                crate::config::hosted_price_bounds_for_config(cfg)?
                    .ok_or_else(|| anyhow!("hosted inference has no exact price-bound profile"))?
                    .into_iter()
                    .map(|bound| (bound.model.clone(), bound))
                    .collect(),
            ))
        } else if let Some(profile) = screening_profile.as_ref() {
            ensure_hosted_provider_contract(cfg.api_format, &cfg.api_base)?;
            Some(Arc::new(
                profile
                    .model_price_bounds
                    .iter()
                    .cloned()
                    .map(|bound| (bound.model.clone(), bound))
                    .collect(),
            ))
        } else {
            None
        };
        let pinned_upstream_provider =
            if let Some(provider) = crate::config::provisional_hosted_provider_for_config(cfg) {
                Some(provider.to_string())
            } else if crate::config::qualification_candidate_mode() {
                Some(
                    crate::config::qualification_candidate_profile_for_config(cfg)?
                        .ok_or_else(|| anyhow!("qualification provider profile is unavailable"))?
                        .upstream_provider_identity,
                )
            } else if let Some(profile) = screening_profile {
                Some(profile.upstream_provider_identity)
            } else {
                None
            };
        let request_api_base = qualification_request_api_base(&cfg.api_base)?;
        Ok(LlmClient {
            // The attempt timeout wraps both sending the request and consuming
            // the complete response body, so header and body stalls take the
            // same retry path.
            http: Arc::new(Mutex::new(None)),
            api_base: cfg.api_base.trim_end_matches('/').to_string(),
            request_api_base,
            api_key,
            api_format: cfg.api_format,
            endpoint_auth,
            require_openrouter_privacy: is_canonical_openrouter_base(&cfg.api_base)
                && (crate::config::hosted_runtime_mode()
                    || crate::config::benchmark_screening_mode()
                    || env_flag("POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY")),
            request_timeout,
            timeout_retry_timeout: request_timeout.min(Duration::from_secs(TIMEOUT_RETRY_CAP_SECS)),
            review_deadline,
            scorer_deadline: None,
            total_deadline,
            admission: Arc::new(Mutex::new(ProviderAdmission::default())),
            hosted_price_bounds,
            pinned_upstream_provider,
            call_ordinal: Arc::new(AtomicU32::new(0)),
        })
    }

    fn model_usage_event(
        &self,
        model: &str,
        role: LlmPhase,
        phase: LlmCallPhase,
        attempt: u32,
        usage: Option<Usage>,
    ) -> ModelUsage {
        let reported = usage.is_some_and(|value| {
            value.prompt_tokens > 0 || value.completion_tokens > 0 || value.provider_cost.is_some()
        });
        let usage = usage.unwrap_or_default();
        ModelUsage {
            model: model.to_string(),
            role: Some(role.usage_role()),
            phase: Some(phase.usage_phase()),
            call_ordinal: Some(self.call_ordinal.fetch_add(1, Ordering::Relaxed) + 1),
            attempt: Some(attempt),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            cost_micros: usage.cost_micros,
            cost_provider_decimal: usage.provider_cost.map(|value| value.to_string()),
            cost_source: Some(if usage.provider_cost.is_some() {
                ModelUsageCostSource::ProviderReported
            } else {
                ModelUsageCostSource::Unavailable
            }),
            accounting_complete: reported,
        }
    }

    /// Run the review. With `consensus > 1`, the first N models of the chain are
    /// each consulted and only findings two or more models agree on are kept.
    pub async fn review(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
    ) -> std::result::Result<ModelReview, ModelError> {
        self.review_validated(cfg, system, user, |_| Ok(())).await
    }

    /// Run a review while treating caller-rejected content as invalid model
    /// output. Each model gets one bounded semantic correction before the
    /// configured cascade advances, and every consumed call remains in usage.
    pub async fn review_validated<F>(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
        validate: F,
    ) -> std::result::Result<ModelReview, ModelError>
    where
        F: Fn(&ModelReview) -> std::result::Result<(), String> + Send + Sync + 'static,
    {
        let validate = Arc::new(validate);
        let chain = cfg.model_chain();
        if cfg.consensus > 1 && chain.len() > 1 {
            let n = cfg.consensus.min(chain.len());
            let handles: Vec<_> = chain[..n]
                .iter()
                .map(|m| {
                    let client = self.clone();
                    let (model, system, user) = (m.clone(), system.to_string(), user.to_string());
                    let validate = Arc::clone(&validate);
                    let task_model = model.clone();
                    let handle = tokio::spawn(async move {
                        let model_log = log_text(&task_model);
                        eprintln!("postil: attempting consensus model: {model_log}");
                        let started_at = Instant::now();
                        let result = client
                            .review_with_model(&task_model, &system, &user, validate.as_ref())
                            .await;
                        let elapsed = elapsed_text(started_at.elapsed());
                        match &result {
                            Ok(_) => eprintln!(
                                "postil: consensus model {model_log} responded in {elapsed}"
                            ),
                            Err(error) if error.is_timeout() => eprintln!(
                                "postil: consensus model {model_log} timed out after {elapsed}"
                            ),
                            Err(error) => eprintln!(
                                "postil: consensus model {model_log} failed after {elapsed} category={}",
                                safe_model_error_category(error)
                            ),
                        }
                        result
                    });
                    (model, handle)
                })
                .collect();
            let mut ok: Vec<ModelReview> = Vec::new();
            let mut failed_usage = Usage::default();
            let mut failed_model_usage = Vec::new();
            let mut failed_incidents: Vec<ModelIncident> = Vec::new();
            let mut usage_accounting_complete = true;
            let mut last_err: Option<ModelError> = None;
            for (model, handle) in handles {
                let model_log = log_text(&model);
                match handle.await {
                    Ok(Ok(r)) => ok.push(r),
                    Ok(Err(mut e)) => {
                        failed_incidents.extend(e.model_incidents.clone());
                        failed_incidents.push(e.incident(ModelIncidentPhase::Review));
                        usage_accounting_complete &= e.usage_accounting_complete;
                        failed_model_usage.extend(e.model_usage.clone());
                        add_usage(&mut failed_usage, e.usage);
                        e.usage = failed_usage;
                        last_err = Some(e);
                    }
                    Err(e) => {
                        usage_accounting_complete = false;
                        eprintln!("postil: consensus model {model_log} task panicked: {e}")
                    }
                }
            }
            if consensus_is_incomplete(crate::config::hosted_runtime_mode(), ok.len(), n) {
                let completed = ok.len();
                for review in ok {
                    add_usage(&mut failed_usage, review.usage);
                    failed_model_usage.extend(review.model_usage);
                    failed_incidents.extend(review.model_incidents);
                    usage_accounting_complete &= review.usage_accounting_complete;
                }
                let cause = last_err
                    .map(|error| error.error)
                    .unwrap_or_else(|| anyhow!("consensus task did not complete"));
                let mut error = ModelError::new(
                    cause.context(format!(
                        "hosted consensus requires all {n} admitted models; only {} completed",
                        completed
                    )),
                    failed_usage,
                    usage_accounting_complete,
                );
                error.model_usage = failed_model_usage;
                error.model_incidents = failed_incidents;
                return Err(error);
            }
            match ok.len() {
                // Wrap the last failure so its error class (provider vs
                // content) survives for gate.onError classification.
                0 => Err(match last_err {
                    Some(e) => {
                        let mut error = ModelError::new(
                            e.error.context(format!("all {n} consensus models failed")),
                            failed_usage,
                            usage_accounting_complete,
                        );
                        error.model_usage = failed_model_usage;
                        error.model_incidents = failed_incidents;
                        error
                    }
                    None => ModelError::new(
                        anyhow!("all {n} consensus models failed"),
                        failed_usage,
                        usage_accounting_complete,
                    ),
                }),
                1 => {
                    let mut review = ok.into_iter().next().unwrap();
                    add_usage(&mut review.usage, failed_usage);
                    review.model_usage.extend(failed_model_usage);
                    for incident in &mut failed_incidents {
                        incident.recovered = true;
                        incident.recovery = Some(ModelIncidentRecovery::Fallback);
                    }
                    review.model_incidents.extend(failed_incidents);
                    review.usage_accounting_complete &= usage_accounting_complete;
                    Ok(review)
                }
                _ => {
                    let mut review = consensus_merge(ok);
                    add_usage(&mut review.usage, failed_usage);
                    review.model_usage.extend(failed_model_usage);
                    for incident in &mut failed_incidents {
                        incident.recovered = true;
                        incident.recovery = Some(ModelIncidentRecovery::Fallback);
                    }
                    review.model_incidents.extend(failed_incidents);
                    review.usage_accounting_complete &= usage_accounting_complete;
                    Ok(review)
                }
            }
        } else {
            let mut failed_usage = Usage::default();
            let mut failed_model_usage = Vec::new();
            let mut failed_incidents: Vec<ModelIncident> = Vec::new();
            let mut usage_accounting_complete = true;
            let mut last_err = None;
            for (index, model) in chain.iter().enumerate() {
                let model_log = log_text(model);
                eprintln!(
                    "postil: attempting model: {model_log} (cascade {}/{})",
                    index + 1,
                    chain.len()
                );
                let started_at = Instant::now();
                match self
                    .review_with_model(model, system, user, validate.as_ref())
                    .await
                {
                    Ok(mut r) => {
                        eprintln!(
                            "postil: model {model_log} responded in {}",
                            elapsed_text(started_at.elapsed())
                        );
                        add_usage(&mut r.usage, failed_usage);
                        r.model_usage.splice(0..0, failed_model_usage);
                        for incident in &mut failed_incidents {
                            incident.recovered = true;
                            incident.recovery = Some(ModelIncidentRecovery::Fallback);
                        }
                        r.model_incidents.splice(0..0, failed_incidents);
                        r.usage_accounting_complete &= usage_accounting_complete;
                        return Ok(r);
                    }
                    Err(mut e) => {
                        failed_incidents.extend(e.model_incidents.clone());
                        failed_incidents.push(e.incident(ModelIncidentPhase::Review));
                        usage_accounting_complete &= e.usage_accounting_complete;
                        failed_model_usage.extend(e.model_usage.clone());
                        let elapsed = elapsed_text(started_at.elapsed());
                        if e.is_deadline_exceeded() {
                            add_usage(&mut failed_usage, e.usage);
                            e.usage = failed_usage;
                            eprintln!(
                                "postil: model {model_log} stopped after {elapsed}: {e}; cascade fallback is disabled after deadline exhaustion"
                            );
                            e.model_usage = failed_model_usage;
                            e.model_incidents = failed_incidents;
                            return Err(e);
                        }
                        let has_fallback = index + 1 < chain.len();
                        if e.is_timeout() {
                            if has_fallback {
                                eprintln!(
                                    "postil: model {model_log} timed out after {elapsed}, falling back to next model"
                                );
                            } else {
                                eprintln!(
                                    "postil: model {model_log} timed out after {elapsed}; no fallback models remain"
                                );
                            }
                        } else if has_fallback {
                            eprintln!(
                                "postil: model {model_log} failed after {elapsed}, falling back to next model category={}",
                                safe_model_error_category(&e)
                            );
                        } else {
                            eprintln!(
                                "postil: model {model_log} failed after {elapsed}; no fallback models remain category={}",
                                safe_model_error_category(&e)
                            );
                        }
                        add_usage(&mut failed_usage, e.usage);
                        e.usage = failed_usage;
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err
                .map(|mut error| {
                    error.model_usage = failed_model_usage;
                    error.model_incidents = failed_incidents;
                    error.usage_accounting_complete = usage_accounting_complete;
                    error
                })
                .unwrap_or_else(|| {
                    ModelError::new(anyhow!("empty model chain"), failed_usage, true)
                }))
        }
    }

    /// Interactive answer validated by the caller's publication contract.
    /// Invalid model content consumes and preserves its usage before the next
    /// configured model is tried.
    pub async fn answer<F>(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
        validate: F,
    ) -> Result<Answer>
    where
        F: Fn(&str) -> Result<String>,
    {
        let mut usage = Usage::default();
        let mut models = Vec::new();
        let mut last_err = None;
        let mut usage_accounting_complete = true;
        let chain = cfg.model_chain();
        let chain_len = chain.len();
        for (index, model) in chain.into_iter().enumerate() {
            let mut model_usage = Usage::default();
            let mut call_usage = Vec::new();
            let mut model_accounting_complete = true;
            match self
                .chat(
                    &model,
                    system,
                    user,
                    &mut model_usage,
                    &mut call_usage,
                    &mut model_accounting_complete,
                    RESPOND_MAX_TOKENS,
                    LlmPhase::Respond,
                    LlmCallPhase::Initial,
                )
                .await
            {
                Ok(content) => {
                    usage_accounting_complete &= model_accounting_complete;
                    add_usage(&mut usage, model_usage);
                    models.append(&mut call_usage);
                    match validate(&content) {
                        Ok(content) => {
                            return Ok(Answer {
                                content,
                                model_used: model,
                                usage,
                                models,
                                usage_accounting_complete,
                            });
                        }
                        Err(error) => {
                            let disposition = if index + 1 < chain_len {
                                "trying the next model"
                            } else {
                                "no fallback models remain"
                            };
                            eprintln!(
                                "postil: model {} produced an invalid reply; {disposition} category={}",
                                log_text(&model),
                                safe_anyhow_category(&error),
                            );
                            last_err = Some(error.context("model reply failed publication checks"));
                        }
                    }
                }
                Err(e) => {
                    // Usage parsed from a provider response is complete even
                    // when the response has no usable answer. A transport
                    // failure with no response usage is ambiguous.
                    if !model_accounting_complete || !has_billable_usage(model_usage) {
                        usage_accounting_complete = false;
                    }
                    eprintln!(
                        "postil: model {} failed category={}",
                        log_text(&model),
                        safe_anyhow_category(&e)
                    );
                    // Provider failures that report no tokens have no billable
                    // usage to attribute. Omit them rather than emitting a
                    // misleading accounting entry; token-bearing failures are
                    // retained and priced by the hosted control plane.
                    if has_billable_usage(model_usage) {
                        add_usage(&mut usage, model_usage);
                    }
                    models.append(&mut call_usage);
                    if e.downcast_ref::<DeadlineExceeded>().is_some() {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("empty model chain")))
    }

    pub async fn score_findings(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
        expected_len: usize,
        timeout: Duration,
    ) -> std::result::Result<ScorerReview, ModelError> {
        let mut scorer_client = self.clone();
        let deadline = Instant::now() + timeout;
        scorer_client.scorer_deadline = Some(
            self.total_deadline
                .map_or(deadline, |total| deadline.min(total)),
        );
        let mut failed_usage = Usage::default();
        let mut failed_model_usage = Vec::new();
        let mut failed_incidents: Vec<ModelIncident> = Vec::new();
        let mut usage_accounting_complete = true;
        let mut last_err = None;
        let chain = cfg.scorer_chain();
        for (index, model) in chain.iter().enumerate() {
            let model_log = log_text(model);
            eprintln!(
                "postil: running scorer with {model_log} (cascade {}/{})",
                index + 1,
                chain.len()
            );
            let started_at = Instant::now();
            match scorer_client
                .score_with_model(model, system, user, expected_len)
                .await
            {
                Ok(mut r) => {
                    eprintln!(
                        "postil: scorer {model_log} completed successfully in {}",
                        elapsed_text(started_at.elapsed())
                    );
                    add_usage(&mut r.usage, failed_usage);
                    r.model_usage.splice(0..0, failed_model_usage);
                    for incident in &mut failed_incidents {
                        incident.recovered = true;
                        incident.recovery = Some(ModelIncidentRecovery::Fallback);
                    }
                    r.model_incidents.splice(0..0, failed_incidents);
                    r.usage_accounting_complete &= usage_accounting_complete;
                    return Ok(r);
                }
                Err(mut e) => {
                    failed_incidents.extend(e.model_incidents.clone());
                    failed_incidents.push(e.incident(ModelIncidentPhase::Scorer));
                    usage_accounting_complete &= e.usage_accounting_complete;
                    failed_model_usage.extend(e.model_usage.clone());
                    let elapsed = elapsed_text(started_at.elapsed());
                    if e.is_deadline_exceeded() {
                        add_usage(&mut failed_usage, e.usage);
                        e.usage = failed_usage;
                        eprintln!(
                            "postil: scorer {model_log} stopped after {elapsed}: {e}; scorer fallback is disabled after deadline exhaustion"
                        );
                        e.model_usage = failed_model_usage;
                        e.model_incidents = failed_incidents;
                        return Err(e);
                    }
                    let has_fallback = index + 1 < chain.len();
                    if e.is_timeout() && has_fallback {
                        eprintln!(
                            "postil: scorer {model_log} timed out after {elapsed}, falling back to next scorer"
                        );
                    } else if e.is_timeout() {
                        eprintln!(
                            "postil: scorer {model_log} timed out after {elapsed}; no fallback scorers remain"
                        );
                    } else if has_fallback {
                        eprintln!(
                            "postil: scorer {model_log} failed after {elapsed}, falling back to next scorer category={}",
                            safe_model_error_category(&e)
                        );
                    } else {
                        eprintln!(
                            "postil: scorer {model_log} failed after {elapsed}; no fallback scorers remain category={}",
                            safe_model_error_category(&e)
                        );
                    }
                    add_usage(&mut failed_usage, e.usage);
                    e.usage = failed_usage;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .map(|mut error| {
                error.model_usage = failed_model_usage;
                error.model_incidents = failed_incidents;
                error.usage_accounting_complete = usage_accounting_complete;
                error
            })
            .unwrap_or_else(|| {
                ModelError::new(anyhow!("empty scorer model chain"), failed_usage, true)
            }))
    }

    /// Qualification-only transport for one atomic same-defect judgment.
    /// This deliberately accepts one exact model and has no evaluator fallback.
    #[cfg(feature = "qualification-candidate")]
    pub async fn attribute_same_defect(
        &self,
        model: &str,
        expected_provider: &str,
        system: &str,
        user: &str,
        timeout: Duration,
    ) -> std::result::Result<AtomicAttributionReview, ModelError> {
        let mut client = self.clone();
        let deadline = Instant::now() + timeout;
        client.scorer_deadline = Some(
            self.total_deadline
                .map_or(deadline, |total| deadline.min(total)),
        );
        let mut usage = Usage::default();
        let mut model_usage = Vec::new();
        let mut usage_accounting_complete = true;
        let first = client
            .chat_attribution_with_temperature(
                model,
                expected_provider,
                system,
                user,
                &mut usage,
                &mut model_usage,
                &mut usage_accounting_complete,
                180,
                0.0,
                LlmPhase::Attribution,
                LlmCallPhase::Initial,
            )
            .await
            .map_err(|error| {
                let complete = usage_accounting_complete
                    && (usage.prompt_tokens > 0
                        || usage.completion_tokens > 0
                        || usage.provider_cost.is_some());
                let mut result = ModelError::new(error, usage, complete);
                result.model_usage = model_usage.clone();
                result
            })?;
        let first_identity = require_attribution_identity(&first, model, expected_provider)
            .map_err(|error| ModelError::new(error, usage, usage_accounting_complete))?;
        let mut raw_responses = vec![first.content.clone()];
        let mut response_identities = vec![first_identity];
        let verdict = match parse_atomic_attribution(&first.content) {
            Ok(verdict) => verdict,
            Err(_) => {
                let repair_system = atomic_attribution_repair_system(system);
                let repair_user = atomic_attribution_repair_user(user, &first.content);
                let second = client
                    .chat_attribution_with_temperature(
                        model,
                        expected_provider,
                        &repair_system,
                        &repair_user,
                        &mut usage,
                        &mut model_usage,
                        &mut usage_accounting_complete,
                        180,
                        0.0,
                        LlmPhase::Attribution,
                        LlmCallPhase::SchemaRepair,
                    )
                    .await
                    .map_err(|error| {
                        let complete = usage_accounting_complete
                            && (usage.prompt_tokens > 0
                                || usage.completion_tokens > 0
                                || usage.provider_cost.is_some());
                        let mut result = ModelError::new(error, usage, complete);
                        result.model_usage = model_usage.clone();
                        result
                    })?;
                let second_identity =
                    require_attribution_identity(&second, model, expected_provider).map_err(
                        |error| ModelError::new(error, usage, usage_accounting_complete),
                    )?;
                raw_responses.push(second.content.clone());
                response_identities.push(second_identity);
                parse_atomic_attribution(&second.content).map_err(|_| {
                    let mut result = ModelError::new(
                        anyhow::Error::new(AtomicAttributionInvalidOutput),
                        usage,
                        usage_accounting_complete,
                    );
                    result.model_usage = model_usage.clone();
                    result
                })?
            }
        };
        Ok(AtomicAttributionReview {
            same_defect: verdict.same_defect,
            reason: verdict.reason,
            model_used: model.to_string(),
            provider_used: expected_provider.to_string(),
            response_identities,
            raw_responses,
            model_usage,
            usage_accounting_complete,
        })
    }

    async fn review_with_model(
        &self,
        model: &str,
        system: &str,
        user: &str,
        validate: &(dyn Fn(&ModelReview) -> std::result::Result<(), String> + Send + Sync),
    ) -> std::result::Result<ModelReview, ModelError> {
        let mut usage = Usage::default();
        let mut call_usage = Vec::new();
        let mut usage_accounting_complete = true;
        let mut model_incidents = Vec::new();
        let initial = self
            .chat(
                model,
                system,
                user,
                &mut usage,
                &mut call_usage,
                &mut usage_accounting_complete,
                REVIEW_MAX_TOKENS,
                LlmPhase::Review,
                LlmCallPhase::Initial,
            )
            .await;
        let content = match initial {
            Ok(content) => content,
            Err(e) => {
                let complete = usage_accounting_complete
                    && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                let mut error = ModelError::new(e, usage, complete);
                error.model_usage = call_usage.clone();
                return Err(error);
            }
        };
        let mut repaired_schema = false;
        let parsed_initial = parse_review(&content);
        let raw = match parsed_initial {
            Ok(raw) => raw,
            Err(parse_err) => {
                let incident = ModelIncident {
                    phase: ModelIncidentPhase::Review,
                    category: ModelIncidentCategory::InvalidOutput,
                    recovered: false,
                    recovery: None,
                };
                // One repair attempt: ask the same model to fix its own JSON.
                let invalid = truncate_utf8_bytes(&content, 16_384);
                let parse_error = parse_err;
                let repair_user = review_schema_repair_user(
                    invalid,
                    truncate_utf8_bytes(&parse_error, REPAIR_ERROR_MAX_BYTES),
                );
                let repaired = match self
                    .chat(
                        model,
                        "You repair malformed JSON. Output only valid JSON.",
                        &repair_user,
                        &mut usage,
                        &mut call_usage,
                        &mut usage_accounting_complete,
                        REVIEW_MAX_TOKENS,
                        LlmPhase::Review,
                        LlmCallPhase::SchemaRepair,
                    )
                    .await
                {
                    Ok(repaired) => repaired,
                    Err(error) => {
                        let mut error =
                            ModelError::new(error.context("JSON repair call failed"), usage, false);
                        error.model_usage = call_usage.clone();
                        error.model_incidents.push(incident);
                        return Err(error);
                    }
                };
                let parsed = parse_review(&repaired).map_err(|error| {
                    let mut error = ModelError::new(
                        anyhow!("model output invalid after repair: {error}"),
                        usage,
                        usage_accounting_complete,
                    );
                    error.model_incidents.push(incident.clone());
                    error.model_usage = call_usage.clone();
                    error
                })?;
                model_incidents.push(ModelIncident {
                    recovered: true,
                    recovery: Some(ModelIncidentRecovery::Repair),
                    ..incident
                });
                repaired_schema = true;
                parsed
            }
        };
        let mut review = into_review(raw, model, usage);
        review.model_usage = call_usage.clone();
        review.model_incidents.append(&mut model_incidents);
        review.usage_accounting_complete = usage_accounting_complete;
        let mut correction_used = repaired_schema;
        if repaired_schema && review.findings.is_empty() && !review.summary.is_empty() {
            let mut error = ModelError::new(
                anyhow!("model output remained semantically contradictory after schema repair"),
                review.usage,
                review.usage_accounting_complete,
            );
            error.model_incidents = review.model_incidents;
            error.model_usage = review.model_usage;
            return Err(error);
        }

        // Semantic consistency retry: a summary that narrates risk next to an
        // empty findings array is the contract violation behind "clean status,
        // scary prose" reviews. Give the model one chance to either structure
        // the risk or retract it; if the contradiction survives, the caller
        // fails the review closed.
        if !repaired_schema && review.findings.is_empty() && !review.summary.is_empty() {
            correction_used = true;
            let incident_index = review.model_incidents.len();
            review.model_incidents.push(ModelIncident {
                phase: ModelIncidentPhase::Review,
                category: ModelIncidentCategory::InvalidOutput,
                recovered: false,
                recovery: None,
            });
            let previous = truncate_utf8_bytes(&content, 16_384);
            let retry_user = review_semantic_retry_user(user, previous);
            let mut retry_usage = usage;
            match self
                .chat(
                    model,
                    system,
                    &retry_user,
                    &mut retry_usage,
                    &mut call_usage,
                    &mut usage_accounting_complete,
                    REVIEW_MAX_TOKENS,
                    LlmPhase::Review,
                    LlmCallPhase::SemanticRetry,
                )
                .await
            {
                Ok(retried) => {
                    review.usage = retry_usage;
                    review.model_usage = call_usage.clone();
                    review.usage_accounting_complete = usage_accounting_complete;
                    if let Ok(retried_raw) = parse_review(&retried) {
                        let mut candidate = into_review(retried_raw, model, retry_usage);
                        candidate.model_usage = call_usage.clone();
                        candidate.usage_accounting_complete = usage_accounting_complete;
                        let still_contradictory =
                            candidate.findings.is_empty() && !candidate.summary.is_empty();
                        if !still_contradictory {
                            review.model_incidents[incident_index].recovered = true;
                            review.model_incidents[incident_index].recovery =
                                Some(ModelIncidentRecovery::Repair);
                            candidate.model_incidents = review.model_incidents.clone();
                            review = candidate;
                        }
                    }
                }
                Err(_) => {
                    review.usage = retry_usage;
                    review.model_usage = call_usage.clone();
                    review.usage_accounting_complete = false;
                    if let Err(error) = self.remaining_budget(LlmPhase::Review) {
                        let mut error =
                            ModelError::new(error.context(ProviderError), retry_usage, false);
                        error.model_usage = call_usage.clone();
                        error.model_incidents = review.model_incidents;
                        return Err(error);
                    }
                }
            }

            // A model that repeats the contradiction is not a usable review.
            // Return an ordinary model failure so the configured cascade gets
            // a chance to recover before the caller emits an operational
            // result. Returning Ok here stopped the cascade at its weakest
            // model and turned harmless descriptive summaries into red gates.
            if review.findings.is_empty() && !review.summary.is_empty() {
                let mut error = ModelError::new(
                    anyhow!("model output remained semantically contradictory after retry"),
                    review.usage,
                    review.usage_accounting_complete,
                );
                error.model_incidents = review.model_incidents;
                error.model_usage = review.model_usage;
                return Err(error);
            }
        }

        if let Err(reason) = validate(&review) {
            if correction_used {
                let mut error = ModelError::new(
                    anyhow!("model output remained unusable after its correction call"),
                    review.usage,
                    review.usage_accounting_complete,
                );
                error.model_usage = review.model_usage;
                error.model_incidents = review.model_incidents;
                return Err(error);
            }
            eprintln!(
                "postil: model {} returned unusable review content; requesting one semantic retry",
                log_text(model),
            );
            let retry_user = review_validation_retry_user(user, &reason);
            let mut retry_usage = review.usage;
            let mut retry_accounting_complete = review.usage_accounting_complete;
            let retry = self
                .chat(
                    model,
                    system,
                    &retry_user,
                    &mut retry_usage,
                    &mut call_usage,
                    &mut retry_accounting_complete,
                    REVIEW_MAX_TOKENS,
                    LlmPhase::Review,
                    LlmCallPhase::SemanticRetry,
                )
                .await;
            match retry {
                Ok(content) => {
                    if let Ok(raw) = parse_review(&content) {
                        let mut candidate = into_review(raw, model, retry_usage);
                        candidate.model_usage = call_usage.clone();
                        candidate.model_incidents = review.model_incidents.clone();
                        candidate.usage_accounting_complete = retry_accounting_complete;
                        if validate(&candidate).is_ok() {
                            candidate.model_incidents.push(ModelIncident {
                                phase: ModelIncidentPhase::Review,
                                category: ModelIncidentCategory::InvalidOutput,
                                recovered: true,
                                recovery: Some(ModelIncidentRecovery::Repair),
                            });
                            return Ok(candidate);
                        }
                    }
                }
                Err(error) => {
                    let mut error = ModelError::new(
                        error.context("review validation retry failed"),
                        retry_usage,
                        false,
                    );
                    error.model_usage = call_usage;
                    error.model_incidents = review.model_incidents;
                    error.model_incidents.push(ModelIncident {
                        phase: ModelIncidentPhase::Review,
                        category: ModelIncidentCategory::InvalidOutput,
                        recovered: false,
                        recovery: None,
                    });
                    return Err(error);
                }
            }

            let mut error = ModelError::new(
                anyhow!("model output remained unusable after semantic retry"),
                retry_usage,
                retry_accounting_complete,
            );
            error.model_usage = call_usage;
            error.model_incidents = review.model_incidents;
            return Err(error);
        }
        Ok(review)
    }

    async fn score_with_model(
        &self,
        model: &str,
        system: &str,
        user: &str,
        expected_len: usize,
    ) -> std::result::Result<ScorerReview, ModelError> {
        let max_tokens = scorer_max_tokens(expected_len).ok_or_else(|| {
            ModelError::new(
                anyhow!(
                    "scorer input has {expected_len} findings; maximum is {SCORER_MAX_FINDINGS}"
                ),
                Usage::default(),
                true,
            )
        })?;
        let mut usage = Usage::default();
        let mut call_usage = Vec::new();
        let mut usage_accounting_complete = true;
        let mut model_incidents = Vec::new();
        let content = self
            .chat_with_temperature(
                model,
                system,
                user,
                &mut usage,
                &mut call_usage,
                &mut usage_accounting_complete,
                max_tokens,
                0.0,
                LlmPhase::Scorer { expected_len },
                LlmCallPhase::Initial,
            )
            .await
            .map_err(|e| {
                let complete = usage_accounting_complete
                    && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                let mut error = ModelError::new(e, usage, complete);
                error.model_usage = call_usage.clone();
                error
            })?;
        let scores = match parse_scores(&content, expected_len) {
            Ok(scores) => scores,
            Err(first_error) => {
                eprintln!("postil: scorer output invalid; requesting one schema repair");
                let invalid = truncate_utf8_bytes(
                    &content,
                    max_tokens as usize * SCORER_REPAIR_BYTES_PER_OUTPUT_TOKEN,
                );
                let repair_system = scorer_repair_system(system);
                let repair_user = scorer_repair_user(user, invalid);
                let incident = ModelIncident {
                    phase: ModelIncidentPhase::Scorer,
                    category: ModelIncidentCategory::InvalidOutput,
                    recovered: false,
                    recovery: None,
                };
                let repaired = self
                    .chat_with_temperature(
                        model,
                        &repair_system,
                        &repair_user,
                        &mut usage,
                        &mut call_usage,
                        &mut usage_accounting_complete,
                        max_tokens,
                        0.0,
                        LlmPhase::Scorer { expected_len },
                        LlmCallPhase::SchemaRepair,
                    )
                    .await
                    .map_err(|error| {
                        let complete = usage_accounting_complete
                            && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                        let mut error = ModelError::new(error, usage, complete);
                        error.model_usage = call_usage.clone();
                        error.model_incidents.push(incident.clone());
                        error
                    })?;
                let scores = parse_scores(&repaired, expected_len).map_err(|second_error| {
                    let mut error = ModelError::new(
                        anyhow!(
                            "scorer output invalid after schema repair: {second_error} (first response: {first_error})"
                        ),
                        usage,
                        usage_accounting_complete,
                    );
                    error.model_incidents.push(incident.clone());
                    error.model_usage = call_usage.clone();
                    error
                })?;
                model_incidents.push(ModelIncident {
                    recovered: true,
                    recovery: Some(ModelIncidentRecovery::Repair),
                    ..incident
                });
                scores
            }
        };
        Ok(ScorerReview {
            scores,
            model_used: model.to_string(),
            usage,
            model_usage: call_usage,
            model_incidents,
            usage_accounting_complete,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn chat(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
        call_usage: &mut Vec<ModelUsage>,
        usage_accounting_complete: &mut bool,
        max_tokens: u32,
        phase: LlmPhase,
        call_phase: LlmCallPhase,
    ) -> Result<String> {
        self.chat_with_temperature(
            model,
            system,
            user,
            usage,
            call_usage,
            usage_accounting_complete,
            max_tokens,
            0.1,
            phase,
            call_phase,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn chat_with_temperature(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
        call_usage: &mut Vec<ModelUsage>,
        usage_accounting_complete: &mut bool,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
        call_phase: LlmCallPhase,
    ) -> Result<String> {
        self.chat_inner(
            model,
            None,
            system,
            user,
            usage,
            call_usage,
            usage_accounting_complete,
            max_tokens,
            temperature,
            phase,
            call_phase,
        )
        .await
        .map(|success| success.content)
        .map_err(classify_chat_error)
    }

    #[cfg(feature = "qualification-candidate")]
    #[allow(clippy::too_many_arguments)]
    async fn chat_attribution_with_temperature(
        &self,
        model: &str,
        expected_provider: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
        call_usage: &mut Vec<ModelUsage>,
        usage_accounting_complete: &mut bool,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
        call_phase: LlmCallPhase,
    ) -> Result<ChatSuccess> {
        if let Some(global) = self.pinned_upstream_provider.as_deref() {
            ensure!(
                global == expected_provider,
                "qualification provider identity mismatch"
            );
        }
        self.chat_inner(
            model,
            Some(expected_provider),
            system,
            user,
            usage,
            call_usage,
            usage_accounting_complete,
            max_tokens,
            temperature,
            phase,
            call_phase,
        )
        .await
        .map_err(classify_chat_error)
    }

    /// Transport, HTTP envelope, and assistant-content handling. The caller
    /// classifies a valid response with unusable assistant content separately
    /// from provider and protocol failures.
    #[allow(clippy::too_many_arguments)]
    async fn chat_inner(
        &self,
        model: &str,
        expected_provider: Option<&str>,
        system: &str,
        user: &str,
        usage: &mut Usage,
        call_usage: &mut Vec<ModelUsage>,
        usage_accounting_complete: &mut bool,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
        call_phase: LlmCallPhase,
    ) -> Result<ChatSuccess> {
        let route_provider = expected_provider.or(self.pinned_upstream_provider.as_deref());
        // This mutable flag is stack-local state held through one exclusively
        // borrowed async call. Request retries run sequentially in this loop,
        // so updating it before continuing or returning needs no atomic type.
        let mut request_max_tokens = max_tokens;
        let mut body = self.request_body_with_provider(
            model,
            system,
            user,
            request_max_tokens,
            temperature,
            phase,
            expected_provider,
        );
        #[cfg(feature = "qualification-candidate")]
        if matches!(phase, LlmPhase::Attribution) {
            Self::ensure_atomic_attribution_request_size(&body)?;
        }
        let mut retries = 0u32;
        let mut timeout_retries = 0u32;
        let mut empty_response_retries = 0u32;
        let mut exhausted_output_retries = 0u32;
        let mut attempt_timeout = self.request_timeout;
        loop {
            let attempt = retries.saturating_add(1);
            let attempt_started_at = Instant::now();
            let remaining = self.remaining_budget(phase)?;
            let deadline_limited = remaining.is_some_and(|value| value <= attempt_timeout);
            let timeout = remaining.map_or(attempt_timeout, |value| value.min(attempt_timeout));
            eprintln!(
                "postil: llm attempt phase={} model={} attempt={}/{} timeout={} budget_remaining={}",
                phase.as_str(),
                log_text(model),
                retries + 1,
                TRANSIENT_RETRIES + 1,
                elapsed_text(timeout),
                remaining
                    .map(elapsed_text)
                    .unwrap_or_else(|| "unbounded".to_string()),
            );
            let response = match tokio::time::timeout(timeout, self.request_once(&body)).await {
                Ok(result) => result,
                Err(_) if deadline_limited => {
                    *usage_accounting_complete = false;
                    call_usage
                        .push(self.model_usage_event(model, phase, call_phase, attempt, None));
                    return Err(DeadlineExceeded(phase).into());
                }
                Err(_) => {
                    *usage_accounting_complete = false;
                    call_usage
                        .push(self.model_usage_event(model, phase, call_phase, attempt, None));
                    if timeout_retries < TIMEOUT_RETRIES && retries < TRANSIENT_RETRIES {
                        retries += 1;
                        timeout_retries += 1;
                        let wait = provider_retry_delay(retries);
                        eprintln!(
                            "postil: model {} hit a request timeout after {}, retrying in {} \
                             (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            elapsed_text(wait)
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.timeout_retry_timeout;
                        continue;
                    }
                    return Err(RequestTimedOut.into());
                }
            };
            match response {
                Ok(response) => {
                    let summary = safe_response_summary(
                        &response.text,
                        self.api_format,
                        is_canonical_openrouter_base(&self.api_base)
                            || matches!(phase, LlmPhase::Attribution),
                    );
                    let elapsed = elapsed_text(attempt_started_at.elapsed());
                    call_usage.push(self.model_usage_event(
                        model,
                        phase,
                        call_phase,
                        attempt,
                        summary.usage,
                    ));
                    if let Some(response_usage) = summary.usage
                        && let Err(error) = self.record_reported_usage(response_usage)
                    {
                        add_usage(usage, response_usage);
                        return Err(error);
                    }
                    if response.status.is_success() {
                        let actual_identity =
                            route_provider.map(|_| actual_response_identity(&response.text));
                        if let Some(expected_provider) = route_provider {
                            validate_routed_response_identity(
                                actual_identity.as_ref(),
                                model,
                                expected_provider,
                            )?;
                        }
                        eprintln!(
                            "postil: llm response phase={} model={} attempt={} status={} elapsed={} bytes={} request_id={} response_id={} returned_model={} provider={} choices={} finish={} usage={} prompt_tokens={} completion_tokens={} reasoning_tokens={} category={}",
                            phase.as_str(),
                            log_text(model),
                            retries + 1,
                            response.status.as_u16(),
                            elapsed,
                            response.text.len(),
                            response.request_id.as_deref().unwrap_or("none"),
                            summary.response_id.as_deref().unwrap_or("none"),
                            summary.returned_model.as_deref().unwrap_or("none"),
                            summary.provider.as_deref().unwrap_or("none"),
                            summary
                                .choices
                                .map_or_else(|| "unknown".to_string(), |count| count.to_string()),
                            summary.finish_reason.as_deref().unwrap_or("none"),
                            if summary.usage.is_some() {
                                "present"
                            } else {
                                "missing"
                            },
                            summary.usage.map_or(0, |value| value.prompt_tokens),
                            summary.usage.map_or(0, |value| value.completion_tokens),
                            summary
                                .reasoning_tokens
                                .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
                            summary.error_type.as_deref().unwrap_or("none"),
                        );
                        let usage_before_parse = *usage;
                        match self.parse_response(&response.text, usage) {
                            Ok(content) => {
                                if let Some(reason) = successful_response_usage_issue(summary.usage)
                                {
                                    *usage_accounting_complete = false;
                                    eprintln!(
                                        "postil: llm usage accounting incomplete phase={} model={} attempt={} reason={reason}",
                                        phase.as_str(),
                                        log_text(model),
                                        retries + 1,
                                    );
                                }
                                return Ok(ChatSuccess {
                                    content,
                                    returned_model: actual_identity
                                        .as_ref()
                                        .and_then(|identity| identity.0.clone())
                                        .or(summary.returned_model),
                                    provider: actual_identity
                                        .and_then(|identity| identity.1)
                                        .or(summary.provider),
                                });
                            }
                            Err(error) => {
                                let parse_added_usage = usage.prompt_tokens
                                    != usage_before_parse.prompt_tokens
                                    || usage.completion_tokens
                                        != usage_before_parse.completion_tokens
                                    || usage.cost_micros != usage_before_parse.cost_micros;
                                if !parse_added_usage && let Some(response_usage) = summary.usage {
                                    add_usage(usage, response_usage);
                                }
                                if summary.usage.is_none() {
                                    *usage_accounting_complete = false;
                                }
                                let expanded_max_tokens =
                                    phase.exhausted_output_retry_max_tokens(request_max_tokens);
                                let exhausted_output_budget = summary.finish_reason.as_deref()
                                    == Some("length")
                                    && expanded_max_tokens > request_max_tokens;
                                if exhausted_output_budget
                                    && exhausted_output_retries < EXHAUSTED_OUTPUT_RETRIES
                                    && retries < TRANSIENT_RETRIES
                                {
                                    retries += 1;
                                    exhausted_output_retries += 1;
                                    let wait = provider_retry_delay(retries);
                                    eprintln!(
                                        "postil: model {} exhausted {request_max_tokens} output tokens after {elapsed}, retrying the complete request with {expanded_max_tokens} tokens in {} (output retry {exhausted_output_retries}/{EXHAUSTED_OUTPUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                                        log_text(model),
                                        elapsed_text(wait),
                                    );
                                    request_max_tokens = expanded_max_tokens;
                                    body = self.request_body_with_provider(
                                        model,
                                        system,
                                        user,
                                        request_max_tokens,
                                        temperature,
                                        phase,
                                        expected_provider,
                                    );
                                    self.sleep_with_budget(phase, wait).await?;
                                    attempt_timeout = self
                                        .request_timeout
                                        .min(Duration::from_secs(TIMEOUT_RETRY_CAP_SECS));
                                    continue;
                                }
                                if error
                                    .downcast_ref::<ModelContentFailure>()
                                    .is_some_and(ModelContentFailure::retryable_empty)
                                    && empty_response_retries < EMPTY_RESPONSE_RETRIES
                                    && retries < TRANSIENT_RETRIES
                                {
                                    retries += 1;
                                    empty_response_retries += 1;
                                    let wait = provider_retry_delay(retries);
                                    eprintln!(
                                        "postil: model {} returned empty content after {elapsed}, retrying in {} (empty retry {empty_response_retries}/{EMPTY_RESPONSE_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                                        log_text(model),
                                        elapsed_text(wait),
                                    );
                                    self.sleep_with_budget(phase, wait).await?;
                                    attempt_timeout = self.request_timeout.min(
                                        Duration::from_secs(EMPTY_RESPONSE_RETRY_TIMEOUT_SECS),
                                    );
                                    continue;
                                }
                                return Err(error);
                            }
                        }
                    }
                    eprintln!(
                        "postil: llm response phase={} model={} attempt={} status={} elapsed={} request_id={} category={}",
                        phase.as_str(),
                        log_text(model),
                        retries + 1,
                        response.status.as_u16(),
                        elapsed,
                        response.request_id.as_deref().unwrap_or("none"),
                        summary.error_type.as_deref().unwrap_or("unclassified"),
                    );
                    if let Some(response_usage) = summary.usage {
                        add_usage(usage, response_usage);
                    } else {
                        *usage_accounting_complete = false;
                    }
                    let status = response.status;
                    if timeout_status(status.as_u16())
                        && timeout_retries < TIMEOUT_RETRIES
                        && retries < TRANSIENT_RETRIES
                    {
                        retries += 1;
                        timeout_retries += 1;
                        let wait = response
                            .retry_after
                            .unwrap_or_else(|| provider_retry_delay(retries));
                        eprintln!(
                            "postil: model {} returned timeout HTTP {status} after {}, retrying in {} \
                             (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            elapsed_text(wait)
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.timeout_retry_timeout;
                        continue;
                    }
                    if timeout_status(status.as_u16()) {
                        let detail = provider_http_status_detail(
                            status,
                            &summary,
                            response.request_id.as_deref(),
                        );
                        return Err(anyhow::Error::new(ProviderHttpFailure(status)).context(detail));
                    }
                    if retryable_status(status.as_u16()) && retries < TRANSIENT_RETRIES {
                        retries += 1;
                        let wait = response
                            .retry_after
                            .unwrap_or_else(|| provider_retry_delay(retries));
                        eprintln!(
                            "postil: model {} returned retryable HTTP {status} after {}, retrying in {} \
                             (retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            elapsed_text(wait)
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.request_timeout;
                        continue;
                    }
                    return Err(anyhow::Error::new(ProviderHttpFailure(status)).context(
                        provider_http_status_detail(
                            status,
                            &summary,
                            response.request_id.as_deref(),
                        ),
                    ));
                }
                Err(error)
                    if reqwest_error(&error).is_some_and(reqwest::Error::is_timeout)
                        && timeout_retries < TIMEOUT_RETRIES
                        && retries < TRANSIENT_RETRIES =>
                {
                    *usage_accounting_complete = false;
                    call_usage
                        .push(self.model_usage_event(model, phase, call_phase, attempt, None));
                    retries += 1;
                    timeout_retries += 1;
                    let wait = provider_retry_delay(retries);
                    eprintln!(
                        "postil: model {} hit a request timeout after {}, retrying in {} \
                         (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                        log_text(model),
                        elapsed_text(attempt_started_at.elapsed()),
                        elapsed_text(wait)
                    );
                    self.sleep_with_budget(phase, wait).await?;
                    attempt_timeout = self.timeout_retry_timeout;
                }
                Err(error)
                    if reqwest_error(&error).is_some_and(reqwest::Error::is_connect)
                        && retries < TRANSIENT_RETRIES =>
                {
                    *usage_accounting_complete = false;
                    call_usage
                        .push(self.model_usage_event(model, phase, call_phase, attempt, None));
                    retries += 1;
                    let wait = provider_retry_delay(retries);
                    eprintln!(
                        "postil: model {} hit a retryable connection error after {}, retrying in {} \
                         (retry {retries}/{TRANSIENT_RETRIES})",
                        log_text(model),
                        elapsed_text(attempt_started_at.elapsed()),
                        elapsed_text(wait)
                    );
                    self.sleep_with_budget(phase, wait).await?;
                    attempt_timeout = self.request_timeout;
                }
                Err(error) => {
                    *usage_accounting_complete = false;
                    call_usage
                        .push(self.model_usage_event(model, phase, call_phase, attempt, None));
                    return Err(error.context("request to model endpoint failed"));
                }
            }
        }
    }

    #[cfg(feature = "qualification-candidate")]
    fn ensure_atomic_attribution_request_size(body: &serde_json::Value) -> Result<()> {
        let bytes =
            serde_json::to_vec(body).context("serialize atomic attribution provider request")?;
        if bytes.len() > crate::attribution::MAX_PROVIDER_REQUEST_BYTES {
            return Err(anyhow::Error::new(AtomicAttributionRequestTooLarge));
        }
        Ok(())
    }

    fn request_body(
        &self,
        model: &str,
        system: &str,
        user: &str,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
    ) -> serde_json::Value {
        self.request_body_with_provider(model, system, user, max_tokens, temperature, phase, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn request_body_with_provider(
        &self,
        model: &str,
        system: &str,
        user: &str,
        max_tokens: u32,
        temperature: f64,
        phase: LlmPhase,
        _expected_provider: Option<&str>,
    ) -> serde_json::Value {
        match self.api_format {
            ApiFormat::OpenaiCompatible => {
                let mut body = json!({
                    "model": model,
                    "temperature": temperature,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                });
                body["max_tokens"] = json!(max_tokens);
                apply_openrouter_privacy(&mut body, self.require_openrouter_privacy);
                let canonical_openrouter = is_canonical_openrouter_base(&self.api_base);
                if let Some(expected_provider) = self.pinned_upstream_provider.as_deref() {
                    apply_openrouter_provider_pin(&mut body, expected_provider);
                }
                if canonical_openrouter && let LlmPhase::Scorer { expected_len } = phase {
                    apply_openrouter_scorer_contract(&mut body, expected_len);
                }
                #[cfg(feature = "qualification-candidate")]
                if matches!(phase, LlmPhase::Attribution) {
                    apply_openrouter_atomic_attribution_contract(&mut body, _expected_provider);
                }
                if canonical_openrouter
                    && let Some(bound) = self
                        .hosted_price_bounds
                        .as_ref()
                        .and_then(|bounds| bounds.get(model))
                {
                    apply_openrouter_price_ceiling(&mut body, bound);
                }
                body
            }
            ApiFormat::Anthropic => json!({
                "model": model,
                "system": system,
                "messages": [{"role": "user", "content": user}],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }),
        }
    }

    fn parse_response(&self, text: &str, usage: &mut Usage) -> Result<String> {
        match self.api_format {
            ApiFormat::OpenaiCompatible => {
                let parsed: ChatResponse = serde_json::from_str(text)
                    .context("model endpoint returned non-JSON OpenAI-compatible body")?;
                if let Some(u) = parsed.usage {
                    add_response_usage(
                        usage,
                        u.prompt_tokens.unwrap_or(0),
                        u.completion_tokens.unwrap_or(0),
                        u.cost.and_then(|raw| ProviderCost::parse(raw.get())),
                    );
                }
                let choice = parsed
                    .choices
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::Error::new(ModelContentFailure::MissingChoices))?;
                let content = choice
                    .message
                    .content
                    .filter(|content| !content.trim().is_empty())
                    .ok_or_else(|| anyhow::Error::new(ModelContentFailure::Empty))?;
                let reason = choice
                    .finish_reason
                    .unwrap_or_else(|| "missing finish_reason".to_string());
                if reason != "stop" {
                    return Err(anyhow::Error::new(ModelContentFailure::NonTerminal {
                        reason,
                    }));
                }
                Ok(content)
            }
            ApiFormat::Anthropic => {
                let parsed: AnthropicResponse = serde_json::from_str(text)
                    .context("model endpoint returned non-JSON Anthropic body")?;
                if let Some(u) = parsed.usage {
                    usage.prompt_tokens += u.input_tokens.unwrap_or(0);
                    usage.completion_tokens += u.output_tokens.unwrap_or(0);
                }
                let stop_reason = parsed
                    .stop_reason
                    .clone()
                    .unwrap_or_else(|| "missing stop_reason".to_string());
                let content = parsed
                    .content
                    .into_iter()
                    .filter(|block| block.kind == "text")
                    .filter_map(|block| block.text)
                    .collect::<Vec<_>>()
                    .join("\n");
                if content.is_empty() {
                    Err(anyhow::Error::new(ModelContentFailure::Empty))
                } else if !matches!(stop_reason.as_str(), "end_turn" | "stop_sequence") {
                    Err(anyhow::Error::new(ModelContentFailure::NonTerminal {
                        reason: stop_reason,
                    }))
                } else {
                    Ok(content)
                }
            }
        }
    }

    async fn request_once(&self, body: &serde_json::Value) -> Result<ModelHttpResponse> {
        self.reserve_provider_attempt(body)?;
        let http = self.http_client()?;
        let mut request = match self.api_format {
            ApiFormat::OpenaiCompatible => {
                let url = format!("{}/chat/completions", self.request_api_base);
                http.post(&url)
                    .bearer_auth(&self.api_key)
                    .header("HTTP-Referer", "https://postil.dev")
                    .header("X-Title", "Postil")
            }
            ApiFormat::Anthropic => {
                let url = format!("{}/messages", self.request_api_base);
                http.post(&url)
                    .header("x-api-key", &self.api_key)
                    .header("anthropic-version", ANTHROPIC_VERSION)
            }
        };
        if let Some(auth) = &self.endpoint_auth {
            request = request.header(auth.name.clone(), auth.value.clone());
        }
        let canonical_openrouter = is_canonical_openrouter_base(&self.api_base);
        if canonical_openrouter {
            request = request.header("X-OpenRouter-Experimental-Metadata", "enabled");
        }
        let mut response = request.json(body).send().await?;
        let status = response.status();
        let retry_after = retry_after_duration(response.headers());
        let request_id = safe_request_id(response.headers(), canonical_openrouter);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= MAX_MODEL_RESPONSE_BYTES,
                "model response exceeded the {MAX_MODEL_RESPONSE_BYTES} byte hard cap"
            );
            bytes.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(bytes).context("model endpoint returned non-UTF-8 body")?;
        Ok(ModelHttpResponse {
            status,
            text,
            retry_after,
            request_id,
        })
    }

    fn reserve_provider_attempt(&self, body: &serde_json::Value) -> Result<()> {
        let input_bytes = serialized_provider_request_bytes(
            body,
            "serializing model request immediately before provider contact",
        )?;
        let output_tokens = body
            .get("max_tokens")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| anyhow!("model request is missing a bounded max_tokens value"))?;
        let projected_cost_micros = if let Some(bounds) = &self.hosted_price_bounds {
            let model = body
                .get("model")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("hosted model request is missing its model identifier"))?;
            let bound = bounds
                .get(model)
                .ok_or_else(|| anyhow!("hosted model {model:?} has no admitted price bound"))?;
            projected_request_cost_micros(input_bytes, output_tokens, bound)?
        } else {
            0
        };
        // Every input token consumes at least one byte of serialized request
        // content, so the byte count is a conservative upper bound on input
        // tokens. Keep the byte and output-token counters separate for their
        // individual caps, and combine only this explicit token upper bound for
        // the aggregate spend cap. Reserving before the network call means
        // retries, repairs, scorer calls, and concurrent consensus calls cannot
        // cross any cap between check/use.
        let token_exposure_upper_bound = input_bytes
            .checked_add(output_tokens)
            .ok_or_else(|| anyhow!("model request token exposure overflowed"))?;
        let mut admission = self
            .admission
            .lock()
            .map_err(|_| anyhow!("model admission lock is poisoned"))?;
        let attempts = admission
            .attempts
            .checked_add(1)
            .ok_or_else(|| anyhow!("model provider attempt count overflowed"))?;
        let total_input = admission
            .input_bytes
            .checked_add(input_bytes)
            .ok_or_else(|| anyhow!("model provider input byte count overflowed"))?;
        let total_output = admission
            .output_token_exposure
            .checked_add(output_tokens)
            .ok_or_else(|| anyhow!("model provider output exposure overflowed"))?;
        let total_token_exposure = admission
            .token_exposure_upper_bound
            .checked_add(token_exposure_upper_bound)
            .ok_or_else(|| anyhow!("model provider spend exposure overflowed"))?;
        let total_projected_cost = admission
            .projected_cost_exposure_micros
            .checked_add(projected_cost_micros)
            .ok_or_else(|| anyhow!("model provider projected cost exposure overflowed"))?;
        if self.hosted_price_bounds.is_some() {
            ensure!(
                attempts <= MAX_PROVIDER_ATTEMPTS,
                "model provider attempt hard cap ({MAX_PROVIDER_ATTEMPTS}) exceeded"
            );
            ensure!(
                total_input <= MAX_PROVIDER_INPUT_BYTES,
                "model provider input hard cap ({MAX_PROVIDER_INPUT_BYTES} bytes) exceeded"
            );
            ensure!(
                total_output <= MAX_PROVIDER_OUTPUT_TOKEN_EXPOSURE,
                "model provider output exposure hard cap ({MAX_PROVIDER_OUTPUT_TOKEN_EXPOSURE} tokens) exceeded"
            );
            ensure!(
                total_token_exposure <= MAX_REPORTED_TOKEN_SPEND,
                "model token spend exposure exceeded the {MAX_REPORTED_TOKEN_SPEND} token hard cap"
            );
            ensure!(
                total_projected_cost <= HOSTED_OPERATION_COST_CAP_MICROS,
                "model provider projected cost exposure exceeded the {HOSTED_OPERATION_COST_CAP_MICROS} micro-dollar hosted operation cap"
            );
        }
        admission.attempts = attempts;
        admission.input_bytes = total_input;
        admission.output_token_exposure = total_output;
        admission.token_exposure_upper_bound = total_token_exposure;
        admission.projected_cost_exposure_micros = total_projected_cost;
        Ok(())
    }

    fn record_reported_usage(&self, usage: Usage) -> Result<()> {
        let tokens = usage
            .prompt_tokens
            .checked_add(usage.completion_tokens)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| anyhow!("model provider reported token count overflowed"))?;
        let mut admission = self
            .admission
            .lock()
            .map_err(|_| anyhow!("model admission lock is poisoned"))?;
        let total_tokens = admission
            .reported_token_spend
            .checked_add(tokens)
            .ok_or_else(|| anyhow!("model provider reported token spend overflowed"))?;
        let total_cost = admission
            .reported_cost_micros
            .checked_add(
                usage
                    .provider_cost
                    .and_then(ProviderCost::micros_ceiling)
                    .unwrap_or(0),
            )
            .ok_or_else(|| anyhow!("model provider reported cost overflowed"))?;
        if self.hosted_price_bounds.is_some() {
            ensure!(
                total_tokens <= MAX_REPORTED_TOKEN_SPEND,
                "model token spend exceeded the {MAX_REPORTED_TOKEN_SPEND} token hard cap"
            );
            ensure!(
                total_cost <= HOSTED_OPERATION_COST_CAP_MICROS,
                "model provider cost exceeded the {} micro-dollar hard cap",
                HOSTED_OPERATION_COST_CAP_MICROS
            );
        }
        admission.reported_token_spend = total_tokens;
        admission.reported_cost_micros = total_cost;
        Ok(())
    }

    fn http_client(&self) -> Result<reqwest::Client> {
        let mut client = self
            .http
            .lock()
            .map_err(|_| anyhow!("model provider HTTP client lock is poisoned"))?;
        if let Some(client) = client.as_ref() {
            return Ok(client.clone());
        }
        let built = secure_http_client(&self.request_api_base)?;
        *client = Some(built.clone());
        Ok(built)
    }

    fn remaining_budget(&self, phase: LlmPhase) -> Result<Option<Duration>> {
        let deadline = match phase {
            LlmPhase::Planner | LlmPhase::Review => self.review_deadline,
            LlmPhase::Scorer { .. } | LlmPhase::Attribution => {
                self.scorer_deadline.or(self.total_deadline)
            }
            LlmPhase::Respond | LlmPhase::Total => self.total_deadline,
        };
        let Some(deadline) = deadline else {
            return Ok(None);
        };
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(Some)
            .ok_or_else(|| DeadlineExceeded(phase).into())
    }

    async fn sleep_with_budget(&self, phase: LlmPhase, duration: Duration) -> Result<()> {
        let Some(remaining) = self.remaining_budget(phase)? else {
            tokio::time::sleep(duration).await;
            return Ok(());
        };
        if remaining <= duration {
            return Err(DeadlineExceeded(phase).into());
        }
        tokio::time::sleep(duration).await;
        Ok(())
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn qualification_request_api_base(canonical_api_base: &str) -> Result<String> {
    #[cfg(feature = "qualification-candidate")]
    if crate::config::qualification_candidate_mode()
        && let Some(raw) = std::env::var_os(QUALIFICATION_CAPTURE_API_BASE_ENV)
    {
        let raw = raw
            .into_string()
            .map_err(|_| anyhow!("qualification capture API base must be UTF-8"))?;
        let url = reqwest::Url::parse(&raw)
            .context("qualification capture API base must be an absolute URL")?;
        let loopback = url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        ensure!(
            url.scheme() == "http"
                && loopback
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "qualification capture API base must be an HTTP loopback URL without credentials, query, or fragment"
        );
        return Ok(raw.trim_end_matches('/').to_string());
    }
    Ok(canonical_api_base.trim_end_matches('/').to_string())
}

fn consensus_is_incomplete(hosted: bool, completed: usize, required: usize) -> bool {
    hosted && completed != required
}

fn apply_openrouter_privacy(body: &mut serde_json::Value, required: bool) {
    if required {
        body["provider"] = json!({
            "data_collection": "deny",
            "zdr": true,
        });
    }
}

fn apply_openrouter_provider_pin(body: &mut serde_json::Value, expected_provider: &str) {
    let provider = body
        .as_object_mut()
        .expect("model request body is an object")
        .entry("provider")
        .or_insert_with(|| json!({}));
    let provider = provider
        .as_object_mut()
        .expect("provider routing configuration is an object");
    provider.insert("order".to_string(), json!([expected_provider]));
    provider.insert("allow_fallbacks".to_string(), json!(false));
}

fn apply_openrouter_price_ceiling(body: &mut serde_json::Value, bound: &ModelPriceBound) {
    let provider = body
        .as_object_mut()
        .expect("model request body is an object")
        .entry("provider")
        .or_insert_with(|| json!({}));
    let provider = provider
        .as_object_mut()
        .expect("provider routing configuration is an object");
    provider.insert(
        "max_price".to_string(),
        json!({
            "prompt": bound.input_micros_per_million_tokens as f64 / 1_000_000.0,
            "completion": bound.output_micros_per_million_tokens as f64 / 1_000_000.0,
        }),
    );
}

fn apply_openrouter_scorer_contract(body: &mut serde_json::Value, expected_len: usize) {
    debug_assert!(expected_len <= SCORER_MAX_FINDINGS);
    let provider = body
        .as_object_mut()
        .expect("model request body is an object")
        .entry("provider")
        .or_insert_with(|| json!({}));
    provider
        .as_object_mut()
        .expect("provider routing configuration is an object")
        .insert("require_parameters".to_string(), json!(true));
    body["reasoning"] = json!({
        "effort": "none",
        "exclude": true,
    });
    body["response_format"] = json!({
        "type": "json_schema",
        "json_schema": {
            "name": "postil_finding_scores",
            "strict": true,
            "schema": {
                "type": "array",
                "minItems": expected_len,
                "maxItems": expected_len,
                "items": {
                    "type": "object",
                    "properties": {
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "kind": {
                            "type": "string",
                            "enum": [
                                "risk",
                                "humanEscalation",
                                "guardrail",
                                "uncertainty",
                                "contentPolicy",
                            ],
                        },
                        "reason": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": SCORER_REASON_SCHEMA_MAX_CHARS,
                            "pattern": SCORER_REASON_JSON_PATTERN,
                        },
                    },
                    "required": ["confidence", "kind", "reason"],
                    "additionalProperties": false,
                },
            },
        },
    });
}

#[cfg(feature = "qualification-candidate")]
fn apply_openrouter_atomic_attribution_contract(
    body: &mut serde_json::Value,
    expected_provider: Option<&str>,
) {
    if let Some(expected_provider) = expected_provider {
        apply_openrouter_provider_pin(body, expected_provider);
    }
    let provider = body
        .as_object_mut()
        .expect("model request body is an object")
        .entry("provider")
        .or_insert_with(|| json!({}));
    let provider = provider
        .as_object_mut()
        .expect("provider routing configuration is an object");
    provider.insert("require_parameters".to_string(), json!(true));
    body["reasoning"] = json!({ "effort": "none", "exclude": true });
    body["response_format"] = json!({
        "type": "json_schema",
        "json_schema": {
            "name": "postil_atomic_attribution",
            "strict": true,
            "schema": {
                "type": "object",
                "properties": {
                    "sameDefect": { "type": "boolean" },
                    "reason": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": SCORER_REASON_SCHEMA_MAX_CHARS,
                        "pattern": SCORER_REASON_JSON_PATTERN,
                    },
                },
                "required": ["sameDefect", "reason"],
                "additionalProperties": false,
            },
        },
    });
}

#[cfg(feature = "qualification-candidate")]
fn require_attribution_identity(
    success: &ChatSuccess,
    expected_model: &str,
    expected_provider: &str,
) -> Result<AtomicAttributionResponseIdentity> {
    let returned_model = success
        .returned_model
        .as_deref()
        .ok_or_else(|| anyhow::Error::new(AtomicAttributionIdentityFailure::Missing))?;
    let returned_provider = success
        .provider
        .as_deref()
        .ok_or_else(|| anyhow::Error::new(AtomicAttributionIdentityFailure::Missing))?;
    if returned_model != expected_model || returned_provider != expected_provider {
        return Err(anyhow::Error::new(
            AtomicAttributionIdentityFailure::Mismatch,
        ));
    }
    Ok(AtomicAttributionResponseIdentity {
        model: returned_model.to_string(),
        provider: returned_provider.to_string(),
    })
}

fn is_canonical_openrouter_base(api_base: &str) -> bool {
    reqwest::Url::parse(api_base).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("openrouter.ai")
            && url.port().is_none()
            && url.path().trim_end_matches('/') == "/api/v1"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn ensure_hosted_provider_contract(api_format: ApiFormat, api_base: &str) -> Result<()> {
    ensure!(
        api_format == ApiFormat::OpenaiCompatible && is_canonical_openrouter_base(api_base),
        "hosted inference requires the canonical OpenRouter OpenAI-compatible endpoint so admitted price and privacy ceilings are enforceable"
    );
    Ok(())
}

fn retry_after_duration(headers: &HeaderMap) -> Option<Duration> {
    retry_after_duration_at(headers, std::time::SystemTime::now())
}

fn retry_after_duration_at(headers: &HeaderMap, now: std::time::SystemTime) -> Option<Duration> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)?;

    let duration = if let Ok(seconds) = value.parse::<u64>() {
        Duration::from_secs(seconds)
    } else {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default()
    };

    Some(duration.min(Duration::from_secs(PROVIDER_RETRY_DELAY_CAP_SECS)))
}

fn safe_header_value(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            Some(opaque_identifier(value))
        })
}

fn safe_request_id(headers: &HeaderMap, expose_identifier: bool) -> Option<String> {
    let value = headers
        .get("x-request-id")
        .or_else(|| headers.get("x-openrouter-request-id"))
        .or_else(|| headers.get("x-generation-id"));
    if expose_identifier {
        safe_header_value(value)
    } else {
        value.map(|_| "present".to_string())
    }
}

fn safe_response_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(opaque_identifier(value))
}

fn actual_response_identity(text: &str) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return (None, None);
    };
    let identifier = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()
                    && trimmed.len() <= 256
                    && !trimmed.chars().any(char::is_control))
                .then(|| trimmed.to_string())
            })
    };
    (identifier("model"), identifier("provider"))
}

fn validate_routed_response_identity(
    identity: Option<&(Option<String>, Option<String>)>,
    expected_model: &str,
    expected_provider: &str,
) -> Result<()> {
    let returned_model = identity
        .and_then(|value| value.0.as_deref())
        .ok_or_else(|| anyhow::Error::new(AtomicAttributionIdentityFailure::Missing))?;
    let returned_provider = identity
        .and_then(|value| value.1.as_deref())
        .ok_or_else(|| anyhow::Error::new(AtomicAttributionIdentityFailure::Missing))?;
    ensure!(
        returned_model == expected_model && returned_provider == expected_provider,
        AtomicAttributionIdentityFailure::Mismatch
    );
    Ok(())
}

fn opaque_identifier(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "sha256:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn safe_error_category(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "api_error" => "api_error",
        "authentication_error" => "authentication_error",
        "authorization_error" => "authorization_error",
        "billing_error" => "billing_error",
        "credits_exhausted" => "credits_exhausted",
        "insufficient_credits" => "insufficient_credits",
        "insufficient_quota" => "insufficient_quota",
        "invalid_request_error" => "invalid_request_error",
        "key_limit_exceeded" => "key_limit_exceeded",
        "not_found_error" => "not_found_error",
        "overloaded_error" => "overloaded_error",
        "permission_error" => "permission_error",
        "provider_error" => "provider_error",
        "rate_limit_error" => "rate_limit_error",
        "server_error" => "server_error",
        "timeout_error" => "timeout_error",
        _ => "reported",
    }
}

fn safe_finish_reason(value: &str) -> &'static str {
    match value {
        "stop" => "stop",
        "length" | "max_tokens" => "length",
        "tool_calls" => "tool_calls",
        "content_filter" => "content_filter",
        "error" => "error",
        _ => "reported",
    }
}

fn provider_http_status_detail(
    status: reqwest::StatusCode,
    summary: &SafeResponseSummary,
    request_id: Option<&str>,
) -> String {
    let category = summary.error_type.as_deref().unwrap_or("unclassified");
    match request_id {
        Some(request_id) => {
            format!(
                "model endpoint returned {status} (category {category}, request id {request_id})"
            )
        }
        None => format!("model endpoint returned {status} (category {category})"),
    }
}

fn safe_response_summary(
    text: &str,
    api_format: ApiFormat,
    expose_identifiers: bool,
) -> SafeResponseSummary {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return SafeResponseSummary::default();
    };
    let raw_string_at = |path: &[&str]| -> Option<&str> {
        path.iter()
            .try_fold(&value, |current, key| {
                key.parse::<usize>()
                    .ok()
                    .and_then(|index| current.get(index))
                    .or_else(|| current.get(*key))
            })?
            .as_str()
    };
    let string_at = |path: &[&str]| -> Option<String> {
        raw_string_at(path).and_then(|value| {
            if expose_identifiers {
                safe_response_identifier(value)
            } else {
                Some("present".to_string())
            }
        })
    };
    let usage_value = value.get("usage").filter(|usage| usage.is_object());
    let exact_cost = serde_json::from_str::<ChatResponse>(text)
        .ok()
        .and_then(|response| response.usage)
        .and_then(|usage| usage.cost)
        .and_then(|raw| ProviderCost::parse(raw.get()));
    let usage = match api_format {
        ApiFormat::OpenaiCompatible => usage_value.map(|usage| Usage {
            prompt_tokens: usage
                .get("prompt_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            completion_tokens: usage
                .get("completion_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            cost_micros: exact_cost.and_then(ProviderCost::micros_rounded),
            provider_cost: exact_cost,
        }),
        ApiFormat::Anthropic => usage_value.map(|usage| Usage {
            prompt_tokens: usage
                .get("input_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            completion_tokens: usage
                .get("output_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            cost_micros: None,
            provider_cost: None,
        }),
    };
    SafeResponseSummary {
        response_id: string_at(&["id"]),
        returned_model: string_at(&["model"]),
        provider: string_at(&["provider"]),
        finish_reason: raw_string_at(&["choices", "0", "finish_reason"])
            .or_else(|| raw_string_at(&["stop_reason"]))
            .map(safe_finish_reason)
            .map(str::to_string),
        reasoning_tokens: usage_value
            .and_then(|usage| usage.get("completion_tokens_details"))
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(serde_json::Value::as_u64),
        error_type: raw_string_at(&["error", "metadata", "error_type"])
            .or_else(|| raw_string_at(&["error", "error_type"]))
            .map(safe_error_category)
            .map(str::to_string),
        choices: value
            .get("choices")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        usage,
    }
}

fn successful_response_usage_issue(usage: Option<Usage>) -> Option<&'static str> {
    match usage {
        None => Some("missing"),
        Some(usage) if usage.prompt_tokens == 0 || usage.completion_tokens == 0 => {
            Some("nonpositive")
        }
        Some(_) => None,
    }
}

impl LlmTimeouts {
    fn from_env(request_default_secs: u64, total_default_secs: Option<u64>) -> Result<Self> {
        let request = duration_from_env(REQUEST_TIMEOUT_ENV, Some(request_default_secs))?
            .expect("default request timeout is always set");
        let total = duration_from_env(TOTAL_TIMEOUT_ENV, total_default_secs)?;
        Ok(Self { request, total })
    }
}

fn resolve_api_key() -> Result<String> {
    api_key::resolve_from_process_env().ok_or_else(|| {
        let key_names = api_key::names_text();
        anyhow!(
            "no API key: set {key_names}. Postil never proxies your inference; bring your own key."
        )
    })
}

fn duration_from_env(name: &str, default_secs: Option<u64>) -> Result<Option<Duration>> {
    let Some(raw) = std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(default_secs.map(Duration::from_secs));
    };
    let seconds = raw
        .parse::<u64>()
        .with_context(|| format!("{name} must be a positive integer number of seconds"))?;
    if seconds == 0 {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(Some(Duration::from_secs(seconds)))
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
    usage: Option<ChatUsage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Message {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    cost: Option<Box<serde_json::value::RawValue>>,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicContentBlock>,
    usage: Option<AnthropicUsage>,
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

fn secure_http_client(api_base: &str) -> Result<reqwest::Client> {
    let (hostname, addresses) = resolve_api_endpoint(api_base)?;
    reqwest::Client::builder()
        // A system proxy resolves the destination itself and would bypass the
        // validated, pinned DNS result below while carrying provider secrets.
        .no_proxy()
        // Provider credentials and prompts must never follow an endpoint's
        // redirect to another origin or into an internal network.
        .redirect(reqwest::redirect::Policy::none())
        // Connect only to the addresses approved by the single resolution
        // above. Reqwest retains the URL hostname for TLS SNI/certificate
        // verification while replacing DNS lookup results with this set.
        .resolve_to_addrs(&hostname, &addresses)
        .build()
        .context("build model provider HTTP client")
}

fn resolve_api_endpoint(api_base: &str) -> Result<(String, Vec<SocketAddr>)> {
    resolve_api_endpoint_with(api_base, |hostname, port| {
        (hostname, port)
            .to_socket_addrs()
            .map(|items| items.collect())
    })
}

fn resolve_api_endpoint_with<F>(api_base: &str, resolver: F) -> Result<(String, Vec<SocketAddr>)>
where
    F: FnOnce(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
{
    let url = reqwest::Url::parse(api_base).context("model API base must be an absolute URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "model API base must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "model API base must not contain credentials"
    );
    let hostname = url
        .host_str()
        .filter(|hostname| !hostname.is_empty())
        .context("model API base must include a hostname")?
        .to_string();
    let port = url
        .port_or_known_default()
        .context("model API base must include a port for its URL scheme")?;
    let addresses = resolver(&hostname, port)
        .with_context(|| format!("model API hostname {hostname:?} could not be resolved"))?;
    anyhow::ensure!(
        !addresses.is_empty(),
        "model API hostname {hostname:?} did not resolve to any addresses"
    );
    let allow_private = std::env::var(ALLOW_PRIVATE_API_BASE_ENV)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if url.scheme() == "http" {
        anyhow::ensure!(
            allow_private && addresses.iter().all(|address| !is_public_ip(address.ip())),
            "plain HTTP model APIs are allowed only for explicitly opted-in private or loopback endpoints"
        );
    }
    if !allow_private {
        for address in &addresses {
            anyhow::ensure!(
                is_public_ip(address.ip()),
                "model API hostname {hostname:?} resolved to a private, loopback, link-local, or non-public address"
            );
        }
    }
    Ok((hostname, addresses))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    // Deprecated IPv4-compatible addresses retain the embedded IPv4's
    // reachability semantics even though they are not `::ffff:` mapped.
    if segments[..6].iter().all(|segment| *segment == 0) {
        return false;
    }
    // The well-known NAT64 prefix embeds the destination IPv4 in the final
    // 32 bits. Reject it when it would translate to a non-public destination.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return is_public_ipv4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn endpoint_auth_from_env(api_format: ApiFormat) -> Result<Option<EndpointAuth>> {
    let header = std::env::var(ENDPOINT_AUTH_HEADER_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let value = std::env::var(ENDPOINT_AUTH_VALUE_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    match (header, value) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(anyhow!(
            "{ENDPOINT_AUTH_VALUE_ENV} must be set when {ENDPOINT_AUTH_HEADER_ENV} is set"
        )),
        (None, Some(_)) => Err(anyhow!(
            "{ENDPOINT_AUTH_HEADER_ENV} must be set when {ENDPOINT_AUTH_VALUE_ENV} is set"
        )),
        (Some(header), Some(secret)) => {
            let normalized = header.trim().to_ascii_lowercase();
            anyhow::ensure!(
                !(ALWAYS_MANAGED_HEADERS.contains(&normalized.as_str())
                    || (api_format == ApiFormat::OpenaiCompatible
                        && normalized == "authorization")),
                "{ENDPOINT_AUTH_HEADER_ENV} cannot override provider-managed header {header:?}"
            );
            let name = HeaderName::from_bytes(header.trim().as_bytes()).with_context(|| {
                format!("{ENDPOINT_AUTH_HEADER_ENV} is not a valid HTTP header name")
            })?;
            let mut value = HeaderValue::from_bytes(secret.as_bytes()).with_context(|| {
                format!("{ENDPOINT_AUTH_VALUE_ENV} is not a valid HTTP header value")
            })?;
            value.set_sensitive(true);
            Ok(Some(EndpointAuth { name, value }))
        }
    }
}

/// Extract and validate the review JSON from model text. Tolerates code fences
/// and leading/trailing prose, nothing else.
fn parse_review(content: &str) -> Result<RawReview, String> {
    let json_str = extract_json_object(content).ok_or("no JSON object found")?;
    serde_json::from_str::<RawReview>(json_str).map_err(|e| e.to_string())
}

fn parse_scores(content: &str, expected_len: usize) -> Result<Vec<FindingScore>, String> {
    let json_str = extract_json_array(content).ok_or("no JSON array found")?;
    let raw = serde_json::from_str::<Vec<RawScore>>(json_str).map_err(|e| e.to_string())?;
    if raw.len() != expected_len {
        return Err(format!(
            "expected {expected_len} score(s), got {}",
            raw.len()
        ));
    }
    raw
        .into_iter()
        .enumerate()
        .map(|(index, score)| {
            if !score.confidence.is_finite() || !(0.0..=1.0).contains(&score.confidence) {
                return Err(format!(
                    "score confidence must be a finite number from 0 through 1 (got {:?})",
                    score.confidence
                ));
            }
            let kind = Kind::parse(&score.kind).ok_or_else(|| {
                format!(
                    "invalid score kind {:?} (risk|humanEscalation|guardrail|uncertainty|contentPolicy)",
                    score.kind
                )
            })?;
            let reason = validate_scorer_reason(&score.reason)?;
            Ok(FindingScore {
                index,
                confidence: score.confidence,
                kind,
                reason,
            })
        })
        .collect::<Result<Vec<_>, String>>()
}

#[cfg(feature = "qualification-candidate")]
fn parse_atomic_attribution(content: &str) -> Result<RawAtomicAttribution, String> {
    let json = extract_json_object(content).ok_or("no JSON object found")?;
    let mut verdict =
        serde_json::from_str::<RawAtomicAttribution>(json).map_err(|error| error.to_string())?;
    verdict.reason = validate_scorer_reason(&verdict.reason)?;
    Ok(verdict)
}

fn validate_scorer_reason(value: &str) -> Result<String, String> {
    if value.chars().next().is_some_and(is_json_schema_whitespace)
        || value.chars().last().is_some_and(is_json_schema_whitespace)
    {
        return Err("score reason must not have leading or trailing whitespace".to_string());
    }
    let reason = value;
    if reason.is_empty() {
        return Err("score reason must not be empty".to_string());
    }
    if reason
        .chars()
        .any(|character| character.is_control() || matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(
            "score reason must not contain control characters or line separators".to_string(),
        );
    }
    let byte_count = reason.len();
    if byte_count > SCORER_REASON_MAX_BYTES {
        return Err(format!(
            "score reason exceeds {SCORER_REASON_MAX_BYTES} UTF-8 bytes (got {byte_count})"
        ));
    }
    let is_terminator = |character: char| {
        matches!(
            character,
            '.' | '!' | '?' | '\u{3002}' | '\u{ff01}' | '\u{ff1f}'
        )
    };
    if !reason.chars().last().is_some_and(is_terminator) {
        return Err("score reason must end with sentence punctuation".to_string());
    }
    Ok(reason.to_string())
}

fn is_json_schema_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            ..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_json_array(text: &str) -> Option<&str> {
    let start = text.find('[')?;
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn into_review(raw: RawReview, model: &str, usage: Usage) -> ModelReview {
    use crate::envelope::{Kind, Severity};
    let findings = raw
        .findings
        .into_iter()
        .map(|f| {
            // Fail toward surfacing: an unrecognized severity label must never
            // erase the whole finding (path/line/body), or a real high-severity
            // issue the model called "major"/"P0"/"moderate" would vanish before
            // grounding, the gate, and the user ever see it. Default unknown
            // labels to Warn. This is conservative (non-silent, without over-gating the
            // way an Error default would).
            let severity = Severity::parse(&f.severity).unwrap_or(Severity::Warn);
            let kind = match f.kind.as_deref() {
                Some("humanEscalation") | Some("human_escalation") => Kind::HumanEscalation,
                Some("guardrail") => Kind::Guardrail,
                Some("uncertainty") => Kind::Uncertainty,
                Some("contentPolicy") | Some("content_policy") => Kind::ContentPolicy,
                _ => Kind::Risk,
            };
            Finding {
                path: f.path.trim_start_matches("./").to_string(),
                line: f.line,
                end_line: f.end_line.filter(|e| *e >= f.line),
                severity,
                kind,
                confidence: f.confidence.clamp(0.0, 1.0),
                generator_confidence: None,
                scorer_confidence: None,
                generator_kind: None,
                scorer_kind: None,
                scorer_reason: None,
                title: f.title,
                body: f.body,
                evidence: f.evidence,
                id: None,
            }
        })
        .collect();
    ModelReview {
        summary: raw.summary.trim().to_string(),
        findings,
        model_used: model.to_string(),
        usage,
        model_usage: vec![],
        model_incidents: vec![],
        usage_accounting_complete: true,
    }
}

/// Keep findings at least two models agree on (same path, lines within 5).
/// Agreement is symmetric: a finding two secondary models report is kept even
/// if the primary missed it. The earliest run's wording represents a cluster
/// (so the primary's phrasing wins when it participates); confidence becomes
/// the max among agreeing reports.
fn consensus_merge(runs: Vec<ModelReview>) -> ModelReview {
    let total_usage = Usage {
        prompt_tokens: runs.iter().map(|r| r.usage.prompt_tokens).sum(),
        completion_tokens: runs.iter().map(|r| r.usage.completion_tokens).sum(),
        cost_micros: runs
            .iter()
            .try_fold(0u64, |sum, run| sum.checked_add(run.usage.cost_micros?)),
        provider_cost: runs.iter().try_fold(
            ProviderCost::parse("0").expect("zero provider cost parses"),
            |sum, run| sum.checked_add(run.usage.provider_cost?),
        ),
    };
    let models: Vec<String> = runs.iter().map(|r| r.model_used.clone()).collect();
    let model_usage = runs.iter().flat_map(|r| r.model_usage.clone()).collect();
    let model_incidents = runs
        .iter()
        .flat_map(|r| r.model_incidents.clone())
        .collect();
    let usage_accounting_complete = runs.iter().all(|r| r.usage_accounting_complete);
    let summary = runs[0].summary.clone();
    // Flatten in run order; greedy clustering then anchors each cluster on its
    // earliest report.
    let tagged: Vec<(usize, Finding)> = runs
        .into_iter()
        .enumerate()
        .flat_map(|(i, r)| r.findings.into_iter().map(move |f| (i, f)))
        .collect();
    let mut consumed = vec![false; tagged.len()];
    let mut kept: Vec<Finding> = Vec::new();
    for i in 0..tagged.len() {
        if consumed[i] {
            continue;
        }
        let (anchor_run, anchor) = &tagged[i];
        let mut runs_agreeing = std::collections::HashSet::from([*anchor_run]);
        let mut max_conf = anchor.confidence;
        let mut members = vec![i];
        for (j, (run, f)) in tagged.iter().enumerate().skip(i + 1) {
            if consumed[j] || f.path != anchor.path || f.line.abs_diff(anchor.line) > 5 {
                continue;
            }
            runs_agreeing.insert(*run);
            max_conf = max_conf.max(f.confidence);
            members.push(j);
        }
        for &j in &members {
            consumed[j] = true;
        }
        if runs_agreeing.len() >= 2 {
            kept.push(Finding {
                confidence: max_conf,
                ..anchor.clone()
            });
        }
    }
    ModelReview {
        summary,
        findings: kept,
        model_used: format!("consensus({})", models.join(", ")),
        usage: total_usage,
        model_usage,
        model_incidents,
        usage_accounting_complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_retry_delay_uses_bounded_equal_jitter() {
        assert_eq!(
            provider_retry_delay_with_sample(1, 0),
            Duration::from_secs(1)
        );
        assert_eq!(
            provider_retry_delay_with_sample(1, 1_000),
            Duration::from_secs(2)
        );
        assert_eq!(
            provider_retry_delay_with_sample(2, 0),
            Duration::from_secs(2)
        );
        assert_eq!(
            provider_retry_delay_with_sample(2, 2_000),
            Duration::from_secs(4)
        );
    }
    use crate::config::Config;
    use crate::envelope::{Kind, Severity};
    use std::sync::{Mutex, OnceLock};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct EnvRestore {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvRestore {
        fn capture(names: &[&'static str]) -> Self {
            Self {
                saved: names
                    .iter()
                    .map(|name| (*name, std::env::var_os(name)))
                    .collect(),
            }
        }

        fn remove(name: &str) {
            unsafe {
                std::env::remove_var(name);
            }
        }

        fn set(name: &str, value: &str) {
            unsafe {
                std::env::set_var(name, value);
            }
        }
    }

    #[test]
    fn every_model_content_failure_is_operational_and_never_advisory_bypassable() {
        let failures = [
            ModelContentFailure::Empty,
            ModelContentFailure::MissingChoices,
            ModelContentFailure::NonTerminal {
                reason: "length".to_string(),
            },
        ];
        for failure in failures {
            let error = ModelError::new(
                classify_chat_error(anyhow::Error::new(failure)),
                Usage::default(),
                false,
            );
            assert!(!error.is_provider());
            assert_eq!(safe_model_error_category(&error), "invalid-output");
        }

        let provider = ModelError::new(
            classify_chat_error(anyhow!("provider transport failed")),
            Usage::default(),
            false,
        );
        assert!(provider.is_provider());
        assert_eq!(safe_model_error_category(&provider), "provider");
    }

    #[test]
    fn log_text_escapes_line_and_terminal_controls() {
        assert_eq!(
            log_text("model\nnext\r\t\u{1b}[31m"),
            r"model\nnext\r\t\u{1b}[31m"
        );
    }

    #[test]
    fn endpoint_auth_rejects_headers_managed_by_each_api_format() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[ENDPOINT_AUTH_HEADER_ENV, ENDPOINT_AUTH_VALUE_ENV]);
        EnvRestore::set(ENDPOINT_AUTH_VALUE_ENV, "secret-value");
        for name in ["X-API-Key", "Anthropic-Version", "Content-Type"] {
            EnvRestore::set(ENDPOINT_AUTH_HEADER_ENV, name);
            for format in [ApiFormat::OpenaiCompatible, ApiFormat::Anthropic] {
                let error = endpoint_auth_from_env(format)
                    .err()
                    .expect("collision rejected");
                assert!(error.to_string().contains("provider-managed header"));
                assert!(!error.to_string().contains("secret-value"));
            }
        }

        EnvRestore::set(ENDPOINT_AUTH_HEADER_ENV, "Authorization");
        let openai_error = endpoint_auth_from_env(ApiFormat::OpenaiCompatible)
            .err()
            .expect("OpenAI-compatible Authorization collision rejected");
        assert!(openai_error.to_string().contains("provider-managed header"));
        assert!(!openai_error.to_string().contains("secret-value"));

        let anthropic = endpoint_auth_from_env(ApiFormat::Anthropic)
            .unwrap()
            .expect("Anthropic additional Authorization accepted");
        assert_eq!(anthropic.name, reqwest::header::AUTHORIZATION);
        assert_eq!(anthropic.value, "secret-value");
    }

    #[test]
    fn api_endpoint_resolution_rejects_any_non_public_result() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[ALLOW_PRIVATE_API_BASE_ENV]);
        EnvRestore::remove(ALLOW_PRIVATE_API_BASE_ENV);
        let error = resolve_api_endpoint_with("https://models.example/v1", |hostname, port| {
            assert_eq!(hostname, "models.example");
            assert_eq!(port, 443);
            Ok(vec![
                "8.8.8.8:443".parse().unwrap(),
                "169.254.169.254:443".parse().unwrap(),
            ])
        })
        .expect_err("a mixed public/private DNS answer must fail closed");
        assert!(error.to_string().contains("non-public address"));
    }

    #[test]
    fn api_endpoint_resolution_preserves_public_addresses_for_pinning() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[ALLOW_PRIVATE_API_BASE_ENV]);
        EnvRestore::remove(ALLOW_PRIVATE_API_BASE_ENV);
        let expected = vec![
            "8.8.8.8:8443".parse().unwrap(),
            "[2606:4700:4700::1111]:8443".parse().unwrap(),
        ];
        let (hostname, addresses) = resolve_api_endpoint_with(
            "https://models.example:8443/v1",
            |_, _| Ok(expected.clone()),
        )
        .unwrap();
        assert_eq!(hostname, "models.example");
        assert_eq!(addresses, expected);
    }

    #[test]
    fn api_endpoint_rejects_ipv4_mapped_compatible_and_nat64_private_targets() {
        for address in [
            "::ffff:127.0.0.1",
            "::a00:1",
            "64:ff9b::a9fe:a9fe",
            "fec0::1",
        ] {
            assert!(
                !is_public_ip(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        assert!(is_public_ip("64:ff9b::808:808".parse().unwrap()));
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => unsafe {
                        std::env::set_var(name, value);
                    },
                    None => unsafe {
                        std::env::remove_var(name);
                    },
                }
            }
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn provider_error_downcast_survives_additional_context() {
        // review.rs's fail-open/fail-closed classifier does
        // `e.downcast_ref::<ProviderError>().is_some()` on the error returned by
        // the LLM client. That error picks up further `.context(...)` layers
        // between here and there (e.g. review.rs wrapping client calls); this
        // pins that anyhow's downcast_ref still finds the marker underneath any
        // number of additional context layers, so the marker is never masked by
        // later wrapping.
        let base: anyhow::Error =
            anyhow::Error::new(std::io::Error::other("boom")).context(ProviderError);
        let wrapped = base
            .context("fetching diff")
            .context("running review")
            .context("one more layer for good measure");
        assert!(
            wrapped.downcast_ref::<ProviderError>().is_some(),
            "ProviderError marker must survive additional context wrapping"
        );
    }

    #[test]
    fn remote_budget_start_sets_default_total_deadline_when_env_is_unset() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[REQUEST_TIMEOUT_ENV, TOTAL_TIMEOUT_ENV, "POSTIL_API_KEY"]);
        EnvRestore::remove(REQUEST_TIMEOUT_ENV);
        EnvRestore::remove(TOTAL_TIMEOUT_ENV);
        EnvRestore::set("POSTIL_API_KEY", "test-key");

        let client = LlmClient::from_env_for_remote_review(
            &Config::default(),
            Instant::now(),
            Duration::from_secs(crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS),
            Duration::from_secs(crate::review::HOSTED_LLM_REVIEW_TIMEOUT_SECS),
            Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS),
        )
        .unwrap();
        let remaining = client.remaining_budget(LlmPhase::Total).unwrap().unwrap();

        assert!(remaining <= Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS));
        assert!(remaining > Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS - 5));
    }

    #[test]
    fn local_from_env_has_no_total_deadline_without_env_override() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[REQUEST_TIMEOUT_ENV, TOTAL_TIMEOUT_ENV, "POSTIL_API_KEY"]);
        EnvRestore::remove(REQUEST_TIMEOUT_ENV);
        EnvRestore::remove(TOTAL_TIMEOUT_ENV);
        EnvRestore::set("POSTIL_API_KEY", "test-key");

        let client = LlmClient::from_env(&Config::default()).unwrap();

        assert!(client.remaining_budget(LlmPhase::Review).unwrap().is_none());
        assert!(client.remaining_budget(LlmPhase::Total).unwrap().is_none());
    }

    #[test]
    fn local_from_env_keeps_the_original_480s_request_timeout() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[REQUEST_TIMEOUT_ENV, TOTAL_TIMEOUT_ENV]);
        EnvRestore::remove(REQUEST_TIMEOUT_ENV);
        EnvRestore::remove(TOTAL_TIMEOUT_ENV);

        // The hosted path uses a shorter per-request timeout (240s) so a timeout
        // retry and fallback fit before its review deadline. Local runs have
        // no total budget by default and must keep the original, more generous
        // request timeout rather than inherit the hosted-tuned value.
        let timeouts = LlmTimeouts::from_env(DEFAULT_REQUEST_TIMEOUT_SECS, None).unwrap();

        assert_eq!(timeouts.request, Duration::from_secs(480));
        assert_ne!(
            timeouts.request,
            Duration::from_secs(crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS)
        );
    }

    #[test]
    fn hosted_provider_contract_requires_canonical_openrouter_openai() {
        assert!(
            ensure_hosted_provider_contract(
                ApiFormat::OpenaiCompatible,
                "https://openrouter.ai/api/v1/"
            )
            .is_ok()
        );
        assert!(
            ensure_hosted_provider_contract(ApiFormat::Anthropic, "https://api.anthropic.com/v1")
                .is_err()
        );
        assert!(
            ensure_hosted_provider_contract(
                ApiFormat::OpenaiCompatible,
                "https://private.example/v1"
            )
            .is_err()
        );
    }

    #[test]
    fn planner_selection_is_exact_unique_bounded_and_grounded() {
        let allowed = BTreeSet::from([2usize, 4, 8]);
        assert_eq!(
            validate_batch_selection(r#"{"batchIds":[8,2]}"#, &allowed, 2).unwrap(),
            vec![2, 8]
        );
        assert!(validate_batch_selection(r#"{"batchIds":[2,2]}"#, &allowed, 2).is_err());
        assert!(validate_batch_selection(r#"{"batchIds":[3]}"#, &allowed, 2).is_err());
        assert!(validate_batch_selection(r#"{"batchIds":[2,4,8]}"#, &allowed, 2).is_err());
        assert!(validate_batch_selection(r#"{"batchIds":[2],"extra":true}"#, &allowed, 2).is_err());
    }

    #[tokio::test]
    async fn zero_capacity_planner_has_no_preflight_exposure_or_provider_call() {
        let server = MockServer::start().await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let mut client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([(
            "provider/model".into(),
            ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 1,
                output_micros_per_million_tokens: 1,
            },
        )])));

        let admission = client
            .preflight_review_plan(
                &config,
                1,
                "system",
                &["candidate".to_string()],
                &["candidate".to_string()],
                Some(("hostile planner manifest", 0)),
            )
            .unwrap();
        assert_eq!(
            admission.output_tokens,
            u64::from(LlmPhase::Review.exhausted_output_retry_max_tokens(REVIEW_MAX_TOKENS))
        );
        let plan = client
            .plan_review_batches(
                &config,
                "hostile planner manifest",
                &BTreeSet::from([2usize]),
                0,
            )
            .await
            .unwrap();
        assert!(plan.batch_ids.is_empty());
        assert!(plan.model_usage.is_empty());
        assert_eq!(plan.usage.prompt_tokens, 0);
        assert_eq!(plan.usage.completion_tokens, 0);
        assert!(plan.usage.provider_cost.is_none());
        assert_eq!(client.admission.lock().unwrap().attempts, 0);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn planner_failure_falls_back_and_preserves_usage_cost_and_incidents() {
        let server = MockServer::start().await;
        for (model, prompt_tokens, completion_tokens, cost) in [
            ("provider/primary", 10, 2, "0.000010"),
            ("provider/fallback", 20, 3, "0.000020"),
        ] {
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .and(body_string_contains(model))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"finish_reason": "stop", "message": {"content": "not valid planner json"}}],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "cost": serde_json::from_str::<serde_json::Value>(cost).unwrap()
                    }
                })))
                .expect(2)
                .mount(&server)
                .await;
        }
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/primary".into(),
            cascade: vec!["provider/fallback".into()],
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let result = client
            .plan_review_batches(
                &config,
                "Batch 2 risk=1 kind=source\nchange",
                &BTreeSet::from([2usize]),
                1,
            )
            .await
            .unwrap();

        assert!(result.fallback_used);
        assert!(result.batch_ids.is_empty());
        assert_eq!(result.usage.prompt_tokens, 60);
        assert_eq!(result.usage.completion_tokens, 10);
        assert_eq!(result.usage.provider_cost.unwrap().to_string(), "0.00006");
        assert_eq!(result.model_usage.len(), 4);
        assert!(
            result
                .model_usage
                .iter()
                .all(|usage| usage.role == Some(ModelUsageRole::ReviewPlanner))
        );
        assert_eq!(result.model_incidents.len(), 4);
        assert!(result.model_incidents.iter().all(|incident| {
            incident.phase == ModelIncidentPhase::Planner
                && incident.category == ModelIncidentCategory::InvalidOutput
                && incident.recovered
                && incident.recovery == Some(ModelIncidentRecovery::Fallback)
        }));
        assert!(result.usage_accounting_complete);
    }

    #[tokio::test]
    async fn planner_schema_repair_preserves_usage_cost_and_recovery_incident() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains("The previous response was invalid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": "{\"batchIds\":[2]}"}}],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 3,
                    "cost": serde_json::from_str::<serde_json::Value>("0.000020").unwrap()
                }
            })))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": "not valid planner json"}}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 2,
                    "cost": serde_json::from_str::<serde_json::Value>("0.000010").unwrap()
                }
            })))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let result = client
            .plan_review_batches(
                &config,
                "Batch 2 risk=1 kind=source\nchange",
                &BTreeSet::from([2usize]),
                1,
            )
            .await
            .unwrap();

        assert!(!result.fallback_used);
        assert_eq!(result.batch_ids, vec![2]);
        assert_eq!(result.usage.prompt_tokens, 30);
        assert_eq!(result.usage.completion_tokens, 5);
        assert_eq!(result.usage.provider_cost.unwrap().to_string(), "0.00003");
        assert_eq!(result.model_usage.len(), 2);
        assert_eq!(result.model_incidents.len(), 1);
        let incident = &result.model_incidents[0];
        assert_eq!(incident.phase, ModelIncidentPhase::Planner);
        assert_eq!(incident.category, ModelIncidentCategory::InvalidOutput);
        assert!(incident.recovered);
        assert_eq!(incident.recovery, Some(ModelIncidentRecovery::Repair));
        assert!(result.usage_accounting_complete);
    }

    #[tokio::test]
    async fn output_exhausted_review_retries_complete_request_with_expanded_budget() {
        let server = MockServer::start().await;
        let review = r#"{"summary":"","findings":[]}"#;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains("\"max_tokens\":16000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": review}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 3}
            })))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains("\"max_tokens\":8000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "length", "message": {"content": "{\"summary\":\"partial"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8000}
            })))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let result = client.review(&config, "system", "user").await.unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.model_usage.len(), 2);
        assert!(result.model_incidents.is_empty());
        assert_eq!(result.usage.prompt_tokens, 30);
        assert_eq!(result.usage.completion_tokens, 8_003);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            let body = String::from_utf8_lossy(&request.body);
            body.contains("\"content\":\"user\"") && !body.contains("You repair malformed JSON")
        }));
    }

    #[tokio::test]
    async fn repeated_output_exhaustion_fails_without_repairing_partial_content() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "length", "message": {"content": "{\"summary\":\"partial"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8000}
            })))
            .expect(2)
            .mount(&server)
            .await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let _error = client.review(&config, "system", "user").await.unwrap_err();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            !String::from_utf8_lossy(&request.body).contains("You repair malformed JSON")
        }));
    }

    #[tokio::test]
    async fn over_limit_finding_fails_after_one_bounded_semantic_repair() {
        let server = MockServer::start().await;
        let body = format!("{}.", "word ".repeat(250));
        let review = serde_json::json!({
            "summary": "A merge-relevant issue.",
            "findings": [{
                "path": "src/lib.rs",
                "line": 1,
                "severity": "warn",
                "kind": "risk",
                "confidence": 0.9,
                "title": "Keep the complete finding",
                "body": body,
                "evidence": "changed();"
            }]
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": review}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2}
            })))
            .expect(2)
            .mount(&server)
            .await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let result = client
            .review_validated(&config, "system", "user", |review| {
                review
                    .findings
                    .iter()
                    .try_for_each(crate::envelope::validate_finding_publication)
            })
            .await;
        assert!(result.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn planner_model_cascade_marks_fallback_and_preserves_incidents() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains("provider/primary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": "invalid"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2}
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(body_string_contains("provider/fallback"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"finish_reason": "stop", "message": {"content": "{\"batchIds\":[2]}"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 3}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let config = Config {
            api_base: server.uri(),
            api_format: ApiFormat::OpenaiCompatible,
            model: "provider/primary".into(),
            cascade: vec!["provider/fallback".into()],
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap();
        *client.http.lock().unwrap() = Some(reqwest::Client::new());

        let result = client
            .plan_review_batches(
                &config,
                "Batch 2 risk=1 kind=source\nchange",
                &BTreeSet::from([2usize]),
                1,
            )
            .await
            .unwrap();

        assert!(result.fallback_used);
        assert_eq!(result.batch_ids, vec![2]);
        assert_eq!(result.usage.prompt_tokens, 40);
        assert_eq!(result.usage.completion_tokens, 7);
        assert_eq!(result.model_usage.len(), 3);
        assert_eq!(result.model_incidents.len(), 2);
        assert!(result.model_incidents.iter().all(|incident| {
            incident.phase == ModelIncidentPhase::Planner
                && incident.category == ModelIncidentCategory::InvalidOutput
                && incident.recovered
                && incident.recovery == Some(ModelIncidentRecovery::Fallback)
        }));
    }

    #[test]
    fn hosted_respond_preflight_accounts_for_every_fallback_before_calls() {
        let config = Config {
            model: "provider/primary".into(),
            cascade: vec!["provider/fallback".into()],
            ..Config::default()
        };
        let mut client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([
            (
                "provider/primary".into(),
                ModelPriceBound {
                    model: "provider/primary".into(),
                    input_micros_per_million_tokens: 1,
                    output_micros_per_million_tokens: 1,
                },
            ),
            (
                "provider/fallback".into(),
                ModelPriceBound {
                    model: "provider/fallback".into(),
                    input_micros_per_million_tokens: 1,
                    output_micros_per_million_tokens: 1,
                },
            ),
        ])));
        let admission = client
            .preflight_respond_plan(&config, "system", "bounded user context")
            .unwrap();
        assert_eq!(admission.provider_attempts, 6);
        assert_eq!(
            admission.output_tokens,
            u64::from(LlmPhase::Respond.exhausted_output_retry_max_tokens(RESPOND_MAX_TOKENS)) * 6
        );
        assert_eq!(client.admission.lock().unwrap().attempts, 0);
    }

    #[test]
    fn exhausted_output_retry_ceiling_is_phase_aware() {
        assert_eq!(
            LlmPhase::Review.exhausted_output_retry_max_tokens(REVIEW_MAX_TOKENS),
            EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS
        );
        assert_eq!(
            LlmPhase::Planner.exhausted_output_retry_max_tokens(PLANNER_MAX_TOKENS),
            PLANNER_MAX_TOKENS * 2
        );
        assert_eq!(
            LlmPhase::Respond.exhausted_output_retry_max_tokens(RESPOND_MAX_TOKENS),
            RESPOND_MAX_TOKENS * 2
        );
        let scorer_tokens = scorer_max_tokens(SCORER_MAX_FINDINGS).unwrap();
        assert_eq!(
            LlmPhase::Scorer {
                expected_len: SCORER_MAX_FINDINGS,
            }
            .exhausted_output_retry_max_tokens(scorer_tokens),
            scorer_tokens
        );
        assert_eq!(
            LlmPhase::Attribution.exhausted_output_retry_max_tokens(1_000),
            1_000
        );
        assert_eq!(
            LlmPhase::Review
                .exhausted_output_retry_max_tokens(EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS + 1),
            EXHAUSTED_OUTPUT_RETRY_MAX_TOKENS + 1
        );
    }

    #[test]
    fn hosted_review_preflight_keeps_scorer_at_its_runtime_ceiling() {
        let config = Config {
            model: "provider/generator".into(),
            scorer: "provider/scorer".into(),
            scorer_enabled: true,
            ..Config::default()
        };
        let mut client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([
            (
                "provider/generator".into(),
                ModelPriceBound {
                    model: "provider/generator".into(),
                    input_micros_per_million_tokens: 1,
                    output_micros_per_million_tokens: 1,
                },
            ),
            (
                "provider/scorer".into(),
                ModelPriceBound {
                    model: "provider/scorer".into(),
                    input_micros_per_million_tokens: 1,
                    output_micros_per_million_tokens: 1,
                },
            ),
        ])));

        let admission = client
            .preflight_review_plan(
                &config,
                1,
                "system",
                &["candidate".to_string()],
                &["candidate".to_string()],
                None,
            )
            .unwrap();
        assert_eq!(
            admission.output_tokens,
            u64::from(LlmPhase::Review.exhausted_output_retry_max_tokens(REVIEW_MAX_TOKENS))
                + u64::from(scorer_max_tokens(SCORER_MAX_FINDINGS).unwrap())
        );
    }

    #[test]
    fn hosted_review_plan_admits_bounded_selection_independent_of_raw_batch_count() {
        let config = Config {
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let mut client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([(
            "provider/model".into(),
            ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 1,
                output_micros_per_million_tokens: 1,
            },
        )])));
        let admission = client
            .preflight_review_plan(
                &config,
                crate::review::MAX_HOSTED_SELECTED_BATCHES,
                "system",
                &vec!["bounded candidate".to_string(); crate::review::MAX_HOSTED_SELECTED_BATCHES],
                &vec!["bounded candidate".to_string(); crate::review::MAX_HOSTED_SELECTED_BATCHES],
                Some((&"m".repeat(96_000), 1)),
            )
            .unwrap();
        assert_eq!(
            admission.output_tokens,
            u64::from(LlmPhase::Review.exhausted_output_retry_max_tokens(REVIEW_MAX_TOKENS))
                * crate::review::MAX_HOSTED_SELECTED_BATCHES as u64
                + u64::from(
                    LlmPhase::Planner.exhausted_output_retry_max_tokens(PLANNER_MAX_TOKENS)
                )
        );
        assert_eq!(client.admission.lock().unwrap().attempts, 0);
    }

    #[test]
    fn maximum_hosted_plan_matches_watchdog_and_transport_arithmetic() {
        let review_calls = crate::review::MAX_HOSTED_SELECTED_BATCHES
            * crate::review::MAX_MODELS_PER_REQUEST
            * MAX_LOGICAL_CALLS_PER_REVIEW_MODEL;
        let planner_calls =
            crate::review::MAX_MODELS_PER_REQUEST * MAX_LOGICAL_CALLS_PER_REVIEW_MODEL;
        let scorer_calls = 2 * MAX_LOGICAL_CALLS_PER_SCORER_MODEL;
        let logical_calls = review_calls + planner_calls + scorer_calls;

        assert_eq!(logical_calls, MAX_HOSTED_PLANNED_CALLS_BY_WATCHDOG);
        assert!(logical_calls * MAX_TRANSPORT_ATTEMPTS_PER_CALL <= MAX_PROVIDER_ATTEMPTS);
    }

    #[tokio::test]
    async fn deterministic_hosted_rejection_contacts_no_provider() {
        let server = wiremock::MockServer::start().await;
        let config = Config {
            api_base: server.uri(),
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let mut client = {
            let _lock = env_lock().lock().unwrap();
            let _env = EnvRestore::capture(&[ENDPOINT_AUTH_HEADER_ENV, ENDPOINT_AUTH_VALUE_ENV]);
            EnvRestore::remove(ENDPOINT_AUTH_HEADER_ENV);
            EnvRestore::remove(ENDPOINT_AUTH_VALUE_ENV);
            LlmClient::build(
                &config,
                "test-key".into(),
                Duration::from_secs(1),
                None,
                None,
            )
            .unwrap()
        };
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([(
            "provider/model".into(),
            ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 1_000_000,
                output_micros_per_million_tokens: 1_000_000,
            },
        )])));

        let error = client
            .preflight_review_plan(
                &config,
                crate::review::MAX_HOSTED_SELECTED_BATCHES,
                "system",
                &vec![hostile_json_text(400_000); crate::review::MAX_HOSTED_SELECTED_BATCHES],
                &vec![hostile_json_text(400_000); crate::review::MAX_HOSTED_SELECTED_BATCHES],
                Some(("manifest", 1)),
            )
            .unwrap_err();

        assert!(error.to_string().contains("per-request cap"));
        assert_eq!(client.admission.lock().unwrap().attempts, 0);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn hosted_preflight_cost_error_reports_exposure_dimensions() {
        let client = LlmClient::build(
            &Config::default(),
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let error = client
            .validate_hosted_exposure(
                "review",
                &PlannedExposure {
                    attempts: 6,
                    input_bytes: 12_345,
                    output_tokens: 678,
                    projected_cost_micros: HOSTED_OPERATION_COST_CAP_MICROS + 1,
                    model_costs_micros: BTreeMap::from([(
                        "provider/model".to_string(),
                        HOSTED_OPERATION_COST_CAP_MICROS + 1,
                    )]),
                },
            )
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("provider exposure across 6 attempts"));
        assert!(message.contains("12345 serialized input bytes"));
        assert!(message.contains("678 output tokens"));
        assert!(message.contains(r#""provider/model"=1000001"#));
    }

    #[test]
    fn planned_exposure_aggregates_atomic_per_model_transport_costs() {
        let first = ModelPriceBound {
            model: "provider/first".to_string(),
            input_micros_per_million_tokens: 1_000_000,
            output_micros_per_million_tokens: 2_000_000,
        };
        let second = ModelPriceBound {
            model: "provider/second\u{1b}[2J,=value".to_string(),
            input_micros_per_million_tokens: 2_000_000,
            output_micros_per_million_tokens: 3_000_000,
        };
        let mut exposure = PlannedExposure::default();
        exposure.add_primary_request(100, 10, &first).unwrap();
        assert_eq!(exposure.attempts, 1);
        assert_eq!(exposure.input_bytes, 100);
        assert_eq!(exposure.output_tokens, 10);
        assert_eq!(exposure.projected_cost_micros, 120);

        let mut exposure = PlannedExposure::default();
        exposure.add_request(100, 10, &first).unwrap();
        exposure.add_request(100, 10, &first).unwrap();
        exposure.add_request(50, 4, &second).unwrap();

        assert_eq!(exposure.attempts, 9);
        assert_eq!(exposure.input_bytes, 750);
        assert_eq!(exposure.output_tokens, 72);
        assert_eq!(exposure.model_costs_micros["provider/first"], 720);
        assert_eq!(exposure.model_costs_micros[&second.model], 336);
        assert_eq!(
            exposure.model_costs_micros.values().sum::<u64>(),
            exposure.projected_cost_micros
        );
        assert_eq!(exposure.projected_cost_micros, 1_056);

        exposure.projected_cost_micros = HOSTED_OPERATION_COST_CAP_MICROS + 1;
        let error = LlmClient::build(
            &Config::default(),
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap()
        .validate_hosted_exposure("review", &exposure)
        .unwrap_err()
        .to_string();
        assert!(!error.contains('\u{1b}'));
        assert!(error.contains(r#""provider/second\\u{1b}[2J,=value"=336"#));

        let mut overflow = PlannedExposure::default();
        overflow
            .model_costs_micros
            .insert(first.model.clone(), u64::MAX);
        let error = overflow.add_request(1, 1, &first).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("planned model cost exposure overflowed")
        );
        assert_eq!(overflow.attempts, 0);
        assert_eq!(overflow.input_bytes, 0);
        assert_eq!(overflow.output_tokens, 0);
        assert_eq!(overflow.projected_cost_micros, 0);
        assert_eq!(overflow.model_costs_micros[&first.model], u64::MAX);
    }

    #[test]
    fn hosted_preflight_counts_exact_hostile_json_expansion() {
        let config = Config {
            model: "provider/model".into(),
            scorer_enabled: false,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let hostile = "\0".repeat(32 * 1_024);

        let exact = client
            .planned_request_bytes(
                "provider/model",
                "system with \"quotes\" and \\slashes",
                &hostile,
                REVIEW_MAX_TOKENS,
                0.0,
                LlmPhase::Review,
            )
            .unwrap();
        let actual = serde_json::to_vec(&client.request_body(
            "provider/model",
            "system with \"quotes\" and \\slashes",
            &hostile,
            REVIEW_MAX_TOKENS,
            0.0,
            LlmPhase::Review,
        ))
        .unwrap()
        .len();

        assert_eq!(exact, actual);
        assert!(exact > hostile.len() * 5);
    }

    #[test]
    fn openai_and_anthropic_request_shapes_enforce_the_hostile_serialized_limit() {
        for api_format in [ApiFormat::OpenaiCompatible, ApiFormat::Anthropic] {
            let config = Config {
                api_format,
                model: "provider/model".into(),
                ..Config::default()
            };
            let client = LlmClient::build(
                &config,
                "test-key".into(),
                Duration::from_secs(1),
                None,
                None,
            )
            .unwrap();
            let body_for = |hostile_bytes: usize| {
                client.request_body(
                    "provider/model",
                    "system",
                    &hostile_json_text(hostile_bytes),
                    REVIEW_MAX_TOKENS,
                    0.1,
                    LlmPhase::Review,
                )
            };
            let mut low = 0usize;
            let mut high = MAX_PROVIDER_REQUEST_BYTES;
            while low < high {
                let middle = low + (high - low).div_ceil(2);
                if serde_json::to_vec(&body_for(middle)).unwrap().len()
                    <= MAX_PROVIDER_REQUEST_BYTES
                {
                    low = middle;
                } else {
                    high = middle - 1;
                }
            }
            assert!(
                crate::review::MAX_REVIEW_BATCH_BYTES <= low,
                "{api_format:?} cannot carry the configured review batch under the serialized cap"
            );
            let accepted = body_for(low);
            let rejected = body_for(low + 1);
            assert!(
                serialized_provider_request_bytes(&accepted, "hostile request").is_ok(),
                "{api_format:?} rejected its largest fitting hostile request"
            );
            assert!(
                serialized_provider_request_bytes(&rejected, "hostile request").is_err(),
                "{api_format:?} admitted a hostile request over the serialized cap"
            );
        }
    }

    #[test]
    fn default_timeout_profile_sets_no_setup_scorer_window_and_worker_margin() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[REQUEST_TIMEOUT_ENV, TOTAL_TIMEOUT_ENV]);
        EnvRestore::remove(REQUEST_TIMEOUT_ENV);
        EnvRestore::remove(TOTAL_TIMEOUT_ENV);

        let timeouts = LlmTimeouts::from_env(
            crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS,
            Some(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS),
        )
        .unwrap();

        assert_eq!(
            timeouts.request,
            Duration::from_secs(crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS)
        );
        assert_eq!(
            timeouts.total,
            Some(Duration::from_secs(
                crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS
            ))
        );
        assert_eq!(crate::review::HOSTED_LLM_REVIEW_TIMEOUT_SECS, 420);
        assert_eq!(
            crate::review::HOSTED_LLM_REVIEW_TIMEOUT_SECS
                - crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS
                - TIMEOUT_RETRY_CAP_SECS,
            90
        );
        assert_eq!(
            crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS
                - crate::review::HOSTED_LLM_REVIEW_TIMEOUT_SECS,
            crate::review::SCORER_TIMEOUT_SECS
        );
        assert_eq!(
            Duration::from_secs(600) - timeouts.total.unwrap(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn from_env_charges_elapsed_time_against_supplied_budget_start() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[REQUEST_TIMEOUT_ENV, TOTAL_TIMEOUT_ENV, "POSTIL_API_KEY"]);
        EnvRestore::remove(REQUEST_TIMEOUT_ENV);
        EnvRestore::remove(TOTAL_TIMEOUT_ENV);
        EnvRestore::set("POSTIL_API_KEY", "test-key");

        let elapsed = Duration::from_secs(10);
        let started_at = Instant::now() - elapsed;
        let client = LlmClient::from_env_for_remote_review(
            &Config::default(),
            started_at,
            Duration::from_secs(crate::review::HOSTED_LLM_REQUEST_TIMEOUT_SECS),
            Duration::from_secs(crate::review::HOSTED_LLM_REVIEW_TIMEOUT_SECS),
            Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS),
        )
        .unwrap();
        let remaining = client.remaining_budget(LlmPhase::Total).unwrap().unwrap();

        assert!(
            remaining
                <= Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS) - elapsed
        );
        assert!(
            remaining
                > Duration::from_secs(crate::review::HOSTED_LLM_TOTAL_TIMEOUT_SECS)
                    - elapsed
                    - Duration::from_secs(5)
        );
    }

    #[test]
    fn extracts_json_from_fenced_output() {
        let text = "Here you go:\n```json\n{\"summary\": \"s\", \"findings\": []}\n```";
        let raw = parse_review(text).unwrap();
        assert_eq!(raw.summary, "s");
    }

    #[test]
    fn extracts_json_with_nested_braces_and_strings() {
        let text = r#"{"summary": "has } brace and \" quote", "findings": []} trailing"#;
        let raw = parse_review(text).unwrap();
        assert!(raw.summary.contains("} brace"));
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_review("I could not review this.").is_err());
    }

    #[test]
    fn scorer_scores_use_array_order_and_validate_kind() {
        let scores = parse_scores(
            r#"[{"confidence":0.8,"kind":"humanEscalation","reason":"This needs an owner decision."},{"confidence":0.6,"kind":"risk","reason":"This follows the second input."}]"#,
            2,
        )
        .unwrap();
        assert_eq!(scores[0].index, 0);
        assert_eq!(scores[0].confidence, 0.8);
        assert_eq!(scores[0].kind, Kind::HumanEscalation);
        assert_eq!(scores[1].index, 1);
        assert_eq!(scores[1].confidence, 0.6);
        assert_eq!(scores[1].kind, Kind::Risk);
    }

    #[test]
    fn scorer_rejects_unknown_fields_and_invalid_confidence() {
        let unknown = parse_scores(
            r#"[{"index":0,"confidence":0.8,"kind":"risk","reason":"This field is not admitted."}]"#,
            1,
        )
        .unwrap_err();
        assert!(unknown.contains("unknown field `index`"));

        for confidence in ["-1", "5", "1e999", "\"NaN\""] {
            let input = format!(
                r#"[{{"confidence":{confidence},"kind":"risk","reason":"This confidence is invalid."}}]"#
            );
            assert!(
                parse_scores(&input, 1).is_err(),
                "accepted malformed confidence {confidence}"
            );
        }
    }

    #[test]
    fn scorer_rejects_severity_label_as_kind() {
        let error = parse_scores(
            r#"[{"confidence":0.7,"kind":"warn","reason":"The response used the wrong field."}]"#,
            1,
        )
        .unwrap_err();
        assert!(error.contains("invalid score kind"));
    }

    #[test]
    fn scorer_rejects_missing_entries() {
        assert!(
            parse_scores(
                r#"[{"confidence":0.5,"kind":"risk","reason":"Only one score is present."}]"#,
                2
            )
            .is_err()
        );
    }

    #[test]
    fn scorer_repair_prompt_states_the_exact_reason_limits() {
        let prompt = scorer_repair_system("base scorer contract");
        assert!(prompt.contains(&format!(
            "at most {SCORER_REASON_PROMPT_MAX_BYTES} UTF-8 bytes"
        )));
    }

    #[test]
    fn scorer_rejects_incomplete_and_overlength_reasons() {
        let incomplete = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"This has no sentence terminator"}]"#,
            1,
        )
        .unwrap_err();
        assert!(incomplete.contains("sentence punctuation"));

        let overlength = serde_json::json!([{
            "confidence": 0.7,
            "kind": "risk",
            "reason": format!("{}.", "x".repeat(SCORER_REASON_MAX_BYTES)),
        }]);
        let error = parse_scores(&overlength.to_string(), 1).unwrap_err();
        assert!(error.contains("exceeds 240 UTF-8 bytes"));

        for reason in [
            " Leading whitespace is invalid.",
            "Trailing whitespace is invalid. ",
            "A tab\tis invalid.",
            "A line\u{2028}separator is invalid.",
        ] {
            let input = serde_json::json!([{
                "confidence": 0.7,
                "kind": "risk",
                "reason": reason,
            }]);
            assert!(
                parse_scores(&input.to_string(), 1).is_err(),
                "accepted malformed reason {reason:?}"
            );
        }
    }

    #[test]
    fn scorer_reason_limits_match_json_schema_unicode_length() {
        let reason = format!("{}.", "x".repeat(SCORER_REASON_MAX_BYTES - 1));
        let input = serde_json::json!([{
            "confidence": 0.7,
            "kind": "risk",
            "reason": reason,
        }]);
        let scores = parse_scores(&input.to_string(), 1).unwrap();
        assert_eq!(scores[0].reason.len(), SCORER_REASON_MAX_BYTES);

        let multibyte = format!("{}。", "界".repeat((SCORER_REASON_MAX_BYTES / 3) - 1));
        let input = serde_json::json!([{
            "confidence": 0.7,
            "kind": "risk",
            "reason": multibyte,
        }]);
        let scores = parse_scores(&input.to_string(), 1).unwrap();
        assert_eq!(scores[0].reason.len(), SCORER_REASON_MAX_BYTES);
    }

    #[test]
    fn scorer_reason_accepts_bounded_single_line_text() {
        let scores = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"The U.S. retry path is not idempotent, e.g. on timeout."}]"#,
            1,
        )
        .unwrap();
        assert_eq!(scores.len(), 1);

        let multiple_sentences = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"The first condition fails. The second condition also fails."}]"#,
            1,
        )
        .unwrap();
        assert_eq!(multiple_sentences.len(), 1);

        let natural_long_reason =
            "The authorization check is bypassed when the cached administrator flag is stale.";
        assert!(natural_long_reason.chars().count() > 60);
        let input = serde_json::json!([{
            "confidence": 0.7,
            "kind": "risk",
            "reason": natural_long_reason,
        }]);
        assert_eq!(parse_scores(&input.to_string(), 1).unwrap().len(), 1);

        let lowercase = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"The first condition fails. the second condition also fails."}]"#,
            1,
        )
        .unwrap();
        assert_eq!(lowercase.len(), 1);

        let no_space = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"The first condition fails.The second condition also fails."}]"#,
            1,
        )
        .unwrap();
        assert_eq!(no_space.len(), 1);

        let file_and_version = parse_scores(
            r#"[{"confidence":0.7,"kind":"risk","reason":"The src/lib.rs behavior changed in version 4.2."}]"#,
            1,
        )
        .unwrap();
        assert_eq!(file_and_version.len(), 1);
    }

    #[test]
    fn provider_retry_after_parses_delta_seconds_and_caps_local_waits() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(retry_after_duration(&headers), Some(Duration::ZERO));

        headers.insert(reqwest::header::RETRY_AFTER, HeaderValue::from_static("12"));
        assert_eq!(
            retry_after_duration(&headers),
            Some(Duration::from_secs(12))
        );

        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_static("999"),
        );
        assert_eq!(
            retry_after_duration(&headers),
            Some(Duration::from_secs(PROVIDER_RETRY_DELAY_CAP_SECS))
        );
    }

    #[test]
    fn provider_retry_after_parses_http_dates_relative_to_the_client_clock() {
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(now + Duration::from_secs(12))).unwrap(),
        );
        assert_eq!(
            retry_after_duration_at(&headers, now),
            Some(Duration::from_secs(12))
        );

        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(now)).unwrap(),
        );
        assert_eq!(retry_after_duration_at(&headers, now), Some(Duration::ZERO));

        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(now - Duration::from_secs(1))).unwrap(),
        );
        assert_eq!(retry_after_duration_at(&headers, now), Some(Duration::ZERO));

        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(
                now + Duration::from_secs(PROVIDER_RETRY_DELAY_CAP_SECS),
            ))
            .unwrap(),
        );
        assert_eq!(
            retry_after_duration_at(&headers, now),
            Some(Duration::from_secs(PROVIDER_RETRY_DELAY_CAP_SECS))
        );

        headers.insert(
            reqwest::header::RETRY_AFTER,
            HeaderValue::from_static("not a delay or HTTP date"),
        );
        assert_eq!(retry_after_duration_at(&headers, now), None);
    }

    #[test]
    fn response_metadata_logs_only_safe_identifiers_or_presence() {
        let summary = safe_response_summary(
            r#"{"id":"secret\nvalue","model":"safe/model-v1","provider":"private key=value","choices":[{"finish_reason":"stop\tsecret"}],"error":{"metadata":{"error_type":"bad bearer token"}}}"#,
            ApiFormat::OpenaiCompatible,
            false,
        );
        assert_eq!(summary.response_id.as_deref(), Some("present"));
        assert_eq!(summary.returned_model.as_deref(), Some("present"));
        assert_eq!(summary.provider.as_deref(), Some("present"));
        assert_eq!(summary.finish_reason.as_deref(), Some("reported"));
        assert_eq!(summary.error_type.as_deref(), Some("reported"));

        let exhausted = safe_response_summary(
            r#"{"choices":[{"finish_reason":"length"}],"usage":{"completion_tokens_details":{"reasoning_tokens":8000}}}"#,
            ApiFormat::OpenaiCompatible,
            false,
        );
        assert_eq!(exhausted.finish_reason.as_deref(), Some("length"));
        assert_eq!(exhausted.reasoning_tokens, Some(8_000));

        let public_summary = safe_response_summary(
            r#"{"id":"response-1","model":"safe/model-v1","provider":"provider-1"}"#,
            ApiFormat::OpenaiCompatible,
            true,
        );
        assert!(
            public_summary
                .response_id
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            public_summary
                .returned_model
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_ne!(public_summary.response_id.as_deref(), Some("response-1"));

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_static("token-shaped-secret"),
        );
        assert_eq!(safe_request_id(&headers, false).as_deref(), Some("present"));
        assert!(
            safe_request_id(&headers, true)
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn openrouter_403_detail_redacts_response_key_management_url() {
        let key_url = "https://openrouter.ai/settings/keys/key-management-identifier";
        let body = format!(
            r#"{{"error":{{"message":"Manage this key at {key_url}","metadata":{{"error_type":"{key_url}"}}}}}}"#
        );
        let summary = safe_response_summary(&body, ApiFormat::OpenaiCompatible, true);
        let detail = provider_http_status_detail(
            reqwest::StatusCode::FORBIDDEN,
            &summary,
            Some("request-safe-1"),
        );

        assert_eq!(summary.error_type.as_deref(), Some("reported"));
        assert!(detail.contains("403 Forbidden"));
        assert!(detail.contains("category reported"));
        assert!(detail.contains("request id request-safe-1"));
        assert!(!detail.contains(key_url));
        assert!(!detail.contains("key-management-identifier"));
    }

    #[test]
    fn successful_response_requires_positive_input_and_output_usage() {
        assert_eq!(successful_response_usage_issue(None), Some("missing"));
        for usage in [
            Usage::default(),
            Usage {
                prompt_tokens: 1,
                completion_tokens: 0,
                ..Default::default()
            },
            Usage {
                prompt_tokens: 0,
                completion_tokens: 1,
                ..Default::default()
            },
        ] {
            assert_eq!(
                successful_response_usage_issue(Some(usage)),
                Some("nonpositive")
            );
        }
        assert_eq!(
            successful_response_usage_issue(Some(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                ..Default::default()
            })),
            None
        );
    }

    #[test]
    fn scorer_prompt_omits_generator_kind_and_confidence_fields() {
        let prompt = crate::prompt::scorer_user_prompt(&[crate::prompt::ScorerPromptFinding {
            index: 0,
            path: "src/a.rs".into(),
            line: 1,
            severity: "warn".into(),
            title: "t".into(),
            body: "b".into(),
            diff_hunk: "h".into(),
        }]);
        assert!(prompt.contains("\"severity\": \"warn\""));
        assert!(!prompt.contains("\"kind\":"));
        assert!(!prompt.contains("\"confidence\":"));
    }

    #[test]
    fn into_review_keeps_unknown_severity_as_warn() {
        // Fail toward surfacing: a severity label outside the alias table
        // ("major"/"P0"/"moderate") must NOT drop the finding. It is retained
        // and defaulted to Warn so grounding and the gate still see it.
        for label in ["major", "P0", "moderate"] {
            let raw = RawReview {
                summary: String::new(),
                findings: vec![RawFinding {
                    path: "src/a.rs".into(),
                    line: 7,
                    end_line: None,
                    severity: label.into(),
                    kind: None,
                    confidence: 0.9,
                    title: "real issue".into(),
                    body: "still grounded".into(),
                    evidence: None,
                }],
            };
            let r = into_review(raw, "m", Usage::default());
            assert_eq!(r.findings.len(), 1, "finding dropped for label {label:?}");
            assert_eq!(r.findings[0].severity, Severity::Warn);
            assert_eq!(r.findings[0].line, 7);
            assert_eq!(r.findings[0].title, "real issue");
        }
    }

    #[test]
    fn into_review_normalizes() {
        let raw = RawReview {
            summary: " s ".into(),
            findings: vec![RawFinding {
                path: "./src/a.rs".into(),
                line: 5,
                end_line: Some(3), // invalid: before start, dropped
                severity: "CRITICAL".into(),
                kind: Some("human_escalation".into()),
                confidence: 1.7,
                title: "".into(),
                body: "a body".into(),
                evidence: None,
            }],
        };
        let r = into_review(raw, "m", Usage::default());
        let f = &r.findings[0];
        assert_eq!(f.path, "src/a.rs");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.kind, Kind::HumanEscalation);
        assert_eq!(f.confidence, 1.0);
        assert_eq!(f.end_line, None);
        assert_eq!(f.title, "");
    }

    #[test]
    fn into_review_parses_content_policy_kind() {
        let raw = RawReview {
            summary: String::new(),
            findings: vec![RawFinding {
                path: "README.md".into(),
                line: 3,
                end_line: None,
                severity: "info".into(),
                kind: Some("contentPolicy".into()),
                confidence: 0.8,
                title: "Stale temporal residue".into(),
                body: "b".into(),
                evidence: None,
            }],
        };
        let r = into_review(raw, "m", Usage::default());
        assert_eq!(r.findings[0].kind, Kind::ContentPolicy);
    }

    #[test]
    fn into_review_preserves_finding_prose_for_contract_validation() {
        let raw = RawReview {
            summary: String::new(),
            findings: vec![RawFinding {
                path: "src/a.rs".into(),
                line: 3,
                end_line: None,
                severity: "warn".into(),
                kind: Some("risk".into()),
                confidence: 0.8,
                title: "@octocat <img> **unsafe**".into(),
                body: format!(
                    "# Summary\n@octocat <details>hidden</details> ![pixel](https://bad.test/x)\n{}",
                    "line\n".repeat(30),
                ),
                evidence: None,
            }],
        };

        let review = into_review(raw, "m", Usage::default());
        let finding = &review.findings[0];
        assert_eq!(finding.title, "@octocat <img> **unsafe**");
        assert!(finding.body.contains("@octocat <details>"));
    }

    fn mk(model: &str, path: &str, line: u32, conf: f64) -> ModelReview {
        ModelReview {
            summary: format!("{model} summary"),
            findings: vec![Finding {
                path: path.into(),
                line,
                end_line: None,
                severity: Severity::Warn,
                kind: Kind::Risk,
                confidence: conf,
                generator_confidence: None,
                scorer_confidence: None,
                generator_kind: None,
                scorer_kind: None,
                scorer_reason: None,
                title: "t".into(),
                body: "b".into(),
                evidence: None,
                id: None,
            }],
            model_used: model.into(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                ..Default::default()
            },
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
        }
    }

    #[test]
    fn consensus_keeps_agreement_drops_solo() {
        let a = mk("a", "x.rs", 10, 0.6);
        let mut b = mk("b", "x.rs", 12, 0.9);
        b.findings.push(Finding {
            path: "solo.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.99,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "solo".into(),
            body: "b".into(),
            evidence: None,
            id: None,
        });
        let merged = consensus_merge(vec![a, b]);
        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0].confidence, 0.9);
        assert_eq!(merged.usage.prompt_tokens, 20);
        assert!(merged.model_used.starts_with("consensus("));
    }

    #[test]
    fn consensus_keeps_secondary_agreement_missed_by_primary() {
        // Models b and c agree on y.rs:30; the primary never saw it. Symmetric
        // agreement must keep it, anchored on b's wording.
        let a = mk("a", "x.rs", 10, 0.6);
        let b = mk("b", "y.rs", 30, 0.7);
        let c = mk("c", "y.rs", 33, 0.8);
        let merged = consensus_merge(vec![a, b, c]);
        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0].path, "y.rs");
        assert_eq!(merged.findings[0].line, 30);
        assert_eq!(merged.findings[0].confidence, 0.8);
    }

    #[test]
    fn consensus_same_model_twice_is_not_agreement() {
        // Two nearby findings from one run must not corroborate each other.
        let a = mk("a", "x.rs", 10, 0.6);
        let mut b = mk("b", "y.rs", 30, 0.7);
        b.findings.push(Finding {
            path: "y.rs".into(),
            line: 32,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "t2".into(),
            body: "b2".into(),
            evidence: None,
            id: None,
        });
        let merged = consensus_merge(vec![a, b]);
        assert!(merged.findings.is_empty());
    }

    #[test]
    fn hosted_consensus_rejects_every_degraded_subset() {
        assert!(consensus_is_incomplete(true, 1, 3));
        assert!(consensus_is_incomplete(true, 2, 3));
        assert!(!consensus_is_incomplete(true, 3, 3));
        assert!(!consensus_is_incomplete(false, 1, 3));
    }

    #[test]
    fn hosted_openrouter_request_denies_collection_and_requires_zdr() {
        let mut body = json!({"model": "provider/model"});
        apply_openrouter_privacy(&mut body, true);
        assert_eq!(body["provider"]["data_collection"], "deny");
        assert_eq!(body["provider"]["zdr"], true);

        let mut byok = json!({"model": "provider/model"});
        apply_openrouter_privacy(&mut byok, false);
        assert!(byok.get("provider").is_none());
    }

    #[test]
    fn canonical_openrouter_scorer_uses_no_reasoning_effort_and_requires_strict_schema() {
        let client = LlmClient::build(
            &Config::default(),
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let scorer = client.request_body(
            "provider/scorer",
            "system",
            "user",
            400,
            0.0,
            LlmPhase::Scorer { expected_len: 1 },
        );
        assert_eq!(
            scorer["reasoning"],
            json!({"effort": "none", "exclude": true})
        );
        assert!(scorer["reasoning"].get("enabled").is_none());
        assert_eq!(scorer["provider"]["require_parameters"], true);
        assert_eq!(scorer["response_format"]["type"], "json_schema");
        assert_eq!(scorer["response_format"]["json_schema"]["strict"], true);
        assert_eq!(
            scorer["response_format"]["json_schema"]["schema"]["items"]["additionalProperties"],
            false
        );
        let schema = &scorer["response_format"]["json_schema"]["schema"];
        assert_eq!(schema["minItems"], 1);
        assert_eq!(schema["maxItems"], 1);
        assert!(schema["items"]["properties"].get("index").is_none());
        assert_eq!(
            schema["items"]["required"],
            json!(["confidence", "kind", "reason"])
        );
        assert_eq!(schema["items"]["properties"]["reason"]["minLength"], 1);
        assert_eq!(
            schema["items"]["properties"]["reason"]["maxLength"],
            SCORER_REASON_SCHEMA_MAX_CHARS
        );
        assert_eq!(
            schema["items"]["properties"]["reason"]["pattern"],
            SCORER_REASON_JSON_PATTERN
        );

        let multiple = client.request_body(
            "provider/scorer",
            "system",
            "user",
            400,
            0.0,
            LlmPhase::Scorer { expected_len: 7 },
        );
        let multiple_schema = &multiple["response_format"]["json_schema"]["schema"];
        assert_eq!(multiple_schema["minItems"], 7);
        assert_eq!(multiple_schema["maxItems"], 7);
        assert!(
            multiple_schema["items"]["properties"]
                .get("index")
                .is_none()
        );

        let generator = client.request_body(
            "provider/generator",
            "system",
            "user",
            REVIEW_MAX_TOKENS,
            0.1,
            LlmPhase::Review,
        );
        assert!(generator.get("reasoning").is_none());
        assert!(generator.get("response_format").is_none());
        assert!(generator["provider"].get("require_parameters").is_none());
    }

    #[test]
    fn hosted_openrouter_request_pins_the_admitted_price_ceiling() {
        let mut body = json!({"model": "provider/model"});
        apply_openrouter_privacy(&mut body, true);
        apply_openrouter_price_ceiling(
            &mut body,
            &ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 435_000,
                output_micros_per_million_tokens: 870_000,
            },
        );
        assert_eq!(
            body["provider"],
            json!({
                "data_collection": "deny",
                "zdr": true,
                "max_price": { "prompt": 0.435, "completion": 0.87 },
            })
        );
    }

    #[test]
    fn pinned_routes_require_the_exact_returned_model_and_provider() {
        let valid = (
            Some("provider/model".to_string()),
            Some("Fireworks".to_string()),
        );
        validate_routed_response_identity(Some(&valid), "provider/model", "Fireworks").unwrap();

        let missing =
            validate_routed_response_identity(None, "provider/model", "Fireworks").unwrap_err();
        assert!(
            missing
                .downcast_ref::<AtomicAttributionIdentityFailure>()
                .is_some_and(|failure| matches!(
                    failure,
                    AtomicAttributionIdentityFailure::Missing
                ))
        );

        let wrong_provider = (
            Some("provider/model".to_string()),
            Some("AnotherProvider".to_string()),
        );
        let mismatch =
            validate_routed_response_identity(Some(&wrong_provider), "provider/model", "Fireworks")
                .unwrap_err();
        assert!(
            mismatch
                .downcast_ref::<AtomicAttributionIdentityFailure>()
                .is_some_and(|failure| {
                    matches!(failure, AtomicAttributionIdentityFailure::Mismatch)
                })
        );
    }

    #[test]
    fn benchmark_screening_enforces_the_exact_provisional_provider_contract() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&[
            "POSTIL_HOSTED_MODE",
            "POSTIL_QUALIFICATION_CANDIDATE_PROFILE",
            "POSTIL_BENCH_SCREEN_PROFILE",
            "POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY",
        ]);
        EnvRestore::remove("POSTIL_HOSTED_MODE");
        EnvRestore::remove("POSTIL_QUALIFICATION_CANDIDATE_PROFILE");
        let directory = tempfile::tempdir().unwrap();
        let profile_path = directory.path().join("screen-profile.json");
        std::fs::write(&profile_path, include_str!("../provisional-models.json")).unwrap();
        EnvRestore::set(
            "POSTIL_BENCH_SCREEN_PROFILE",
            profile_path.to_str().unwrap(),
        );
        EnvRestore::set("POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY", "1");

        let config = Config {
            model: "z-ai/glm-5.2".into(),
            cascade: Vec::new(),
            consensus: 1,
            scorer_enabled: false,
            scorer: String::new(),
            scorer_fallback: String::new(),
            api_base: "https://openrouter.ai:443/api/v1".into(),
            api_format: ApiFormat::OpenaiCompatible,
            ..Config::default()
        };
        config.require_model().unwrap();
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let body =
            client.request_body("z-ai/glm-5.2", "system", "user", 100, 0.0, LlmPhase::Review);
        assert_eq!(body["provider"]["order"], json!(["Fireworks"]));
        assert_eq!(body["provider"]["allow_fallbacks"], false);
        assert_eq!(body["provider"]["data_collection"], "deny");
        assert_eq!(body["provider"]["zdr"], true);
        assert_eq!(
            body["provider"]["max_price"],
            json!({ "prompt": 1.4, "completion": 4.4 })
        );

        let drifted = Config {
            model: "another/model".into(),
            ..config
        };
        let error = LlmClient::build(
            &drifted,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .err()
        .expect("profile drift must fail");
        assert!(error.to_string().contains("does not exactly match"));
    }

    #[cfg(feature = "qualification-candidate")]
    #[test]
    fn qualification_route_is_pinned_for_generator_scorer_repair_and_attribution_requests() {
        let mut client = LlmClient::build(
            &Config::default(),
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.pinned_upstream_provider = Some("PinnedProvider".into());
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([(
            "provider/model".into(),
            ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 435_000,
                output_micros_per_million_tokens: 870_000,
            },
        )])));
        for phase in [
            LlmPhase::Review,
            LlmPhase::Scorer { expected_len: 1 },
            LlmPhase::Attribution,
        ] {
            let body = client.request_body_with_provider(
                "provider/model",
                "system",
                "user",
                180,
                0.0,
                phase,
                matches!(phase, LlmPhase::Attribution).then_some("PinnedProvider"),
            );
            assert_eq!(body["provider"]["order"], json!(["PinnedProvider"]));
            assert_eq!(body["provider"]["allow_fallbacks"], false);
            assert_eq!(
                body["provider"]["max_price"],
                json!({ "prompt": 0.435, "completion": 0.87 })
            );
        }
    }

    #[test]
    fn byok_openai_and_direct_anthropic_request_bodies_have_no_hosted_routing_fields() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvRestore::capture(&["POSTIL_HOSTED_MODE"]);
        EnvRestore::remove("POSTIL_HOSTED_MODE");

        let openai = LlmClient::build(
            &Config {
                model: "provider/model".into(),
                api_base: "https://models.example.test/v1".into(),
                ..Config::default()
            },
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let openai_body = openai.request_body(
            "provider/model",
            "system",
            "user",
            100,
            0.0,
            LlmPhase::Scorer { expected_len: 1 },
        );
        assert!(openai_body.get("provider").is_none());
        assert!(openai_body.get("reasoning").is_none());
        assert!(openai_body.get("response_format").is_none());

        let anthropic = LlmClient::build(
            &Config {
                model: "provider/model".into(),
                api_format: ApiFormat::Anthropic,
                api_base: "https://api.anthropic.com/v1".into(),
                ..Config::default()
            },
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let anthropic_body = anthropic.request_body(
            "provider/model",
            "system",
            "user",
            100,
            0.0,
            LlmPhase::Scorer { expected_len: 1 },
        );
        assert!(anthropic_body.get("provider").is_none());
        assert!(anthropic_body.get("reasoning").is_none());
        assert!(anthropic_body.get("response_format").is_none());
        assert_eq!(anthropic_body["system"], "system");
    }

    #[test]
    fn hosted_projected_and_reported_costs_cannot_cross_the_service_reservation() {
        let config = Config {
            model: "provider/model".into(),
            ..Config::default()
        };
        let mut client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        client.hosted_price_bounds = Some(Arc::new(HashMap::from([(
            "provider/model".into(),
            ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 1,
                output_micros_per_million_tokens: 100_000_000,
            },
        )])));
        let body = json!({"model": "provider/model", "max_tokens": 6_000});
        client.reserve_provider_attempt(&body).unwrap();
        let error = client.reserve_provider_attempt(&body).unwrap_err();
        assert!(error.to_string().contains("hosted operation cap"));
        assert_eq!(
            client
                .admission
                .lock()
                .unwrap()
                .projected_cost_exposure_micros,
            600_001
        );

        let error = client
            .record_reported_usage(Usage {
                provider_cost: ProviderCost::parse("1.000001"),
                ..Usage::default()
            })
            .unwrap_err();
        assert!(error.to_string().contains("1000000 micro-dollar hard cap"));
    }

    #[test]
    fn projected_price_uses_bytes_as_a_conservative_input_token_bound() {
        let projected = projected_request_cost_micros(
            1_000_001,
            8_000,
            &ModelPriceBound {
                model: "provider/model".into(),
                input_micros_per_million_tokens: 100_000,
                output_micros_per_million_tokens: 1_000_000,
            },
        )
        .unwrap();
        assert_eq!(projected, 108_001);
    }

    #[cfg(feature = "qualification-candidate")]
    #[test]
    fn atomic_attribution_provider_request_bound_is_exact() {
        let empty = json!({"payload": ""});
        let overhead = serde_json::to_vec(&empty).unwrap().len();
        let accepted = json!({
            "payload": "x".repeat(crate::attribution::MAX_PROVIDER_REQUEST_BYTES - overhead),
        });
        assert_eq!(
            serde_json::to_vec(&accepted).unwrap().len(),
            crate::attribution::MAX_PROVIDER_REQUEST_BYTES,
        );
        LlmClient::ensure_atomic_attribution_request_size(&accepted).unwrap();

        let rejected = json!({
            "payload": "x".repeat(crate::attribution::MAX_PROVIDER_REQUEST_BYTES - overhead + 1),
        });
        let error = LlmClient::ensure_atomic_attribution_request_size(&rejected).unwrap_err();
        assert!(
            error
                .downcast_ref::<AtomicAttributionRequestTooLarge>()
                .is_some()
        );
    }

    fn provider_request_with_exact_serialized_size(target: usize) -> serde_json::Value {
        let empty = json!({
            "model": "provider/model",
            "max_tokens": 1,
            "payload": ""
        });
        let overhead = serde_json::to_vec(&empty).unwrap().len();
        assert!(target >= overhead);
        let remaining = target - overhead;
        let quote_count = remaining / 2;
        let plain_count = remaining % 2;
        let mut payload = "\"".repeat(quote_count);
        payload.push_str(&"x".repeat(plain_count));
        let body = json!({
            "model": "provider/model",
            "max_tokens": 1,
            "payload": payload
        });
        assert_eq!(serde_json::to_vec(&body).unwrap().len(), target);
        body
    }

    #[test]
    fn provider_request_bound_counts_exact_json_escaping_at_n_and_n_plus_one() {
        let accepted = provider_request_with_exact_serialized_size(MAX_PROVIDER_REQUEST_BYTES);
        assert_eq!(
            serialized_provider_request_bytes(&accepted, "test request").unwrap(),
            MAX_PROVIDER_REQUEST_BYTES
        );

        let rejected = provider_request_with_exact_serialized_size(MAX_PROVIDER_REQUEST_BYTES + 1);
        let error = serialized_provider_request_bytes(&rejected, "test request").unwrap_err();
        assert!(error.to_string().contains("per-request cap"));
        assert!(
            error
                .to_string()
                .contains(&(MAX_PROVIDER_REQUEST_BYTES + 1).to_string())
        );
    }

    #[test]
    fn openai_length_finish_reason_rejects_complete_looking_partial_content() {
        let config = Config {
            api_base: "http://127.0.0.1:1".into(),
            api_format: ApiFormat::OpenaiCompatible,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        for (body, expected) in [
            (
                r#"{"choices":[{"finish_reason":"length","message":{"content":"{\"summary\":\"\",\"findings\":[]}"}}]}"#,
                "length",
            ),
            (
                r#"{"choices":[{"message":{"content":"{\"summary\":\"\",\"findings\":[]}"}}]}"#,
                "missing finish_reason",
            ),
        ] {
            let error = client
                .parse_response(body, &mut Usage::default())
                .unwrap_err();
            let partial = error.downcast_ref::<ModelContentFailure>().unwrap();
            assert_eq!(partial.nonterminal_reason(), Some(expected));
        }
    }

    #[test]
    fn anthropic_max_tokens_stop_reason_rejects_complete_looking_partial_content() {
        let config = Config {
            api_base: "http://127.0.0.1:1".into(),
            api_format: ApiFormat::Anthropic,
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        for (body, expected) in [
            (
                r#"{"stop_reason":"max_tokens","content":[{"type":"text","text":"{\"summary\":\"\",\"findings\":[]}"}]}"#,
                "max_tokens",
            ),
            (
                r#"{"content":[{"type":"text","text":"{\"summary\":\"\",\"findings\":[]}"}]}"#,
                "missing stop_reason",
            ),
        ] {
            let error = client
                .parse_response(body, &mut Usage::default())
                .unwrap_err();
            let partial = error.downcast_ref::<ModelContentFailure>().unwrap();
            assert_eq!(partial.nonterminal_reason(), Some(expected));
        }
    }

    #[tokio::test]
    async fn oversized_provider_request_is_rejected_before_network_contact() {
        let server = MockServer::start().await;
        let config = Config {
            api_base: server.uri(),
            model: "provider/model".into(),
            ..Config::default()
        };
        let client = LlmClient::build(
            &config,
            "test-key".into(),
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        let oversized = provider_request_with_exact_serialized_size(MAX_PROVIDER_REQUEST_BYTES + 1);
        let error = match client.request_once(&oversized).await {
            Ok(_) => panic!("oversized request reached the provider transport"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("per-request cap"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn scorer_budget_matches_the_qualified_finding_bound() {
        assert_eq!(scorer_max_tokens(0), Some(256));
        assert_eq!(scorer_max_tokens(1), Some(400));
        assert_eq!(scorer_max_tokens(20), Some(3_136));
        assert_eq!(scorer_max_tokens(21), None);
        assert_eq!(scorer_max_tokens(usize::MAX), None);
    }
}
