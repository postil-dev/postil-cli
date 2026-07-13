//! OpenAI-compatible and native Anthropic chat client with model cascade, one JSON-repair retry,
//! optional multi-model consensus, and fail-closed semantics.
//!
//! OpenAI-compatible endpoints use `POST {base}/chat/completions` by default.
//! Native Anthropic endpoints use `POST {base}/messages` when explicitly selected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;

use crate::api_key;
use crate::config::{ApiFormat, Config};
use crate::envelope::{
    Finding, Kind, ModelIncident, ModelIncidentCategory, ModelIncidentPhase, ModelIncidentRecovery,
    ModelUsage, Usage,
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
    }

    fn is_timeout(&self) -> bool {
        self.error.chain().any(|cause| {
            cause
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
                || cause.downcast_ref::<RequestTimedOut>().is_some()
                || cause.downcast_ref::<DeadlineExceeded>().is_some()
        })
    }

    fn is_deadline_exceeded(&self) -> bool {
        self.error.downcast_ref::<DeadlineExceeded>().is_some()
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

fn add_usage(total: &mut Usage, usage: Usage) {
    total.prompt_tokens += usage.prompt_tokens;
    total.completion_tokens += usage.completion_tokens;
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
}

#[derive(Debug, Deserialize)]
struct RawScore {
    index: usize,
    confidence: f64,
    kind: String,
    #[serde(default)]
    reason: String,
}

fn default_confidence() -> f64 {
    0.5
}

#[derive(Clone)]
pub struct LlmClient {
    http: Arc<Mutex<Option<reqwest::Client>>>,
    api_base: String,
    api_key: String,
    api_format: ApiFormat,
    endpoint_auth: Option<EndpointAuth>,
    request_timeout: Duration,
    timeout_retry_timeout: Duration,
    review_deadline: Option<Instant>,
    total_deadline: Option<Instant>,
}

#[derive(Clone)]
struct EndpointAuth {
    name: HeaderName,
    value: HeaderValue,
    secret: String,
}

#[derive(Debug, Clone, Copy)]
struct LlmTimeouts {
    request: Duration,
    total: Option<Duration>,
}

/// Retries per model on transient provider errors before the cascade moves on.
const TRANSIENT_RETRIES: u32 = 2;
/// A fresh request can recover when the caller's request timeout, rather than
/// the provider's response, ended an otherwise viable routed completion. The
/// shared total deadline remains authoritative, so this cannot extend a hosted
/// review beyond its worker budget.
const TIMEOUT_RETRIES: u32 = 1;
const TIMEOUT_RETRY_CAP_SECS: u64 = 90;

/// Runaway-generation bound only. It is sized so legitimate reviews (observed
/// up to roughly 12k output tokens) do not truncate. A truncated response goes
/// through JSON repair and can salvage low-quality findings. Interactive answers
/// use their provider default.
const REVIEW_MAX_TOKENS: u32 = 16384;
const SCORER_MAX_TOKENS: u32 = 4096;
const ANTHROPIC_DEFAULT_MAX_TOKENS: u32 = 4096;
const RESPOND_MAX_TOKENS: u32 = 4096;
const ANTHROPIC_VERSION: &str = "2023-06-01";
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 480;
const REQUEST_TIMEOUT_ENV: &str = "POSTIL_LLM_REQUEST_TIMEOUT_SECS";
const TOTAL_TIMEOUT_ENV: &str = "POSTIL_LLM_TOTAL_TIMEOUT_SECS";
const ENDPOINT_AUTH_HEADER_ENV: &str = "POSTIL_ENDPOINT_AUTH_HEADER";
const ENDPOINT_AUTH_VALUE_ENV: &str = "POSTIL_ENDPOINT_AUTH_VALUE";
const ALLOW_PRIVATE_API_BASE_ENV: &str = "POSTIL_ALLOW_PRIVATE_API_BASE";
const ALWAYS_MANAGED_HEADERS: &[&str] = &["x-api-key", "anthropic-version", "content-type"];

/// Marker context attached to transport/provider-level failures (endpoint
/// unreachable, HTTP error status, timeout, malformed HTTP envelope) — the
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

fn timeout_status(status: u16) -> bool {
    matches!(status, 408 | 504)
}

fn reqwest_error(error: &anyhow::Error) -> Option<&reqwest::Error> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
}

#[derive(Debug, Clone, Copy)]
enum LlmPhase {
    Review,
    Total,
}

#[derive(Debug, Clone, Copy)]
struct DeadlineExceeded(LlmPhase);

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            LlmPhase::Review => f.write_str("LLM review deadline exceeded"),
            LlmPhase::Total => f.write_str("LLM total deadline exceeded"),
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
    pub(crate) async fn doctor_probe(cfg: &Config, api_key: String) -> Result<()> {
        let client = Self::build(cfg, api_key, Duration::from_secs(30), None, None)?;
        let body = client.request_body(&cfg.model, "", "ping", Some(1), 0.0);
        let (status, text) =
            tokio::time::timeout(Duration::from_secs(30), client.request_once(&body))
                .await
                .map_err(|_| RequestTimedOut)??;
        if !status.is_success() {
            return Err(anyhow!(
                "model endpoint returned {status}: {}",
                client.safe_error_snippet(&text)
            ));
        }
        client.parse_response(&text, &mut Usage::default())?;
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
        Ok(LlmClient {
            // The attempt timeout wraps both sending the request and consuming
            // the complete response body, so header and body stalls take the
            // same retry path.
            http: Arc::new(Mutex::new(None)),
            api_base: cfg.api_base.trim_end_matches('/').to_string(),
            api_key,
            api_format: cfg.api_format,
            endpoint_auth,
            request_timeout,
            timeout_retry_timeout: request_timeout.min(Duration::from_secs(TIMEOUT_RETRY_CAP_SECS)),
            review_deadline,
            total_deadline,
        })
    }

    /// Run the review. With `consensus > 1`, the first N models of the chain are
    /// each consulted and only findings two or more models agree on are kept.
    pub async fn review(
        &self,
        cfg: &Config,
        system: &str,
        user: &str,
    ) -> std::result::Result<ModelReview, ModelError> {
        let chain = cfg.model_chain();
        if cfg.consensus > 1 && chain.len() > 1 {
            let n = cfg.consensus.min(chain.len());
            let handles: Vec<_> = chain[..n]
                .iter()
                .map(|m| {
                    let client = self.clone();
                    let (model, system, user) = (m.clone(), system.to_string(), user.to_string());
                    let task_model = model.clone();
                    let handle = tokio::spawn(async move {
                        let model_log = log_text(&task_model);
                        eprintln!("postil: attempting consensus model: {model_log}");
                        let started_at = Instant::now();
                        let result = client.review_with_model(&task_model, &system, &user).await;
                        let elapsed = elapsed_text(started_at.elapsed());
                        match &result {
                            Ok(_) => eprintln!(
                                "postil: consensus model {model_log} responded in {elapsed}"
                            ),
                            Err(error) if error.is_timeout() => eprintln!(
                                "postil: consensus model {model_log} timed out after {elapsed}"
                            ),
                            Err(error) => eprintln!(
                                "postil: consensus model {model_log} failed after {elapsed}: {}",
                                log_text(&format!("{error:#}"))
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
                        if e.model_usage.is_empty()
                            && (e.usage.prompt_tokens > 0 || e.usage.completion_tokens > 0)
                        {
                            e.model_usage.push(ModelUsage {
                                model: model.clone(),
                                prompt_tokens: e.usage.prompt_tokens,
                                completion_tokens: e.usage.completion_tokens,
                            });
                        }
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
                eprintln!("postil: attempting model: {model_log}");
                let started_at = Instant::now();
                match self.review_with_model(model, system, user).await {
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
                        if e.model_usage.is_empty()
                            && (e.usage.prompt_tokens > 0 || e.usage.completion_tokens > 0)
                        {
                            e.model_usage.push(ModelUsage {
                                model: model.clone(),
                                prompt_tokens: e.usage.prompt_tokens,
                                completion_tokens: e.usage.completion_tokens,
                            });
                        }
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
                                "postil: model {model_log} failed after {elapsed}, falling back to next model: {}",
                                log_text(&format!("{e:#}"))
                            );
                        } else {
                            eprintln!(
                                "postil: model {model_log} failed after {elapsed}; no fallback models remain: {}",
                                log_text(&format!("{e:#}"))
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

    /// Free-form answer (no JSON contract). Used by the interactive bot to reply
    /// to a maintainer's question or mention. Tries the model chain in order.
    pub async fn answer(&self, cfg: &Config, system: &str, user: &str) -> Result<Answer> {
        let mut usage = Usage::default();
        let mut models = Vec::new();
        let mut last_err = None;
        let mut usage_accounting_complete = true;
        for model in cfg.model_chain() {
            let mut model_usage = Usage::default();
            let mut model_accounting_complete = true;
            match self
                .chat(
                    &model,
                    system,
                    user,
                    &mut model_usage,
                    &mut model_accounting_complete,
                    Some(RESPOND_MAX_TOKENS),
                    LlmPhase::Total,
                )
                .await
            {
                Ok(content) => {
                    usage_accounting_complete &= model_accounting_complete;
                    add_usage(&mut usage, model_usage);
                    models.push(ModelUsage {
                        model: model.clone(),
                        prompt_tokens: model_usage.prompt_tokens,
                        completion_tokens: model_usage.completion_tokens,
                    });
                    return Ok(Answer {
                        content: content.trim().to_string(),
                        model_used: model,
                        usage,
                        models,
                        usage_accounting_complete,
                    });
                }
                Err(e) => {
                    // Usage parsed from a provider response is complete even
                    // when the response has no usable answer. A transport
                    // failure with no response usage is ambiguous.
                    if !model_accounting_complete
                        || (model_usage.prompt_tokens == 0 && model_usage.completion_tokens == 0)
                    {
                        usage_accounting_complete = false;
                    }
                    eprintln!("postil: model {model} failed: {e:#}");
                    // Provider failures that report no tokens have no billable
                    // usage to attribute. Omit them rather than emitting a
                    // misleading accounting entry; token-bearing failures are
                    // retained and priced by the hosted control plane.
                    if model_usage.prompt_tokens > 0 || model_usage.completion_tokens > 0 {
                        add_usage(&mut usage, model_usage);
                        models.push(ModelUsage {
                            model: model.clone(),
                            prompt_tokens: model_usage.prompt_tokens,
                            completion_tokens: model_usage.completion_tokens,
                        });
                    }
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
    ) -> std::result::Result<ScorerReview, ModelError> {
        let mut failed_usage = Usage::default();
        let mut failed_model_usage = Vec::new();
        let mut failed_incidents: Vec<ModelIncident> = Vec::new();
        let mut usage_accounting_complete = true;
        let mut last_err = None;
        let chain = cfg.scorer_chain();
        for (index, model) in chain.iter().enumerate() {
            let model_log = log_text(model);
            eprintln!("postil: running scorer with {model_log}");
            let started_at = Instant::now();
            match self
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
                    if e.model_usage.is_empty()
                        && (e.usage.prompt_tokens > 0 || e.usage.completion_tokens > 0)
                    {
                        e.model_usage.push(ModelUsage {
                            model: model.clone(),
                            prompt_tokens: e.usage.prompt_tokens,
                            completion_tokens: e.usage.completion_tokens,
                        });
                    }
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
                            "postil: scorer {model_log} failed after {elapsed}, falling back to next scorer: {}",
                            log_text(&format!("{e:#}"))
                        );
                    } else {
                        eprintln!(
                            "postil: scorer {model_log} failed after {elapsed}; no fallback scorers remain: {}",
                            log_text(&format!("{e:#}"))
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

    async fn review_with_model(
        &self,
        model: &str,
        system: &str,
        user: &str,
    ) -> std::result::Result<ModelReview, ModelError> {
        let mut usage = Usage::default();
        let mut usage_accounting_complete = true;
        let mut model_incidents = Vec::new();
        let content = self
            .chat(
                model,
                system,
                user,
                &mut usage,
                &mut usage_accounting_complete,
                Some(REVIEW_MAX_TOKENS),
                LlmPhase::Review,
            )
            .await
            .map_err(|e| {
                let complete = usage_accounting_complete
                    && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                ModelError::new(e, usage, complete)
            })?;
        let raw = match parse_review(&content) {
            Ok(raw) => raw,
            Err(parse_err) => {
                let incident = ModelIncident {
                    phase: ModelIncidentPhase::Review,
                    category: ModelIncidentCategory::InvalidOutput,
                    recovered: false,
                    recovery: None,
                };
                // One repair attempt: ask the same model to fix its own JSON.
                let repair_user = format!(
                    "The following was supposed to be a single valid JSON object matching the \
                     review schema but failed to parse ({parse_err}). Output ONLY the corrected \
                     JSON object, nothing else:\n\n{content}"
                );
                let repaired = match self
                    .chat(
                        model,
                        "You repair malformed JSON. Output only valid JSON.",
                        &repair_user,
                        &mut usage,
                        &mut usage_accounting_complete,
                        Some(REVIEW_MAX_TOKENS),
                        LlmPhase::Review,
                    )
                    .await
                {
                    Ok(repaired) => repaired,
                    Err(error) => {
                        let mut error =
                            ModelError::new(error.context("JSON repair call failed"), usage, false);
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
                    error
                })?;
                model_incidents.push(ModelIncident {
                    recovered: true,
                    recovery: Some(ModelIncidentRecovery::Repair),
                    ..incident
                });
                parsed
            }
        };
        let mut review = into_review(raw, model, usage);
        review.model_incidents.append(&mut model_incidents);
        review.usage_accounting_complete = usage_accounting_complete;

        // Semantic consistency retry: a summary that narrates risk next to an
        // empty findings array is the contract violation behind "clean status,
        // scary prose" reviews. Give the model one chance to either structure
        // the risk or retract it; if the contradiction survives, the caller
        // fails the review closed.
        if review.findings.is_empty() && !review.summary.is_empty() {
            let incident_index = review.model_incidents.len();
            review.model_incidents.push(ModelIncident {
                phase: ModelIncidentPhase::Review,
                category: ModelIncidentCategory::InvalidOutput,
                recovered: false,
                recovery: None,
            });
            let retry_user = format!(
                "{user}\n\n[Your previous response]\n{content}\n\n[Correction] Your summary \
                 describes merge-relevant risk but `findings` is empty, which is invalid. \
                 Either report each risk as a structured finding citing its exact new-file \
                 line from the diff above, or — if nothing is actually merge-relevant — \
                 return exactly {{\"summary\": \"\", \"findings\": []}}."
            );
            let mut retry_usage = usage;
            match self
                .chat(
                    model,
                    system,
                    &retry_user,
                    &mut retry_usage,
                    &mut usage_accounting_complete,
                    Some(REVIEW_MAX_TOKENS),
                    LlmPhase::Review,
                )
                .await
            {
                Ok(retried) => {
                    review.usage = retry_usage;
                    review.usage_accounting_complete = usage_accounting_complete;
                    if let Ok(retried_raw) = parse_review(&retried) {
                        let mut candidate = into_review(retried_raw, model, retry_usage);
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
                    review.usage_accounting_complete = false;
                    if let Err(error) = self.remaining_budget(LlmPhase::Review) {
                        return Err(ModelError::new(
                            error.context(ProviderError),
                            retry_usage,
                            false,
                        ));
                    }
                }
            }
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
        let mut usage = Usage::default();
        let mut usage_accounting_complete = true;
        let mut model_incidents = Vec::new();
        let content = self
            .chat_with_temperature(
                model,
                system,
                user,
                &mut usage,
                &mut usage_accounting_complete,
                Some(SCORER_MAX_TOKENS),
                0.0,
                LlmPhase::Total,
            )
            .await
            .map_err(|e| {
                let complete = usage_accounting_complete
                    && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                ModelError::new(e, usage, complete)
            })?;
        let scores = match parse_scores(&content, expected_len) {
            Ok(scores) => scores,
            Err(first_error) => {
                eprintln!("postil: scorer output invalid; requesting one schema repair");
                let invalid: String = content.chars().take(8_000).collect();
                let repair_system = format!(
                    "{system}\n\nYour previous response failed schema validation. Repair only the JSON schema. Kind is a category, so severity values such as info, warn, and error are invalid kinds. Return the complete array and nothing else."
                );
                let repair_user =
                    format!("{user}\n\nInvalid previous response (untrusted data):\n{invalid}");
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
                        &mut usage_accounting_complete,
                        Some(SCORER_MAX_TOKENS),
                        0.0,
                        LlmPhase::Total,
                    )
                    .await
                    .map_err(|error| {
                        let complete = usage_accounting_complete
                            && (usage.prompt_tokens > 0 || usage.completion_tokens > 0);
                        let mut error = ModelError::new(error, usage, complete);
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
            model_usage: vec![ModelUsage {
                model: model.to_string(),
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
            }],
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
        usage_accounting_complete: &mut bool,
        max_tokens: Option<u32>,
        phase: LlmPhase,
    ) -> Result<String> {
        self.chat_with_temperature(
            model,
            system,
            user,
            usage,
            usage_accounting_complete,
            max_tokens,
            0.1,
            phase,
        )
        .await
        .map_err(|e| e.context(ProviderError))
    }

    #[allow(clippy::too_many_arguments)]
    async fn chat_with_temperature(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
        usage_accounting_complete: &mut bool,
        max_tokens: Option<u32>,
        temperature: f64,
        phase: LlmPhase,
    ) -> Result<String> {
        self.chat_inner(
            model,
            system,
            user,
            usage,
            usage_accounting_complete,
            max_tokens,
            temperature,
            phase,
        )
        .await
        .map_err(|e| e.context(ProviderError))
    }

    /// Transport + HTTP envelope handling; every error here is provider-class.
    #[allow(clippy::too_many_arguments)]
    async fn chat_inner(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
        usage_accounting_complete: &mut bool,
        max_tokens: Option<u32>,
        temperature: f64,
        phase: LlmPhase,
    ) -> Result<String> {
        // This mutable flag is stack-local state held through one exclusively
        // borrowed async call. Request retries run sequentially in this loop,
        // so updating it before continuing or returning needs no atomic type.
        let body = self.request_body(model, system, user, max_tokens, temperature);
        let mut retries = 0u32;
        let mut timeout_retries = 0u32;
        let mut attempt_timeout = self.request_timeout;
        let text = loop {
            let attempt_started_at = Instant::now();
            let remaining = self.remaining_budget(phase)?;
            let deadline_limited = remaining.is_some_and(|value| value <= attempt_timeout);
            let timeout = remaining.map_or(attempt_timeout, |value| value.min(attempt_timeout));
            let response = match tokio::time::timeout(timeout, self.request_once(&body)).await {
                Ok(result) => result,
                Err(_) if deadline_limited => {
                    *usage_accounting_complete = false;
                    return Err(DeadlineExceeded(phase).into());
                }
                Err(_) => {
                    *usage_accounting_complete = false;
                    if timeout_retries < TIMEOUT_RETRIES && retries < TRANSIENT_RETRIES {
                        retries += 1;
                        timeout_retries += 1;
                        let wait = Duration::from_secs(2 * retries as u64);
                        eprintln!(
                            "postil: model {} hit a request timeout after {}, retrying in {}s \
                             (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            wait.as_secs()
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.timeout_retry_timeout;
                        continue;
                    }
                    return Err(RequestTimedOut.into());
                }
            };
            match response {
                Ok((status, text)) => {
                    if status.is_success() {
                        break text;
                    }
                    let snippet = self.safe_error_snippet(&text);
                    if timeout_status(status.as_u16())
                        && timeout_retries < TIMEOUT_RETRIES
                        && retries < TRANSIENT_RETRIES
                    {
                        *usage_accounting_complete = false;
                        retries += 1;
                        timeout_retries += 1;
                        let wait = Duration::from_secs(2 * retries as u64);
                        eprintln!(
                            "postil: model {} returned timeout HTTP {status} after {}, retrying in {}s \
                             (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            wait.as_secs()
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.timeout_retry_timeout;
                        continue;
                    }
                    if timeout_status(status.as_u16()) {
                        return Err(anyhow::Error::new(RequestTimedOut)
                            .context(format!("model endpoint returned {status}: {snippet}")));
                    }
                    if retryable_status(status.as_u16()) && retries < TRANSIENT_RETRIES {
                        retries += 1;
                        let wait = Duration::from_secs(2 * retries as u64);
                        eprintln!(
                            "postil: model {} returned retryable HTTP {status} after {}, retrying in {}s \
                             (retry {retries}/{TRANSIENT_RETRIES})",
                            log_text(model),
                            elapsed_text(attempt_started_at.elapsed()),
                            wait.as_secs()
                        );
                        self.sleep_with_budget(phase, wait).await?;
                        attempt_timeout = self.request_timeout;
                        continue;
                    }
                    return Err(anyhow!("model endpoint returned {status}: {snippet}"));
                }
                Err(error)
                    if reqwest_error(&error).is_some_and(reqwest::Error::is_timeout)
                        && timeout_retries < TIMEOUT_RETRIES
                        && retries < TRANSIENT_RETRIES =>
                {
                    *usage_accounting_complete = false;
                    retries += 1;
                    timeout_retries += 1;
                    let wait = Duration::from_secs(2 * retries as u64);
                    eprintln!(
                        "postil: model {} hit a request timeout after {}, retrying in {}s \
                         (timeout retry {timeout_retries}/{TIMEOUT_RETRIES}; retry {retries}/{TRANSIENT_RETRIES})",
                        log_text(model),
                        elapsed_text(attempt_started_at.elapsed()),
                        wait.as_secs()
                    );
                    self.sleep_with_budget(phase, wait).await?;
                    attempt_timeout = self.timeout_retry_timeout;
                }
                Err(error)
                    if reqwest_error(&error).is_some_and(reqwest::Error::is_connect)
                        && retries < TRANSIENT_RETRIES =>
                {
                    *usage_accounting_complete = false;
                    retries += 1;
                    let wait = Duration::from_secs(2 * retries as u64);
                    eprintln!(
                        "postil: model {} hit a retryable connection error after {}, retrying in {}s \
                         (retry {retries}/{TRANSIENT_RETRIES})",
                        log_text(model),
                        elapsed_text(attempt_started_at.elapsed()),
                        wait.as_secs()
                    );
                    self.sleep_with_budget(phase, wait).await?;
                    attempt_timeout = self.request_timeout;
                }
                Err(error) => {
                    return Err(error.context("request to model endpoint failed"));
                }
            }
        };
        self.parse_response(&text, usage)
    }

    fn request_body(
        &self,
        model: &str,
        system: &str,
        user: &str,
        max_tokens: Option<u32>,
        temperature: f64,
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
                if let Some(max_tokens) = max_tokens {
                    body["max_tokens"] = json!(max_tokens);
                }
                body
            }
            ApiFormat::Anthropic => json!({
                "model": model,
                "system": system,
                "messages": [{"role": "user", "content": user}],
                "max_tokens": max_tokens.unwrap_or(ANTHROPIC_DEFAULT_MAX_TOKENS),
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
                    usage.prompt_tokens += u.prompt_tokens.unwrap_or(0);
                    usage.completion_tokens += u.completion_tokens.unwrap_or(0);
                }
                parsed
                    .choices
                    .into_iter()
                    .next()
                    .and_then(|choice| choice.message.content)
                    .ok_or_else(|| anyhow!("model response had no choices/content"))
            }
            ApiFormat::Anthropic => {
                let parsed: AnthropicResponse = serde_json::from_str(text)
                    .context("model endpoint returned non-JSON Anthropic body")?;
                if let Some(u) = parsed.usage {
                    usage.prompt_tokens += u.input_tokens.unwrap_or(0);
                    usage.completion_tokens += u.output_tokens.unwrap_or(0);
                }
                let content = parsed
                    .content
                    .into_iter()
                    .filter(|block| block.kind == "text")
                    .filter_map(|block| block.text)
                    .collect::<Vec<_>>()
                    .join("\n");
                if content.is_empty() {
                    Err(anyhow!("model response had no text content blocks"))
                } else {
                    Ok(content)
                }
            }
        }
    }

    fn safe_error_snippet(&self, text: &str) -> String {
        let mut redacted = text.replace(&self.api_key, "[REDACTED]");
        if let Some(auth) = &self.endpoint_auth {
            redacted = redacted.replace(&auth.secret, "[REDACTED]");
        }
        redacted.chars().take(300).collect()
    }

    async fn request_once(
        &self,
        body: &serde_json::Value,
    ) -> Result<(reqwest::StatusCode, String)> {
        let http = self.http_client()?;
        let mut request = match self.api_format {
            ApiFormat::OpenaiCompatible => {
                let url = format!("{}/chat/completions", self.api_base);
                http.post(&url)
                    .bearer_auth(&self.api_key)
                    .header("HTTP-Referer", "https://postil.dev")
                    .header("X-Title", "Postil")
            }
            ApiFormat::Anthropic => {
                let url = format!("{}/messages", self.api_base);
                http.post(&url)
                    .header("x-api-key", &self.api_key)
                    .header("anthropic-version", ANTHROPIC_VERSION)
            }
        };
        if let Some(auth) = &self.endpoint_auth {
            request = request.header(auth.name.clone(), auth.value.clone());
        }
        let response = request.json(body).send().await?;
        let status = response.status();
        let text = response.text().await?;
        Ok((status, text))
    }

    fn http_client(&self) -> Result<reqwest::Client> {
        let mut client = self
            .http
            .lock()
            .map_err(|_| anyhow!("model provider HTTP client lock is poisoned"))?;
        if let Some(client) = client.as_ref() {
            return Ok(client.clone());
        }
        let built = secure_http_client(&self.api_base)?;
        *client = Some(built.clone());
        Ok(built)
    }

    fn remaining_budget(&self, phase: LlmPhase) -> Result<Option<Duration>> {
        let deadline = match phase {
            LlmPhase::Review => self.review_deadline,
            LlmPhase::Total => self.total_deadline,
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
}

#[derive(Debug, Deserialize)]
struct Message {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicContentBlock>,
    usage: Option<AnthropicUsage>,
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
            Ok(Some(EndpointAuth {
                name,
                value,
                secret,
            }))
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
    let mut seen = vec![false; expected_len];
    let mut scores = raw
        .into_iter()
        .map(|score| {
            if score.index >= expected_len {
                return Err(format!("score index {} out of range", score.index));
            }
            if std::mem::replace(&mut seen[score.index], true) {
                return Err(format!("duplicate score index {}", score.index));
            }
            let kind = Kind::parse(&score.kind).ok_or_else(|| {
                format!(
                    "invalid score kind {:?} (risk|humanEscalation|guardrail|uncertainty|contentPolicy)",
                    score.kind
                )
            })?;
            Ok(FindingScore {
                index: score.index,
                confidence: score.confidence.clamp(0.0, 1.0),
                kind,
                reason: score.reason.trim().chars().take(300).collect(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    scores.sort_by_key(|score| score.index);
    Ok(scores)
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
            // labels to Warn — conservative (non-silent, doesn't over-gate the
            // way an Error default would).
            let severity = Severity::parse(&f.severity).unwrap_or(Severity::Warn);
            let kind = match f.kind.as_deref() {
                Some("humanEscalation") | Some("human_escalation") => Kind::HumanEscalation,
                Some("guardrail") => Kind::Guardrail,
                Some("uncertainty") => Kind::Uncertainty,
                Some("contentPolicy") | Some("content_policy") => Kind::ContentPolicy,
                _ => Kind::Risk,
            };
            let title = if f.title.trim().is_empty() {
                let body_head: String = f.body.chars().take(80).collect();
                body_head
            } else {
                f.title
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
                title,
                body: f.body,
                id: None,
            }
        })
        .collect();
    ModelReview {
        summary: raw.summary.trim().to_string(),
        findings,
        model_used: model.to_string(),
        usage,
        model_usage: vec![ModelUsage {
            model: model.to_string(),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
        }],
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
    use crate::config::Config;
    use crate::envelope::{Kind, Severity};
    use std::sync::{Mutex, OnceLock};

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
    fn scorer_scores_parse_clamp_and_validate_kind() {
        let scores = parse_scores(
            r#"[{"index":0,"confidence":1.2,"kind":"humanEscalation","reason":"needs owner"}]"#,
            1,
        )
        .unwrap();
        assert_eq!(scores[0].index, 0);
        assert_eq!(scores[0].confidence, 1.0);
        assert_eq!(scores[0].kind, Kind::HumanEscalation);
    }

    #[test]
    fn scorer_rejects_severity_label_as_kind() {
        let error = parse_scores(
            r#"[{"index":0,"confidence":0.7,"kind":"warn","reason":"wrong field"}]"#,
            1,
        )
        .unwrap_err();
        assert!(error.contains("invalid score kind"));
    }

    #[test]
    fn scorer_rejects_missing_entries() {
        assert!(parse_scores(r#"[{"index":0,"confidence":0.5,"kind":"risk"}]"#, 2).is_err());
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
            }],
        };
        let r = into_review(raw, "m", Usage::default());
        let f = &r.findings[0];
        assert_eq!(f.path, "src/a.rs");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.kind, Kind::HumanEscalation);
        assert_eq!(f.confidence, 1.0);
        assert_eq!(f.end_line, None);
        assert_eq!(f.title, "a body");
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
            }],
        };
        let r = into_review(raw, "m", Usage::default());
        assert_eq!(r.findings[0].kind, Kind::ContentPolicy);
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
                id: None,
            }],
            model_used: model.into(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
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
            id: None,
        });
        let merged = consensus_merge(vec![a, b]);
        assert!(merged.findings.is_empty());
    }
}
