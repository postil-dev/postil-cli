//! OpenAI-compatible chat client with model cascade, one JSON-repair retry,
//! optional multi-model consensus, and fail-closed semantics.
//!
//! Works against OpenRouter (default), Ollama, vLLM, LiteLLM, Azure OpenAI, or
//! any other endpoint that speaks `POST {base}/chat/completions`.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use crate::api_key;
use crate::config::Config;
use crate::envelope::{Finding, Usage};

#[derive(Debug, Clone)]
pub struct ModelReview {
    pub summary: String,
    pub findings: Vec<Finding>,
    pub model_used: String,
    pub usage: Usage,
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

fn default_confidence() -> f64 {
    0.5
}

#[derive(Clone)]
pub struct LlmClient {
    http: reqwest::Client,
    api_base: String,
    api_key: String,
}

/// Retries per model on transient provider errors before the cascade moves on.
const TRANSIENT_RETRIES: u32 = 2;

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

impl LlmClient {
    pub fn from_env(cfg: &Config) -> Result<Self> {
        let api_key = api_key::resolve_from_process_env().ok_or_else(|| {
            let key_names = api_key::names_text();
            anyhow!(
                "no API key: set {key_names}. Postil never proxies your inference; bring your own key."
            )
        })?;
        Ok(LlmClient {
            http: reqwest::Client::builder()
                // Generation time scales with diff size; a thorough review of a
                // truncation-limit diff can exceed 3 minutes of streaming.
                .timeout(std::time::Duration::from_secs(600))
                .build()?,
            api_base: cfg.api_base.trim_end_matches('/').to_string(),
            api_key,
        })
    }

    /// Run the review. With `consensus > 1`, the first N models of the chain are
    /// each consulted and only findings two or more models agree on are kept.
    pub async fn review(&self, cfg: &Config, system: &str, user: &str) -> Result<ModelReview> {
        let chain = cfg.model_chain();
        if cfg.consensus > 1 && chain.len() > 1 {
            let n = cfg.consensus.min(chain.len());
            let handles: Vec<_> = chain[..n]
                .iter()
                .map(|m| {
                    let client = self.clone();
                    let (model, system, user) = (m.clone(), system.to_string(), user.to_string());
                    tokio::spawn(
                        async move { client.review_with_model(&model, &system, &user).await },
                    )
                })
                .collect();
            let mut ok: Vec<ModelReview> = Vec::new();
            let mut last_err: Option<anyhow::Error> = None;
            for h in handles {
                match h.await {
                    Ok(Ok(r)) => ok.push(r),
                    Ok(Err(e)) => {
                        eprintln!("postil: consensus model failed: {e:#}");
                        last_err = Some(e);
                    }
                    Err(e) => eprintln!("postil: consensus task panicked: {e}"),
                }
            }
            match ok.len() {
                // Wrap the last failure so its error class (provider vs
                // content) survives for gate.onError classification.
                0 => Err(match last_err {
                    Some(e) => e.context(format!("all {n} consensus models failed")),
                    None => anyhow!("all {n} consensus models failed"),
                }),
                1 => Ok(ok.into_iter().next().unwrap()),
                _ => Ok(consensus_merge(ok)),
            }
        } else {
            let mut last_err = None;
            for model in &chain {
                match self.review_with_model(model, system, user).await {
                    Ok(r) => return Ok(r),
                    Err(e) => {
                        eprintln!("postil: model {model} failed: {e:#}");
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| anyhow!("empty model chain")))
        }
    }

    /// Free-form answer (no JSON contract). Used by the interactive bot to reply
    /// to a maintainer's question or mention. Tries the model chain in order.
    pub async fn answer(&self, cfg: &Config, system: &str, user: &str) -> Result<(String, String)> {
        let mut usage = Usage::default();
        let mut last_err = None;
        for model in cfg.model_chain() {
            match self.chat(&model, system, user, &mut usage).await {
                Ok(content) => return Ok((content.trim().to_string(), model)),
                Err(e) => {
                    eprintln!("postil: model {model} failed: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("empty model chain")))
    }

    async fn review_with_model(
        &self,
        model: &str,
        system: &str,
        user: &str,
    ) -> Result<ModelReview> {
        let mut usage = Usage::default();
        let content = self.chat(model, system, user, &mut usage).await?;
        let raw = match parse_review(&content) {
            Ok(raw) => raw,
            Err(parse_err) => {
                // One repair attempt: ask the same model to fix its own JSON.
                let repair_user = format!(
                    "The following was supposed to be a single valid JSON object matching the \
                     review schema but failed to parse ({parse_err}). Output ONLY the corrected \
                     JSON object, nothing else:\n\n{content}"
                );
                let repaired = self
                    .chat(
                        model,
                        "You repair malformed JSON. Output only valid JSON.",
                        &repair_user,
                        &mut usage,
                    )
                    .await
                    .context("JSON repair call failed")?;
                parse_review(&repaired)
                    .map_err(|e| anyhow!("model output invalid after repair: {e}"))?
            }
        };
        let mut review = into_review(raw, model, usage);

        // Semantic consistency retry: a summary that narrates risk next to an
        // empty findings array is the contract violation behind "clean status,
        // scary prose" reviews. Give the model one chance to either structure
        // the risk or retract it; if the contradiction survives, the caller
        // fails the review closed.
        if review.findings.is_empty() && !review.summary.is_empty() {
            let retry_user = format!(
                "{user}\n\n[Your previous response]\n{content}\n\n[Correction] Your summary \
                 describes merge-relevant risk but `findings` is empty, which is invalid. \
                 Either report each risk as a structured finding citing its exact new-file \
                 line from the diff above, or — if nothing is actually merge-relevant — \
                 return exactly {{\"summary\": \"\", \"findings\": []}}."
            );
            let mut retry_usage = usage;
            if let Ok(retried) = self
                .chat(model, system, &retry_user, &mut retry_usage)
                .await
                && let Ok(retried_raw) = parse_review(&retried)
            {
                let candidate = into_review(retried_raw, model, retry_usage);
                let still_contradictory =
                    candidate.findings.is_empty() && !candidate.summary.is_empty();
                if still_contradictory {
                    review.usage = retry_usage;
                } else {
                    review = candidate;
                }
            }
        }
        Ok(review)
    }

    async fn chat(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
    ) -> Result<String> {
        self.chat_inner(model, system, user, usage)
            .await
            .map_err(|e| e.context(ProviderError))
    }

    /// Transport + HTTP envelope handling; every error here is provider-class.
    async fn chat_inner(
        &self,
        model: &str,
        system: &str,
        user: &str,
        usage: &mut Usage,
    ) -> Result<String> {
        let body = json!({
            "model": model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        });
        let mut attempt = 0u32;
        let text = loop {
            attempt += 1;
            let sent = self
                .http
                .post(format!("{}/chat/completions", self.api_base))
                .bearer_auth(&self.api_key)
                .header("HTTP-Referer", "https://postil.dev")
                .header("X-Title", "Postil")
                .json(&body)
                .send()
                .await;
            match sent {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.context("reading model response")?;
                    if status.is_success() {
                        break text;
                    }
                    let snippet: String = text.chars().take(300).collect();
                    if retryable_status(status.as_u16()) && attempt <= TRANSIENT_RETRIES {
                        let wait = std::time::Duration::from_secs(2 * attempt as u64);
                        eprintln!(
                            "postil: {model} returned {status}, retrying in {}s \
                             (attempt {attempt}/{TRANSIENT_RETRIES})",
                            wait.as_secs()
                        );
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    return Err(anyhow!("model endpoint returned {status}: {snippet}"));
                }
                // Connection-level failures retry too; timeouts do not (the
                // request already waited the full budget).
                Err(e) if e.is_connect() && attempt <= TRANSIENT_RETRIES => {
                    tokio::time::sleep(std::time::Duration::from_secs(2 * attempt as u64)).await;
                }
                Err(e) => {
                    return Err(anyhow::Error::from(e).context("request to model endpoint failed"));
                }
            }
        };
        let parsed: ChatResponse =
            serde_json::from_str(&text).context("model endpoint returned non-JSON body")?;
        if let Some(u) = parsed.usage {
            usage.prompt_tokens += u.prompt_tokens.unwrap_or(0);
            usage.completion_tokens += u.completion_tokens.unwrap_or(0);
        }
        parsed
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| anyhow!("model response had no choices/content"))
    }
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

/// Extract and validate the review JSON from model text. Tolerates code fences
/// and leading/trailing prose, nothing else.
fn parse_review(content: &str) -> Result<RawReview, String> {
    let json_str = extract_json_object(content).ok_or("no JSON object found")?;
    serde_json::from_str::<RawReview>(json_str).map_err(|e| e.to_string())
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
                title,
                body: f.body,
            }
        })
        .collect();
    ModelReview {
        summary: raw.summary.trim().to_string(),
        findings,
        model_used: model.to_string(),
        usage,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Kind, Severity};

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
                title: "t".into(),
                body: "b".into(),
            }],
            model_used: model.into(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
            },
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
            title: "solo".into(),
            body: "b".into(),
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
            title: "t2".into(),
            body: "b2".into(),
        });
        let merged = consensus_merge(vec![a, b]);
        assert!(merged.findings.is_empty());
    }
}
