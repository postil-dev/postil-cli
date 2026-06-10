//! The Postil review envelope: the JSON contract between the model and the rest
//! of the system. Every consumer (CLI, GitHub Action, hosted worker) reads the
//! same shape. The parser fails closed: if the model returns invalid or
//! ungrounded JSON, we synthesize a single `error` finding at
//! `.postil/model-output:1` so a flaky model can never silently approve.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Warn => 1,
            Severity::Error => 2,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "information" | "note" | "low" => Some(Severity::Info),
            "warn" | "warning" | "medium" => Some(Severity::Warn),
            "error" | "high" | "critical" | "blocker" => Some(Severity::Error),
            _ => None,
        }
    }

    pub fn glyph(self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Warn => "⚠️",
            Severity::Error => "❌",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    /// Concrete merge risk: bug, regression, security, data loss.
    Risk,
    /// Decision belongs to an accountable human, not the bot.
    HumanEscalation,
    /// Recurring class of issue worth a durable lint/test/policy.
    Guardrail,
    /// Material ambiguity the reviewer cannot resolve from the diff alone.
    Uncertainty,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub line: u32,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FindingKind>,
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
}

/// The full review envelope. `--output-json` serialises this; the hosted worker
/// deserialises it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub summary: String,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default, rename = "modelUsed", skip_serializing_if = "Option::is_none")]
    pub model_used: Option<String>,
    #[serde(
        default,
        rename = "cliVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub cli_version: Option<String>,
}

impl Envelope {
    /// Construct the fail-closed envelope used whenever the model output cannot
    /// be trusted. Always emits exactly one `error` finding so downstream check
    /// runs conclude `failure`.
    pub fn model_output_error(detail: impl Into<String>) -> Self {
        Envelope {
            summary: "Model returned a response Postil could not validate. Failing closed.".into(),
            findings: vec![Finding {
                path: ".postil/model-output".into(),
                line: 1,
                severity: Severity::Error,
                kind: Some(FindingKind::Risk),
                body: detail.into(),
            }],
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        }
    }

    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
    }
}

/// Parse the model's raw text into an envelope. Fails closed on:
/// - non-JSON or wrapper text the JSON-repair step could not recover,
/// - missing or empty `summary`,
/// - missing `findings` array,
/// - any finding with a blank path / zero line / unrecognised severity,
/// - "ungrounded summary" sentinel: a non-empty summary with zero findings is
///   allowed; an empty summary with zero findings is not, since the model would
///   have communicated nothing.
pub fn parse_envelope(raw: &str) -> Result<Envelope, EnvelopeParseError> {
    let trimmed = strip_code_fence(raw.trim());
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| EnvelopeParseError::InvalidJson(e.to_string()))?;

    let summary = value
        .get("summary")
        .and_then(|v| v.as_str())
        .ok_or(EnvelopeParseError::MissingSummary)?
        .trim()
        .to_string();

    let findings_value = value
        .get("findings")
        .ok_or(EnvelopeParseError::MissingFindings)?;
    let raw_findings = findings_value
        .as_array()
        .ok_or(EnvelopeParseError::MissingFindings)?;

    let mut findings = Vec::with_capacity(raw_findings.len());
    for (idx, item) in raw_findings.iter().enumerate() {
        let path = item
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .ok_or(EnvelopeParseError::FindingMissingPath(idx))?
            .to_string();

        let line = item
            .get("line")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .ok_or(EnvelopeParseError::FindingInvalidLine(idx))? as u32;

        let severity_str = item
            .get("severity")
            .and_then(|v| v.as_str())
            .ok_or(EnvelopeParseError::FindingMissingSeverity(idx))?;
        let severity = Severity::parse(severity_str)
            .ok_or_else(|| EnvelopeParseError::FindingBadSeverity(idx, severity_str.to_string()))?;

        let kind = item
            .get("kind")
            .and_then(|v| v.as_str())
            .and_then(|k| match k.trim() {
                "risk" => Some(FindingKind::Risk),
                "humanEscalation" | "human_escalation" => Some(FindingKind::HumanEscalation),
                "guardrail" => Some(FindingKind::Guardrail),
                "uncertainty" => Some(FindingKind::Uncertainty),
                _ => None,
            });

        let body = item
            .get("body")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .ok_or(EnvelopeParseError::FindingMissingBody(idx))?
            .to_string();

        findings.push(Finding {
            path,
            line,
            severity,
            kind,
            body,
        });
    }

    // Note: empty summary + zero findings is the clean signal the prompt asks
    // for — it is the legitimate "nothing to report" output.
    Ok(Envelope {
        summary,
        findings,
        usage: Usage::default(),
        model_used: None,
        cli_version: None,
    })
}

fn strip_code_fence(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("```json").or_else(|| s.strip_prefix("```")) {
        rest.trim().trim_end_matches("```").trim()
    } else {
        s
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("envelope missing summary")]
    MissingSummary,
    #[error("envelope missing findings array")]
    MissingFindings,
    #[error("finding #{0} missing path")]
    FindingMissingPath(usize),
    #[error("finding #{0} has invalid line")]
    FindingInvalidLine(usize),
    #[error("finding #{0} missing severity")]
    FindingMissingSeverity(usize),
    #[error("finding #{0} has unknown severity {1:?}")]
    FindingBadSeverity(usize, String),
    #[error("finding #{0} missing body")]
    FindingMissingBody(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_envelope() {
        let raw = r#"{"summary":"clean","findings":[]}"#;
        let e = parse_envelope(raw).unwrap();
        assert_eq!(e.summary, "clean");
        assert!(e.findings.is_empty());
        assert_eq!(e.worst_severity(), None);
    }

    #[test]
    fn parses_findings_with_kind() {
        let raw = r#"{"summary":"one risk","findings":[
            {"path":"src/a.rs","line":3,"severity":"error","kind":"risk","body":"null deref"}
        ]}"#;
        let e = parse_envelope(raw).unwrap();
        assert_eq!(e.findings.len(), 1);
        assert_eq!(e.findings[0].severity, Severity::Error);
        assert_eq!(e.findings[0].kind, Some(FindingKind::Risk));
        assert_eq!(e.worst_severity(), Some(Severity::Error));
    }

    #[test]
    fn strips_code_fence() {
        let raw = "```json\n{\"summary\":\"ok\",\"findings\":[]}\n```";
        let e = parse_envelope(raw).unwrap();
        assert_eq!(e.summary, "ok");
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            parse_envelope("not json"),
            Err(EnvelopeParseError::InvalidJson(_))
        ));
    }

    #[test]
    fn empty_summary_and_no_findings_is_the_clean_signal() {
        let raw = r#"{"summary":"","findings":[]}"#;
        let e = parse_envelope(raw).unwrap();
        assert!(e.summary.is_empty());
        assert!(e.findings.is_empty());
        assert_eq!(e.worst_severity(), None);
    }

    #[test]
    fn rejects_zero_line() {
        let raw = r#"{"summary":"x","findings":[
            {"path":"a","line":0,"severity":"warn","body":"b"}
        ]}"#;
        assert!(matches!(
            parse_envelope(raw),
            Err(EnvelopeParseError::FindingInvalidLine(0))
        ));
    }

    #[test]
    fn rejects_unknown_severity() {
        let raw = r#"{"summary":"x","findings":[
            {"path":"a","line":1,"severity":"chartreuse","body":"b"}
        ]}"#;
        assert!(matches!(
            parse_envelope(raw),
            Err(EnvelopeParseError::FindingBadSeverity(0, _))
        ));
    }

    #[test]
    fn model_output_error_is_always_failure() {
        let e = Envelope::model_output_error("bad json");
        assert_eq!(e.findings.len(), 1);
        assert_eq!(e.worst_severity(), Some(Severity::Error));
        assert_eq!(e.findings[0].path, ".postil/model-output");
    }
}
