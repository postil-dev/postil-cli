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
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Risk => "risk",
            Kind::HumanEscalation => "humanEscalation",
            Kind::Guardrail => "guardrail",
            Kind::Uncertainty => "uncertainty",
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
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
    pub suppressed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gate {
    /// Severity at or above which the gate check fails. "never" disables the gate.
    pub fail_on: String,
    pub failing: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub version: u32,
    pub summary: String,
    pub silent: bool,
    pub findings: Vec<Finding>,
    pub resolved: Vec<Finding>,
    pub counts: Counts,
    /// Counts of finding confidences in [0-.2, .2-.4, .4-.6, .6-.8, .8-1].
    pub confidence_buckets: [u32; 5],
    pub gate: Gate,
    pub model_used: String,
    pub usage: Usage,
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

/// Path marker for synthetic unusable-output findings (the model answered but
/// the output could not be validated). A malicious diff can induce this class
/// via prompt injection, so it always fails the gate — even under
/// `gate.onError: advisory`.
pub const OPERATIONAL_PATH: &str = ".postil/model-output";

/// Path marker for synthetic provider findings (endpoint unreachable, HTTP
/// errors, timeouts): outage-class failures the diff content cannot induce.
/// This is the only class `gate.onError: advisory` lets stand aside.
pub const PROVIDER_PATH: &str = ".postil/provider";

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
    }
}

/// The synthetic finding emitted when the provider could not be reached at all.
pub fn provider_error_finding(detail: &str) -> Finding {
    Finding {
        path: PROVIDER_PATH.to_string(),
        line: 1,
        end_line: None,
        severity: Severity::Error,
        kind: Kind::Uncertainty,
        confidence: 1.0,
        title: "Model provider unavailable".to_string(),
        body: format!(
            "Postil could not complete the model request and is failing closed rather \
             than passing unreviewed code.\n\nDetail: {detail}"
        ),
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
            title: "t".into(),
            body: "b".into(),
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
    fn envelope_serializes_camel_case() {
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            resolved: vec![],
            counts: Counts::default(),
            confidence_buckets: [0; 5],
            gate: Gate {
                fail_on: "error".into(),
                failing: false,
            },
            model_used: "m".into(),
            usage: Usage::default(),
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        let v = serde_json::to_value(&env).unwrap();
        assert!(v.get("confidenceBuckets").is_some());
        assert!(v.get("modelUsed").is_some());
        assert_eq!(v["gate"]["failOn"], "error");
    }
}
