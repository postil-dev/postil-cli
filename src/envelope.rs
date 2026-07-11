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

/// Path marker for synthetic unusable-output findings (the model answered but
/// the output could not be validated). A malicious diff can induce this class
/// via prompt injection, so it always fails the gate — even under
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
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            duration_ms: 0,
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
