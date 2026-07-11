//! SARIF 2.1.0 output for code-scanning ingestion (GitHub code scanning,
//! GitLab SAST, and any SARIF-aware viewer).
//!
//! Each finding becomes a `result`; each finding `kind` becomes a `rule`.
//! Confidence rides along as a property so downstream filters can use it.

use serde_json::{Value, json};

use crate::envelope::{Envelope, Kind, Severity};

fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

fn rule_id(kind: Kind) -> &'static str {
    // Stable ids so code-scanning can track a class across runs.
    match kind {
        Kind::Risk => "postil/risk",
        Kind::HumanEscalation => "postil/human-escalation",
        Kind::Guardrail => "postil/guardrail",
        Kind::Uncertainty => "postil/uncertainty",
        Kind::ContentPolicy => "postil/content-policy",
    }
}

fn rule_descriptions() -> Vec<Value> {
    [
        (
            Kind::Risk,
            "Concrete defect: bug, security, or correctness issue.",
        ),
        (
            Kind::HumanEscalation,
            "A consequential decision an accountable human must confirm.",
        ),
        (
            Kind::Guardrail,
            "Violation of a stated repository guardrail.",
        ),
        (
            Kind::Uncertainty,
            "Something critical could not be verified from the diff.",
        ),
        (
            Kind::ContentPolicy,
            "Violation of the active content policy (fabricated claims, AI-authorship residue, leaked conversation text, or stale/style residue).",
        ),
    ]
    .into_iter()
    .map(|(k, desc)| {
        json!({
            "id": rule_id(k),
            "name": k.as_str(),
            "shortDescription": { "text": desc },
            "defaultConfiguration": { "level": "warning" }
        })
    })
    .collect()
}

pub fn to_sarif(envelope: &Envelope) -> Value {
    let results: Vec<Value> = envelope
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": rule_id(f.kind),
                "level": level(f.severity),
                "message": { "text": format!("{}\n\n{}", f.title, f.body) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path },
                        "region": {
                            "startLine": f.line,
                            "endLine": f.end_line.unwrap_or(f.line)
                        }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "kind": f.kind.as_str()
                }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Postil",
                    "informationUri": "https://postil.dev",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rule_descriptions()
                }
            },
            "results": results,
            "properties": {
                "gateFailing": envelope.gate.failing,
                "gateFailOn": envelope.gate.fail_on,
                "modelUsed": envelope.model_used,
                "silent": envelope.silent
            }
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Finding, Gate, Usage};

    fn env_with(findings: Vec<Finding>) -> Envelope {
        Envelope {
            version: 1,
            summary: String::new(),
            silent: findings.is_empty(),
            counts: Envelope::counts_of(&findings, 0),
            confidence_buckets: Envelope::buckets_of(&findings),
            findings,
            resolved: vec![],
            gate: Gate {
                fail_on: "error".into(),
                failing: true,
            block_on_kinds: vec![],
            },
            model_used: "m".into(),
            usage: Usage::default(),
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        }
    }

    #[test]
    fn maps_finding_to_result() {
        let f = Finding {
            path: "src/a.rs".into(),
            line: 12,
            end_line: Some(14),
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.9,
            title: "Bug".into(),
            body: "details".into(),
        id: None,
        };
        let s = to_sarif(&env_with(vec![f]));
        let r = &s["runs"][0]["results"][0];
        assert_eq!(r["ruleId"], "postil/risk");
        assert_eq!(r["level"], "error");
        assert_eq!(
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert_eq!(
            r["locations"][0]["physicalLocation"]["region"]["endLine"],
            14
        );
        assert_eq!(r["properties"]["confidence"], 0.9);
        let _ = &s["$schema"];
        assert_eq!(s["version"], "2.1.0");
    }

    #[test]
    fn silent_envelope_has_no_results() {
        let s = to_sarif(&env_with(vec![]));
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(s["runs"][0]["properties"]["silent"], true);
    }
}
