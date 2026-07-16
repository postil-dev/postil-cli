//! `postil plan`: Terraform-plan semantics for review configuration.
//!
//! Re-applies a candidate config's policy filters (ignore globs, severity
//! threshold, confidence floor, max findings, gate level) to stored envelopes
//! and reports what would change. Deterministic; zero model calls.

use std::path::Path;

use anyhow::{Context, Result};

use crate::config::Config;
use crate::envelope::{Envelope, Finding};
use crate::filter::build_ignore_set;

pub struct PlanRow {
    pub name: String,
    pub findings_before: usize,
    pub findings_after: usize,
    pub gate_before: bool,
    pub gate_after: bool,
    pub newly_suppressed: Vec<Finding>,
}

pub fn run(envelopes_dir: &Path, candidate: &Config) -> Result<Vec<PlanRow>> {
    let mut rows = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(envelopes_dir)
        .with_context(|| format!("reading {}", envelopes_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();
    for path in entries {
        let raw = std::fs::read_to_string(&path)?;
        let env: Envelope = match serde_json::from_str(&raw) {
            Ok(e) => e,
            Err(err) => {
                eprintln!(
                    "postil: skipping {} (not an envelope: {err})",
                    path.display()
                );
                continue;
            }
        };
        rows.push(replay(&path, &env, candidate)?);
    }
    Ok(rows)
}

fn replay(path: &Path, env: &Envelope, cfg: &Config) -> Result<PlanRow> {
    let ignore = build_ignore_set(&cfg.ignore)?;
    let all_findings = env
        .findings
        .iter()
        .cloned()
        .chain(
            env.suppressed_findings
                .iter()
                .map(|suppressed| suppressed.finding.clone()),
        )
        .collect::<Vec<_>>();
    let mut kept: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();
    for f in &all_findings {
        let keep = !ignore.is_match(&f.path)
            && f.severity >= cfg.severity_threshold
            && f.confidence >= cfg.min_confidence;
        if keep {
            kept.push(f.clone());
        } else {
            suppressed.push(f.clone());
        }
    }
    kept.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.total_cmp(&a.confidence))
    });
    if kept.len() > cfg.max_findings {
        suppressed.extend(kept.split_off(cfg.max_findings));
    }
    let block_on_kinds: Vec<String> = cfg
        .block_on_kinds
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect();
    let gate_after = kept.iter().any(|finding| {
        if cfg.gate_fail_on.as_str().eq_ignore_ascii_case("never") {
            false
        } else if finding.path == crate::envelope::OPERATIONAL_PATH {
            true
        } else if finding.path == crate::envelope::PROVIDER_PATH {
            cfg.gate_on_error == crate::config::OnError::Block
        } else {
            crate::envelope::finding_blocks_gate(
                finding,
                cfg.gate_fail_on.as_str(),
                &block_on_kinds,
                false,
            )
        }
    });
    Ok(PlanRow {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        findings_before: all_findings.len(),
        findings_after: kept.len(),
        gate_before: env.gate.failing,
        gate_after,
        newly_suppressed: suppressed,
    })
}

pub fn print_report(rows: &[PlanRow], cfg: &Config) {
    if rows.is_empty() {
        eprintln!("postil plan: no envelopes found to replay.");
        return;
    }
    eprintln!(
        "postil plan: replaying {} stored review(s) under candidate config ({})\n",
        rows.len(),
        cfg.source
    );
    let mut gate_flips = 0;
    let mut total_suppressed = 0;
    for r in rows {
        let gate = match (r.gate_before, r.gate_after) {
            (true, false) => {
                gate_flips += 1;
                "gate: FAILING -> passing"
            }
            (false, true) => {
                gate_flips += 1;
                "gate: passing -> FAILING"
            }
            (true, true) => "gate: failing (unchanged)",
            (false, false) => "gate: passing (unchanged)",
        };
        eprintln!(
            "  {}: {} -> {} finding(s); {}",
            r.name, r.findings_before, r.findings_after, gate
        );
        for f in &r.newly_suppressed {
            total_suppressed += 1;
            eprintln!(
                "      would suppress: {}:{} [{}] {}",
                f.path,
                f.line,
                f.severity.as_str(),
                f.title
            );
        }
    }
    eprintln!(
        "\nSummary: {total_suppressed} finding(s) would be suppressed; {gate_flips} gate outcome(s) would change."
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::envelope::{Counts, Gate, Kind, Severity, Usage};

    fn envelope_with(findings: Vec<Finding>, gate_failing: bool) -> Envelope {
        let counts = Envelope::counts_of(&findings, 0);
        let buckets = Envelope::buckets_of(&findings);
        Envelope {
            version: 1,
            summary: String::new(),
            silent: findings.is_empty(),
            findings,
            suppressed_findings: vec![],
            resolved: vec![],
            counts,
            confidence_buckets: buckets,
            gate: Gate {
                fail_on: "error".into(),
                failing: gate_failing,
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
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        }
    }

    fn f(path: &str, sev: Severity, conf: f64) -> Finding {
        Finding {
            path: path.into(),
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
            evidence: None,
            id: None,
        }
    }

    #[test]
    fn replay_flips_gate_and_counts_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let env = envelope_with(
            vec![
                f("a.rs", Severity::Error, 0.65),
                f("vendor/x.js", Severity::Warn, 0.9),
            ],
            true,
        );
        std::fs::write(
            dir.path().join("r1.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.min_confidence = 0.7; // suppresses the error finding
        cfg.ignore = vec!["vendor/**".into()]; // suppresses the vendor finding
        let rows = run(dir.path(), &cfg).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].findings_before, 2);
        assert_eq!(rows[0].findings_after, 0);
        assert!(rows[0].gate_before);
        assert!(!rows[0].gate_after);
        assert_eq!(rows[0].newly_suppressed.len(), 2);
        let _ = Counts::default();
    }

    #[test]
    fn replay_uses_human_escalation_confidence_floor() {
        let dir = tempfile::tempdir().unwrap();
        let mut weak = f("a.rs", Severity::Error, 0.05);
        weak.kind = Kind::HumanEscalation;
        let env = envelope_with(vec![weak], true);
        std::fs::write(
            dir.path().join("r1.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.min_confidence = 0.0;
        let rows = run(dir.path(), &cfg).unwrap();

        assert_eq!(rows[0].findings_after, 1);
        assert!(!rows[0].gate_after);
    }

    #[test]
    fn replay_never_blocks_provider_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = f(crate::envelope::PROVIDER_PATH, Severity::Error, 1.0);
        provider.kind = Kind::Uncertainty;
        let env = envelope_with(vec![provider], true);
        std::fs::write(
            dir.path().join("provider.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.gate_fail_on = crate::config::GateLevel::Never;
        cfg.gate_on_error = crate::config::OnError::Advisory;
        assert!(!run(dir.path(), &cfg).unwrap()[0].gate_after);

        cfg.gate_on_error = crate::config::OnError::Block;
        assert!(!run(dir.path(), &cfg).unwrap()[0].gate_after);
    }

    #[test]
    fn replay_never_blocks_unusable_model_output() {
        let dir = tempfile::tempdir().unwrap();
        let env = envelope_with(vec![crate::envelope::fail_closed_finding("invalid")], true);
        std::fs::write(
            dir.path().join("invalid.json"),
            serde_json::to_string(&env).unwrap(),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.gate_fail_on = crate::config::GateLevel::Never;
        cfg.gate_on_error = crate::config::OnError::Advisory;
        assert!(!run(dir.path(), &cfg).unwrap()[0].gate_after);
    }

    #[test]
    fn replay_can_restore_a_retained_suppressed_finding() {
        let path = Path::new("r1.json");
        let hidden = f("src/lib.rs", Severity::Warn, 0.55);
        let mut env = envelope_with(vec![], false);
        env.suppressed_findings = vec![crate::envelope::SuppressedFinding {
            finding: hidden,
            reason: crate::envelope::SuppressionReason::BelowConfidence,
        }];
        env.counts.suppressed = 1;

        let cfg = Config {
            min_confidence: 0.5,
            ..Config::default()
        };
        let row = replay(path, &env, &cfg).unwrap();

        assert_eq!(row.findings_before, 1);
        assert_eq!(row.findings_after, 1);
        assert!(row.newly_suppressed.is_empty());
    }
}
