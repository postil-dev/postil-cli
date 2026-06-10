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
    let mut kept: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();
    for f in &env.findings {
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
    let gate_after = kept.iter().any(|f| cfg.gate_fail_on.fails(f.severity));
    Ok(PlanRow {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        findings_before: env.findings.len(),
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
            resolved: vec![],
            counts,
            confidence_buckets: buckets,
            gate: Gate {
                fail_on: "error".into(),
                failing: gate_failing,
            },
            model_used: "m".into(),
            usage: Usage::default(),
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
            title: "t".into(),
            body: "b".into(),
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
}
