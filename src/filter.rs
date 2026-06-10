//! Post-model filtering: grounding, ignore globs, severity/confidence
//! thresholds, max-findings cap, and incremental baseline reconciliation.

use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::Config;
use crate::diff::DiffIndex;
use crate::envelope::Finding;

#[derive(Debug, Default)]
pub struct FilterOutcome {
    pub kept: Vec<Finding>,
    pub suppressed: u32,
    pub ungrounded: u32,
    /// True when the model reported findings but every one was ungrounded —
    /// the output cannot be trusted at all.
    pub all_ungrounded: bool,
}

pub fn build_ignore_set(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p)?);
    }
    Ok(b.build()?)
}

/// Apply grounding then config policy. Order matters: ungrounded findings are
/// evidence of a bad model run; suppressed findings are policy.
pub fn apply(cfg: &Config, index: &DiffIndex, mut findings: Vec<Finding>) -> Result<FilterOutcome> {
    let had_any = !findings.is_empty();

    // Grounding: a finding must cite a line on the new side of the diff.
    let before = findings.len();
    findings.retain(|f| index.contains(&f.path, f.line));
    let ungrounded = (before - findings.len()) as u32;
    let all_ungrounded = had_any && findings.is_empty();

    // Policy suppression.
    let ignore = build_ignore_set(&cfg.ignore)?;
    let mut suppressed = 0u32;
    findings.retain(|f| {
        let keep = !ignore.is_match(&f.path)
            && f.severity >= cfg.severity_threshold
            && f.confidence >= cfg.min_confidence;
        if !keep {
            suppressed += 1;
        }
        keep
    });

    // Highest severity first, then confidence; cap to maxFindings.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.total_cmp(&a.confidence))
    });
    if findings.len() > cfg.max_findings {
        suppressed += (findings.len() - cfg.max_findings) as u32;
        findings.truncate(cfg.max_findings);
    }

    Ok(FilterOutcome {
        kept: findings,
        suppressed,
        ungrounded,
        all_ungrounded,
    })
}

/// Incremental reconciliation. A baseline finding is RESOLVED when the new
/// (incremental) diff touched the lines it pointed at — the author changed that
/// code — and no new finding re-flags the same spot. Untouched baseline
/// findings are still OPEN and are carried forward so the gate cannot be
/// cleared by pushing an unrelated commit.
pub struct Reconciliation {
    pub resolved: Vec<Finding>,
    pub carried: Vec<Finding>,
}

pub fn reconcile(
    baseline: &[Finding],
    incremental_index: &DiffIndex,
    new_findings: &[Finding],
) -> Reconciliation {
    let mut resolved = Vec::new();
    let mut carried = Vec::new();
    for f in baseline {
        // Synthetic fail-closed findings never carry forward; each run re-earns trust.
        if f.path == ".postil/model-output" {
            continue;
        }
        let end = f.end_line.unwrap_or(f.line);
        let touched = incremental_index.touches(&f.path, f.line, end);
        let reflagged = new_findings
            .iter()
            .any(|n| n.path == f.path && n.line.abs_diff(f.line) <= 3);
        if touched && !reflagged {
            resolved.push(f.clone());
        } else if !reflagged {
            let mut carry = f.clone();
            if !carry.body.contains("[carried from previous review]") {
                carry.body = format!("[carried from previous review]\n\n{}", carry.body);
            }
            carried.push(carry);
        }
        // reflagged → the new finding supersedes the baseline one; drop the old copy.
    }
    Reconciliation { resolved, carried }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::diff;
    use crate::envelope::{Kind, Severity};

    fn f(path: &str, line: u32, sev: Severity, conf: f64) -> Finding {
        Finding {
            path: path.into(),
            line,
            end_line: None,
            severity: sev,
            kind: Kind::Risk,
            confidence: conf,
            title: "t".into(),
            body: "b".into(),
        }
    }

    fn index_for(path: &str, start: u32, count: u32) -> DiffIndex {
        let text = format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,{count} +{start},{count} @@\n{}",
            "+x\n".repeat(count as usize)
        );
        DiffIndex::build(&diff::parse(&text))
    }

    #[test]
    fn grounding_drops_uncited_lines() {
        let idx = index_for("a.rs", 10, 3);
        let cfg = Config::default();
        let out = apply(
            &cfg,
            &idx,
            vec![
                f("a.rs", 11, Severity::Error, 0.9),
                f("a.rs", 99, Severity::Error, 0.9),
            ],
        )
        .unwrap();
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.ungrounded, 1);
        assert!(!out.all_ungrounded);
    }

    #[test]
    fn all_ungrounded_is_flagged() {
        let idx = index_for("a.rs", 10, 3);
        let cfg = Config::default();
        let out = apply(&cfg, &idx, vec![f("other.rs", 1, Severity::Error, 0.9)]).unwrap();
        assert!(out.all_ungrounded);
        assert!(out.kept.is_empty());
    }

    #[test]
    fn policy_suppression_counts() {
        let idx = index_for("a.rs", 1, 50);
        let mut cfg = Config::default();
        cfg.min_confidence = 0.7;
        cfg.severity_threshold = Severity::Warn;
        cfg.ignore = vec!["**/vendor/**".into()];
        let out = apply(
            &cfg,
            &idx,
            vec![
                f("a.rs", 1, Severity::Error, 0.9), // kept
                f("a.rs", 2, Severity::Info, 0.9),  // below severity threshold
                f("a.rs", 3, Severity::Error, 0.5), // below confidence
            ],
        )
        .unwrap();
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.suppressed, 2);
    }

    #[test]
    fn cap_keeps_most_severe() {
        let idx = index_for("a.rs", 1, 50);
        let mut cfg = Config::default();
        cfg.max_findings = 1;
        let out = apply(
            &cfg,
            &idx,
            vec![
                f("a.rs", 1, Severity::Warn, 0.9),
                f("a.rs", 2, Severity::Error, 0.8),
            ],
        )
        .unwrap();
        assert_eq!(out.kept.len(), 1);
        assert_eq!(out.kept[0].severity, Severity::Error);
        assert_eq!(out.suppressed, 1);
    }

    #[test]
    fn reconcile_resolves_touched_carries_untouched() {
        let idx = index_for("a.rs", 10, 3); // incremental diff touches a.rs:10-12
        let baseline = vec![
            f("a.rs", 11, Severity::Error, 0.9), // touched → resolved
            f("b.rs", 5, Severity::Warn, 0.8),   // untouched → carried
            f(".postil/model-output", 1, Severity::Error, 1.0), // synthetic → dropped
        ];
        let rec = reconcile(&baseline, &idx, &[]);
        assert_eq!(rec.resolved.len(), 1);
        assert_eq!(rec.resolved[0].path, "a.rs");
        assert_eq!(rec.carried.len(), 1);
        assert_eq!(rec.carried[0].path, "b.rs");
        assert!(rec.carried[0].body.starts_with("[carried"));
    }

    #[test]
    fn reconcile_reflagged_supersedes() {
        let idx = index_for("a.rs", 10, 3);
        let baseline = vec![f("a.rs", 11, Severity::Error, 0.9)];
        let new = vec![f("a.rs", 12, Severity::Error, 0.95)];
        let rec = reconcile(&baseline, &idx, &new);
        assert!(rec.resolved.is_empty());
        assert!(rec.carried.is_empty());
    }
}
