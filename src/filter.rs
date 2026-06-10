//! Post-filter findings against repo policy + diff grounding.
//!
//! Rules (applied in order):
//!   1. `.postil/model-output` findings are SACRED — they bypass every filter
//!      so a model-output failure always reaches the user.
//!   2. Drop findings whose path matches any `ignore` glob.
//!   3. Drop findings strictly below `severityThreshold`.
//!   4. Drop findings not grounded in the diff (path or line not touched). If
//!      `nearest_line` finds a close line on the same file, snap to it instead
//!      of dropping — models are bad at hunk math but the grounding is still
//!      genuine when the file matches.
//!   5. Cap to `maxFindings`, preserving severity order (Error > Warn > Info).

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::diff::ParsedDiff;
use crate::envelope::{Envelope, Finding, Severity};
use crate::repo_config::RepoConfig;

const MODEL_OUTPUT_PATH: &str = ".postil/model-output";
const DEFAULT_MAX_FINDINGS: usize = 25;
const LINE_SNAP_WINDOW: u32 = 50;

pub struct FilterReport {
    pub kept: Vec<Finding>,
    pub dropped_by_ignore: usize,
    pub dropped_by_severity: usize,
    pub dropped_by_grounding: usize,
    pub dropped_by_cap: usize,
}

pub fn apply(env: &mut Envelope, cfg: &RepoConfig, diff: &ParsedDiff) -> FilterReport {
    let ignore = build_globset(&cfg.ignore);
    let threshold = cfg.severity_threshold.unwrap_or(Severity::Info);
    let max_findings = cfg.max_findings.unwrap_or(DEFAULT_MAX_FINDINGS);

    let mut kept = Vec::with_capacity(env.findings.len());
    let mut dropped_by_ignore = 0;
    let mut dropped_by_severity = 0;
    let mut dropped_by_grounding = 0;

    for mut f in env.findings.drain(..) {
        if f.path == MODEL_OUTPUT_PATH {
            kept.push(f);
            continue;
        }
        if let Some(ref set) = ignore
            && set.is_match(&f.path)
        {
            dropped_by_ignore += 1;
            continue;
        }
        if f.severity.rank() < threshold.rank() {
            dropped_by_severity += 1;
            continue;
        }
        if !diff.touches(&f.path, f.line) {
            match diff.nearest_line(&f.path, f.line) {
                Some(snapped) if snapped.abs_diff(f.line) <= LINE_SNAP_WINDOW => {
                    f.line = snapped;
                }
                _ => {
                    dropped_by_grounding += 1;
                    continue;
                }
            }
        }
        kept.push(f);
    }

    // Severity-descending stable sort.
    kept.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));

    // Cap to max_findings, but model-output is sacred — count it separately
    // and always keep it.
    let (sacred, mut normal): (Vec<_>, Vec<_>) =
        kept.into_iter().partition(|f| f.path == MODEL_OUTPUT_PATH);
    let dropped_by_cap = if normal.len() > max_findings {
        let dropped = normal.len() - max_findings;
        normal.truncate(max_findings);
        dropped
    } else {
        0
    };
    let mut kept = sacred;
    kept.extend(normal);

    // If the only remaining content is "no findings", scrub the summary too:
    // silence is a feature.
    if kept.is_empty() && cfg.review.on_clean == crate::repo_config::OnClean::Skip {
        env.summary.clear();
    }
    env.findings = kept.clone();

    FilterReport {
        kept,
        dropped_by_ignore,
        dropped_by_severity,
        dropped_by_grounding,
        dropped_by_cap,
    }
}

fn build_globset(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        if let Ok(g) = Glob::new(p) {
            b.add(g);
        }
    }
    b.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::ParsedDiff;
    use crate::envelope::{Envelope, Finding, Severity, Usage};
    use crate::repo_config::RepoConfig;
    use std::collections::HashMap;

    fn diff_with(path: &str, lines: &[u32]) -> ParsedDiff {
        let mut m = HashMap::new();
        m.insert(path.to_string(), lines.to_vec());
        ParsedDiff { lines_by_file: m }
    }

    fn env(findings: Vec<Finding>) -> Envelope {
        Envelope {
            summary: "s".into(),
            findings,
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        }
    }

    fn f(path: &str, line: u32, sev: Severity) -> Finding {
        Finding {
            path: path.into(),
            line,
            severity: sev,
            kind: None,
            body: "b".into(),
        }
    }

    #[test]
    fn model_output_survives_all_filters() {
        let mut e = env(vec![f(".postil/model-output", 1, Severity::Error)]);
        let cfg = RepoConfig {
            ignore: vec![".postil/**".into()],
            severity_threshold: Some(Severity::Error),
            max_findings: Some(0),
            ..Default::default()
        };
        let _ = apply(&mut e, &cfg, &ParsedDiff::empty());
        assert_eq!(e.findings.len(), 1);
    }

    #[test]
    fn ignore_drops_matching_path() {
        let mut e = env(vec![f("dist/x.js", 5, Severity::Warn)]);
        let cfg = RepoConfig {
            ignore: vec!["dist/**".into()],
            ..Default::default()
        };
        let r = apply(&mut e, &cfg, &diff_with("dist/x.js", &[5]));
        assert!(e.findings.is_empty());
        assert_eq!(r.dropped_by_ignore, 1);
    }

    #[test]
    fn severity_threshold_drops_below() {
        let mut e = env(vec![
            f("a", 1, Severity::Info),
            f("a", 2, Severity::Warn),
            f("a", 3, Severity::Error),
        ]);
        let cfg = RepoConfig {
            severity_threshold: Some(Severity::Warn),
            ..Default::default()
        };
        let r = apply(&mut e, &cfg, &diff_with("a", &[1, 2, 3]));
        assert_eq!(e.findings.len(), 2);
        assert_eq!(r.dropped_by_severity, 1);
    }

    #[test]
    fn ungrounded_findings_get_dropped_or_snapped() {
        let mut e = env(vec![
            f("src/a.rs", 200, Severity::Warn),   // close-ish to 180
            f("src/a.rs", 9_000, Severity::Warn), // far
            f("src/b.rs", 5, Severity::Warn),     // wrong file
        ]);
        let cfg = RepoConfig::default();
        let r = apply(&mut e, &cfg, &diff_with("src/a.rs", &[180]));
        assert_eq!(r.dropped_by_grounding, 2);
        assert_eq!(e.findings.len(), 1);
        assert_eq!(e.findings[0].line, 180);
    }

    #[test]
    fn max_findings_caps_keeping_severity_first() {
        let mut e = env(vec![
            f("a", 1, Severity::Info),
            f("a", 2, Severity::Error),
            f("a", 3, Severity::Warn),
        ]);
        let cfg = RepoConfig {
            max_findings: Some(2),
            ..Default::default()
        };
        let _ = apply(&mut e, &cfg, &diff_with("a", &[1, 2, 3]));
        assert_eq!(e.findings.len(), 2);
        assert_eq!(e.findings[0].severity, Severity::Error);
        assert_eq!(e.findings[1].severity, Severity::Warn);
    }

    #[test]
    fn clears_summary_when_clean_and_on_clean_is_skip() {
        let mut e = env(vec![]);
        let cfg = RepoConfig::default();
        let _ = apply(&mut e, &cfg, &ParsedDiff::empty());
        assert_eq!(e.summary, "");
    }
}
