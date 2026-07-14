//! Post-model filtering: grounding, ignore globs, severity/confidence
//! thresholds, max-findings cap, and incremental baseline reconciliation.

use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::Config;
use crate::diff::DiffIndex;
use crate::envelope::{Finding, SuppressedFinding, SuppressionReason};

#[derive(Debug, Default)]
pub struct FilterOutcome {
    pub kept: Vec<Finding>,
    pub suppressed: u32,
    pub suppressed_findings: Vec<SuppressedFinding>,
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

    // Keep the grounded anchor while collapsing ranges that a forge cannot
    // resolve. A model may cite a valid start line with an end line outside the
    // hunk or in a later hunk; sending that range makes GitHub reject the whole
    // batched review.
    for finding in &mut findings {
        if finding.end_line.is_some_and(|end| {
            end > finding.line && !index.contains_range(&finding.path, finding.line, end)
        }) {
            finding.end_line = None;
        }
    }

    // Grounding: a finding must cite a line on the new side of the diff. Content-
    // policy findings may additionally cite a reserved synthetic anchor (the
    // rendered PR title/description), which only they may use — a non-content-
    // policy finding on that path is not accepted.
    let before = findings.len();
    findings.retain(|f| {
        index.contains(&f.path, f.line)
            || (f.kind == crate::envelope::Kind::ContentPolicy
                && index.contains_content_policy(&f.path, f.line))
    });
    let ungrounded = (before - findings.len()) as u32;
    let all_ungrounded = had_any && findings.is_empty();

    // Policy suppression.
    let ignore = build_ignore_set(&cfg.ignore)?;
    let mut suppressed_findings = Vec::new();
    findings.retain(|f| {
        let reason = if ignore.is_match(&f.path) {
            Some(SuppressionReason::Ignored)
        } else if f.severity < cfg.severity_threshold {
            Some(SuppressionReason::BelowSeverity)
        } else if f.confidence < cfg.min_confidence {
            Some(SuppressionReason::BelowConfidence)
        } else {
            None
        };
        if let Some(reason) = reason {
            suppressed_findings.push(SuppressedFinding {
                finding: f.clone(),
                reason,
            });
            false
        } else {
            true
        }
    });

    // Highest severity first, then confidence; cap to maxFindings.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.total_cmp(&a.confidence))
    });
    if findings.len() > cfg.max_findings {
        suppressed_findings.extend(findings[cfg.max_findings..].iter().cloned().map(|finding| {
            SuppressedFinding {
                finding,
                reason: SuppressionReason::MaxFindings,
            }
        }));
        findings.truncate(cfg.max_findings);
    }

    let suppressed = suppressed_findings.len() as u32;

    Ok(FilterOutcome {
        kept: findings,
        suppressed,
        suppressed_findings,
        ungrounded,
        all_ungrounded,
    })
}

/// Incremental reconciliation. This decides, for each finding from the previous
/// review (the baseline), whether it is now RESOLVED (drop it), SUPERSEDED by a
/// fresh finding for the same issue (drop the stale copy, the new one stands),
/// or still OPEN (CARRY it forward so the gate cannot be cleared by pushing an
/// unrelated commit).
///
/// The guiding principle is fail-closed: this is a merge gate, so when the
/// signal is ambiguous we CARRY rather than resolve or silently drop. The two
/// heuristics below are deliberately conservative because both the original
/// "touched ⇒ resolved" and "nearby ⇒ superseded" rules could clear the gate
/// over an unfixed Error.
pub struct Reconciliation {
    pub resolved: Vec<Finding>,
    pub carried: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileScope {
    Incremental,
    /// A complete full review replaces the previous review's signal. When the
    /// model run is not trustworthy, baseline findings remain carried.
    Full {
        trustworthy: bool,
    },
}

pub const CARRIED_MARKER: &str = "[carried from previous review]";

pub fn is_carried(finding: &Finding) -> bool {
    finding.body.starts_with(CARRIED_MARKER)
}

/// How close (in lines) a new finding must be to a baseline finding to be
/// considered "the same spot". Kept small; proximity alone is not enough to
/// supersede (see `supersedes`).
const REFLAG_PROXIMITY: u32 = 3;

/// True when `new` plausibly re-reports the SAME issue as the baseline finding
/// `base` (so the fresh copy supersedes the stale one). Proximity alone is not
/// sufficient: an unrelated low-severity finding landing near an unfixed Error
/// must not erase the Error from the gate. We require same path, same kind, and
/// comparable-or-higher severity (`new.severity >= base.severity`). Anything
/// weaker is treated as a different, coexisting issue and the baseline is
/// carried.
fn supersedes(base: &Finding, new: &Finding) -> bool {
    if base.path == crate::envelope::CHANGE_METADATA_PATH
        || new.path == crate::envelope::CHANGE_METADATA_PATH
    {
        return base.path == new.path && base.id.is_some() && base.id == new.id;
    }
    new.path == base.path
        && new.line.abs_diff(base.line) <= REFLAG_PROXIMITY
        && new.kind == base.kind
        && new.severity >= base.severity
}

/// Whether the reviewed diff plausibly ADDRESSES the baseline finding (so it
/// can be declared resolved). Interval overlap (`touches`) is too loose: a
/// finding with a wide `end_line` span (e.g. 5..40) would be resolved by a
/// single one-line edit anywhere inside it, even if the bug is untouched. We
/// only resolve when the diff touches the finding's ANCHOR line itself (the
/// `line`, where the model pinned the issue), not merely somewhere in its span.
/// This still cannot prove the edit fixed the bug — the model staying silent the
/// next run is the real confirmation we lack — but it removes the worst
/// false-resolve (wide-span / distant-touch) and fails closed (carry) when the
/// edit landed elsewhere in the span.
///
/// Incremental baselines cite the OLD head, so their anchors must be checked
/// against old-side hunk coordinates. A trustworthy full review is
/// authoritative over the complete PR and resolves any baseline issue the
/// fresh model run did not reproduce.
fn touch_addresses(index: &DiffIndex, f: &Finding, scope: ReconcileScope) -> bool {
    match scope {
        ReconcileScope::Incremental => index.contains_old(&f.path, f.line),
        ReconcileScope::Full { trustworthy } => trustworthy,
    }
}

pub fn reconcile(
    baseline: &[Finding],
    index: &DiffIndex,
    new_findings: &[Finding],
    scope: ReconcileScope,
) -> Reconciliation {
    let mut resolved = Vec::new();
    let mut carried = Vec::new();
    for f in baseline {
        // Operational virtual findings never carry forward; each run re-earns
        // trust and re-detects its own limits. Reviewable PR-description and
        // change-metadata findings remain durable until a full review clears
        // them or a fresh finding supersedes them.
        if crate::envelope::is_ephemeral_anchor(&f.path) {
            continue;
        }
        let superseded = new_findings.iter().any(|n| supersedes(f, n));
        if superseded {
            // A fresh, same-issue finding stands in for the baseline; the new
            // copy is already in `new_findings` and will reach the gate.
            continue;
        }
        if touch_addresses(index, f, scope) {
            // An incremental edit touched the old-head anchor, or a trustworthy
            // full review did not reproduce the issue: treat it as resolved.
            // Incremental touch is imperfect because a non-fixing edit can also
            // resolve it, but a full re-review re-detects a still-broken issue.
            resolved.push(f.clone());
        } else {
            // Not superseded and the anchor line was not touched: the issue
            // persists. Carry it forward (fail-closed) so an unrelated nearby
            // finding or a distant in-span edit cannot clear the gate.
            let mut carry = f.clone();
            if !is_carried(&carry) {
                carry.body = format!("{CARRIED_MARKER}\n\n{}", carry.body);
            }
            carried.push(carry);
        }
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

    fn index_for(path: &str, start: u32, count: u32) -> DiffIndex {
        let text = format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -{start},{count} +{start},{count} @@\n{}",
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
    fn grounding_collapses_invalid_and_cross_hunk_ranges() {
        let parsed = diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10,3 +10,3 @@\n+x\n+y\n+z\n@@ -30,2 +30,2 @@\n+a\n+b\n",
        );
        let idx = DiffIndex::build(&parsed);
        let cfg = Config::default();
        let mut valid = f("a.rs", 10, Severity::Error, 0.9);
        valid.end_line = Some(12);
        let mut cross_hunk = f("a.rs", 11, Severity::Error, 0.9);
        cross_hunk.end_line = Some(30);
        let mut outside = f("a.rs", 30, Severity::Error, 0.9);
        outside.end_line = Some(99);

        let out = apply(&cfg, &idx, vec![valid, cross_hunk, outside]).unwrap();
        assert_eq!(out.kept[0].end_line, Some(12));
        assert!(out.kept[1].end_line.is_none());
        assert!(out.kept[2].end_line.is_none());
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
    fn content_policy_finding_grounds_on_reserved_path() {
        // A contentPolicy finding on the reserved PR-description anchor survives
        // grounding when the anchor range is registered; a non-contentPolicy
        // finding on the same anchor does not.
        let mut idx = index_for("a.rs", 1, 5);
        idx.add_content_policy_path(crate::envelope::PR_DESCRIPTION_PATH, 3);
        let cfg = Config::default();

        let mut cp = f(
            crate::envelope::PR_DESCRIPTION_PATH,
            2,
            Severity::Error,
            0.9,
        );
        cp.kind = Kind::ContentPolicy;
        let out = apply(&cfg, &idx, vec![cp]).unwrap();
        assert_eq!(
            out.kept.len(),
            1,
            "content-policy PR-body finding was dropped"
        );
        assert!(!out.all_ungrounded);

        // A risk-kind finding on the reserved path is not groundable there.
        let risk = f(
            crate::envelope::PR_DESCRIPTION_PATH,
            2,
            Severity::Error,
            0.9,
        );
        let out = apply(&cfg, &idx, vec![risk]).unwrap();
        assert!(out.kept.is_empty());
        assert!(out.all_ungrounded);

        // Out-of-range content-policy line is still rejected.
        let mut oob = f(
            crate::envelope::PR_DESCRIPTION_PATH,
            9,
            Severity::Error,
            0.9,
        );
        oob.kind = Kind::ContentPolicy;
        let out = apply(&cfg, &idx, vec![oob]).unwrap();
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
        assert_eq!(
            out.suppressed_findings[0].reason,
            SuppressionReason::BelowSeverity
        );
        assert_eq!(
            out.suppressed_findings[1].reason,
            SuppressionReason::BelowConfidence
        );
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
        assert_eq!(out.suppressed_findings.len(), 1);
        assert_eq!(
            out.suppressed_findings[0].reason,
            SuppressionReason::MaxFindings
        );
        assert_eq!(out.kept[0].severity, Severity::Error);
        assert_eq!(out.suppressed, 1);
    }

    #[test]
    fn reconcile_resolves_touched_carries_untouched() {
        let idx = index_for("a.rs", 10, 3); // incremental diff touches a.rs:10-12
        let baseline = vec![
            f("a.rs", 11, Severity::Error, 0.9), // touched → resolved
            f("b.rs", 5, Severity::Warn, 0.8),   // untouched → carried
            f(".postil/content-policy.md", 7, Severity::Warn, 0.8),
            f(".postil/model-output", 1, Severity::Error, 1.0), // synthetic → dropped
        ];
        let rec = reconcile(&baseline, &idx, &[], ReconcileScope::Incremental);
        assert_eq!(rec.resolved.len(), 1);
        assert_eq!(rec.resolved[0].path, "a.rs");
        assert_eq!(rec.carried.len(), 2);
        assert_eq!(rec.carried[0].path, "b.rs");
        assert!(rec.carried[0].body.starts_with("[carried"));
        assert_eq!(rec.carried[1].path, ".postil/content-policy.md");
        assert!(rec.carried[1].body.starts_with("[carried"));
    }

    #[test]
    fn reviewable_virtual_anchors_carry_but_operational_anchors_expire() {
        let idx = index_for("unrelated.rs", 1, 1);
        let baseline = vec![
            f(
                crate::envelope::CHANGE_METADATA_PATH,
                1,
                Severity::Error,
                0.9,
            ),
            f(crate::envelope::PR_DESCRIPTION_PATH, 1, Severity::Warn, 0.8),
            f(crate::envelope::OPERATIONAL_PATH, 1, Severity::Error, 1.0),
            f(crate::envelope::PROVIDER_PATH, 1, Severity::Error, 1.0),
        ];
        let rec = reconcile(&baseline, &idx, &[], ReconcileScope::Incremental);
        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 2);
        assert_eq!(rec.carried[0].path, crate::envelope::CHANGE_METADATA_PATH);
        assert_eq!(rec.carried[1].path, crate::envelope::PR_DESCRIPTION_PATH);
    }

    #[test]
    fn unrelated_change_metadata_at_same_line_never_supersedes() {
        let idx = index_for("unrelated.rs", 1, 1);
        let mut baseline = f(
            crate::envelope::CHANGE_METADATA_PATH,
            1,
            Severity::Error,
            0.9,
        );
        baseline.id = Some("dependency-a".into());
        let mut fresh = f(
            crate::envelope::CHANGE_METADATA_PATH,
            1,
            Severity::Error,
            0.9,
        );
        fresh.id = Some("dependency-b".into());
        let rec = reconcile(&[baseline], &idx, &[fresh], ReconcileScope::Incremental);
        assert_eq!(rec.carried.len(), 1);
        assert!(rec.resolved.is_empty());
    }

    #[test]
    fn reconcile_reflagged_supersedes() {
        let idx = index_for("a.rs", 10, 3);
        let baseline = vec![f("a.rs", 11, Severity::Error, 0.9)];
        let new = vec![f("a.rs", 12, Severity::Error, 0.95)];
        let rec = reconcile(&baseline, &idx, &new, ReconcileScope::Incremental);
        assert!(rec.resolved.is_empty());
        assert!(rec.carried.is_empty());
    }

    // H1: an unrelated, lower-severity new finding near an unfixed baseline
    // Error must NOT supersede it. The baseline line is not touched by the
    // incremental diff, so the Error has to be carried (gate still fails).
    #[test]
    fn reconcile_unrelated_nearby_finding_does_not_drop_baseline_error() {
        let idx = index_for("z.rs", 100, 1); // incremental diff is elsewhere
        let baseline = vec![f("a.rs", 10, Severity::Error, 0.9)];
        let new = vec![f("a.rs", 12, Severity::Info, 0.9)]; // unrelated, lower sev
        let rec = reconcile(&baseline, &idx, &new, ReconcileScope::Incremental);
        assert_eq!(rec.resolved.len(), 0);
        assert_eq!(rec.carried.len(), 1, "baseline Error was dropped");
        assert_eq!(rec.carried[0].severity, Severity::Error);
        assert!(rec.carried[0].body.starts_with("[carried"));
    }

    // H1 (companion): a comparable-or-higher severity, same-kind finding at the
    // same spot DOES supersede — the original carry-forward design intent.
    #[test]
    fn reconcile_same_issue_higher_severity_supersedes() {
        let idx = index_for("z.rs", 100, 1);
        let baseline = vec![f("a.rs", 10, Severity::Warn, 0.9)];
        let new = vec![f("a.rs", 11, Severity::Error, 0.9)];
        let rec = reconcile(&baseline, &idx, &new, ReconcileScope::Incremental);
        assert!(rec.resolved.is_empty());
        assert!(rec.carried.is_empty(), "same-issue reflag should supersede");
    }

    // H2: a wide-span baseline Error (5..40) whose ANCHOR line (5) is not in the
    // incremental diff must not be auto-resolved by a single unrelated touch at
    // line 30 inside its span. With no reflag, it is carried (fail-closed).
    #[test]
    fn reconcile_wide_span_distant_touch_is_not_resolved() {
        let idx = index_for("a.rs", 30, 1); // touches only a.rs:30
        let mut wide = f("a.rs", 5, Severity::Error, 0.9);
        wide.end_line = Some(40);
        let rec = reconcile(&[wide], &idx, &[], ReconcileScope::Incremental);
        assert_eq!(rec.resolved.len(), 0, "wide-span finding falsely resolved");
        assert_eq!(rec.carried.len(), 1);
        assert_eq!(rec.carried[0].severity, Severity::Error);
    }

    #[test]
    fn reconcile_uses_old_head_coordinates_for_rewritten_anchor() {
        // PR 314 regression: the baseline finding cited old-head line 99. The
        // rewrite touched it in an old-side 93..109 hunk which moved to new-side
        // 133..159. Looking for new-side line 99 misses the edit and carries a
        // stale finding forever.
        let text = format!(
            "diff --git a/src/components/code-copy-enhancer.tsx b/src/components/code-copy-enhancer.tsx\n\
             --- a/src/components/code-copy-enhancer.tsx\n\
             +++ b/src/components/code-copy-enhancer.tsx\n\
             @@ -93,17 +133,27 @@ export function CodeCopyEnhancer() {{\n{}{}",
            "-old line\n".repeat(17),
            "+new line\n".repeat(27)
        );
        let idx = DiffIndex::build(&diff::parse(&text));
        assert!(idx.contains_old("src/components/code-copy-enhancer.tsx", 99));
        assert!(!idx.contains("src/components/code-copy-enhancer.tsx", 99));

        let baseline = f(
            "src/components/code-copy-enhancer.tsx",
            99,
            Severity::Error,
            0.9,
        );
        let rec = reconcile(&[baseline], &idx, &[], ReconcileScope::Incremental);
        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn trustworthy_full_review_resolves_findings_it_does_not_reproduce() {
        let idx = index_for("other.rs", 1, 1);
        let baseline = vec![f("a.rs", 99, Severity::Error, 0.9)];
        let rec = reconcile(
            &baseline,
            &idx,
            &[],
            ReconcileScope::Full { trustworthy: true },
        );
        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn failed_full_review_keeps_baseline_findings_open() {
        let idx = index_for("a.rs", 1, 100);
        let baseline = vec![f("a.rs", 99, Severity::Error, 0.9)];
        let rec = reconcile(
            &baseline,
            &idx,
            &[],
            ReconcileScope::Full { trustworthy: false },
        );
        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
    }
}
