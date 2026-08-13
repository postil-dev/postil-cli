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
    findings.retain(|f| index.contains_exact_evidence(f));
    let ungrounded = (before - findings.len()) as u32;
    let all_ungrounded = had_any && findings.is_empty();

    let mut suppressed_findings = Vec::new();

    // Anchor corroboration. Grounding proves the cited line exists and that the
    // quoted evidence is its text; it does not prove the finding is ABOUT that
    // line. A model that reasons correctly about one construct and cites
    // another produces a claim no reader can check against the code in front of
    // them, and any later rule that builds on the citation inherits the error.
    let mismatched: Vec<Finding> = {
        let mut mismatched = Vec::new();
        findings.retain(|f| {
            if anchor_verdict(index, f) == AnchorVerdict::Mismatched {
                mismatched.push(f.clone());
                suppressed_findings.push(SuppressedFinding {
                    finding: f.clone(),
                    reason: SuppressionReason::AnchorMismatch,
                });
                false
            } else {
                true
            }
        });
        mismatched
    };

    // Content-policy claims are second-order: they compare the PR's own prose
    // against what the diff does. When the "what the diff does" half came from a
    // finding that misread the diff, the content-policy claim is an accusation
    // built on that misreading, so it falls with it rather than outliving it at
    // a higher confidence than the finding it rests on.
    apply_derived_confidence(&mut findings, &mismatched, &mut suppressed_findings);

    // Policy suppression.
    let ignore = build_ignore_set(&cfg.ignore)?;
    findings.retain(|f| {
        let reason = if deterministically_non_actionable(f) {
            Some(SuppressionReason::NonActionable)
        } else if ignore.is_match(&f.path) {
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

    // One observation replicated across every file it touches is one finding,
    // not one per file. Collapsing here rather than at the model boundary keeps
    // the collapse honest: the retained copy names the other locations, so the
    // reader still learns the full extent of the issue.
    collapse_shared_root_cause(&mut findings, &mut suppressed_findings);

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

/// How far from its cited line a named construct may sit and still corroborate
/// the anchor. Wide enough to span a function signature, a systemd unit stanza,
/// or a YAML task block, so a finding that pins the top of a construct and
/// discusses a key further down still corroborates.
const ANCHOR_CORROBORATION_WINDOW: u32 = 12;

/// Shortest quoted span treated as a locatable construct. Below this, a token
/// matches too much of any file to say anything about where a finding belongs.
const MIN_CONSTRUCT_CHARS: usize = 4;

/// Longest quoted span treated as a locatable construct. A longer quote is
/// prose being quoted, not an identifier being named.
const MAX_CONSTRUCT_CHARS: usize = 80;

/// Most words a delimited span may carry and still be a name rather than a
/// sentence. Long enough for a descriptive task or test name.
const MAX_CONSTRUCT_WORDS: usize = 6;

/// How much prose a finding must carry before two copies of it can be judged
/// the same observation. A real finding states a claim in sentences; a pair
/// that matches on less than this has not earned a collapse.
const MIN_ROOT_CAUSE_TOKENS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorVerdict {
    /// A construct the finding names sits at or near the cited line.
    Corroborated,
    /// Every construct the finding names sits elsewhere on the same path.
    Mismatched,
    /// The finding names nothing the diff can locate, so the anchor can be
    /// neither confirmed nor contradicted. Grounding already passed; leave it.
    Unlocatable,
}

/// Decide whether a finding's own prose corroborates the line it cites.
///
/// Two things have to hold for a citation to be checkable. The constructs the
/// finding names must reach the anchor, and they must sit close enough together
/// that the relationship the finding asserts between them exists at one place
/// in the file. A finding fails the first when it simply wrote down the wrong
/// number. It fails the second when it correctly read several constructs and
/// then described them as one — the production case, where a password task, its
/// `no_log`, and an unrelated task's `diff: false` were reported as a single
/// edit sixteen lines apart.
///
/// Neither failure is inferred from silence. A finding that names nothing the
/// diff can locate is `Unlocatable` and stands on the grounding check alone.
fn anchor_verdict(index: &DiffIndex, finding: &Finding) -> AnchorVerdict {
    if crate::envelope::is_reserved_anchor(&finding.path) || !index.has_new_side_text(&finding.path)
    {
        return AnchorVerdict::Unlocatable;
    }
    let anchor_end = finding.end_line.unwrap_or(finding.line);
    // Read each construct at the occurrence most favourable to the finding: the
    // one nearest its anchor. If the claim does not hold together even there, it
    // does not hold together anywhere.
    let mut located: Vec<u32> = Vec::new();
    for construct in named_constructs(finding) {
        let lines = index.new_side_lines_containing(&finding.path, &construct);
        if let Some(nearest) = lines
            .into_iter()
            .min_by_key(|line| line.abs_diff(finding.line).min(line.abs_diff(anchor_end)))
        {
            located.push(nearest);
        }
    }
    if located.is_empty() {
        return AnchorVerdict::Unlocatable;
    }

    let low = finding.line.saturating_sub(ANCHOR_CORROBORATION_WINDOW);
    let high = anchor_end.saturating_add(ANCHOR_CORROBORATION_WINDOW);
    if !located.iter().any(|line| (low..=high).contains(line)) {
        return AnchorVerdict::Mismatched;
    }

    let nearest = *located.iter().min().expect("located is non-empty");
    let furthest = *located.iter().max().expect("located is non-empty");
    if furthest - nearest > ANCHOR_CORROBORATION_WINDOW {
        return AnchorVerdict::Mismatched;
    }
    AnchorVerdict::Corroborated
}

/// Constructs a finding names in its own prose: the spans it puts in backticks
/// or double quotes that look like code rather than like English.
fn named_constructs(finding: &Finding) -> Vec<String> {
    let mut constructs = Vec::new();
    let own_basename = finding.path.rsplit('/').next().unwrap_or(&finding.path);
    for text in [finding.title.as_str(), finding.body.as_str()] {
        // Backticks and quotes are not equivalent. A backticked span is a
        // literal being named — an identifier, a key, a task title. A
        // double-quoted span is as often a quoted sentence, so it has to look
        // like code before it counts.
        for (delimiter, prose_allowed) in [('`', true), ('"', false)] {
            let mut parts = text.split(delimiter);
            // A split on a paired delimiter alternates outside/inside; only the
            // odd indices are quoted spans, and a trailing unpaired delimiter
            // leaves a final outside part that is correctly skipped.
            parts.next();
            while let Some(span) = parts.next() {
                if parts.next().is_none() {
                    break;
                }
                let span = span.trim();
                if !is_locatable_construct(span, prose_allowed) {
                    continue;
                }
                // The finding's own path is metadata about where it points, not
                // a construct at the line it points to.
                if span == finding.path || span == own_basename {
                    continue;
                }
                if !constructs.iter().any(|existing| existing == span) {
                    constructs.push(span.to_string());
                }
            }
        }
    }
    constructs
}

/// Whether a delimited span names something the diff could contain.
///
/// `prose_allowed` relaxes the code-shape test for spans the author marked as
/// literals. A named Ansible task or test case carries no punctuation and no
/// camel case, and rejecting it loses the one construct that pins where a
/// finding belongs. The relaxation is safe because an extracted span only ever
/// matters when the diff actually contains it.
fn is_locatable_construct(span: &str, prose_allowed: bool) -> bool {
    let chars = span.chars().count();
    if !(MIN_CONSTRUCT_CHARS..=MAX_CONSTRUCT_CHARS).contains(&chars) {
        return false;
    }
    let words = span.split_whitespace().count();
    if span.contains('\n') || words > MAX_CONSTRUCT_WORDS {
        return false;
    }
    if prose_allowed {
        return true;
    }
    let code_punctuation = span
        .chars()
        .any(|c| matches!(c, '_' | '.' | ':' | '/' | '-' | '=' | '(' | '[' | '{'));
    let has_digit = span.chars().any(|c| c.is_ascii_digit());
    let inner_capital = span
        .chars()
        .zip(span.chars().skip(1))
        .any(|(previous, next)| previous.is_ascii_lowercase() && next.is_ascii_uppercase());
    code_punctuation || has_digit || inner_capital
}

/// Cap a content-policy finding's confidence at that of the code finding it
/// argues from, and drop it outright when every finding it argues from was
/// suppressed as mis-anchored.
///
/// A content-policy finding says "the PR description claims X but the change
/// does Y". The "does Y" half is only ever as reliable as the reading of the
/// diff that produced it. Left uncapped, a 0.60-confidence misreading becomes a
/// 0.95-confidence accusation that the author described their own change
/// falsely, which is both the most damaging thing this reviewer can say and the
/// claim it has the least independent basis for.
fn apply_derived_confidence(
    findings: &mut Vec<Finding>,
    mismatched: &[Finding],
    suppressed_findings: &mut Vec<SuppressedFinding>,
) {
    let sources: Vec<(String, f64)> = findings
        .iter()
        .filter(|f| f.kind != crate::envelope::Kind::ContentPolicy)
        .map(|f| (f.path.clone(), f.confidence))
        .collect();
    let mismatched_paths: Vec<String> = mismatched
        .iter()
        .filter(|f| f.kind != crate::envelope::Kind::ContentPolicy)
        .map(|f| f.path.clone())
        .collect();

    let mut derived_only_from_suppressed = Vec::new();
    for finding in findings.iter_mut() {
        if finding.kind != crate::envelope::Kind::ContentPolicy {
            continue;
        }
        let ceiling = sources
            .iter()
            .filter(|(path, _)| references_path(finding, path))
            .map(|(_, confidence)| *confidence)
            .fold(f64::NEG_INFINITY, f64::max);
        if ceiling.is_finite() {
            finding.confidence = finding.confidence.min(ceiling);
            continue;
        }
        // No surviving finding backs this claim. If the claim points at a path
        // whose only finding was suppressed as mis-anchored, it is that
        // misreading restated as an accusation.
        if mismatched_paths
            .iter()
            .any(|path| references_path(finding, path))
        {
            derived_only_from_suppressed.push(finding.clone());
        }
    }
    if derived_only_from_suppressed.is_empty() {
        return;
    }
    findings.retain(|finding| {
        let dropped = derived_only_from_suppressed
            .iter()
            .any(|candidate| finding_identity(candidate) == finding_identity(finding));
        if dropped {
            suppressed_findings.push(SuppressedFinding {
                finding: finding.clone(),
                reason: SuppressionReason::DerivedFromSuppressed,
            });
        }
        !dropped
    });
}

/// Whether a finding's prose points at `path`, by full path or by basename.
fn references_path(finding: &Finding, path: &str) -> bool {
    if crate::envelope::is_reserved_anchor(path) {
        return false;
    }
    let basename = path.rsplit('/').next().unwrap_or(path);
    let haystack = format!("{} {}", finding.title, finding.body).to_ascii_lowercase();
    haystack.contains(&path.to_ascii_lowercase())
        || (basename.contains('.') && haystack.contains(&basename.to_ascii_lowercase()))
}

fn finding_identity(finding: &Finding) -> (String, u32, String, String) {
    (
        finding.path.clone(),
        finding.line,
        finding.title.clone(),
        finding.body.clone(),
    )
}

/// Collapse findings that make the same claim about different locations into
/// one finding that names them all.
///
/// The retained copy is the most confident, breaking ties toward the earliest
/// location so the choice is stable across runs.
fn collapse_shared_root_cause(
    findings: &mut Vec<Finding>,
    suppressed_findings: &mut Vec<SuppressedFinding>,
) {
    use std::collections::HashMap;

    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (position, finding) in findings.iter().enumerate() {
        if crate::envelope::is_reserved_anchor(&finding.path) || is_carried(finding) {
            continue;
        }
        let Some(key) = root_cause_key(finding) else {
            continue;
        };
        if groups.entry(key.clone()).or_default().is_empty() {
            order.push(key.clone());
        }
        groups
            .get_mut(&key)
            .expect("group just inserted")
            .push(position);
    }

    let mut drop_positions = std::collections::HashSet::new();
    for key in &order {
        let positions = &groups[key];
        if positions.len() < 2 {
            continue;
        }
        let keep = *positions
            .iter()
            .min_by(|left, right| {
                let a = &findings[**left];
                let b = &findings[**right];
                b.confidence
                    .total_cmp(&a.confidence)
                    .then_with(|| a.path.cmp(&b.path))
                    .then_with(|| a.line.cmp(&b.line))
            })
            .expect("group is non-empty");
        let mut others: Vec<String> = positions
            .iter()
            .filter(|position| **position != keep)
            .map(|position| format!("{}:{}", findings[*position].path, findings[*position].line))
            .collect();
        others.sort();
        for position in positions {
            if *position != keep {
                drop_positions.insert(*position);
            }
        }
        annotate_shared_locations(&mut findings[keep], &others);
    }
    if drop_positions.is_empty() {
        return;
    }
    let mut position = 0;
    findings.retain(|finding| {
        let dropped = drop_positions.contains(&position);
        position += 1;
        if dropped {
            suppressed_findings.push(SuppressedFinding {
                finding: finding.clone(),
                reason: SuppressionReason::DuplicateRootCause,
            });
        }
        !dropped
    });
}

/// The claim a finding makes, with the location it makes it about removed.
/// Two findings share a root cause when only their locations differ.
///
/// Returns `None` for prose too short to identify a claim. Two findings that
/// agree on a handful of words have not been shown to be the same observation,
/// and collapsing them would hide a real second defect.
fn root_cause_key(finding: &Finding) -> Option<String> {
    let prose = format!("{}\n{}", finding.title, finding.body);
    let mut normalized = String::with_capacity(prose.len());
    let mut tokens = 0usize;
    for token in prose.split_whitespace() {
        tokens += 1;
        let trimmed = token.trim_matches(|c: char| !c.is_alphanumeric());
        let path_like = trimmed.contains('/')
            || (trimmed.contains('.')
                && trimmed.rsplit('.').next().is_some_and(|extension| {
                    !extension.is_empty() && extension.chars().all(|c| c.is_ascii_alphabetic())
                }));
        if path_like {
            normalized.push_str("<path> ");
        } else if trimmed.chars().any(|c| c.is_ascii_digit()) {
            normalized.push_str("<n> ");
        } else {
            normalized.push_str(&token.to_ascii_lowercase());
            normalized.push(' ');
        }
    }
    if tokens < MIN_ROOT_CAUSE_TOKENS {
        return None;
    }
    Some(format!(
        "{}|{}|{}",
        finding.kind.as_str(),
        finding.severity.as_str(),
        normalized.trim()
    ))
}

/// Append the other locations sharing this finding's cause, but never at the
/// cost of the finding's publishability: forge sinks must not repair prose, so
/// a note that would push the body past the publication limits is dropped
/// rather than truncated.
fn annotate_shared_locations(finding: &mut Finding, others: &[String]) {
    if others.is_empty() {
        return;
    }
    let note = format!(
        "\n\nThe same issue appears at {}.",
        others
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut annotated = finding.clone();
    annotated.body = format!("{}{note}", finding.body);
    if crate::envelope::validate_finding_publication(&annotated).is_ok() {
        finding.body = annotated.body;
    }
}

/// Strip blocking severity from `uncertainty` findings that only ask the author
/// to check something.
///
/// This runs last, after uncertainty resolution has had its chance to turn a
/// question into an evidenced claim and after policy thresholds have been
/// applied to the severity the model asked for. The order matters in both
/// directions: resolving first means a finding that did the work keeps its
/// severity, and demoting after thresholds means the question stays visible
/// instead of dropping below a `warn` floor and disappearing.
pub fn demote_deferred_verification(findings: &mut [Finding]) {
    for finding in findings {
        if defers_verification_to_the_author(finding) {
            finding.severity = crate::envelope::Severity::Info;
        }
    }
}

/// Whether an `uncertainty` finding only asks the author to check something.
///
/// "Confirm that X is always created" is a question, not a finding. It costs
/// the author the verification work the reviewer was supposed to do, and it
/// does so at a severity that can gate a merge. Repository-wide support is
/// represented by a structured receipt, so prose about search work is not
/// treated as proof.
fn defers_verification_to_the_author(finding: &Finding) -> bool {
    if finding.kind != crate::envelope::Kind::Uncertainty
        || finding.severity == crate::envelope::Severity::Info
        || crate::envelope::is_reserved_anchor(&finding.path)
    {
        return false;
    }
    // The ask is read from the body alone. A title is a headline and is
    // routinely imperative ("Verify the caller contract") even for a finding
    // whose body then goes and establishes the answer; demoting on the headline
    // would punish exactly the findings that did the work.
    let body = finding.body.to_ascii_lowercase();
    [
        "confirm that",
        "confirm the",
        "please confirm",
        "verify that",
        "verify the",
        "please verify",
        "double-check",
        "make sure that",
        "ensure that",
        "check whether",
        "check that",
    ]
    .iter()
    .any(|marker| body.contains(marker))
}

fn deterministically_non_actionable(finding: &Finding) -> bool {
    let title = finding.title.to_ascii_lowercase();
    let body = finding.body.to_ascii_lowercase();
    let evidence = finding
        .evidence
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let concrete_impact = [
        "will fail",
        "returns the wrong",
        "data loss",
        "corrupt",
        "unauthorized",
        "injection",
        "panic",
        "deadlock",
        "race condition",
        "breaks ",
    ]
    .iter()
    .any(|marker| title.contains(marker) || body.contains(marker));
    let generic_remedy = title.contains("without justification")
        || body.contains("add a comment explaining")
        || body.contains("add an explanation for")
        || body.contains("add documentation for");
    if generic_remedy && !concrete_impact {
        return true;
    }

    let test_path = finding.path.split('/').any(|part| {
        matches!(part, "test" | "tests" | "__tests__")
            || part.contains("_test")
            || part.contains(".test.")
            || part.contains(".spec.")
    });
    let credential_claim = title.contains("credential")
        || title.contains("secret")
        || title.contains("token")
        || body.contains("credential")
        || body.contains("secret")
        || body.contains("token");
    let inert_value = [
        "test-", "test_", "dummy", "example", "fake", "mock", "\"\"", "''",
    ]
    .iter()
    .any(|marker| evidence.contains(marker));
    let production_reachable = [
        "production code uses",
        "production path accepts",
        "reachable from production",
        "deployed credential",
    ]
    .iter()
    .any(|marker| body.contains(marker));
    if test_path && credential_claim && inert_value && !production_reachable {
        return true;
    }

    if finding.kind == crate::envelope::Kind::ContentPolicy {
        let absence_only = (title.contains("fabricat") || body.contains("fabricat"))
            && [
                "diff does not prove",
                "diff does not add",
                "does not prove it",
            ]
            .iter()
            .any(|marker| body.contains(marker));
        let deleted_contradiction =
            title.contains("self-contradict") && body.contains("remove the first line");
        if absence_only || deleted_contradiction {
            return true;
        }
        let product_model_language = evidence.contains("model-authored")
            && ["reply", "response", "reject", "validate", "parse", "return"]
                .iter()
                .any(|marker| evidence.contains(marker));
        let actual_authorship_residue = ["as an ai", "written by", "generated by", "i cannot"]
            .iter()
            .any(|marker| evidence.contains(marker));
        if product_model_language
            && (title.contains("authorship") || body.contains("authorship"))
            && !actual_authorship_residue
        {
            return true;
        }
    }
    false
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
pub enum ReviewTrust {
    /// At least one required model request failed or returned unusable output.
    Failed,
    /// Every selected request completed, but the model saw only a bounded
    /// subset of the complete review input.
    Bounded,
    /// Every source batch in the review input completed successfully.
    Exhaustive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileScope {
    Incremental { trust: ReviewTrust },
    Full { trust: ReviewTrust },
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
    if defect_identity(base) == defect_identity(new) && new.severity >= base.severity {
        return true;
    }
    new.path == base.path
        && new.line.abs_diff(base.line) <= REFLAG_PROXIMITY
        && new.kind == base.kind
        && new.severity >= base.severity
}

fn defect_identity(finding: &Finding) -> (String, crate::envelope::Kind, String, Option<String>) {
    (
        finding.path.to_ascii_lowercase(),
        finding.kind,
        finding.title.trim().to_ascii_lowercase(),
        finding.evidence.clone(),
    )
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
        ReconcileScope::Incremental { .. } => index.contains_old(&f.path, f.line),
        ReconcileScope::Full { trust } => trust == ReviewTrust::Exhaustive,
    }
}

fn push_carried(
    carried: &mut Vec<Finding>,
    identities: &mut std::collections::HashSet<(
        String,
        crate::envelope::Kind,
        String,
        Option<String>,
    )>,
    mut finding: Finding,
) {
    if !is_carried(&finding) {
        finding.body = format!("{CARRIED_MARKER}\n\n{}", finding.body);
    }
    let identity = defect_identity(&finding);
    if identities.insert(identity) {
        carried.push(finding);
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
    let mut carried_identities = std::collections::HashSet::new();
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
        if let ReconcileScope::Incremental { trust } = scope
            && index.contains_old(&f.path, f.line)
        {
            if index.old_evidence_matches(f)
                && let Some((path, line)) = index.remap_current_evidence(f)
            {
                let mut carry = f.clone();
                carry.path = path;
                carry.line = line;
                carry.end_line = None;
                push_carried(&mut carried, &mut carried_identities, carry);
            } else if trust == ReviewTrust::Exhaustive
                || (trust == ReviewTrust::Bounded
                    && f.evidence.is_some()
                    && index.contains_reviewed_baseline_coordinate(f))
            {
                resolved.push(f.clone());
            } else {
                push_carried(&mut carried, &mut carried_identities, f.clone());
            }
        } else if let ReconcileScope::Full {
            trust: ReviewTrust::Bounded,
        } = scope
        {
            if let Some((path, line)) = index.remap_current_evidence(f) {
                if index.remap_reviewed_evidence(f).as_ref() == Some(&(path.clone(), line)) {
                    // The selected model input contained this exact current
                    // anchor and the model did not reproduce it.
                    resolved.push(f.clone());
                } else {
                    // The issue's evidence remains in an unselected part of
                    // the full diff. Keep it open at its current coordinate.
                    let mut carry = f.clone();
                    carry.path = path;
                    carry.line = line;
                    carry.end_line = None;
                    push_carried(&mut carried, &mut carried_identities, carry);
                }
            } else if f.evidence.is_some()
                && f.path != crate::envelope::CHANGE_METADATA_PATH
                && index.contains_reviewed_baseline_coordinate(f)
            {
                // The selected input covered this coordinate and the complete
                // current diff no longer contains the exact citation. The
                // completed model request did not reproduce the issue.
                resolved.push(f.clone());
            } else {
                // Changed evidence outside the selected input, historical
                // findings without canonical evidence, and virtual change
                // metadata remain open.
                push_carried(&mut carried, &mut carried_identities, f.clone());
            }
        } else if touch_addresses(index, f, scope) {
            // An incremental edit touched the old-head anchor, or a trustworthy
            // full review did not reproduce the issue: treat it as resolved.
            // Incremental touch is imperfect because a non-fixing edit can also
            // resolve it, but a full re-review re-detects a still-broken issue.
            resolved.push(f.clone());
        } else {
            // Not superseded and the anchor line was not touched: the issue
            // persists. Carry it forward (fail-closed) so an unrelated nearby
            // finding or a distant in-span edit cannot clear the gate.
            push_carried(&mut carried, &mut carried_identities, f.clone());
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
            repository_claim: None,
            title: "t".into(),
            body: "b".into(),
            evidence: Some("x".into()),
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
        cross_hunk.evidence = Some("y".into());
        cross_hunk.end_line = Some(30);
        let mut outside = f("a.rs", 30, Severity::Error, 0.9);
        outside.evidence = Some("a".into());
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
        idx.add_content_policy_evidence(
            crate::envelope::PR_DESCRIPTION_PATH,
            "### .postil/pr-description\n     1   first\n     2   x\n     3   third\n",
        );
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
    fn guard_71_generic_shell_justification_is_suppressed() {
        let parsed = diff::parse(
            "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n+      shell: bash\n",
        );
        let idx = DiffIndex::build(&parsed);
        let mut finding = f(".github/workflows/ci.yml", 1, Severity::Warn, 0.9);
        finding.title = "Avoid shell override without justification".into();
        finding.body =
            "The shell override lacks context. Add a comment explaining why bash is required."
                .into();
        finding.evidence = Some("      shell: bash".into());
        let outcome = apply(&Config::default(), &idx, vec![finding]).unwrap();
        assert!(outcome.kept.is_empty());
        assert_eq!(
            outcome.suppressed_findings[0].reason,
            SuppressionReason::NonActionable
        );
    }

    #[test]
    fn test_requests_are_not_suppressed_from_prose_alone() {
        let parsed = diff::parse(
            "diff --git a/src/client.rs b/src/client.rs\n--- a/src/client.rs\n+++ b/src/client.rs\n@@ -1 +1 @@\n+let timeout_ms = 0;\n",
        );
        let idx = DiffIndex::build(&parsed);

        let mut generic = f("src/client.rs", 1, Severity::Warn, 0.9);
        generic.title = "Add a test for the timeout setting".into();
        generic.body = "The new setting has no dedicated coverage.".into();
        generic.evidence = Some("let timeout_ms = 0;".into());
        let generic_outcome = apply(&Config::default(), &idx, vec![generic]).unwrap();
        assert_eq!(generic_outcome.kept.len(), 1);
        assert!(generic_outcome.suppressed_findings.is_empty());

        let mut concrete = f("src/client.rs", 1, Severity::Error, 0.9);
        concrete.title = "Zero timeout disables the request deadline".into();
        concrete.body = "This lets a stalled provider request hang indefinitely. Add a test for the zero-value path.".into();
        concrete.evidence = Some("let timeout_ms = 0;".into());
        let concrete_outcome = apply(&Config::default(), &idx, vec![concrete]).unwrap();
        assert_eq!(concrete_outcome.kept.len(), 1);
        assert!(concrete_outcome.suppressed_findings.is_empty());
    }

    #[test]
    fn guard_69_inert_test_token_without_production_reachability_is_suppressed() {
        let parsed = diff::parse(
            "diff --git a/tests/auth_test.rs b/tests/auth_test.rs\n--- a/tests/auth_test.rs\n+++ b/tests/auth_test.rs\n@@ -1 +1 @@\n+let token = \"test-token\";\n",
        );
        let idx = DiffIndex::build(&parsed);
        let mut finding = f("tests/auth_test.rs", 1, Severity::Error, 0.99);
        finding.title = "Remove exposed credential".into();
        finding.body = "This test token could be a credential. Check whether it is used in production code and rotate it.".into();
        finding.evidence = Some("let token = \"test-token\";".into());
        let outcome = apply(&Config::default(), &idx, vec![finding]).unwrap();
        assert!(outcome.kept.is_empty());
        assert_eq!(
            outcome.suppressed_findings[0].reason,
            SuppressionReason::NonActionable
        );
    }

    #[test]
    fn postil_380_legitimate_model_authored_product_language_is_suppressed() {
        let parsed = diff::parse(
            "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n+Model-authored replies are validated before publication.\n",
        );
        let idx = DiffIndex::build(&parsed);
        let mut finding = f("README.md", 1, Severity::Warn, 0.9);
        finding.kind = Kind::ContentPolicy;
        finding.title = "Remove AI authorship residue".into();
        finding.body = "This is authorship residue. Rewrite the sentence.".into();
        finding.evidence = Some("Model-authored replies are validated before publication.".into());
        let outcome = apply(&Config::default(), &idx, vec![finding]).unwrap();
        assert!(outcome.kept.is_empty());
        assert_eq!(
            outcome.suppressed_findings[0].reason,
            SuppressionReason::NonActionable
        );
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
        let rec = reconcile(
            &baseline,
            &idx,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &baseline,
            &idx,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &[baseline],
            &idx,
            &[fresh],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
        assert_eq!(rec.carried.len(), 1);
        assert!(rec.resolved.is_empty());
    }

    #[test]
    fn reconcile_reflagged_supersedes() {
        let idx = index_for("a.rs", 10, 3);
        let baseline = vec![f("a.rs", 11, Severity::Error, 0.9)];
        let new = vec![f("a.rs", 12, Severity::Error, 0.95)];
        let rec = reconcile(
            &baseline,
            &idx,
            &new,
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &baseline,
            &idx,
            &new,
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &baseline,
            &idx,
            &new,
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &[wide],
            &idx,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
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
        let rec = reconcile(
            &[baseline],
            &idx,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn reconcile_remaps_unchanged_evidence_and_respects_incremental_coverage() {
        let shifted = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +11 @@\n x\n",
        ));
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let remapped = reconcile(
            std::slice::from_ref(&baseline),
            &shifted,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
        assert_eq!(remapped.carried.len(), 1);
        assert_eq!(remapped.carried[0].line, 11);
        assert!(is_carried(&remapped.carried[0]));

        let changed = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +10 @@\n-x\n+y\n",
        ));
        let expired = reconcile(
            &[baseline],
            &changed,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );
        assert!(expired.carried.is_empty());
        assert_eq!(expired.resolved.len(), 1);

        let bounded = reconcile(
            &[f("a.rs", 10, Severity::Error, 0.9)],
            &changed,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Bounded,
            },
        );
        assert!(bounded.resolved.is_empty());
        assert_eq!(bounded.carried.len(), 1);

        let mut selected_change = changed.clone();
        selected_change.add_rendered_evidence("### a.rs\nold     10 - x\n    10 + y\n");
        let selected = reconcile(
            &[f("a.rs", 10, Severity::Error, 0.9)],
            &selected_change,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Bounded,
            },
        );
        assert_eq!(selected.resolved.len(), 1);
        assert!(selected.carried.is_empty());
    }

    #[test]
    fn reconcile_treats_indentation_changes_as_changed_evidence() {
        let whitespace_change = DiffIndex::build(&diff::parse(
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -10 +10 @@\n- value = 1\n+  value = 1\n",
        ));
        let mut baseline = f("a.py", 10, Severity::Error, 0.9);
        baseline.evidence = Some(" value = 1".into());

        let result = reconcile(
            &[baseline],
            &whitespace_change,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Exhaustive,
            },
        );

        assert!(result.carried.is_empty());
        assert_eq!(result.resolved.len(), 1);
    }

    #[test]
    fn trustworthy_full_review_resolves_findings_it_does_not_reproduce() {
        let idx = index_for("other.rs", 1, 1);
        let baseline = vec![f("a.rs", 99, Severity::Error, 0.9)];
        let rec = reconcile(
            &baseline,
            &idx,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Exhaustive,
            },
        );
        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn bounded_full_review_carries_changed_unselected_baseline_evidence() {
        let changed = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +10 @@\n-x\n+y\n",
        ));
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &changed,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
    }

    #[test]
    fn bounded_full_review_resolves_changed_selected_baseline_evidence() {
        let mut changed = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +10 @@\n-x\n+y\n",
        ));
        changed.add_rendered_evidence("### a.rs\nold     10 - x\n    10 + y\n");
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &changed,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn bounded_full_review_carries_unselected_current_evidence() {
        let shifted = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +11 @@\n x\n",
        ));
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &shifted,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
        assert_eq!(rec.carried[0].line, 11);
        assert!(is_carried(&rec.carried[0]));
    }

    #[test]
    fn bounded_full_review_resolves_selected_evidence_not_reproduced() {
        let mut unchanged = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +10 @@\n x\n",
        ));
        unchanged.add_rendered_evidence("### a.rs\n@@ starting at line 10 @@\n    10   x\n");
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &unchanged,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert_eq!(rec.resolved.len(), 1);
        assert!(rec.carried.is_empty());
    }

    #[test]
    fn bounded_full_review_does_not_confuse_duplicate_selected_evidence() {
        let mut duplicate = DiffIndex::build(&diff::parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -10 +10 @@\n x\n@@ -20 +20 @@\n x\n",
        ));
        duplicate.add_rendered_evidence("### a.rs\n@@ starting at line 20 @@\n    20   x\n");
        let baseline = f("a.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &duplicate,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
        assert_eq!(rec.carried[0].line, 10);
    }

    #[test]
    fn bounded_full_review_remaps_evidence_across_rename() {
        let renamed = DiffIndex::build(&diff::parse(
            "diff --git a/old.rs b/new.rs\n--- a/old.rs\n+++ b/new.rs\n@@ -10 +12 @@\n x\n",
        ));
        let baseline = f("old.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &renamed,
            &[],
            ReconcileScope::Full {
                trust: ReviewTrust::Bounded,
            },
        );

        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
        assert_eq!(rec.carried[0].path, "new.rs");
        assert_eq!(rec.carried[0].line, 12);
    }

    #[test]
    fn bounded_review_resolves_selected_changed_evidence_across_rename() {
        let mut renamed = DiffIndex::build(&diff::parse(
            "diff --git a/old.rs b/new.rs\nsimilarity index 90%\nrename from old.rs\nrename to new.rs\n--- a/old.rs\n+++ b/new.rs\n@@ -10 +10 @@\n-x\n+y\n",
        ));
        renamed.add_rendered_evidence("### new.rs\nold     10 - x\n    10 + y\n");
        let baseline = f("old.rs", 10, Severity::Error, 0.9);
        let rec = reconcile(
            &[baseline],
            &renamed,
            &[],
            ReconcileScope::Incremental {
                trust: ReviewTrust::Bounded,
            },
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
            ReconcileScope::Full {
                trust: ReviewTrust::Failed,
            },
        );
        assert!(rec.resolved.is_empty());
        assert_eq!(rec.carried.len(), 1);
    }

    /// The Ansible playbook from the production misattribution: a
    /// password-switching task with `no_log: true` sits at 965..972, and an
    /// unrelated rclone-config task with `diff: false` sits at 979..982.
    fn playbook_index() -> DiffIndex {
        let mut text = String::from(
            "diff --git a/ansible/playbooks/backup.yml b/ansible/playbooks/backup.yml\n\
             --- a/ansible/playbooks/backup.yml\n\
             +++ b/ansible/playbooks/backup.yml\n\
             @@ -960,24 +960,24 @@\n",
        );
        for line in 960..=990 {
            let content = match line {
                965 => "  - name: Switch RGW admin password".to_string(),
                972 => "    no_log: true".to_string(),
                979 => "  - name: Write rclone config".to_string(),
                981 => "    diff: false".to_string(),
                other => format!("    key_{other}: value"),
            };
            text.push('+');
            text.push_str(&content);
            text.push('\n');
        }
        DiffIndex::build(&diff::parse(&text))
    }

    fn playbook_finding(line: u32, title: &str, body: &str) -> Finding {
        let mut finding = f("ansible/playbooks/backup.yml", line, Severity::Error, 0.6);
        finding.title = title.into();
        finding.body = body.into();
        finding.evidence = Some(match line {
            981 => "    diff: false".to_string(),
            other => format!("    key_{other}: value"),
        });
        finding
    }

    #[test]
    fn a_finding_citing_a_line_its_named_construct_does_not_sit_on_is_suppressed() {
        // Reproduces the production defect: the model reasoned about the
        // password task at 965 and cited 981, where an unrelated task lives.
        // Grounding passes because the evidence really is line 981's text.
        let idx = playbook_index();
        let cfg = Config::default();
        let finding = playbook_finding(
            981,
            "Password task drops `no_log: true`",
            "The `Switch RGW admin password` task replaces `no_log: true` with \
             `diff: false`, so the new password is written to the job log in \
             plaintext on every run of this playbook.",
        );

        let out = apply(&cfg, &idx, vec![finding]).unwrap();

        assert!(
            out.kept.is_empty(),
            "a mis-anchored finding is not published"
        );
        assert_eq!(
            out.ungrounded, 0,
            "it grounded; the anchor is what is wrong"
        );
        assert_eq!(out.suppressed_findings.len(), 1);
        assert_eq!(
            out.suppressed_findings[0].reason,
            SuppressionReason::AnchorMismatch
        );
    }

    #[test]
    fn a_finding_citing_the_line_its_named_construct_sits_on_is_kept() {
        let idx = playbook_index();
        let cfg = Config::default();
        let mut finding = playbook_finding(
            972,
            "Password task drops `no_log: true`",
            "The `Switch RGW admin password` task no longer sets `no_log: true`, \
             so the new password is written to the job log in plaintext.",
        );
        finding.evidence = Some("    no_log: true".to_string());

        let out = apply(&cfg, &idx, vec![finding]).unwrap();

        assert_eq!(out.kept.len(), 1);
        assert!(out.suppressed_findings.is_empty());
    }

    #[test]
    fn a_finding_naming_nothing_the_diff_can_locate_keeps_its_anchor() {
        // Without a locatable construct there is no evidence either way, and
        // grounding has already done its job. Silence must not become a verdict.
        let idx = playbook_index();
        let cfg = Config::default();
        let finding = playbook_finding(
            981,
            "This task is not idempotent",
            "Re-running the playbook rewrites the file unconditionally, so every \
             run reports a change even when nothing differs.",
        );

        let out = apply(&cfg, &idx, vec![finding]).unwrap();

        assert_eq!(out.kept.len(), 1);
    }

    #[test]
    fn a_content_policy_claim_built_on_a_mis_anchored_finding_falls_with_it() {
        // The second production error-severity finding: the PR description was
        // compared against the misreading and its author accused of describing
        // the change falsely.
        let mut idx = playbook_index();
        idx.add_content_policy_evidence(
            crate::envelope::PR_DESCRIPTION_PATH,
            "### .postil/pr-description\n     1   Backup hardening\n     2   Keeps no_log on the password task.\n",
        );
        let cfg = Config::default();
        let mis_anchored = playbook_finding(
            981,
            "Password task drops `no_log: true`",
            "The `Switch RGW admin password` task replaces `no_log: true` with \
             `diff: false`, exposing the password in the job log.",
        );
        let mut derived = f(
            crate::envelope::PR_DESCRIPTION_PATH,
            2,
            Severity::Error,
            0.95,
        );
        derived.kind = Kind::ContentPolicy;
        derived.title = "PR description contradicts the change".into();
        derived.body = "The description states no_log is kept, but \
                        ansible/playbooks/backup.yml removes it."
            .into();
        derived.evidence = Some("Keeps no_log on the password task.".into());

        let out = apply(&cfg, &idx, vec![mis_anchored, derived]).unwrap();

        assert!(out.kept.is_empty(), "neither error-severity claim survives");
        let reasons: Vec<_> = out
            .suppressed_findings
            .iter()
            .map(|entry| entry.reason)
            .collect();
        assert!(reasons.contains(&SuppressionReason::AnchorMismatch));
        assert!(reasons.contains(&SuppressionReason::DerivedFromSuppressed));
    }

    #[test]
    fn a_content_policy_claim_cannot_outrank_the_finding_it_argues_from() {
        let mut idx = playbook_index();
        idx.add_content_policy_evidence(
            crate::envelope::PR_DESCRIPTION_PATH,
            "### .postil/pr-description\n     1   Backup hardening\n     2   Keeps no_log on the password task.\n",
        );
        let mut cfg = Config::default();
        cfg.min_confidence = 0.0;
        let mut source = playbook_finding(
            972,
            "Password task drops `no_log: true`",
            "The `Switch RGW admin password` task no longer sets `no_log: true`.",
        );
        source.evidence = Some("    no_log: true".to_string());
        source.confidence = 0.55;
        let mut derived = f(
            crate::envelope::PR_DESCRIPTION_PATH,
            2,
            Severity::Error,
            0.95,
        );
        derived.kind = Kind::ContentPolicy;
        derived.title = "PR description contradicts the change".into();
        derived.body = "The description states no_log is kept, but \
                        ansible/playbooks/backup.yml removes it."
            .into();
        derived.evidence = Some("Keeps no_log on the password task.".into());

        let out = apply(&cfg, &idx, vec![source, derived]).unwrap();

        let content_policy = out
            .kept
            .iter()
            .find(|finding| finding.kind == Kind::ContentPolicy)
            .expect("the claim survives, at its source's confidence");
        assert!(
            (content_policy.confidence - 0.55).abs() < f64::EPSILON,
            "confidence was {}, expected the source's 0.55",
            content_policy.confidence
        );
    }

    #[test]
    fn one_observation_repeated_across_files_becomes_one_finding() {
        // Production shape: five systemd unit templates, one claim, bodies
        // differing only by filename.
        let units = [
            "backup-asset.service.j2",
            "backup-integrity.service.j2",
            "backup-prune.service.j2",
            "backup-restore-test.service.j2",
            "backup-tenant-data-maintenance.service.j2",
        ];
        let mut text = String::new();
        let mut findings = Vec::new();
        for (position, unit) in units.iter().enumerate() {
            let path = format!("ansible/roles/backup/templates/{unit}");
            text.push_str(&format!(
                "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -10,1 +10,1 @@\n+EnvironmentFile=/etc/backup.env\n",
            ));
            let mut finding = f(&path, 10, Severity::Warn, 0.6);
            finding.kind = Kind::Risk;
            finding.title = format!("EnvironmentFile in {unit} is not optional");
            finding.body = format!(
                "In {unit} the EnvironmentFile directive has no leading dash, so \
                 systemd refuses to start the unit when the file is absent rather \
                 than continuing with the environment unset."
            );
            finding.evidence = Some("EnvironmentFile=/etc/backup.env".into());
            finding.confidence = 0.6 + position as f64 * 0.01;
            findings.push(finding);
        }
        let idx = DiffIndex::build(&diff::parse(&text));
        let cfg = Config::default();

        let out = apply(&cfg, &idx, findings).unwrap();

        assert_eq!(out.kept.len(), 1, "one claim, one finding");
        assert_eq!(out.suppressed_findings.len(), 4);
        assert!(
            out.suppressed_findings
                .iter()
                .all(|entry| entry.reason == SuppressionReason::DuplicateRootCause)
        );
        let body = &out.kept[0].body;
        for unit in &units {
            if !out.kept[0].path.ends_with(unit) {
                assert!(
                    body.contains(unit),
                    "the retained finding names {unit} as also affected"
                );
            }
        }
    }

    #[test]
    fn findings_with_too_little_prose_to_compare_are_not_collapsed() {
        let mut text = String::new();
        let mut findings = Vec::new();
        for path in ["a.rs", "b.rs"] {
            text.push_str(&format!(
                "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n+x\n",
            ));
            let mut finding = f(path, 1, Severity::Warn, 0.9);
            finding.title = "Unchecked index".into();
            finding.body = "This can panic.".into();
            findings.push(finding);
        }
        let idx = DiffIndex::build(&diff::parse(&text));
        let cfg = Config::default();

        let out = apply(&cfg, &idx, findings).unwrap();

        assert_eq!(
            out.kept.len(),
            2,
            "two short findings are still two findings"
        );
    }

    fn uncertainty(title: &str, body: &str) -> Finding {
        let mut finding = f("values.cluster.yaml", 675, Severity::Warn, 0.6);
        finding.kind = Kind::Uncertainty;
        finding.title = title.into();
        finding.body = body.into();
        finding
    }

    #[test]
    fn an_uncertainty_finding_that_only_asks_the_author_to_check_stops_blocking() {
        let mut findings = vec![uncertainty(
            "rgwConfig may not be a recognized field",
            "Verify that rgwConfig is a field the chart recognizes; if it is not, \
             the block is silently ignored.",
        )];

        demote_deferred_verification(&mut findings);

        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "the question stays visible but cannot carry a blocking severity"
        );
    }

    #[test]
    fn prose_about_search_work_does_not_substitute_for_a_repository_receipt() {
        let mut findings = vec![uncertainty(
            "rgwConfig is not a recognized field",
            "The diff adds no schema entry for rgwConfig and no other reference to \
             it, so verify that the chart consumes it.",
        )];

        demote_deferred_verification(&mut findings);

        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn demotion_leaves_other_kinds_and_reserved_anchors_alone() {
        let mut risk = uncertainty(
            "Confirm that the cache is warmed",
            "Confirm that the cache is warmed before the first request.",
        );
        risk.kind = Kind::Risk;
        let mut operational = uncertainty(
            "Review incomplete",
            "Confirm that the full diff was reviewed.",
        );
        operational.path = crate::envelope::OPERATIONAL_PATH.into();
        let mut findings = vec![risk, operational];

        demote_deferred_verification(&mut findings);

        assert_eq!(
            findings[0].severity,
            Severity::Warn,
            "only uncertainty demotes"
        );
        assert_eq!(
            findings[1].severity,
            Severity::Warn,
            "an operational anchor states the run's own limits"
        );
    }
}
