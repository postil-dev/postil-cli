//! Forge abstraction: everything Postil needs from a code host.
//!
//! Ships GitHub, GitLab, Bitbucket, and Azure DevOps — each covering its
//! self-managed/server variant through a custom base-URL environment variable.

pub mod azure;
pub mod bitbucket;
pub mod github;
pub mod gitlab;

use anyhow::Result;

use crate::envelope::{Envelope, Finding, Severity, SuppressionReason};

/// Base URL for the brand status icons rendered in PR comments and check
/// summaries. The four icons (error, warn, info, pass) are served by the
/// marketing site and mirror the product-page statusline.
pub const STATUS_ICON_BASE: &str = "https://postil.dev/status";

/// Markdown `<img>` for a named status icon, sized to sit inline with text.
pub fn icon_md(name: &str) -> String {
    format!(
        "<img src=\"{STATUS_ICON_BASE}/{name}.svg\" width=\"14\" height=\"14\" \
         alt=\"{name}\" align=\"text-bottom\">"
    )
}

pub fn severity_icon(severity: Severity) -> String {
    icon_md(match severity {
        Severity::Error => "error",
        Severity::Warn => "warn",
        Severity::Info => "info",
    })
}

#[derive(Debug, Clone)]
pub struct PrMeta {
    pub title: String,
    pub body: String,
    pub head_sha: String,
    pub base_sha: String,
}

/// Check conclusions, mapped per-forge. Postil semantics:
/// - advisory check (`postil/review`): success unless the run itself failed.
/// - gate check (`postil/gate`): failure iff gate-level findings exist (or the
///   run failed — fail closed). Never `neutral` for the gate: a grey square
///   that reads as "didn't fail" is the GitHub Copilot mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Success,
    Failure,
    /// Operational error on the advisory check only.
    Neutral,
}

/// What a `respond` thread number points at. GitHub's issues API covers both,
/// so it ignores this; GitLab/Bitbucket/Azure key issues and PRs on different
/// endpoints, so they branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadKind {
    /// A pull request / merge request.
    Pull,
    /// An issue / work item on the forge's issue tracker.
    Issue,
}

#[allow(async_fn_in_trait)]
pub trait Forge {
    /// True when the forge renders inline HTML `<img>` in markdown comments
    /// (GitHub, GitLab). Forges that show raw HTML get text-only statuslines.
    fn rich_markdown(&self) -> bool {
        false
    }
    /// Compose the top-level review body. Forges can add validated links to the
    /// otherwise forge-neutral envelope metadata.
    fn review_summary(&self, envelope: &Envelope) -> String {
        check_summary(envelope, self.rich_markdown(), SummaryContext::from_env())
    }
    async fn fetch_pr_meta(&self) -> Result<PrMeta>;
    /// Unified diff of the full PR.
    async fn fetch_diff(&self) -> Result<String>;
    /// Unified diff covering `since_sha..head_sha` only (incremental reviews).
    /// `head_sha` is the SHA the caller is reviewing, not whatever the PR's
    /// head happens to be at fetch time — a later push must not widen the diff.
    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String>;
    /// Post the batched review: one summary plus inline comments per finding.
    async fn post_review(&self, summary: &str, findings: &[Finding], head_sha: &str) -> Result<()>;
    /// Ensure both check runs exist (in_progress); returns (advisory_id, gate_id).
    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)>;
    /// Complete both checks with the envelope's outcome.
    async fn complete_checks(
        &self,
        advisory_id: &str,
        gate_id: &str,
        advisory: CheckState,
        gate: CheckState,
        envelope: &Envelope,
    ) -> Result<()>;

    /// Title and body of the issue/PR/MR a maintainer mentioned Postil on, used
    /// to ground the answer (`postil respond`). `kind` disambiguates the number
    /// for forges whose issues and pulls live on different endpoints.
    async fn fetch_thread(&self, number: u64, kind: ThreadKind) -> Result<(String, String)>;

    /// Post a top-level comment (Postil's reply to a mention). `kind` selects the
    /// issue- vs pull-level endpoint where the forge separates them.
    async fn post_comment(&self, number: u64, kind: ThreadKind, body: &str) -> Result<()>;
}

/// GitHub rejects a check-run `output.summary` over 65535 chars and a `title`
/// over 255 with HTTP 422, which would abort posting both checks. These caps
/// keep composed strings safely under those limits. Shared so every forge that
/// PATCHes check output can apply the same bound.
pub const MAX_CHECK_SUMMARY: usize = 60_000;
pub const MAX_CHECK_TITLE: usize = 255;

/// Truncate `s` to at most `max` characters, appending an explicit marker when
/// anything is cut so the reader knows the output is not complete. The marker is
/// counted against the budget, so the result never exceeds `max` characters.
pub fn cap_text(s: &str, max: usize, marker: &str) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let budget = max.saturating_sub(marker.chars().count());
    let mut out: String = s.chars().take(budget).collect();
    out.push_str(marker);
    out
}

pub(crate) fn wrap_plain_text(text: &str, width: usize) -> String {
    if width == 0 {
        return text.to_string();
    }

    let mut wrapped = Vec::new();
    for line in text.split('\n') {
        wrap_plain_line(line, width, &mut wrapped);
    }
    wrapped.join("\n")
}

fn wrap_plain_line(mut line: &str, width: usize, wrapped: &mut Vec<String>) {
    if line.is_empty() {
        wrapped.push(String::new());
        return;
    }

    while line.chars().count() > width {
        let (break_at, split_on_space) = wrap_break(line, width);
        let chunk = &line[..break_at];
        wrapped.push(if split_on_space {
            chunk.trim_end_matches(' ').to_string()
        } else {
            chunk.to_string()
        });
        line = if split_on_space {
            line[break_at..].trim_start_matches(' ')
        } else {
            &line[break_at..]
        };

        if line.is_empty() {
            return;
        }
    }

    wrapped.push(line.to_string());
}

fn wrap_break(line: &str, width: usize) -> (usize, bool) {
    let mut hard_break = line.len();
    let mut last_space = None;
    // Only break on a space that follows a word: breaking inside leading
    // indentation would select an all-space chunk, which trims to an empty
    // line and drops the indentation from the remainder.
    let mut seen_word = false;

    for (column, (idx, ch)) in line.char_indices().enumerate() {
        if ch == ' ' {
            if seen_word {
                last_space = Some(idx);
            }
        } else {
            seen_word = true;
        }
        if column == width {
            hard_break = idx;
            break;
        }
    }

    if let Some(idx) = last_space {
        (idx, true)
    } else {
        (hard_break, false)
    }
}

/// Cap a check-run summary to a size GitHub accepts, with a truncation marker.
pub fn cap_check_summary(s: &str) -> String {
    cap_text(
        s,
        MAX_CHECK_SUMMARY,
        "\n\n[output truncated at the check-run size limit]",
    )
}

/// Cap a check-run title to a size GitHub accepts.
pub fn cap_check_title(s: &str) -> String {
    cap_text(s, MAX_CHECK_TITLE, "…")
}

/// True when a finding's path is a synthetic Postil anchor (e.g. the reserved
/// PR-description path or the fail-closed/provider markers) rather than a real
/// file line. These cannot be posted as inline code annotations or review
/// comments; they are surfaced in the check-run summary and PR comment body.
pub fn is_synthetic_path(path: &str) -> bool {
    crate::envelope::is_reserved_anchor(path)
}

pub fn is_operational_path(path: &str) -> bool {
    matches!(
        path,
        crate::envelope::OPERATIONAL_PATH | crate::envelope::PROVIDER_PATH
    )
}

pub fn only_operational_findings(findings: &[Finding]) -> bool {
    !findings.is_empty()
        && findings
            .iter()
            .all(|finding| is_operational_path(&finding.path))
}

pub fn valid_details_url(value: Option<String>) -> Option<String> {
    value.filter(|value| {
        reqwest::Url::parse(value)
            .map(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
            .unwrap_or(false)
    })
}

pub fn check_title(envelope: &Envelope) -> String {
    if envelope.silent {
        "No merge-relevant findings".to_string()
    } else {
        let c = &envelope.counts;
        format!("{} error, {} warn, {} info", c.error, c.warn, c.info)
    }
}

/// Truthful clean-result wording for review comments and check summaries.
/// Some silent runs intentionally make no model call.
pub fn clean_review_message(envelope: &Envelope) -> &'static str {
    match envelope.model_used.as_str() {
        "none (disabled by config)" => "Review disabled by configuration.",
        "none (empty diff)" => "No reviewable diff; no model call was made.",
        _ => "Postil reviewed this change and found nothing that affects the merge decision.",
    }
}

#[derive(Default)]
pub struct SummaryContext {
    pub details_url: Option<String>,
    pub prevention_hint: bool,
    pub prevention_commands: Vec<String>,
}

impl SummaryContext {
    pub fn from_env() -> Self {
        Self {
            details_url: valid_details_url(std::env::var("POSTIL_DETAILS_URL").ok()),
            prevention_hint: std::env::var("POSTIL_PREVENTION_HINT").as_deref() == Ok("1"),
            prevention_commands: prevention_commands_from_env(),
        }
    }
}

fn prevention_commands_from_env() -> Vec<String> {
    let Ok(raw) = std::env::var("POSTIL_PREVENTION_COMMANDS_JSON") else {
        return Vec::new();
    };
    parse_prevention_commands(&raw)
}

fn parse_prevention_commands(raw: &str) -> Vec<String> {
    if raw.len() > 4_096 {
        return Vec::new();
    }
    let Ok(commands) = serde_json::from_str::<Vec<String>>(raw) else {
        return Vec::new();
    };
    commands
        .into_iter()
        .take(5)
        .filter_map(|command| {
            let command = command.trim();
            (!command.is_empty()
                && command.chars().count() <= 200
                && !command.chars().any(|ch| ch.is_control() || ch == '`'))
            .then(|| command.to_string())
        })
        .collect()
}

fn summary_count(
    rich: bool,
    status: &str,
    count: usize,
    singular: &str,
    plural_label: &str,
) -> String {
    let label = plural(count, singular, plural_label);
    if rich {
        format!("{} **{count} {label}**", icon_md(status))
    } else {
        format!("{status}: **{count} {label}**")
    }
}

pub fn check_summary(envelope: &Envelope, rich: bool, context: SummaryContext) -> String {
    let mut s = String::new();
    let operational = only_operational_findings(&envelope.findings);
    let has_operational = envelope
        .findings
        .iter()
        .any(|finding| is_operational_path(&finding.path));

    if operational {
        if envelope.gate.failing {
            s.push_str(
                "Postil could not complete this review, so no review verdict exists. The merge check remains blocked.",
            );
        } else {
            s.push_str(
                "Postil could not complete this review, so no review verdict exists. This repository treats review outages as advisory.",
            );
        }
        s.push('\n');
    } else if envelope.silent {
        s.push_str(clean_review_message(envelope));
        s.push('\n');
    } else {
        let visible = envelope
            .findings
            .iter()
            .filter(|finding| !is_operational_path(&finding.path))
            .count();
        let blocking = envelope
            .findings
            .iter()
            .filter(|finding| !is_operational_path(&finding.path))
            .filter(|finding| {
                crate::envelope::finding_blocks_gate(
                    finding,
                    &envelope.gate.fail_on,
                    &envelope.gate.block_on_kinds,
                    false,
                )
            })
            .count();
        if has_operational && visible > 0 {
            s.push_str(&summary_count(
                rich,
                "warn",
                visible,
                "finding; review incomplete",
                "findings; review incomplete",
            ));
            s.push('\n');
        } else if blocking > 0 {
            s.push_str(&summary_count(
                rich,
                "error",
                blocking,
                "blocking finding",
                "blocking findings",
            ));
            let advisory = visible.saturating_sub(blocking);
            if advisory > 0 {
                s.push_str(" · ");
                s.push_str(&summary_count(
                    rich,
                    "info",
                    advisory,
                    "advisory finding",
                    "advisory findings",
                ));
            }
            s.push('\n');
        } else if visible > 0 {
            s.push_str(&summary_count(
                rich,
                "info",
                visible,
                "advisory finding",
                "advisory findings",
            ));
            s.push('\n');
        } else {
            s.push_str(&summary_count(
                rich,
                "info",
                1,
                "finding in review details",
                "findings in review details",
            ));
            s.push('\n');
        }
    }

    // PR-level policy findings use a synthetic anchor because no changed file
    // line exists for an inline comment. Unlike operational sentinels, these
    // are actionable review results, so keep their bounded detail visible in
    // the review summary instead of reducing them to a count and dashboard
    // link.
    let synthetic_findings: Vec<_> = envelope
        .findings
        .iter()
        .filter(|finding| is_synthetic_path(&finding.path))
        .filter(|finding| !is_operational_path(&finding.path))
        .take(3)
        .collect();
    if !synthetic_findings.is_empty() {
        s.push('\n');
        for finding in &synthetic_findings {
            let location = if finding.path == crate::envelope::PR_DESCRIPTION_PATH {
                "pull request description".to_string()
            } else {
                format!("`{}`", safe_code_text(&finding.path))
            };
            s.push_str(&format!(
                "- **{}** in {}: {}\n",
                safe_markdown_text(&finding.title),
                location,
                safe_evidence_text(&finding.body),
            ));
        }
        let undisclosed = envelope
            .findings
            .iter()
            .filter(|finding| is_synthetic_path(&finding.path))
            .filter(|finding| !is_operational_path(&finding.path))
            .count()
            .saturating_sub(synthetic_findings.len());
        if undisclosed > 0 {
            s.push_str(&format!(
                "- {} more PR-level {} in the review details.\n",
                undisclosed,
                plural(undisclosed, "finding is", "findings are"),
            ));
        }
    }
    if !envelope.resolved.is_empty() {
        s.push_str(&summary_count(
            rich,
            "pass",
            envelope.resolved.len(),
            "resolved finding",
            "resolved findings",
        ));
        s.push('\n');
    }

    let eligible: Vec<_> = envelope
        .suppressed_findings
        .iter()
        .filter(|suppressed| suppressed.reason != SuppressionReason::Ignored)
        .collect();
    let disclosed: Vec<_> = eligible.iter().take(5).copied().collect();
    if !disclosed.is_empty() {
        if rich {
            s.push_str(&format!(
                "\n<details><summary>{} {} suppressed{}</summary>\n\n",
                icon_md("info"),
                eligible.len(),
                if eligible.len() > disclosed.len() {
                    format!(" (showing {})", disclosed.len())
                } else {
                    String::new()
                },
            ));
        } else {
            s.push_str(&format!(
                "\ninfo: {} suppressed{}:\n",
                eligible.len(),
                if eligible.len() > disclosed.len() {
                    format!(" (showing {})", disclosed.len())
                } else {
                    String::new()
                },
            ));
        }
        for suppressed in disclosed {
            s.push_str(&format!(
                "- **{}** at `{}`:{}: {}; severity {}, confidence {}. {}\n",
                safe_markdown_text(&suppressed.finding.title),
                safe_code_text(&suppressed.finding.path),
                suppressed.finding.line,
                suppression_reason(suppressed.reason),
                suppressed.finding.severity.as_str(),
                format_confidence(suppressed.finding.confidence),
                safe_evidence_text(&suppressed.finding.body),
            ));
        }
        if rich {
            s.push_str("\n</details>\n");
        }
    }

    if context.prevention_hint && !operational && !envelope.silent {
        if rich {
            s.push_str("\n<details><summary>Before the next push</summary>\n\n");
        } else {
            s.push_str("\nBefore the next push:\n");
        }
        s.push_str("Install committed-change review with `postil hook install`.\n");
        if !context.prevention_commands.is_empty() {
            s.push_str("Run the repository's verified checks:\n");
            for command in &context.prevention_commands {
                s.push_str(&format!("- `{command}`\n"));
            }
        }
        s.push_str("After staging and before committing, run `postil review --staged`.\n");
        if rich {
            s.push_str("\n</details>\n");
        }
    }

    if let Some(details_url) = context.details_url {
        if rich {
            s.push_str(&format!("\n<sub>[Review details]({details_url})</sub>\n"));
        } else {
            s.push_str(&format!("\n[Review details]({details_url})\n"));
        }
    }
    s
}

fn safe_evidence_text(value: &str) -> String {
    safe_markdown_text(value).chars().take(240).collect()
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn suppression_reason(reason: SuppressionReason) -> &'static str {
    match reason {
        SuppressionReason::Ignored => "ignored by repository policy",
        SuppressionReason::BelowSeverity => "below the configured severity threshold",
        SuppressionReason::BelowConfidence => "below the configured confidence threshold",
        SuppressionReason::MaxFindings => "outside the configured finding cap",
    }
}

fn safe_markdown_text(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .replace('@', "＠")
        .replace(['[', ']', '*', '_', '<', '>'], "")
        .chars()
        .take(160)
        .collect()
}

fn safe_code_text(value: &str) -> String {
    value
        .replace(['\r', '\n', '`'], "")
        .chars()
        .take(300)
        .collect()
}

/// The body of one inline finding comment: icon (rich forges), bold title,
/// severity / confidence / kind statusline, then the finding body.
pub fn finding_comment_body(f: &Finding, rich: bool) -> String {
    let publication = crate::envelope::finding_publication_text(&f.title, &f.body);
    let icon = if rich {
        format!("{} ", severity_icon(f.severity))
    } else {
        String::new()
    };
    format!(
        "{}**{}**\n`{}` · confidence {} · kind: {}\n\n{}",
        icon,
        publication.title,
        f.severity.as_str(),
        format_confidence(f.confidence),
        f.kind.as_str(),
        publication.body
    )
}

/// Confidence rendered as the product statusline shows it: a bare decimal
/// probability ("0.91"), not a percentage.
pub fn format_confidence(c: f64) -> String {
    format!("{:.2}", c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Kind, Severity};

    fn finding() -> Finding {
        Finding {
            path: "src/auth.rs".into(),
            line: 41,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.91,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Unsanitized input reaches query".into(),
            body: "user_input flows into exec_query.".into(),
            id: None,
        }
    }

    fn envelope_with_findings(findings: Vec<Finding>) -> Envelope {
        Envelope {
            version: 1,
            summary: String::new(),
            silent: findings.is_empty(),
            counts: Envelope::counts_of(&findings, 0),
            confidence_buckets: Envelope::buckets_of(&findings),
            findings,
            suppressed_findings: vec![],
            resolved: vec![],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: true,
                block_on_kinds: vec!["humanEscalation".into()],
            },
            model_used: "review-model".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        }
    }

    #[test]
    fn rich_comment_carries_brand_icon_and_statusline() {
        let body = finding_comment_body(&finding(), true);
        assert!(body.contains("https://postil.dev/status/error.svg"));
        assert!(body.contains("confidence 0.91 · kind: risk"));
    }

    #[test]
    fn empty_finding_title_cannot_break_the_comment_wrapper() {
        let mut unsafe_finding = finding();
        unsafe_finding.title.clear();
        unsafe_finding.body = "**@octocat <img> [`code`]**\n\nKeep `useful()` formatting.".into();

        let body = finding_comment_body(&unsafe_finding, true);

        assert!(!body.contains("@octocat"));
        assert!(!body.contains("<img>"));
        assert!(!body.contains("****"));
        assert!(body.contains("`useful()`"));
    }

    #[test]
    fn only_exact_virtual_anchors_are_synthetic() {
        assert!(is_synthetic_path(crate::envelope::PROVIDER_PATH));
        assert!(is_synthetic_path(crate::envelope::OPERATIONAL_PATH));
        assert!(is_synthetic_path(crate::envelope::PR_DESCRIPTION_PATH));
        assert!(is_synthetic_path(crate::envelope::DIFF_PATH));
        assert!(!is_synthetic_path(".postil/content-policy.md"));
        assert!(!is_synthetic_path(".postil/guardrails.md"));
    }

    #[test]
    fn summary_is_explicit_path_free_and_marks_weak_escalations_non_blocking() {
        let mut escalation = finding();
        escalation.kind = Kind::HumanEscalation;
        escalation.confidence = 0.05;
        let mut suppressed_findings = (0..6)
            .map(|index| crate::envelope::SuppressedFinding {
                finding: Finding {
                    title: format!("Lower confidence concern {index}"),
                    body: "Evidence from the changed branch shows the value can be lost.".into(),
                    ..finding()
                },
                reason: crate::envelope::SuppressionReason::BelowConfidence,
            })
            .collect::<Vec<_>>();
        suppressed_findings.push(crate::envelope::SuppressedFinding {
            finding: Finding {
                title: "Ignored generated file".into(),
                ..finding()
            },
            reason: crate::envelope::SuppressionReason::Ignored,
        });
        let env = Envelope {
            version: 1,
            summary: "A weak signal needs review.".into(),
            silent: false,
            findings: vec![escalation],
            suppressed_findings,
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [1, 0, 0, 0, 0],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec!["humanEscalation".into()],
            },
            model_used: "review-model".into(),
            scorer_model: Some("scorer-model".into()),
            scorer_error: None,
            scorer_disagreements: Some(1),
            usage: crate::envelope::Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
            },
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 1_250,
            base_sha: None,
            head_sha: Some("abcdef123456".into()),
            since_sha: None,
        };

        let summary = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                prevention_hint: true,
                prevention_commands: vec!["cargo test --lib".into()],
            },
        );

        assert!(summary.starts_with(&format!("{} **1 advisory finding**", icon_md("info"))));
        assert!(!summary.contains("does not block"));
        assert!(!summary.contains("Unsanitized input reaches query"));
        assert!(!summary.contains("src/auth.rs:41"));
        assert!(!summary.contains("Review metadata"));
        assert!(!summary.contains("abcdef1"));
        assert!(summary.contains(&format!(
            "<details><summary>{} 6 suppressed (showing 5)</summary>",
            icon_md("info")
        )));
        assert!(summary.contains("Lower confidence concern 0"));
        assert!(summary.contains("severity error, confidence 0.91"));
        assert!(summary.contains("Evidence from the changed branch"));
        assert!(!summary.contains("Ignored generated file"));
        assert!(summary.contains("postil review --staged"));
        assert!(summary.contains("postil hook install"));
        assert!(summary.contains("cargo test --lib"));
        assert!(
            summary
                .contains("<sub>[Review details](https://postil.dev/orgs/acme/runs/run-1)</sub>")
        );

        let plain = check_summary(&env, false, Default::default());
        assert!(plain.contains("info: 6 suppressed (showing 5):"));
        assert!(!plain.contains("<details>"));
    }

    #[test]
    fn summary_counts_cover_blocking_advisory_resolved_and_suppressed() {
        let blocking = envelope_with_findings(vec![finding()]);
        let blocking_summary = check_summary(&blocking, true, Default::default());
        assert!(
            blocking_summary.starts_with(&format!("{} **1 blocking finding**\n", icon_md("error")))
        );
        let blocking_plural = envelope_with_findings(vec![finding(), finding()]);
        assert!(
            check_summary(&blocking_plural, true, Default::default())
                .starts_with(&format!("{} **2 blocking findings**\n", icon_md("error")))
        );

        let mut advisory_one = finding();
        advisory_one.severity = Severity::Warn;
        let mut advisory_two = advisory_one.clone();
        advisory_two.line = 42;
        let mut advisory = envelope_with_findings(vec![advisory_one, advisory_two]);
        advisory.gate.failing = false;
        let advisory_summary = check_summary(&advisory, true, Default::default());
        assert!(
            advisory_summary.starts_with(&format!("{} **2 advisory findings**\n", icon_md("info")))
        );

        let mut resolved_singular = envelope_with_findings(vec![finding()]);
        resolved_singular.resolved = vec![finding()];
        assert!(
            check_summary(&resolved_singular, true, Default::default())
                .contains(&format!("{} **1 resolved finding**\n", icon_md("pass")))
        );

        let mut detail_counts = envelope_with_findings(vec![finding()]);
        detail_counts.resolved = vec![finding(), finding()];
        detail_counts.suppressed_findings = vec![crate::envelope::SuppressedFinding {
            finding: finding(),
            reason: SuppressionReason::BelowConfidence,
        }];
        let detail_summary = check_summary(&detail_counts, true, Default::default());
        assert!(detail_summary.contains(&format!("{} **2 resolved findings**\n", icon_md("pass"))));
        assert!(detail_summary.contains(&format!(
            "<details><summary>{} 1 suppressed</summary>",
            icon_md("info")
        )));
        assert!(!detail_summary.contains("earlier finding"));
    }

    #[test]
    fn review_details_are_subordinate_when_present_and_absent_when_unset() {
        let env = envelope_with_findings(vec![finding()]);
        let with_details = check_summary(
            &env,
            true,
            SummaryContext {
                details_url: Some("https://postil.dev/orgs/acme/runs/run-1".into()),
                ..Default::default()
            },
        );
        assert!(
            with_details.ends_with(
                "<sub>[Review details](https://postil.dev/orgs/acme/runs/run-1)</sub>\n"
            )
        );

        let without_details = check_summary(&env, true, Default::default());
        assert!(!without_details.contains("Review details"));
        assert!(!without_details.contains("<sub>"));
    }

    #[test]
    fn pr_description_finding_is_visible_without_exposing_operational_detail() {
        let mut pr_description = finding();
        pr_description.path = crate::envelope::PR_DESCRIPTION_PATH.into();
        pr_description.title = "Required disclosure is missing".into();
        pr_description.body =
            "Add the compatibility impact to the pull request description.".into();
        let mut provider = finding();
        provider.path = crate::envelope::PROVIDER_PATH.into();
        provider.title = "private provider title".into();
        provider.body = "private provider body".into();
        let mut env = envelope_with_findings(vec![pr_description, provider]);
        env.silent = false;

        let summary = check_summary(&env, true, Default::default());

        assert!(summary.contains("Required disclosure is missing"));
        assert!(summary.contains("in pull request description"));
        assert!(summary.contains("Add the compatibility impact"));
        assert!(!summary.contains("private provider title"));
        assert!(!summary.contains("private provider body"));
    }

    #[test]
    fn prevention_commands_are_bounded_and_markdown_safe() {
        let parsed = parse_prevention_commands(
            r#"["cargo test --lib","bun test","bad`command","line\nbreak","","one","two","three","four"]"#,
        );
        assert_eq!(parsed, vec!["cargo test --lib", "bun test"]);
        assert!(parse_prevention_commands(&"x".repeat(4_097)).is_empty());
    }

    #[test]
    fn compact_summary_hides_model_metadata_and_raw_scorer_errors() {
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "review-model".into(),
            scorer_model: None,
            scorer_error: Some("[click me](https://attacker.invalid)".into()),
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        let summary = check_summary(&env, false, Default::default());

        assert!(summary.contains("Postil reviewed this change"));
        assert!(!summary.contains("<details>"));
        assert!(!summary.contains("Scorer"));
        assert!(!summary.contains("attacker.invalid"));
    }

    #[test]
    fn plain_comment_has_statusline_without_html() {
        let body = finding_comment_body(&finding(), false);
        assert!(!body.contains("<img"));
        assert!(body.contains("`error` · confidence 0.91 · kind: risk"));
    }

    #[test]
    fn check_output_caps_stay_within_github_limits() {
        // A summary far over the limit is truncated below 65535 with a marker.
        let long = "x".repeat(200_000);
        let capped = cap_check_summary(&long);
        assert!(capped.chars().count() <= MAX_CHECK_SUMMARY);
        assert!(capped.contains("[output truncated"));
        // A short summary is passed through unchanged.
        assert_eq!(cap_check_summary("brief"), "brief");
        // Titles cap at 255 with an ellipsis marker; short ones pass through.
        let long_title = "t".repeat(1000);
        let capped_title = cap_check_title(&long_title);
        assert!(capped_title.chars().count() <= MAX_CHECK_TITLE);
        assert!(capped_title.ends_with('…'));
        assert_eq!(
            cap_check_title("2 error, 0 warn, 1 info"),
            "2 error, 0 warn, 1 info"
        );
    }

    #[test]
    fn silent_summary_is_plain_and_compact_for_all_forges() {
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        assert!(!check_summary(&env, true, Default::default()).contains("status/pass.svg"));
        assert!(!check_summary(&env, false, Default::default()).contains("<img"));
    }

    #[test]
    fn silent_summary_distinguishes_reviews_from_no_model_runs() {
        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "none (disabled by config)".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Default::default(),
            model_usage: vec![],
            model_incidents: vec![],
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };

        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("Review disabled by configuration.")
        );

        env.model_used = "none (empty diff)".into();
        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("No reviewable diff; no model call was made.")
        );

        env.model_used = "review-model".into();
        assert!(
            check_summary(&env, false, Default::default())
                .starts_with("Postil reviewed this change")
        );
    }

    #[test]
    fn wrap_plain_text_leaves_short_text_unchanged() {
        assert_eq!(wrap_plain_text("short text", 100), "short text");
    }

    #[test]
    fn wrap_plain_text_wraps_long_paragraph_without_splitting_words() {
        let text = (0..40)
            .map(|n| format!("word{n:02}"))
            .collect::<Vec<_>>()
            .join(" ");

        let wrapped = wrap_plain_text(&text, 100);

        assert_ne!(wrapped, text);
        assert!(wrapped.lines().all(|line| line.chars().count() <= 100));
        assert_eq!(
            wrapped.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
    }

    #[test]
    fn wrap_plain_text_preserves_existing_newlines_and_blank_lines() {
        let text = "alpha\n\nsecond line needs wrapping here\nthird";

        assert_eq!(
            wrap_plain_text(text, 20),
            "alpha\n\nsecond line needs\nwrapping here\nthird"
        );
    }

    #[test]
    fn wrap_plain_text_hard_breaks_single_word_longer_than_width() {
        let text = "x".repeat(150);
        let wrapped = wrap_plain_text(&text, 100);
        let lines = wrapped.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].chars().count(), 100);
        assert_eq!(lines[1].chars().count(), 50);
    }

    #[test]
    fn wrap_plain_text_keeps_indented_overlong_lines_intact() {
        // A code-snippet line: leading indentation, then content past the
        // width. Must not emit an empty chunk or drop the indent.
        let text = format!("    let value = {};", "y".repeat(120));
        let wrapped = wrap_plain_text(&text, 100);

        assert!(wrapped.lines().all(|l| !l.trim().is_empty()));
        assert!(wrapped.starts_with("    let value"));
        assert!(wrapped.lines().all(|l| l.chars().count() <= 100));
    }
}
