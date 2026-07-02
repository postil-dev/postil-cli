//! Forge abstraction: everything Postil needs from a code host.
//!
//! Ships GitHub, GitLab, Bitbucket, and Azure DevOps — each covering its
//! self-managed/server variant through a custom base-URL environment variable.

pub mod azure;
pub mod bitbucket;
pub mod github;
pub mod gitlab;

use anyhow::Result;

use crate::envelope::{Envelope, Finding, Severity};

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

    for (column, (idx, ch)) in line.char_indices().enumerate() {
        if column > width {
            break;
        }
        if ch == ' ' && idx > 0 {
            last_space = Some(idx);
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
    path.starts_with(".postil/")
}

pub fn check_title(envelope: &Envelope) -> String {
    if envelope.silent {
        "No merge-relevant findings".to_string()
    } else {
        let c = &envelope.counts;
        format!("{} error, {} warn, {} info", c.error, c.warn, c.info)
    }
}

pub fn check_summary(envelope: &Envelope, rich: bool) -> String {
    let mut s = String::new();
    let pass = |s: &mut String| {
        if rich {
            s.push_str(&icon_md("pass"));
            s.push(' ');
        }
    };
    if envelope.silent {
        pass(&mut s);
        s.push_str(
            "Postil reviewed this change and found nothing that affects the merge decision.\n",
        );
    } else {
        if !envelope.summary.is_empty() {
            s.push_str(&envelope.summary);
            s.push_str("\n\n");
        }
        for f in &envelope.findings {
            let icon = if rich {
                format!("{} ", severity_icon(f.severity))
            } else {
                String::new()
            };
            s.push_str(&format!(
                "- {}**{}** `{}:{}` — {} · confidence {} · kind: {}\n",
                icon,
                f.severity.as_str(),
                f.path,
                f.line,
                f.title,
                format_confidence(f.confidence),
                f.kind.as_str(),
            ));
        }
    }
    if !envelope.resolved.is_empty() {
        s.push('\n');
        pass(&mut s);
        s.push_str(&format!(
            "{} finding(s) from the previous review resolved.\n",
            envelope.resolved.len()
        ));
    }
    if envelope.counts.suppressed > 0 {
        s.push_str(&format!(
            "\n{} finding(s) suppressed by policy (confidence/severity/ignore).\n",
            envelope.counts.suppressed
        ));
    }
    s.push_str(&format!("\nModel: {}\n", envelope.model_used));
    s
}

/// The body of one inline finding comment: icon (rich forges), bold title,
/// severity / confidence / kind statusline, then the finding body.
pub fn finding_comment_body(f: &Finding, rich: bool) -> String {
    let icon = if rich {
        format!("{} ", severity_icon(f.severity))
    } else {
        String::new()
    };
    format!(
        "{}**{}**\n`{}` · confidence {} · kind: {}\n\n{}",
        icon,
        f.title,
        f.severity.as_str(),
        format_confidence(f.confidence),
        f.kind.as_str(),
        f.body
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
            title: "Unsanitized input reaches query".into(),
            body: "user_input flows into exec_query.".into(),
        }
    }

    #[test]
    fn rich_comment_carries_brand_icon_and_statusline() {
        let body = finding_comment_body(&finding(), true);
        assert!(body.contains("https://postil.dev/status/error.svg"));
        assert!(body.contains("confidence 0.91 · kind: risk"));
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
    fn silent_summary_icon_only_when_rich() {
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: crate::envelope::Gate {
                fail_on: "error".into(),
                failing: false,
            },
            model_used: "m".into(),
            usage: Default::default(),
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        assert!(check_summary(&env, true).contains("status/pass.svg"));
        assert!(!check_summary(&env, false).contains("<img"));
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
}
