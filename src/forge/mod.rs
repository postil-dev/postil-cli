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

#[allow(async_fn_in_trait)]
pub trait Forge {
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
}

pub fn check_title(envelope: &Envelope) -> String {
    if envelope.silent {
        "No merge-relevant findings".to_string()
    } else {
        let c = &envelope.counts;
        format!("{} error, {} warn, {} info", c.error, c.warn, c.info)
    }
}

pub fn check_summary(envelope: &Envelope) -> String {
    let mut s = String::new();
    if envelope.silent {
        s.push_str(&format!(
            "{} Postil reviewed this change and found nothing that affects the merge \
             decision.\n",
            icon_md("pass")
        ));
    } else {
        if !envelope.summary.is_empty() {
            s.push_str(&envelope.summary);
            s.push_str("\n\n");
        }
        for f in &envelope.findings {
            s.push_str(&format!(
                "- {} **{}** `{}:{}` — {} · confidence {} · kind: {}\n",
                severity_icon(f.severity),
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
        s.push_str(&format!(
            "\n{} {} finding(s) from the previous review resolved.\n",
            icon_md("pass"),
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

/// Confidence rendered as the product statusline shows it: a bare decimal
/// probability ("0.91"), not a percentage.
pub fn format_confidence(c: f64) -> String {
    format!("{:.2}", c)
}
