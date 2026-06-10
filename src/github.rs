//! GitHub API client. Just enough to:
//!   - fetch a PR's unified diff,
//!   - read repo config files at the PR head SHA,
//!   - post inline review comments (with issue-comment fallback),
//!   - create/complete a check-run.

use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::envelope::{Envelope, Finding, Severity};

const APP_USER_AGENT: &str = concat!("postil/", env!("CARGO_PKG_VERSION"));

pub struct GitHub {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone, Copy)]
pub enum CheckConclusion {
    Success,
    Neutral,
    Failure,
}

impl CheckConclusion {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckConclusion::Success => "success",
            CheckConclusion::Neutral => "neutral",
            CheckConclusion::Failure => "failure",
        }
    }
}

impl GitHub {
    pub fn new(base_url: impl Into<String>, token: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .context("github token contains invalid characters")?,
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(60))
            .build()
            .context("building GitHub HTTP client")?;
        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    pub async fn fetch_pr_diff(&self, repo: &str, pr: u64) -> Result<String> {
        let url = format!(
            "{}/repos/{repo}/pulls/{pr}",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .header(ACCEPT, "application/vnd.github.v3.diff")
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "GitHub diff fetch failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(resp.text().await?)
    }

    pub async fn read_file_at(&self, repo: &str, path: &str, sha: &str) -> Result<Option<String>> {
        let url = format!(
            "{}/repos/{repo}/contents/{path}?ref={sha}",
            self.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(&url).send().await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("contents fetch failed: {}", resp.status());
        }
        let body: ContentResponse = resp.json().await?;
        if body.encoding.as_deref() == Some("base64") {
            let cleaned: String = body
                .content
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let bytes = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes())?;
            return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
        }
        Ok(body.content)
    }

    pub async fn create_check_run(&self, repo: &str, sha: &str, name: &str) -> Result<u64> {
        let url = format!(
            "{}/repos/{repo}/check-runs",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "name": name,
            "head_sha": sha,
            "status": "in_progress",
        });
        let resp = self.http.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "create check-run failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let body: CheckRunResponse = resp.json().await?;
        Ok(body.id)
    }

    pub async fn complete_check_run(
        &self,
        repo: &str,
        check_run_id: u64,
        conclusion: CheckConclusion,
        title: &str,
        summary: &str,
        text: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/repos/{repo}/check-runs/{check_run_id}",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "status": "completed",
            "conclusion": conclusion.as_str(),
            "completed_at": chrono::Utc::now().to_rfc3339(),
            "output": {
                "title": title,
                "summary": summary,
                "text": text,
            }
        });
        let resp = self.http.patch(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "complete check-run failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }

    pub async fn post_inline_review(
        &self,
        repo: &str,
        pr: u64,
        sha: &str,
        envelope: &Envelope,
    ) -> Result<()> {
        let body_text = render_review_body(envelope);
        let comments: Vec<_> = envelope
            .findings
            .iter()
            .filter(|f| f.path != ".postil/model-output")
            .map(finding_to_review_comment)
            .collect();

        let event = match envelope.worst_severity() {
            Some(Severity::Error) => "REQUEST_CHANGES",
            _ => "COMMENT",
        };

        let url = format!(
            "{}/repos/{repo}/pulls/{pr}/reviews",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "commit_id": sha,
            "body": body_text,
            "event": event,
            "comments": comments,
        });

        let resp = self.http.post(&url).json(&body).send().await?;
        if resp.status().is_success() {
            return Ok(());
        }

        // Inline post can 422 when GitHub considers a finding outside the diff
        // hunk. Fall back to an issue comment so the signal still reaches the
        // PR.
        let status = resp.status();
        let resp_body = resp.text().await.unwrap_or_default();
        warn!(
            %status,
            body = %resp_body,
            "inline review post failed; falling back to issue comment"
        );
        self.post_issue_comment(repo, pr, &body_text).await
    }

    pub async fn post_issue_comment(&self, repo: &str, pr: u64, body: &str) -> Result<()> {
        let url = format!(
            "{}/repos/{repo}/issues/{pr}/comments",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "issue comment failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }

    pub async fn approve_pr(&self, repo: &str, pr: u64, sha: &str) -> Result<()> {
        let url = format!(
            "{}/repos/{repo}/pulls/{pr}/reviews",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({
            "commit_id": sha,
            "body": "Postil reviewed this change and has no merge-relevant findings.",
            "event": "APPROVE",
        });
        let resp = self.http.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "approve failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct CheckRunResponse {
    id: u64,
}

#[derive(Deserialize)]
struct ContentResponse {
    content: Option<String>,
    encoding: Option<String>,
}

#[derive(Serialize)]
struct ReviewComment<'a> {
    path: &'a str,
    line: u32,
    side: &'a str,
    body: String,
}

fn finding_to_review_comment(f: &Finding) -> ReviewComment<'_> {
    ReviewComment {
        path: &f.path,
        line: f.line,
        side: "RIGHT",
        body: render_finding_comment(f),
    }
}

pub fn render_finding_comment(f: &Finding) -> String {
    let mut out = format!("**{} {}**", f.severity.glyph(), severity_label(f.severity));
    if let Some(kind) = f.kind {
        out.push_str(&format!(" · `{}`", kind_label(kind)));
    }
    out.push_str("\n\n");
    out.push_str(&f.body);
    out
}

pub fn render_review_body(env: &Envelope) -> String {
    if env.findings.is_empty() {
        return env.summary.clone();
    }
    let mut out = String::new();
    if !env.summary.trim().is_empty() {
        out.push_str(env.summary.trim());
        out.push_str("\n\n");
    }
    let mut chips = String::from("status: ");
    if env.findings.iter().any(|f| f.severity == Severity::Error) {
        chips.push('❌');
    }
    if env.findings.iter().any(|f| f.severity == Severity::Warn) {
        chips.push_str("⚠️");
    }
    if env.findings.iter().any(|f| f.severity == Severity::Info) {
        chips.push_str("ℹ️");
    }
    out.push_str(&chips);
    out
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Error => "error",
    }
}

fn kind_label(k: crate::envelope::FindingKind) -> &'static str {
    use crate::envelope::FindingKind::*;
    match k {
        Risk => "risk",
        HumanEscalation => "human-escalation",
        Guardrail => "guardrail",
        Uncertainty => "uncertainty",
    }
}

pub fn envelope_to_conclusion(env: &Envelope, fail_on: Severity) -> CheckConclusion {
    let Some(worst) = env.worst_severity() else {
        return CheckConclusion::Success;
    };
    if worst.rank() >= fail_on.rank() {
        CheckConclusion::Failure
    } else {
        CheckConclusion::Neutral
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, Finding, FindingKind, Usage};

    fn f(s: Severity) -> Finding {
        Finding {
            path: "a".into(),
            line: 1,
            severity: s,
            kind: Some(FindingKind::Risk),
            body: "b".into(),
        }
    }

    #[test]
    fn conclusion_clean_is_success() {
        let env = Envelope {
            summary: "".into(),
            findings: vec![],
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        };
        assert!(matches!(
            envelope_to_conclusion(&env, Severity::Error),
            CheckConclusion::Success
        ));
    }

    #[test]
    fn conclusion_warn_with_fail_on_error_is_neutral() {
        let env = Envelope {
            summary: "x".into(),
            findings: vec![f(Severity::Warn)],
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        };
        assert!(matches!(
            envelope_to_conclusion(&env, Severity::Error),
            CheckConclusion::Neutral
        ));
    }

    #[test]
    fn conclusion_error_is_failure() {
        let env = Envelope {
            summary: "x".into(),
            findings: vec![f(Severity::Error)],
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        };
        assert!(matches!(
            envelope_to_conclusion(&env, Severity::Error),
            CheckConclusion::Failure
        ));
    }

    #[test]
    fn review_body_includes_status_line_when_findings() {
        let env = Envelope {
            summary: "two issues".into(),
            findings: vec![f(Severity::Error), f(Severity::Warn)],
            usage: Usage::default(),
            model_used: None,
            cli_version: None,
        };
        let body = render_review_body(&env);
        assert!(body.contains("two issues"));
        assert!(body.contains("status:"));
        assert!(body.contains("❌"));
        assert!(body.contains("⚠️"));
    }
}
