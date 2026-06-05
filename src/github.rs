use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    config::{RepoReviewConfig, ReviewTarget, translate_coderabbit, translate_kodo},
    review::{Finding, ReviewEnvelope, severity_marks},
    text::limit_text,
};

#[derive(Debug, Clone)]
pub struct GithubClient {
    http: Client,
    base_url: String,
    token: String,
}

impl GithubClient {
    pub fn new(base_url: String, token: String) -> Result<Self> {
        Ok(Self {
            http: Client::builder()
                .user_agent("postil-reviewer/0.1.0")
                .build()
                .context("build GitHub HTTP client")?,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn fetch_diff(&self, target: &ReviewTarget, limit: usize) -> Result<String> {
        let res = self
            .http
            .get(self.pull_url(target))
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github.v3.diff")
            .send()
            .await
            .context("fetch pull request diff")?;
        let status = res.status();
        if !status.is_success() {
            return Err(anyhow!(
                "github diff {}: {}",
                status.as_u16(),
                res.text().await.unwrap_or_default()
            ));
        }
        let diff = res.text().await.context("read diff body")?;
        Ok(limit_text(diff, limit))
    }

    pub async fn load_repo_config(&self, target: &ReviewTarget) -> Result<RepoReviewConfig> {
        let candidates = [
            (".postil.yaml", "postil"),
            (".postil.yml", "postil"),
            (".postil.json", "postil"),
            (".coderabbit.yaml", "coderabbit"),
            (".coderabbit.yml", "coderabbit"),
            (".kodo.yaml", "kodo"),
            (".kodo.yml", "kodo"),
        ];
        let Some(ref sha) = target.head_sha else {
            return Ok(RepoReviewConfig::default());
        };
        for (path, kind) in candidates {
            match self.fetch_raw_file(target, sha, path).await {
                Ok(Some(text)) => {
                    let parsed = match kind {
                        "postil" => RepoReviewConfig::from_text(path, &text),
                        "coderabbit" => translate_coderabbit(&text),
                        "kodo" => translate_kodo(&text),
                        _ => unreachable!(),
                    };
                    if let Ok(config) = parsed {
                        return Ok(config);
                    }
                }
                Ok(None) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(RepoReviewConfig::default())
    }

    async fn fetch_raw_file(
        &self,
        target: &ReviewTarget,
        sha: &str,
        path: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.base_url, target.owner, target.repo, path, sha
        );
        let res = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github.v3.raw")
            .send()
            .await
            .with_context(|| format!("fetch config {path}"))?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = res.status();
        if !status.is_success() {
            return Err(anyhow!(
                "github config {path} {}: {}",
                status.as_u16(),
                res.text().await.unwrap_or_default()
            ));
        }
        Ok(Some(res.text().await.context("read config body")?))
    }

    pub async fn post_inline_review(
        &self,
        target: &ReviewTarget,
        envelope: &ReviewEnvelope,
        body: &str,
    ) -> Result<()> {
        let comments: Vec<ReviewComment> = envelope
            .findings
            .iter()
            .map(|f| ReviewComment {
                path: f.path.clone(),
                line: f.line,
                side: "RIGHT",
                body: format!("**{}** · {}", f.severity.as_str().to_uppercase(), f.body),
            })
            .collect();
        let payload = PullReviewRequest {
            commit_id: target.head_sha.clone(),
            event: if comments.is_empty() {
                "APPROVE"
            } else {
                "COMMENT"
            },
            body: if body.trim().is_empty() {
                None
            } else {
                Some(body)
            },
            comments: if comments.is_empty() {
                None
            } else {
                Some(comments)
            },
        };
        let res = self
            .http
            .post(format!(
                "{}/repos/{}/{}/pulls/{}/reviews",
                self.base_url, target.owner, target.repo, target.pull_number
            ))
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github+json")
            .json(&payload)
            .send()
            .await
            .context("post pull request review")?;
        let status = res.status();
        if !status.is_success() {
            return Err(anyhow!(
                "github review {}: {}",
                status.as_u16(),
                res.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    pub async fn post_issue_comment(&self, target: &ReviewTarget, body: &str) -> Result<()> {
        if body.trim().is_empty() {
            return Ok(());
        }
        let res = self
            .http
            .post(format!(
                "{}/repos/{}/{}/issues/{}/comments",
                self.base_url, target.owner, target.repo, target.pull_number
            ))
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github+json")
            .json(&json!({ "body": body }))
            .send()
            .await
            .context("post fallback issue comment")?;
        let status = res.status();
        if !status.is_success() {
            return Err(anyhow!(
                "github issue comment {}: {}",
                status.as_u16(),
                res.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    pub async fn complete_check_run(
        &self,
        target: &ReviewTarget,
        check_name: &str,
        check_run_id: Option<u64>,
        conclusion: &str,
        output: CheckOutput,
        started_at: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let (method, url, payload) = if let Some(id) = check_run_id {
            (
                reqwest::Method::PATCH,
                format!(
                    "{}/repos/{}/{}/check-runs/{}",
                    self.base_url, target.owner, target.repo, id
                ),
                json!({
                    "status": "completed",
                    "conclusion": conclusion,
                    "completed_at": now,
                    "output": output,
                }),
            )
        } else {
            (
                reqwest::Method::POST,
                format!(
                    "{}/repos/{}/{}/check-runs",
                    self.base_url, target.owner, target.repo
                ),
                json!({
                    "name": check_name,
                    "head_sha": target
                        .head_sha
                        .as_deref()
                        .context("head sha is required when creating a check run")?,
                    "status": "completed",
                    "conclusion": conclusion,
                    "started_at": started_at,
                    "completed_at": now,
                    "output": output,
                }),
            )
        };
        let res = self
            .http
            .request(method, url)
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github+json")
            .json(&payload)
            .send()
            .await
            .context("create check run")?;
        let status = res.status();
        if !status.is_success() {
            return Err(anyhow!(
                "github check-run {}: {}",
                status.as_u16(),
                res.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    fn pull_url(&self, target: &ReviewTarget) -> String {
        format!(
            "{}/repos/{}/{}/pulls/{}",
            self.base_url, target.owner, target.repo, target.pull_number
        )
    }
}

#[derive(Debug, Serialize)]
struct PullReviewRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_id: Option<String>,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comments: Option<Vec<ReviewComment>>,
}

#[derive(Debug, Serialize)]
struct ReviewComment {
    path: String,
    line: u64,
    side: &'static str,
    body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckOutput {
    pub title: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl CheckOutput {
    pub fn empty() -> Self {
        Self {
            title: "Empty diff".to_string(),
            summary: "Nothing to review.".to_string(),
            text: None,
        }
    }

    pub fn from_envelope(envelope: &ReviewEnvelope) -> Self {
        let marks = severity_marks(&envelope.findings);
        let title = if marks.is_empty() {
            "No merge-relevant findings".to_string()
        } else {
            marks
        };
        let text = if envelope.findings.is_empty() {
            None
        } else {
            Some(render_findings(&envelope.findings))
        };
        Self {
            title,
            summary: if envelope.summary.trim().is_empty() {
                if envelope.findings.is_empty() {
                    String::new()
                } else {
                    "See inline review comments.".to_string()
                }
            } else {
                envelope.summary.clone()
            },
            text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Severity,
        review::{FindingKind, TokenUsage},
    };

    #[test]
    fn clean_check_output_has_no_recap_body() {
        let output = CheckOutput::from_envelope(&ReviewEnvelope {
            summary: String::new(),
            findings: Vec::new(),
            usage: TokenUsage::default(),
            model_used: "m".into(),
        });

        assert_eq!(output.title, "No merge-relevant findings");
        assert_eq!(output.summary, "");
        assert_eq!(output.text, None);
    }

    #[test]
    fn dirty_check_output_uses_repeated_severity_marks() {
        let output = CheckOutput::from_envelope(&ReviewEnvelope {
            summary: String::new(),
            findings: vec![
                finding(Severity::Error),
                finding(Severity::Warn),
                finding(Severity::Warn),
                finding(Severity::Info),
            ],
            usage: TokenUsage::default(),
            model_used: "m".into(),
        });

        assert_eq!(output.title, "!!! !! !! !");
        assert!(!output.title.contains("warning"));
        assert!(!output.title.contains("error"));
        assert!(!output.summary.contains("No merge-relevant"));
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            path: "src/lib.rs".into(),
            line: 1,
            severity,
            kind: Some(FindingKind::Risk),
            body: "risk".into(),
        }
    }
}

fn render_findings(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "**{}** `{}`:{}\n\n{}",
                f.severity.as_str().to_uppercase(),
                f.path,
                f.line,
                f.body
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n---\n\n")
}

pub fn check_conclusion(envelope: &ReviewEnvelope) -> &'static str {
    if envelope
        .findings
        .iter()
        .any(|f| f.severity == crate::config::Severity::Error)
    {
        "failure"
    } else if envelope
        .findings
        .iter()
        .any(|f| f.severity == crate::config::Severity::Warn)
    {
        "neutral"
    } else {
        "success"
    }
}
