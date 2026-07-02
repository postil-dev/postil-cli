//! GitHub forge implementation (github.com and GHES via GITHUB_API_URL).

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use super::{CheckState, Forge, PrMeta, ThreadKind, check_summary, check_title};
use crate::envelope::{Envelope, Finding, Severity};

pub struct GitHub {
    http: reqwest::Client,
    api_base: String,
    token: String,
    owner: String,
    repo: String,
    pr: u64,
}

impl GitHub {
    pub fn new(repo_slug: &str, pr: u64) -> Result<Self> {
        let (owner, repo) = repo_slug
            .split_once('/')
            .ok_or_else(|| anyhow!("--repo must be owner/name, got {repo_slug:?}"))?;
        let token = std::env::var("GITHUB_TOKEN")
            .map_err(|_| anyhow!("GITHUB_TOKEN is required for --forge github"))?;
        let api_base = std::env::var("GITHUB_API_URL")
            .unwrap_or_else(|_| "https://api.github.com".to_string());
        Ok(GitHub {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_base: api_base.trim_end_matches('/').to_string(),
            token,
            owner: owner.to_string(),
            repo: repo.to_string(),
            pr,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/repos/{}/{}{path}", self.api_base, self.owner, self.repo)
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .bearer_auth(&self.token)
            .header("User-Agent", "postil")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        Err(anyhow!("GitHub {what} failed: {status}: {snippet}"))
    }
}

#[derive(Deserialize)]
struct PrResponse {
    title: String,
    body: Option<String>,
    head: RefObj,
    base: RefObj,
}

#[derive(Deserialize)]
struct RefObj {
    sha: String,
}

#[derive(Deserialize)]
struct CheckRun {
    id: u64,
}

impl Forge for GitHub {
    fn rich_markdown(&self) -> bool {
        true
    }

    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pulls/{}", self.pr)),
            )
            .send()
            .await
            .context("fetching PR metadata")?;
        let pr: PrResponse = Self::check_ok(resp, "PR fetch").await?.json().await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.body.unwrap_or_default(),
            head_sha: pr.head.sha,
            base_sha: pr.base.sha,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pulls/{}", self.pr)),
            )
            .header("Accept", "application/vnd.github.v3.diff")
            .send()
            .await
            .context("fetching PR diff")?;
        Ok(Self::check_ok(resp, "diff fetch").await?.text().await?)
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/compare/{since_sha}...{head_sha}")),
            )
            .header("Accept", "application/vnd.github.v3.diff")
            .send()
            .await
            .context("fetching incremental diff")?;
        Ok(Self::check_ok(resp, "compare fetch").await?.text().await?)
    }

    async fn post_review(&self, summary: &str, findings: &[Finding], head_sha: &str) -> Result<()> {
        let comments: Vec<_> = findings
            .iter()
            // Carried findings already have comments from the previous review.
            .filter(|f| !f.body.starts_with("[carried from previous review]"))
            // Synthetic-path findings (PR description, fail-closed markers) have
            // no real file line to anchor an inline comment; they surface only in
            // the summary body.
            .filter(|f| !super::is_synthetic_path(&f.path))
            .map(|f| {
                let mut c = json!({
                    "path": f.path,
                    "line": f.line,
                    "side": "RIGHT",
                    "body": super::finding_comment_body(f, true),
                });
                if let Some(end) = f.end_line
                    && end > f.line
                {
                    c["start_line"] = json!(f.line);
                    c["line"] = json!(end);
                    c["start_side"] = json!("RIGHT");
                }
                c
            })
            .collect();
        if comments.is_empty() && summary.is_empty() {
            return Ok(());
        }
        let body = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": summary,
            "comments": comments,
        });
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pulls/{}/reviews", self.pr)),
            )
            .json(&body)
            .send()
            .await
            .context("posting review")?;
        Self::check_ok(resp, "review post").await?;
        Ok(())
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        let mut ids = Vec::with_capacity(2);
        for name in ["postil/review", "postil/gate"] {
            let resp = self
                .request(reqwest::Method::POST, self.url("/check-runs"))
                .json(&json!({
                    "name": name,
                    "head_sha": head_sha,
                    "status": "in_progress",
                }))
                .send()
                .await
                .with_context(|| format!("creating check-run {name}"))?;
            let run: CheckRun = Self::check_ok(resp, "check-run create")
                .await?
                .json()
                .await?;
            ids.push(run.id.to_string());
        }
        Ok((ids[0].clone(), ids[1].clone()))
    }

    async fn complete_checks(
        &self,
        advisory_id: &str,
        gate_id: &str,
        advisory: CheckState,
        gate: CheckState,
        envelope: &Envelope,
    ) -> Result<()> {
        let conclusion = |s: CheckState| match s {
            CheckState::Success => "success",
            CheckState::Failure => "failure",
            CheckState::Neutral => "neutral",
        };
        let annotations: Vec<_> = envelope
            .findings
            .iter()
            // Synthetic-path findings have no real file line to annotate; they
            // are already carried in the check-run summary body.
            .filter(|f| !super::is_synthetic_path(&f.path))
            .take(50) // GitHub caps annotations per request at 50.
            .map(|f| {
                json!({
                    "path": f.path,
                    "start_line": f.line,
                    "end_line": f.end_line.unwrap_or(f.line),
                    "annotation_level": match f.severity {
                        Severity::Info => "notice",
                        Severity::Warn => "warning",
                        Severity::Error => "failure",
                    },
                    "title": f.title,
                    "message": f.body.chars().take(800).collect::<String>(),
                })
            })
            .collect();
        for (id, state, name, with_annotations) in [
            (advisory_id, advisory, "postil/review", true),
            (gate_id, gate, "postil/gate", false),
        ] {
            let gate_note = if name == "postil/gate" {
                let failing: Vec<_> = envelope
                    .findings
                    .iter()
                    .filter(|f| {
                        crate::config::GateLevel::parse(&envelope.gate.fail_on)
                            .map(|g| g.fails(f.severity))
                            .unwrap_or(false)
                    })
                    .map(|f| format!("- `{}:{}` {}", f.path, f.line, f.title))
                    .collect();
                if envelope.gate.failing {
                    format!(
                        "Gate failing at `{}` on:\n{}\n",
                        envelope.gate.fail_on,
                        failing.join("\n")
                    )
                } else {
                    format!("Gate (`failOn: {}`) passing.\n", envelope.gate.fail_on)
                }
            } else {
                check_summary(envelope, true)
            };
            let mut output = json!({
                // GitHub rejects title >255 and summary >65535 with HTTP 422,
                // which would abort posting both checks. Cap both defensively.
                "title": super::cap_check_title(&check_title(envelope)),
                "summary": super::cap_check_summary(&gate_note),
            });
            if with_annotations && !annotations.is_empty() {
                output["annotations"] = json!(annotations);
            }
            let resp = self
                .request(
                    reqwest::Method::PATCH,
                    self.url(&format!("/check-runs/{id}")),
                )
                .json(&json!({
                    "status": "completed",
                    "conclusion": conclusion(state),
                    "output": output,
                }))
                .send()
                .await
                .with_context(|| format!("completing check-run {name}"))?;
            Self::check_ok(resp, "check-run complete").await?;
        }
        Ok(())
    }

    /// Title and body of an issue or PR (the issues API covers both, so `kind`
    /// is not needed here).
    async fn fetch_thread(&self, number: u64, _kind: ThreadKind) -> Result<(String, String)> {
        let resp = self
            .request(reqwest::Method::GET, self.url(&format!("/issues/{number}")))
            .send()
            .await
            .context("fetching issue")?;
        let v: serde_json::Value = Self::check_ok(resp, "issue fetch").await?.json().await?;
        let title = v["title"].as_str().unwrap_or_default().to_string();
        let body = v["body"].as_str().unwrap_or_default().to_string();
        Ok((title, body))
    }

    /// Post a top-level comment on an issue or PR (the bot's reply to a mention).
    async fn post_comment(&self, number: u64, _kind: ThreadKind, body: &str) -> Result<()> {
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/issues/{number}/comments")),
            )
            .json(&json!({ "body": body }))
            .send()
            .await
            .context("posting comment")?;
        Self::check_ok(resp, "comment post").await?;
        Ok(())
    }
}
