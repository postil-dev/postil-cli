//! GitLab forge implementation (gitlab.com and self-managed via GITLAB_API_URL).
//!
//! Check semantics map to commit statuses: GitLab has no `neutral`, so an
//! operational error marks both statuses `failed` — fail closed, never grey.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use super::{CheckState, Forge, PrMeta, ThreadKind, check_summary, check_title};
use crate::envelope::{Envelope, Finding};

pub struct GitLab {
    http: reqwest::Client,
    api_base: String,
    token: String,
    /// URL-encoded project path (group%2Fproject).
    project: String,
    mr_iid: u64,
}

#[derive(Deserialize, Clone)]
struct DiffRefs {
    base_sha: String,
    start_sha: String,
    head_sha: String,
}

#[derive(Deserialize)]
struct MrResponse {
    title: String,
    description: Option<String>,
    diff_refs: DiffRefs,
}

#[derive(Deserialize)]
struct FileDiffItem {
    old_path: String,
    new_path: String,
    diff: String,
    #[serde(default)]
    new_file: bool,
    #[serde(default)]
    deleted_file: bool,
}

#[derive(Deserialize)]
struct CompareResponse {
    diffs: Vec<FileDiffItem>,
}

impl GitLab {
    pub fn new(repo_slug: &str, mr_iid: u64) -> Result<Self> {
        let token = std::env::var("GITLAB_TOKEN")
            .map_err(|_| anyhow!("GITLAB_TOKEN is required for --forge gitlab"))?;
        let api_base = std::env::var("GITLAB_API_URL")
            .unwrap_or_else(|_| "https://gitlab.com/api/v4".to_string());
        Ok(GitLab {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_base: api_base.trim_end_matches('/').to_string(),
            token,
            project: repo_slug.replace('/', "%2F"),
            mr_iid,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/projects/{}{path}", self.api_base, self.project)
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("User-Agent", "postil")
    }

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        Err(anyhow!("GitLab {what} failed: {status}: {snippet}"))
    }

    async fn mr(&self) -> Result<MrResponse> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/merge_requests/{}", self.mr_iid)),
            )
            .send()
            .await
            .context("fetching MR")?;
        Ok(Self::check_ok(resp, "MR fetch").await?.json().await?)
    }

    fn assemble_unified(items: &[FileDiffItem]) -> String {
        let mut out = String::new();
        for item in items {
            out.push_str(&format!(
                "diff --git a/{} b/{}\n",
                item.old_path, item.new_path
            ));
            if item.new_file {
                out.push_str(&format!("--- /dev/null\n+++ b/{}\n", item.new_path));
            } else if item.deleted_file {
                out.push_str(&format!("--- a/{}\n+++ /dev/null\n", item.old_path));
            } else {
                out.push_str(&format!(
                    "--- a/{}\n+++ b/{}\n",
                    item.old_path, item.new_path
                ));
            }
            out.push_str(&item.diff);
            if !item.diff.ends_with('\n') {
                out.push('\n');
            }
        }
        out
    }

    async fn set_status(
        &self,
        sha: &str,
        name: &str,
        state: &str,
        description: &str,
    ) -> Result<()> {
        let resp = self
            .request(reqwest::Method::POST, self.url(&format!("/statuses/{sha}")))
            .json(&json!({
                "state": state,
                "name": name,
                "description": description.chars().take(250).collect::<String>(),
            }))
            .send()
            .await
            .with_context(|| format!("setting status {name}"))?;
        Self::check_ok(resp, "status set").await?;
        Ok(())
    }
}

impl Forge for GitLab {
    fn rich_markdown(&self) -> bool {
        true
    }

    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let mr = self.mr().await?;
        Ok(PrMeta {
            title: mr.title,
            body: mr.description.unwrap_or_default(),
            head_sha: mr.diff_refs.head_sha,
            base_sha: mr.diff_refs.base_sha,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        let mut items: Vec<FileDiffItem> = Vec::new();
        for page in 1..=10 {
            let resp = self
                .request(
                    reqwest::Method::GET,
                    self.url(&format!(
                        "/merge_requests/{}/diffs?per_page=100&page={page}",
                        self.mr_iid
                    )),
                )
                .send()
                .await
                .context("fetching MR diffs")?;
            let batch: Vec<FileDiffItem> = Self::check_ok(resp, "diff fetch").await?.json().await?;
            let done = batch.len() < 100;
            items.extend(batch);
            if done {
                break;
            }
        }
        Ok(Self::assemble_unified(&items))
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!(
                    "/repository/compare?from={since_sha}&to={head_sha}"
                )),
            )
            .send()
            .await
            .context("fetching incremental compare")?;
        let cmp: CompareResponse = Self::check_ok(resp, "compare fetch").await?.json().await?;
        Ok(Self::assemble_unified(&cmp.diffs))
    }

    async fn post_review(
        &self,
        summary: &str,
        findings: &[Finding],
        _head_sha: &str,
    ) -> Result<()> {
        let mr = self.mr().await?;
        for f in findings {
            if f.body.starts_with("[carried from previous review]") {
                continue;
            }
            let body = json!({
                "body": super::finding_comment_body(f, true),
                "position": {
                    "position_type": "text",
                    "base_sha": mr.diff_refs.base_sha,
                    "start_sha": mr.diff_refs.start_sha,
                    "head_sha": mr.diff_refs.head_sha,
                    "new_path": f.path,
                    "new_line": f.line,
                },
            });
            let resp = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/merge_requests/{}/discussions", self.mr_iid)),
                )
                .json(&body)
                .send()
                .await
                .context("posting discussion")?;
            // A position the API refuses (e.g. line outside the visible diff)
            // falls back to a plain note rather than dropping the finding.
            if !resp.status().is_success() {
                let note = json!({
                    "body": format!(
                        "`{}:{}` **{}** ({})\n\n{}",
                        f.path, f.line, f.title, f.severity.as_str(), f.body
                    ),
                });
                let resp = self
                    .request(
                        reqwest::Method::POST,
                        self.url(&format!("/merge_requests/{}/notes", self.mr_iid)),
                    )
                    .json(&note)
                    .send()
                    .await
                    .context("posting fallback note")?;
                Self::check_ok(resp, "note post").await?;
            }
        }
        if !summary.is_empty() {
            let resp = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/merge_requests/{}/notes", self.mr_iid)),
                )
                .json(&json!({ "body": summary }))
                .send()
                .await
                .context("posting summary note")?;
            Self::check_ok(resp, "summary post").await?;
        }
        Ok(())
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        self.set_status(head_sha, "postil/review", "running", "review in progress")
            .await?;
        self.set_status(head_sha, "postil/gate", "running", "gate pending")
            .await?;
        // GitLab statuses are keyed by (sha, name); reuse the names as IDs.
        Ok(("postil/review".to_string(), "postil/gate".to_string()))
    }

    async fn complete_checks(
        &self,
        _advisory_id: &str,
        _gate_id: &str,
        advisory: CheckState,
        gate: CheckState,
        envelope: &Envelope,
    ) -> Result<()> {
        let head = envelope
            .head_sha
            .clone()
            .ok_or_else(|| anyhow!("envelope missing headSha for status update"))?;
        let map = |s: CheckState| match s {
            CheckState::Success => "success",
            // No neutral on GitLab; an errored run must not read as a pass.
            CheckState::Failure | CheckState::Neutral => "failed",
        };
        self.set_status(
            &head,
            "postil/review",
            map(advisory),
            &check_summary(envelope, true),
        )
        .await?;
        let gate_desc = if envelope.gate.failing {
            format!(
                "failing at {}: {}",
                envelope.gate.fail_on,
                check_title(envelope)
            )
        } else {
            format!("passing (failOn: {})", envelope.gate.fail_on)
        };
        self.set_status(&head, "postil/gate", map(gate), &gate_desc)
            .await?;
        Ok(())
    }

    /// Title and description of an issue or MR. GitLab's issue and merge-request
    /// objects both expose `title` and `description`, so only the resource path
    /// differs by `kind`.
    async fn fetch_thread(&self, number: u64, kind: ThreadKind) -> Result<(String, String)> {
        let resource = match kind {
            ThreadKind::Pull => "merge_requests",
            ThreadKind::Issue => "issues",
        };
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/{resource}/{number}")),
            )
            .send()
            .await
            .context("fetching thread")?;
        let v: serde_json::Value = Self::check_ok(resp, "thread fetch").await?.json().await?;
        let title = v["title"].as_str().unwrap_or_default().to_string();
        let body = v["description"].as_str().unwrap_or_default().to_string();
        Ok((title, body))
    }

    /// Post a top-level note on an issue or MR (the bot's reply to a mention).
    /// Both resources expose `/{resource}/{number}/notes` with a `body` field.
    async fn post_comment(&self, number: u64, kind: ThreadKind, body: &str) -> Result<()> {
        let resource = match kind {
            ThreadKind::Pull => "merge_requests",
            ThreadKind::Issue => "issues",
        };
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/{resource}/{number}/notes")),
            )
            .json(&json!({ "body": body }))
            .send()
            .await
            .context("posting note")?;
        Self::check_ok(resp, "note post").await?;
        Ok(())
    }
}
