//! Azure DevOps Services forge (`dev.azure.com`; Server/collection via
//! `AZURE_DEVOPS_API_URL`).
//!
//! Azure has no "PR unified diff" endpoint: it returns a list of changed paths
//! plus per-version file content. Postil fetches both sides of each changed
//! text file and reconstructs a standard unified diff locally so the same diff
//! parser and grounding logic apply as for every other forge.
//!
//! Auth: `AZURE_DEVOPS_TOKEN` (a PAT) sent via HTTP Basic with an empty user.
//! `--repo` is `organization/project/repository`. Checks map to PR statuses;
//! Azure has no neutral, so an operational error marks the gate `failed`.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use super::{CheckState, Forge, PrMeta, check_summary, check_title};
use crate::envelope::{Envelope, Finding};

const API_VERSION: &str = "7.1";

pub struct Azure {
    http: reqwest::Client,
    base: String,
    token: String,
    org: String,
    project: String,
    repo: String,
    pr: u64,
}

#[derive(Deserialize)]
struct MergeCommit {
    #[serde(rename = "commitId")]
    commit_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrResponse {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    last_merge_source_commit: MergeCommit,
    last_merge_target_commit: MergeCommit,
}

#[derive(Deserialize)]
struct ChangeItem {
    #[serde(default)]
    path: String,
    #[serde(rename = "isFolder", default)]
    is_folder: bool,
}

#[derive(Deserialize)]
struct Change {
    #[serde(default)]
    item: Option<ChangeItem>,
    #[serde(rename = "changeType", default)]
    change_type: String,
}

#[derive(Deserialize)]
struct DiffResponse {
    #[serde(default)]
    changes: Vec<Change>,
}

impl Azure {
    pub fn new(repo_slug: &str, pr: u64) -> Result<Self> {
        let parts: Vec<&str> = repo_slug.splitn(3, '/').collect();
        let [org, project, repo] = parts.as_slice() else {
            return Err(anyhow!(
                "--repo must be organization/project/repository for --forge azure, got {repo_slug:?}"
            ));
        };
        let token = std::env::var("AZURE_DEVOPS_TOKEN")
            .map_err(|_| anyhow!("AZURE_DEVOPS_TOKEN (a PAT) is required for --forge azure"))?;
        let base = std::env::var("AZURE_DEVOPS_API_URL")
            .unwrap_or_else(|_| "https://dev.azure.com".to_string());
        Ok(Azure {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            base: base.trim_end_matches('/').to_string(),
            token,
            org: org.to_string(),
            project: project.to_string(),
            repo: repo.to_string(),
            pr,
        })
    }

    /// `{base}/{org}/{project}/_apis/git/repositories/{repo}{path}` with the
    /// api-version query appended (preserving any existing query string).
    fn url(&self, path: &str, query: &str) -> String {
        let sep = if query.is_empty() { "" } else { "&" };
        format!(
            "{}/{}/{}/_apis/git/repositories/{}{path}?{query}{sep}api-version={API_VERSION}",
            self.base, self.org, self.project, self.repo
        )
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .basic_auth("", Some(&self.token))
            .header("User-Agent", "postil")
    }

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        Err(anyhow!("Azure DevOps {what} failed: {status}: {snippet}"))
    }

    async fn pr(&self) -> Result<PrResponse> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pullRequests/{}", self.pr), ""),
            )
            .send()
            .await
            .context("fetching PR")?;
        Ok(Self::check_ok(resp, "PR fetch").await?.json().await?)
    }

    /// File content at a commit, or empty string if the file does not exist
    /// there (added/deleted files have one missing side).
    async fn item_at(&self, path: &str, commit: &str) -> Result<String> {
        let q = format!(
            "path={}&versionType=commit&version={commit}&includeContent=true",
            urlencode(path)
        );
        let resp = self
            .request(reqwest::Method::GET, self.url("/items", &q))
            .header("Accept", "text/plain")
            .send()
            .await
            .with_context(|| format!("fetching {path} at {commit}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(String::new());
        }
        Ok(Self::check_ok(resp, "item fetch").await?.text().await?)
    }

    async fn build_diff(&self, base_sha: &str, head_sha: &str) -> Result<String> {
        let q = format!(
            "baseVersion={base_sha}&baseVersionType=commit&\
             targetVersion={head_sha}&targetVersionType=commit"
        );
        let resp = self
            .request(reqwest::Method::GET, self.url("/diffs/commits", &q))
            .send()
            .await
            .context("fetching change list")?;
        let diff: DiffResponse = Self::check_ok(resp, "change list fetch")
            .await?
            .json()
            .await?;

        let mut out = String::new();
        for change in &diff.changes {
            let Some(item) = &change.item else { continue };
            if item.is_folder || item.path.is_empty() {
                continue;
            }
            let path = item.path.trim_start_matches('/');
            let ct = change.change_type.to_ascii_lowercase();
            let is_add = ct.contains("add");
            let is_delete = ct.contains("delete");
            let old = if is_add {
                String::new()
            } else {
                self.item_at(path, base_sha).await?
            };
            let new = if is_delete {
                String::new()
            } else {
                self.item_at(path, head_sha).await?
            };
            if old == new {
                continue;
            }
            out.push_str(&unified_file_diff(path, &old, &new, is_add, is_delete));
        }
        Ok(out)
    }

    async fn set_status(
        &self,
        sha: &str,
        name: &str,
        state: &str,
        description: &str,
    ) -> Result<()> {
        // PR statuses live under the PR, keyed by genre/name.
        let body = json!({
            "state": state,
            "description": description.chars().take(250).collect::<String>(),
            "targetUrl": "https://postil.dev",
            "context": { "name": name, "genre": "postil" },
        });
        let _ = sha; // PR statuses attach to the PR iteration, not the commit.
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pullRequests/{}/statuses", self.pr), ""),
            )
            .json(&body)
            .send()
            .await
            .with_context(|| format!("setting status {name}"))?;
        Self::check_ok(resp, "status set").await?;
        Ok(())
    }
}

impl Forge for Azure {
    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let pr = self.pr().await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.description,
            head_sha: pr.last_merge_source_commit.commit_id,
            base_sha: pr.last_merge_target_commit.commit_id,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        let pr = self.pr().await?;
        self.build_diff(
            &pr.last_merge_target_commit.commit_id,
            &pr.last_merge_source_commit.commit_id,
        )
        .await
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        self.build_diff(since_sha, head_sha).await
    }

    async fn post_review(
        &self,
        summary: &str,
        findings: &[Finding],
        _head_sha: &str,
    ) -> Result<()> {
        for f in findings {
            if f.body.starts_with("[carried from previous review]") {
                continue;
            }
            // Azure threads anchor to a file + line range with right-side context.
            let body = json!({
                "comments": [{
                    "parentCommentId": 0,
                    "commentType": 1,
                    "content": format!(
                        "**{}** ({} / {} confidence)\n\n{}",
                        f.title, f.severity.as_str(), super::format_confidence(f.confidence), f.body
                    ),
                }],
                "status": 1,
                "threadContext": {
                    "filePath": format!("/{}", f.path),
                    "rightFileStart": { "line": f.line, "offset": 1 },
                    "rightFileEnd": { "line": f.end_line.unwrap_or(f.line), "offset": 1 },
                },
            });
            let resp = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/pullRequests/{}/threads", self.pr), ""),
                )
                .json(&body)
                .send()
                .await
                .context("posting review thread")?;
            if !resp.status().is_success() {
                // Fall back to a non-anchored thread.
                let note = json!({
                    "comments": [{
                        "parentCommentId": 0,
                        "commentType": 1,
                        "content": format!(
                            "`{}:{}` **{}** ({})\n\n{}",
                            f.path, f.line, f.title, f.severity.as_str(), f.body
                        ),
                    }],
                    "status": 1,
                });
                let resp = self
                    .request(
                        reqwest::Method::POST,
                        self.url(&format!("/pullRequests/{}/threads", self.pr), ""),
                    )
                    .json(&note)
                    .send()
                    .await
                    .context("posting fallback thread")?;
                Self::check_ok(resp, "thread post").await?;
            }
        }
        if !summary.is_empty() {
            let resp = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/pullRequests/{}/threads", self.pr), ""),
                )
                .json(&json!({
                    "comments": [{ "parentCommentId": 0, "commentType": 1, "content": summary }],
                    "status": 1,
                }))
                .send()
                .await
                .context("posting summary thread")?;
            Self::check_ok(resp, "summary post").await?;
        }
        Ok(())
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        self.set_status(head_sha, "postil/review", "pending", "review in progress")
            .await?;
        self.set_status(head_sha, "postil/gate", "pending", "gate pending")
            .await?;
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
        let head = envelope.head_sha.clone().unwrap_or_default();
        let map = |s: CheckState| match s {
            CheckState::Success => "succeeded",
            // No neutral on Azure; an errored run must not read as a pass.
            CheckState::Failure | CheckState::Neutral => "failed",
        };
        self.set_status(
            &head,
            "postil/review",
            map(advisory),
            &check_summary(envelope),
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
}

/// Build one file's unified-diff section in the format `diff.rs` expects:
/// a `diff --git` header (so the parser seeds the path even for additions),
/// the `---`/`+++` lines, and `similar`-generated hunks.
fn unified_file_diff(path: &str, old: &str, new: &str, is_add: bool, is_delete: bool) -> String {
    use similar::TextDiff;
    let mut out = format!("diff --git a/{path} b/{path}\n");
    if is_add {
        out.push_str(&format!("--- /dev/null\n+++ b/{path}\n"));
    } else if is_delete {
        out.push_str(&format!("--- a/{path}\n+++ /dev/null\n"));
    } else {
        out.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
    }
    let diff = TextDiff::from_lines(old, new);
    let hunks = diff.unified_diff().context_radius(3).to_string();
    out.push_str(&hunks);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Minimal percent-encoding for the `path` query-parameter value. `/` is left
/// literal on purpose: it appears after `?`, so it is unambiguously part of the
/// query value (not the URL path), Azure accepts it, and some gateways reject an
/// over-encoded `%2F`. Everything outside the RFC 3986 unreserved set is encoded.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff;

    #[test]
    fn reconstructed_diff_parses_and_grounds() {
        let old = "fn a() {\n    let x = 1;\n}\n";
        let new = "fn a() {\n    let x = 2;\n}\n";
        let section = unified_file_diff("src/a.rs", old, new, false, false);
        assert!(section.contains("diff --git a/src/a.rs b/src/a.rs"));
        let parsed = diff::parse(&section);
        let index = diff::DiffIndex::build(&parsed);
        // The changed line (2) must be grounded so findings on it are kept.
        assert!(index.contains("src/a.rs", 2));
    }

    #[test]
    fn added_file_uses_dev_null_base() {
        let section = unified_file_diff("new.rs", "", "a\nb\n", true, false);
        assert!(section.contains("--- /dev/null"));
        assert!(section.contains("+++ b/new.rs"));
        let parsed = diff::parse(&section);
        assert_eq!(parsed.files.len(), 1);
    }
}
