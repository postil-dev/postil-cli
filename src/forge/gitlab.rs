//! GitLab forge implementation (gitlab.com and self-managed via GITLAB_API_URL).
//!
//! Check semantics map to commit statuses: GitLab has no `neutral`, so an
//! operational error marks both statuses `failed`: fail closed, never grey.

use anyhow::{Context, Result, anyhow, ensure};
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
    #[cfg(test)]
    diff: String,
    new_file: bool,
    deleted_file: bool,
    #[cfg(test)]
    collapsed: bool,
    #[cfg(test)]
    too_large: bool,
}

#[derive(Deserialize)]
struct CompareResponse {
    compare_timeout: bool,
    diffs: Vec<FileDiffItem>,
}

#[derive(Deserialize)]
struct DiffVersion {
    state: String,
    real_size: String,
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
        let request_id = super::response_request_id(&resp).unwrap_or_else(|| "none".into());
        Err(super::http_failure(
            status,
            format!("GitLab {what} failed: {status} (request id {request_id})"),
        ))
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
        super::bounded_response_json(Self::check_ok(resp, "MR fetch").await?, "GitLab MR").await
    }

    #[cfg(test)]
    fn append_unified(out: &mut String, items: &[FileDiffItem]) -> Result<()> {
        for item in items {
            if item.collapsed || item.too_large {
                return Err(anyhow!(
                    "GitLab omitted diff content for {}; refusing a partial review",
                    item.new_path
                ));
            }
            let old_marker = crate::diff::display_path(&format!("a/{}", item.old_path));
            let new_marker = crate::diff::display_path(&format!("b/{}", item.new_path));
            let mut section = format!("diff --git {old_marker} {new_marker}\n");
            if item.new_file {
                section.push_str(&format!("--- /dev/null\n+++ {new_marker}\n"));
            } else if item.deleted_file {
                section.push_str(&format!("--- {old_marker}\n+++ /dev/null\n"));
            } else {
                section.push_str(&format!("--- {old_marker}\n+++ {new_marker}\n"));
            }
            section.push_str(&item.diff);
            if !item.diff.ends_with('\n') {
                section.push('\n');
            }
            ensure!(
                out.len().saturating_add(section.len())
                    <= crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES,
                "GitLab assembled diff exceeds the {} byte acquisition limit",
                crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES
            );
            out.push_str(&section);
        }
        Ok(())
    }

    #[cfg(test)]
    fn assemble_unified(items: &[FileDiffItem]) -> Result<String> {
        let mut out = String::new();
        Self::append_unified(&mut out, items)?;
        Ok(out)
    }

    #[cfg(test)]
    fn assemble_compare(compare: CompareResponse) -> Result<String> {
        ensure!(
            !compare.compare_timeout,
            "GitLab compare timed out or exceeded provider limits"
        );
        Self::assemble_unified(&compare.diffs)
    }

    async fn source_file(&self, revision: &str, path: &str) -> Result<(String, usize)> {
        const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
        ensure!(
            super::valid_repository_path(path),
            "GitLab returned an unsafe repository path"
        );
        let mut url = reqwest::Url::parse(
            &self.url(&format!("/repository/files/{}/raw", encode_component(path))),
        )
        .context("building GitLab source URL")?;
        url.query_pairs_mut().append_pair("ref", revision);
        let response = self
            .request(reqwest::Method::GET, url.to_string())
            .send()
            .await
            .context("fetching GitLab source file")?;
        let mut response = Self::check_ok(response, "source file fetch").await?;
        let bytes = super::bounded_response_bytes_with_limit(
            &mut response,
            "GitLab source file",
            MAX_FILE_BYTES,
        )
        .await?;
        let byte_count = bytes.len();
        Ok((
            String::from_utf8(bytes).unwrap_or_else(|_| "\0".to_string()),
            byte_count,
        ))
    }

    async fn build_complete_diff(
        &self,
        items: Vec<FileDiffItem>,
        base_sha: &str,
        head_sha: &str,
    ) -> Result<String> {
        let mut output = String::new();
        let mut acquired = 0usize;
        for item in items {
            ensure!(
                super::valid_repository_path(&item.old_path)
                    && super::valid_repository_path(&item.new_path),
                "GitLab returned an unsafe repository path"
            );
            let (old, old_bytes) = if item.new_file {
                (String::new(), 0)
            } else {
                self.source_file(base_sha, &item.old_path).await?
            };
            acquired = checked_acquired_bytes(acquired, old_bytes)?;
            let (new, new_bytes) = if item.deleted_file {
                (String::new(), 0)
            } else {
                self.source_file(head_sha, &item.new_path).await?
            };
            acquired = checked_acquired_bytes(acquired, new_bytes)?;
            let section = super::azure::diff_section(
                &item.new_path,
                &old,
                &new,
                item.new_file,
                item.deleted_file,
            );
            ensure!(
                output.len().saturating_add(section.len())
                    <= crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES,
                "GitLab reconstructed diff exceeds the {} byte acquisition limit",
                crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES
            );
            output.push_str(&section);
        }
        Ok(output)
    }

    fn validate_diff_version(version: &DiffVersion, item_count: usize) -> Result<()> {
        ensure!(
            version.state == "collected",
            "GitLab diff version is not complete (state {})",
            version.state
        );
        let expected_items: usize = version
            .real_size
            .parse()
            .context("GitLab diff version real_size is not numeric")?;
        ensure!(
            item_count == expected_items,
            "GitLab returned {item_count} diff files but the collected version reports {expected_items}"
        );
        Ok(())
    }

    async fn latest_diff_version(&self) -> Result<DiffVersion> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!(
                    "/merge_requests/{}/versions?per_page=1&page=1",
                    self.mr_iid
                )),
            )
            .send()
            .await
            .context("fetching MR diff version")?;
        let versions: Vec<DiffVersion> = super::bounded_response_json(
            Self::check_ok(resp, "diff version fetch").await?,
            "GitLab diff version",
        )
        .await?;
        versions
            .into_iter()
            .next()
            .context("GitLab returned no merge-request diff version")
    }

    /// Post one finding as an anchored discussion, falling back to a plain
    /// note when GitLab refuses the position (e.g. line outside the visible
    /// diff).
    async fn post_finding(&self, mr: &MrResponse, f: &Finding) -> Result<()> {
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
        if resp.status().is_success() {
            return Ok(());
        }
        let note = json!({
            "body": format!(
                "`{}:{}`\n\n{}",
                super::safe_code_text(&f.path),
                f.line,
                super::finding_comment_body(f, true),
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
        Ok(())
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

fn encode_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn checked_acquired_bytes(current: usize, additional: usize) -> Result<usize> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| anyhow!("GitLab source acquisition size overflowed"))?;
    ensure!(
        total <= crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES,
        "GitLab source acquisition exceeds the {} byte limit",
        crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES
    );
    Ok(total)
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
        const PER_PAGE: usize = 100;
        const MAX_PAGES: usize = 100;
        const MAX_ITEMS: usize = 10_000;
        let version = self.latest_diff_version().await?;
        let mr = self.mr().await?;
        let expected_items: usize = version
            .real_size
            .parse()
            .context("GitLab diff version real_size is not numeric")?;
        ensure!(
            expected_items <= MAX_ITEMS,
            "GitLab diff version exceeds {MAX_ITEMS} files"
        );
        let mut items = Vec::with_capacity(expected_items);
        let mut retained_bytes = 0usize;
        let mut item_count = 0usize;
        let mut page = 1usize;
        loop {
            ensure!(
                page <= MAX_PAGES,
                "GitLab diff pagination exceeds {MAX_PAGES} pages"
            );
            let resp = self
                .request(
                    reqwest::Method::GET,
                    self.url(&format!(
                        "/merge_requests/{}/diffs?per_page={PER_PAGE}&page={page}",
                        self.mr_iid
                    )),
                )
                .send()
                .await
                .context("fetching MR diffs")?;
            let checked = Self::check_ok(resp, "diff fetch").await?;
            let next_page = checked
                .headers()
                .get("x-next-page")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let page_text = super::bounded_response_text(checked, "GitLab diff page").await?;
            retained_bytes = retained_bytes
                .checked_add(page_text.len())
                .ok_or_else(|| anyhow!("GitLab diff page size overflowed"))?;
            ensure!(
                retained_bytes <= crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES,
                "GitLab diff pages exceed the aggregate acquisition limit"
            );
            let batch: Vec<FileDiffItem> =
                serde_json::from_str(&page_text).context("decoding GitLab diff page")?;
            drop(page_text);
            ensure!(
                item_count.saturating_add(batch.len()) <= MAX_ITEMS,
                "GitLab diff pagination exceeds {MAX_ITEMS} files"
            );
            let batch_len = batch.len();
            item_count = item_count.saturating_add(batch_len);
            items.extend(batch);
            match next_page.as_deref() {
                Some("") => break,
                Some(next) => {
                    let parsed: usize =
                        next.parse().context("invalid GitLab x-next-page header")?;
                    ensure!(parsed > page, "GitLab pagination did not advance");
                    page = parsed;
                }
                None if batch_len < PER_PAGE => break,
                None => {
                    return Err(anyhow!(
                        "GitLab returned a full diff page without authoritative pagination headers"
                    ));
                }
            }
        }
        Self::validate_diff_version(&version, item_count)?;
        self.build_complete_diff(items, &mr.diff_refs.base_sha, &mr.diff_refs.head_sha)
            .await
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
        let cmp: CompareResponse = super::bounded_response_json(
            Self::check_ok(resp, "compare fetch").await?,
            "GitLab compare diff",
        )
        .await?;
        ensure!(
            !cmp.compare_timeout,
            "GitLab compare timed out or exceeded provider limits"
        );
        self.build_complete_diff(cmp.diffs, since_sha, head_sha)
            .await
    }

    async fn post_review(
        &self,
        summary: &str,
        findings: &[Finding],
        _head_sha: &str,
    ) -> Result<()> {
        if super::only_operational_findings(findings) {
            return Ok(());
        }
        let mr = self.mr().await?;
        // One failed comment must not drop the rest: post everything we can,
        // then report the failures together.
        let mut failures: Vec<String> = Vec::new();
        for f in findings {
            if f.body.starts_with("[carried from previous review]")
                || super::is_synthetic_path(&f.path)
            {
                // Carried findings already have comments; synthetic-path findings
                // (PR description, fail-closed markers) have no MR line to anchor
                // and surface in the summary body instead.
                continue;
            }
            if let Err(e) = self.post_finding(&mr, f).await {
                failures.push(format!("{}:{}: {e:#}", f.path, f.line));
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
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "{} finding comment(s) failed to post: {}",
                failures.len(),
                failures.join("; ")
            ))
        }
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
            &check_summary(envelope, true, super::SummaryContext::from_env()),
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
        let v: serde_json::Value = super::bounded_response_json(
            Self::check_ok(resp, "thread fetch").await?,
            "GitLab thread",
        )
        .await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn item(collapsed: bool, too_large: bool) -> FileDiffItem {
        FileDiffItem {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -1 +1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            collapsed,
            too_large,
        }
    }

    #[test]
    fn collapsed_and_too_large_diffs_fail_closed() {
        assert!(GitLab::assemble_unified(&[item(true, false)]).is_err());
        assert!(GitLab::assemble_unified(&[item(false, true)]).is_err());
        assert!(GitLab::assemble_unified(&[item(false, false)]).is_ok());
    }

    #[test]
    fn compare_timeout_and_incomplete_versions_fail_closed() {
        assert!(
            GitLab::assemble_compare(CompareResponse {
                compare_timeout: true,
                diffs: vec![item(false, false)],
            })
            .is_err()
        );
        assert!(
            GitLab::validate_diff_version(
                &DiffVersion {
                    state: "collecting".into(),
                    real_size: "1".into(),
                },
                1,
            )
            .is_err()
        );
        assert!(
            GitLab::validate_diff_version(
                &DiffVersion {
                    state: "collected".into(),
                    real_size: "2".into(),
                },
                1,
            )
            .is_err()
        );
    }
}
