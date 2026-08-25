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

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use serde::Deserialize;
use serde_json::json;
use std::io::Write;

use super::{
    CheckRunIds, CheckState, Forge, PrMeta, ReviewPublicationReceipt, check_summary, check_title,
    untracked_review_publication_receipt,
};
use crate::diff::{DiffSnapshot, DiffSpool, WorkspaceBudget};
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

#[derive(Deserialize, Clone)]
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
    status: String,
    // Absent on PRs with merge conflicts; surfaced as an actionable error.
    last_merge_source_commit: Option<MergeCommit>,
    last_merge_target_commit: Option<MergeCommit>,
}

fn pr_matches_snapshot(
    pr: &PrResponse,
    source: &MergeCommit,
    target: &MergeCommit,
    expected: &PrMeta,
) -> bool {
    pr.status == "active"
        && pr.title == expected.title
        && pr.description == expected.body
        && source.commit_id == expected.head_sha
        && Some(target.commit_id.as_str()) == expected.target_sha.as_deref()
}

#[derive(Deserialize)]
struct ChangeItem {
    path: String,
    #[serde(rename = "isFolder")]
    is_folder: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Change {
    item: ChangeItem,
    change_type: String,
    /// Original path for renames; content lookups on the base side use it.
    #[serde(default)]
    source_server_item: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiffResponse {
    changes: Vec<Change>,
    /// False when the change list is paginated and this page is partial.
    all_changes_included: bool,
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
        let request_id = super::response_request_id(&resp).unwrap_or_else(|| "none".into());
        Err(super::http_failure(
            status,
            format!("Azure DevOps {what} failed: {status} (request id {request_id})"),
        ))
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
        super::bounded_response_json(Self::check_ok(resp, "PR fetch").await?, "Azure PR").await
    }

    async fn merge_base(&self, source: &str, target: &str) -> Result<String> {
        let query = format!("otherCommitId={source}");
        let response = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/commits/{target}/mergebases"), &query),
            )
            .send()
            .await
            .context("fetching Azure pull request merge base")?;
        let merge_bases: Vec<MergeCommit> = super::bounded_response_json(
            Self::check_ok(response, "merge-base fetch").await?,
            "Azure merge-base response",
        )
        .await?;
        ensure!(
            merge_bases.len() == 1 && !merge_bases[0].commit_id.is_empty(),
            "Azure pull request must have exactly one merge base"
        );
        Ok(merge_bases[0].commit_id.clone())
    }

    /// File content at a commit. Added and deleted sides are skipped by the
    /// caller, so a missing expected item is an incomplete acquisition.
    async fn item_at(
        &self,
        path: &str,
        commit: &str,
        workspace: WorkspaceBudget,
    ) -> Result<DiffSnapshot> {
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
        super::response_snapshot_in(
            Self::check_ok(resp, "item fetch").await?,
            "Azure item content",
            workspace,
            None,
        )
        .await
    }

    /// The full change list across pages. `/diffs/commits` pages `changes`
    /// ($top defaults to 100); consuming one page would silently review only
    /// part of a large PR and pass the rest unseen, so this paginates to
    /// exhaustion and fails closed on a runaway list rather than truncating.
    async fn change_list(&self, base_sha: &str, head_sha: &str) -> Result<Vec<Change>> {
        const PAGE: usize = 100;
        let mut changes: Vec<Change> = Vec::new();
        let mut retained_bytes = 0usize;
        loop {
            let q = format!(
                "baseVersion={base_sha}&baseVersionType=commit&\
                 targetVersion={head_sha}&targetVersionType=commit&\
                 $top={PAGE}&$skip={}",
                changes.len()
            );
            let resp = self
                .request(reqwest::Method::GET, self.url("/diffs/commits", &q))
                .send()
                .await
                .context("fetching change list")?;
            let page_text = super::bounded_response_text(
                Self::check_ok(resp, "change list fetch").await?,
                "Azure change-list page",
            )
            .await?;
            retained_bytes = super::checked_metadata_total(
                retained_bytes,
                page_text.len(),
                "Azure change-list pages",
            )?;
            let page: DiffResponse =
                serde_json::from_str(&page_text).context("decoding Azure change-list page")?;
            let n = page.changes.len();
            validate_change_page(changes.len(), n, PAGE)?;
            let all_changes_included = page.all_changes_included;
            changes.extend(page.changes);
            debug_assert!(changes.len() <= super::MAX_FORGE_CHANGED_FILES);
            if azure_page_complete(n, all_changes_included)? {
                return Ok(changes);
            }
        }
    }

    async fn build_diff(
        &self,
        base_sha: &str,
        head_sha: &str,
        workspace: WorkspaceBudget,
    ) -> Result<DiffSnapshot> {
        let changes = self.change_list(base_sha, head_sha).await?;
        let mut jobs = Vec::with_capacity(changes.len());
        for change in changes {
            let item = &change.item;
            ensure!(!item.path.is_empty(), "Azure change item has an empty path");
            if item.is_folder {
                continue;
            }
            let path = item.path.trim_start_matches('/');
            ensure!(
                super::valid_repository_path(path),
                "Azure change item has an unsafe repository path"
            );
            let ct = change.change_type.to_ascii_lowercase();
            let kinds = ct
                .split(',')
                .map(str::trim)
                .filter(|kind| !kind.is_empty())
                .collect::<Vec<_>>();
            ensure!(
                !kinds.is_empty()
                    && kinds
                        .iter()
                        .all(|kind| matches!(*kind, "add" | "edit" | "delete" | "rename")),
                "Azure change item has an unsupported change type"
            );
            let is_add = kinds.contains(&"add");
            let is_delete = kinds.contains(&"delete");
            // Renames keep their history under the original path on the base side.
            let base_path = change
                .source_server_item
                .as_deref()
                .map(|p| p.trim_start_matches('/'))
                .unwrap_or(path);
            ensure!(
                super::valid_repository_path(base_path),
                "Azure change item has an unsafe source repository path"
            );
            jobs.push((base_path.to_string(), path.to_string(), is_add, is_delete));
        }
        let mut sections = stream::iter(jobs.into_iter().enumerate().map(
            |(index, (base_path, path, is_add, is_delete))| {
                let workspace = workspace.clone();
                async move {
                    let old = if is_add {
                        DiffSnapshot::from_bytes_in(b"", workspace.clone())?
                    } else {
                        self.item_at(&base_path, base_sha, workspace.clone())
                            .await?
                    };
                    let new = if is_delete {
                        DiffSnapshot::from_bytes_in(b"", workspace.clone())?
                    } else {
                        self.item_at(&path, head_sha, workspace.clone()).await?
                    };
                    if old.as_bytes() == new.as_bytes() {
                        return Ok::<_, anyhow::Error>((
                            index,
                            DiffSnapshot::from_bytes_in(b"", workspace.clone())?,
                        ));
                    }
                    let mut section = DiffSpool::new_in(workspace.clone())?;
                    write_diff_section(
                        &mut section,
                        &base_path,
                        &path,
                        old.source_str(),
                        new.source_str(),
                        is_add,
                        is_delete,
                    )?;
                    Ok((index, section.finish()?))
                }
            },
        ))
        .buffered(4);
        let mut out = DiffSpool::new_in(workspace.clone())?;
        while let Some((_, section)) = sections.try_next().await? {
            out.write_all(section.as_bytes())
                .context("spooling Azure reconstructed diff")?;
        }
        out.finish()
    }

    /// Post one finding as an anchored thread, falling back to a non-anchored
    /// thread when Azure rejects the inline position.
    async fn post_finding(&self, f: &Finding) -> Result<()> {
        // Azure threads anchor to a file + line range with right-side context.
        let body = json!({
            "comments": [{
                "parentCommentId": 0,
                "commentType": 1,
                "content": super::finding_comment_body(f, false),
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
        if resp.status().is_success() {
            return Ok(());
        }
        let note = json!({
            "comments": [{
                "parentCommentId": 0,
                "commentType": 1,
                "content": format!(
                    "`{}:{}`\n\n{}",
                    super::safe_code_text(&f.path),
                    f.line,
                    super::finding_comment_body(f, false),
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
        Ok(())
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
        ensure!(pr.status == "active", "Azure pull request is not active");
        let (source, target) =
            merge_commits(pr.last_merge_source_commit, pr.last_merge_target_commit)?;
        let merge_base = self
            .merge_base(&source.commit_id, &target.commit_id)
            .await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.description,
            head_sha: source.commit_id,
            base_sha: merge_base,
            target_sha: Some(target.commit_id),
            changed_files: None,
        })
    }

    async fn fetch_diff(&self, snapshot: &PrMeta) -> Result<DiffSnapshot> {
        let workspace = WorkspaceBudget::new();
        let diff = self
            .build_diff(&snapshot.base_sha, &snapshot.head_sha, workspace)
            .await?;
        let current = self.fetch_pr_meta().await?;
        ensure!(
            current.head_sha == snapshot.head_sha && current.base_sha == snapshot.base_sha,
            "Azure pull request changed while its diff was being acquired"
        );
        Ok(diff)
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<DiffSnapshot> {
        self.build_diff(since_sha, head_sha, WorkspaceBudget::new())
            .await
    }

    async fn post_review(
        &self,
        envelope: &Envelope,
        snapshot: &PrMeta,
        _publication_diff: Option<&crate::diff::Diff>,
    ) -> Result<ReviewPublicationReceipt> {
        let findings = &envelope.findings;
        let receipt = untracked_review_publication_receipt("azure", envelope, &snapshot.head_sha);
        if super::only_operational_findings(findings) {
            return Ok(receipt);
        }
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!("postil: azure review delivery skipped because the pull request changed");
            return Ok(receipt);
        }
        let summary = self.review_summary(envelope);
        // One failed comment must not drop the rest: post everything we can,
        // then report the failures together.
        let mut failures: Vec<String> = Vec::new();
        for f in findings {
            if f.body.starts_with("[carried from previous review]")
                || super::is_synthetic_path(&f.path)
            {
                // Carried findings already have comments; synthetic-path findings
                // have no file line to anchor and surface in the summary instead.
                continue;
            }
            if let Err(e) = self.post_finding(f).await {
                failures.push(format!("{}:{}: {e:#}", f.path, f.line));
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
        if failures.is_empty() {
            Ok(receipt)
        } else {
            Err(anyhow!(
                "{} finding comment(s) failed to post: {}",
                failures.len(),
                failures.join("; ")
            ))
        }
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
        _check_ids: CheckRunIds<'_>,
        advisory: CheckState,
        gate: Option<CheckState>,
        envelope: &Envelope,
        snapshot: &PrMeta,
        _annotate_findings: bool,
    ) -> Result<()> {
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!("postil: azure status delivery skipped because the pull request changed");
            return Ok(());
        }
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
            &check_summary(envelope, false, super::SummaryContext::from_env()),
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
        if let Some(gate) = gate {
            self.set_status(&head, "postil/gate", map(gate), &gate_desc)
                .await?;
        }
        Ok(())
    }

    async fn snapshot_is_current(&self, expected: &PrMeta) -> Result<bool> {
        let current = self.pr().await?;
        let (source, target) = match merge_commits(
            current.last_merge_source_commit.clone(),
            current.last_merge_target_commit.clone(),
        ) {
            Ok(commits) => commits,
            Err(_) => return Ok(false),
        };
        if !pr_matches_snapshot(&current, &source, &target, expected) {
            return Ok(false);
        }
        Ok(self
            .merge_base(&source.commit_id, &target.commit_id)
            .await?
            == expected.base_sha)
    }
}

/// Both merge commits, or an actionable error: Azure omits them on PRs with
/// merge conflicts, where there is no merge preview to diff.
fn merge_commits(
    source: Option<MergeCommit>,
    target: Option<MergeCommit>,
) -> Result<(MergeCommit, MergeCommit)> {
    match (source, target) {
        (Some(s), Some(t)) => Ok((s, t)),
        _ => Err(anyhow!(
            "PR has no merge commits (does it have merge conflicts?); resolve conflicts and re-run"
        )),
    }
}

fn azure_page_complete(count: usize, marker: bool) -> Result<bool> {
    match marker {
        true => Ok(true),
        false if count == 0 => Err(anyhow!(
            "Azure change-list pagination reported more changes but made no progress"
        )),
        false => Ok(false),
    }
}

fn validate_change_page(
    current: usize,
    page_count: usize,
    requested_page_size: usize,
) -> Result<()> {
    ensure!(
        page_count <= requested_page_size,
        "Azure change-list page exceeded the requested {requested_page_size} entries"
    );
    let total = current
        .checked_add(page_count)
        .ok_or_else(|| anyhow!("Azure change-list entry count overflowed"))?;
    ensure!(
        total <= super::MAX_FORGE_CHANGED_FILES,
        "PR change list exceeds {} entries; refusing to review a truncated change set",
        super::MAX_FORGE_CHANGED_FILES
    );
    Ok(())
}

/// One file's diff section, or a "differ" marker if the content is binary.
/// Split out of `build_diff` so classification is unit-testable without
/// network access.
#[cfg(test)]
pub(super) fn diff_section(
    old_path: &str,
    new_path: &str,
    old: &str,
    new: &str,
    is_add: bool,
    is_delete: bool,
) -> String {
    let mut out = Vec::new();
    write_diff_section(&mut out, old_path, new_path, old, new, is_add, is_delete)
        .expect("writing a diff to memory cannot fail");
    String::from_utf8(out).expect("text diff output is UTF-8")
}

pub(super) fn write_diff_section(
    mut out: impl Write,
    old_path: &str,
    new_path: &str,
    old: &str,
    new: &str,
    is_add: bool,
    is_delete: bool,
) -> Result<()> {
    let old_marker = crate::diff::display_path(&format!("a/{old_path}"));
    let new_marker = crate::diff::display_path(&format!("b/{new_path}"));
    // Binary content cannot be line-diffed; mark it like git does so the path
    // is still visible in the review context.
    if old.contains('\0') || new.contains('\0') {
        writeln!(out, "diff --git {old_marker} {new_marker}")?;
        writeln!(out, "Binary files {old_marker} and {new_marker} differ")?;
        return Ok(());
    }
    write_unified_file_diff(&mut out, old_path, new_path, old, new, is_add, is_delete)
}

/// Build one file's unified-diff section in the format `diff.rs` expects:
/// a `diff --git` header (so the parser seeds the path even for additions),
/// the `---`/`+++` lines, and `similar`-generated hunks.
#[cfg(test)]
fn unified_file_diff(
    old_path: &str,
    new_path: &str,
    old: &str,
    new: &str,
    is_add: bool,
    is_delete: bool,
) -> String {
    let mut out = Vec::new();
    write_unified_file_diff(&mut out, old_path, new_path, old, new, is_add, is_delete)
        .expect("writing a diff to memory cannot fail");
    String::from_utf8(out).expect("text diff output is UTF-8")
}

fn write_unified_file_diff(
    mut out: impl Write,
    old_path: &str,
    new_path: &str,
    old: &str,
    new: &str,
    is_add: bool,
    is_delete: bool,
) -> Result<()> {
    use similar::TextDiff;
    const MAX_IN_MEMORY_MODIFIED_FILE_BYTES: usize = 32 * 1024 * 1024;
    let old_marker = crate::diff::display_path(&format!("a/{old_path}"));
    let new_marker = crate::diff::display_path(&format!("b/{new_path}"));
    writeln!(out, "diff --git {old_marker} {new_marker}")?;
    if is_add {
        writeln!(out, "--- /dev/null")?;
        writeln!(out, "+++ {new_marker}")?;
    } else if is_delete {
        writeln!(out, "--- {old_marker}")?;
        writeln!(out, "+++ /dev/null")?;
    } else {
        writeln!(out, "--- {old_marker}")?;
        writeln!(out, "+++ {new_marker}")?;
    }
    if is_add {
        write_full_file_hunk(&mut out, new, true)?;
        return Ok(());
    }
    if is_delete {
        write_full_file_hunk(&mut out, old, false)?;
        return Ok(());
    }
    let reconstruction_bytes = old
        .len()
        .checked_add(new.len())
        .context("modified-file reconstruction size overflowed")?;
    if reconstruction_bytes > MAX_IN_MEMORY_MODIFIED_FILE_BYTES {
        write_replacement_hunk(&mut out, old, new)?;
        return Ok(());
    }
    let diff = TextDiff::from_lines(old, new);
    diff.unified_diff().context_radius(3).to_writer(out)?;
    Ok(())
}

fn write_replacement_hunk(mut out: impl Write, old: &str, new: &str) -> Result<()> {
    let old_lines = u32::try_from(old.lines().count())
        .context("old source file has too many lines to represent")?;
    let new_lines = u32::try_from(new.lines().count())
        .context("new source file has too many lines to represent")?;
    writeln!(
        out,
        "@@ -1,{old_lines} +1,{new_lines} @@ bounded full-file reconstruction"
    )?;
    for line in old.lines() {
        writeln!(out, "-{line}")?;
    }
    if !old.is_empty() && !old.ends_with('\n') {
        writeln!(out, "\\ No newline at end of file")?;
    }
    for line in new.lines() {
        writeln!(out, "+{line}")?;
    }
    if !new.is_empty() && !new.ends_with('\n') {
        writeln!(out, "\\ No newline at end of file")?;
    }
    Ok(())
}

fn write_full_file_hunk(mut out: impl Write, content: &str, added: bool) -> Result<()> {
    if content.is_empty() {
        return Ok(());
    }
    let lines = content.lines().count();
    let lines = u32::try_from(lines).context("source file has too many lines to represent")?;
    if added {
        writeln!(out, "@@ -0,0 +1,{lines} @@")?;
    } else {
        writeln!(out, "@@ -1,{lines} +0,0 @@")?;
    }
    let marker = if added { '+' } else { '-' };
    for line in content.lines() {
        writeln!(out, "{marker}{line}")?;
    }
    if !content.ends_with('\n') {
        writeln!(out, "\\ No newline at end of file")?;
    }
    Ok(())
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

    fn snapshot() -> PrMeta {
        PrMeta {
            title: "title".into(),
            body: "body".into(),
            head_sha: "head".into(),
            base_sha: "merge-base".into(),
            target_sha: Some("target".into()),
            changed_files: None,
        }
    }

    fn pull_request(status: &str) -> PrResponse {
        PrResponse {
            title: "title".into(),
            description: "body".into(),
            status: status.into(),
            last_merge_source_commit: None,
            last_merge_target_commit: None,
        }
    }

    #[test]
    fn delivery_snapshot_rejects_closed_pull_request() {
        assert!(!pr_matches_snapshot(
            &pull_request("completed"),
            &MergeCommit {
                commit_id: "head".into(),
            },
            &MergeCommit {
                commit_id: "target".into(),
            },
            &snapshot()
        ));
    }

    #[test]
    fn delivery_snapshot_rejects_changed_target() {
        assert!(!pr_matches_snapshot(
            &pull_request("active"),
            &MergeCommit {
                commit_id: "head".into(),
            },
            &MergeCommit {
                commit_id: "advanced-target".into(),
            },
            &snapshot()
        ));
    }

    #[test]
    fn delivery_snapshot_rejects_changed_head_and_metadata() {
        let mut current = pull_request("active");
        assert!(!pr_matches_snapshot(
            &current,
            &MergeCommit {
                commit_id: "advanced-head".into(),
            },
            &MergeCommit {
                commit_id: "target".into(),
            },
            &snapshot()
        ));
        current.title = "edited title".into();
        assert!(!pr_matches_snapshot(
            &current,
            &MergeCommit {
                commit_id: "head".into(),
            },
            &MergeCommit {
                commit_id: "target".into(),
            },
            &snapshot()
        ));
    }

    #[test]
    fn reconstructed_diff_parses_and_grounds() {
        let old = "fn a() {\n    let x = 1;\n}\n";
        let new = "fn a() {\n    let x = 2;\n}\n";
        let section = unified_file_diff("src/a.rs", "src/a.rs", old, new, false, false);
        assert!(section.contains("diff --git a/src/a.rs b/src/a.rs"));
        let parsed = diff::parse(&section);
        let index = diff::DiffIndex::build(&parsed);
        // The changed line (2) must be grounded so findings on it are kept.
        assert!(index.contains("src/a.rs", 2));
    }

    #[test]
    fn added_file_uses_dev_null_base() {
        let section = unified_file_diff("new.rs", "new.rs", "", "a\nb\n", true, false);
        assert!(section.contains("--- /dev/null"));
        assert!(section.contains("+++ b/new.rs"));
        let parsed = diff::parse(&section);
        assert_eq!(parsed.files.len(), 1);
    }

    #[test]
    fn many_line_added_file_above_32_mib_reconstructs_with_bounded_index() {
        use std::fmt::Write as _;

        let line_count = 34_000u32;
        let mut source = String::new();
        for line in 1..=line_count {
            writeln!(source, "let value_{line} = {};", "x".repeat(1_000)).unwrap();
        }
        assert!(source.len() > 32 * 1024 * 1024);
        let mut spool = DiffSpool::new().unwrap();
        write_diff_section(
            &mut spool,
            "src/huge.rs",
            "src/huge.rs",
            "",
            &source,
            true,
            false,
        )
        .unwrap();
        let snapshot = spool.finish().unwrap();
        let prepared = crate::diff::prepare_review(&snapshot).unwrap();
        assert!(prepared.index.is_complete());
        assert!(prepared.index.contains("src/huge.rs", line_count));
    }

    #[test]
    fn ordinary_file_under_cap_is_diffed_normally() {
        let old = "fn a() {\n    let x = 1;\n}\n";
        let new = "fn a() {\n    let x = 2;\n}\n";
        let section = diff_section("src/a.rs", "src/a.rs", old, new, false, false);
        assert!(!section.contains("differ"));
        let parsed = diff::parse(&section);
        assert!(!parsed.files[0].binary);
        assert!(!parsed.files[0].hunks.is_empty());
    }

    #[test]
    fn renamed_file_preserves_old_and_new_paths() {
        let section = diff_section(
            "src/old.rs",
            "src/new.rs",
            "let value = 1;\n",
            "let value = 2;\n",
            false,
            false,
        );
        assert!(section.contains("diff --git a/src/old.rs b/src/new.rs"));
        let parsed = diff::parse(&section);
        assert_eq!(parsed.files[0].old_path, "src/old.rs");
        assert_eq!(parsed.files[0].path, "src/new.rs");
    }

    #[test]
    fn pagination_marker_is_authoritative_and_no_progress_fails() {
        assert!(!azure_page_complete(12, false).unwrap());
        assert!(azure_page_complete(100, true).unwrap());
        assert!(azure_page_complete(0, false).is_err());
    }

    #[test]
    fn terminal_marker_cannot_bypass_aggregate_change_limit() {
        assert!(validate_change_page(crate::forge::MAX_FORGE_CHANGED_FILES, 1, 100).is_err());
        assert!(validate_change_page(crate::forge::MAX_FORGE_CHANGED_FILES - 1, 1, 100).is_ok());
        assert!(validate_change_page(0, 101, 100).is_err());
    }
}
