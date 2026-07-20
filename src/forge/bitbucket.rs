//! Bitbucket Cloud forge implementation. `BITBUCKET_API_URL` selects a
//! Cloud-compatible API gateway; Data Center uses a different REST contract.
//!
//! Auth: `BITBUCKET_TOKEN`. If `BITBUCKET_USER` is set the token is treated as
//! an app password and sent via HTTP Basic; otherwise it is a workspace/repo
//! access token sent as a Bearer credential.
//!
//! Checks map to commit build statuses. Bitbucket has no `neutral`, so an
//! operational error marks the gate `FAILED`: fail closed, never grey.
//!
//! Incremental diffs are disabled unless `POSTIL_ENABLE_BITBUCKET_INCREMENTAL=1`
//! is present. Bitbucket's compare endpoint uses the opposite two-dot order from
//! `git diff`; keep the path available for verified deployments without making
//! unverified hosted runs trust it by default.

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use std::io::Write;

use super::{
    CheckState, Forge, PrMeta, ReviewPublicationReceipt, ThreadKind, check_summary, check_title,
    untracked_review_publication_receipt,
};
use crate::diff::{DiffSnapshot, DiffSpool, WorkspaceBudget};
use crate::envelope::{Envelope, Finding};

const ENABLE_INCREMENTAL_ENV: &str = "POSTIL_ENABLE_BITBUCKET_INCREMENTAL";

pub struct Bitbucket {
    http: reqwest::Client,
    api_base: String,
    auth: Auth,
    /// "workspace/repo".
    workspace: String,
    repo: String,
    pr: u64,
}

enum Auth {
    Bearer(String),
    Basic { user: String, pass: String },
}

#[derive(Deserialize)]
struct Commit {
    hash: String,
}

#[derive(Deserialize)]
struct Endpoint {
    commit: Commit,
}

#[derive(Deserialize)]
struct Rendered {
    #[serde(default)]
    raw: String,
}

#[derive(Deserialize)]
struct PrResponse {
    #[serde(default)]
    title: String,
    #[serde(default)]
    summary: Option<Rendered>,
    state: String,
    source: Endpoint,
    destination: Endpoint,
}

fn pr_matches_snapshot(pr: &PrResponse, expected: &PrMeta) -> bool {
    let body = pr
        .summary
        .as_ref()
        .map(|summary| summary.raw.as_str())
        .unwrap_or_default();
    pr.state == "OPEN"
        && pr.title == expected.title
        && body == expected.body
        && pr.source.commit.hash == expected.head_sha
        && Some(pr.destination.commit.hash.as_str()) == expected.target_sha.as_deref()
}

#[derive(Deserialize)]
struct DiffStatPage {
    values: Vec<DiffStat>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct DiffStat {
    status: String,
    #[serde(default)]
    old: Option<DiffStatFile>,
    #[serde(default)]
    new: Option<DiffStatFile>,
}

#[derive(Deserialize)]
struct DiffStatFile {
    path: String,
}

impl Bitbucket {
    pub fn new(repo_slug: &str, pr: u64) -> Result<Self> {
        let (workspace, repo) = repo_slug
            .split_once('/')
            .ok_or_else(|| anyhow!("--repo must be workspace/repo, got {repo_slug:?}"))?;
        let token = std::env::var("BITBUCKET_TOKEN")
            .map_err(|_| anyhow!("BITBUCKET_TOKEN is required for --forge bitbucket"))?;
        let auth = match std::env::var("BITBUCKET_USER") {
            Ok(user) if !user.is_empty() => Auth::Basic { user, pass: token },
            _ => Auth::Bearer(token),
        };
        let api_base = std::env::var("BITBUCKET_API_URL")
            .unwrap_or_else(|_| "https://api.bitbucket.org/2.0".to_string());
        Ok(Bitbucket {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_base: api_base.trim_end_matches('/').to_string(),
            auth,
            workspace: workspace.to_string(),
            repo: repo.to_string(),
            pr,
        })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/repositories/{}/{}{path}",
            self.api_base, self.workspace, self.repo
        )
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        let rb = self
            .http
            .request(method, url)
            .header("User-Agent", "postil");
        match &self.auth {
            Auth::Bearer(t) => rb.bearer_auth(t),
            Auth::Basic { user, pass } => rb.basic_auth(user, Some(pass)),
        }
    }

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let request_id = super::response_request_id(&resp).unwrap_or_else(|| "none".into());
        Err(super::http_failure(
            status,
            format!("Bitbucket {what} failed: {status} (request id {request_id})"),
        ))
    }

    /// Post one finding inline, falling back to a top-level comment when the
    /// API refuses the inline position.
    async fn post_finding(&self, f: &Finding) -> Result<()> {
        let body = json!({
            "content": { "raw": super::finding_comment_body(f, false) },
            "inline": { "path": f.path, "to": f.line },
        });
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pullrequests/{}/comments", self.pr)),
            )
            .json(&body)
            .send()
            .await
            .context("posting inline comment")?;
        if resp.status().is_success() {
            return Ok(());
        }
        let note = json!({ "content": { "raw": format!(
            "`{}:{}`\n\n{}",
            super::safe_code_text(&f.path),
            f.line,
            super::finding_comment_body(f, false),
        )}});
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pullrequests/{}/comments", self.pr)),
            )
            .json(&note)
            .send()
            .await
            .context("posting fallback comment")?;
        Self::check_ok(resp, "comment post").await?;
        Ok(())
    }

    async fn pr_meta(&self) -> Result<PrResponse> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pullrequests/{}", self.pr)),
            )
            .send()
            .await
            .context("fetching PR")?;
        super::bounded_response_json(Self::check_ok(resp, "PR fetch").await?, "Bitbucket PR").await
    }

    async fn merge_base(&self, destination: &str, source: &str) -> Result<String> {
        let response = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/merge-base/{destination}..{source}")),
            )
            .send()
            .await
            .context("fetching Bitbucket pull request merge base")?;
        let merge_base: Commit = super::bounded_response_json(
            Self::check_ok(response, "merge-base fetch").await?,
            "Bitbucket merge-base response",
        )
        .await?;
        validate_commit(&merge_base.hash)?;
        Ok(merge_base.hash)
    }

    async fn set_status(&self, sha: &str, key: &str, state: &str, description: &str) -> Result<()> {
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/commit/{sha}/statuses/build")),
            )
            .json(&json!({
                "key": key,
                "state": state,
                "name": key,
                "url": "https://postil.dev",
                "description": description.chars().take(250).collect::<String>(),
            }))
            .send()
            .await
            .with_context(|| format!("setting status {key}"))?;
        Self::check_ok(resp, "status set").await?;
        Ok(())
    }

    async fn diffstat_pages(&self, initial_url: String) -> Result<Vec<DiffStat>> {
        const MAX_FILES: usize = super::MAX_FORGE_CHANGED_FILES;
        const MAX_PAGES: usize = 200;
        let expected_origin =
            reqwest::Url::parse(&self.api_base).context("invalid Bitbucket API URL")?;
        let mut next = Some(initial_url);
        let mut entries = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut retained_bytes = 0usize;
        let mut pages = 0usize;
        while let Some(url) = next.take() {
            pages = pages
                .checked_add(1)
                .ok_or_else(|| anyhow!("Bitbucket diffstat page count overflowed"))?;
            ensure!(
                pages <= MAX_PAGES,
                "Bitbucket diffstat exceeds {MAX_PAGES} pages"
            );
            ensure!(
                visited.insert(url.clone()),
                "Bitbucket diffstat pagination repeated a page URL"
            );
            let parsed =
                reqwest::Url::parse(&url).context("invalid Bitbucket diffstat next URL")?;
            ensure!(
                parsed.scheme() == expected_origin.scheme()
                    && parsed.host_str() == expected_origin.host_str()
                    && parsed.port_or_known_default() == expected_origin.port_or_known_default(),
                "Bitbucket diffstat pagination attempted to leave the configured API origin"
            );
            let response = self
                .request(reqwest::Method::GET, url)
                .send()
                .await
                .context("fetching diffstat page")?;
            let page_text = super::bounded_response_text(
                Self::check_ok(response, "diffstat fetch").await?,
                "Bitbucket diffstat page",
            )
            .await?;
            retained_bytes = super::checked_metadata_total(
                retained_bytes,
                page_text.len(),
                "Bitbucket diffstat pages",
            )?;
            let page: DiffStatPage =
                serde_json::from_str(&page_text).context("decoding Bitbucket diffstat page")?;
            ensure!(
                !page.values.is_empty() || page.next.is_none(),
                "Bitbucket diffstat pagination reported a next page without progress"
            );
            for entry in &page.values {
                validate_diffstat(entry)?;
            }
            entries.extend(page.values);
            ensure!(
                entries.len() <= MAX_FILES,
                "Bitbucket diffstat exceeds the {MAX_FILES} file limit"
            );
            next = page.next;
        }
        Ok(entries)
    }

    async fn source_file(
        &self,
        commit: &str,
        path: &str,
        workspace: WorkspaceBudget,
    ) -> Result<(DiffSnapshot, usize)> {
        validate_commit(commit)?;
        ensure!(
            !path.starts_with('/')
                && path
                    .split('/')
                    .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
            "Bitbucket diffstat returned an unsafe source path"
        );
        let url = self.url(&format!("/src/{commit}/{}", encode_path(path)));
        let response = self
            .request(reqwest::Method::GET, url)
            .send()
            .await
            .with_context(|| format!("fetching Bitbucket source file {}", safe_path(path)))?;
        let snapshot = super::response_snapshot_in(
            Self::check_ok(response, "source fetch").await?,
            "Bitbucket source file",
            workspace,
            None,
        )
        .await?;
        let byte_count = snapshot.as_bytes().len();
        Ok((snapshot, byte_count))
    }

    async fn build_complete_diff(
        &self,
        base_sha: &str,
        head_sha: &str,
        diffstat_url: String,
        workspace: WorkspaceBudget,
    ) -> Result<DiffSnapshot> {
        let entries = self.diffstat_pages(diffstat_url).await?;
        let mut sections = stream::iter(entries.into_iter().enumerate().map(|(index, entry)| {
            let workspace = workspace.clone();
            async move {
                let old_path = entry.old.as_ref().map(|file| file.path.as_str());
                let new_path = entry.new.as_ref().map(|file| file.path.as_str());
                let path = new_path
                    .or(old_path)
                    .ok_or_else(|| anyhow!("Bitbucket diffstat entry has no path"))?;
                let status = entry.status.to_ascii_lowercase();
                let is_add = status == "added" || old_path.is_none();
                let is_delete = status == "removed" || new_path.is_none();
                let (old, old_bytes) = if is_add {
                    (DiffSnapshot::from_bytes_in(b"", workspace.clone())?, 0)
                } else {
                    self.source_file(base_sha, old_path.unwrap_or(path), workspace.clone())
                        .await?
                };
                let (new, new_bytes) = if is_delete {
                    (DiffSnapshot::from_bytes_in(b"", workspace.clone())?, 0)
                } else {
                    self.source_file(head_sha, new_path.unwrap_or(path), workspace.clone())
                        .await?
                };
                let mut section = DiffSpool::new_in(workspace.clone())?;
                super::azure::write_diff_section(
                    &mut section,
                    old_path.unwrap_or(path),
                    new_path.unwrap_or(path),
                    old.source_str(),
                    new.source_str(),
                    is_add,
                    is_delete,
                )?;
                Ok::<_, anyhow::Error>((index, old_bytes, new_bytes, section.finish()?))
            }
        }))
        .buffered(4);
        let mut output = DiffSpool::new_in(workspace.clone())?;
        while let Some((_, old_bytes, new_bytes, section)) = sections.try_next().await? {
            old_bytes
                .checked_add(new_bytes)
                .ok_or_else(|| anyhow!("Bitbucket source acquisition size overflowed"))?;
            output
                .write_all(section.as_bytes())
                .context("spooling Bitbucket reconstructed diff")?;
        }
        output.finish()
    }
}

fn validate_diffstat(entry: &DiffStat) -> Result<()> {
    ensure!(
        matches!(
            entry.status.to_ascii_lowercase().as_str(),
            "added" | "removed" | "modified" | "renamed"
        ),
        "Bitbucket diffstat returned an unsupported status"
    );
    ensure!(
        entry.old.is_some() || entry.new.is_some(),
        "Bitbucket diffstat entry has no file"
    );
    for file in entry.old.iter().chain(entry.new.iter()) {
        ensure!(
            super::valid_repository_path(&file.path),
            "Bitbucket diffstat returned an unsafe repository path"
        );
    }
    Ok(())
}

fn encode_path(path: &str) -> String {
    path.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Bitbucket commit id is not a hexadecimal object id"
    );
    Ok(())
}

fn safe_path(path: &str) -> String {
    let digest = sha2::Sha256::digest(path.as_bytes());
    format!(
        "sha256:{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

impl Forge for Bitbucket {
    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let pr = self.pr_meta().await?;
        ensure!(pr.state == "OPEN", "Bitbucket pull request is not open");
        validate_commit(&pr.source.commit.hash)?;
        validate_commit(&pr.destination.commit.hash)?;
        let merge_base = self
            .merge_base(&pr.destination.commit.hash, &pr.source.commit.hash)
            .await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.summary.map(|s| s.raw).unwrap_or_default(),
            head_sha: pr.source.commit.hash,
            base_sha: merge_base,
            target_sha: Some(pr.destination.commit.hash),
            changed_files: None,
        })
    }

    async fn fetch_diff(&self, snapshot: &PrMeta) -> Result<DiffSnapshot> {
        let workspace = WorkspaceBudget::new();
        let diff = self
            .build_complete_diff(
                &snapshot.base_sha,
                &snapshot.head_sha,
                self.url(&format!("/pullrequests/{}/diffstat?pagelen=100", self.pr)),
                workspace,
            )
            .await?;
        let current = self.fetch_pr_meta().await?;
        ensure!(
            current.head_sha == snapshot.head_sha && current.base_sha == snapshot.base_sha,
            "Bitbucket pull request changed while its diff was being acquired"
        );
        Ok(diff)
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<DiffSnapshot> {
        let workspace = WorkspaceBudget::new();
        if std::env::var(ENABLE_INCREMENTAL_ENV).as_deref() != Ok("1") {
            return Err(anyhow!(
                "Bitbucket incremental review is disabled because the compare-diff path has \
                 not been verified for this deployment; set {ENABLE_INCREMENTAL_ENV}=1 only \
                 after validating /diff/{{head}}..{{since}} against the target Bitbucket API"
            ));
        }
        validate_commit(since_sha)?;
        validate_commit(head_sha)?;
        self.build_complete_diff(
            since_sha,
            head_sha,
            self.url(&format!("/diffstat/{head_sha}..{since_sha}?pagelen=100")),
            workspace,
        )
        .await
    }

    async fn post_review(
        &self,
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> Result<ReviewPublicationReceipt> {
        let findings = &envelope.findings;
        let receipt =
            untracked_review_publication_receipt("bitbucket", envelope, &snapshot.head_sha);
        if super::only_operational_findings(findings) {
            return Ok(receipt);
        }
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!("postil: bitbucket review delivery skipped because the pull request changed");
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
                    self.url(&format!("/pullrequests/{}/comments", self.pr)),
                )
                .json(&json!({ "content": { "raw": summary } }))
                .send()
                .await
                .context("posting summary comment")?;
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
        self.set_status(
            head_sha,
            "postil/review",
            "INPROGRESS",
            "review in progress",
        )
        .await?;
        self.set_status(head_sha, "postil/gate", "INPROGRESS", "gate pending")
            .await?;
        Ok(("postil/review".to_string(), "postil/gate".to_string()))
    }

    async fn complete_checks(
        &self,
        _advisory_id: &str,
        _gate_id: &str,
        advisory: CheckState,
        gate: Option<CheckState>,
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> Result<()> {
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!("postil: bitbucket status delivery skipped because the pull request changed");
            return Ok(());
        }
        let head = envelope
            .head_sha
            .clone()
            .ok_or_else(|| anyhow!("envelope missing headSha for status update"))?;
        let map = |s: CheckState| match s {
            CheckState::Success => "SUCCESSFUL",
            // No neutral on Bitbucket; an errored run must not read as a pass.
            CheckState::Failure | CheckState::Neutral => "FAILED",
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
        let current = self.pr_meta().await?;
        if !pr_matches_snapshot(&current, expected) {
            return Ok(false);
        }
        validate_commit(&current.source.commit.hash)?;
        validate_commit(&current.destination.commit.hash)?;
        let merge_base = self
            .merge_base(
                &current.destination.commit.hash,
                &current.source.commit.hash,
            )
            .await?;
        Ok(merge_base == expected.base_sha)
    }

    /// Title and description of a PR. Bitbucket Cloud's issue tracker is a
    /// separate, often-disabled product with a different object shape we cannot
    /// verify against a live instance, so respond is scoped to pull requests.
    async fn fetch_thread(&self, _number: u64, kind: ThreadKind) -> Result<(String, String)> {
        // TODO(respond): Bitbucket issue-tracker comments
        // (`/issues/{id}` + `/issues/{id}/comments`) are unverified; scope to PRs.
        if kind == ThreadKind::Issue {
            return Err(anyhow!(
                "postil respond on Bitbucket supports --pr only (issue tracker not supported)"
            ));
        }
        let pr = self.pr_meta().await?;
        Ok((pr.title, pr.summary.map(|s| s.raw).unwrap_or_default()))
    }

    /// Post a top-level comment on a PR (the bot's reply to a mention).
    async fn post_comment(&self, number: u64, kind: ThreadKind, body: &str) -> Result<()> {
        // TODO(respond): Bitbucket issue-tracker comments are unverified; scope to PRs.
        if kind == ThreadKind::Issue {
            return Err(anyhow!(
                "postil respond on Bitbucket supports --pr only (issue tracker not supported)"
            ));
        }
        let resp = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pullrequests/{number}/comments")),
            )
            .json(&json!({ "content": { "raw": body } }))
            .send()
            .await
            .context("posting comment")?;
        Self::check_ok(resp, "comment post").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn pull_request(state: &str, target: &str) -> PrResponse {
        PrResponse {
            title: "title".into(),
            summary: Some(Rendered { raw: "body".into() }),
            state: state.into(),
            source: Endpoint {
                commit: Commit {
                    hash: "head".into(),
                },
            },
            destination: Endpoint {
                commit: Commit {
                    hash: target.into(),
                },
            },
        }
    }

    #[test]
    fn delivery_snapshot_rejects_closed_pull_request() {
        assert!(!pr_matches_snapshot(
            &pull_request("MERGED", "target"),
            &snapshot()
        ));
    }

    #[test]
    fn delivery_snapshot_rejects_changed_target() {
        assert!(!pr_matches_snapshot(
            &pull_request("OPEN", "advanced-target"),
            &snapshot()
        ));
    }

    #[test]
    fn delivery_snapshot_rejects_changed_head_and_metadata() {
        let mut current = pull_request("OPEN", "target");
        current.source.commit.hash = "advanced-head".into();
        assert!(!pr_matches_snapshot(&current, &snapshot()));
        current.source.commit.hash = "head".into();
        current.title = "edited title".into();
        assert!(!pr_matches_snapshot(&current, &snapshot()));
    }
}
