//! GitHub forge implementation (github.com and GHES via GITHUB_API_URL).

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    CheckState, Forge, PrMeta, SummaryContext, ThreadKind, check_summary, check_title,
    only_operational_findings, valid_details_url, wrap_plain_text,
};
use crate::diff::{DiffSnapshot, DiffSpool, WorkspaceBudget};
use crate::envelope::{Envelope, Finding, Severity};
use crate::filter;

pub struct GitHub {
    http: reqwest::Client,
    api_base: String,
    details_url: Option<String>,
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
        let details_url = valid_details_url(std::env::var("POSTIL_DETAILS_URL").ok());
        Ok(GitHub {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_base: api_base.trim_end_matches('/').to_string(),
            details_url,
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

    fn add_details_url(&self, body: &mut serde_json::Value) {
        if let Some(details_url) = &self.details_url {
            body["details_url"] = json!(details_url);
        }
    }

    async fn fetch_pr_state(&self) -> Result<PrResponse> {
        let response = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/pulls/{}", self.pr)),
                ),
                "PR head fetch",
            )
            .await?;
        let pr: PrResponse = super::bounded_response_json(
            Self::check_ok(response, "PR head fetch").await?,
            "GitHub PR head",
        )
        .await?;
        Ok(pr)
    }

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let request_id = github_request_id(resp.headers()).unwrap_or_else(|| "none".to_string());
        Err(super::http_failure(
            status,
            format!("GitHub {what} failed: {status} (request id {request_id})"),
        ))
    }

    async fn send_retryable(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response> {
        const RETRIES: u32 = 2;
        const TOTAL_BUDGET: Duration = Duration::from_secs(55);
        let operation_started_at = std::time::Instant::now();
        for retry in 0..=RETRIES {
            let attempt = retry + 1;
            let started_at = std::time::Instant::now();
            let remaining = TOTAL_BUDGET.saturating_sub(operation_started_at.elapsed());
            if remaining.is_zero() {
                return Err(anyhow!("GitHub {what} retry budget exhausted"));
            }
            let response = request
                .try_clone()
                .context("GitHub request body is not retryable")?
                .timeout(remaining)
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    eprintln!(
                        "postil: github operation={} attempt={}/{} category=transport-error elapsed_ms={} budget_remaining_ms={}",
                        what.replace(' ', "-"),
                        attempt,
                        RETRIES + 1,
                        started_at.elapsed().as_millis(),
                        TOTAL_BUDGET
                            .saturating_sub(operation_started_at.elapsed())
                            .as_millis(),
                    );
                    if retry == RETRIES {
                        return Err(error).with_context(|| format!("GitHub {what} request failed"));
                    }
                    let remaining = TOTAL_BUDGET.saturating_sub(operation_started_at.elapsed());
                    let delay = github_transport_retry_delay(retry).min(remaining);
                    if delay.is_zero() {
                        return Err(error)
                            .with_context(|| format!("GitHub {what} retry budget exhausted"));
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
            let status = response.status();
            let request_id =
                github_request_id(response.headers()).unwrap_or_else(|| "none".to_string());
            eprintln!(
                "postil: github operation={} attempt={}/{} status={} elapsed_ms={} request_id={} rate_remaining={} retry_after_secs={}",
                what.replace(' ', "-"),
                attempt,
                RETRIES + 1,
                status.as_u16(),
                started_at.elapsed().as_millis(),
                request_id,
                safe_numeric_header(response.headers(), "x-ratelimit-remaining")
                    .unwrap_or_else(|| "unknown".to_string()),
                retry_after(response.headers())
                    .map(|delay| delay.as_secs().to_string())
                    .unwrap_or_else(|| "none".to_string()),
            );
            if retry == RETRIES || !github_retryable_response(status, response.headers()) {
                return Ok(response);
            }
            let remaining = TOTAL_BUDGET.saturating_sub(operation_started_at.elapsed());
            let delay = github_retry_delay(status, response.headers(), retry).min(remaining);
            if delay.is_zero() {
                return Ok(response);
            }
            eprintln!(
                "postil: github operation={} retrying_in_secs={} retry={}/{}",
                what.replace(' ', "-"),
                delay.as_secs(),
                retry + 1,
                RETRIES,
            );
            tokio::time::sleep(delay).await;
        }
        unreachable!("bounded GitHub retry loop always returns")
    }

    async fn reconcile_check_run(
        &self,
        head_sha: &str,
        name: &str,
        external_id: &str,
    ) -> Result<Option<CheckRun>> {
        let response = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!(
                        "/commits/{head_sha}/check-runs?check_name={name}&filter=latest&per_page=100"
                    )),
                ),
                "check-run reconciliation",
            )
            .await?;
        let list: CheckRunList = super::bounded_response_json(
            Self::check_ok(response, "check-run reconciliation").await?,
            "GitHub check-run reconciliation",
        )
        .await?;
        Ok(list
            .check_runs
            .into_iter()
            .find(|run| run.external_id.as_deref() == Some(external_id)))
    }

    async fn create_check_run(
        &self,
        body: &serde_json::Value,
        head_sha: &str,
        name: &str,
        external_id: &str,
    ) -> Result<CheckRun> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            let response = self
                .request(reqwest::Method::POST, self.url("/check-runs"))
                .json(body)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    return super::bounded_response_json(response, "GitHub check-run").await;
                }
                Ok(response)
                    if github_retryable_response(response.status(), response.headers()) =>
                {
                    if let Some(run) = self
                        .reconcile_check_run(head_sha, name, external_id)
                        .await?
                    {
                        return Ok(run);
                    }
                    if retry == RETRIES {
                        return Err(super::http_failure(
                            response.status(),
                            format!("GitHub check-run create failed: {}", response.status()),
                        ));
                    }
                }
                Ok(response) => {
                    return Err(Self::check_ok(response, "check-run create")
                        .await
                        .unwrap_err());
                }
                Err(error) => {
                    if let Some(run) = self
                        .reconcile_check_run(head_sha, name, external_id)
                        .await?
                    {
                        return Ok(run);
                    }
                    if retry == RETRIES {
                        return Err(error).context("creating check-run after reconciliation");
                    }
                }
            }
            tokio::time::sleep(github_transport_retry_delay(retry)).await;
        }
        unreachable!("bounded check-run create loop always returns")
    }

    async fn review_exists(&self, marker: &str, head_sha: &str) -> Result<bool> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        for page in 1..=MAX_PAGES {
            let response = self
                .send_retryable(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!(
                            "/pulls/{}/reviews?per_page={PAGE_SIZE}&page={page}",
                            self.pr
                        )),
                    ),
                    "review reconciliation",
                )
                .await?;
            let reviews: Vec<PublishedReview> = super::bounded_response_json(
                Self::check_ok(response, "review reconciliation").await?,
                "GitHub review reconciliation",
            )
            .await?;
            let page_len = reviews.len();
            if reviews.into_iter().any(|review| {
                review.commit_id.as_deref() == Some(head_sha)
                    && review
                        .body
                        .as_deref()
                        .is_some_and(|body| body.contains(marker))
            }) {
                return Ok(true);
            }
            if page_len < PAGE_SIZE {
                return Ok(false);
            }
        }
        Err(anyhow!(
            "GitHub review reconciliation exceeded {MAX_PAGES} pages; refusing an unsafe retry"
        ))
    }

    async fn send_review_reconciled(
        &self,
        body: &serde_json::Value,
        marker: &str,
        head_sha: &str,
        what: &str,
    ) -> Result<Option<reqwest::Response>> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            let response = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/pulls/{}/reviews", self.pr)),
                )
                .json(body)
                .send()
                .await;
            match response {
                Ok(response)
                    if response.status().is_success()
                        || !github_retryable_response(response.status(), response.headers()) =>
                {
                    return Ok(Some(response));
                }
                Ok(response) => {
                    if self.review_exists(marker, head_sha).await? {
                        return Ok(None);
                    }
                    if retry == RETRIES {
                        return Ok(Some(response));
                    }
                }
                Err(error) => {
                    if self.review_exists(marker, head_sha).await? {
                        return Ok(None);
                    }
                    if retry == RETRIES {
                        return Err(error).with_context(|| format!("GitHub {what} failed"));
                    }
                }
            }
            tokio::time::sleep(github_transport_retry_delay(retry)).await;
        }
        unreachable!("bounded GitHub review loop always returns")
    }

    async fn comment_exists(&self, number: u64, marker: &str) -> Result<bool> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        for page in 1..=MAX_PAGES {
            let response = self
                .send_retryable(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!(
                            "/issues/{number}/comments?per_page={PAGE_SIZE}&page={page}&sort=created&direction=desc"
                        )),
                    ),
                    "comment reconciliation",
                )
                .await?;
            let comments: Vec<PublishedComment> = super::bounded_response_json(
                Self::check_ok(response, "comment reconciliation").await?,
                "GitHub comment reconciliation",
            )
            .await?;
            let page_len = comments.len();
            if comments
                .into_iter()
                .any(|comment| comment.body.contains(marker))
            {
                return Ok(true);
            }
            if page_len < PAGE_SIZE {
                return Ok(false);
            }
        }
        Err(anyhow!(
            "GitHub comment reconciliation exceeded {MAX_PAGES} pages; refusing an unsafe retry"
        ))
    }

    async fn post_comment_reconciled(&self, number: u64, body: &str, marker: &str) -> Result<()> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            let response = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/issues/{number}/comments")),
                )
                .json(&json!({ "body": body }))
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response)
                    if github_retryable_response(response.status(), response.headers()) =>
                {
                    if self.comment_exists(number, marker).await? {
                        return Ok(());
                    }
                    if retry == RETRIES {
                        Self::check_ok(response, "comment post").await?;
                    }
                }
                Ok(response) => {
                    Self::check_ok(response, "comment post").await?;
                }
                Err(error) => {
                    if self.comment_exists(number, marker).await? {
                        return Ok(());
                    }
                    if retry == RETRIES {
                        return Err(error).context("posting comment after reconciliation");
                    }
                }
            }
            tokio::time::sleep(github_transport_retry_delay(retry)).await;
        }
        unreachable!("bounded GitHub comment loop always returns")
    }

    async fn pull_files(&self, expected: usize) -> Result<Vec<PullFile>> {
        const PAGE_SIZE: usize = 100;
        const MAX_FILES: usize = 3_000;
        ensure!(
            expected <= MAX_FILES,
            "GitHub PR has {expected} changed files, beyond the complete files API limit of {MAX_FILES}"
        );
        let mut files = Vec::with_capacity(expected);
        let mut retained_bytes = 0usize;
        let mut page = 1usize;
        let max_pages = expected.div_ceil(PAGE_SIZE).max(1);
        loop {
            ensure!(
                page <= max_pages,
                "GitHub PR files pagination exceeded its declared page count"
            );
            let response = self
                .send_retryable(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!(
                            "/pulls/{}/files?per_page={PAGE_SIZE}&page={page}",
                            self.pr
                        )),
                    ),
                    "PR files fetch",
                )
                .await?;
            let page_text = super::bounded_response_text(
                Self::check_ok(response, "PR files fetch").await?,
                "GitHub PR files page",
            )
            .await?;
            retained_bytes = super::checked_metadata_total(
                retained_bytes,
                page_text.len(),
                "GitHub PR files pages",
            )?;
            let batch: Vec<PullFile> =
                serde_json::from_str(&page_text).context("decoding GitHub PR files page")?;
            let count = batch.len();
            ensure!(
                count <= PAGE_SIZE,
                "GitHub PR files page exceeded requested size"
            );
            for file in &batch {
                file.retained_bytes()?;
            }
            files.extend(batch);
            ensure!(
                files.len() <= expected && files.len() <= MAX_FILES,
                "GitHub PR files pagination exceeded the declared changed-file count"
            );
            if files.len() == expected || count < PAGE_SIZE {
                break;
            }
            page = page
                .checked_add(1)
                .ok_or_else(|| anyhow!("GitHub PR files page number overflowed"))?;
        }
        ensure!(
            files.len() == expected,
            "GitHub PR files API returned {} of {expected} declared changed files",
            files.len()
        );
        Ok(files)
    }

    async fn source_file(
        &self,
        revision: &str,
        path: &str,
        workspace: WorkspaceBudget,
    ) -> Result<(DiffSnapshot, usize)> {
        ensure!(
            super::valid_repository_path(path),
            "GitHub returned an unsafe repository path"
        );
        let mut url = reqwest::Url::parse(&self.url(&format!("/contents/{}", encode_path(path))))
            .context("building GitHub contents URL")?;
        url.query_pairs_mut().append_pair("ref", revision);
        let response = self
            .send_retryable(
                self.request(reqwest::Method::GET, url.to_string())
                    .header("Accept", "application/vnd.github.raw+json"),
                "source file fetch",
            )
            .await?;
        let snapshot = super::response_snapshot_in(
            Self::check_ok(response, "source file fetch").await?,
            "GitHub source file",
            workspace,
            None,
        )
        .await?;
        let byte_count = snapshot.as_bytes().len();
        Ok((snapshot, byte_count))
    }

    async fn build_complete_diff(
        &self,
        files: Vec<PullFile>,
        base_sha: &str,
        head_sha: &str,
        context: &str,
        workspace: WorkspaceBudget,
    ) -> Result<DiffSnapshot> {
        let mut seen = HashSet::with_capacity(files.len());
        for file in &files {
            validate_pull_file(file, context)?;
            ensure!(
                seen.insert(file.filename.clone()),
                "{context} returned a duplicate file"
            );
        }
        let mut sections = stream::iter(files.into_iter().enumerate().map(|(index, file)| {
            let workspace = workspace.clone();
            async move {
                let old_path = file.previous_filename.as_deref().unwrap_or(&file.filename);
                let (is_add, is_delete) = match file.status.as_str() {
                    "added" => (true, false),
                    "removed" => (false, true),
                    "modified" | "changed" | "copied" | "renamed" => (false, false),
                    _ => unreachable!("validated above"),
                };
                let (old, old_bytes) = if is_add {
                    (DiffSnapshot::from_bytes_in(b"", workspace.clone())?, 0)
                } else {
                    self.source_file(base_sha, old_path, workspace.clone())
                        .await?
                };
                let (new, new_bytes) = if is_delete {
                    (DiffSnapshot::from_bytes_in(b"", workspace.clone())?, 0)
                } else {
                    self.source_file(head_sha, &file.filename, workspace.clone())
                        .await?
                };
                let mut section = DiffSpool::new_in(workspace.clone())?;
                super::azure::write_diff_section(
                    &mut section,
                    old_path,
                    &file.filename,
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
            let _ = old_bytes
                .checked_add(new_bytes)
                .ok_or_else(|| anyhow!("{context} source acquisition size overflowed"))?;
            output
                .write_all(section.as_bytes())
                .with_context(|| format!("spooling {context}"))?;
        }
        output.finish()
    }
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

fn validate_pull_file(file: &PullFile, context: &str) -> Result<()> {
    ensure!(
        super::valid_repository_path(&file.filename),
        "{context} returned an unsafe repository path"
    );
    ensure!(
        matches!(
            file.status.as_str(),
            "added" | "removed" | "modified" | "changed" | "copied" | "renamed"
        ),
        "{context} returned an unsupported file status"
    );
    if let Some(previous) = file.previous_filename.as_deref() {
        ensure!(
            super::valid_repository_path(previous),
            "{context} returned an unsafe previous repository path"
        );
    }
    ensure!(
        !matches!(file.status.as_str(), "renamed" | "copied") || file.previous_filename.is_some(),
        "{context} omitted the previous path for a renamed or copied file"
    );
    Ok(())
}

fn safe_numeric_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
        .map(|value| value.chars().take(20).collect())
}

fn github_request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-github-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(super::opaque_id)
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    safe_numeric_header(headers, "retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

fn github_retryable_response(status: reqwest::StatusCode, headers: &HeaderMap) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
        || (status == reqwest::StatusCode::FORBIDDEN
            && (headers.contains_key("retry-after")
                || safe_numeric_header(headers, "x-ratelimit-remaining").as_deref() == Some("0")))
}

fn github_retry_delay(status: reqwest::StatusCode, headers: &HeaderMap, retry: u32) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    github_retry_delay_at(status, headers, retry, now)
}

fn github_retry_delay_at(
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    retry: u32,
    now: u64,
) -> Duration {
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
    if let Some(delay) = retry_after(headers) {
        return delay.min(MAX_RETRY_DELAY);
    }
    if matches!(status.as_u16(), 403 | 429)
        && let Some(reset) = safe_numeric_header(headers, "x-ratelimit-reset")
            .and_then(|value| value.parse::<u64>().ok())
        && reset > now
    {
        return Duration::from_secs(reset - now).min(MAX_RETRY_DELAY);
    }
    let delay = if matches!(status.as_u16(), 403 | 429) {
        Duration::from_secs(60 * (retry as u64 + 1))
    } else {
        Duration::from_secs(2_u64.pow(retry + 1))
    };
    delay.min(MAX_RETRY_DELAY)
}

fn github_transport_retry_delay(retry: u32) -> Duration {
    Duration::from_millis(100 * 2_u64.pow(retry))
}

fn short_sha(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(12)
        .collect()
}

fn gate_title(envelope: &Envelope) -> &'static str {
    if envelope.gate.failing {
        "Merge gate failed"
    } else {
        "Merge gate passed"
    }
}

fn gate_summary(envelope: &Envelope) -> String {
    if !envelope.findings.is_empty()
        && envelope.findings.iter().all(|finding| {
            matches!(
                finding.path.as_str(),
                crate::envelope::OPERATIONAL_PATH | crate::envelope::PROVIDER_PATH
            )
        })
    {
        return if envelope.gate.failing {
            "Postil could not complete this review, so no review verdict exists. The merge check remains blocked.\n".to_string()
        } else {
            "Postil could not complete this review, so no review verdict exists. This repository treats review outages as advisory.\n".to_string()
        };
    }
    if !envelope.gate.failing {
        return format!(
            "Merge gate passed: no findings block under the configured policy (failOn: {}).\n",
            envelope.gate.fail_on
        );
    }

    let failing: Vec<_> = envelope
        .findings
        .iter()
        .filter(|f| {
            !matches!(
                f.path.as_str(),
                crate::envelope::OPERATIONAL_PATH | crate::envelope::PROVIDER_PATH
            ) && crate::envelope::finding_blocks_gate(
                f,
                &envelope.gate.fail_on,
                &envelope.gate.block_on_kinds,
                false,
            )
        })
        .map(|f| {
            let publication = crate::envelope::finding_publication_text(&f.title, &f.body);
            format!(
                "- `{}:{}` {}",
                super::safe_code_text(&f.path),
                f.line,
                publication.title,
            )
        })
        .collect();
    if failing.is_empty() {
        return format!(
            "Merge gate failed under the configured operational error policy (failOn: {}).\n",
            envelope.gate.fail_on
        );
    }
    let subject = if failing.len() == 1 {
        "1 finding blocks".to_string()
    } else {
        format!("{} findings block", failing.len())
    };
    format!(
        "Merge gate failed: {subject} under the configured policy (failOn: {}).\n\n{}\n",
        envelope.gate.fail_on,
        failing.join("\n")
    )
}

#[derive(Deserialize)]
struct PrResponse {
    title: String,
    body: Option<String>,
    state: String,
    #[serde(default)]
    merged: bool,
    head: RefObj,
    base: RefObj,
    changed_files: usize,
}

#[derive(Debug, Deserialize)]
struct PullFile {
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
    changes: usize,
}

impl PullFile {
    fn retained_bytes(&self) -> Result<usize> {
        self.filename
            .len()
            .checked_add(self.status.len())
            .and_then(|total| total.checked_add(std::mem::size_of_val(&self.changes)))
            .and_then(|total| {
                total.checked_add(self.previous_filename.as_ref().map_or(0, String::len))
            })
            .ok_or_else(|| anyhow!("GitHub PR file metadata size overflowed"))
    }
}

#[derive(Deserialize)]
struct CompareResponse {
    merge_base_commit: RefObj,
    #[serde(default)]
    files: Vec<PullFile>,
}

#[derive(Deserialize)]
struct RefObj {
    sha: String,
}

#[derive(Deserialize)]
struct CheckRun {
    id: u64,
    #[serde(default)]
    external_id: Option<String>,
}

#[derive(Deserialize)]
struct CheckRunList {
    check_runs: Vec<CheckRun>,
}

#[derive(Deserialize)]
struct PublishedReview {
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    commit_id: Option<String>,
}

#[derive(Deserialize)]
struct PublishedComment {
    body: String,
}

impl Forge for GitHub {
    fn rich_markdown(&self) -> bool {
        true
    }

    fn review_summary(&self, envelope: &Envelope) -> String {
        check_summary(
            envelope,
            true,
            SummaryContext {
                details_url: self.details_url.clone(),
                prevention_hint: std::env::var("POSTIL_PREVENTION_HINT").as_deref() == Ok("1"),
                prevention_commands: SummaryContext::from_env().prevention_commands,
            },
        )
    }

    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let resp = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/pulls/{}", self.pr)),
                ),
                "PR fetch",
            )
            .await?;
        let pr: PrResponse =
            super::bounded_response_json(Self::check_ok(resp, "PR fetch").await?, "GitHub PR")
                .await?;
        ensure!(
            pr.state == "open" && !pr.merged,
            "GitHub pull request is not open"
        );
        ensure!(
            valid_object_id(&pr.base.sha) && valid_object_id(&pr.head.sha),
            "GitHub PR refs must be hexadecimal object ids"
        );
        let compare_response = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/compare/{}...{}", pr.base.sha, pr.head.sha)),
                ),
                "PR merge-base fetch",
            )
            .await?;
        let compare: CompareResponse = super::bounded_response_json(
            Self::check_ok(compare_response, "PR merge-base fetch").await?,
            "GitHub PR merge-base response",
        )
        .await?;
        ensure!(
            valid_object_id(&compare.merge_base_commit.sha),
            "GitHub merge base must be a hexadecimal object id"
        );
        Ok(PrMeta {
            title: pr.title,
            body: pr.body.unwrap_or_default(),
            head_sha: pr.head.sha,
            base_sha: compare.merge_base_commit.sha,
            target_sha: Some(pr.base.sha),
            changed_files: Some(pr.changed_files),
        })
    }

    async fn fetch_diff(&self, snapshot: &PrMeta) -> Result<DiffSnapshot> {
        let workspace = WorkspaceBudget::new();
        let expected = snapshot
            .changed_files
            .context("GitHub immutable review snapshot is missing its changed-file count")?;
        let files = self.pull_files(expected).await?;
        let current = self.fetch_pr_meta().await?;
        ensure!(
            current.head_sha == snapshot.head_sha
                && current.base_sha == snapshot.base_sha
                && current.target_sha == snapshot.target_sha
                && current.changed_files == snapshot.changed_files,
            "GitHub PR changed while its file list was being acquired"
        );
        self.build_complete_diff(
            files,
            &snapshot.base_sha,
            &snapshot.head_sha,
            "GitHub PR files API",
            workspace,
        )
        .await
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<DiffSnapshot> {
        let workspace = WorkspaceBudget::new();
        ensure!(
            valid_object_id(since_sha) && valid_object_id(head_sha),
            "GitHub compare revisions must be hexadecimal object ids"
        );
        let resp = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/compare/{since_sha}...{head_sha}")),
                ),
                "compare fetch",
            )
            .await?;
        let compare: CompareResponse = super::bounded_response_json(
            Self::check_ok(resp, "compare fetch").await?,
            "GitHub compare response",
        )
        .await?;
        ensure!(
            compare.merge_base_commit.sha == since_sha,
            "GitHub incremental compare no longer descends from the requested baseline; refusing an incomplete review"
        );
        // GitHub documents that compare responses include at most 300 files
        // and expose no complete file count. Exactly 300 is therefore
        // ambiguous and must fail closed.
        ensure!(
            compare.files.len() < 300,
            "GitHub compare reached the 300-file response cap; refusing an incomplete incremental review"
        );
        self.build_complete_diff(
            compare.files,
            since_sha,
            head_sha,
            "GitHub compare API",
            workspace,
        )
        .await
    }

    async fn post_review(
        &self,
        summary: &str,
        findings: &[Finding],
        snapshot: &PrMeta,
    ) -> Result<()> {
        let head_sha = snapshot.head_sha.as_str();
        if only_operational_findings(findings) {
            return Ok(());
        }
        // Every carried finding is already visible in an earlier Postil review.
        // Check-runs still receive the complete envelope, but posting the same
        // visible set as another PR review is duplicate noise.
        if !findings.is_empty() && findings.iter().all(filter::is_carried) {
            return Ok(());
        }
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!(
                "postil: github review delivery skipped because the PR snapshot changed reviewed_head={} reviewed_target={} reviewed_merge_base={}",
                short_sha(head_sha),
                short_sha(snapshot.target_sha.as_deref().unwrap_or("unknown")),
                short_sha(&snapshot.base_sha),
            );
            return Ok(());
        }
        let comments: Vec<_> = findings
            .iter()
            // Carried findings already have comments from the previous review.
            .filter(|f| !filter::is_carried(f))
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
        let marker = review_marker(head_sha, summary, findings);
        let marked_summary = append_marker(summary, &marker);
        let body = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": marked_summary,
            "comments": comments,
        });
        let Some(resp) = self
            .send_review_reconciled(&body, &marker, head_sha, "review post")
            .await?
        else {
            return Ok(());
        };
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let request_id = github_request_id(resp.headers()).unwrap_or_else(|| "none".to_string());
        if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Err(anyhow!(
                "GitHub review post failed: {status} (request id {request_id})"
            ));
        }

        eprintln!(
            "postil: github operation=review-post status=422 category=unresolved-line request_id={} recovery=summary-only",
            request_id,
        );
        let summary_only = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": append_marker(if summary.is_empty() {
                "Postil completed the review, but GitHub could not attach its inline comments."
            } else {
                summary
            }, &marker),
        });
        if let Some(fallback) = self
            .send_review_reconciled(&summary_only, &marker, head_sha, "summary-only review post")
            .await?
        {
            Self::check_ok(fallback, "summary-only review post").await?;
        }
        Ok(())
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        let mut ids = Vec::with_capacity(2);
        for name in ["postil/review", "postil/gate"] {
            let external_id = format!("postil:{name}:{head_sha}");
            let mut body = json!({
                "name": name,
                "head_sha": head_sha,
                "status": "in_progress",
                "external_id": external_id,
            });
            self.add_details_url(&mut body);
            let run = self
                .create_check_run(&body, head_sha, name, &external_id)
                .await
                .with_context(|| format!("creating check-run {name}"))?;
            ids.push(run.id.to_string());
        }
        Ok((ids[0].clone(), ids[1].clone()))
    }

    async fn snapshot_is_current(&self, expected: &PrMeta) -> Result<bool> {
        let pr = self.fetch_pr_state().await?;
        if pr.state != "open"
            || pr.merged
            || pr.head.sha != expected.head_sha
            || Some(pr.base.sha.as_str()) != expected.target_sha.as_deref()
        {
            return Ok(false);
        }
        ensure!(
            valid_object_id(&pr.base.sha) && valid_object_id(&pr.head.sha),
            "GitHub PR refs must be hexadecimal object ids"
        );
        let response = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/compare/{}...{}", pr.base.sha, pr.head.sha)),
                ),
                "PR merge-base freshness fetch",
            )
            .await?;
        let compare: CompareResponse = super::bounded_response_json(
            Self::check_ok(response, "PR merge-base freshness fetch").await?,
            "GitHub PR merge-base freshness response",
        )
        .await?;
        Ok(compare.merge_base_commit.sha == expected.base_sha)
    }

    async fn complete_checks(
        &self,
        advisory_id: &str,
        gate_id: &str,
        advisory: CheckState,
        gate: CheckState,
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> Result<()> {
        if !self.snapshot_is_current(snapshot).await? {
            eprintln!(
                "postil: github check delivery skipped because the PR snapshot changed reviewed_head={} reviewed_target={} reviewed_merge_base={}",
                short_sha(&snapshot.head_sha),
                short_sha(snapshot.target_sha.as_deref().unwrap_or("unknown")),
                short_sha(&snapshot.base_sha),
            );
            return Ok(());
        }
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
                let publication = crate::envelope::finding_publication_text(&f.title, &f.body);
                let message: String = publication.body.chars().take(800).collect();
                json!({
                    "path": f.path,
                    "start_line": f.line,
                    "end_line": f.end_line.unwrap_or(f.line),
                    "annotation_level": match f.severity {
                        Severity::Info => "notice",
                        Severity::Warn => "warning",
                        Severity::Error => "failure",
                    },
                    "title": publication.title,
                    "message": wrap_plain_text(&message, 100),
                })
            })
            .collect();
        for (id, state, name, with_annotations) in [
            (advisory_id, advisory, "postil/review", true),
            (gate_id, gate, "postil/gate", false),
        ] {
            let gate_note = if name == "postil/gate" {
                gate_summary(envelope)
            } else {
                check_summary(
                    envelope,
                    true,
                    SummaryContext {
                        details_url: self.details_url.clone(),
                        prevention_hint: false,
                        prevention_commands: vec![],
                    },
                )
            };
            let title = if name == "postil/gate" {
                gate_title(envelope).to_string()
            } else {
                check_title(envelope)
            };
            let mut output = json!({
                // GitHub rejects title >255 and summary >65535 with HTTP 422,
                // which would abort posting both checks. Cap both defensively.
                "title": super::cap_check_title(&title),
                "summary": super::cap_check_summary(&gate_note),
            });
            if with_annotations && !annotations.is_empty() {
                output["annotations"] = json!(annotations);
            }
            let mut body = json!({
                "status": "completed",
                "conclusion": conclusion(state),
                "output": output,
            });
            self.add_details_url(&mut body);
            let resp = self
                .send_retryable(
                    self.request(
                        reqwest::Method::PATCH,
                        self.url(&format!("/check-runs/{id}")),
                    )
                    .json(&body),
                    &format!("complete {name}"),
                )
                .await?;
            Self::check_ok(resp, "check-run complete").await?;
        }
        Ok(())
    }

    /// Title and body of an issue or PR (the issues API covers both, so `kind`
    /// is not needed here).
    async fn fetch_thread(&self, number: u64, _kind: ThreadKind) -> Result<(String, String)> {
        let resp = self
            .send_retryable(
                self.request(reqwest::Method::GET, self.url(&format!("/issues/{number}"))),
                "issue fetch",
            )
            .await?;
        let v: serde_json::Value = super::bounded_response_json(
            Self::check_ok(resp, "issue fetch").await?,
            "GitHub issue",
        )
        .await?;
        let title = v["title"].as_str().unwrap_or_default().to_string();
        let body = v["body"].as_str().unwrap_or_default().to_string();
        Ok((title, body))
    }

    /// Post a top-level comment on an issue or PR (the bot's reply to a mention).
    async fn post_comment(&self, number: u64, _kind: ThreadKind, body: &str) -> Result<()> {
        let marker = comment_marker(number, body);
        self.post_comment_reconciled(number, &append_marker(body, &marker), &marker)
            .await
    }
}

fn valid_object_id(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn review_marker(head_sha: &str, summary: &str, findings: &[Finding]) -> String {
    let mut digest = Sha256::new();
    digest.update(head_sha.as_bytes());
    digest.update(summary.as_bytes());
    for finding in findings {
        digest.update(finding.path.as_bytes());
        digest.update(finding.line.to_be_bytes());
        digest.update(finding.title.as_bytes());
    }
    let hash = digest.finalize();
    format!(
        "<!-- postil-review:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

fn append_marker(body: &str, marker: &str) -> String {
    if body.trim().is_empty() {
        marker.to_string()
    } else {
        format!("{body}\n\n{marker}")
    }
}

fn comment_marker(number: u64, body: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(number.to_be_bytes());
    digest.update(body.as_bytes());
    let hash = digest.finalize();
    format!(
        "<!-- postil-comment:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

#[cfg(test)]
mod tests {
    use super::{
        GitHub, PullFile, gate_summary, github_retry_delay_at, github_retryable_response,
        github_transport_retry_delay, only_operational_findings, valid_details_url,
        validate_pull_file,
    };
    use crate::envelope::{Envelope, Finding, Gate, Kind, Severity, Usage};
    use crate::forge::{CheckState, Forge, PrMeta};
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::time::Duration;
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn delivery_envelope(head_sha: &str, base_sha: &str) -> Envelope {
        Envelope {
            version: 1,
            summary: String::new(),
            silent: true,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Envelope::counts_of(&[], 0),
            confidence_buckets: Envelope::buckets_of(&[]),
            gate: Gate {
                fail_on: "error".into(),
                failing: false,
                block_on_kinds: vec![],
            },
            model_used: "model".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: Some(base_sha.into()),
            head_sha: Some(head_sha.into()),
            since_sha: None,
        }
    }

    fn delivery_snapshot(head_sha: &str, target_sha: &str, merge_base_sha: &str) -> PrMeta {
        PrMeta {
            title: "t".into(),
            body: "b".into(),
            head_sha: head_sha.into(),
            base_sha: merge_base_sha.into(),
            target_sha: Some(target_sha.into()),
            changed_files: Some(1),
        }
    }

    #[test]
    fn github_retry_delays_honor_headers_with_a_hard_cap() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("999999"));
        assert_eq!(
            github_retry_delay_at(reqwest::StatusCode::TOO_MANY_REQUESTS, &headers, 0, 1_000),
            Duration::from_secs(10)
        );

        headers.remove("retry-after");
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("999999"));
        assert_eq!(
            github_retry_delay_at(reqwest::StatusCode::FORBIDDEN, &headers, 0, 1_000),
            Duration::from_secs(10)
        );
        assert!(github_retryable_response(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            &headers
        ));
        assert_eq!(github_transport_retry_delay(0), Duration::from_millis(100));
        assert_eq!(github_transport_retry_delay(1), Duration::from_millis(200));
    }

    #[tokio::test]
    async fn github_safe_requests_retry_transport_errors() {
        let github = GitHub {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap(),
            api_base: "http://127.0.0.1:9".into(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
        };
        let started_at = std::time::Instant::now();
        let error = github
            .send_retryable(
                github.request(reqwest::Method::GET, github.url("/transport-failure")),
                "transport test",
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("request failed"));
        assert!(started_at.elapsed() >= Duration::from_millis(300));
        assert!(started_at.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn github_check_create_reconciles_before_retrying_uncertain_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/check-runs"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/commits/abcdef12/check-runs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "check_runs": [{"id": 77, "external_id": "postil:postil/review:abcdef12"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let github = test_github(&server);
        let external_id = "postil:postil/review:abcdef12";
        let body = serde_json::json!({
            "name": "postil/review",
            "head_sha": "abcdef12",
            "status": "in_progress",
            "external_id": external_id
        });

        let run = github
            .create_check_run(&body, "abcdef12", "postil/review", external_id)
            .await
            .unwrap();

        assert_eq!(run.id, 77);
    }

    #[tokio::test]
    async fn github_review_reconciles_before_retrying_uncertain_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "body": "summary\n\n<!-- postil-review:test -->",
                    "commit_id": "abcdef12"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let github = test_github(&server);
        let body = serde_json::json!({
            "body": "summary\n\n<!-- postil-review:test -->",
            "commit_id": "abcdef12",
            "event": "COMMENT"
        });

        let response = github
            .send_review_reconciled(
                &body,
                "<!-- postil-review:test -->",
                "abcdef12",
                "review post",
            )
            .await
            .unwrap();

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn github_comment_reconciles_before_retrying_uncertain_post() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/issues/9/comments"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/issues/9/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "body": "reply\n\n<!-- postil-comment:test -->"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let github = test_github(&server);

        github
            .post_comment_reconciled(
                9,
                "reply\n\n<!-- postil-comment:test -->",
                "<!-- postil-comment:test -->",
            )
            .await
            .unwrap();
    }

    fn test_github(server: &MockServer) -> GitHub {
        GitHub {
            http: reqwest::Client::new(),
            api_base: server.uri(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
        }
    }

    fn pull_file_page(start: usize, count: usize) -> Vec<serde_json::Value> {
        (start..start + count)
            .map(|index| {
                serde_json::json!({
                    "filename": format!("src/file-{index}.rs"),
                    "status": "modified",
                    "changes": 1
                })
            })
            .collect()
    }

    #[tokio::test]
    async fn github_pull_files_stops_at_one_complete_full_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/files"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(pull_file_page(0, 100)))
            .expect(1)
            .mount(&server)
            .await;

        let files = test_github(&server).pull_files(100).await.unwrap();
        assert_eq!(files.len(), 100);
    }

    #[tokio::test]
    async fn github_pull_files_stops_at_two_complete_full_pages() {
        let server = MockServer::start().await;
        for (page, start) in [(1, 0), (2, 100)] {
            Mock::given(method("GET"))
                .and(path("/repos/owner/repo/pulls/1/files"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", page.to_string()))
                .respond_with(ResponseTemplate::new(200).set_body_json(pull_file_page(start, 100)))
                .expect(1)
                .mount(&server)
                .await;
        }

        let files = test_github(&server).pull_files(200).await.unwrap();
        assert_eq!(files.len(), 200);
    }

    #[tokio::test]
    async fn github_pull_files_accepts_a_partial_page_after_a_full_page() {
        let server = MockServer::start().await;
        for (page, start, count) in [(1, 0, 100), (2, 100, 1)] {
            Mock::given(method("GET"))
                .and(path("/repos/owner/repo/pulls/1/files"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", page.to_string()))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(pull_file_page(start, count)),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let files = test_github(&server).pull_files(101).await.unwrap();
        assert_eq!(files.len(), 101);
    }

    #[test]
    fn github_copied_files_require_their_previous_path() {
        let missing_source = PullFile {
            filename: "src/copy.rs".into(),
            status: "copied".into(),
            previous_filename: None,
            changes: 1,
        };
        let error = validate_pull_file(&missing_source, "fixture").unwrap_err();
        assert!(error.to_string().contains("renamed or copied"));

        let with_source = PullFile {
            previous_filename: Some("src/original.rs".into()),
            ..missing_source
        };
        validate_pull_file(&with_source, "fixture").unwrap();
    }

    #[tokio::test]
    async fn github_incremental_diff_rejects_a_non_ancestor_baseline() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/compare/aaaaaaaa...bbbbbbbb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccc"},
                "files": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = match test_github(&server)
            .fetch_diff_since("aaaaaaaa", "bbbbbbbb")
            .await
        {
            Ok(_) => panic!("non-ancestor incremental compare was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no longer descends"));
    }

    #[tokio::test]
    async fn github_snapshot_rejects_a_closed_pull_request_before_diff_fetch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "closed", "merged": false,
                "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/compare/bbbbbbbb...aaaaaaaa"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let error = test_github(&server).fetch_pr_meta().await.unwrap_err();
        assert!(error.to_string().contains("not open"));
    }

    #[tokio::test]
    async fn github_review_is_not_posted_after_the_pr_head_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b",
                "state": "open", "merged": false,
                "head": {"sha": "bbbbbbbbbbbb"}, "base": {"sha": "base"}, "changed_files": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let github = GitHub {
            http: reqwest::Client::new(),
            api_base: server.uri(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
        };
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            id: None,
        };

        github
            .post_review(
                "Summary",
                &[finding],
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn github_review_is_not_posted_after_the_target_branch_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"},
                "base": {"sha": "dddddddddddd"},
                "changed_files": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/owner/repo/compare/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        for id in ["11", "12"] {
            Mock::given(method("PATCH"))
                .and(path(format!("/repos/owner/repo/check-runs/{id}")))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&server)
                .await;
        }
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            id: None,
        };

        let github = test_github(&server);
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        github
            .post_review("Summary", &[finding], &snapshot)
            .await
            .unwrap();
        github
            .complete_checks(
                "11",
                "12",
                CheckState::Success,
                CheckState::Success,
                &delivery_envelope("aaaaaaaaaaaa", "cccccccccccc"),
                &snapshot,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn github_review_and_checks_are_not_delivered_after_the_merge_base_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"},
                "base": {"sha": "bbbbbbbbbbbb"},
                "changed_files": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "dddddddddddd"}, "files": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        for id in ["11", "12"] {
            Mock::given(method("PATCH"))
                .and(path(format!("/repos/owner/repo/check-runs/{id}")))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&server)
                .await;
        }
        let github = test_github(&server);
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            id: None,
        };
        let envelope = delivery_envelope("aaaaaaaaaaaa", "cccccccccccc");
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");

        github
            .post_review("Summary", &[finding], &snapshot)
            .await
            .unwrap();
        github
            .complete_checks(
                "11",
                "12",
                CheckState::Success,
                CheckState::Success,
                &envelope,
                &snapshot,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn github_review_is_not_posted_after_the_pr_closes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "closed", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "base"}, "changed_files": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let github = GitHub {
            http: reqwest::Client::new(),
            api_base: server.uri(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
        };
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            id: None,
        };

        github
            .post_review(
                "Summary",
                &[finding],
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn github_review_and_check_annotations_revalidate_model_prose() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b",
                "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccccccc"}, "files": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        for id in ["11", "12"] {
            Mock::given(method("PATCH"))
                .and(path(format!("/repos/owner/repo/check-runs/{id}")))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
        }
        let github = GitHub {
            http: reqwest::Client::new(),
            api_base: server.uri(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
        };
        let finding = Finding {
            path: "src/lib.rs".into(),
            line: 1,
            end_line: None,
            severity: Severity::Error,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: format!("@octocat <img> {}", "oversized ".repeat(100)),
            body: format!(
                "# Summary\n@octocat <details>hidden</details> ![pixel](https://attacker.invalid/x)\n{}",
                "article line\n".repeat(100),
            ),
            id: None,
        };
        let envelope = Envelope {
            version: 1,
            summary: String::new(),
            silent: false,
            findings: vec![finding.clone()],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Envelope::counts_of(std::slice::from_ref(&finding), 0),
            confidence_buckets: Envelope::buckets_of(std::slice::from_ref(&finding)),
            gate: Gate {
                fail_on: "error".into(),
                failing: true,
                block_on_kinds: vec![],
            },
            model_used: "model".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: Some("cccccccccccc".into()),
            head_sha: Some("aaaaaaaaaaaa".into()),
            since_sha: None,
        };

        github
            .post_review(
                "One finding needs attention.",
                std::slice::from_ref(&finding),
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
        github
            .complete_checks(
                "11",
                "12",
                CheckState::Failure,
                CheckState::Failure,
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let review = requests
            .iter()
            .find(|request| {
                request.method == reqwest::Method::POST
                    && request.url.path().ends_with("/pulls/1/reviews")
            })
            .unwrap();
        let review_body: serde_json::Value = serde_json::from_slice(&review.body).unwrap();
        let inline = review_body["comments"][0]["body"].as_str().unwrap();
        assert!(inline.chars().count() < 1_600);
        assert!(!inline.contains("@octocat"));
        assert!(!inline.contains("<details>"));
        assert!(
            !inline
                .lines()
                .any(|line| line.trim_start().starts_with("!["))
        );
        assert!(!inline.contains("# Summary"));

        let advisory = requests
            .iter()
            .find(|request| request.url.path().ends_with("/check-runs/11"))
            .unwrap();
        let check_body: serde_json::Value = serde_json::from_slice(&advisory.body).unwrap();
        let annotation = &check_body["output"]["annotations"][0];
        let title = annotation["title"].as_str().unwrap();
        let message = annotation["message"].as_str().unwrap();
        assert!(title.chars().count() <= crate::envelope::FINDING_PUBLIC_TITLE_MAX_CHARS);
        assert!(message.chars().count() <= 800);
        assert!(!title.contains('@'));
        assert!(!message.contains("@octocat"));
        assert!(!message.contains("<details>"));
    }

    #[test]
    fn details_url_accepts_only_http_and_https_urls() {
        assert_eq!(
            valid_details_url(Some("https://postil.dev/orgs/acme/runs/review-1".into())),
            Some("https://postil.dev/orgs/acme/runs/review-1".into())
        );
        assert_eq!(
            valid_details_url(Some("http://localhost:3000/runs/review-1".into())),
            Some("http://localhost:3000/runs/review-1".into())
        );
        assert_eq!(valid_details_url(Some("ftp://postil.dev/run".into())), None);
        assert_eq!(valid_details_url(Some("https://".into())), None);
        assert_eq!(valid_details_url(Some("not a URL".into())), None);
        assert_eq!(valid_details_url(None), None);
    }

    #[test]
    fn only_operational_failures_skip_the_pr_review() {
        let provider = crate::envelope::provider_error_finding("private provider detail");
        assert!(only_operational_findings(std::slice::from_ref(&provider)));

        let mut real = provider;
        real.path = "src/lib.rs".into();
        assert!(!only_operational_findings(&[real]));
        assert!(!only_operational_findings(&[]));
    }

    #[test]
    fn gate_summary_counts_qualified_kind_blocks_from_stored_envelope() {
        let finding = Finding {
            path: "src/auth.rs".into(),
            line: 41,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::HumanEscalation,
            confidence: 0.30,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            title: "Human judgment required".into(),
            body: "Concrete compatibility concern.".into(),
            id: None,
        };
        let env = Envelope {
            version: 1,
            summary: String::new(),
            silent: false,
            findings: vec![finding],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: Gate {
                fail_on: "error".into(),
                failing: true,
                block_on_kinds: vec!["humanEscalation".into()],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };

        let summary = gate_summary(&env);
        assert!(summary.contains("1 finding blocks under the configured policy"));
        assert!(summary.contains("src/auth.rs:41"));
    }

    #[test]
    fn gate_summary_reports_provider_failure_from_serialized_gate_outcome() {
        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: false,
            findings: vec![],
            suppressed_findings: vec![],
            resolved: vec![],
            counts: Default::default(),
            confidence_buckets: [0; 5],
            gate: Gate {
                fail_on: "never".into(),
                failing: true,
                block_on_kinds: vec![],
            },
            model_used: "m".into(),
            scorer_model: None,
            scorer_error: None,
            scorer_disagreements: None,
            usage: Usage::default(),
            model_usage: vec![],
            model_incidents: vec![],
            review_coverage: None,
            review_admission: None,
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        env.findings
            .push(crate::envelope::provider_error_finding("timeout"));

        let summary = gate_summary(&env);
        assert!(summary.contains("no review verdict exists"));
        assert!(summary.contains("merge check remains blocked"));
        assert!(!summary.contains("provider"));
        assert!(!summary.contains("timeout"));
    }
}
