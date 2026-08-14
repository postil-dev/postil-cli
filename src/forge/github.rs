//! GitHub forge implementation (github.com and GHES via GITHUB_API_URL).

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    CheckRunIds, CheckState, FindingPublicationOutcome, FindingPublicationReceipt, Forge, PrMeta,
    ReviewPublicationReceipt, ReviewPublicationSummary, SummaryContext, ThreadKind, check_summary,
    check_title, only_operational_findings, valid_details_url,
};
use crate::diff::{DiffSnapshot, DiffSpool, WorkspaceBudget};
use crate::envelope::{Envelope, Finding, Severity};
use crate::filter;

pub const EXPECTED_REPOSITORY_ID_ENV: &str = "POSTIL_EXPECTED_GITHUB_REPO_ID";
const GITHUB_MAX_ANNOTATIONS_PER_REQUEST: usize = 50;

// Filtering caps visible findings before forge publication, so one completed
// check update always fits GitHub's annotation request limit. Raising the
// product cap requires implementing multi-request annotation delivery first.
const _: () = assert!(crate::config::MAX_FINDINGS <= GITHUB_MAX_ANNOTATIONS_PER_REQUEST);

pub struct GitHub {
    http: reqwest::Client,
    api_base: String,
    details_url: Option<String>,
    token: String,
    owner: String,
    repo: String,
    pr: u64,
    expected_repository_id: Option<u64>,
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
        let expected_repository_id = match std::env::var(EXPECTED_REPOSITORY_ID_ENV) {
            Ok(value) => {
                let parsed = value.parse::<u64>().with_context(|| {
                    format!("{EXPECTED_REPOSITORY_ID_ENV} must be a positive integer")
                })?;
                ensure!(
                    parsed > 0,
                    "{EXPECTED_REPOSITORY_ID_ENV} must be a positive integer"
                );
                Some(parsed)
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow!(
                    "{EXPECTED_REPOSITORY_ID_ENV} must be valid Unicode"
                ));
            }
        };
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
            expected_repository_id,
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

    fn review_summary_for_receipt(
        &self,
        envelope: &Envelope,
        receipt: &ReviewPublicationReceipt,
    ) -> String {
        let from_env = SummaryContext::from_env();
        check_summary(
            envelope,
            true,
            SummaryContext {
                details_url: self.details_url.clone(),
                prevention_hint: std::env::var("POSTIL_PREVENTION_HINT").as_deref() == Ok("1"),
                prevention_commands: from_env.prevention_commands,
                publication: Some(publication_summary(receipt)),
            },
        )
    }

    async fn finalize_review_summary(
        &self,
        envelope: &Envelope,
        receipt: &ReviewPublicationReceipt,
        marker: &str,
    ) -> Result<()> {
        let review_id = receipt
            .review_id
            .as_deref()
            .context("GitHub published review omitted its review id")?
            .parse::<u64>()
            .context("GitHub published review returned an invalid review id")?;
        let summary = self.review_summary_for_receipt(envelope, receipt);
        let body = bounded_review_body(&summary, marker, self.details_url.as_deref());
        let response = self
            .send_write_retryable(
                self.request(
                    reqwest::Method::PUT,
                    self.url(&format!("/pulls/{}/reviews/{review_id}", self.pr)),
                )
                .json(&json!({ "body": body })),
                "review summary update",
            )
            .await?;
        Self::check_ok(response, "review summary update").await?;
        Ok(())
    }

    async fn finalize_review_summary_if_possible(
        &self,
        envelope: &Envelope,
        receipt: &ReviewPublicationReceipt,
        marker: &str,
    ) {
        if self
            .finalize_review_summary(envelope, receipt, marker)
            .await
            .is_err()
        {
            eprintln!(
                "postil: github operation=review-summary-update status=incomplete recovery=truthful-initial-summary"
            );
        }
    }

    fn check_external_id(&self, name: &str, head_sha: &str) -> String {
        let run_id = self.details_url.as_deref().and_then(|details_url| {
            reqwest::Url::parse(details_url)
                .ok()?
                .path_segments()?
                .rfind(|segment| !segment.is_empty())
                .filter(|segment| {
                    segment.len() <= 80
                        && segment.chars().all(|character| {
                            character.is_ascii_alphanumeric() || "-_".contains(character)
                        })
                })
                .map(str::to_string)
        });
        run_id.map_or_else(
            || format!("postil:{name}:{head_sha}"),
            |run_id| format!("postil:{run_id}:{name}:{head_sha}"),
        )
    }

    async fn verify_repository_identity_before_write(&self) -> Result<()> {
        let Some(expected_id) = self.expected_repository_id else {
            if crate::config::hosted_runtime_mode() {
                return Err(super::repository_identity_failure(format!(
                    "hosted GitHub publication requires {EXPECTED_REPOSITORY_ID_ENV}"
                )));
            }
            return Ok(());
        };
        let response = self
            .request(reqwest::Method::GET, self.url(""))
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|error| {
                super::repository_identity_failure(format!(
                    "GitHub repository identity could not be verified: {error}"
                ))
            })?;
        let response = Self::check_ok(response, "repository identity fence")
            .await
            .map_err(|error| {
                super::repository_identity_failure(format!(
                    "GitHub repository identity could not be verified: {error:#}"
                ))
            })?;
        let identity: RepositoryIdentity =
            super::bounded_response_json(response, "GitHub repository identity")
                .await
                .map_err(|error| {
                    super::repository_identity_failure(format!(
                        "GitHub repository identity could not be verified: {error:#}"
                    ))
                })?;
        let expected_name = format!("{}/{}", self.owner, self.repo);
        if identity.id != expected_id || !identity.full_name.eq_ignore_ascii_case(&expected_name) {
            return Err(super::repository_identity_failure(
                "GitHub repository identity changed; refusing publication",
            ));
        }
        Ok(())
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
        self.send_retryable_inner(request, what, false).await
    }

    async fn send_write_retryable(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response> {
        self.send_retryable_inner(request, what, true).await
    }

    async fn send_retryable_inner(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
        fence_each_attempt: bool,
    ) -> Result<reqwest::Response> {
        const RETRIES: u32 = 2;
        const TOTAL_BUDGET: Duration = Duration::from_secs(55);
        let operation_started_at = std::time::Instant::now();
        for retry in 0..=RETRIES {
            if fence_each_attempt {
                self.verify_repository_identity_before_write().await?;
            }
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
            self.verify_repository_identity_before_write().await?;
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

    async fn find_review(&self, marker: &str, head_sha: &str) -> Result<Option<PublishedReview>> {
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
            if let Some(review) = reviews.into_iter().find(|review| {
                review.commit_id.as_deref() == Some(head_sha)
                    && review
                        .body
                        .as_deref()
                        .is_some_and(|body| body.contains(marker))
            }) {
                return Ok(Some(review));
            }
            if page_len < PAGE_SIZE {
                return Ok(None);
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
    ) -> Result<ReviewDelivery> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            self.verify_repository_identity_before_write().await?;
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
                    return Ok(ReviewDelivery::Response(response));
                }
                Ok(response) => {
                    if let Some(review) = self.find_review(marker, head_sha).await? {
                        return Ok(ReviewDelivery::Reconciled(review));
                    }
                    if retry == RETRIES {
                        return Ok(ReviewDelivery::Response(response));
                    }
                }
                Err(error) => {
                    if let Some(review) = self.find_review(marker, head_sha).await? {
                        return Ok(ReviewDelivery::Reconciled(review));
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

    async fn review_comments(&self, review_id: u64) -> Result<Vec<PublishedReviewComment>> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        let mut comments = Vec::new();
        for page in 1..=MAX_PAGES {
            let response = self
                .send_retryable(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!(
                            "/pulls/{}/reviews/{review_id}/comments?per_page={PAGE_SIZE}&page={page}",
                            self.pr
                        )),
                    ),
                    "review comment reconciliation",
                )
                .await?;
            let page_comments: Vec<PublishedReviewComment> = super::bounded_response_json(
                Self::check_ok(response, "review comment reconciliation").await?,
                "GitHub review comment reconciliation",
            )
            .await?;
            let page_len = page_comments.len();
            comments.extend(page_comments);
            if page_len < PAGE_SIZE {
                return Ok(comments);
            }
        }
        Err(anyhow!(
            "GitHub review comment reconciliation exceeded {MAX_PAGES} pages"
        ))
    }

    async fn materialize_review_receipt(
        &self,
        mut receipt: ReviewPublicationReceipt,
        review: PublishedReview,
    ) -> Result<ReviewPublicationReceipt> {
        receipt.review_id = review.id.map(|id| id.to_string());
        let mut comments = review.comments;
        if comments.is_empty()
            && receipt
                .findings
                .iter()
                .any(|finding| finding.initial_outcome == FindingPublicationOutcome::Inline)
            && let Some(review_id) = review.id
        {
            comments = self.review_comments(review_id).await?;
        }
        for finding in &mut receipt.findings {
            if finding.initial_outcome != FindingPublicationOutcome::Inline {
                continue;
            }
            let marker = finding_marker(&finding.finding_id);
            if let Some(comment) = comments
                .iter()
                .find(|comment| comment.body.contains(&marker))
            {
                finding.comment_id = Some(comment.id.to_string());
            } else {
                finding.initial_outcome = FindingPublicationOutcome::Unknown;
            }
        }
        Ok(receipt)
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

    /// Finding markers already carried by inline comments on this pull request.
    ///
    /// A finding's id is a hash over the head SHA, kind, path, line, and title,
    /// so an identical marker is the same finding at the same place on the same
    /// commit. Two reviews of one head — a push review followed by an `@postil`
    /// mention, say — legitimately re-detect the same issue, and without this
    /// the second run posts a second copy of every comment the first already
    /// left.
    ///
    /// Failure here is not a publication failure. A review that cannot read the
    /// existing comments posts everything it found, which is the behaviour this
    /// dedup replaces.
    async fn published_finding_markers(&self) -> std::collections::HashSet<String> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        let mut markers = std::collections::HashSet::new();
        for page in 1..=MAX_PAGES {
            let request = self.request(
                reqwest::Method::GET,
                self.url(&format!(
                    "/pulls/{}/comments?per_page={PAGE_SIZE}&page={page}",
                    self.pr
                )),
            );
            let Ok(response) = self.send_retryable(request, "inline comment dedup").await else {
                return markers;
            };
            let Ok(response) = Self::check_ok(response, "inline comment dedup").await else {
                return markers;
            };
            let Ok(comments): Result<Vec<PublishedReviewComment>> =
                super::bounded_response_json(response, "GitHub inline comment dedup").await
            else {
                return markers;
            };
            let page_len = comments.len();
            for comment in comments {
                if let Some(marker) = finding_marker_in(&comment.body) {
                    markers.insert(marker);
                }
            }
            if page_len < PAGE_SIZE {
                break;
            }
        }
        markers
    }

    async fn post_comment_reconciled(&self, number: u64, body: &str, marker: &str) -> Result<()> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            self.verify_repository_identity_before_write().await?;
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

    #[cfg(test)]
    async fn fetch_repository_file_at_revision(
        &self,
        revision: &str,
        path: &str,
    ) -> Result<String> {
        let (snapshot, _) = self
            .source_file(revision, path, WorkspaceBudget::new())
            .await?;
        String::from_utf8(snapshot.as_bytes().to_vec())
            .context("GitHub repository file is not valid UTF-8")
    }

    pub(crate) async fn fetch_repository_file_if_present(
        &self,
        revision: &str,
        path: &str,
    ) -> Result<Option<String>> {
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
                "repository file fetch",
            )
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let snapshot = super::response_snapshot_in(
            Self::check_ok(response, "repository file fetch").await?,
            "GitHub repository file",
            WorkspaceBudget::new(),
            None,
        )
        .await?;
        String::from_utf8(snapshot.as_bytes().to_vec())
            .context("GitHub repository file is not valid UTF-8")
            .map(Some)
    }

    pub(crate) async fn search_repository_at_head(
        &self,
        head_sha: &str,
        terms: Vec<crate::repository_search::SearchTerm>,
    ) -> crate::envelope::RepositorySearchReceipt {
        if terms.is_empty() {
            return crate::repository_search::unavailable(Some(head_sha));
        }
        let fallback_terms = terms.clone();
        let deadline = crate::repository_search::github_aggregate_deadline();
        match tokio::time::timeout(
            deadline,
            self.search_repository_at_head_inner(head_sha, terms),
        )
        .await
        {
            Err(_) => crate::repository_search::exhausted_with_terms(head_sha, &fallback_terms),
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error))
                if error
                    .chain()
                    .any(|cause| cause.downcast_ref::<RepositorySearchExhausted>().is_some()) =>
            {
                crate::repository_search::exhausted_with_terms(head_sha, &fallback_terms)
            }
            Ok(Err(_)) => {
                crate::repository_search::unavailable_with_terms(Some(head_sha), &fallback_terms)
            }
        }
    }

    async fn search_repository_at_head_inner(
        &self,
        head_sha: &str,
        terms: Vec<crate::repository_search::SearchTerm>,
    ) -> Result<crate::envelope::RepositorySearchReceipt> {
        ensure!(
            crate::repository_search::valid_full_object_id(head_sha),
            "GitHub repository search requires a full commit SHA"
        );
        let mut budget = RepositorySearchBudget::new();
        let response = self
            .send_repository_search_request(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/git/commits/{head_sha}")),
                ),
                &mut budget,
            )
            .await?;
        let commit: GitCommitResponse =
            super::bounded_response_json(response, "GitHub repository commit").await?;
        ensure!(
            commit.sha.eq_ignore_ascii_case(head_sha),
            "GitHub repository commit did not match the reviewed head"
        );
        ensure!(
            crate::repository_search::valid_full_object_id(&commit.tree.sha),
            "GitHub repository commit returned an invalid tree id"
        );

        let mut queue = VecDeque::from([(String::new(), commit.tree.sha, 0usize)]);
        let mut blobs = Vec::new();
        let mut entry_count = 0usize;
        let mut tree_count = 0usize;
        let mut total_bytes = 0u64;
        let mut gitlinks = Vec::new();
        while let Some((prefix, tree_sha, depth)) = queue.pop_front() {
            tree_count = tree_count
                .checked_add(1)
                .context("repository tree object count overflowed")?;
            if tree_count > crate::repository_search::github_tree_object_cap() {
                return Ok(crate::repository_search::exhausted_with_terms(
                    head_sha, &terms,
                ));
            }
            budget.charge_objects(1)?;
            if depth > crate::repository_search::tree_depth_cap() {
                return Ok(crate::repository_search::exhausted_with_terms(
                    head_sha, &terms,
                ));
            }
            let response = self
                .send_repository_search_request(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!("/git/trees/{tree_sha}")),
                    ),
                    &mut budget,
                )
                .await?;
            let tree: GitTreeResponse =
                super::bounded_response_json(response, "GitHub repository tree").await?;
            ensure!(
                tree.sha.eq_ignore_ascii_case(&tree_sha),
                "GitHub repository tree did not match the requested object"
            );
            ensure!(!tree.truncated, "GitHub repository tree was incomplete");
            let mut entries = tree.tree;
            ensure!(
                crate::repository_search::git_tree_matches(
                    &tree_sha,
                    entries.iter().map(|entry| (
                        entry.path.as_str(),
                        entry.mode.as_str(),
                        entry.sha.as_str(),
                    )),
                ),
                "GitHub repository tree entries did not match the requested object"
            );
            entries.sort_by(|left, right| left.path.cmp(&right.path));
            budget.charge_objects(entries.len())?;
            let mut names = HashSet::with_capacity(entries.len());
            for entry in entries {
                entry_count = entry_count
                    .checked_add(1)
                    .context("repository tree entry count overflowed")?;
                if entry_count > crate::repository_search::tree_entry_cap() {
                    return Ok(crate::repository_search::exhausted_with_terms(
                        head_sha, &terms,
                    ));
                }
                ensure!(
                    !entry.path.is_empty()
                        && !entry.path.contains('/')
                        && entry.path != "."
                        && entry.path != ".."
                        && !entry.path.contains('\0')
                        && names.insert(entry.path.clone()),
                    "GitHub repository tree returned an unsafe path"
                );
                ensure!(
                    crate::repository_search::valid_full_object_id(&entry.sha),
                    "GitHub repository tree returned an invalid object id"
                );
                let path = if prefix.is_empty() {
                    entry.path
                } else {
                    format!("{prefix}/{}", entry.path)
                };
                ensure!(
                    super::valid_repository_path(&path),
                    "GitHub repository tree returned an unsafe path"
                );
                match (entry.kind.as_str(), entry.mode.as_str()) {
                    ("tree", "040000") => {
                        ensure!(entry.size.is_none(), "GitHub repository tree had a size");
                        queue.push_back((path, entry.sha, depth.saturating_add(1)));
                    }
                    ("blob", "100644" | "100755" | "120000") => {
                        let size = entry
                            .size
                            .context("GitHub repository blob omitted its size")?;
                        let Some(next_total) = total_bytes.checked_add(size) else {
                            return Ok(crate::repository_search::exhausted_with_terms(
                                head_sha, &terms,
                            ));
                        };
                        total_bytes = next_total;
                        if total_bytes > crate::repository_search::search_byte_cap() {
                            return Ok(crate::repository_search::exhausted_with_terms(
                                head_sha, &terms,
                            ));
                        }
                        blobs.push((path, entry.sha, entry.mode, size));
                    }
                    ("commit", "160000") => {
                        ensure!(entry.size.is_none(), "GitHub submodule entry had a size");
                        gitlinks.push((path, entry.sha));
                    }
                    _ => {
                        return Err(anyhow!(
                            "GitHub repository tree returned an unsupported object type or mode"
                        ));
                    }
                }
            }
        }
        blobs.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            blobs.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "GitHub repository tree returned a duplicate path"
        );
        let mut snapshot_entries = blobs
            .iter()
            .map(|(path, object_id, mode, size)| {
                crate::repository_search::RepositorySnapshotEntry {
                    path: path.clone(),
                    object_id: object_id.clone(),
                    mode: mode.clone(),
                    kind: crate::repository_search::RepositorySnapshotEntryKind::Blob,
                    size: Some(*size),
                }
            })
            .chain(gitlinks.iter().map(|(path, object_id)| {
                crate::repository_search::RepositorySnapshotEntry {
                    path: path.clone(),
                    object_id: object_id.clone(),
                    mode: "160000".to_string(),
                    kind: crate::repository_search::RepositorySnapshotEntryKind::Gitlink,
                    size: None,
                }
            }))
            .collect::<Vec<_>>();
        snapshot_entries.sort_by(|left, right| left.path.cmp(&right.path));
        let tree_sha256 = crate::repository_search::tree_sha256(&snapshot_entries);
        let mut search = crate::repository_search::SearchAccumulator::new(terms);
        for (path, object_id) in &gitlinks {
            search.scan_gitlink(path, object_id);
        }
        for (path, blob_sha, _mode, size) in blobs {
            search.scan_path(&path);
            let response = self
                .send_repository_search_request(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!("/git/blobs/{blob_sha}")),
                    )
                    .header("Accept", "application/vnd.github.raw+json"),
                    &mut budget,
                )
                .await?;
            let remaining = budget.remaining()?;
            tokio::time::timeout(
                remaining,
                search.scan_response(&path, &blob_sha, response, size),
            )
            .await
            .map_err(|_| anyhow::Error::new(RepositorySearchExhausted))??;
        }
        if gitlinks.is_empty() {
            Ok(search.complete(head_sha, tree_sha256))
        } else {
            Ok(search.incomplete(head_sha, tree_sha256))
        }
    }

    async fn send_repository_search_request(
        &self,
        request: reqwest::RequestBuilder,
        budget: &mut RepositorySearchBudget,
    ) -> Result<reqwest::Response> {
        let remaining = budget.charge_request()?;
        let response = request.timeout(remaining).send().await.map_err(|error| {
            if error.is_timeout() {
                anyhow::Error::new(RepositorySearchExhausted)
            } else {
                anyhow!(error).context("GitHub repository object request failed")
            }
        })?;
        if github_repository_rate_limit_risk(response.status(), response.headers()) {
            return Err(anyhow::Error::new(RepositorySearchExhausted));
        }
        if !response.status().is_success() {
            return Err(anyhow!(
                "GitHub repository object request failed: {}",
                response.status()
            ));
        }
        Ok(response)
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

fn github_repository_rate_limit_risk(status: reqwest::StatusCode, headers: &HeaderMap) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || (status == reqwest::StatusCode::FORBIDDEN
            && (headers.contains_key("retry-after")
                || headers.contains_key("x-ratelimit-reset")
                || safe_numeric_header(headers, "x-ratelimit-remaining").as_deref() == Some("0")))
        || safe_numeric_header(headers, "x-ratelimit-remaining").as_deref() == Some("0")
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
            let publication = crate::envelope::forge_safe_finding_publication_text(f);
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
struct GitTreeResponse {
    sha: String,
    #[serde(default)]
    truncated: bool,
    tree: Vec<GitTreeEntry>,
}

#[derive(Deserialize)]
struct GitTreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Deserialize)]
struct GitCommitResponse {
    sha: String,
    tree: RefObj,
}

#[derive(Debug)]
struct RepositorySearchExhausted;

impl std::fmt::Display for RepositorySearchExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("repository search budget exhausted")
    }
}

impl std::error::Error for RepositorySearchExhausted {}

struct RepositorySearchBudget {
    started_at: Instant,
    requests: usize,
    objects: usize,
}

impl RepositorySearchBudget {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            requests: 0,
            objects: 0,
        }
    }

    fn remaining(&self) -> Result<Duration> {
        let remaining = crate::repository_search::github_aggregate_deadline()
            .saturating_sub(self.started_at.elapsed());
        if remaining.is_zero() {
            Err(anyhow::Error::new(RepositorySearchExhausted))
        } else {
            Ok(remaining)
        }
    }

    fn charge_request(&mut self) -> Result<Duration> {
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or_else(|| anyhow::Error::new(RepositorySearchExhausted))?;
        if self.requests > crate::repository_search::github_request_cap() {
            return Err(anyhow::Error::new(RepositorySearchExhausted));
        }
        self.remaining()
    }

    fn charge_objects(&mut self, count: usize) -> Result<()> {
        self.objects = self
            .objects
            .checked_add(count)
            .ok_or_else(|| anyhow::Error::new(RepositorySearchExhausted))?;
        if self.objects > crate::repository_search::github_object_cap() {
            return Err(anyhow::Error::new(RepositorySearchExhausted));
        }
        self.remaining().map(|_| ())
    }
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

#[derive(Clone, Deserialize)]
struct PublishedReview {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    commit_id: Option<String>,
    #[serde(default)]
    comments: Vec<PublishedReviewComment>,
}

#[derive(Clone, Deserialize)]
struct PublishedReviewComment {
    id: u64,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
struct PublishedComment {
    body: String,
}

enum ReviewDelivery {
    Response(reqwest::Response),
    Reconciled(PublishedReview),
}

#[derive(Deserialize)]
struct RepositoryIdentity {
    id: u64,
    full_name: String,
}

impl Forge for GitHub {
    fn rich_markdown(&self) -> bool {
        true
    }

    fn review_summary(&self, envelope: &Envelope) -> String {
        let receipt =
            planned_review_receipt(envelope, envelope.head_sha.as_deref().unwrap_or("unknown"));
        self.review_summary_for_receipt(envelope, &receipt)
    }

    fn plan_review_publication(
        &self,
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> ReviewPublicationReceipt {
        planned_review_receipt(envelope, &snapshot.head_sha)
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
        envelope: &Envelope,
        snapshot: &PrMeta,
    ) -> Result<ReviewPublicationReceipt> {
        let findings = &envelope.findings;
        let head_sha = snapshot.head_sha.as_str();
        let planned_receipt = self.plan_review_publication(envelope, snapshot);
        if only_operational_findings(findings) {
            return Ok(planned_receipt);
        }
        // Every carried finding is already visible in an earlier Postil review.
        // Check-runs still receive the complete envelope, but posting the same
        // visible set as another PR review is duplicate noise.
        if !findings.is_empty() && findings.iter().all(filter::is_carried) {
            return Ok(planned_receipt);
        }
        if !self.snapshot_is_current(snapshot).await? {
            return Err(anyhow!(
                "GitHub review delivery skipped because the PR snapshot changed reviewed_head={} reviewed_target={} reviewed_merge_base={}",
                short_sha(head_sha),
                short_sha(snapshot.target_sha.as_deref().unwrap_or("unknown")),
                short_sha(&snapshot.base_sha),
            ));
        }
        // A re-review of an unchanged head re-detects what the last review
        // found. Those findings arrive fresh rather than carried, so the carry
        // filter above cannot see them; their markers already on the PR can.
        let published = self.published_finding_markers().await;
        let comments: Vec<_> = findings
            .iter()
            // Carried findings already have comments from the previous review.
            .filter(|f| !filter::is_carried(f))
            // Synthetic-path findings (PR description, fail-closed markers) have
            // no real file line to anchor an inline comment; they surface only in
            // the summary body.
            .filter(|f| !super::is_synthetic_path(&f.path))
            .filter(|f| {
                let (finding_id, _) = finding_receipt_id(f);
                !published.contains(&finding_marker(&finding_id))
            })
            .map(|f| {
                let (finding_id, _) = finding_receipt_id(f);
                let mut c = json!({
                    "path": f.path,
                    "line": f.line,
                    "side": "RIGHT",
                    "body": append_marker(
                        &super::finding_comment_body(f, true),
                        &finding_marker(&finding_id),
                    ),
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
        let summary = self.review_summary_for_receipt(envelope, &planned_receipt);
        if comments.is_empty() && summary.is_empty() {
            return Ok(planned_receipt);
        }
        let marker = review_marker(&planned_receipt.receipt_id);
        let marked_summary = bounded_review_body(&summary, &marker, self.details_url.as_deref());
        let has_planned_inline = planned_receipt
            .findings
            .iter()
            .any(|finding| finding.initial_outcome == FindingPublicationOutcome::Inline);
        let body = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": marked_summary,
            "comments": comments,
        });
        let delivery = self
            .send_review_reconciled(&body, &marker, head_sha, "review post")
            .await?;
        let resp = match delivery {
            ReviewDelivery::Reconciled(review) => {
                let receipt = self
                    .materialize_review_receipt(planned_receipt, review)
                    .await?;
                if has_planned_inline {
                    self.finalize_review_summary_if_possible(envelope, &receipt, &marker)
                        .await;
                }
                return Ok(receipt);
            }
            ReviewDelivery::Response(response) => response,
        };
        if resp.status().is_success() {
            let review: PublishedReview =
                super::bounded_response_json(resp, "GitHub published review").await?;
            let receipt = self
                .materialize_review_receipt(planned_receipt, review)
                .await?;
            if has_planned_inline {
                self.finalize_review_summary_if_possible(envelope, &receipt, &marker)
                    .await;
            }
            return Ok(receipt);
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
        let rejected_receipt = rejected_inline_receipt(planned_receipt);
        let fallback_summary = self.review_summary_for_receipt(envelope, &rejected_receipt);
        let summary_only = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": bounded_review_body(
                if fallback_summary.is_empty() {
                    "Postil completed the review, but GitHub could not attach its inline comments."
                } else {
                    &fallback_summary
                },
                &marker,
                self.details_url.as_deref(),
            ),
        });
        let fallback = self
            .send_review_reconciled(&summary_only, &marker, head_sha, "summary-only review post")
            .await?;
        match fallback {
            ReviewDelivery::Reconciled(review) => {
                self.materialize_review_receipt(rejected_receipt, review)
                    .await
            }
            ReviewDelivery::Response(response) => {
                let response = Self::check_ok(response, "summary-only review post").await?;
                let review: PublishedReview =
                    super::bounded_response_json(response, "GitHub summary-only review").await?;
                self.materialize_review_receipt(rejected_receipt, review)
                    .await
            }
        }
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        let mut ids = Vec::with_capacity(2);
        for name in ["postil/review", "postil/gate"] {
            let external_id = self.check_external_id(name, head_sha);
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
            || pr.title != expected.title
            || pr.body.as_deref().unwrap_or_default() != expected.body
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
        check_ids: CheckRunIds<'_>,
        advisory: CheckState,
        gate: Option<CheckState>,
        envelope: &Envelope,
        snapshot: &PrMeta,
        annotate_findings: bool,
    ) -> Result<()> {
        if !self.snapshot_is_current(snapshot).await? {
            return Err(anyhow!(
                "GitHub check delivery skipped because the PR snapshot changed reviewed_head={} reviewed_target={} reviewed_merge_base={}",
                short_sha(&snapshot.head_sha),
                short_sha(snapshot.target_sha.as_deref().unwrap_or("unknown")),
                short_sha(&snapshot.base_sha),
            ));
        }
        let conclusion = |s: CheckState| match s {
            CheckState::Success => "success",
            CheckState::Failure => "failure",
            CheckState::Neutral => "neutral",
        };
        let annotations: Vec<_> = if annotate_findings {
            envelope
                .findings
                .iter()
                // Carried findings remain visible on the review that introduced
                // them. Re-annotating can also target a stale line range.
                .filter(|f| !filter::is_carried(f))
                // Synthetic-path findings have no real file line to annotate;
                // they are already carried in the check-run summary body.
                .filter(|f| !super::is_synthetic_path(&f.path))
                .map(|f| {
                    let publication = crate::envelope::forge_safe_finding_publication_text(f);
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
                        "message": publication.body,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        debug_assert!(annotations.len() <= GITHUB_MAX_ANNOTATIONS_PER_REQUEST);
        let mut checks = vec![(check_ids.advisory, advisory, "postil/review", true)];
        if let Some(gate) = gate {
            checks.push((check_ids.gate, gate, "postil/gate", false));
        }
        let mut results = stream::iter(checks.into_iter().enumerate().map(
            |(index, (id, state, name, with_annotations))| {
                let annotations = &annotations;
                async move {
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
                                publication: None,
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
                    if annotate_findings && with_annotations && !annotations.is_empty() {
                        output["annotations"] = json!(annotations);
                    }
                    let mut body = json!({
                        "status": "completed",
                        "conclusion": conclusion(state),
                        "output": output,
                    });
                    self.add_details_url(&mut body);
                    let result = match self
                        .send_write_retryable(
                            self.request(
                                reqwest::Method::PATCH,
                                self.url(&format!("/check-runs/{id}")),
                            )
                            .json(&body),
                            &format!("complete {name}"),
                        )
                        .await
                    {
                        Ok(response) => Self::check_ok(response, "check-run complete")
                            .await
                            .map(|_| ()),
                        Err(error) => Err(error),
                    };
                    (index, name, result)
                }
            },
        ))
        .buffer_unordered(2)
        .collect::<Vec<_>>()
        .await;
        results.sort_by_key(|(index, _, _)| *index);
        let mut failures = Vec::new();
        for (_, name, result) in results {
            if let Err(error) = result {
                if super::is_repository_identity_failure(&error) {
                    return Err(error);
                }
                failures.push(format!("{name}: {error:#}"));
            }
        }
        if !failures.is_empty() {
            return Err(anyhow!(
                "{} GitHub check completion(s) failed: {}",
                failures.len(),
                failures.join("; ")
            ));
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

fn finding_receipt_id(finding: &Finding) -> (String, bool) {
    if let Some(id) = finding.id.as_deref().filter(|id| !id.is_empty()) {
        return (id.to_string(), true);
    }
    let mut digest = Sha256::new();
    digest.update(finding.path.as_bytes());
    digest.update(finding.line.to_be_bytes());
    digest.update(finding.end_line.unwrap_or(finding.line).to_be_bytes());
    digest.update(finding.kind.as_str().as_bytes());
    digest.update(finding.title.as_bytes());
    if let Some(evidence) = finding.evidence.as_deref() {
        digest.update(evidence.as_bytes());
    }
    let hash = digest.finalize();
    (
        format!(
            "legacy-v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
        ),
        false,
    )
}

fn finding_receipt(
    finding: &Finding,
    initial_outcome: FindingPublicationOutcome,
) -> FindingPublicationReceipt {
    let (finding_id, stable_identity) = finding_receipt_id(finding);
    FindingPublicationReceipt {
        finding_id,
        stable_identity,
        initial_outcome,
        inline_rejected: false,
        comment_id: None,
    }
}

fn planned_review_receipt(envelope: &Envelope, head_sha: &str) -> ReviewPublicationReceipt {
    let mut findings = Vec::new();
    for finding in envelope
        .findings
        .iter()
        .filter(|finding| !super::is_operational_path(&finding.path))
    {
        let outcome = if filter::is_carried(finding) {
            FindingPublicationOutcome::Carried
        } else if super::is_synthetic_path(&finding.path) {
            FindingPublicationOutcome::SummaryOnly
        } else {
            FindingPublicationOutcome::Inline
        };
        findings.push(finding_receipt(finding, outcome));
    }
    findings.extend(
        envelope
            .resolved
            .iter()
            .map(|finding| finding_receipt(finding, FindingPublicationOutcome::Resolved)),
    );
    findings.extend(envelope.suppressed_findings.iter().map(|suppressed| {
        finding_receipt(&suppressed.finding, FindingPublicationOutcome::Suppressed)
    }));

    let mut digest = Sha256::new();
    digest.update(b"github-review-receipt-v2\0");
    digest.update(head_sha.as_bytes());
    for finding in &findings {
        digest.update(finding.finding_id.as_bytes());
        digest.update([finding.initial_outcome as u8]);
    }
    let hash = digest.finalize();
    ReviewPublicationReceipt {
        version: ReviewPublicationReceipt::VERSION,
        channel: super::ReviewPublicationChannel::ReviewComments,
        receipt_id: format!(
            "github-review-v2:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
        ),
        review_id: None,
        findings,
    }
}

fn publication_summary(receipt: &ReviewPublicationReceipt) -> ReviewPublicationSummary {
    let mut summary = ReviewPublicationSummary::default();
    for finding in &receipt.findings {
        match finding.initial_outcome {
            FindingPublicationOutcome::Inline if finding.comment_id.is_some() => {
                summary.active_inline += 1;
            }
            FindingPublicationOutcome::Inline => {}
            FindingPublicationOutcome::CheckAnnotation => summary.summary_only += 1,
            FindingPublicationOutcome::SummaryOnly => summary.summary_only += 1,
            FindingPublicationOutcome::Carried => summary.carried += 1,
            FindingPublicationOutcome::Resolved
            | FindingPublicationOutcome::Suppressed
            | FindingPublicationOutcome::Unknown => {}
        }
        if finding.inline_rejected {
            summary.rejected_inline += 1;
        }
    }
    summary
}

fn rejected_inline_receipt(mut receipt: ReviewPublicationReceipt) -> ReviewPublicationReceipt {
    for finding in &mut receipt.findings {
        if finding.initial_outcome == FindingPublicationOutcome::Inline {
            finding.initial_outcome = FindingPublicationOutcome::SummaryOnly;
            finding.inline_rejected = true;
            finding.comment_id = None;
        }
    }
    receipt
}

fn finding_marker(finding_id: &str) -> String {
    let hash = Sha256::digest(finding_id.as_bytes());
    format!(
        "<!-- postil-finding:v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

fn review_marker(receipt_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(receipt_id.as_bytes());
    let hash = digest.finalize();
    format!(
        "<!-- postil-review:v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

/// The finding marker a published comment body ends with, if any.
fn finding_marker_in(body: &str) -> Option<String> {
    const OPEN: &str = "<!-- postil-finding:v1:";
    let start = body.rfind(OPEN)?;
    let end = body[start..].find("-->")? + start + "-->".len();
    Some(body[start..end].to_string())
}

fn append_marker(body: &str, marker: &str) -> String {
    if body.trim().is_empty() {
        marker.to_string()
    } else {
        format!("{body}\n\n{marker}")
    }
}

const MAX_REVIEW_BODY_BYTES: usize = 60_000;
const OVERSIZED_REVIEW_MESSAGE: &str =
    "Review summary omitted because it exceeds GitHub's size limit.";

fn bounded_review_body(body: &str, marker: &str, details_url: Option<&str>) -> String {
    let marked = append_marker(body, marker);
    if marked.len() <= MAX_REVIEW_BODY_BYTES {
        return marked;
    }
    if let Some(details_url) = details_url {
        let linked = append_marker(
            &format!("{OVERSIZED_REVIEW_MESSAGE}\n\n<sub>[Review details]({details_url})</sub>"),
            marker,
        );
        if linked.len() <= MAX_REVIEW_BODY_BYTES {
            return linked;
        }
    }
    append_marker(OVERSIZED_REVIEW_MESSAGE, marker)
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
        EXPECTED_REPOSITORY_ID_ENV, GitHub, PullFile, RepositorySearchBudget, finding_marker,
        finding_marker_in, finding_receipt_id, gate_summary, github_repository_rate_limit_risk,
        github_retry_delay_at, github_retryable_response, github_transport_retry_delay,
        only_operational_findings, valid_details_url, validate_pull_file,
    };
    use crate::envelope::{
        Envelope, Finding, Gate, Kind, Severity, SuppressedFinding, SuppressionReason, Usage,
    };
    use crate::forge::{CheckRunIds, CheckState, FindingPublicationOutcome, Forge, PrMeta};
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
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
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: Some(base_sha.into()),
            head_sha: Some(head_sha.into()),
            since_sha: None,
        }
    }

    fn delivery_envelope_with_findings(
        head_sha: &str,
        base_sha: &str,
        findings: Vec<Finding>,
    ) -> Envelope {
        let mut envelope = delivery_envelope(head_sha, base_sha);
        envelope.silent = findings.is_empty();
        envelope.counts = Envelope::counts_of(&findings, 0);
        envelope.confidence_buckets = Envelope::buckets_of(&findings);
        envelope.gate.failing = findings
            .iter()
            .any(|finding| finding.severity == Severity::Error);
        envelope.findings = findings;
        envelope
    }

    fn publication_finding(id: &str, path: &str, body: &str) -> Finding {
        Finding {
            path: path.into(),
            line: 7,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Risk,
            confidence: 0.9,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: None,
            title: format!("Finding {id}"),
            body: body.into(),
            evidence: Some("let value = risky();".into()),
            id: Some(id.into()),
        }
    }

    fn repository_search_terms() -> Vec<crate::repository_search::SearchTerm> {
        use crate::envelope::{RepositoryClaim, RepositoryClaimKind};
        crate::repository_search::search_terms(std::iter::once(&RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["clusterVersion".into()],
        }))
        .unwrap()
    }

    #[test]
    fn hosted_repository_identity_environment_contract_is_stable() {
        assert_eq!(EXPECTED_REPOSITORY_ID_ENV, "POSTIL_EXPECTED_GITHUB_REPO_ID");
    }

    #[test]
    fn review_summary_body_is_bounded_before_github_publication() {
        let marker = "<!-- postil-review:test -->";
        assert_eq!(
            super::bounded_review_body("summary", marker, None),
            format!("summary\n\n{marker}")
        );
        let fallback = super::bounded_review_body(
            &"x".repeat(super::MAX_REVIEW_BODY_BYTES),
            marker,
            Some("https://postil.dev/runs/1"),
        );
        assert!(fallback.contains(super::OVERSIZED_REVIEW_MESSAGE));
        assert!(fallback.contains("[Review details](https://postil.dev/runs/1)"));
        assert!(fallback.ends_with(marker));
        assert!(fallback.len() <= super::MAX_REVIEW_BODY_BYTES);

        let oversized_url = format!("https://postil.dev/{}", "x".repeat(60_000));
        let without_link = super::bounded_review_body(
            &"x".repeat(super::MAX_REVIEW_BODY_BYTES),
            marker,
            Some(&oversized_url),
        );
        assert!(!without_link.contains("Review details"));
        assert!(without_link.len() <= super::MAX_REVIEW_BODY_BYTES);
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
            expected_repository_id: None,
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

        assert!(matches!(response, super::ReviewDelivery::Reconciled(_)));
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
            expected_repository_id: None,
        }
    }

    #[tokio::test]
    async fn fetch_repository_file_at_revision_returns_text_and_rejects_binary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/config/review.toml"))
            .and(query_param("ref", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_string("enabled = true\n"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/assets/data.bin"))
            .and(query_param("ref", "def456"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0xff, 0xfe]))
            .expect(1)
            .mount(&server)
            .await;
        let github = test_github(&server);

        let text = github
            .fetch_repository_file_at_revision("abc123", "config/review.toml")
            .await
            .unwrap();
        assert_eq!(text, "enabled = true\n");

        let error = github
            .fetch_repository_file_at_revision("def456", "assets/data.bin")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[tokio::test]
    async fn fetch_repository_file_if_present_never_reads_a_base_revision() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/config/review.toml"))
            .and(query_param("ref", "head123"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/config/review.toml"))
            .and(query_param("ref", "base123"))
            .respond_with(ResponseTemplate::new(200).set_body_string("enabled = true\n"))
            .expect(0)
            .mount(&server)
            .await;

        let github = test_github(&server);
        let content = github
            .fetch_repository_file_if_present("head123", "config/review.toml")
            .await
            .unwrap();

        assert_eq!(content, None);
    }

    #[tokio::test]
    async fn fetch_repository_file_if_present_does_not_mask_head_failures() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/config/review.toml"))
            .and(query_param("ref", "head123"))
            .respond_with(ResponseTemplate::new(500))
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/contents/config/review.toml"))
            .and(query_param("ref", "base123"))
            .respond_with(ResponseTemplate::new(200).set_body_string("stale = true\n"))
            .expect(0)
            .mount(&server)
            .await;

        let error = test_github(&server)
            .fetch_repository_file_if_present("head123", "config/review.toml")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("500"));
    }

    #[tokio::test]
    async fn repository_search_walks_nested_trees_and_every_blob_at_the_pinned_head() {
        use crate::envelope::{
            RepositoryClaim, RepositoryClaimKind, RepositorySearchQueryKind, RepositorySearchState,
        };

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        let readme = b"CephCluster supports stable releases.\n";
        let generated = b"clusterVersion: 19.2.5\nimage: ceph:19.2.5\n";
        let symlink = b"../outside";
        let readme_blob = crate::repository_search::git_blob_sha1(readme);
        let generated_blob = crate::repository_search::git_blob_sha1(generated);
        let symlink_blob = crate::repository_search::git_blob_sha1(symlink);
        let submodule = "1".repeat(40);
        let manifest_tree = crate::repository_search::git_tree_sha1([(
            "generated.yaml",
            "100644",
            generated_blob.as_str(),
        )]);
        let root_tree = crate::repository_search::git_tree_sha1([
            ("README.md", "100644", readme_blob.as_str()),
            ("manifests", "040000", manifest_tree.as_str()),
            ("outside-link", "120000", symlink_blob.as_str()),
            ("vendor", "160000", submodule.as_str()),
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": head,
                "tree": {"sha": root_tree}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/trees/{root_tree}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": root_tree,
                "truncated": false,
                "tree": [
                    {"path": "README.md", "mode": "100644", "type": "blob", "sha": readme_blob, "size": readme.len()},
                    {"path": "manifests", "mode": "040000", "type": "tree", "sha": manifest_tree},
                    {"path": "outside-link", "mode": "120000", "type": "blob", "sha": symlink_blob, "size": symlink.len()},
                    {"path": "vendor", "mode": "160000", "type": "commit", "sha": submodule}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/owner/repo/git/trees/{manifest_tree}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": manifest_tree,
                "truncated": false,
                "tree": [
                    {"path": "generated.yaml", "mode": "100644", "type": "blob", "sha": generated_blob, "size": generated.len()}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        for (blob, body) in [
            (readme_blob.as_str(), readme.as_slice()),
            (generated_blob.as_str(), generated.as_slice()),
            (symlink_blob.as_str(), symlink.as_slice()),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/repos/owner/repo/git/blobs/{blob}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .expect(1)
                .mount(&server)
                .await;
        }

        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec!["outside-secret-term".into()],
            versions: vec!["19.2.5".into()],
            paths: vec!["manifests/generated.yaml".into()],
            identifiers: vec!["clusterVersion".into()],
        };
        let terms = crate::repository_search::search_terms(std::iter::once(&claim)).unwrap();
        let receipt = test_github(&server)
            .search_repository_at_head(&head, terms)
            .await;

        assert_eq!(receipt.head_sha.as_deref(), Some(head.as_str()));
        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert!(receipt.tree_sha256.is_some());
        assert_eq!(receipt.searched_blobs, 3);
        assert_eq!(
            receipt.searched_bytes,
            (readme.len() + generated.len() + symlink.len()) as u64
        );
        assert!(receipt.queries.iter().any(|query| {
            query.kind == RepositorySearchQueryKind::Path
                && receipt.matched_query_sha256.contains(&query.query_sha256)
        }));
        assert!(receipt.matches.iter().any(|matched| {
            matched.path == "manifests/generated.yaml" && matched.occurrences == 2
        }));
        let outside = receipt
            .queries
            .iter()
            .find(|query| query.kind == RepositorySearchQueryKind::Value)
            .unwrap();
        assert!(!receipt.matched_query_sha256.contains(&outside.query_sha256));
    }

    #[tokio::test]
    async fn repository_search_rejects_same_size_blob_substitution() {
        use crate::envelope::RepositorySearchState;

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        let expected = b"required-construct=true\n";
        let substituted = b"required-construct=fals\n";
        assert_eq!(expected.len(), substituted.len());
        let blob = crate::repository_search::git_blob_sha1(expected);
        let tree =
            crate::repository_search::git_tree_sha1([("config.txt", "100644", blob.as_str())]);

        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": head,
                "tree": {"sha": tree}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/trees/{tree}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": tree,
                "truncated": false,
                "tree": [{
                    "path": "config.txt", "mode": "100644", "type": "blob",
                    "sha": blob, "size": expected.len()
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/blobs/{blob}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(substituted))
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .search_repository_at_head(&head, repository_search_terms())
            .await;

        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert_eq!(receipt.searched_blobs, 0);
    }

    #[tokio::test]
    async fn repository_search_rejects_tree_entry_substitution() {
        use crate::envelope::RepositorySearchState;

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        let expected_blob = crate::repository_search::git_blob_sha1(b"expected\n");
        let substituted_blob = crate::repository_search::git_blob_sha1(b"attacker\n");
        let tree = crate::repository_search::git_tree_sha1([(
            "config.txt",
            "100644",
            expected_blob.as_str(),
        )]);

        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": head,
                "tree": {"sha": tree}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/trees/{tree}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": tree,
                "truncated": false,
                "tree": [{
                    "path": "config.txt", "mode": "100644", "type": "blob",
                    "sha": substituted_blob, "size": 9
                }]
            })))
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .search_repository_at_head(&head, repository_search_terms())
            .await;

        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert_eq!(receipt.searched_blobs, 0);
    }

    #[tokio::test]
    async fn repository_search_rejects_head_mutation_before_reading_a_tree() {
        use crate::envelope::{RepositoryClaim, RepositoryClaimKind, RepositorySearchState};

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        let changed_head = "b".repeat(40);
        let tree = "c".repeat(40);
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": changed_head,
                "tree": {"sha": tree}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/trees/{tree}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["identifier".into()],
        };
        let terms = crate::repository_search::search_terms(std::iter::once(&claim)).unwrap();

        let receipt = test_github(&server)
            .search_repository_at_head(&head, terms)
            .await;
        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert_eq!(receipt.queries.len(), 1);
    }

    #[tokio::test]
    async fn repository_search_reports_exhaustion_before_fetching_oversized_blobs() {
        use crate::envelope::RepositorySearchState;

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        let blob = "c".repeat(40);
        let tree = crate::repository_search::git_tree_sha1([("huge.bin", "100644", blob.as_str())]);
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": head,
                "tree": {"sha": tree}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/trees/{tree}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": tree,
                "truncated": false,
                "tree": [{
                    "path": "huge.bin", "mode": "100644", "type": "blob", "sha": blob,
                    "size": crate::repository_search::search_byte_cap() + 1
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/blobs/{blob}")))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .search_repository_at_head(&head, repository_search_terms())
            .await;
        assert_eq!(receipt.state, RepositorySearchState::Exhausted);
    }

    #[tokio::test]
    async fn repository_search_rejects_hostile_tree_paths_and_truncated_trees() {
        use crate::envelope::RepositorySearchState;

        for (entry_path, truncated) in [("../escape", false), ("safe", true)] {
            let server = MockServer::start().await;
            let head = "a".repeat(40);
            let tree = "b".repeat(40);
            let blob = "c".repeat(40);
            Mock::given(method("GET"))
                .and(path(format!("/repos/owner/repo/git/commits/{head}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "sha": head,
                    "tree": {"sha": tree}
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/repos/owner/repo/git/trees/{tree}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "sha": tree,
                    "truncated": truncated,
                    "tree": [{
                        "path": entry_path, "mode": "100644", "type": "blob", "sha": blob,
                        "size": 1
                    }]
                })))
                .mount(&server)
                .await;

            let receipt = test_github(&server)
                .search_repository_at_head(&head, repository_search_terms())
                .await;
            assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        }
    }

    #[tokio::test]
    async fn repository_search_with_zero_terms_makes_no_github_requests() {
        use crate::envelope::RepositorySearchState;

        let server = MockServer::start().await;
        let receipt = test_github(&server)
            .search_repository_at_head(&"a".repeat(40), vec![])
            .await;

        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn repository_search_budget_enforces_request_object_and_deadline_caps() {
        let mut requests = RepositorySearchBudget::new();
        for _ in 0..crate::repository_search::github_request_cap() {
            requests.charge_request().unwrap();
        }
        assert!(requests.charge_request().is_err());

        let mut objects = RepositorySearchBudget::new();
        objects
            .charge_objects(crate::repository_search::github_object_cap())
            .unwrap();
        assert!(objects.charge_objects(1).is_err());

        let mut expired = RepositorySearchBudget::new();
        expired.started_at = Instant::now() - crate::repository_search::github_aggregate_deadline();
        assert!(expired.remaining().is_err());
    }

    #[tokio::test]
    async fn repository_search_reports_rate_limit_risk_as_exhausted() {
        use crate::envelope::RepositorySearchState;

        let server = MockServer::start().await;
        let head = "a".repeat(40);
        Mock::given(method("GET"))
            .and(path(format!("/repos/owner/repo/git/commits/{head}")))
            .respond_with(ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "0"))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .search_repository_at_head(&head, repository_search_terms())
            .await;
        assert_eq!(receipt.state, RepositorySearchState::Exhausted);
    }

    #[test]
    fn repository_rate_limit_risk_distinguishes_permission_failures() {
        assert!(!github_repository_rate_limit_risk(
            reqwest::StatusCode::FORBIDDEN,
            &HeaderMap::new(),
        ));
        let mut limited = HeaderMap::new();
        limited.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        assert!(github_repository_rate_limit_risk(
            reqwest::StatusCode::OK,
            &limited,
        ));
    }

    async fn mount_current_delivery_snapshot(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"},
                "base": {"sha": "bbbbbbbbbbbb"},
                "changed_files": 1
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccccccc"},
                "files": []
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn github_receipt_separates_inline_summary_carried_resolved_and_suppressed() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let inline = publication_finding(
            "inline-1",
            "src/lib.rs",
            "The expression `time() - kube_pod_start_time > 60d` measures pod age.",
        );
        let synthetic = publication_finding(
            "summary-1",
            crate::envelope::PR_DESCRIPTION_PATH,
            "The pull request description contradicts the changed code.",
        );
        let carried = publication_finding(
            "carried-1",
            "src/old.rs",
            "[carried from previous review]\n\nAn earlier issue remains.",
        );
        let resolved = publication_finding("resolved-1", "src/fixed.rs", "Resolved issue.");
        let suppressed = publication_finding("suppressed-1", "src/noise.rs", "Suppressed issue.");
        let mut envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![inline, synthetic, carried],
        );
        envelope.resolved = vec![resolved];
        envelope.suppressed_findings = vec![SuppressedFinding {
            finding: suppressed,
            reason: SuppressionReason::BelowConfidence,
        }];

        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 77,
                "commit_id": "aaaaaaaaaaaa",
                "comments": [{
                    "id": 501,
                    "body": format!("finding\n\n{}", super::finding_marker("inline-1"))
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/77"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();

        assert_eq!(receipt.version, 2);
        assert_eq!(
            receipt.channel,
            super::super::ReviewPublicationChannel::ReviewComments
        );
        assert!(receipt.receipt_id.starts_with("github-review-v2:"));
        assert_eq!(receipt.review_id.as_deref(), Some("77"));
        let outcome = |id: &str| {
            receipt
                .findings
                .iter()
                .find(|finding| finding.finding_id == id)
                .unwrap()
        };
        assert_eq!(
            outcome("inline-1").initial_outcome,
            FindingPublicationOutcome::Inline
        );
        assert_eq!(outcome("inline-1").comment_id.as_deref(), Some("501"));
        assert_eq!(
            outcome("summary-1").initial_outcome,
            FindingPublicationOutcome::SummaryOnly
        );
        assert_eq!(
            outcome("carried-1").initial_outcome,
            FindingPublicationOutcome::Carried
        );
        assert_eq!(
            outcome("resolved-1").initial_outcome,
            FindingPublicationOutcome::Resolved
        );
        assert_eq!(
            outcome("suppressed-1").initial_outcome,
            FindingPublicationOutcome::Suppressed
        );

        let requests = server.received_requests().await.unwrap();
        let review: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method == reqwest::Method::POST)
                .unwrap()
                .body,
        )
        .unwrap();
        let initial_summary = review["body"].as_str().unwrap();
        assert!(!initial_summary.contains("posted inline"));
        let inline_body = review["comments"][0]["body"].as_str().unwrap();
        assert!(inline_body.contains("`time() - kube_pod_start_time > 60d`"));
        assert!(!inline_body.contains("&gt; 60d`"));
        let update: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method == reqwest::Method::PUT)
                .unwrap()
                .body,
        )
        .unwrap();
        let final_summary = update["body"].as_str().unwrap();
        assert!(final_summary.contains("1 finding posted inline"));
        assert!(final_summary.contains("1 finding in review details"));
        assert!(final_summary.contains("3 advisory findings"));
        assert!(final_summary.contains("1 resolved finding"));
    }

    #[tokio::test]
    async fn github_summary_update_failure_preserves_truthful_review_and_receipt() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "inline-1",
                "src/lib.rs",
                "A concrete issue.",
            )],
        );
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 79,
                "commit_id": "aaaaaaaaaaaa",
                "comments": [{
                    "id": 502,
                    "body": format!("finding\n\n{}", super::finding_marker("inline-1"))
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/79"))
            .respond_with(ResponseTemplate::new(422))
            .expect(1)
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();

        assert_eq!(receipt.review_id.as_deref(), Some("79"));
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("502"));
        let requests = server.received_requests().await.unwrap();
        let initial: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method == reqwest::Method::POST)
                .unwrap()
                .body,
        )
        .unwrap();
        assert!(!initial["body"].as_str().unwrap().contains("posted inline"));
    }

    #[tokio::test]
    async fn github_oversized_summary_falls_back_without_losing_inline_publication() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "inline-1",
                "src/lib.rs",
                "A concrete issue.",
            )],
        );
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 80,
                "commit_id": "aaaaaaaaaaaa",
                "comments": [{
                    "id": 503,
                    "body": format!("finding\n\n{}", super::finding_marker("inline-1"))
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/80"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let mut github = test_github(&server);
        github.details_url = Some(format!("https://postil.dev/{}", "x".repeat(60_000)));

        let receipt = github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();

        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("503"));
        let requests = server.received_requests().await.unwrap();
        let initial: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method == reqwest::Method::POST)
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(initial["comments"].as_array().unwrap().len(), 1);
        let body = initial["body"].as_str().unwrap();
        assert!(body.contains(super::OVERSIZED_REVIEW_MESSAGE));
        assert!(!body.contains("Review details"));
        assert!(body.contains("<!-- postil-review:v1:"));
        assert!(body.len() <= super::MAX_REVIEW_BODY_BYTES);
    }

    #[tokio::test]
    async fn github_422_receipt_records_rejected_inline_and_summary_only_fallback() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "id": 78,
                        "commit_id": "aaaaaaaaaaaa",
                        "comments": []
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "inline-1",
                "src/lib.rs",
                "A concrete issue.",
            )],
        );

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
        let finding = &receipt.findings[0];
        assert_eq!(
            finding.initial_outcome,
            FindingPublicationOutcome::SummaryOnly
        );
        assert!(finding.inline_rejected);
        assert!(finding.comment_id.is_none());

        let requests = server.received_requests().await.unwrap();
        let posts: Vec<_> = requests
            .iter()
            .filter(|request| request.method == reqwest::Method::POST)
            .collect();
        let fallback: serde_json::Value = serde_json::from_slice(&posts[1].body).unwrap();
        assert!(fallback.get("comments").is_none());
        let summary = fallback["body"].as_str().unwrap();
        assert!(summary.contains("1 finding in review details"));
        assert!(summary.contains("inline placement unavailable"));
        assert!(!summary.contains("Before the next push"));
    }

    #[tokio::test]
    async fn github_ambiguous_post_reconciles_review_and_comment_receipts() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "inline-1",
                "src/lib.rs",
                "A concrete issue.",
            )],
        );
        let planned = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        let review_marker = super::review_marker(&planned.receipt_id);
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
                    "id": 88,
                    "body": review_marker,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/88"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/88/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 601,
                    "body": super::finding_marker("inline-1")
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
        assert_eq!(receipt.review_id.as_deref(), Some("88"));
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("601"));
        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::Inline
        );
    }

    #[tokio::test]
    async fn github_receipt_marks_unobserved_inline_identity_unknown() {
        let server = MockServer::start().await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "inline-1",
                "src/lib.rs",
                "A concrete issue.",
            )],
        );
        let planned = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        let receipt = test_github(&server)
            .materialize_review_receipt(
                planned,
                super::PublishedReview {
                    id: None,
                    body: None,
                    commit_id: Some("aaaaaaaaaaaa".into()),
                    comments: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::Unknown
        );
        let summary = test_github(&server).review_summary_for_receipt(&envelope, &receipt);
        assert!(!summary.contains("posted inline"));
    }

    #[tokio::test]
    async fn github_check_completion_attempts_the_gate_after_an_advisory_patch_fails() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/repo/check-runs/11"))
            .respond_with(ResponseTemplate::new(422).set_body_string("invalid advisory patch"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/repos/owner/repo/check-runs/12"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let error = test_github(&server)
            .complete_checks(
                CheckRunIds {
                    advisory: "11",
                    gate: "12",
                },
                CheckState::Success,
                Some(CheckState::Success),
                &delivery_envelope("aaaaaaaaaaaa", "cccccccccccc"),
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                false,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("postil/review"));
        assert!(!error.to_string().contains("postil/gate"));
    }

    #[tokio::test]
    async fn github_check_completion_starts_both_patches_before_an_outer_timeout() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        Mock::given(method("PATCH"))
            .and(path_regex(r"^/repos/owner/repo/check-runs/(11|12)$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(1))
                    .set_body_json(serde_json::json!({})),
            )
            .mount(&server)
            .await;
        let github = test_github(&server);
        let envelope = delivery_envelope("aaaaaaaaaaaa", "cccccccccccc");
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            github.complete_checks(
                CheckRunIds {
                    advisory: "11",
                    gate: "12",
                },
                CheckState::Success,
                Some(CheckState::Success),
                &envelope,
                &snapshot,
                false,
            ),
        )
        .await;
        assert!(result.is_err());

        let requests = server.received_requests().await.unwrap();
        let mut patched = requests
            .iter()
            .filter(|request| request.method == reqwest::Method::PATCH)
            .map(|request| request.url.path().to_string())
            .collect::<Vec<_>>();
        patched.sort();
        assert_eq!(
            patched,
            vec![
                "/repos/owner/repo/check-runs/11",
                "/repos/owner/repo/check-runs/12"
            ]
        );
    }

    fn fenced_test_github(server: &MockServer, expected_repository_id: u64) -> GitHub {
        GitHub {
            expected_repository_id: Some(expected_repository_id),
            ..test_github(server)
        }
    }

    #[tokio::test]
    async fn github_repository_identity_fence_rejects_a_renamed_repository() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/renamed"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/issues/9/comments"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;

        let error = fenced_test_github(&server, 42)
            .post_comment_reconciled(9, "reply", "marker")
            .await
            .unwrap_err();
        assert!(crate::forge::is_repository_identity_failure(&error));
    }

    #[tokio::test]
    async fn github_repository_identity_fence_rejects_a_fork_id_for_base_publication() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/issues/9/comments"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;

        let error = fenced_test_github(&server, 99)
            .post_comment_reconciled(9, "reply", "marker")
            .await
            .unwrap_err();
        assert!(crate::forge::is_repository_identity_failure(&error));
    }

    #[tokio::test]
    async fn github_repository_identity_fence_publishes_only_for_the_same_pr_snapshot() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/compare/bbbbbbbb...aaaaaaaa"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccc"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        fenced_test_github(&server, 42)
            .post_review(
                &delivery_envelope("aaaaaaaa", "cccccccc"),
                &delivery_snapshot("aaaaaaaa", "bbbbbbbb", "cccccccc"),
            )
            .await
            .unwrap();
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
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
            expected_repository_id: None,
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
            repository_claim: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            evidence: None,
            id: None,
        };

        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]);
        let error = github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("PR snapshot changed"));
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
            repository_claim: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            evidence: None,
            id: None,
        };

        let github = test_github(&server);
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]);
        let review_error = github.post_review(&envelope, &snapshot).await.unwrap_err();
        assert!(review_error.to_string().contains("PR snapshot changed"));
        let check_error = github
            .complete_checks(
                CheckRunIds {
                    advisory: "11",
                    gate: "12",
                },
                CheckState::Success,
                Some(CheckState::Success),
                &delivery_envelope("aaaaaaaaaaaa", "cccccccccccc"),
                &snapshot,
                false,
            )
            .await
            .unwrap_err();
        assert!(check_error.to_string().contains("PR snapshot changed"));
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
            repository_claim: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            evidence: None,
            id: None,
        };
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]);
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");

        let review_error = github.post_review(&envelope, &snapshot).await.unwrap_err();
        assert!(review_error.to_string().contains("PR snapshot changed"));
        let check_error = github
            .complete_checks(
                CheckRunIds {
                    advisory: "11",
                    gate: "12",
                },
                CheckState::Success,
                Some(CheckState::Success),
                &envelope,
                &snapshot,
                false,
            )
            .await
            .unwrap_err();
        assert!(check_error.to_string().contains("PR snapshot changed"));
    }

    #[tokio::test]
    async fn github_snapshot_rejects_changed_reviewed_metadata() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "edited title", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"},
                "base": {"sha": "bbbbbbbbbbbb"},
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

        let github = test_github(&server);
        assert!(
            !github
                .snapshot_is_current(&delivery_snapshot(
                    "aaaaaaaaaaaa",
                    "bbbbbbbbbbbb",
                    "cccccccccccc",
                ))
                .await
                .unwrap()
        );
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
            expected_repository_id: None,
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
            repository_claim: None,
            title: "Finding".into(),
            body: "A concrete issue.".into(),
            evidence: None,
            id: None,
        };

        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]);
        let error = github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("PR snapshot changed"));
    }

    #[tokio::test]
    async fn github_finding_presentations_are_exclusive_and_preserve_valid_model_prose() {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 99,
                "comments": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/99/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/99"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        for id in ["11", "12", "13", "14"] {
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
            expected_repository_id: None,
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
            repository_claim: None,
            title: "Preserve the complete finding".into(),
            body: format!("{}.", "a".repeat(226)),
            evidence: Some("let vulnerable = true;".into()),
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
            repository_search: Default::default(),
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: Some("cccccccccccc".into()),
            head_sha: Some("aaaaaaaaaaaa".into()),
            since_sha: None,
        };

        github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap();
        github
            .complete_checks(
                CheckRunIds {
                    advisory: "11",
                    gate: "12",
                },
                CheckState::Failure,
                Some(CheckState::Failure),
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                false,
            )
            .await
            .unwrap();
        github
            .complete_checks(
                CheckRunIds {
                    advisory: "13",
                    gate: "14",
                },
                CheckState::Failure,
                Some(CheckState::Failure),
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                true,
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
        assert!(inline.contains(&finding.body));

        let review_comment_advisory = requests
            .iter()
            .find(|request| request.url.path().ends_with("/check-runs/11"))
            .unwrap();
        let review_comment_check_body: serde_json::Value =
            serde_json::from_slice(&review_comment_advisory.body).unwrap();
        assert!(
            review_comment_check_body["output"]
                .get("annotations")
                .is_none()
        );

        let advisory = requests
            .iter()
            .find(|request| request.url.path().ends_with("/check-runs/13"))
            .unwrap();
        let check_body: serde_json::Value = serde_json::from_slice(&advisory.body).unwrap();
        let annotation = &check_body["output"]["annotations"][0];
        let title = annotation["title"].as_str().unwrap();
        let message = annotation["message"].as_str().unwrap();
        assert_eq!(title, finding.title);
        assert_eq!(message, finding.body);
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
    fn check_external_id_links_the_hosted_run() {
        let github = GitHub {
            http: reqwest::Client::new(),
            api_base: "https://api.github.test".into(),
            details_url: Some("https://postil.dev/orgs/acme/runs/review-380".into()),
            token: "unused".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
            expected_repository_id: None,
        };
        assert_eq!(
            github.check_external_id("postil/review", "abcdef12"),
            "postil:review-380:postil/review:abcdef12"
        );
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
            repository_claim: None,
            title: "Human judgment required".into(),
            body: "Concrete compatibility concern.".into(),
            evidence: None,
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
            repository_search: Default::default(),
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
            repository_search: Default::default(),
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

    fn dedup_finding() -> Finding {
        Finding {
            path: "values.cluster.yaml".into(),
            line: 675,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Uncertainty,
            confidence: 0.6,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: None,
            title: "rgwConfig may not be a recognized field".into(),
            body: "The chart may silently ignore this block.".into(),
            evidence: None,
            id: None,
        }
    }

    fn dedup_github(server: &MockServer) -> GitHub {
        GitHub {
            http: reqwest::Client::new(),
            api_base: server.uri(),
            details_url: None,
            token: "test-token".into(),
            owner: "owner".into(),
            repo: "repo".into(),
            pr: 1,
            expected_repository_id: None,
        }
    }

    async fn mount_dedup_snapshot(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b", "state": "open", "merged": false,
                "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"},
                "changed_files": 1
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccccccc"}, "files": []
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/11/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(server)
            .await;
    }

    /// A second review of an unchanged head re-detects what the first found.
    /// Those findings are fresh, not carried, so only the marker already on the
    /// pull request can tell the run its comment is a duplicate.
    #[tokio::test]
    async fn github_does_not_repost_an_inline_comment_already_on_the_pull_request() {
        let server = MockServer::start().await;
        mount_dedup_snapshot(&server).await;
        let finding = dedup_finding();
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding.clone()]);
        let github = dedup_github(&server);
        let (finding_id, _) = finding_receipt_id(
            envelope
                .findings
                .first()
                .expect("one finding in the envelope"),
        );
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 7,
                    "body": format!("**{}**\n\n{}", finding.title, finding_marker(&finding_id)),
                }])),
            )
            .mount(&server)
            .await;
        let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let captured = posted.clone();
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |request: &wiremock::Request| {
                captured
                    .lock()
                    .expect("capture lock")
                    .push(request.body_json().expect("review body"));
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 11}))
            })
            .mount(&server)
            .await;

        github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .expect("the review still posts its summary");

        let bodies = posted.lock().expect("capture lock");
        let body = bodies.first().expect("one review posted");
        assert_eq!(
            body["comments"].as_array().map_or(0, Vec::len),
            0,
            "the duplicate inline comment is not reposted"
        );
    }

    #[tokio::test]
    async fn github_posts_an_inline_comment_the_pull_request_does_not_carry() {
        let server = MockServer::start().await;
        mount_dedup_snapshot(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 7,
                    "body": "**Some other finding**\n\n<!-- postil-finding:v1:aabbccddeeff -->",
                }])),
            )
            .mount(&server)
            .await;
        let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let captured = posted.clone();
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |request: &wiremock::Request| {
                captured
                    .lock()
                    .expect("capture lock")
                    .push(request.body_json().expect("review body"));
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 11}))
            })
            .mount(&server)
            .await;
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![dedup_finding()]);

        dedup_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .expect("review posts");

        let bodies = posted.lock().expect("capture lock");
        let body = bodies.first().expect("one review posted");
        assert_eq!(
            body["comments"].as_array().map_or(0, Vec::len),
            1,
            "an unrelated marker must not suppress a real finding"
        );
    }

    #[tokio::test]
    async fn github_publishes_normally_when_existing_comments_cannot_be_read() {
        // Dedup is an improvement on top of publication, never a gate on it.
        let server = MockServer::start().await;
        mount_dedup_snapshot(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let captured = posted.clone();
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |request: &wiremock::Request| {
                captured
                    .lock()
                    .expect("capture lock")
                    .push(request.body_json().expect("review body"));
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 11}))
            })
            .mount(&server)
            .await;
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![dedup_finding()]);

        dedup_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .expect("review posts");

        let bodies = posted.lock().expect("capture lock");
        assert_eq!(
            bodies.first().expect("one review posted")["comments"]
                .as_array()
                .map_or(0, Vec::len),
            1
        );
    }

    #[test]
    fn finding_marker_is_read_back_from_a_published_comment_body() {
        let marker = finding_marker("finding-id");
        assert_eq!(
            finding_marker_in(&format!("**Title**\n\nBody text.\n\n{marker}")),
            Some(marker)
        );
        assert_eq!(finding_marker_in("no marker here"), None);
    }
}
