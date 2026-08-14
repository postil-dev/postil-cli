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
    CheckRunIds, CheckState, FindingPublicationOutcome, FindingPublicationReceipt, Forge,
    GitHubPublicationPlan, GitHubPublicationPlanIdentity, GitHubPublicationPlanRequest, PrMeta,
    PublicationPlanActivationCondition, PublicationPlanCheckAnnotation,
    PublicationPlanCheckConclusion, PublicationPlanCheckStatus, PublicationPlanDuplicateProvenance,
    PublicationPlanFileComment, PublicationPlanFinding, PublicationPlanFindingFallback,
    PublicationPlanFindingReconciliation, PublicationPlanGateAnalysis,
    PublicationPlanGateOwnership, PublicationPlanLifecycleReceipt,
    PublicationPlanMarkerAbsenceGuard, PublicationPlanOperation,
    PublicationPlanOperationActivation, PublicationPlanOperationKind,
    PublicationPlanOperationReconciliation, PublicationPlanOperationResultField,
    PublicationPlanOperationResultReference, PublicationPlanPlacementClassification,
    PublicationPlanRepository, PublicationPlanReviewAttemptKind, PublicationPlanReviewComment,
    PublicationPlanReviewCreateOutcome, PublicationPlanReviewCreatePayload,
    PublicationPlanReviewSummaryCase, PublicationPlanSnapshot, PublicationPlanTerminalOperation,
    PublicationPlanTerminalOutcome, ReviewPublicationReceipt, ReviewPublicationSummary,
    SummaryContext, ThreadKind, check_summary, check_title, only_operational_findings,
    valid_details_url,
};
use crate::diff::{Diff, DiffIndex, DiffSnapshot, DiffSpool, WorkspaceBudget};
use crate::envelope::{Envelope, Finding, Severity};
use crate::filter;

pub const EXPECTED_REPOSITORY_ID_ENV: &str = "POSTIL_EXPECTED_GITHUB_REPO_ID";
const GITHUB_MAX_ANNOTATIONS_PER_REQUEST: usize = 50;
const FILE_LEVEL_COMMENT_MARKER: &str = "<!-- postil-placement:file -->";

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

    fn review_summary_with_unplaced_findings(
        &self,
        envelope: &Envelope,
        receipt: &ReviewPublicationReceipt,
        unplaced: &[&Finding],
    ) -> String {
        let mut summary = self.review_summary_for_receipt(envelope, receipt);
        for finding in unplaced {
            let (finding_id, _) = finding_receipt_id(finding);
            summary.push_str(&format!(
                "\n\nLocation: `{}:{}`\n\n{}",
                super::safe_code_text(&finding.path),
                finding.line,
                append_marker(
                    &super::finding_comment_body(finding, true),
                    &finding_marker(&finding_id),
                ),
            ));
        }
        summary
    }

    async fn finalize_review_summary(
        &self,
        envelope: &Envelope,
        receipt: &ReviewPublicationReceipt,
        marker: &str,
        snapshot: &PrMeta,
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
            .send_snapshot_write_retryable(
                self.request(
                    reqwest::Method::PUT,
                    self.url(&format!("/pulls/{}/reviews/{review_id}", self.pr)),
                )
                .json(&json!({ "body": body })),
                "review summary update",
                snapshot,
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
        snapshot: &PrMeta,
    ) {
        if self
            .finalize_review_summary(envelope, receipt, marker, snapshot)
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

    async fn publication_plan_repository_identity(&self) -> Result<RepositoryIdentity> {
        let response = self
            .send_retryable(
                self.request(reqwest::Method::GET, self.url("")),
                "publication-plan repository identity",
            )
            .await?;
        let identity: RepositoryIdentity = super::bounded_response_json(
            Self::check_ok(response, "publication-plan repository identity").await?,
            "GitHub publication-plan repository identity",
        )
        .await?;
        let expected_name = format!("{}/{}", self.owner, self.repo);
        ensure!(
            identity.id > 0 && identity.full_name.eq_ignore_ascii_case(&expected_name),
            "GitHub repository identity changed; refusing publication planning"
        );
        if let Some(expected_id) = self.expected_repository_id {
            ensure!(
                identity.id == expected_id,
                "GitHub repository identity changed; refusing publication planning"
            );
        }
        Ok(identity)
    }

    async fn reconcile_published_finding_markers(
        &self,
        receipt: &mut ReviewPublicationReceipt,
        envelope: &Envelope,
        head_sha: &str,
    ) -> std::collections::HashMap<String, PublishedReviewComment> {
        let published = self.published_finding_comments(head_sha).await;
        for publication in &mut receipt.findings {
            let Ok(finding) = publication_plan_finding(envelope, &publication.finding_id) else {
                continue;
            };
            let Some(comment) = finding_marker_candidates(finding)
                .iter()
                .find_map(|marker| published.get(marker))
            else {
                continue;
            };
            publication.initial_outcome = FindingPublicationOutcome::Carried;
            publication.inline_rejected = false;
            publication.comment_id = Some(comment.id.to_string());
        }
        published
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
        self.send_retryable_inner(request, what, false, None).await
    }

    async fn send_write_retryable(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response> {
        self.send_retryable_inner(request, what, true, None).await
    }

    async fn send_snapshot_write_retryable(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
        snapshot: &PrMeta,
    ) -> Result<reqwest::Response> {
        self.send_retryable_inner(request, what, true, Some(snapshot))
            .await
    }

    async fn send_retryable_inner(
        &self,
        request: reqwest::RequestBuilder,
        what: &str,
        fence_each_attempt: bool,
        expected_snapshot: Option<&PrMeta>,
    ) -> Result<reqwest::Response> {
        const RETRIES: u32 = 2;
        const TOTAL_BUDGET: Duration = Duration::from_secs(55);
        let operation_started_at = std::time::Instant::now();
        for retry in 0..=RETRIES {
            if let Some(expected_snapshot) = expected_snapshot
                && !Box::pin(self.snapshot_is_current(expected_snapshot)).await?
            {
                return Err(anyhow!(
                    "GitHub {what} skipped because the PR snapshot changed"
                ));
            }
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

    async fn find_review(
        &self,
        markers: &[String],
        head_sha: &str,
        allow_correlated_legacy_marker: bool,
    ) -> Result<Option<PublishedReview>> {
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
                    && review.body.as_deref().is_some_and(|body| {
                        markers.iter().any(|marker| body.contains(marker))
                            || (allow_correlated_legacy_marker
                                && review_marker_in(body).is_some_and(|marker| {
                                    marker.starts_with("<!-- postil-review:v1:")
                                }))
                    })
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
        snapshot: &PrMeta,
        what: &str,
    ) -> Result<ReviewDelivery> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            if !self.snapshot_is_current(snapshot).await? {
                return Err(anyhow!(
                    "GitHub review delivery skipped because the PR snapshot changed"
                ));
            }
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
                    if let Some(review) = self
                        .find_review(&[marker.to_string()], &snapshot.head_sha, false)
                        .await?
                    {
                        return Ok(ReviewDelivery::Reconciled(review));
                    }
                    if retry == RETRIES {
                        return Ok(ReviewDelivery::Response(response));
                    }
                }
                Err(error) => {
                    if let Some(review) = self
                        .find_review(&[marker.to_string()], &snapshot.head_sha, false)
                        .await?
                    {
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
            let markers = [
                finding_marker(&finding.finding_id),
                legacy_finding_marker(&finding.finding_id),
            ];
            if let Some(comment) = comments
                .iter()
                .find(|comment| markers.iter().any(|marker| comment.body.contains(marker)))
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
    async fn published_finding_comments(
        &self,
        head_sha: &str,
    ) -> std::collections::HashMap<String, PublishedReviewComment> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        let mut comments_by_marker = std::collections::HashMap::new();
        for page in 1..=MAX_PAGES {
            let request = self.request(
                reqwest::Method::GET,
                self.url(&format!(
                    "/pulls/{}/comments?per_page={PAGE_SIZE}&page={page}",
                    self.pr
                )),
            );
            let Ok(response) = self.send_retryable(request, "inline comment dedup").await else {
                return comments_by_marker;
            };
            let Ok(response) = Self::check_ok(response, "inline comment dedup").await else {
                return comments_by_marker;
            };
            let Ok(comments): Result<Vec<PublishedReviewComment>> =
                super::bounded_response_json(response, "GitHub inline comment dedup").await
            else {
                return comments_by_marker;
            };
            let page_len = comments.len();
            for comment in comments {
                if comment.commit_id.as_deref() == Some(head_sha)
                    && let Some(marker) = finding_marker_in(&comment.body)
                {
                    comments_by_marker.insert(marker, comment);
                }
            }
            if page_len < PAGE_SIZE {
                break;
            }
        }
        comments_by_marker
    }

    async fn find_review_comment(
        &self,
        marker: &str,
        head_sha: &str,
    ) -> Result<Option<PublishedReviewComment>> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 20;
        for page in 1..=MAX_PAGES {
            let response = self
                .send_retryable(
                    self.request(
                        reqwest::Method::GET,
                        self.url(&format!(
                            "/pulls/{}/comments?per_page={PAGE_SIZE}&page={page}",
                            self.pr
                        )),
                    ),
                    "file-level review comment reconciliation",
                )
                .await?;
            let comments: Vec<PublishedReviewComment> = super::bounded_response_json(
                Self::check_ok(response, "file-level review comment reconciliation").await?,
                "GitHub file-level review comment reconciliation",
            )
            .await?;
            let page_len = comments.len();
            if let Some(comment) = comments.into_iter().find(|comment| {
                comment.body.contains(marker) && comment.commit_id.as_deref() == Some(head_sha)
            }) {
                return Ok(Some(comment));
            }
            if page_len < PAGE_SIZE {
                return Ok(None);
            }
        }
        Err(anyhow!(
            "GitHub file-level review comment reconciliation exceeded {MAX_PAGES} pages"
        ))
    }

    async fn post_file_comment_reconciled(
        &self,
        body: &serde_json::Value,
        marker: &str,
        snapshot: &PrMeta,
    ) -> Result<PublishedReviewComment> {
        const RETRIES: u32 = 2;
        for retry in 0..=RETRIES {
            if !self.snapshot_is_current(snapshot).await? {
                return Err(anyhow!(
                    "GitHub file-level review comment delivery skipped because the PR snapshot changed"
                ));
            }
            self.verify_repository_identity_before_write().await?;
            let response = self
                .request(
                    reqwest::Method::POST,
                    self.url(&format!("/pulls/{}/comments", self.pr)),
                )
                .json(body)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    let comment: PublishedReviewComment =
                        super::bounded_response_json(response, "GitHub file-level review comment")
                            .await?;
                    ensure!(
                        comment.commit_id.as_deref() == Some(snapshot.head_sha.as_str()),
                        "GitHub file-level review comment response did not identify the reviewed head"
                    );
                    return Ok(comment);
                }
                Ok(response)
                    if github_retryable_response(response.status(), response.headers()) =>
                {
                    if let Some(comment) =
                        self.find_review_comment(marker, &snapshot.head_sha).await?
                    {
                        return Ok(comment);
                    }
                    if retry == RETRIES {
                        Self::check_ok(response, "file-level review comment").await?;
                    }
                }
                Ok(response) => {
                    Self::check_ok(response, "file-level review comment").await?;
                }
                Err(error) => {
                    if let Some(comment) =
                        self.find_review_comment(marker, &snapshot.head_sha).await?
                    {
                        return Ok(comment);
                    }
                    if retry == RETRIES {
                        return Err(error)
                            .context("posting file-level review comment after reconciliation");
                    }
                }
            }
            tokio::time::sleep(github_transport_retry_delay(retry)).await;
        }
        unreachable!("bounded GitHub file-level comment loop always returns")
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

    let mut failing_findings = envelope
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
        .collect::<Vec<_>>();
    failing_findings.sort_by_key(|finding| super::publication_finding_sort_key(finding));
    let failing: Vec<_> = failing_findings
        .into_iter()
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
    #[serde(default)]
    commit_id: Option<String>,
}

#[derive(Deserialize)]
struct PublishedComment {
    body: String,
}

enum ReviewDelivery {
    Response(reqwest::Response),
    Reconciled(PublishedReview),
}

#[derive(Clone, Deserialize)]
struct RepositoryIdentity {
    id: u64,
    full_name: String,
}

#[derive(Clone)]
struct PlannedCheckOutput {
    name: &'static str,
    state: CheckState,
    title: String,
    summary: String,
    annotations: Vec<PublicationPlanCheckAnnotation>,
}

fn planned_check_outputs(
    envelope: &Envelope,
    advisory: CheckState,
    gate: Option<CheckState>,
    annotate_findings: bool,
    details_url: Option<String>,
) -> Vec<PlannedCheckOutput> {
    let annotations = if annotate_findings {
        let mut findings = envelope
            .findings
            .iter()
            .filter(|finding| !filter::is_carried(finding))
            .filter(|finding| !super::is_synthetic_path(&finding.path))
            .collect::<Vec<_>>();
        findings.sort_by_key(|finding| super::publication_finding_sort_key(finding));
        findings
            .into_iter()
            .map(|finding| {
                let publication = crate::envelope::forge_safe_finding_publication_text(finding);
                PublicationPlanCheckAnnotation {
                    path: finding.path.clone(),
                    start_line: finding.line,
                    end_line: finding.end_line.unwrap_or(finding.line),
                    annotation_level: match finding.severity {
                        Severity::Info => "notice",
                        Severity::Warn => "warning",
                        Severity::Error => "failure",
                    }
                    .to_string(),
                    title: publication.title,
                    message: publication.body,
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    debug_assert!(annotations.len() <= GITHUB_MAX_ANNOTATIONS_PER_REQUEST);

    let advisory_summary = check_summary(
        envelope,
        true,
        SummaryContext {
            details_url,
            prevention_hint: false,
            prevention_commands: vec![],
            publication: None,
        },
    );
    let mut checks = vec![PlannedCheckOutput {
        name: "postil/review",
        state: advisory,
        title: super::cap_check_title(&check_title(envelope)),
        summary: super::cap_check_summary(&advisory_summary),
        annotations,
    }];
    if let Some(gate) = gate {
        checks.push(PlannedCheckOutput {
            name: "postil/gate",
            state: gate,
            title: super::cap_check_title(gate_title(envelope)),
            summary: super::cap_check_summary(&gate_summary(envelope)),
            annotations: vec![],
        });
    }
    checks
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

    async fn build_publication_plan(
        &self,
        request: GitHubPublicationPlanRequest<'_>,
    ) -> Result<GitHubPublicationPlan> {
        let GitHubPublicationPlanRequest {
            controller_generation,
            input_identity,
            envelope,
            snapshot,
            publication_diff,
            should_comment,
            duplicate_of_baseline,
            annotate_findings,
            advisory,
            gate,
        } = request;
        ensure!(
            self.snapshot_is_current(snapshot).await?,
            "GitHub publication planning skipped because the pull request snapshot changed"
        );
        let repository = self.publication_plan_repository_identity().await?;
        let target_sha = snapshot
            .target_sha
            .as_deref()
            .context("GitHub publication planning requires a target snapshot")?;
        let repository_id = repository.id.to_string();
        let pull_request_number = self.pr.to_string();
        let mut receipt = self.plan_review_publication(envelope, snapshot);
        if annotate_findings {
            receipt.channel = super::ReviewPublicationChannel::CheckAnnotations;
            for finding in &mut receipt.findings {
                if finding.initial_outcome == FindingPublicationOutcome::Inline {
                    finding.initial_outcome = FindingPublicationOutcome::CheckAnnotation;
                }
            }
        } else if duplicate_of_baseline {
            for finding in &mut receipt.findings {
                if matches!(
                    finding.initial_outcome,
                    FindingPublicationOutcome::Inline
                        | FindingPublicationOutcome::FileComment
                        | FindingPublicationOutcome::SummaryOnly
                ) {
                    finding.initial_outcome = FindingPublicationOutcome::Carried;
                }
            }
        }
        let desired_receipt = receipt.clone();
        let review_output_digest =
            publication_plan_review_output_digest(PublicationPlanReviewOutputInput {
                controller_generation,
                input_identity,
                repository_id: &repository_id,
                pull_request_number: &pull_request_number,
                snapshot,
                envelope,
                receipt: &desired_receipt,
                should_comment,
                duplicate_of_baseline,
                annotate_findings,
                advisory,
                gate,
                details_url: self.details_url.as_deref(),
            })?;
        let key_scope = PublicationPlanKeyScope {
            repository_id: &repository_id,
            pull_request_number: &pull_request_number,
            head_sha: &snapshot.head_sha,
            controller_generation,
            input_identity,
            review_output_digest: &review_output_digest,
        };
        let logical_review_identity = publication_plan_logical_review_identity(key_scope);
        let initial_review_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::InitialReviewCreate,
            None,
        );
        let relocated_review_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::RelocatedReviewCreate,
            None,
        );
        let summary_review_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::SummaryReviewCreate,
            None,
        );
        let advisory_create_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::AdvisoryCheckCreate,
            None,
        );
        let advisory_complete_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::AdvisoryCheckComplete,
            None,
        );
        let marker = review_marker(&receipt.receipt_id);
        let compatible_receipt_ids =
            legacy_planned_review_receipt_ids(envelope, &snapshot.head_sha)
                .into_iter()
                .filter(|receipt_id| receipt_id != &receipt.receipt_id)
                .collect::<Vec<_>>();
        let mut review_markers = vec![marker.clone()];
        review_markers.extend(
            compatible_receipt_ids
                .iter()
                .map(|receipt_id| legacy_review_marker(receipt_id)),
        );

        let mut initial_review_payload = None;
        let mut relocated_review_payload = None;
        let mut summary_review_payload = None;
        let mut fallback_intent =
            std::collections::HashMap::<String, Vec<PublicationPlanFindingFallback>>::new();
        let mut finding_update_operations = Vec::new();
        let mut published = std::collections::HashMap::new();
        let mut line_findings = Vec::<(&Finding, String, u32)>::new();
        let mut file_findings = Vec::<(&Finding, String)>::new();
        let mut summary_findings = Vec::<&Finding>::new();
        let mut relocated_receipt = None;
        let mut summary_receipt = None;

        if should_comment && !annotate_findings {
            published = self
                .reconcile_published_finding_markers(&mut receipt, envelope, &snapshot.head_sha)
                .await;
            let publishable_findings = publication_plan_publishable_findings(envelope, &published);
            let summary = self.review_summary_for_receipt(envelope, &receipt);
            let comments = publishable_findings
                .iter()
                .map(|finding| publication_plan_review_comment(&initial_review_comment(finding)))
                .collect::<Result<Vec<_>>>()?;
            if !comments.is_empty() || !summary.is_empty() {
                initial_review_payload = Some(PublicationPlanReviewCreatePayload {
                    commit_id: snapshot.head_sha.clone(),
                    event: "COMMENT".to_string(),
                    body: bounded_review_body(&summary, &marker, self.details_url.as_deref()),
                    comments,
                });
            }

            if !publishable_findings.is_empty() {
                let owned_publication_diff = if publication_diff.is_none() {
                    Some(
                        self.fetch_diff(snapshot)
                            .await
                            .context("fetching complete diff for GitHub publication planning")?,
                    )
                } else {
                    None
                };
                let parsed_publication_diff = owned_publication_diff
                    .as_ref()
                    .map(|diff| crate::diff::parse(diff.as_str()));
                let publication_diff = publication_diff
                    .or(parsed_publication_diff.as_ref())
                    .context(
                        "GitHub publication planning is missing the complete pull-request diff",
                    )?;
                let placement_index = DiffIndex::build(publication_diff);
                for finding in &publishable_findings {
                    let (finding_id, _) = finding_receipt_id(finding);
                    let Some(path) = publication_file_path(publication_diff, &finding.path) else {
                        fallback_intent.insert(
                            finding_id,
                            vec![PublicationPlanFindingFallback::SummaryOnly],
                        );
                        summary_findings.push(*finding);
                        continue;
                    };
                    if let Some(line) = placement_index.nearest_new_side_line(path, finding.line) {
                        fallback_intent.insert(
                            finding_id,
                            vec![
                                PublicationPlanFindingFallback::RelocatedInline,
                                PublicationPlanFindingFallback::FileComment,
                            ],
                        );
                        line_findings.push((*finding, path.to_string(), line));
                    } else {
                        fallback_intent.insert(
                            finding_id,
                            vec![PublicationPlanFindingFallback::FileComment],
                        );
                        file_findings.push((*finding, path.to_string()));
                    }
                }

                let mut fallback_receipt = receipt.clone();
                for (finding, _) in &file_findings {
                    set_publication_outcome(
                        &mut fallback_receipt,
                        finding,
                        FindingPublicationOutcome::FileComment,
                        false,
                    )?;
                }
                for finding in &summary_findings {
                    set_publication_outcome(
                        &mut fallback_receipt,
                        finding,
                        FindingPublicationOutcome::SummaryOnly,
                        true,
                    )?;
                }
                let fallback_summary = self.review_summary_with_unplaced_findings(
                    envelope,
                    &fallback_receipt,
                    &summary_findings,
                );
                let fallback_summary = if summary_findings.is_empty() {
                    bounded_review_body(
                        if fallback_summary.is_empty() {
                            "Postil completed the review."
                        } else {
                            &fallback_summary
                        },
                        &marker,
                        self.details_url.as_deref(),
                    )
                } else {
                    required_review_body(&fallback_summary, &marker)?
                };
                relocated_review_payload = Some(PublicationPlanReviewCreatePayload {
                    commit_id: snapshot.head_sha.clone(),
                    event: "COMMENT".to_string(),
                    body: fallback_summary,
                    comments: line_findings
                        .iter()
                        .map(|(finding, path, line)| {
                            publication_plan_review_comment(&fallback_line_comment(
                                finding, path, *line,
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?,
                });

                relocated_receipt = Some(fallback_receipt.clone());
                let mut file_fallback_receipt = fallback_receipt;
                for (finding, _, _) in &line_findings {
                    set_publication_outcome(
                        &mut file_fallback_receipt,
                        finding,
                        FindingPublicationOutcome::FileComment,
                        false,
                    )?;
                }
                if !line_findings.is_empty() {
                    let summary = self.review_summary_with_unplaced_findings(
                        envelope,
                        &file_fallback_receipt,
                        &summary_findings,
                    );
                    summary_review_payload = Some(PublicationPlanReviewCreatePayload {
                        commit_id: snapshot.head_sha.clone(),
                        event: "COMMENT".to_string(),
                        body: if summary_findings.is_empty() {
                            bounded_review_body(&summary, &marker, self.details_url.as_deref())
                        } else {
                            required_review_body(&summary, &marker)?
                        },
                        comments: vec![],
                    });
                }
                summary_receipt = Some(file_fallback_receipt);
            }
        }

        let observed_review_id = if should_comment && !annotate_findings {
            let has_correlated_finding = receipt
                .findings
                .iter()
                .any(|finding| finding.comment_id.is_some());
            let observed_review = self
                .find_review(&review_markers, &snapshot.head_sha, has_correlated_finding)
                .await?;
            if let Some(observed_marker) = observed_review
                .as_ref()
                .and_then(|review| review.body.as_deref())
                .and_then(review_marker_in)
                && !review_markers.contains(&observed_marker)
            {
                review_markers.push(observed_marker);
            }
            observed_review.and_then(|review| review.id.map(|id| id.to_string()))
        } else {
            None
        };
        receipt.review_id.clone_from(&observed_review_id);

        let line_placements = line_findings
            .iter()
            .map(|(finding, path, line)| (finding_receipt_id(finding).0, (path.as_str(), *line)))
            .collect::<std::collections::HashMap<_, _>>();
        let file_placements = file_findings
            .iter()
            .map(|(finding, path)| (finding_receipt_id(finding).0, path.as_str()))
            .chain(
                line_findings
                    .iter()
                    .map(|(finding, path, _)| (finding_receipt_id(finding).0, path.as_str())),
            )
            .collect::<std::collections::HashMap<_, _>>();
        let findings = receipt
            .findings
            .iter()
            .map(|publication| {
                let finding = publication_plan_finding(envelope, &publication.finding_id)?;
                let desired_core = super::finding_comment_body(finding, true);
                let current_marker = finding_marker(&publication.finding_id);
                let desired_body = append_marker(&desired_core, &current_marker);
                let mut desired_bodies = vec![desired_body.clone()];
                if let Some((path, line)) = line_placements.get(&publication.finding_id) {
                    desired_bodies.push(
                        fallback_line_comment(finding, path, *line)["body"]
                            .as_str()
                            .context("GitHub relocated finding plan omitted its body")?
                            .to_string(),
                    );
                }
                if let Some(path) = file_placements.get(&publication.finding_id) {
                    desired_bodies.push(
                        file_level_comment(finding, path, &snapshot.head_sha)["body"]
                            .as_str()
                            .context("GitHub file finding plan omitted its body")?
                            .to_string(),
                    );
                }
                let observed = published_comment_for_finding(&published, finding);
                let observed_matches = observed.is_some_and(|comment| {
                    desired_bodies.iter().any(|desired| {
                        without_finding_marker(&comment.body) == without_finding_marker(desired)
                    })
                });
                let desired_initial_outcome = desired_receipt
                    .findings
                    .iter()
                    .find(|desired| desired.finding_id == publication.finding_id)
                    .map(|desired| desired.initial_outcome)
                    .context("GitHub lifecycle receipt omitted its desired finding outcome")?;
                let suppression_reason = envelope
                    .suppressed_findings
                    .iter()
                    .find(|suppressed| {
                        finding_receipt_id(&suppressed.finding).0 == publication.finding_id
                    })
                    .map(|suppressed| suppressed.reason);
                let duplicate_provenance = if suppression_reason
                    == Some(crate::envelope::SuppressionReason::DuplicateRootCause)
                {
                    PublicationPlanDuplicateProvenance::SuppressedRootCause
                } else if duplicate_of_baseline
                    && matches!(
                        desired_initial_outcome,
                        FindingPublicationOutcome::Carried
                            | FindingPublicationOutcome::Inline
                            | FindingPublicationOutcome::SummaryOnly
                    )
                {
                    PublicationPlanDuplicateProvenance::Baseline
                } else {
                    PublicationPlanDuplicateProvenance::None
                };
                let reconciliation = if observed_matches {
                    PublicationPlanFindingReconciliation::Retain
                } else if observed.is_some() {
                    PublicationPlanFindingReconciliation::Replace
                } else if should_comment
                    && !annotate_findings
                    && desired_initial_outcome == FindingPublicationOutcome::Inline
                {
                    PublicationPlanFindingReconciliation::Create
                } else {
                    PublicationPlanFindingReconciliation::Omit
                };
                if reconciliation == PublicationPlanFindingReconciliation::Replace {
                    let observed = observed
                        .context("GitHub finding replacement omitted its observed comment")?;
                    let replacement_body = if observed.body.contains(FILE_LEVEL_COMMENT_MARKER) {
                        let path = file_placements
                            .get(&publication.finding_id)
                            .copied()
                            .unwrap_or(finding.path.as_str());
                        file_level_comment(finding, path, &snapshot.head_sha)["body"]
                            .as_str()
                            .context("GitHub file finding replacement omitted its body")?
                            .to_string()
                    } else if let Some((path, line)) = line_placements.get(&publication.finding_id)
                    {
                        fallback_line_comment(finding, path, *line)["body"]
                            .as_str()
                            .context("GitHub relocated finding replacement omitted its body")?
                            .to_string()
                    } else {
                        desired_body.clone()
                    };
                    let operation_key = publication_plan_operation_key(
                        key_scope,
                        PublicationPlanOperationKeyKind::FindingCommentUpdate,
                        Some(&publication.finding_id),
                    );
                    let expected_markers = finding_marker_candidates(finding);
                    finding_update_operations.push(PublicationPlanOperation::new(
                        0,
                        operation_key.clone(),
                        vec![],
                        PublicationPlanOperationActivation {
                            any_of: vec![
                                PublicationPlanActivationCondition::FindingContentDiffers {
                                    observed_comment_id: observed.id.to_string(),
                                    expected_markers: expected_markers.clone(),
                                },
                            ],
                        },
                        PublicationPlanOperationReconciliation {
                            logical_identity: operation_key,
                            markers: expected_markers.clone(),
                            observed_remote_id: Some(observed.id.to_string()),
                            exclusive: true,
                        },
                        PublicationPlanOperationKind::FindingCommentUpdate {
                            finding_id: publication.finding_id.clone(),
                            observed_comment_id: observed.id.to_string(),
                            expected_markers,
                            body_sha256: publication_plan_body_digest(&replacement_body),
                            body: replacement_body,
                        },
                    )?);
                }
                let compatible_markers = finding_marker_candidates(finding)
                    .into_iter()
                    .filter(|candidate| candidate != &current_marker)
                    .collect();
                Ok(PublicationPlanFinding {
                    finding_id: publication.finding_id.clone(),
                    stable_identity: publication.stable_identity,
                    path: finding.path.clone(),
                    line: finding.line,
                    end_line: finding.end_line,
                    initial_outcome: desired_initial_outcome,
                    fallback_intent: fallback_intent
                        .get(&publication.finding_id)
                        .cloned()
                        .unwrap_or_default(),
                    content_digest: publication_plan_finding_content_digest(finding),
                    marker: current_marker,
                    compatible_markers,
                    desired_body_sha256: publication_plan_body_digest(&desired_body),
                    desired_body,
                    observed_comment_id: observed.map(|comment| comment.id.to_string()),
                    observed_body_sha256: observed
                        .map(|comment| publication_plan_body_digest(&comment.body)),
                    observed_outcome: observed.map(|comment| {
                        if comment.body.contains(FILE_LEVEL_COMMENT_MARKER) {
                            FindingPublicationOutcome::FileComment
                        } else {
                            desired_initial_outcome
                        }
                    }),
                    reconciliation,
                    suppression_reason,
                    duplicate_provenance,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let lifecycle_receipt = PublicationPlanLifecycleReceipt::new(
            input_identity.to_string(),
            receipt.channel,
            receipt.receipt_id.clone(),
            compatible_receipt_ids,
            observed_review_id,
            duplicate_of_baseline,
            findings.clone(),
        )?;

        let review_guard = PublicationPlanMarkerAbsenceGuard {
            markers: review_markers.clone(),
            head_sha: snapshot.head_sha.clone(),
            required: true,
        };
        let review_reconciliation = || PublicationPlanOperationReconciliation {
            logical_identity: logical_review_identity.clone(),
            markers: review_markers.clone(),
            observed_remote_id: receipt.review_id.clone(),
            exclusive: true,
        };
        let advisory_external_id = self.check_external_id("postil/review", &snapshot.head_sha);
        let mut operations = vec![PublicationPlanOperation::new(
            0,
            advisory_create_operation_key.clone(),
            vec![],
            PublicationPlanOperationActivation {
                any_of: vec![PublicationPlanActivationCondition::Always],
            },
            PublicationPlanOperationReconciliation {
                logical_identity: advisory_external_id.clone(),
                markers: vec![],
                observed_remote_id: None,
                exclusive: true,
            },
            PublicationPlanOperationKind::AdvisoryCheckCreate {
                name: "postil/review".to_string(),
                head_sha: snapshot.head_sha.clone(),
                status: PublicationPlanCheckStatus::InProgress,
                external_id: advisory_external_id,
                details_url: self.details_url.clone(),
            },
        )?];
        let mut review_operation_keys = Vec::new();
        if let Some(payload) = initial_review_payload {
            operations.push(PublicationPlanOperation::new(
                0,
                initial_review_operation_key.clone(),
                vec![],
                PublicationPlanOperationActivation {
                    any_of: vec![PublicationPlanActivationCondition::MarkerAbsent {
                        guard: review_guard.clone(),
                    }],
                },
                review_reconciliation(),
                PublicationPlanOperationKind::ReviewCreate {
                    attempt: PublicationPlanReviewAttemptKind::Initial,
                    logical_review_identity: logical_review_identity.clone(),
                    payload,
                },
            )?);
            review_operation_keys.push(initial_review_operation_key.clone());
        }
        if let Some(payload) = relocated_review_payload {
            operations.push(PublicationPlanOperation::new(
                0,
                relocated_review_operation_key.clone(),
                vec![initial_review_operation_key.clone()],
                PublicationPlanOperationActivation {
                    any_of: vec![PublicationPlanActivationCondition::SemanticPlacementRejected {
                        dependency_operation_key: initial_review_operation_key.clone(),
                        http_status: 422,
                        classification:
                            PublicationPlanPlacementClassification::InvalidReviewCommentPlacement,
                        marker_absence: review_guard.clone(),
                    }],
                },
                review_reconciliation(),
                PublicationPlanOperationKind::ReviewCreate {
                    attempt: PublicationPlanReviewAttemptKind::RelocatedInline,
                    logical_review_identity: logical_review_identity.clone(),
                    payload,
                },
            )?);
            review_operation_keys.push(relocated_review_operation_key.clone());
        }
        if let Some(payload) = summary_review_payload {
            operations.push(PublicationPlanOperation::new(
                0,
                summary_review_operation_key.clone(),
                vec![relocated_review_operation_key.clone()],
                PublicationPlanOperationActivation {
                    any_of: vec![PublicationPlanActivationCondition::SemanticPlacementRejected {
                        dependency_operation_key: relocated_review_operation_key.clone(),
                        http_status: 422,
                        classification:
                            PublicationPlanPlacementClassification::InvalidReviewCommentPlacement,
                        marker_absence: review_guard.clone(),
                    }],
                },
                review_reconciliation(),
                PublicationPlanOperationKind::ReviewCreate {
                    attempt: PublicationPlanReviewAttemptKind::SummaryOnly,
                    logical_review_identity: logical_review_identity.clone(),
                    payload,
                },
            )?);
            review_operation_keys.push(summary_review_operation_key.clone());
        }

        finding_update_operations.sort_by(|left, right| {
            publication_plan_operation_finding_id(left)
                .cmp(&publication_plan_operation_finding_id(right))
        });
        let finding_update_keys = finding_update_operations
            .iter()
            .filter_map(|operation| match &operation.desired {
                PublicationPlanOperationKind::FindingCommentUpdate { .. } => {
                    Some(operation.operation_key.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let mut fallback_findings = file_findings
            .iter()
            .map(|(finding, path)| (*finding, path.clone(), false))
            .chain(
                line_findings
                    .iter()
                    .map(|(finding, path, _)| (*finding, path.clone(), true)),
            )
            .collect::<Vec<_>>();
        fallback_findings
            .sort_by_key(|(finding, _, _)| super::publication_finding_sort_key(finding));
        let mut file_operation_metadata = Vec::new();
        for (finding, path, relocated) in fallback_findings {
            let (finding_id, _) = finding_receipt_id(finding);
            let operation_key = publication_plan_operation_key(
                key_scope,
                PublicationPlanOperationKeyKind::FileCommentFallback,
                Some(&finding_id),
            );
            let finding_markers = finding_marker_candidates(finding);
            let marker_absence = PublicationPlanMarkerAbsenceGuard {
                markers: finding_markers.clone(),
                head_sha: snapshot.head_sha.clone(),
                required: true,
            };
            let semantic_dependency = if relocated {
                relocated_review_operation_key.clone()
            } else {
                initial_review_operation_key.clone()
            };
            let mut activation = vec![
                PublicationPlanActivationCondition::SemanticPlacementRejected {
                    dependency_operation_key: semantic_dependency.clone(),
                    http_status: 422,
                    classification:
                        PublicationPlanPlacementClassification::InvalidReviewCommentPlacement,
                    marker_absence: marker_absence.clone(),
                },
                PublicationPlanActivationCondition::PartialReviewObserved {
                    dependency_operation_key: initial_review_operation_key.clone(),
                    review_markers: review_markers.clone(),
                    finding_marker_absence: marker_absence.clone(),
                },
            ];
            let mut dependencies = vec![initial_review_operation_key.clone()];
            if relocated {
                activation.push(PublicationPlanActivationCondition::PartialReviewObserved {
                    dependency_operation_key: relocated_review_operation_key.clone(),
                    review_markers: review_markers.clone(),
                    finding_marker_absence: marker_absence.clone(),
                });
                dependencies.push(relocated_review_operation_key.clone());
            }
            let payload = publication_plan_file_comment(&file_level_comment(
                finding,
                &path,
                &snapshot.head_sha,
            ))?;
            operations.push(PublicationPlanOperation::new(
                0,
                operation_key.clone(),
                dependencies,
                PublicationPlanOperationActivation { any_of: activation },
                PublicationPlanOperationReconciliation {
                    logical_identity: operation_key.clone(),
                    markers: finding_markers,
                    observed_remote_id: None,
                    exclusive: true,
                },
                PublicationPlanOperationKind::FileCommentFallback {
                    finding_id: finding_id.clone(),
                    payload,
                },
            )?);
            file_operation_metadata.push((finding_id, relocated, operation_key));
        }
        operations.append(&mut finding_update_operations);

        let mut terminal_operations = file_operation_metadata
            .iter()
            .map(
                |(finding_id, _, operation_key)| PublicationPlanTerminalOperation {
                    operation_key: operation_key.clone(),
                    finding_id: Some(finding_id.clone()),
                    requires_remote_id: true,
                    accepted_outcomes: vec![
                        PublicationPlanTerminalOutcome::Applied,
                        PublicationPlanTerminalOutcome::ReconciledExisting,
                        PublicationPlanTerminalOutcome::NotRequiredMarkerPresent,
                    ],
                },
            )
            .collect::<Vec<_>>();
        terminal_operations.extend(finding_update_keys.iter().map(|operation_key| {
            PublicationPlanTerminalOperation {
                operation_key: operation_key.clone(),
                finding_id: operations
                    .iter()
                    .find(|operation| operation.operation_key == *operation_key)
                    .and_then(publication_plan_operation_finding_id)
                    .map(str::to_string),
                requires_remote_id: true,
                accepted_outcomes: vec![
                    PublicationPlanTerminalOutcome::Applied,
                    PublicationPlanTerminalOutcome::ReconciledExisting,
                ],
            }
        }));
        let mut summary_cases = Vec::new();
        let mut add_summary_cases =
            |selected_review_operation_key: &str,
             base_receipt: &ReviewPublicationReceipt,
             variable_file_ids: &[String],
             required_file_ids: &[String]| {
                for variable_count in 0..=variable_file_ids.len() {
                    let mut candidate = base_receipt.clone();
                    for (finding_id, _, _) in &file_operation_metadata {
                        let applied = required_file_ids.contains(finding_id)
                            || variable_file_ids
                                .iter()
                                .take(variable_count)
                                .any(|candidate| candidate == finding_id);
                        if let Some(publication) = candidate
                            .findings
                            .iter_mut()
                            .find(|publication| publication.finding_id == *finding_id)
                        {
                            publication.initial_outcome = if applied {
                                FindingPublicationOutcome::FileComment
                            } else {
                                FindingPublicationOutcome::Inline
                            };
                        }
                    }
                    for finding in &mut candidate.findings {
                        if matches!(
                            finding.initial_outcome,
                            FindingPublicationOutcome::Inline
                                | FindingPublicationOutcome::FileComment
                        ) && finding.comment_id.is_none()
                        {
                            finding.comment_id = Some("required".to_string());
                        }
                    }
                    let selected_review_outcomes = if variable_count == 0 {
                        vec![
                            PublicationPlanReviewCreateOutcome::Created,
                            PublicationPlanReviewCreateOutcome::ReconciledExisting,
                        ]
                    } else {
                        vec![PublicationPlanReviewCreateOutcome::PartialObserved]
                    };
                    summary_cases.push(PublicationPlanReviewSummaryCase {
                        selected_review_operation_key: selected_review_operation_key.to_string(),
                        selected_review_outcomes,
                        file_comment_count: u32::try_from(required_file_ids.len() + variable_count)
                            .expect("bounded finding count fits in u32"),
                        body: bounded_review_body(
                            &self.review_summary_for_receipt(envelope, &candidate),
                            &marker,
                            self.details_url.as_deref(),
                        ),
                    });
                }
            };
        let all_file_ids = file_operation_metadata
            .iter()
            .map(|(finding_id, _, _)| finding_id.clone())
            .collect::<Vec<_>>();
        let relocated_file_ids = file_operation_metadata
            .iter()
            .filter(|(_, relocated, _)| *relocated)
            .map(|(finding_id, _, _)| finding_id.clone())
            .collect::<Vec<_>>();
        let direct_file_ids = file_operation_metadata
            .iter()
            .filter(|(_, relocated, _)| !*relocated)
            .map(|(finding_id, _, _)| finding_id.clone())
            .collect::<Vec<_>>();
        if review_operation_keys.contains(&initial_review_operation_key) {
            add_summary_cases(&initial_review_operation_key, &receipt, &all_file_ids, &[]);
        }
        if review_operation_keys.contains(&relocated_review_operation_key)
            && let Some(base_receipt) = relocated_receipt.as_ref()
        {
            add_summary_cases(
                &relocated_review_operation_key,
                base_receipt,
                &relocated_file_ids,
                &direct_file_ids,
            );
        }
        if review_operation_keys.contains(&summary_review_operation_key)
            && let Some(base_receipt) = summary_receipt.as_ref()
        {
            add_summary_cases(
                &summary_review_operation_key,
                base_receipt,
                &[],
                &all_file_ids,
            );
        }
        let summary_update_operation_key = publication_plan_operation_key(
            key_scope,
            PublicationPlanOperationKeyKind::ReviewSummaryUpdate,
            None,
        );
        let mut summary_update_emitted = false;
        if !summary_cases.is_empty() {
            let mut dependencies = review_operation_keys.clone();
            dependencies.extend(
                file_operation_metadata
                    .iter()
                    .map(|(_, _, operation_key)| operation_key.clone()),
            );
            dependencies.extend(finding_update_keys.clone());
            dependencies.sort();
            dependencies.dedup();
            operations.push(PublicationPlanOperation::new(
                0,
                summary_update_operation_key.clone(),
                dependencies,
                PublicationPlanOperationActivation {
                    any_of: vec![
                        PublicationPlanActivationCondition::ReviewSelectionTerminal {
                            selected_review_operation_keys: review_operation_keys.clone(),
                        },
                    ],
                },
                review_reconciliation(),
                PublicationPlanOperationKind::ReviewSummaryUpdate {
                    logical_review_identity: logical_review_identity.clone(),
                    terminal_operations,
                    cases: summary_cases,
                },
            )?);
            summary_update_emitted = true;
        }
        let checks = planned_check_outputs(
            envelope,
            advisory,
            Some(gate),
            annotate_findings,
            self.details_url.clone(),
        );
        let advisory_check = checks
            .iter()
            .find(|check| check.name == "postil/review")
            .context("GitHub publication planning omitted advisory analysis")?;
        let advisory_dependencies = publication_plan_advisory_completion_dependencies(
            &operations,
            &advisory_create_operation_key,
            summary_update_emitted.then_some(summary_update_operation_key.as_str()),
        );
        operations.push(PublicationPlanOperation::new(
            0,
            advisory_complete_operation_key.clone(),
            advisory_dependencies,
            PublicationPlanOperationActivation {
                any_of: vec![PublicationPlanActivationCondition::Always],
            },
            PublicationPlanOperationReconciliation {
                logical_identity: advisory_complete_operation_key,
                markers: vec![],
                observed_remote_id: None,
                exclusive: true,
            },
            PublicationPlanOperationKind::AdvisoryCheckComplete {
                name: advisory_check.name.to_string(),
                head_sha: snapshot.head_sha.clone(),
                created_check: PublicationPlanOperationResultReference {
                    dependency_operation_key: advisory_create_operation_key,
                    result_field: PublicationPlanOperationResultField::RemoteId,
                },
                conclusion: PublicationPlanCheckConclusion::from(advisory_check.state),
                title: advisory_check.title.clone(),
                summary: advisory_check.summary.clone(),
                annotations: advisory_check.annotations.clone(),
                details_url: self.details_url.clone(),
            },
        )?);
        for (index, operation) in operations.iter_mut().enumerate() {
            operation.ordinal = u32::try_from(index + 1)
                .context("GitHub publication plan operation ordinal overflowed")?;
        }
        let gate_check = checks
            .iter()
            .find(|check| check.name == "postil/gate")
            .context("GitHub publication planning omitted gate analysis")?;
        let gate_analysis = PublicationPlanGateAnalysis {
            ownership: PublicationPlanGateOwnership::Service,
            authoritative: false,
            organization_gate_mode_required: true,
            name: gate_check.name.to_string(),
            head_sha: snapshot.head_sha.clone(),
            analyzed_conclusion: PublicationPlanCheckConclusion::from(gate_check.state),
            title: gate_check.title.clone(),
            summary: gate_check.summary.clone(),
            details_url: self.details_url.clone(),
        };

        GitHubPublicationPlan::new(
            GitHubPublicationPlanIdentity {
                controller_generation: controller_generation.to_string(),
                input_identity: input_identity.to_string(),
                review_output_digest,
                repository: PublicationPlanRepository {
                    id: repository_id,
                    full_name: repository.full_name,
                },
                pull_request_number,
                reviewed_snapshot: PublicationPlanSnapshot {
                    head_sha: snapshot.head_sha.clone(),
                    merge_base_sha: snapshot.base_sha.clone(),
                    target_sha: target_sha.to_string(),
                    pull_request_title_sha256: publication_plan_text_digest(&snapshot.title),
                    pull_request_body_sha256: publication_plan_text_digest(&snapshot.body),
                },
            },
            lifecycle_receipt,
            operations,
            gate_analysis,
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
        envelope: &Envelope,
        snapshot: &PrMeta,
        publication_diff: Option<&Diff>,
    ) -> Result<ReviewPublicationReceipt> {
        let findings = &envelope.findings;
        let head_sha = snapshot.head_sha.as_str();
        let mut planned_receipt = self.plan_review_publication(envelope, snapshot);
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
        let published = self
            .reconcile_published_finding_markers(&mut planned_receipt, envelope, head_sha)
            .await;
        let observed_comment_count = planned_receipt
            .findings
            .iter()
            .filter(|publication| {
                publication.initial_outcome == FindingPublicationOutcome::Carried
                    && publication.comment_id.is_some()
            })
            .count();
        let publishable_findings = publication_plan_publishable_findings(envelope, &published);
        let comments: Vec<_> = publishable_findings
            .iter()
            .map(|finding| initial_review_comment(finding))
            .collect();
        let summary = self.review_summary_for_receipt(envelope, &planned_receipt);
        if comments.is_empty() && summary.is_empty() {
            return Ok(planned_receipt);
        }
        let marker = review_marker(&planned_receipt.receipt_id);
        let mut review_markers = vec![marker.clone()];
        review_markers.extend(
            legacy_planned_review_receipt_ids(envelope, head_sha)
                .iter()
                .map(|receipt_id| legacy_review_marker(receipt_id)),
        );
        let has_new_summary_finding = findings
            .iter()
            .any(|finding| !filter::is_carried(finding) && super::is_synthetic_path(&finding.path));
        let all_comments_already_published = observed_comment_count > 0
            && publishable_findings.is_empty()
            && !has_new_summary_finding;
        if publishable_findings.is_empty()
            && all_comments_already_published
            && let Some(review) = self
                .find_review(&review_markers, head_sha, observed_comment_count > 0)
                .await?
        {
            planned_receipt.review_id = review.id.map(|id| id.to_string());
            self.finalize_review_summary_if_possible(envelope, &planned_receipt, &marker, snapshot)
                .await;
            return Ok(planned_receipt);
        }
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
            .send_review_reconciled(&body, &marker, snapshot, "review post")
            .await?;
        let mut recovered_partial_review = None;
        let response = match delivery {
            ReviewDelivery::Reconciled(review) => {
                let receipt = self
                    .materialize_review_receipt(planned_receipt.clone(), review.clone())
                    .await?;
                if receipt_covers_findings(&receipt, &publishable_findings) {
                    if has_planned_inline {
                        self.finalize_review_summary_if_possible(
                            envelope, &receipt, &marker, snapshot,
                        )
                        .await;
                    }
                    return Ok(receipt);
                }
                recovered_partial_review = Some(review);
                None
            }
            ReviewDelivery::Response(response) if response.status().is_success() => {
                let review: PublishedReview =
                    super::bounded_response_json(response, "GitHub published review").await?;
                let receipt = self
                    .materialize_review_receipt(planned_receipt.clone(), review.clone())
                    .await?;
                if receipt_covers_findings(&receipt, &publishable_findings) {
                    if has_planned_inline {
                        self.finalize_review_summary_if_possible(
                            envelope, &receipt, &marker, snapshot,
                        )
                        .await;
                    }
                    return Ok(receipt);
                }
                recovered_partial_review = Some(review);
                None
            }
            ReviewDelivery::Response(response) => Some(response),
        };
        if let Some(resp) = response {
            let status = resp.status();
            let request_id =
                github_request_id(resp.headers()).unwrap_or_else(|| "none".to_string());
            if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
                return Err(anyhow!(
                    "GitHub review post failed: {status} (request id {request_id})"
                ));
            }

            let rejection_body =
                super::bounded_response_text(resp, "GitHub rejected review").await?;
            if !github_review_rejected_line(&rejection_body) {
                return Err(anyhow!(
                    "GitHub review post failed validation: {status} (request id {request_id})"
                ));
            }

            eprintln!(
                "postil: github operation=review-post status=422 category=unresolved-line request_id={} recovery=placement-ladder",
                request_id,
            );
        } else {
            eprintln!(
                "postil: github operation=review-reconciliation status=partial recovery=placement-ladder"
            );
        }

        let owned_publication_diff = if publication_diff.is_none() {
            let snapshot = self
                .fetch_diff(snapshot)
                .await
                .context("fetching complete diff for GitHub placement fallback")?;
            Some(crate::diff::parse(snapshot.as_str()))
        } else {
            None
        };
        let publication_diff = publication_diff
            .or(owned_publication_diff.as_ref())
            .context("GitHub placement fallback is missing the complete pull-request diff")?;
        let placement_index = DiffIndex::build(publication_diff);
        let mut line_findings = Vec::new();
        let mut file_findings = Vec::new();
        let mut summary_findings = Vec::new();
        for finding in &publishable_findings {
            let Some(path) = publication_file_path(publication_diff, &finding.path) else {
                summary_findings.push(*finding);
                continue;
            };
            if let Some(line) = placement_index.nearest_new_side_line(path, finding.line) {
                line_findings.push((*finding, path, line));
            } else {
                file_findings.push((*finding, path));
            }
        }

        let mut fallback_receipt = planned_receipt;
        for (finding, _) in &file_findings {
            set_publication_outcome(
                &mut fallback_receipt,
                finding,
                FindingPublicationOutcome::FileComment,
                false,
            )?;
        }
        for finding in &summary_findings {
            set_publication_outcome(
                &mut fallback_receipt,
                finding,
                FindingPublicationOutcome::SummaryOnly,
                true,
            )?;
        }
        let fallback_summary = self.review_summary_with_unplaced_findings(
            envelope,
            &fallback_receipt,
            &summary_findings,
        );
        let fallback_summary = if summary_findings.is_empty() {
            bounded_review_body(
                if fallback_summary.is_empty() {
                    "Postil completed the review."
                } else {
                    &fallback_summary
                },
                &marker,
                self.details_url.as_deref(),
            )
        } else {
            required_review_body(&fallback_summary, &marker)?
        };
        let mut fallback_body = json!({
            "commit_id": head_sha,
            "event": "COMMENT",
            "body": fallback_summary,
        });
        if !line_findings.is_empty() {
            fallback_body["comments"] = json!(
                line_findings
                    .iter()
                    .map(|(finding, path, line)| fallback_line_comment(finding, path, *line))
                    .collect::<Vec<_>>()
            );
        }
        let fallback = if let Some(review) = recovered_partial_review {
            ReviewDelivery::Reconciled(review)
        } else {
            match self
                .find_review(&review_markers, head_sha, observed_comment_count > 0)
                .await?
            {
                Some(review) => ReviewDelivery::Reconciled(review),
                None => {
                    self.send_review_reconciled(
                        &fallback_body,
                        &marker,
                        snapshot,
                        "placement fallback review post",
                    )
                    .await?
                }
            }
        };
        let mut receipt = match fallback {
            ReviewDelivery::Reconciled(review) => Some(
                self.materialize_review_receipt(fallback_receipt.clone(), review)
                    .await?,
            ),
            ReviewDelivery::Response(response) if response.status().is_success() => {
                let review: PublishedReview =
                    super::bounded_response_json(response, "GitHub placement fallback review")
                        .await?;
                Some(
                    self.materialize_review_receipt(fallback_receipt.clone(), review)
                        .await?,
                )
            }
            ReviewDelivery::Response(response) => {
                let status = response.status();
                let request_id =
                    github_request_id(response.headers()).unwrap_or_else(|| "none".to_string());
                let body =
                    super::bounded_response_text(response, "GitHub rejected fallback review")
                        .await?;
                if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
                    && !line_findings.is_empty()
                    && github_review_rejected_line(&body)
                {
                    eprintln!(
                        "postil: github operation=placement-fallback status=422 category=unresolved-line request_id={} recovery=file-comments",
                        request_id,
                    );
                    None
                } else {
                    return Err(anyhow!(
                        "GitHub placement fallback review failed: {status} (request id {request_id})"
                    ));
                }
            }
        };

        if let Some(materialized) = receipt.as_mut() {
            for (finding, path, _) in line_findings.drain(..) {
                if receipt_has_finding_comment(materialized, finding) {
                    continue;
                }
                set_publication_outcome(
                    materialized,
                    finding,
                    FindingPublicationOutcome::FileComment,
                    false,
                )?;
                file_findings.push((finding, path));
            }
        }

        if receipt.is_none() {
            for (finding, path, _) in line_findings.drain(..) {
                set_publication_outcome(
                    &mut fallback_receipt,
                    finding,
                    FindingPublicationOutcome::FileComment,
                    false,
                )?;
                file_findings.push((finding, path));
            }
            let fallback_summary = self.review_summary_with_unplaced_findings(
                envelope,
                &fallback_receipt,
                &summary_findings,
            );
            let fallback_summary = if summary_findings.is_empty() {
                bounded_review_body(&fallback_summary, &marker, self.details_url.as_deref())
            } else {
                required_review_body(&fallback_summary, &marker)?
            };
            let summary_body = json!({
                "commit_id": head_sha,
                "event": "COMMENT",
                "body": fallback_summary,
            });
            let delivery = self
                .send_review_reconciled(
                    &summary_body,
                    &marker,
                    snapshot,
                    "file-comment fallback review post",
                )
                .await?;
            let materialized = match delivery {
                ReviewDelivery::Reconciled(review) => {
                    self.materialize_review_receipt(fallback_receipt.clone(), review)
                        .await?
                }
                ReviewDelivery::Response(response) => {
                    let response =
                        Self::check_ok(response, "file-comment fallback review post").await?;
                    let review: PublishedReview = super::bounded_response_json(
                        response,
                        "GitHub file-comment fallback review",
                    )
                    .await?;
                    self.materialize_review_receipt(fallback_receipt.clone(), review)
                        .await?
                }
            };
            receipt = Some(materialized);
        }

        let mut receipt = receipt.context("GitHub placement fallback omitted its receipt")?;
        super::write_review_publication_receipt_from_env(&durable_partial_receipt(&receipt))?;
        for (finding, path) in file_findings {
            let (finding_id, _) = finding_receipt_id(finding);
            let finding_marker = finding_marker(&finding_id);
            let payload = file_level_comment(finding, path, head_sha);
            let comment = self
                .post_file_comment_reconciled(&payload, &finding_marker, snapshot)
                .await?;
            let publication = receipt
                .findings
                .iter_mut()
                .find(|publication| publication.finding_id == finding_id)
                .context("GitHub file-level comment omitted its publication receipt")?;
            publication.initial_outcome = FindingPublicationOutcome::FileComment;
            publication.inline_rejected = false;
            publication.comment_id = Some(comment.id.to_string());
            super::write_review_publication_receipt_from_env(&durable_partial_receipt(&receipt))?;
        }
        self.finalize_review_summary_if_possible(envelope, &receipt, &marker, snapshot)
            .await;
        Ok(receipt)
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
        let checks = planned_check_outputs(
            envelope,
            advisory,
            gate,
            annotate_findings,
            self.details_url.clone(),
        );
        let mut results = stream::iter(checks.into_iter().enumerate().map(
            |(index, planned)| async move {
                let id = if planned.name == "postil/review" {
                    check_ids.advisory
                } else {
                    check_ids.gate
                };
                let mut output = json!({
                    "title": planned.title,
                    "summary": planned.summary,
                });
                if !planned.annotations.is_empty() {
                    output["annotations"] = json!(
                        planned
                            .annotations
                            .iter()
                            .map(|annotation| json!({
                                "path": annotation.path,
                                "start_line": annotation.start_line,
                                "end_line": annotation.end_line,
                                "annotation_level": annotation.annotation_level,
                                "title": annotation.title,
                                "message": annotation.message,
                            }))
                            .collect::<Vec<_>>()
                    );
                }
                let mut body = json!({
                    "status": "completed",
                    "conclusion": conclusion(planned.state),
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
                        &format!("complete {}", planned.name),
                    )
                    .await
                {
                    Ok(response) => Self::check_ok(response, "check-run complete")
                        .await
                        .map(|_| ()),
                    Err(error) => Err(error),
                };
                (index, planned.name, result)
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
    (
        format!(
            "legacy-v2:{}",
            crate::repository_search::hex_digest(digest.finalize())
        ),
        false,
    )
}

fn legacy_finding_receipt_id(finding: &Finding) -> String {
    if let Some(id) = finding.id.as_deref().filter(|id| !id.is_empty()) {
        return id.to_string();
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
    format!(
        "legacy-v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
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
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let mut digest = Sha256::new();
    digest.update(b"github-review-receipt-v2\0");
    digest.update(head_sha.as_bytes());
    for finding in &findings {
        digest.update(finding.finding_id.as_bytes());
        digest.update([finding.initial_outcome as u8]);
    }
    ReviewPublicationReceipt {
        version: ReviewPublicationReceipt::VERSION,
        channel: super::ReviewPublicationChannel::ReviewComments,
        receipt_id: format!(
            "github-review-v2:{}",
            crate::repository_search::hex_digest(digest.finalize())
        ),
        review_id: None,
        findings,
    }
}

fn legacy_planned_review_receipt_ids(envelope: &Envelope, head_sha: &str) -> Vec<String> {
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
        findings.push((legacy_finding_receipt_id(finding), outcome));
    }
    findings.extend(envelope.resolved.iter().map(|finding| {
        (
            legacy_finding_receipt_id(finding),
            FindingPublicationOutcome::Resolved,
        )
    }));
    findings.extend(envelope.suppressed_findings.iter().map(|suppressed| {
        (
            legacy_finding_receipt_id(&suppressed.finding),
            FindingPublicationOutcome::Suppressed,
        )
    }));
    let receipt_id = |findings: &[(String, FindingPublicationOutcome)]| {
        let mut digest = Sha256::new();
        digest.update(b"github-review-receipt-v2\0");
        digest.update(head_sha.as_bytes());
        for (finding_id, outcome) in findings {
            digest.update(finding_id.as_bytes());
            digest.update([*outcome as u8]);
        }
        let hash = digest.finalize();
        format!(
            "github-review-v2:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
        )
    };
    findings.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical_order = receipt_id(&findings);
    vec![canonical_order]
}

fn publication_plan_text_digest(value: &str) -> String {
    format!(
        "sha256:{}",
        crate::repository_search::hex_digest(Sha256::digest(value.as_bytes()))
    )
}

fn publication_plan_finding_content_digest(finding: &Finding) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalFindingPublication<'a> {
        path: &'a str,
        line: u32,
        end_line: Option<u32>,
        severity: Severity,
        kind: crate::envelope::Kind,
        confidence: f64,
        title: &'a str,
        body: &'a str,
    }
    let canonical = serde_json::to_vec(&CanonicalFindingPublication {
        path: &finding.path,
        line: finding.line,
        end_line: finding.end_line,
        severity: finding.severity,
        kind: finding.kind,
        confidence: finding.confidence,
        title: &finding.title,
        body: &finding.body,
    })
    .expect("canonical finding publication is serializable");
    publication_plan_text_digest(std::str::from_utf8(&canonical).expect("JSON is UTF-8"))
}

struct PublicationPlanReviewOutputInput<'a> {
    controller_generation: &'a str,
    input_identity: &'a str,
    repository_id: &'a str,
    pull_request_number: &'a str,
    snapshot: &'a PrMeta,
    envelope: &'a Envelope,
    receipt: &'a ReviewPublicationReceipt,
    should_comment: bool,
    duplicate_of_baseline: bool,
    annotate_findings: bool,
    advisory: CheckState,
    gate: CheckState,
    details_url: Option<&'a str>,
}

fn publication_plan_review_output_digest(
    input: PublicationPlanReviewOutputInput<'_>,
) -> Result<String> {
    let PublicationPlanReviewOutputInput {
        controller_generation,
        input_identity,
        repository_id,
        pull_request_number,
        snapshot,
        envelope,
        receipt,
        should_comment,
        duplicate_of_baseline,
        annotate_findings,
        advisory,
        gate,
        details_url,
    } = input;
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalFindingInput {
        finding_id: String,
        content_digest: String,
        initial_outcome: FindingPublicationOutcome,
        suppression_reason: Option<crate::envelope::SuppressionReason>,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalInput<'a> {
        controller_generation: &'a str,
        input_identity: &'a str,
        repository_id: &'a str,
        pull_request_number: &'a str,
        head_sha: &'a str,
        merge_base_sha: &'a str,
        target_sha: &'a str,
        pull_request_title_sha256: String,
        pull_request_body_sha256: String,
        should_comment: bool,
        duplicate_of_baseline: bool,
        annotate_findings: bool,
        advisory: &'a str,
        gate: &'a str,
        details_url: Option<&'a str>,
        findings: Vec<CanonicalFindingInput>,
    }
    let check_state = |state| match state {
        CheckState::Success => "success",
        CheckState::Failure => "failure",
        CheckState::Neutral => "neutral",
    };
    let mut findings = receipt
        .findings
        .iter()
        .map(|publication| {
            let finding = publication_plan_finding(envelope, &publication.finding_id)?;
            let suppression_reason = envelope
                .suppressed_findings
                .iter()
                .find(|suppressed| {
                    finding_receipt_id(&suppressed.finding).0 == publication.finding_id
                })
                .map(|suppressed| suppressed.reason);
            Ok(CanonicalFindingInput {
                finding_id: publication.finding_id.clone(),
                content_digest: publication_plan_finding_content_digest(finding),
                initial_outcome: publication.initial_outcome,
                suppression_reason,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let canonical = serde_json::to_vec(&CanonicalInput {
        controller_generation,
        input_identity,
        repository_id,
        pull_request_number,
        head_sha: &snapshot.head_sha,
        merge_base_sha: &snapshot.base_sha,
        target_sha: snapshot
            .target_sha
            .as_deref()
            .context("GitHub publication planning requires a target snapshot")?,
        pull_request_title_sha256: publication_plan_text_digest(&snapshot.title),
        pull_request_body_sha256: publication_plan_text_digest(&snapshot.body),
        should_comment,
        duplicate_of_baseline,
        annotate_findings,
        advisory: check_state(advisory),
        gate: check_state(gate),
        details_url,
        findings,
    })?;
    Ok(format!(
        "sha256:{}",
        crate::repository_search::hex_digest(Sha256::digest(canonical))
    ))
}

#[derive(Clone, Copy)]
struct PublicationPlanKeyScope<'a> {
    repository_id: &'a str,
    pull_request_number: &'a str,
    head_sha: &'a str,
    controller_generation: &'a str,
    input_identity: &'a str,
    review_output_digest: &'a str,
}

fn publication_plan_operation_key(
    scope: PublicationPlanKeyScope<'_>,
    kind: PublicationPlanOperationKeyKind,
    finding_id: Option<&str>,
) -> String {
    let kind = kind.as_str();
    let mut digest = Sha256::new();
    digest.update(b"github-publication-operation-v1\0");
    for value in [
        scope.repository_id,
        scope.pull_request_number,
        scope.head_sha,
        scope.controller_generation,
        scope.input_identity,
        scope.review_output_digest,
        kind,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    if let Some(finding_id) = finding_id {
        digest.update(finding_id.as_bytes());
    }
    format!(
        "github-publication-v1:{kind}:sha256:{}",
        crate::repository_search::hex_digest(digest.finalize())
    )
}

fn publication_plan_advisory_completion_dependencies(
    preceding_operations: &[PublicationPlanOperation],
    create_operation_key: &str,
    summary_update_operation_key: Option<&str>,
) -> Vec<String> {
    summary_update_operation_key.map_or_else(
        || {
            preceding_operations
                .iter()
                .map(|operation| operation.operation_key.clone())
                .collect()
        },
        |operation_key| vec![create_operation_key.to_string(), operation_key.to_string()],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPlanOperationKeyKind {
    InitialReviewCreate,
    RelocatedReviewCreate,
    SummaryReviewCreate,
    FileCommentFallback,
    FindingCommentUpdate,
    ReviewSummaryUpdate,
    AdvisoryCheckCreate,
    AdvisoryCheckComplete,
}

impl PublicationPlanOperationKeyKind {
    #[cfg(test)]
    const ALL: [Self; 8] = [
        Self::InitialReviewCreate,
        Self::RelocatedReviewCreate,
        Self::SummaryReviewCreate,
        Self::FileCommentFallback,
        Self::FindingCommentUpdate,
        Self::ReviewSummaryUpdate,
        Self::AdvisoryCheckCreate,
        Self::AdvisoryCheckComplete,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::InitialReviewCreate => "initial-review-create",
            Self::RelocatedReviewCreate => "relocated-review-create",
            Self::SummaryReviewCreate => "summary-review-create",
            Self::FileCommentFallback => "file-comment-fallback",
            Self::FindingCommentUpdate => "finding-comment-update",
            Self::ReviewSummaryUpdate => "review-summary-update",
            Self::AdvisoryCheckCreate => "advisory-check-create",
            Self::AdvisoryCheckComplete => "advisory-check-complete",
        }
    }
}

fn publication_plan_operation_finding_id(operation: &PublicationPlanOperation) -> Option<&str> {
    match &operation.desired {
        PublicationPlanOperationKind::FileCommentFallback { finding_id, .. }
        | PublicationPlanOperationKind::FindingCommentUpdate { finding_id, .. } => Some(finding_id),
        _ => None,
    }
}

fn publication_plan_logical_review_identity(scope: PublicationPlanKeyScope<'_>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"github-publication-logical-review-v1\0");
    for value in [
        scope.repository_id,
        scope.pull_request_number,
        scope.head_sha,
        scope.controller_generation,
        scope.input_identity,
        scope.review_output_digest,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    format!(
        "github-publication-v1:review:sha256:{}",
        crate::repository_search::hex_digest(digest.finalize())
    )
}

fn publication_plan_publishable_findings<'a>(
    envelope: &'a Envelope,
    published: &std::collections::HashMap<String, PublishedReviewComment>,
) -> Vec<&'a Finding> {
    let mut findings = envelope
        .findings
        .iter()
        .filter(|finding| !filter::is_carried(finding))
        .filter(|finding| !super::is_synthetic_path(&finding.path))
        .filter(|finding| {
            !finding_marker_candidates(finding)
                .iter()
                .any(|marker| published.contains_key(marker))
        })
        .collect::<Vec<_>>();
    findings.sort_by_key(|finding| super::publication_finding_sort_key(finding));
    findings
}

fn publication_plan_finding<'a>(envelope: &'a Envelope, finding_id: &str) -> Result<&'a Finding> {
    envelope
        .findings
        .iter()
        .chain(envelope.resolved.iter())
        .chain(
            envelope
                .suppressed_findings
                .iter()
                .map(|suppressed| &suppressed.finding),
        )
        .find(|finding| finding_receipt_id(finding).0 == finding_id)
        .with_context(|| format!("GitHub publication plan omitted finding identity {finding_id}"))
}

fn publication_plan_review_comment(
    value: &serde_json::Value,
) -> Result<PublicationPlanReviewComment> {
    Ok(PublicationPlanReviewComment {
        path: value["path"]
            .as_str()
            .context("GitHub review comment plan omitted its path")?
            .to_string(),
        line: value["line"]
            .as_u64()
            .and_then(|line| u32::try_from(line).ok())
            .context("GitHub review comment plan omitted its line")?,
        side: value["side"]
            .as_str()
            .context("GitHub review comment plan omitted its side")?
            .to_string(),
        start_line: value["start_line"]
            .as_u64()
            .and_then(|line| u32::try_from(line).ok()),
        start_side: value["start_side"].as_str().map(str::to_string),
        body: value["body"]
            .as_str()
            .context("GitHub review comment plan omitted its body")?
            .to_string(),
    })
}

fn publication_plan_file_comment(value: &serde_json::Value) -> Result<PublicationPlanFileComment> {
    Ok(PublicationPlanFileComment {
        body: value["body"]
            .as_str()
            .context("GitHub file-comment plan omitted its body")?
            .to_string(),
        commit_id: value["commit_id"]
            .as_str()
            .context("GitHub file-comment plan omitted its commit id")?
            .to_string(),
        path: value["path"]
            .as_str()
            .context("GitHub file-comment plan omitted its path")?
            .to_string(),
        subject_type: value["subject_type"]
            .as_str()
            .context("GitHub file-comment plan omitted its subject type")?
            .to_string(),
    })
}

fn initial_review_comment(finding: &Finding) -> serde_json::Value {
    let (finding_id, _) = finding_receipt_id(finding);
    let mut comment = json!({
        "path": finding.path,
        "line": finding.line,
        "side": "RIGHT",
        "body": append_marker(
            &super::finding_comment_body(finding, true),
            &finding_marker(&finding_id),
        ),
    });
    if let Some(end) = finding.end_line
        && end > finding.line
    {
        comment["start_line"] = json!(finding.line);
        comment["line"] = json!(end);
        comment["start_side"] = json!("RIGHT");
    }
    comment
}

fn fallback_line_comment(finding: &Finding, path: &str, line: u32) -> serde_json::Value {
    let (finding_id, _) = finding_receipt_id(finding);
    let mut body = String::new();
    if path != finding.path {
        body.push_str(&format!(
            "This finding refers to `{}:{}`, outside the changed lines in this file.\n\n",
            super::safe_code_text(&finding.path),
            finding.line,
        ));
    } else if line != finding.line {
        body.push_str(&format!(
            "This finding refers to line {}, outside the changed lines.\n\n",
            finding.line,
        ));
    }
    body.push_str(&super::finding_comment_body(finding, true));
    json!({
        "path": path,
        "line": line,
        "side": "RIGHT",
        "body": append_marker(&body, &finding_marker(&finding_id)),
    })
}

fn file_level_comment(finding: &Finding, path: &str, head_sha: &str) -> serde_json::Value {
    let (finding_id, _) = finding_receipt_id(finding);
    let body = format!(
        "Original location: `{}:{}`\n\n{}",
        super::safe_code_text(&finding.path),
        finding.line,
        super::finding_comment_body(finding, true),
    );
    let body = append_marker(&body, FILE_LEVEL_COMMENT_MARKER);
    json!({
        "body": append_marker(&body, &finding_marker(&finding_id)),
        "commit_id": head_sha,
        "path": path,
        "subject_type": "file",
    })
}

fn publication_file_path<'a>(diff: &'a Diff, finding_path: &str) -> Option<&'a str> {
    diff.files
        .iter()
        .find(|file| file.path == finding_path)
        .map(|file| file.path.as_str())
        .or_else(|| {
            diff.files
                .iter()
                .find(|file| !file.deleted && file.old_path == finding_path)
                .map(|file| file.path.as_str())
        })
}

fn set_publication_outcome(
    receipt: &mut ReviewPublicationReceipt,
    finding: &Finding,
    outcome: FindingPublicationOutcome,
    inline_rejected: bool,
) -> Result<()> {
    let (finding_id, _) = finding_receipt_id(finding);
    let publication = receipt
        .findings
        .iter_mut()
        .find(|publication| publication.finding_id == finding_id)
        .context("GitHub placement fallback omitted a finding publication receipt")?;
    publication.initial_outcome = outcome;
    publication.inline_rejected = inline_rejected;
    publication.comment_id = None;
    Ok(())
}

fn receipt_covers_findings(receipt: &ReviewPublicationReceipt, findings: &[&Finding]) -> bool {
    findings
        .iter()
        .all(|finding| receipt_has_finding_comment(receipt, finding))
}

fn receipt_has_finding_comment(receipt: &ReviewPublicationReceipt, finding: &Finding) -> bool {
    let (finding_id, _) = finding_receipt_id(finding);
    receipt
        .findings
        .iter()
        .find(|publication| publication.finding_id == finding_id)
        .is_some_and(|publication| publication.comment_id.is_some())
}

fn github_review_rejected_line(body: &str) -> bool {
    let normalized = body.to_ascii_lowercase();
    if normalized.contains("line could not be resolved")
        || normalized.contains("line must be part of the diff")
    {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .is_some_and(|errors| {
            errors.iter().any(|error| {
                matches!(
                    error.get("field").and_then(serde_json::Value::as_str),
                    Some("line" | "start_line")
                ) && error.get("code").and_then(serde_json::Value::as_str) == Some("invalid")
            })
        })
}

fn publication_summary(receipt: &ReviewPublicationReceipt) -> ReviewPublicationSummary {
    let mut summary = ReviewPublicationSummary::default();
    for finding in &receipt.findings {
        match finding.initial_outcome {
            FindingPublicationOutcome::Inline if finding.comment_id.is_some() => {
                summary.active_inline += 1;
            }
            FindingPublicationOutcome::Inline => {}
            FindingPublicationOutcome::FileComment if finding.comment_id.is_some() => {
                summary.file_comments += 1;
            }
            FindingPublicationOutcome::FileComment => {}
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

fn durable_partial_receipt(receipt: &ReviewPublicationReceipt) -> ReviewPublicationReceipt {
    let mut durable = receipt.clone();
    for finding in &mut durable.findings {
        if finding.initial_outcome == FindingPublicationOutcome::FileComment
            && finding.comment_id.is_none()
        {
            finding.initial_outcome = FindingPublicationOutcome::Unknown;
        }
    }
    durable
}

fn finding_marker(finding_id: &str) -> String {
    let hash = Sha256::digest(finding_id.as_bytes());
    format!(
        "<!-- postil-finding:v2:{} -->",
        crate::repository_search::hex_digest(hash)
    )
}

fn legacy_finding_marker(finding_id: &str) -> String {
    let hash = Sha256::digest(finding_id.as_bytes());
    format!(
        "<!-- postil-finding:v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

fn finding_marker_candidates(finding: &Finding) -> Vec<String> {
    let (finding_id, _) = finding_receipt_id(finding);
    let legacy_id = legacy_finding_receipt_id(finding);
    let mut markers = vec![
        finding_marker(&finding_id),
        legacy_finding_marker(&finding_id),
    ];
    if legacy_id != finding_id {
        markers.push(legacy_finding_marker(&legacy_id));
    }
    markers
}

fn review_marker(receipt_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(receipt_id.as_bytes());
    let hash = digest.finalize();
    format!(
        "<!-- postil-review:v2:{} -->",
        crate::repository_search::hex_digest(hash)
    )
}

fn legacy_review_marker(receipt_id: &str) -> String {
    let hash = Sha256::digest(receipt_id.as_bytes());
    format!(
        "<!-- postil-review:v1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} -->",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
    )
}

fn review_marker_in(body: &str) -> Option<String> {
    let start = ["<!-- postil-review:v2:", "<!-- postil-review:v1:"]
        .into_iter()
        .filter_map(|open| body.rfind(open))
        .max()?;
    let end = body[start..].find("-->")? + start + "-->".len();
    Some(body[start..end].to_string())
}

/// The finding marker a published comment body ends with, if any.
fn finding_marker_in(body: &str) -> Option<String> {
    let start = ["<!-- postil-finding:v2:", "<!-- postil-finding:v1:"]
        .into_iter()
        .filter_map(|open| body.rfind(open))
        .max()?;
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

fn without_finding_marker(body: &str) -> &str {
    let Some(marker) = finding_marker_in(body) else {
        return body.trim_end();
    };
    body.strip_suffix(&marker)
        .map(str::trim_end)
        .unwrap_or_else(|| body.trim_end())
}

fn publication_plan_body_digest(body: &str) -> String {
    publication_plan_text_digest(body)
}

fn published_comment_for_finding<'a>(
    published: &'a std::collections::HashMap<String, PublishedReviewComment>,
    finding: &Finding,
) -> Option<&'a PublishedReviewComment> {
    finding_marker_candidates(finding)
        .iter()
        .find_map(|marker| published.get(marker))
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

fn required_review_body(body: &str, marker: &str) -> Result<String> {
    let marked = append_marker(body, marker);
    ensure!(
        marked.len() <= MAX_REVIEW_BODY_BYTES,
        "GitHub review summary cannot represent every unplaced finding within its size limit"
    );
    Ok(marked)
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
    use crate::forge::{
        CheckRunIds, CheckState, FindingPublicationOutcome, Forge, PrMeta,
        PublicationPlanActivationCondition, PublicationPlanCheckStatus, PublicationPlanOperation,
        PublicationPlanOperationActivation, PublicationPlanOperationKind,
        PublicationPlanOperationReconciliation,
    };
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PUBLICATION_INPUT_IDENTITY: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn publication_plan_key_scope<'a>(
        head_sha: &'a str,
        input_identity: &'a str,
        review_output_digest: &'a str,
    ) -> super::PublicationPlanKeyScope<'a> {
        super::PublicationPlanKeyScope {
            repository_id: "42",
            pull_request_number: "7",
            head_sha,
            controller_generation: "1",
            input_identity,
            review_output_digest,
        }
    }

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

    fn placement_diff() -> crate::diff::Diff {
        crate::diff::parse(
            "diff --git a/src/lib.rs b/src/lib.rs\n\
             --- a/src/lib.rs\n\
             +++ b/src/lib.rs\n\
             @@ -10 +10,3 @@\n\
              context\n\
             +added one\n\
             +added two\n",
        )
    }

    fn file_only_placement_diff() -> crate::diff::Diff {
        crate::diff::parse(
            "diff --git a/src/lib.rs b/src/lib.rs\n\
             index 9daeafb..0f15a6e 100644\n\
             Binary files a/src/lib.rs and b/src/lib.rs differ\n",
        )
    }

    fn unrelated_placement_diff() -> crate::diff::Diff {
        crate::diff::parse(
            "diff --git a/src/other.rs b/src/other.rs\n\
             --- a/src/other.rs\n\
             +++ b/src/other.rs\n\
             @@ -1 +1 @@\n\
             -old();\n\
             +new();\n",
        )
    }

    fn two_file_placement_diff() -> crate::diff::Diff {
        crate::diff::parse(
            "diff --git a/src/first.bin b/src/first.bin\n\
             index 9daeafb..0f15a6e 100644\n\
             Binary files a/src/first.bin and b/src/first.bin differ\n\
             diff --git a/src/second.bin b/src/second.bin\n\
             index 9daeafb..0f15a6e 100644\n\
             Binary files a/src/second.bin and b/src/second.bin differ\n",
        )
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
        mount_current_delivery_snapshot(&server).await;
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
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let github = test_github(&server);
        let body = serde_json::json!({
            "body": "summary\n\n<!-- postil-review:test -->",
            "commit_id": "aaaaaaaaaaaa",
            "event": "COMMENT"
        });
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");

        let response = github
            .send_review_reconciled(
                &body,
                "<!-- postil-review:test -->",
                &snapshot,
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

    #[test]
    fn publication_plan_operation_keys_match_every_key_safe_contract_shape() {
        let expected = [
            (
                "initial-review-create",
                "05d5806e72114f105b5b1e2809be8651811a3e527d89f7455c20dedbf32f24ce",
            ),
            (
                "relocated-review-create",
                "178636b4f224fdfb105833cde04ca2f5b1cf74bf407b9ab2dd23938198467058",
            ),
            (
                "summary-review-create",
                "7ca44380841305baacfac07805bc41c4b308f95acd0278b3e5ed3bfca4f7d8a0",
            ),
            (
                "file-comment-fallback",
                "6e61767bbe33ef6d754950c5bcce236fbeb92df235005db907731caa96e047dc",
            ),
            (
                "finding-comment-update",
                "875e393c65ef65394d4e73148f3369bad46f1d23d064cb906b3a8a69feb38d2f",
            ),
            (
                "review-summary-update",
                "e575a792bbe3c702f35bd4218263a9cf160b841c1e898c8045802530d56cac5f",
            ),
            (
                "advisory-check-create",
                "3be1458de77b6d90c70ead018e3897dddf217dc3bb5c0a68ba51b3f4129556d4",
            ),
            (
                "advisory-check-complete",
                "2c9ec6990843d0012a5489aa99a2fec170326e1a36f48a38fc51a73b42af33d7",
            ),
        ];
        for (kind, (expected_kind, expected_digest)) in super::PublicationPlanOperationKeyKind::ALL
            .into_iter()
            .zip(expected)
        {
            assert_eq!(kind.as_str(), expected_kind);
            let finding_id = matches!(
                kind,
                super::PublicationPlanOperationKeyKind::FileCommentFallback
                    | super::PublicationPlanOperationKeyKind::FindingCommentUpdate
            )
            .then_some("finding-1");
            let key = super::publication_plan_operation_key(
                publication_plan_key_scope(
                    "head-1",
                    PUBLICATION_INPUT_IDENTITY,
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                ),
                kind,
                finding_id,
            );
            assert_eq!(
                key,
                format!("github-publication-v1:{expected_kind}:sha256:{expected_digest}")
            );
            assert!(!key.contains('/'));
        }
    }

    #[test]
    fn advisory_check_completion_depends_on_creation_and_terminal_review_work() {
        let operation = |operation_key: &str| {
            PublicationPlanOperation::new(
                0,
                operation_key.into(),
                vec![],
                PublicationPlanOperationActivation {
                    any_of: vec![PublicationPlanActivationCondition::Always],
                },
                PublicationPlanOperationReconciliation {
                    logical_identity: operation_key.into(),
                    markers: vec![],
                    observed_remote_id: None,
                    exclusive: true,
                },
                PublicationPlanOperationKind::AdvisoryCheckCreate {
                    name: "postil/review".into(),
                    head_sha: "aaaaaaaaaaaa".into(),
                    status: PublicationPlanCheckStatus::InProgress,
                    external_id: "postil:postil/review:aaaaaaaaaaaa".into(),
                    details_url: None,
                },
            )
            .unwrap()
        };
        let preceding = vec![
            operation("advisory-create"),
            operation("finding-update"),
            operation("file-fallback"),
        ];

        assert_eq!(
            super::publication_plan_advisory_completion_dependencies(
                &preceding,
                "advisory-create",
                None,
            ),
            vec!["advisory-create", "finding-update", "file-fallback"]
        );
        assert_eq!(
            super::publication_plan_advisory_completion_dependencies(
                &preceding,
                "advisory-create",
                Some("review-summary-update"),
            ),
            vec!["advisory-create", "review-summary-update"]
        );
    }

    #[test]
    fn same_head_rereviews_bind_remote_identity_to_generation_and_content() {
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![publication_finding(
                "finding-1",
                "src/lib.rs",
                "Original finding body.",
            )],
        );
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let receipt = super::planned_review_receipt(&envelope, &snapshot.head_sha);
        let identity = |generation: &str, snapshot: &PrMeta, envelope: &Envelope, gate| {
            super::publication_plan_review_output_digest(super::PublicationPlanReviewOutputInput {
                controller_generation: generation,
                input_identity: PUBLICATION_INPUT_IDENTITY,
                repository_id: "42",
                pull_request_number: "7",
                snapshot,
                envelope,
                receipt: &receipt,
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate,
                details_url: None,
            })
            .unwrap()
        };
        let baseline = identity("1", &snapshot, &envelope, CheckState::Success);
        let mut changed_title = snapshot.clone();
        changed_title.title = "Changed title".into();
        let mut changed_body = snapshot.clone();
        changed_body.body = "Changed pull request body".into();
        let mut changed_finding = envelope.clone();
        changed_finding.findings[0].body = "Changed finding body.".into();
        let mut changed_confidence = envelope.clone();
        changed_confidence.findings[0].confidence = 0.73;
        let variants = [
            identity("2", &snapshot, &envelope, CheckState::Success),
            identity("1", &changed_title, &envelope, CheckState::Success),
            identity("1", &changed_body, &envelope, CheckState::Success),
            identity("1", &snapshot, &changed_finding, CheckState::Success),
            identity("1", &snapshot, &changed_confidence, CheckState::Success),
            identity("1", &snapshot, &envelope, CheckState::Failure),
        ];
        for variant in variants {
            assert_ne!(variant, baseline);
            let variant_scope = publication_plan_key_scope(
                &snapshot.head_sha,
                PUBLICATION_INPUT_IDENTITY,
                &variant,
            );
            let baseline_scope = publication_plan_key_scope(
                &snapshot.head_sha,
                PUBLICATION_INPUT_IDENTITY,
                &baseline,
            );
            assert_ne!(
                super::publication_plan_logical_review_identity(variant_scope),
                super::publication_plan_logical_review_identity(baseline_scope)
            );
            assert_ne!(
                super::publication_plan_operation_key(
                    variant_scope,
                    super::PublicationPlanOperationKeyKind::InitialReviewCreate,
                    None,
                ),
                super::publication_plan_operation_key(
                    baseline_scope,
                    super::PublicationPlanOperationKeyKind::InitialReviewCreate,
                    None,
                )
            );
        }

        let changed_input_identity =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let changed_input_output =
            super::publication_plan_review_output_digest(super::PublicationPlanReviewOutputInput {
                controller_generation: "1",
                input_identity: changed_input_identity,
                repository_id: "42",
                pull_request_number: "7",
                snapshot: &snapshot,
                envelope: &envelope,
                receipt: &receipt,
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate: CheckState::Success,
                details_url: None,
            })
            .unwrap();
        assert_ne!(changed_input_output, baseline);
        assert_ne!(
            super::publication_plan_operation_key(
                publication_plan_key_scope(
                    &snapshot.head_sha,
                    changed_input_identity,
                    &changed_input_output,
                ),
                super::PublicationPlanOperationKeyKind::InitialReviewCreate,
                None,
            ),
            super::publication_plan_operation_key(
                publication_plan_key_scope(
                    &snapshot.head_sha,
                    PUBLICATION_INPUT_IDENTITY,
                    &baseline,
                ),
                super::PublicationPlanOperationKeyKind::InitialReviewCreate,
                None,
            )
        );
    }

    #[test]
    fn durable_markers_are_strong_and_accept_released_compatibility_shapes() {
        let finding = publication_finding("finding-1", "src/lib.rs", "Body.");
        let finding_markers = super::finding_marker_candidates(&finding);
        assert_eq!(finding_markers.len(), 2);
        assert!(finding_markers[0].starts_with("<!-- postil-finding:v2:"));
        assert_eq!(
            finding_markers[0].len(),
            "<!-- postil-finding:v2: -->".len() + 64
        );
        assert!(finding_markers[1].starts_with("<!-- postil-finding:v1:"));
        assert_eq!(
            finding_markers[1].len(),
            "<!-- postil-finding:v1: -->".len() + 12
        );

        let current_receipt = super::planned_review_receipt(
            &delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]),
            "aaaaaaaaaaaa",
        );
        let current_review_marker = super::review_marker(&current_receipt.receipt_id);
        assert!(current_review_marker.starts_with("<!-- postil-review:v2:"));
        assert_eq!(
            current_review_marker.len(),
            "<!-- postil-review:v2: -->".len() + 64
        );
        let released_marker = super::legacy_review_marker("github-review-v2:0123456789ab");
        assert!(released_marker.starts_with("<!-- postil-review:v1:"));
        assert_eq!(
            released_marker.len(),
            "<!-- postil-review:v1: -->".len() + 12
        );
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

    async fn mount_no_existing_review(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn publication_plan_reuses_review_checks_markers_and_the_placement_ladder() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(2)
            .mount(&server)
            .await;

        let mut active = publication_finding(
            "active-1",
            "src/lib.rs",
            "The unchecked value reaches the protected operation.",
        );
        active.severity = Severity::Error;
        let mut carried = publication_finding(
            "carried-1",
            "src/carried.rs",
            "The carried finding remains open.",
        );
        carried.body = format!(
            "{} The carried finding remains open.",
            crate::filter::CARRIED_MARKER
        );
        let summary_only = publication_finding(
            "summary-1",
            crate::envelope::CHANGE_METADATA_PATH,
            "The metadata finding belongs in the summary.",
        );
        let resolved = publication_finding(
            "resolved-1",
            "src/resolved.rs",
            "The resolved finding remains identifiable.",
        );
        let suppressed = publication_finding(
            "suppressed-1",
            "src/suppressed.rs",
            "The suppressed finding remains identifiable.",
        );
        let mut envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![active, carried, summary_only],
        );
        envelope.resolved.push(resolved);
        envelope.suppressed_findings.push(SuppressedFinding {
            finding: suppressed,
            reason: SuppressionReason::BelowConfidence,
        });
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let planner = || {
            let mut github = test_github(&server);
            github.details_url = Some("https://postil.dev/orgs/acme/runs/run-1".into());
            github
        };
        let plan = planner()
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: "1",
                input_identity: PUBLICATION_INPUT_IDENTITY,
                envelope: &envelope,
                snapshot: &snapshot,
                publication_diff: Some(&placement_diff()),
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate: CheckState::Failure,
            })
            .await
            .unwrap();
        let mut reordered_envelope = envelope.clone();
        reordered_envelope.findings.reverse();
        reordered_envelope.resolved.reverse();
        reordered_envelope.suppressed_findings.reverse();
        let reordered_plan = planner()
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: "1",
                input_identity: PUBLICATION_INPUT_IDENTITY,
                envelope: &reordered_envelope,
                snapshot: &snapshot,
                publication_diff: Some(&placement_diff()),
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate: CheckState::Failure,
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&plan).unwrap(),
            serde_json::to_vec(&reordered_plan).unwrap(),
            "provider finding order must not affect publication intent"
        );
        let serialized = serde_json::to_value(&plan).unwrap();
        let operations = serialized["operations"].as_array().unwrap();
        assert_eq!(
            operations
                .iter()
                .map(|operation| operation["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "advisoryCheckCreate",
                "reviewCreate",
                "reviewCreate",
                "reviewCreate",
                "fileCommentFallback",
                "reviewSummaryUpdate",
                "advisoryCheckComplete",
            ]
        );
        assert_eq!(operations[0]["ordinal"], 1);
        assert_eq!(operations[1]["ordinal"], 2);
        assert_eq!(operations[2]["ordinal"], 3);
        assert_eq!(operations[0]["name"], "postil/review");
        assert_eq!(operations[0]["headSha"], "aaaaaaaaaaaa");
        assert_eq!(operations[0]["status"], "in_progress");
        assert_eq!(
            operations[0]["externalId"],
            "postil:run-1:postil/review:aaaaaaaaaaaa"
        );
        assert_eq!(
            operations[0]["detailsUrl"],
            "https://postil.dev/orgs/acme/runs/run-1"
        );
        assert_eq!(operations[1]["attempt"], "initial");
        assert_eq!(operations[2]["attempt"], "relocatedInline");
        assert_eq!(operations[3]["attempt"], "summaryOnly");
        assert_eq!(operations[1]["payload"]["comments"][0]["line"], 7);
        assert_eq!(
            operations[2]["payload"]["comments"][0]["path"],
            "src/lib.rs"
        );
        assert!(operations[3]["payload"]["body"].is_string());
        let logical_review_identity = operations[1]["logicalReviewIdentity"].as_str().unwrap();
        for operation in &operations[1..4] {
            assert_eq!(operation["logicalReviewIdentity"], logical_review_identity);
            assert_eq!(
                operation["reconciliation"]["logicalIdentity"],
                logical_review_identity
            );
            assert_eq!(operation["reconciliation"]["exclusive"], true);
            assert_eq!(
                operation["reconciliation"]["markers"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
        assert_eq!(
            operations[2]["activation"]["anyOf"][0]["condition"],
            "semanticPlacementRejected"
        );
        assert_eq!(operations[2]["activation"]["anyOf"][0]["httpStatus"], 422);
        assert_eq!(
            operations[2]["activation"]["anyOf"][0]["classification"],
            "invalidReviewCommentPlacement"
        );
        assert_eq!(
            operations[2]["activation"]["anyOf"][0]["markerAbsence"],
            operations[1]["activation"]["anyOf"][0]["guard"]
        );
        assert_eq!(
            operations[3]["activation"]["anyOf"][0]["markerAbsence"],
            operations[1]["activation"]["anyOf"][0]["guard"]
        );
        let findings = serialized["lifecycleReceipt"]["findings"]
            .as_array()
            .unwrap();
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["findingId"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "active-1",
                "carried-1",
                "resolved-1",
                "summary-1",
                "suppressed-1"
            ]
        );
        assert_eq!(findings[0]["initialOutcome"], "inline");
        assert_eq!(
            findings[0]["fallbackIntent"],
            serde_json::json!(["relocatedInline", "fileComment"])
        );
        assert_eq!(findings[1]["initialOutcome"], "carried");
        assert_eq!(findings[2]["initialOutcome"], "resolved");
        assert_eq!(findings[3]["initialOutcome"], "summaryOnly");
        assert_eq!(findings[4]["initialOutcome"], "suppressed");
        assert_eq!(findings[4]["suppressionReason"], "belowConfidence");
        assert!(
            serialized["lifecycleReceipt"]["digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(operations[4]["findingId"], "active-1");
        assert_eq!(
            operations[4]["activation"]["anyOf"][0]["condition"],
            "semanticPlacementRejected"
        );
        assert_eq!(
            operations[4]["activation"]["anyOf"][1]["condition"],
            "partialReviewObserved"
        );
        assert_eq!(
            operations[4]["activation"]["anyOf"][1]["findingMarkerAbsence"]["markers"],
            operations[4]["reconciliation"]["markers"]
        );
        assert_eq!(
            operations[5]["terminalOperations"][0]["findingId"],
            "active-1"
        );
        assert_eq!(
            operations[5]["terminalOperations"][0]["requiresRemoteId"],
            true
        );
        assert_eq!(operations[5]["cases"][0]["fileCommentCount"], 0);
        assert_eq!(operations[5]["cases"][1]["fileCommentCount"], 1);
        assert_eq!(
            operations[5]["cases"][1]["selectedReviewOutcomes"],
            serde_json::json!(["partialObserved"])
        );
        assert_eq!(operations[6]["name"], "postil/review");
        assert_eq!(operations[6]["conclusion"], "success");
        assert_eq!(
            operations[6]["dependencies"],
            serde_json::json!([
                operations[0]["operationKey"].clone(),
                operations[5]["operationKey"].clone()
            ])
        );
        assert_eq!(
            operations[6]["createdCheck"]["dependencyOperationKey"],
            operations[0]["operationKey"]
        );
        assert_eq!(operations[6]["createdCheck"]["resultField"], "remoteId");
        assert_eq!(serialized["repository"]["id"], "42");
        assert_eq!(serialized["pullRequestNumber"], "1");
        assert_eq!(serialized["gateAnalysis"]["ownership"], "service");
        assert_eq!(serialized["gateAnalysis"]["authoritative"], false);
        assert_eq!(
            serialized["gateAnalysis"]["organizationGateModeRequired"],
            true
        );
        assert_eq!(serialized["gateAnalysis"]["name"], "postil/gate");
        assert_eq!(serialized["gateAnalysis"]["analyzedConclusion"], "failure");
        assert!(operations.iter().all(|operation| {
            operation["kind"] != "gateCheck" && operation["name"] != "postil/gate"
        }));
        assert_eq!(plan.recompute_intent_digest().unwrap(), plan.intent_digest);

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !matches!(
                request.method,
                wiremock::http::Method::POST
                    | wiremock::http::Method::PATCH
                    | wiremock::http::Method::PUT
                    | wiremock::http::Method::DELETE
            )
        }));
    }

    #[tokio::test]
    async fn publication_plan_recovers_a_partial_review_without_an_alternative_create() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let first = publication_finding(
            "first",
            "src/lib.rs",
            "The first finding was observed in the partial review.",
        );
        let second = publication_finding(
            "second",
            "src/lib.rs",
            "The second finding is missing from the partial review.",
        );
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![second, first.clone()],
        );
        let legacy_review_marker = "<!-- postil-review:v1:0123456789ab -->".to_string();
        let first_body = super::initial_review_comment(&first)["body"]
            .as_str()
            .unwrap()
            .to_string();
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 501,
                    "body": first_body,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 77,
                    "body": legacy_review_marker.clone(),
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(2)
            .mount(&server)
            .await;

        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let build = || async {
            test_github(&server)
                .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                    controller_generation: "3",
                    input_identity: PUBLICATION_INPUT_IDENTITY,
                    envelope: &envelope,
                    snapshot: &snapshot,
                    publication_diff: Some(&placement_diff()),
                    should_comment: true,
                    duplicate_of_baseline: false,
                    annotate_findings: false,
                    advisory: CheckState::Success,
                    gate: CheckState::Success,
                })
                .await
                .unwrap()
        };
        let first_plan = build().await;
        let second_plan = build().await;
        assert_eq!(
            serde_json::to_vec(&first_plan).unwrap(),
            serde_json::to_vec(&second_plan).unwrap()
        );
        let plan = serde_json::to_value(first_plan).unwrap();
        let findings = plan["lifecycleReceipt"]["findings"].as_array().unwrap();
        assert_eq!(findings[0]["findingId"], "first");
        assert_eq!(findings[0]["observedCommentId"], "501");
        assert_eq!(findings[0]["observedOutcome"], "inline");
        assert_eq!(findings[0]["reconciliation"], "retain");
        assert_eq!(findings[1]["findingId"], "second");
        assert!(findings[1].get("observedCommentId").is_none());
        assert_eq!(plan["lifecycleReceipt"]["observedReviewId"], "77");

        let operations = plan["operations"].as_array().unwrap();
        let review_operations = &operations[1..4];
        let logical_identity = review_operations[0]["logicalReviewIdentity"].clone();
        let shared_markers = review_operations[0]["reconciliation"]["markers"].clone();
        assert!(
            shared_markers
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(legacy_review_marker))
        );
        let exact_marker_guard = review_operations[0]["activation"]["anyOf"][0]["guard"].clone();
        for operation in review_operations {
            assert_eq!(operation["logicalReviewIdentity"], logical_identity);
            assert_eq!(operation["reconciliation"]["markers"], shared_markers);
            assert_eq!(operation["reconciliation"]["observedRemoteId"], "77");
            assert_eq!(operation["reconciliation"]["exclusive"], true);
        }
        assert_eq!(
            review_operations[1]["activation"]["anyOf"][0]["markerAbsence"],
            exact_marker_guard
        );
        assert_eq!(
            review_operations[2]["activation"]["anyOf"][0]["markerAbsence"],
            exact_marker_guard
        );

        let file_fallback = operations
            .iter()
            .find(|operation| operation["kind"] == "fileCommentFallback")
            .unwrap();
        assert_eq!(file_fallback["findingId"], "second");
        let partial_conditions = file_fallback["activation"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|condition| condition["condition"] == "partialReviewObserved")
            .collect::<Vec<_>>();
        assert_eq!(partial_conditions.len(), 2);
        for condition in partial_conditions {
            assert_eq!(condition["reviewMarkers"], shared_markers);
            assert_eq!(
                condition["findingMarkerAbsence"]["markers"],
                file_fallback["reconciliation"]["markers"]
            );
            assert_eq!(condition["findingMarkerAbsence"]["required"], true);
        }

        let final_summary = operations
            .iter()
            .find(|operation| operation["kind"] == "reviewSummaryUpdate")
            .unwrap();
        assert!(
            final_summary["dependencies"]
                .as_array()
                .unwrap()
                .contains(&file_fallback["operationKey"])
        );
        assert_eq!(
            final_summary["terminalOperations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            final_summary["terminalOperations"][0]["findingId"],
            "second"
        );
        let partial_case = final_summary["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| {
                case["selectedReviewOperationKey"] == review_operations[0]["operationKey"]
                    && case["selectedReviewOutcomes"] == serde_json::json!(["partialObserved"])
                    && case["fileCommentCount"] == 1
            })
            .expect("partial observation has a truthful final summary case");
        assert!(
            partial_case["body"]
                .as_str()
                .unwrap()
                .contains("file-level")
        );

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !matches!(
                request.method,
                wiremock::http::Method::POST
                    | wiremock::http::Method::PATCH
                    | wiremock::http::Method::PUT
                    | wiremock::http::Method::DELETE
            )
        }));
    }

    #[tokio::test]
    async fn publication_plan_updates_stale_same_head_finding_content() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let finding = publication_finding(
            "stable-finding",
            "src/lib.rs",
            "The desired finding body is current.",
        );
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding.clone()]);
        let receipt = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        let review_marker = super::review_marker(&receipt.receipt_id);
        let stale_body = super::append_marker(
            "**Stale finding title**\n\nThe old finding prose is obsolete.",
            &super::finding_marker("stable-finding"),
        );
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 501,
                    "body": stale_body,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 77,
                    "body": review_marker,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(2)
            .mount(&server)
            .await;
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let first_plan = test_github(&server)
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: "4",
                input_identity: PUBLICATION_INPUT_IDENTITY,
                envelope: &envelope,
                snapshot: &snapshot,
                publication_diff: Some(&placement_diff()),
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate: CheckState::Success,
            })
            .await
            .unwrap();
        let mut changed_envelope = envelope.clone();
        changed_envelope.findings[0].body = "A later same-head finding body is desired.".into();
        let changed_plan = test_github(&server)
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: "4",
                input_identity: PUBLICATION_INPUT_IDENTITY,
                envelope: &changed_envelope,
                snapshot: &snapshot,
                publication_diff: Some(&placement_diff()),
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: false,
                advisory: CheckState::Success,
                gate: CheckState::Success,
            })
            .await
            .unwrap();

        let first = serde_json::to_value(&first_plan).unwrap();
        let changed = serde_json::to_value(&changed_plan).unwrap();
        let finding_receipt = &first["lifecycleReceipt"]["findings"][0];
        assert_eq!(finding_receipt["findingId"], "stable-finding");
        assert_eq!(finding_receipt["observedCommentId"], "501");
        assert_eq!(finding_receipt["reconciliation"], "replace");
        assert_ne!(
            finding_receipt["desiredBodySha256"],
            finding_receipt["observedBodySha256"]
        );
        let update = first["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["kind"] == "findingCommentUpdate")
            .unwrap();
        assert_eq!(update["findingId"], "stable-finding");
        assert_eq!(update["observedCommentId"], "501");
        assert_eq!(update["reconciliation"]["observedRemoteId"], "501");
        assert_eq!(update["expectedMarkers"].as_array().unwrap().len(), 2);
        let final_summary = first["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["kind"] == "reviewSummaryUpdate")
            .unwrap();
        assert!(
            final_summary["dependencies"]
                .as_array()
                .unwrap()
                .contains(&update["operationKey"])
        );

        let changed_update = changed["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["kind"] == "findingCommentUpdate")
            .unwrap();
        assert_eq!(first["inputIdentity"], changed["inputIdentity"]);
        assert_ne!(first["reviewOutputDigest"], changed["reviewOutputDigest"]);
        assert_ne!(update["operationKey"], changed_update["operationKey"]);
        assert_ne!(update["desiredDigest"], changed_update["desiredDigest"]);
        assert_ne!(first["intentDigest"], changed["intentDigest"]);

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !matches!(
                request.method,
                wiremock::http::Method::POST
                    | wiremock::http::Method::PATCH
                    | wiremock::http::Method::PUT
                    | wiremock::http::Method::DELETE
            )
        }));
    }

    #[tokio::test]
    async fn publication_plan_routes_check_annotation_presentation_without_review_delivery() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "full_name": "owner/repo"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut finding = publication_finding(
            "annotation-1",
            "src/lib.rs",
            "The unchecked value reaches the protected operation.",
        );
        finding.severity = Severity::Error;
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![finding]);
        let snapshot = delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc");
        let plan = test_github(&server)
            .build_publication_plan(crate::forge::GitHubPublicationPlanRequest {
                controller_generation: "1",
                input_identity: PUBLICATION_INPUT_IDENTITY,
                envelope: &envelope,
                snapshot: &snapshot,
                publication_diff: Some(&placement_diff()),
                should_comment: true,
                duplicate_of_baseline: false,
                annotate_findings: true,
                advisory: CheckState::Success,
                gate: CheckState::Failure,
            })
            .await
            .unwrap();
        let operations = serde_json::to_value(plan).unwrap()["operations"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0]["kind"], "advisoryCheckCreate");
        assert_eq!(operations[1]["kind"], "advisoryCheckComplete");
        assert_eq!(operations[1]["annotations"][0]["path"], "src/lib.rs");
        assert_eq!(operations[1]["annotations"][0]["startLine"], 7);
        assert_eq!(
            operations[1]["dependencies"],
            serde_json::json!([operations[0]["operationKey"].clone()])
        );
        assert!(
            operations
                .iter()
                .all(|operation| operation["kind"] != "gateCheck")
        );

        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            !matches!(
                request.method,
                wiremock::http::Method::POST
                    | wiremock::http::Method::PATCH
                    | wiremock::http::Method::PUT
                    | wiremock::http::Method::DELETE
            )
        }));
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
                None,
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
                None,
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
                None,
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
        assert!(body.contains("<!-- postil-review:v2:"));
        assert!(body.len() <= super::MAX_REVIEW_BODY_BYTES);
    }

    #[tokio::test]
    async fn github_line_rejection_retries_on_the_nearest_changed_line() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "id": 78,
                        "commit_id": "aaaaaaaaaaaa"
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78/comments"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 601,
                    "body": super::finding_marker("inline-1")
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
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

        let mut github = test_github(&server);
        github.details_url = Some("https://postil.dev/orgs/acme/runs/run-1".into());
        let diff = placement_diff();
        let receipt = github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap();
        let finding = &receipt.findings[0];
        assert_eq!(finding.initial_outcome, FindingPublicationOutcome::Inline);
        assert!(!finding.inline_rejected);
        assert_eq!(finding.comment_id.as_deref(), Some("601"));

        let requests = server.received_requests().await.unwrap();
        let posts: Vec<_> = requests
            .iter()
            .filter(|request| request.method == reqwest::Method::POST)
            .collect();
        let fallback: serde_json::Value = serde_json::from_slice(&posts[1].body).unwrap();
        let comments = fallback["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 10);
        assert_eq!(comments[0]["side"], "RIGHT");
        assert!(comments[0].get("start_line").is_none());
        assert!(comments[0].get("start_side").is_none());
        assert!(
            comments[0]["body"]
                .as_str()
                .unwrap()
                .contains("This finding refers to line 7, outside the changed lines.")
        );
    }

    #[tokio::test]
    async fn github_line_rejection_falls_back_to_a_file_level_comment() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
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
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 601,
                "body": super::finding_marker("inline-1"),
                "commit_id": "aaaaaaaaaaaa"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
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
        let diff = file_only_placement_diff();

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap();

        let finding = &receipt.findings[0];
        assert_eq!(
            finding.initial_outcome,
            FindingPublicationOutcome::FileComment
        );
        assert!(!finding.inline_rejected);
        assert_eq!(finding.comment_id.as_deref(), Some("601"));
        let requests = server.received_requests().await.unwrap();
        let file_comment: serde_json::Value = requests
            .iter()
            .find(|request| {
                request.method == reqwest::Method::POST
                    && request.url.path() == "/repos/owner/repo/pulls/1/comments"
            })
            .unwrap()
            .body_json()
            .unwrap();
        assert_eq!(file_comment["subject_type"], "file");
        assert_eq!(file_comment["path"], "src/lib.rs");
        assert!(file_comment.get("line").is_none());
        let body = file_comment["body"].as_str().unwrap();
        assert!(body.contains("Finding inline-1"));
        assert!(body.contains("A concrete issue."));
        assert!(body.contains(super::FILE_LEVEL_COMMENT_MARKER));
        let summary_update: serde_json::Value = requests
            .iter()
            .find(|request| request.method == reqwest::Method::PUT)
            .unwrap()
            .body_json()
            .unwrap();
        assert!(
            summary_update["body"]
                .as_str()
                .unwrap()
                .contains("1 finding posted as file-level review comment")
        );
    }

    #[tokio::test]
    async fn github_line_rejection_includes_the_full_finding_when_the_file_is_absent() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
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
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
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
        let diff = unrelated_placement_diff();

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
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
        let review_posts = requests
            .iter()
            .filter(|request| {
                request.method == reqwest::Method::POST
                    && request.url.path() == "/repos/owner/repo/pulls/1/reviews"
            })
            .collect::<Vec<_>>();
        let fallback: serde_json::Value = review_posts[1].body_json().unwrap();
        assert!(fallback.get("comments").is_none());
        let summary = fallback["body"].as_str().unwrap();
        assert!(summary.contains("Location: `src/lib.rs:7`"));
        assert!(summary.contains("Finding inline-1"));
        assert!(summary.contains("A concrete issue."));
        assert!(summary.contains(&super::finding_marker("inline-1")));
    }

    #[tokio::test]
    async fn github_second_line_rejection_degrades_to_a_file_level_comment() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) < 2 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "id": 78,
                        "commit_id": "aaaaaaaaaaaa",
                        "comments": []
                    }))
                }
            })
            .expect(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 601,
                "body": super::finding_marker("inline-1"),
                "commit_id": "aaaaaaaaaaaa"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
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
        let diff = placement_diff();

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap();

        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::FileComment
        );
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("601"));
    }

    #[tokio::test]
    async fn github_partial_file_comment_retry_resumes_the_existing_review() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![
                publication_finding("first", "src/first.bin", "First issue."),
                publication_finding("second", "src/second.bin", "Second issue."),
            ],
        );
        let planned = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        let review_marker = super::review_marker(&planned.receipt_id);
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 7,
                    "body": format!(
                        "{}\n\n{}",
                        super::FILE_LEVEL_COMMENT_MARKER,
                        super::finding_marker("first")
                    ),
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 78,
                    "body": review_marker,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 602,
                "body": super::finding_marker("second"),
                "commit_id": "aaaaaaaaaaaa"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let diff = two_file_placement_diff();

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap();

        assert_eq!(receipt.review_id.as_deref(), Some("78"));
        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::Carried
        );
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("7"));
        assert_eq!(
            receipt.findings[1].initial_outcome,
            FindingPublicationOutcome::FileComment
        );
        assert_eq!(receipt.findings[1].comment_id.as_deref(), Some("602"));
        let requests = server.received_requests().await.unwrap();
        let review_posts = requests
            .iter()
            .filter(|request| {
                request.method == reqwest::Method::POST
                    && request.url.path() == "/repos/owner/repo/pulls/1/reviews"
            })
            .collect::<Vec<_>>();
        assert_eq!(review_posts.len(), 1, "the existing review is resumed");
        let initial: serde_json::Value = review_posts[0].body_json().unwrap();
        assert_eq!(initial["comments"].as_array().unwrap().len(), 1);
        assert_eq!(initial["comments"][0]["path"], "src/second.bin");
        let summary_update: serde_json::Value = requests
            .iter()
            .find(|request| request.method == reqwest::Method::PUT)
            .unwrap()
            .body_json()
            .unwrap();
        let summary = summary_update["body"].as_str().unwrap();
        assert!(summary.contains("1 finding posted as file-level review comment"));
        assert!(!summary.contains("2 findings posted"));
        assert!(!summary.contains("posted inline"));
    }

    #[tokio::test]
    async fn github_partial_review_without_its_line_comment_uses_file_level_delivery() {
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
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 78,
                    "body": review_marker,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 601,
                "body": super::finding_marker("inline-1"),
                "commit_id": "aaaaaaaaaaaa"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/78"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let diff = placement_diff();

        let receipt = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap();

        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::FileComment
        );
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("601"));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == reqwest::Method::POST
                        && request.url.path() == "/repos/owner/repo/pulls/1/reviews"
                })
                .count(),
            1
        );
        let file_comment: serde_json::Value = requests
            .iter()
            .find(|request| {
                request.method == reqwest::Method::POST
                    && request.url.path() == "/repos/owner/repo/pulls/1/comments"
            })
            .unwrap()
            .body_json()
            .unwrap();
        assert_eq!(file_comment["subject_type"], "file");
        assert_eq!(file_comment["path"], "src/lib.rs");
    }

    #[tokio::test]
    async fn github_generic_validation_failure_does_not_trigger_placement_fallback() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "Validation Failed",
                "errors": [{"field": "body", "code": "invalid"}]
            })))
            .expect(1)
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
        let diff = placement_diff();

        let error = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed validation"));
    }

    #[tokio::test]
    async fn github_unplaced_finding_must_fit_in_the_review_summary() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "Line could not be resolved"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let findings = (0..50)
            .map(|index| {
                let mut body = "x".repeat(crate::envelope::FINDING_PUBLIC_BODY_MAX_CHARS - 1);
                body.push('.');
                publication_finding(
                    &format!("inline-{index}"),
                    &format!("src/missing-{index}.rs"),
                    &body,
                )
            })
            .collect();
        let envelope = delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", findings);
        let diff = unrelated_placement_diff();

        let error = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot represent every unplaced finding"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn github_file_comment_response_must_identify_the_reviewed_head() {
        let server = MockServer::start().await;
        mount_current_delivery_snapshot(&server).await;
        mount_no_existing_review(&server).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
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
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 601,
                "body": super::finding_marker("inline-1")
            })))
            .expect(1)
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
        let diff = file_only_placement_diff();

        let error = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("did not identify the reviewed head")
        );
    }

    #[tokio::test]
    async fn github_rechecks_the_snapshot_before_each_file_comment() {
        let server = MockServer::start().await;
        mount_no_existing_review(&server).await;
        let pr_reads = Arc::new(AtomicUsize::new(0));
        let pr_response_reads = Arc::clone(&pr_reads);
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(move |_request: &wiremock::Request| {
                let current = pr_response_reads.fetch_add(1, Ordering::SeqCst) < 4;
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "title": "t", "body": "b", "state": "open", "merged": false,
                    "head": {"sha": if current { "aaaaaaaaaaaa" } else { "dddddddddddd" }},
                    "base": {"sha": "bbbbbbbbbbbb"},
                    "changed_files": 2
                }))
            })
            .expect(5)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccccccc"},
                "files": []
            })))
            .expect(4)
            .mount(&server)
            .await;
        let review_calls = Arc::new(AtomicUsize::new(0));
        let review_response_calls = Arc::clone(&review_calls);
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |_request: &wiremock::Request| {
                if review_response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(422)
                        .set_body_json(serde_json::json!({"message": "Line could not be resolved"}))
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
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 601,
                "body": super::finding_marker("first"),
                "commit_id": "aaaaaaaaaaaa"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![
                publication_finding("first", "src/first.bin", "First issue."),
                publication_finding("second", "src/second.bin", "Second issue."),
            ],
        );
        let diff = two_file_placement_diff();

        let error = test_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                Some(&diff),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("PR snapshot changed"));
    }

    #[test]
    fn github_file_level_comment_preserves_a_renamed_original_location() {
        let mut finding = publication_finding("renamed", "src/old.rs", "A concrete issue.");
        finding.line = 19;
        let diff = crate::diff::parse(
            "diff --git a/src/old.rs b/src/new.rs\n\
             similarity index 100%\n\
             rename from src/old.rs\n\
             rename to src/new.rs\n",
        );
        let path = super::publication_file_path(&diff, &finding.path).unwrap();

        let payload = super::file_level_comment(&finding, path, "aaaaaaaaaaaa");

        assert_eq!(payload["path"], "src/new.rs");
        assert!(
            payload["body"]
                .as_str()
                .unwrap()
                .contains("Original location: `src/old.rs:19`")
        );
    }

    #[test]
    fn pending_file_comments_are_unknown_in_durable_partial_receipts() {
        let envelope = delivery_envelope_with_findings(
            "aaaaaaaaaaaa",
            "cccccccccccc",
            vec![
                publication_finding("first", "src/first.bin", "First issue."),
                publication_finding("second", "src/second.bin", "Second issue."),
            ],
        );
        let mut receipt = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        receipt.findings[0].initial_outcome = FindingPublicationOutcome::FileComment;
        receipt.findings[0].comment_id = Some("601".into());
        receipt.findings[1].initial_outcome = FindingPublicationOutcome::FileComment;

        let durable = super::durable_partial_receipt(&receipt);

        assert_eq!(
            durable.findings[0].initial_outcome,
            FindingPublicationOutcome::FileComment
        );
        assert_eq!(durable.findings[0].comment_id.as_deref(), Some("601"));
        assert_eq!(
            durable.findings[1].initial_outcome,
            FindingPublicationOutcome::Unknown
        );
        assert!(durable.findings[1].comment_id.is_none());
    }

    #[test]
    fn github_line_rejection_classification_is_narrow() {
        assert!(super::github_review_rejected_line(
            r#"{"message":"Line could not be resolved"}"#
        ));
        assert!(super::github_review_rejected_line(
            r#"{"message":"Validation Failed","errors":[{"field":"start_line","code":"invalid"}]}"#
        ));
        assert!(!super::github_review_rejected_line(
            r#"{"message":"Validation Failed","errors":[{"field":"body","code":"invalid"}]}"#
        ));
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
                None,
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
                None,
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
                None,
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
        let review_error = github
            .post_review(&envelope, &snapshot, None)
            .await
            .unwrap_err();
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

        let review_error = github
            .post_review(&envelope, &snapshot, None)
            .await
            .unwrap_err();
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
                None,
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
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = request.body_json().expect("review body");
                ResponseTemplate::new(200).set_body_json(published_review_response(
                    &body,
                    99,
                    "aaaaaaaaaaaa",
                ))
            })
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
                None,
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

    fn published_review_response(
        request_body: &serde_json::Value,
        review_id: u64,
        commit_id: &str,
    ) -> serde_json::Value {
        let comments = request_body["comments"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(index, comment)| {
                serde_json::json!({
                    "id": index + 1,
                    "body": comment["body"],
                    "commit_id": commit_id,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "id": review_id,
            "commit_id": commit_id,
            "comments": comments,
        })
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

    #[tokio::test]
    async fn github_stops_review_summary_retries_when_the_snapshot_changes() {
        let server = MockServer::start().await;
        let pr_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured_reads = pr_reads.clone();
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(move |_request: &wiremock::Request| {
                let title = if captured_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
                {
                    "t"
                } else {
                    "changed"
                };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "title": title, "body": "b", "state": "open", "merged": false,
                    "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"},
                    "changed_files": 1
                }))
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/owner/repo/compare/bbbbbbbbbbbb...aaaaaaaaaaaa",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merge_base_commit": {"sha": "cccccccccccc"}, "files": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/99"))
            .respond_with(ResponseTemplate::new(503).insert_header("retry-after", "1"))
            .expect(1)
            .mount(&server)
            .await;

        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![dedup_finding()]);
        let mut receipt = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        receipt.review_id = Some("99".into());
        let marker = super::review_marker(&receipt.receipt_id);
        let error = dedup_github(&server)
            .finalize_review_summary(
                &envelope,
                &receipt,
                &marker,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("PR snapshot changed"));
        assert_eq!(pr_reads.load(std::sync::atomic::Ordering::SeqCst), 2);
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
        let planned = super::planned_review_receipt(&envelope, "aaaaaaaaaaaa");
        let review_marker = super::review_marker(&planned.receipt_id);
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/comments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 7,
                    "body": format!("**{}**\n\n{}", finding.title, finding_marker(&finding_id)),
                    "commit_id": "aaaaaaaaaaaa",
                    "subject_type": "line"
                }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": 11,
                    "body": review_marker,
                    "commit_id": "aaaaaaaaaaaa"
                }])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/owner/repo/pulls/1/reviews/11"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let captured = posted.clone();
        Mock::given(method("POST"))
            .and(path("/repos/owner/repo/pulls/1/reviews"))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = request.body_json().expect("review body");
                captured.lock().expect("capture lock").push(body.clone());
                ResponseTemplate::new(200).set_body_json(published_review_response(
                    &body,
                    11,
                    "aaaaaaaaaaaa",
                ))
            })
            .expect(0)
            .mount(&server)
            .await;

        let receipt = github
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                None,
            )
            .await
            .expect("the existing review and comment reconcile");

        assert!(
            posted.lock().expect("capture lock").is_empty(),
            "the duplicate review is not reposted"
        );
        assert_eq!(receipt.review_id.as_deref(), Some("11"));
        assert_eq!(receipt.findings[0].comment_id.as_deref(), Some("7"));
        assert_eq!(
            receipt.findings[0].initial_outcome,
            FindingPublicationOutcome::Carried
        );
        let requests = server.received_requests().await.unwrap();
        let summary_update: serde_json::Value = requests
            .iter()
            .find(|request| request.method == reqwest::Method::PUT)
            .unwrap()
            .body_json()
            .unwrap();
        let summary = summary_update["body"].as_str().unwrap();
        assert!(!summary.contains("posted inline"));
        assert!(!summary.contains("posted as file-level"));
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
                let body: serde_json::Value = request.body_json().expect("review body");
                captured.lock().expect("capture lock").push(body.clone());
                ResponseTemplate::new(200).set_body_json(published_review_response(
                    &body,
                    11,
                    "aaaaaaaaaaaa",
                ))
            })
            .mount(&server)
            .await;
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![dedup_finding()]);

        dedup_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                None,
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
                let body: serde_json::Value = request.body_json().expect("review body");
                captured.lock().expect("capture lock").push(body.clone());
                ResponseTemplate::new(200).set_body_json(published_review_response(
                    &body,
                    11,
                    "aaaaaaaaaaaa",
                ))
            })
            .mount(&server)
            .await;
        let envelope =
            delivery_envelope_with_findings("aaaaaaaaaaaa", "cccccccccccc", vec![dedup_finding()]);

        dedup_github(&server)
            .post_review(
                &envelope,
                &delivery_snapshot("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"),
                None,
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
