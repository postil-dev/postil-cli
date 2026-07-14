//! GitHub forge implementation (github.com and GHES via GITHUB_API_URL).

use anyhow::{Context, Result, anyhow, ensure};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    CheckState, Forge, PrMeta, SummaryContext, ThreadKind, check_summary, check_title,
    only_operational_findings, valid_details_url, wrap_plain_text,
};
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

    async fn check_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let request_id = github_request_id(resp.headers()).unwrap_or_else(|| "none".to_string());
        Err(anyhow!(
            "GitHub {what} failed: {status} (request id {request_id})"
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

    async fn pull_files(&self, expected: usize) -> Result<Vec<PullFile>> {
        const PAGE_SIZE: usize = 100;
        const MAX_FILES: usize = 3_000;
        ensure!(
            expected <= MAX_FILES,
            "GitHub PR has {expected} changed files, beyond the complete files API limit of {MAX_FILES}"
        );
        let mut files = Vec::with_capacity(expected);
        let mut page = 1usize;
        loop {
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
            let batch: Vec<PullFile> = super::bounded_response_json(
                Self::check_ok(response, "PR files fetch").await?,
                "GitHub PR files page",
            )
            .await?;
            let count = batch.len();
            ensure!(
                count <= PAGE_SIZE,
                "GitHub PR files page exceeded requested size"
            );
            files.extend(batch);
            ensure!(
                files.len() <= expected && files.len() <= MAX_FILES,
                "GitHub PR files pagination exceeded the declared changed-file count"
            );
            if count < PAGE_SIZE {
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

    #[cfg(debug_assertions)]
    fn is_loopback_test_api(&self) -> bool {
        reqwest::Url::parse(&self.api_base)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
    }

    #[cfg(debug_assertions)]
    async fn test_raw_diff(&self, path: &str, context: &str) -> Result<String> {
        let response = self
            .send_retryable(
                self.request(reqwest::Method::GET, self.url(path))
                    .header("Accept", "application/vnd.github.v3.diff"),
                context,
            )
            .await?;
        super::bounded_response_text(Self::check_ok(response, context).await?, context).await
    }
}

fn render_complete_file_patches(files: Vec<PullFile>, context: &str) -> Result<String> {
    let mut seen = HashSet::with_capacity(files.len());
    let mut output = String::new();
    for file in files {
        ensure!(
            seen.insert(file.filename.clone()),
            "{context} returned duplicate file {}",
            file.filename
        );
        let old_path = file.previous_filename.as_deref().unwrap_or(&file.filename);
        let old_marker = crate::diff::display_path(&format!("a/{old_path}"));
        let new_marker = crate::diff::display_path(&format!("b/{}", file.filename));
        let mut section = format!("diff --git {old_marker} {new_marker}\n");
        match file.status.as_str() {
            "added" => section.push_str(&format!("--- /dev/null\n+++ {new_marker}\n")),
            "removed" => section.push_str(&format!("--- {old_marker}\n+++ /dev/null\n")),
            "renamed" => {
                section.push_str(&format!(
                    "rename from {}\nrename to {}\n--- {old_marker}\n+++ {new_marker}\n",
                    crate::diff::display_path(old_path),
                    crate::diff::display_path(&file.filename)
                ));
            }
            "modified" | "changed" | "copied" => {
                section.push_str(&format!("--- {old_marker}\n+++ {new_marker}\n"));
            }
            other => {
                return Err(anyhow!(
                    "{context} returned unsupported file status {other:?}"
                ));
            }
        }
        match file.patch {
            Some(patch) => {
                ensure!(
                    patch.starts_with("@@") || patch.is_empty(),
                    "{context} returned a malformed patch for {}",
                    file.filename
                );
                section.push_str(&patch);
                if !section.ends_with('\n') {
                    section.push('\n');
                }
            }
            None if file.changes == 0 => {
                section.push_str(&format!(
                    "Binary files {old_marker} and {new_marker} differ\n"
                ));
            }
            None => {
                return Err(anyhow!(
                    "{context} omitted the patch for changed text file {}; refusing an incomplete review",
                    file.filename
                ));
            }
        }
        let next_len = output
            .len()
            .checked_add(section.len())
            .ok_or_else(|| anyhow!("{context} reconstructed diff size overflowed"))?;
        ensure!(
            next_len <= crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES,
            "{context} reconstructed diff exceeds the {} byte acquisition limit",
            crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES
        );
        output.push_str(&section);
    }
    Ok(output)
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
    head: RefObj,
    base: RefObj,
    #[serde(default)]
    changed_files: usize,
}

#[derive(Debug, Deserialize)]
struct PullFile {
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
    #[serde(default)]
    patch: Option<String>,
    #[serde(default)]
    changes: usize,
}

#[derive(Deserialize)]
struct CompareResponse {
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
        Ok(PrMeta {
            title: pr.title,
            body: pr.body.unwrap_or_default(),
            head_sha: pr.head.sha,
            base_sha: pr.base.sha,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        #[cfg(debug_assertions)]
        if self.is_loopback_test_api() {
            return self
                .test_raw_diff(&format!("/pulls/{}", self.pr), "test diff fetch")
                .await;
        }
        let meta_response = self
            .send_retryable(
                self.request(
                    reqwest::Method::GET,
                    self.url(&format!("/pulls/{}", self.pr)),
                ),
                "PR diff metadata fetch",
            )
            .await?;
        let meta: PrResponse = super::bounded_response_json(
            Self::check_ok(meta_response, "PR diff metadata fetch").await?,
            "GitHub PR diff metadata",
        )
        .await?;
        let files = self.pull_files(meta.changed_files).await?;
        render_complete_file_patches(files, "GitHub PR files API")
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        #[cfg(debug_assertions)]
        if self.is_loopback_test_api() {
            return self
                .test_raw_diff(
                    &format!("/compare/{since_sha}...{head_sha}"),
                    "test compare fetch",
                )
                .await;
        }
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
        // GitHub documents that compare responses include at most 300 files
        // and expose no complete file count. Exactly 300 is therefore
        // ambiguous and must fail closed.
        ensure!(
            compare.files.len() < 300,
            "GitHub compare reached the 300-file response cap; refusing an incomplete incremental review"
        );
        render_complete_file_patches(compare.files, "GitHub compare API")
    }

    async fn post_review(&self, summary: &str, findings: &[Finding], head_sha: &str) -> Result<()> {
        if only_operational_findings(findings) {
            return Ok(());
        }
        // Every carried finding is already visible in an earlier Postil review.
        // Check-runs still receive the complete envelope, but posting the same
        // visible set as another PR review is duplicate noise.
        if !findings.is_empty() && findings.iter().all(filter::is_carried) {
            return Ok(());
        }
        let current_head = self.fetch_pr_meta().await?.head_sha;
        if current_head != head_sha {
            eprintln!(
                "postil: github review delivery skipped because PR head changed reviewed_head={} current_head={}",
                short_sha(head_sha),
                short_sha(&current_head),
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
            "body": if summary.is_empty() {
                "Postil completed the review, but GitHub could not attach its inline comments."
            } else {
                summary
            },
        });
        let fallback = self
            .request(
                reqwest::Method::POST,
                self.url(&format!("/pulls/{}/reviews", self.pr)),
            )
            .json(&summary_only)
            .send()
            .await
            .context("posting summary-only review")?;
        Self::check_ok(fallback, "summary-only review post").await?;
        Ok(())
    }

    async fn start_checks(&self, head_sha: &str) -> Result<(String, String)> {
        let mut ids = Vec::with_capacity(2);
        for name in ["postil/review", "postil/gate"] {
            let mut body = json!({
                "name": name,
                "head_sha": head_sha,
                "status": "in_progress",
            });
            self.add_details_url(&mut body);
            let resp = self
                .request(reqwest::Method::POST, self.url("/check-runs"))
                .json(&body)
                .send()
                .await
                .with_context(|| format!("creating check-run {name}"))?;
            let run: CheckRun = super::bounded_response_json(
                Self::check_ok(resp, "check-run create").await?,
                "GitHub check-run",
            )
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

fn valid_object_id(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{
        GitHub, PullFile, gate_summary, github_retry_delay_at, github_retryable_response,
        github_transport_retry_delay, only_operational_findings, render_complete_file_patches,
        valid_details_url,
    };
    use crate::envelope::{Envelope, Finding, Gate, Kind, Severity, Usage};
    use crate::forge::{CheckState, Forge};
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    async fn github_review_is_not_posted_after_the_pr_head_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/repo/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "t", "body": "b",
                "head": {"sha": "bbbbbbbbbbbb"}, "base": {"sha": "base"}
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
            .post_review("Summary", &[finding], "aaaaaaaaaaaa")
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
                "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "base"}
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
            usage_accounting_complete: true,
            duration_ms: 0,
            base_sha: Some("base".into()),
            head_sha: Some("aaaaaaaaaaaa".into()),
            since_sha: None,
        };

        github
            .post_review(
                "One finding needs attention.",
                std::slice::from_ref(&finding),
                "aaaaaaaaaaaa",
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

    #[test]
    fn complete_file_patch_reconstruction_rejects_omitted_text() {
        let omitted = PullFile {
            filename: "src/a.rs".into(),
            status: "modified".into(),
            previous_filename: None,
            patch: None,
            changes: 2,
        };
        assert!(render_complete_file_patches(vec![omitted], "test").is_err());

        let complete = PullFile {
            filename: "src/a.rs".into(),
            status: "modified".into(),
            previous_filename: None,
            patch: Some("@@ -1 +1 @@\n-old\n+new".into()),
            changes: 2,
        };
        let diff = render_complete_file_patches(vec![complete], "test").unwrap();
        let parsed = crate::diff::parse(&diff);
        assert!(crate::diff::DiffIndex::build(&parsed).contains("src/a.rs", 1));
    }
}
