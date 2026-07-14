//! Bitbucket forge implementation (bitbucket.org Cloud; Data Center via
//! `BITBUCKET_API_URL`).
//!
//! Auth: `BITBUCKET_TOKEN`. If `BITBUCKET_USER` is set the token is treated as
//! an app password and sent via HTTP Basic; otherwise it is a workspace/repo
//! access token sent as a Bearer credential.
//!
//! Checks map to commit build statuses. Bitbucket has no `neutral`, so an
//! operational error marks the gate `FAILED` — fail closed, never grey.
//!
//! Incremental diffs are disabled unless `POSTIL_ENABLE_BITBUCKET_INCREMENTAL=1`
//! is present. Bitbucket's compare endpoint uses the opposite two-dot order from
//! `git diff`; keep the path available for verified deployments without making
//! unverified hosted runs trust it by default.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use super::{CheckState, Forge, PrMeta, ThreadKind, check_summary, check_title};
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
    source: Endpoint,
    destination: Endpoint,
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
        let snippet = super::bounded_error_snippet(resp).await;
        Err(anyhow!("Bitbucket {what} failed: {status}: {snippet}"))
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
        Ok(Self::check_ok(resp, "PR fetch").await?.json().await?)
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
}

impl Forge for Bitbucket {
    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let pr = self.pr_meta().await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.summary.map(|s| s.raw).unwrap_or_default(),
            head_sha: pr.source.commit.hash,
            base_sha: pr.destination.commit.hash,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pullrequests/{}/diff", self.pr)),
            )
            .send()
            .await
            .context("fetching PR diff")?;
        super::bounded_response_text(
            Self::check_ok(resp, "diff fetch").await?,
            "Bitbucket PR diff",
        )
        .await
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        if std::env::var(ENABLE_INCREMENTAL_ENV).as_deref() != Ok("1") {
            return Err(anyhow!(
                "Bitbucket incremental review is disabled because the compare-diff path has \
                 not been verified for this deployment; set {ENABLE_INCREMENTAL_ENV}=1 only \
                 after validating /diff/{{head}}..{{since}} against the target Bitbucket API"
            ));
        }
        // Bitbucket's `diff/{spec}` two-dot form is `{to}..{from}`: it renders
        // the changes that take the repo from `from` to `to`. We want everything
        // new between `since` and `head`, so `to` = head and `from` = since.
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/diff/{head_sha}..{since_sha}")),
            )
            .send()
            .await
            .context("fetching incremental diff")?;
        super::bounded_response_text(
            Self::check_ok(resp, "compare fetch").await?,
            "Bitbucket compare diff",
        )
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
        gate: CheckState,
        envelope: &Envelope,
    ) -> Result<()> {
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
        self.set_status(&head, "postil/gate", map(gate), &gate_desc)
            .await?;
        Ok(())
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
