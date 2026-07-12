//! GitHub forge implementation (github.com and GHES via GITHUB_API_URL).

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::json;

use super::{
    CheckState, Forge, PrMeta, SummaryContext, ThreadKind, check_summary, check_title,
    wrap_plain_text,
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
    web_base: String,
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
        let web_base = valid_details_url(std::env::var("GITHUB_SERVER_URL").ok())
            .unwrap_or_else(|| "https://github.com".to_string());
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
            web_base: web_base.trim_end_matches('/').to_string(),
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
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        Err(anyhow!("GitHub {what} failed: {status}: {snippet}"))
    }
}

fn valid_details_url(value: Option<String>) -> Option<String> {
    value.filter(|value| {
        reqwest::Url::parse(value)
            .map(|url| matches!(url.scheme(), "http" | "https") && url.has_host())
            .unwrap_or(false)
    })
}

fn gate_title(envelope: &Envelope) -> &'static str {
    if envelope.gate.failing {
        "Merge gate failed"
    } else {
        "Merge gate passed"
    }
}

fn gate_summary(envelope: &Envelope) -> String {
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
            crate::envelope::finding_blocks_gate(
                f,
                &envelope.gate.fail_on,
                &envelope.gate.block_on_kinds,
                false,
            )
        })
        .map(|f| format!("- `{}:{}` {}", f.path, f.line, f.title))
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
        let commit_url = envelope.head_sha.as_deref().map(|sha| {
            format!(
                "{}/{}/{}/commit/{sha}",
                self.web_base, self.owner, self.repo
            )
        });
        check_summary(
            envelope,
            true,
            SummaryContext {
                commit_url: commit_url.as_deref(),
                details_url: self.details_url.as_deref(),
            },
        )
    }

    async fn fetch_pr_meta(&self) -> Result<PrMeta> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pulls/{}", self.pr)),
            )
            .send()
            .await
            .context("fetching PR metadata")?;
        let pr: PrResponse = Self::check_ok(resp, "PR fetch").await?.json().await?;
        Ok(PrMeta {
            title: pr.title,
            body: pr.body.unwrap_or_default(),
            head_sha: pr.head.sha,
            base_sha: pr.base.sha,
        })
    }

    async fn fetch_diff(&self) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/pulls/{}", self.pr)),
            )
            .header("Accept", "application/vnd.github.v3.diff")
            .send()
            .await
            .context("fetching PR diff")?;
        Ok(Self::check_ok(resp, "diff fetch").await?.text().await?)
    }

    async fn fetch_diff_since(&self, since_sha: &str, head_sha: &str) -> Result<String> {
        let resp = self
            .request(
                reqwest::Method::GET,
                self.url(&format!("/compare/{since_sha}...{head_sha}")),
            )
            .header("Accept", "application/vnd.github.v3.diff")
            .send()
            .await
            .context("fetching incremental diff")?;
        Ok(Self::check_ok(resp, "compare fetch").await?.text().await?)
    }

    async fn post_review(&self, summary: &str, findings: &[Finding], head_sha: &str) -> Result<()> {
        // Every carried finding is already visible in an earlier Postil review.
        // Check-runs still receive the complete envelope, but posting the same
        // visible set as another PR review is duplicate noise.
        if !findings.is_empty() && findings.iter().all(filter::is_carried) {
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
        Self::check_ok(resp, "review post").await?;
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
            let run: CheckRun = Self::check_ok(resp, "check-run create")
                .await?
                .json()
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
                let message: String = f.body.chars().take(800).collect();
                json!({
                    "path": f.path,
                    "start_line": f.line,
                    "end_line": f.end_line.unwrap_or(f.line),
                    "annotation_level": match f.severity {
                        Severity::Info => "notice",
                        Severity::Warn => "warning",
                        Severity::Error => "failure",
                    },
                    "title": f.title,
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
                self.review_summary(envelope)
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
                .request(
                    reqwest::Method::PATCH,
                    self.url(&format!("/check-runs/{id}")),
                )
                .json(&body)
                .send()
                .await
                .with_context(|| format!("completing check-run {name}"))?;
            Self::check_ok(resp, "check-run complete").await?;
        }
        Ok(())
    }

    /// Title and body of an issue or PR (the issues API covers both, so `kind`
    /// is not needed here).
    async fn fetch_thread(&self, number: u64, _kind: ThreadKind) -> Result<(String, String)> {
        let resp = self
            .request(reqwest::Method::GET, self.url(&format!("/issues/{number}")))
            .send()
            .await
            .context("fetching issue")?;
        let v: serde_json::Value = Self::check_ok(resp, "issue fetch").await?.json().await?;
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

#[cfg(test)]
mod tests {
    use super::{gate_summary, valid_details_url};
    use crate::envelope::{Envelope, Finding, Gate, Kind, Severity, Usage};

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
    fn gate_summary_reports_operational_failure_without_inventing_blockers() {
        let mut env = Envelope {
            version: 1,
            summary: String::new(),
            silent: false,
            findings: vec![],
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
            duration_ms: 0,
            base_sha: None,
            head_sha: None,
            since_sha: None,
        };
        env.findings
            .push(crate::envelope::provider_error_finding("timeout"));

        assert_eq!(
            gate_summary(&env),
            "Merge gate failed under the configured operational error policy (failOn: never).\n"
        );
    }
}
