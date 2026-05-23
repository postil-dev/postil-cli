use std::{env, fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warn => 1,
            Self::Error => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OnClean {
    Approve,
    Skip,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReviewConfig {
    pub enabled: bool,
    pub on_clean: OnClean,
    pub auto_merge: bool,
    pub required_checks: Vec<String>,
    pub auto_merge_timeout_ms: u64,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            on_clean: OnClean::Skip,
            auto_merge: false,
            required_checks: Vec::new(),
            auto_merge_timeout_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReviewerConfig {
    pub tone: String,
    pub focus: Vec<String>,
}

impl Default for ReviewerConfig {
    fn default() -> Self {
        Self {
            tone: "neutral".to_string(),
            focus: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RepoReviewConfig {
    pub enabled: bool,
    pub ignore: Vec<String>,
    pub severity_threshold: Severity,
    pub max_findings: usize,
    pub reviewer: ReviewerConfig,
    pub review: ReviewConfig,
    pub required_checks: Vec<String>,
    pub auto_merge_timeout_ms: Option<u64>,
}

impl Default for RepoReviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ignore: Vec::new(),
            severity_threshold: Severity::Info,
            max_findings: 25,
            reviewer: ReviewerConfig::default(),
            review: ReviewConfig::default(),
            required_checks: Vec::new(),
            auto_merge_timeout_ms: None,
        }
    }
}

impl RepoReviewConfig {
    pub fn normalize(mut self) -> Self {
        if !self.required_checks.is_empty() && self.review.required_checks.is_empty() {
            self.review.required_checks = self.required_checks.clone();
        }
        if let Some(timeout) = self.auto_merge_timeout_ms {
            self.review.auto_merge_timeout_ms = timeout;
        }
        self
    }

    pub fn from_text(path: &str, text: &str) -> Result<Self> {
        let parsed: Self = if path.ends_with(".json") {
            serde_json::from_str(text).with_context(|| format!("parse JSON config {path}"))?
        } else {
            serde_yaml::from_str(text).with_context(|| format!("parse YAML config {path}"))?
        };
        Ok(parsed.normalize())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct RuntimeFileConfig {
    pub github_token: Option<String>,
    pub github_repository: Option<String>,
    pub github_event_path: Option<String>,
    pub github_api_url: Option<String>,
    pub openrouter_api_key: Option<String>,
    pub openrouter_api_url: Option<String>,
    pub review_model: Option<String>,
    pub review_model_cascade: Option<String>,
    pub fail_on: Option<Severity>,
    pub no_inline: Option<bool>,
    pub diff_limit: Option<usize>,
    pub check_name: Option<String>,
    pub check_run_id: Option<u64>,
    pub repo: Option<String>,
    pub pr: Option<u64>,
    pub sha: Option<String>,
    pub review: Option<RepoReviewConfig>,
}

impl RuntimeFileConfig {
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        if path.extension().and_then(|v| v.to_str()) == Some("json") {
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
        } else {
            serde_yaml::from_str(&text).with_context(|| format!("parse {}", path.display()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub github_token: Option<String>,
    pub github_repository: Option<String>,
    pub github_event_path: Option<String>,
    pub github_api_url: String,
    pub openrouter_api_key: String,
    pub openrouter_api_url: String,
    pub review_model: String,
    pub review_model_cascade: Option<String>,
    pub fail_on: Severity,
    pub no_inline: bool,
    pub diff_limit: usize,
    pub check_name: String,
    pub check_run_id: Option<u64>,
    pub repo: Option<String>,
    pub pr: Option<u64>,
    pub sha: Option<String>,
    pub file_review_config: Option<RepoReviewConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
    pub github_token: Option<String>,
    pub github_repository: Option<String>,
    pub github_event_path: Option<String>,
    pub github_api_url: Option<String>,
    pub openrouter_api_key: Option<String>,
    pub openrouter_api_url: Option<String>,
    pub review_model: Option<String>,
    pub review_model_cascade: Option<String>,
    pub fail_on: Option<Severity>,
    pub no_inline: Option<bool>,
    pub diff_limit: Option<usize>,
    pub check_name: Option<String>,
    pub check_run_id: Option<u64>,
    pub repo: Option<String>,
    pub pr: Option<u64>,
    pub sha: Option<String>,
}

impl RuntimeConfig {
    pub fn load(file: Option<RuntimeFileConfig>, flags: RuntimeOverrides) -> Result<Self> {
        let file = file.unwrap_or_default();
        let github_token = pick_optional(
            flags.github_token,
            env::var("GITHUB_TOKEN").ok(),
            file.github_token,
        );
        let openrouter_api_key = pick_required(
            flags.openrouter_api_key,
            env::var("OPENROUTER_API_KEY").ok(),
            file.openrouter_api_key,
            "OPENROUTER_API_KEY",
            true,
        )?;

        Ok(Self {
            github_token,
            github_repository: flags
                .github_repository
                .or_else(|| env::var("GITHUB_REPOSITORY").ok())
                .or(file.github_repository),
            github_event_path: flags
                .github_event_path
                .or_else(|| env::var("GITHUB_EVENT_PATH").ok())
                .or(file.github_event_path),
            github_api_url: flags
                .github_api_url
                .or_else(|| env::var("POSTIL_GITHUB_API_URL").ok())
                .or(file.github_api_url)
                .unwrap_or_else(|| "https://api.github.com".to_string()),
            openrouter_api_url: flags
                .openrouter_api_url
                .or_else(|| env::var("POSTIL_OPENROUTER_API_URL").ok())
                .or(file.openrouter_api_url)
                .unwrap_or_else(|| "https://openrouter.ai/api/v1".to_string()),
            openrouter_api_key,
            review_model: flags
                .review_model
                .or_else(|| env::var("REVIEW_MODEL").ok())
                .or(file.review_model)
                .unwrap_or_else(|| "deepseek/deepseek-v4-pro".to_string()),
            review_model_cascade: flags
                .review_model_cascade
                .or_else(|| env::var("REVIEW_MODEL_CASCADE").ok())
                .or(file.review_model_cascade),
            fail_on: flags
                .fail_on
                .or_else(|| severity_env("POSTIL_FAIL_ON"))
                .or(file.fail_on)
                .unwrap_or(Severity::Error),
            no_inline: flags.no_inline.or(file.no_inline).unwrap_or(false),
            diff_limit: flags.diff_limit.or(file.diff_limit).unwrap_or(120_000),
            check_name: flags
                .check_name
                .or_else(|| env::var("POSTIL_CHECK_NAME").ok())
                .or(file.check_name)
                .unwrap_or_else(|| "postil/review".to_string()),
            check_run_id: flags.check_run_id.or(file.check_run_id),
            repo: flags.repo.or(file.repo),
            pr: flags.pr.or(file.pr),
            sha: flags.sha.or(file.sha),
            file_review_config: file.review.map(RepoReviewConfig::normalize),
        })
    }

    pub fn models(&self) -> Vec<String> {
        let raw = self
            .review_model_cascade
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(&self.review_model);
        let models: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if models.is_empty() {
            vec![self.review_model.clone()]
        } else {
            models
        }
    }
}

fn pick_required(
    flag: Option<String>,
    env: Option<String>,
    file: Option<String>,
    name: &str,
    required: bool,
) -> Result<String> {
    let value = flag.or(env).or(file).filter(|v| !v.trim().is_empty());
    if required {
        value.ok_or_else(|| anyhow!("{name} is not set"))
    } else {
        Ok(value.unwrap_or_default())
    }
}

fn pick_optional(
    flag: Option<String>,
    env: Option<String>,
    file: Option<String>,
) -> Option<String> {
    flag.or(env).or(file).filter(|v| !v.trim().is_empty())
}

fn severity_env(name: &str) -> Option<Severity> {
    env::var(name).ok().and_then(|v| match v.trim() {
        "info" => Some(Severity::Info),
        "warn" => Some(Severity::Warn),
        "error" => Some(Severity::Error),
        _ => None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewTarget {
    pub owner: String,
    pub repo: String,
    pub pull_number: u64,
    pub head_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubEvent {
    pull_request: Option<EventPullRequest>,
}

#[derive(Debug, Deserialize)]
struct EventPullRequest {
    number: Option<u64>,
    head: Option<EventHead>,
}

#[derive(Debug, Deserialize)]
struct EventHead {
    sha: Option<String>,
}

pub fn resolve_target(cfg: &RuntimeConfig) -> Result<ReviewTarget> {
    let event = cfg.github_event_path.as_ref().and_then(|path| {
        let text = fs::read_to_string(path).ok()?;
        serde_json::from_str::<GithubEvent>(&text).ok()
    });
    let repo_full = cfg
        .repo
        .as_ref()
        .or(cfg.github_repository.as_ref())
        .ok_or_else(|| anyhow!("repo unknown: set --repo, config repo, or GITHUB_REPOSITORY"))?;
    let (owner, repo) = repo_full
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid repo: {repo_full}"))?;
    if owner.is_empty() || repo.is_empty() {
        bail!("invalid repo: {repo_full}");
    }
    let pull_number = cfg
        .pr
        .or_else(|| event.as_ref()?.pull_request.as_ref()?.number)
        .ok_or_else(|| anyhow!("pr unknown: set --pr, config pr, or run via pull_request event"))?;
    if pull_number == 0 {
        bail!("pr unknown: set --pr, config pr, or run via pull_request event");
    }
    let head_sha = cfg
        .sha
        .clone()
        .or_else(|| event?.pull_request?.head?.sha)
        .filter(|v| !v.trim().is_empty());
    Ok(ReviewTarget {
        owner: owner.to_string(),
        repo: repo.to_string(),
        pull_number,
        head_sha,
    })
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct CoderabbitConfig {
    pub reviews: Option<CoderabbitReviews>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct CoderabbitReviews {
    pub path_filters: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct KodoConfig {
    pub exclude: Vec<String>,
    pub severity: Option<Severity>,
}

pub fn translate_coderabbit(text: &str) -> Result<RepoReviewConfig> {
    let parsed: CoderabbitConfig = serde_yaml::from_str(text).context("parse CodeRabbit config")?;
    let ignore = parsed
        .reviews
        .map(|r| {
            r.path_filters
                .into_iter()
                .filter_map(|p| p.strip_prefix('!').map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(RepoReviewConfig {
        ignore,
        ..RepoReviewConfig::default()
    })
}

pub fn translate_kodo(text: &str) -> Result<RepoReviewConfig> {
    let parsed: KodoConfig = serde_yaml::from_str(text).context("parse Kodo config")?;
    Ok(RepoReviewConfig {
        ignore: parsed.exclude,
        severity_threshold: parsed.severity.unwrap_or(Severity::Info),
        ..RepoReviewConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_reviews_skip_by_default() {
        assert_eq!(ReviewConfig::default().on_clean, OnClean::Skip);
    }

    #[test]
    fn local_runtime_does_not_require_github_token() {
        let cfg = RuntimeConfig::load(
            Some(RuntimeFileConfig {
                openrouter_api_key: Some("test-openrouter".to_string()),
                ..RuntimeFileConfig::default()
            }),
            RuntimeOverrides::default(),
        )
        .unwrap();
        assert!(cfg.diff_limit > 0);
    }
}
