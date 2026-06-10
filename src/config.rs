//! Runtime configuration. Single resolution function with explicit precedence:
//!
//!   1. CLI flags
//!   2. Environment variables
//!   3. `--config` file
//!   4. Built-in defaults
//!
//! This is the engine's "where do I review and how" config. Per-repo policy
//! (`.postil.yaml`) is loaded separately by `repo_config.rs` and applied as a
//! post-filter on findings.

use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::cli::ReviewArgs;
use crate::envelope::Severity;

pub const DEFAULT_MODEL: &str = "deepseek/deepseek-v4-pro";
pub const DEFAULT_CHECK_NAME: &str = "postil/review";
pub const DEFAULT_DIFF_LIMIT: usize = 120_000;
pub const DEFAULT_GITHUB_API: &str = "https://api.github.com";
pub const DEFAULT_OPENROUTER_API: &str = "https://openrouter.ai/api/v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct FileConfig {
    pub repo: Option<String>,
    pub pr: Option<u64>,
    pub sha: Option<String>,
    pub review_model: Option<String>,
    pub review_model_cascade: Option<String>,
    pub fail_on: Option<String>,
    pub no_inline: Option<bool>,
    pub github_token: Option<String>,
    pub openrouter_api_key: Option<String>,
    pub github_api_url: Option<String>,
    pub openrouter_api_url: Option<String>,
    pub diff_limit: Option<usize>,
    pub check_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub source: Source,
    pub fail_on: Severity,
    pub no_inline: bool,
    pub github_token: Option<String>,
    pub openrouter_api_key: Option<String>,
    pub review_model: String,
    pub model_cascade: Vec<String>,
    pub github_api_url: String,
    pub openrouter_api_url: String,
    pub diff_limit: usize,
    pub check_name: String,
    pub check_run_id: Option<u64>,
    pub output_json: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum Source {
    /// Review the GitHub pull-request `owner/name#pr@sha`.
    GithubPr { repo: String, pr: u64, sha: String },
    /// Review the locally-staged diff.
    Staged,
    /// Review the diff against a local base ref.
    LocalBase { base: String },
    /// Review a unified-diff file directly.
    DiffFile { path: PathBuf },
}

impl RuntimeConfig {
    pub fn resolve(args: &ReviewArgs) -> anyhow::Result<Self> {
        // Step 1: load --config file if any (lowest priority above defaults).
        let file: FileConfig = match &args.config {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    serde_json::from_str(&text)?
                } else {
                    serde_yaml::from_str(&text)?
                }
            }
            None => FileConfig::default(),
        };

        // Step 2: pick source.
        let source = pick_source(args, &file)?;

        // Step 3: layer values. Macro keeps precedence consistent.
        macro_rules! pick {
            ($cli:expr, $env:expr, $file:expr, $default:expr) => {{
                $cli.clone()
                    .or_else(|| std::env::var($env).ok().filter(|v| !v.is_empty()))
                    .or_else(|| $file.clone())
                    .unwrap_or_else(|| $default.to_string())
            }};
        }

        let github_token = args
            .github_token
            .clone()
            .or_else(|| env_nonempty("GITHUB_TOKEN"))
            .or(file.github_token.clone());
        let openrouter_api_key = args
            .openrouter_api_key
            .clone()
            .or_else(|| env_nonempty("OPENROUTER_API_KEY"))
            .or(file.openrouter_api_key.clone());

        let review_model = pick!(
            args.review_model,
            "REVIEW_MODEL",
            file.review_model,
            DEFAULT_MODEL
        );

        let cascade_raw = args
            .review_model_cascade
            .clone()
            .or_else(|| env_nonempty("REVIEW_MODEL_CASCADE"))
            .or(file.review_model_cascade.clone())
            .unwrap_or_default();
        let model_cascade: Vec<String> = cascade_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let fail_on_str = args
            .fail_on
            .clone()
            .or_else(|| env_nonempty("POSTIL_FAIL_ON"))
            .or(file.fail_on.clone())
            .unwrap_or_else(|| "error".to_string());
        let fail_on = Severity::parse(&fail_on_str)
            .with_context(|| format!("invalid fail-on value: {fail_on_str}"))?;

        let no_inline = args.no_inline || file.no_inline.unwrap_or(false);

        let github_api_url = pick!(
            args.github_api_url,
            "POSTIL_GITHUB_API_URL",
            file.github_api_url,
            DEFAULT_GITHUB_API
        );
        let openrouter_api_url = pick!(
            args.openrouter_api_url,
            "POSTIL_OPENROUTER_API_URL",
            file.openrouter_api_url,
            DEFAULT_OPENROUTER_API
        );

        let diff_limit = if args.diff_limit != DEFAULT_DIFF_LIMIT {
            args.diff_limit
        } else {
            file.diff_limit.unwrap_or(DEFAULT_DIFF_LIMIT)
        };

        let check_name = pick!(
            args.check_name,
            "POSTIL_CHECK_NAME",
            file.check_name,
            DEFAULT_CHECK_NAME
        );

        Ok(RuntimeConfig {
            source,
            fail_on,
            no_inline,
            github_token,
            openrouter_api_key,
            review_model,
            model_cascade,
            github_api_url,
            openrouter_api_url,
            diff_limit,
            check_name,
            check_run_id: args.check_run_id,
            output_json: args.output_json.clone(),
        })
    }

    pub fn is_remote(&self) -> bool {
        matches!(self.source, Source::GithubPr { .. })
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn pick_source(args: &ReviewArgs, file: &FileConfig) -> anyhow::Result<Source> {
    // Local modes win when explicitly set — they conflict with --repo/--pr/--sha at the CLI layer.
    if args.staged {
        return Ok(Source::Staged);
    }
    if let Some(base) = &args.base {
        return Ok(Source::LocalBase { base: base.clone() });
    }
    if let Some(path) = &args.diff_file {
        return Ok(Source::DiffFile { path: path.clone() });
    }

    let repo = args
        .repo
        .clone()
        .or(file.repo.clone())
        .or_else(|| env_nonempty("GITHUB_REPOSITORY"));
    let pr = args.pr.or(file.pr).or_else(read_pr_from_event);
    let sha = args
        .sha
        .clone()
        .or(file.sha.clone())
        .or_else(read_sha_from_event);

    match (repo, pr, sha) {
        (Some(repo), Some(pr), Some(sha)) => Ok(Source::GithubPr { repo, pr, sha }),
        _ => anyhow::bail!(
            "no review source: pass --staged / --base / --diff-file for local review, or --repo/--pr/--sha (or GITHUB_REPOSITORY + GITHUB_EVENT_PATH) for remote review"
        ),
    }
}

fn read_pr_from_event() -> Option<u64> {
    let path = std::env::var("GITHUB_EVENT_PATH").ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("pull_request")
        .and_then(|p| p.get("number"))
        .and_then(|n| n.as_u64())
        .or_else(|| v.get("number").and_then(|n| n.as_u64()))
}

fn read_sha_from_event() -> Option<String> {
    let path = std::env::var("GITHUB_EVENT_PATH").ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("pull_request")
        .and_then(|p| p.get("head"))
        .and_then(|h| h.get("sha"))
        .and_then(|s| s.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ReviewArgs;

    fn args() -> ReviewArgs {
        ReviewArgs {
            diff_limit: DEFAULT_DIFF_LIMIT,
            ..Default::default()
        }
    }

    #[test]
    #[serial_test::serial]
    fn defaults_resolve_for_staged() {
        unsafe {
            std::env::remove_var("REVIEW_MODEL");
        }
        let a = ReviewArgs {
            staged: true,
            diff_limit: DEFAULT_DIFF_LIMIT,
            ..Default::default()
        };
        let c = RuntimeConfig::resolve(&a).unwrap();
        assert_eq!(c.review_model, DEFAULT_MODEL);
        assert_eq!(c.fail_on, Severity::Error);
        assert_eq!(c.check_name, DEFAULT_CHECK_NAME);
        assert!(matches!(c.source, Source::Staged));
    }

    #[test]
    #[serial_test::serial]
    fn flag_overrides_env_and_file() {
        unsafe {
            std::env::set_var("REVIEW_MODEL", "from-env");
        }
        let a = ReviewArgs {
            staged: true,
            review_model: Some("from-flag".to_string()),
            diff_limit: DEFAULT_DIFF_LIMIT,
            ..Default::default()
        };
        let c = RuntimeConfig::resolve(&a).unwrap();
        assert_eq!(c.review_model, "from-flag");
        unsafe {
            std::env::remove_var("REVIEW_MODEL");
        }
    }

    #[test]
    fn cascade_splits_on_comma() {
        let a = ReviewArgs {
            staged: true,
            review_model_cascade: Some("a, b ,c".to_string()),
            diff_limit: DEFAULT_DIFF_LIMIT,
            ..Default::default()
        };
        let c = RuntimeConfig::resolve(&a).unwrap();
        assert_eq!(c.model_cascade, vec!["a", "b", "c"]);
    }

    #[test]
    fn requires_source() {
        let a = args();
        assert!(RuntimeConfig::resolve(&a).is_err());
    }
}
