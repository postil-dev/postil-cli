//! Command-line surface. Kept thin: every field maps to a `RuntimeConfig`
//! override resolved in `config.rs`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "postil",
    bin_name = "postil",
    version,
    about = "Low-noise pull-request review gate.",
    long_about = "Review pull-request diffs. Comment only when the comment can affect merge."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Default review args when no subcommand is given.
    #[command(flatten)]
    pub review: ReviewArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Review a pull request or local diff.
    Review(Box<ReviewArgs>),
    /// Print the embedded system prompt.
    Prompt,
    /// Validate a `.postil.yaml` config file.
    ValidateConfig {
        /// Path to the config file.
        path: PathBuf,
    },
}

#[derive(Debug, Args, Default, Clone)]
pub struct ReviewArgs {
    /// Runtime config file (YAML or JSON).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Target repository as `owner/name`.
    #[arg(long)]
    pub repo: Option<String>,

    /// Pull-request number.
    #[arg(long)]
    pub pr: Option<u64>,

    /// Pull-request head SHA.
    #[arg(long)]
    pub sha: Option<String>,

    /// Exit code 1 threshold.
    #[arg(long, value_name = "info|warn|error")]
    pub fail_on: Option<String>,

    /// Skip inline PR review comments.
    #[arg(long, default_value_t = false)]
    pub no_inline: bool,

    /// GitHub token.
    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,

    /// OpenRouter API key.
    #[arg(long, env = "OPENROUTER_API_KEY")]
    pub openrouter_api_key: Option<String>,

    /// Primary review model.
    #[arg(long, env = "REVIEW_MODEL")]
    pub review_model: Option<String>,

    /// Comma-separated model cascade.
    #[arg(long, env = "REVIEW_MODEL_CASCADE")]
    pub review_model_cascade: Option<String>,

    /// GitHub API base URL override.
    #[arg(long, env = "POSTIL_GITHUB_API_URL")]
    pub github_api_url: Option<String>,

    /// OpenRouter API base URL override.
    #[arg(long, env = "POSTIL_OPENROUTER_API_URL")]
    pub openrouter_api_url: Option<String>,

    /// Maximum diff bytes sent to the model.
    #[arg(long, default_value_t = 120_000)]
    pub diff_limit: usize,

    /// GitHub check-run name.
    #[arg(long, env = "POSTIL_CHECK_NAME")]
    pub check_name: Option<String>,

    /// Pre-created check-run id (hosted worker path).
    #[arg(long)]
    pub check_run_id: Option<u64>,

    /// Write the JSON envelope to this path.
    #[arg(long, value_name = "FILE")]
    pub output_json: Option<PathBuf>,

    // ---- Local diff modes. Mutually exclusive with --repo/--pr/--sha. ----
    /// Review the staged diff in the current working tree.
    #[arg(long, group = "local_source", conflicts_with_all = ["repo", "pr", "sha"])]
    pub staged: bool,

    /// Review the diff against this base ref (e.g. `origin/main`).
    #[arg(long, group = "local_source", value_name = "REF", conflicts_with_all = ["repo", "pr", "sha"])]
    pub base: Option<String>,

    /// Review a unified-diff file directly.
    #[arg(long, group = "local_source", value_name = "FILE", conflicts_with_all = ["repo", "pr", "sha"])]
    pub diff_file: Option<PathBuf>,
}
