//! Command-line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "postil",
    version,
    about = "Low-noise AI review gate. Silent on clean changes, hard gate on real risk.",
    long_about = "Postil reviews diffs for merge-relevant findings only: bugs, security \
                  issues, breaking changes, and decisions that need a human. It stays \
                  silent on clean changes and fails closed when a model's output cannot \
                  be trusted. One binary works locally, in CI, and hosted."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ForgeArg {
    Github,
    Gitlab,
    Local,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Review carries the full flag set by design.
pub enum Command {
    /// Review a diff: a PR/MR on a forge, or local changes.
    Review {
        /// Code host for remote review. Inferred as github when --repo is set.
        #[arg(long, value_enum)]
        forge: Option<ForgeArg>,
        /// Repository as owner/name (GitHub) or group/project (GitLab).
        #[arg(long)]
        repo: Option<String>,
        /// Pull/merge request number.
        #[arg(long)]
        pr: Option<u64>,
        /// Head SHA to report checks against (defaults to the PR head).
        #[arg(long)]
        sha: Option<String>,
        /// Review staged changes (git diff --cached).
        #[arg(long)]
        staged: bool,
        /// Review changes since a base ref (git diff base...HEAD).
        #[arg(long)]
        base: Option<String>,
        /// Review a unified diff from a file.
        #[arg(long)]
        diff_file: Option<PathBuf>,
        /// Existing advisory check-run id to complete (hosted callers).
        #[arg(long)]
        check_run_id: Option<String>,
        /// Existing gate check-run id to complete (hosted callers).
        #[arg(long)]
        gate_check_run_id: Option<String>,
        /// Incremental review: only commits since this SHA.
        #[arg(long)]
        since_sha: Option<String>,
        /// Previous review envelope for finding reconciliation.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Print the envelope JSON on stdout (machine consumers).
        #[arg(long)]
        output_json: bool,
        /// Exit 1 at/above this severity: info|warn|error|never. Overrides gate.failOn.
        #[arg(long)]
        fail_on: Option<String>,
        /// Explicit config file (bypasses discovery).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Model override (else REVIEW_MODEL, else config, else default).
        #[arg(long)]
        model: Option<String>,
        /// Do not post comments or checks to the forge; report locally only.
        #[arg(long)]
        no_post: bool,
    },
    /// Replay stored envelopes under a candidate config: what would change?
    Plan {
        /// Directory of envelope JSON files from previous reviews.
        #[arg(long)]
        envelopes: PathBuf,
        /// Candidate config file to evaluate (defaults to discovery).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print the resolved configuration and where it came from.
    Config {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Write a starter .postil.yaml.
    Init {
        /// Overwrite an existing .postil.yaml.
        #[arg(long)]
        force: bool,
    },
    /// Validate endpoint, key, model, and repo setup with actionable errors.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Manage git hooks.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Subcommand)]
pub enum HookAction {
    /// Install a pre-push hook that reviews outgoing commits.
    Install {
        #[arg(long)]
        force: bool,
    },
}
