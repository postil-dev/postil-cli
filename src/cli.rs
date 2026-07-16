//! Command-line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::output::OutputFormat;

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
    Bitbucket,
    Azure,
    Local,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Review carries the full flag set by design.
pub enum Command {
    /// Print immutable qualification metadata embedded in this binary.
    #[command(hide = true)]
    QualificationMetadata,
    /// Run one atomic attribution judgment for candidate qualification.
    #[cfg(feature = "qualification-candidate")]
    #[command(hide = true)]
    AtomicAttribution {
        /// JSON request file. Sensitive evaluator input is never accepted on argv.
        #[arg(long)]
        input: PathBuf,
        /// Explicit config file for provider selection.
        #[arg(long)]
        config: Option<PathBuf>,
    },
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
        /// Expected PR head SHA. Publication stops if the head differs.
        #[arg(long)]
        sha: Option<String>,
        /// Expected target-branch SHA. Publication stops if the target differs.
        #[arg(long)]
        base_sha: Option<String>,
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
        /// Print the review envelope in this format on stdout: json, yaml, or csv.
        #[arg(long, value_enum)]
        output: Option<OutputFormat>,
        /// Write --output or --output-json data to this path instead of stdout.
        #[arg(long)]
        output_file: Option<PathBuf>,
        /// Deprecated in v0.2.1: use --output json. Prints the envelope JSON.
        #[arg(long, conflicts_with = "output")]
        output_json: bool,
        /// Write SARIF 2.1.0 to this path for code-scanning ingestion.
        #[arg(long)]
        sarif: Option<PathBuf>,
        /// Exit 1 at/above this severity: info|warn|error|never. Overrides gate.failOn.
        #[arg(long)]
        fail_on: Option<String>,
        /// Explicit config file (bypasses discovery).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Model override (else REVIEW_MODEL, else config, else default).
        #[arg(long)]
        model: Option<String>,
        /// Use deterministic semantic synthesis and model-assisted risk selection to cap large reviews at five source batches; report bounded coverage.
        #[arg(long)]
        bounded: bool,
        /// Post review comments and checks to the selected forge. Reviews are local-only by default.
        #[arg(long, conflicts_with = "no_post")]
        publish: bool,
        /// Deprecated compatibility flag. Reviews are local-only by default.
        #[arg(long, hide = true, conflicts_with = "publish")]
        no_post: bool,
        /// Leave the merge-gate check pending for a controlling service to complete.
        #[arg(long, requires = "publish")]
        defer_gate_check: bool,
    },
    /// Reply to an @postil mention on a pull request or issue (interactive bot).
    Respond {
        /// Code host. GitHub and GitLab support PRs/MRs and issues; Bitbucket
        /// and Azure DevOps support pull requests only.
        #[arg(long, value_enum, default_value = "github")]
        forge: ForgeArg,
        /// Repository as owner/name.
        #[arg(long)]
        repo: Option<String>,
        /// Pull request number the mention is on.
        #[arg(long)]
        pr: Option<u64>,
        /// Issue number the mention is on.
        #[arg(long)]
        issue: Option<u64>,
        /// The maintainer's message text (the mention body). Falls back to the
        /// POSTIL_COMMENT environment variable — prefer that for automation:
        /// argv is visible in `ps` and clap would reject text starting with `-`.
        #[arg(long, allow_hyphen_values = true)]
        comment: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        model: Option<String>,
        /// Post the reply to the selected forge. Replies are printed locally by default.
        #[arg(long, conflicts_with = "no_post")]
        publish: bool,
        /// Deprecated compatibility flag. Replies are local-only by default.
        #[arg(long, hide = true, conflicts_with = "publish")]
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

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

    #[test]
    fn review_bounded_is_an_explicit_action_flag_with_concise_help() {
        let parsed = Cli::try_parse_from(["postil", "review", "--staged", "--bounded"]).unwrap();
        let Command::Review { bounded, .. } = parsed.command else {
            panic!("review command was not parsed");
        };
        assert!(bounded);

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--bounded"));
        assert!(help.contains(
            "Use deterministic semantic synthesis and model-assisted risk selection to cap large reviews at five source batches; report bounded coverage"
        ));
    }

    #[test]
    fn review_publication_requires_an_explicit_flag() {
        let parsed = Cli::try_parse_from([
            "postil",
            "review",
            "--repo",
            "postil-dev/postil",
            "--pr",
            "1",
        ])
        .unwrap();
        let Command::Review { publish, .. } = parsed.command else {
            panic!("expected review command");
        };
        assert!(!publish);

        let parsed = Cli::try_parse_from([
            "postil",
            "review",
            "--repo",
            "postil-dev/postil",
            "--pr",
            "1",
            "--publish",
        ])
        .unwrap();
        let Command::Review { publish, .. } = parsed.command else {
            panic!("expected review command");
        };
        assert!(publish);
    }

    #[test]
    fn deferred_gate_check_is_an_explicit_publication_option() {
        let parsed = Cli::try_parse_from([
            "postil",
            "review",
            "--repo",
            "postil-dev/postil",
            "--pr",
            "1",
            "--publish",
            "--defer-gate-check",
        ])
        .unwrap();
        let Command::Review {
            defer_gate_check, ..
        } = parsed.command
        else {
            panic!("expected review command");
        };
        assert!(defer_gate_check);

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--defer-gate-check"));
    }

    #[test]
    fn review_accepts_an_expected_target_snapshot() {
        let parsed = Cli::try_parse_from([
            "postil",
            "review",
            "--repo",
            "postil-dev/postil",
            "--pr",
            "1",
            "--sha",
            "aaaaaaaa",
            "--base-sha",
            "bbbbbbbb",
        ])
        .unwrap();
        let Command::Review { sha, base_sha, .. } = parsed.command else {
            panic!("expected review command");
        };
        assert_eq!(sha.as_deref(), Some("aaaaaaaa"));
        assert_eq!(base_sha.as_deref(), Some("bbbbbbbb"));

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--base-sha"));
        assert!(help.contains("Expected target-branch SHA"));
    }

    #[test]
    fn publication_flags_are_mutually_exclusive() {
        assert!(
            Cli::try_parse_from([
                "postil",
                "review",
                "--repo",
                "postil-dev/postil",
                "--pr",
                "1",
                "--publish",
                "--no-post",
            ])
            .is_err()
        );
    }
}
