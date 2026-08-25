//! Command-line surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::output::OutputFormat;

const UNSUPPORTED_PUBLICATION_ENVIRONMENT: [&str; 2] = ["POSTIL_PUBLISH", "POSTIL_NO_POST"];

/// Resolve the forge-publication action from command-line flags only.
///
/// Publication is a mutation, so environment variables never authorize it.
/// Refuse publication-looking legacy variables instead of silently choosing an
/// interpretation that could write to a forge.
pub fn publication_enabled(publish: bool, no_post: bool) -> anyhow::Result<bool> {
    let present = UNSUPPORTED_PUBLICATION_ENVIRONMENT
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .collect::<Vec<_>>();
    if !present.is_empty() {
        anyhow::bail!(
            "{} cannot control forge publication; remove {} and pass --publish explicitly to write to the forge",
            present.join(" and "),
            if present.len() == 1 { "it" } else { "them" }
        );
    }
    Ok(publish && !no_post)
}

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
    /// Probe machine-readable CLI capabilities without external access.
    Capabilities {
        /// Require and print an exact publication-plan contract identifier.
        #[arg(long, value_name = "IDENTIFIER")]
        publication_plan_contract: String,
    },
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
    #[command(
        after_help = "Examples:\n  postil review\n  postil review --staged\n  postil review --base origin/main\n\nBare local review selects, in order: staged changes; committed changes since the current branch remote's default branch; tracked working-tree changes; then an empty clean diff. Locally known symbolic remote HEAD, main, master, and trunk refs are recognized without fetching. If no default branch can be resolved, Postil fails closed and asks for --base, --staged, or --diff-file. Explicit source flags are mutually exclusive and keep their exact behavior.\n\nUse `postil models` to see supported model-ID contracts, embedded defaults, qualification, and override syntax."
    )]
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
        #[arg(long, conflicts_with_all = ["base", "diff_file"])]
        staged: bool,
        /// Review changes since a base ref (git diff base...HEAD).
        #[arg(long, conflicts_with_all = ["staged", "diff_file"])]
        base: Option<String>,
        /// Review a unified diff from a file.
        #[arg(long, conflicts_with_all = ["staged", "base"])]
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
        /// Reviewer reasoning effort: max|xhigh|high|medium|low|minimal|none (else REVIEW_REASONING_EFFORT, else config, else low).
        #[arg(long, value_name = "EFFORT")]
        reasoning_effort: Option<String>,
        /// Scorer reasoning effort: max|xhigh|high|medium|low|minimal|none (else REVIEW_SCORER_REASONING_EFFORT, else config, else none).
        #[arg(long, value_name = "EFFORT")]
        scorer_reasoning_effort: Option<String>,
        /// Keep detailed provider, retry, and batch telemetry in interactive terminals.
        #[arg(long)]
        verbose: bool,
        /// Disable animation while keeping concise human progress milestones.
        #[arg(long)]
        no_progress: bool,
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
        /// Write an immutable GitHub publication plan without mutating the forge.
        #[arg(
            long,
            hide = true,
            value_name = "PATH",
            requires_all = [
                "repo",
                "pr",
                "sha",
                "base_sha",
                "publication_generation",
                "publication_input_identity"
            ],
            conflicts_with_all = [
                "publish",
                "no_post",
                "check_run_id",
                "gate_check_run_id",
                "defer_gate_check"
            ]
        )]
        publication_plan_output: Option<PathBuf>,
        /// Service-owned generation identity for publication planning.
        #[arg(
            long,
            hide = true,
            value_name = "IDENTITY",
            requires = "publication_plan_output"
        )]
        publication_generation: Option<String>,
        /// Service-supplied immutable input identity for publication planning.
        #[arg(
            long,
            hide = true,
            value_name = "SHA256",
            requires = "publication_plan_output"
        )]
        publication_input_identity: Option<String>,
    },
    /// Explain supported model IDs, embedded defaults, qualification, and overrides.
    Models,
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
    /// Authenticate through a Postil login server.
    Login {
        /// Organization to select during approval. The browser approval page
        /// is authoritative for membership; this only pre-fills a hint.
        #[arg(long)]
        org: Option<String>,
    },
    /// Revoke the stored login server-side, then remove it locally.
    Logout,
}

pub fn publication_plan_contract_capability(required: &str) -> anyhow::Result<&'static str> {
    anyhow::ensure!(
        required == crate::forge::GITHUB_PUBLICATION_PLAN_CONTRACT,
        "unsupported publication-plan contract {required:?}; supported contract: {}",
        crate::forge::GITHUB_PUBLICATION_PLAN_CONTRACT
    );
    Ok(crate::forge::GITHUB_PUBLICATION_PLAN_CONTRACT)
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

    use super::{Cli, Command, publication_plan_contract_capability};

    const PUBLICATION_INPUT_IDENTITY: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn publication_plan_capability_requires_the_exact_contract() {
        let parsed = Cli::try_parse_from([
            "postil",
            "capabilities",
            "--publication-plan-contract",
            "github-publication-v1",
        ])
        .unwrap();
        let Command::Capabilities {
            publication_plan_contract,
        } = parsed.command
        else {
            panic!("expected capabilities command");
        };
        assert_eq!(publication_plan_contract, "github-publication-v1");
        assert_eq!(
            publication_plan_contract_capability(&publication_plan_contract).unwrap(),
            "github-publication-v1"
        );
        assert!(publication_plan_contract_capability("github-publication-v2").is_err());
    }

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
    fn review_help_makes_bare_selection_and_model_discovery_explicit() {
        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("postil review\n"));
        assert!(help.contains("staged changes; committed changes"));
        assert!(help.contains("postil models"));
        let root = Cli::command().render_long_help().to_string();
        assert!(root.contains("models"));
        assert!(!root.contains("respond"));
    }

    #[test]
    fn review_accepts_role_specific_reasoning_effort_flags() {
        let parsed = Cli::try_parse_from([
            "postil",
            "review",
            "--reasoning-effort",
            "xhigh",
            "--scorer-reasoning-effort",
            "none",
        ])
        .unwrap();
        let Command::Review {
            reasoning_effort,
            scorer_reasoning_effort,
            ..
        } = parsed.command
        else {
            panic!("expected review command");
        };
        assert_eq!(reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(scorer_reasoning_effort.as_deref(), Some("none"));

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--reasoning-effort <EFFORT>"));
        assert!(help.contains("--scorer-reasoning-effort <EFFORT>"));
        assert!(help.contains("max|xhigh|high|medium|low|minimal|none"));
    }

    #[test]
    fn local_review_sources_are_mutually_exclusive() {
        for arguments in [
            vec!["postil", "review", "--staged", "--base", "main"],
            vec!["postil", "review", "--staged", "--diff-file", "change.diff"],
            vec![
                "postil",
                "review",
                "--base",
                "main",
                "--diff-file",
                "change.diff",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn no_progress_keeps_concise_human_milestones() {
        let parsed = Cli::try_parse_from(["postil", "review", "--no-progress"]).unwrap();
        let Command::Review { no_progress, .. } = parsed.command else {
            panic!("expected review command");
        };
        assert!(no_progress);

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--no-progress"));
        assert!(help.contains("concise human progress milestones"));
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

    #[test]
    fn publication_plan_is_hidden_snapshot_bound_and_separate_from_mutation() {
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
            "--publication-plan-output",
            "publication-plan.json",
            "--publication-generation",
            "1",
            "--publication-input-identity",
            PUBLICATION_INPUT_IDENTITY,
        ])
        .unwrap();
        let Command::Review {
            publication_plan_output,
            publication_generation,
            publication_input_identity,
            publish,
            ..
        } = parsed.command
        else {
            panic!("expected review command");
        };
        assert_eq!(
            publication_plan_output.as_deref(),
            Some(std::path::Path::new("publication-plan.json"))
        );
        assert_eq!(publication_generation.as_deref(), Some("1"));
        assert_eq!(
            publication_input_identity.as_deref(),
            Some(PUBLICATION_INPUT_IDENTITY)
        );
        assert!(!publish);

        let help = Cli::command()
            .find_subcommand_mut("review")
            .expect("review subcommand")
            .render_long_help()
            .to_string();
        assert!(!help.contains("publication-plan-output"));

        for extra in [
            vec!["--publish"],
            vec!["--no-post"],
            vec!["--check-run-id", "901"],
            vec!["--gate-check-run-id", "902"],
        ] {
            let mut arguments = vec![
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
                "--publication-plan-output",
                "publication-plan.json",
                "--publication-generation",
                "1",
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
            ];
            arguments.extend(extra);
            assert!(Cli::try_parse_from(arguments).is_err());
        }

        assert!(
            Cli::try_parse_from([
                "postil",
                "review",
                "--repo",
                "postil-dev/postil",
                "--pr",
                "1",
                "--sha",
                "aaaaaaaa",
                "--publication-plan-output",
                "publication-plan.json",
                "--publication-generation",
                "1",
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
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
                "--publication-plan-output",
                "publication-plan.json",
                "--publication-generation",
                "1",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
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
                "--publication-plan-output",
                "publication-plan.json",
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "postil",
                "review",
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
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
                "--publication-plan-output",
                "publication-plan.json",
                "--publication-generation",
                "1",
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
                "--publication-input-identity",
                PUBLICATION_INPUT_IDENTITY,
            ])
            .is_err()
        );
    }

    #[test]
    fn login_accepts_an_optional_org_hint() {
        let parsed = Cli::try_parse_from(["postil", "login"]).unwrap();
        let Command::Login { org } = parsed.command else {
            panic!("expected login command");
        };
        assert_eq!(org, None);

        let parsed = Cli::try_parse_from(["postil", "login", "--org", "runatlas-is"]).unwrap();
        let Command::Login { org } = parsed.command else {
            panic!("expected login command");
        };
        assert_eq!(org.as_deref(), Some("runatlas-is"));
    }

    #[test]
    fn logout_takes_no_arguments() {
        let parsed = Cli::try_parse_from(["postil", "logout"]).unwrap();
        assert!(matches!(parsed.command, Command::Logout));
        assert!(Cli::try_parse_from(["postil", "logout", "--org", "runatlas-is"]).is_err());
    }
}
