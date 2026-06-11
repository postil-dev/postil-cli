use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use clap::{Parser, Subcommand};
use postil_cli::config::{
    self, RuntimeConfig, RuntimeFileConfig, RuntimeOverrides, Severity, resolve_target,
};
use postil_cli::github::{CheckOutput, GithubClient, check_conclusion};
use postil_cli::local;
use postil_cli::openrouter::{self, OpenRouterClient};
use postil_cli::review::{
    ReviewEnvelope, TokenUsage, apply_config, is_model_output_error, parse_envelope, review_body,
    system_prompt,
};
use postil_cli::text::limit_text;

#[derive(Debug, Parser)]
#[command(name = "postil", about = "Postil low-noise review gate")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Review(ReviewArgs),
}

#[derive(Debug, Parser, Default)]
struct ReviewArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    repo: Option<String>,
    #[arg(long)]
    pr: Option<u64>,
    #[arg(long)]
    sha: Option<String>,
    #[arg(long, value_enum)]
    fail_on: Option<Severity>,
    #[arg(long)]
    no_inline: bool,
    #[arg(long)]
    github_token: Option<String>,
    #[arg(long)]
    openrouter_api_key: Option<String>,
    #[arg(long)]
    review_model: Option<String>,
    #[arg(long)]
    review_model_cascade: Option<String>,
    #[arg(long)]
    github_api_url: Option<String>,
    #[arg(long)]
    openrouter_api_url: Option<String>,
    #[arg(long)]
    diff_limit: Option<usize>,
    #[arg(long)]
    check_name: Option<String>,
    #[arg(long)]
    check_run_id: Option<u64>,
    #[arg(long)]
    output_json: Option<PathBuf>,
    #[arg(long)]
    staged: bool,
    #[arg(long)]
    base: Option<String>,
    #[arg(long)]
    diff_file: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    local_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli
        .command
        .unwrap_or(Command::Review(ReviewArgs::default()))
    {
        Command::Review(args) => run_review(args).await,
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("[postil] {err:#}");
            ExitCode::from(1)
        }
    }
}

async fn run_review(args: ReviewArgs) -> Result<ExitCode> {
    let output_json = args.output_json.clone();
    let local_diff = LocalDiffSource::from_args(&args)?;
    let file_cfg = match args.config.as_ref() {
        Some(path) => Some(RuntimeFileConfig::from_path(path)?),
        None => None,
    };
    let overrides = RuntimeOverrides {
        github_token: args.github_token,
        openrouter_api_key: args.openrouter_api_key,
        review_model: args.review_model,
        review_model_cascade: args.review_model_cascade,
        github_api_url: args.github_api_url,
        openrouter_api_url: args.openrouter_api_url,
        fail_on: args.fail_on,
        no_inline: args.no_inline.then_some(true),
        diff_limit: args.diff_limit,
        check_name: args.check_name,
        check_run_id: args.check_run_id,
        repo: args.repo,
        pr: args.pr,
        sha: args.sha,
        ..RuntimeOverrides::default()
    };
    let runtime = RuntimeConfig::load(file_cfg, overrides)?;
    let openrouter = OpenRouterClient::new(
        runtime.openrouter_api_url.clone(),
        runtime.openrouter_api_key.clone(),
    )?;
    let started_at = Utc::now().to_rfc3339();

    let remote = local_diff.is_none();
    let (diff, repo_config, target, github, source_label) = if let Some(source) = local_diff {
        let diff = source.read(runtime.diff_limit)?;
        let repo_config = match &runtime.file_review_config {
            Some(config) => config.clone(),
            None => source.load_repo_config()?,
        };
        (diff, repo_config, None, None, source.label())
    } else {
        let target = resolve_target(&runtime)?;
        let github_token = runtime
            .github_token
            .clone()
            .context("GITHUB_TOKEN is not set")?;
        let github = GithubClient::new(runtime.github_api_url.clone(), github_token)?;
        let diff = github.fetch_diff(&target, runtime.diff_limit).await?;
        let repo_config = match &runtime.file_review_config {
            Some(config) => config.clone(),
            None => github.load_repo_config(&target).await?,
        };
        (
            diff,
            repo_config,
            Some(target),
            Some(github),
            "github pull request".to_string(),
        )
    };

    if diff.trim().is_empty() {
        if let Some(path) = output_json.as_ref() {
            write_envelope(
                path,
                &ReviewEnvelope {
                    summary: "Nothing to review.".to_string(),
                    findings: Vec::new(),
                    usage: TokenUsage::default(),
                    model_used: "none".to_string(),
                },
            )?;
        }
        if let (Some(github), Some(target)) = (github.as_ref(), target.as_ref()) {
            github
                .complete_check_run(
                    target,
                    &runtime.check_name,
                    runtime.check_run_id,
                    "neutral",
                    CheckOutput::empty(),
                    &started_at,
                )
                .await?;
        }
        println!("[postil] empty diff - nothing to review");
        return Ok(ExitCode::SUCCESS);
    }

    if !repo_config.enabled {
        let output = CheckOutput {
            title: "Postil Review".to_string(),
            summary: "Postil is disabled for this repo via config.".to_string(),
            text: None,
        };
        if let (Some(github), Some(target)) = (github.as_ref(), target.as_ref()) {
            github
                .complete_check_run(
                    target,
                    &runtime.check_name,
                    runtime.check_run_id,
                    "neutral",
                    output,
                    &started_at,
                )
                .await?;
        }
        if let Some(path) = output_json.as_ref() {
            write_envelope(
                path,
                &ReviewEnvelope {
                    summary: "Postil is disabled for this repo via config.".to_string(),
                    findings: Vec::new(),
                    usage: TokenUsage::default(),
                    model_used: "none".to_string(),
                },
            )?;
        }
        if let Some(target) = target.as_ref() {
            println!(
                "[postil] {}/{}#{} -> neutral (disabled by config)",
                target.owner, target.repo, target.pull_number
            );
        } else {
            println!("[postil] local diff ({source_label}) -> neutral (disabled by config)");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let prompt = system_prompt(&repo_config);
    let user_content = review_user_content(&source_label, &diff);
    let model_result = run_cascade(&openrouter, &runtime.models(), &prompt, &user_content).await?;
    let mut envelope = apply_config(
        parse_envelope(
            &model_result.content,
            model_result.usage.clone(),
            model_result.model_used.clone(),
        ),
        &repo_config,
    )?;
    if is_model_output_error(&envelope) {
        eprintln!(
            "[postil] model output was not valid JSON{}; retrying once with a compact JSON repair prompt",
            model_result
                .finish_reason
                .as_deref()
                .map(|reason| format!(" (finish_reason: {reason})"))
                .unwrap_or_default()
        );
        let retry_content = json_repair_user_content(&source_label, &diff, &model_result.content);
        let retry = openrouter
            .complete_compact_json(&model_result.model_used, &prompt, &retry_content)
            .await
            .context("retry review model after invalid JSON output")?;
        let retry_envelope = apply_config(
            parse_envelope(&retry.content, retry.usage, retry.model_used),
            &repo_config,
        )?;
        if !is_model_output_error(&retry_envelope) {
            envelope = retry_envelope;
        }
    }
    if let Some(path) = output_json {
        write_envelope(&path, &envelope)?;
    }
    let inline_count = envelope.findings.len();
    let clean = envelope.findings.is_empty();
    let should_post = repo_config.review.enabled
        && !(clean && repo_config.review.on_clean == config::OnClean::Skip);
    let label = if clean { "clean" } else { "needs-attention" };
    let review_body = review_body(&envelope, inline_count, label);

    if remote && should_post && !runtime.no_inline {
        if let (Some(github), Some(target)) = (github.as_ref(), target.as_ref()) {
            if let Err(err) = github
                .post_inline_review(target, &envelope, &review_body)
                .await
            {
                eprintln!("[postil] inline review post failed: {err:#}");
                github
                    .post_issue_comment(target, &review_body)
                    .await
                    .context("post fallback issue comment after review failure")?;
            }
        }
    }

    let conclusion = check_conclusion(&envelope);
    if let (Some(github), Some(target)) = (github.as_ref(), target.as_ref()) {
        github
            .complete_check_run(
                target,
                &runtime.check_name,
                runtime.check_run_id,
                conclusion,
                CheckOutput::from_envelope(&envelope),
                &started_at,
            )
            .await?;
    }
    if let Some(target) = target.as_ref() {
        println!(
            "[postil] {}/{}#{} -> {} ({} findings, model: {})",
            target.owner,
            target.repo,
            target.pull_number,
            conclusion,
            envelope.findings.len(),
            envelope.model_used
        );
    } else {
        println!(
            "[postil] local diff ({source_label}) -> {} ({} findings, model: {})",
            conclusion,
            envelope.findings.len(),
            envelope.model_used
        );
        if !envelope.findings.is_empty() {
            println!("{}", render_local_findings(&envelope));
        }
    }

    if envelope
        .findings
        .iter()
        .any(|f| f.severity.rank() >= runtime.fail_on.rank())
    {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn write_envelope(path: &std::path::Path, envelope: &ReviewEnvelope) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(envelope)?)
        .with_context(|| format!("write {}", path.display()))
}

async fn run_cascade(
    client: &OpenRouterClient,
    models: &[String],
    system_prompt: &str,
    user_content: &str,
) -> Result<openrouter::OpenRouterResult> {
    let mut errors = Vec::new();
    for model in models {
        match client.complete(model, system_prompt, user_content).await {
            Ok(result) => return Ok(result),
            Err(err) => errors.push(format!("{model}: {err:#}")),
        }
    }
    Err(anyhow!("all models failed:\n{}", errors.join("\n")))
}

#[derive(Debug, Clone)]
enum LocalDiffSource {
    Staged,
    Base(String),
    DiffFile(PathBuf),
    LocalDir(PathBuf),
}

impl LocalDiffSource {
    fn from_args(args: &ReviewArgs) -> Result<Option<Self>> {
        let requested = args.staged as u8
            + args.base.is_some() as u8
            + args.diff_file.is_some() as u8
            + args.local_dir.is_some() as u8;
        if requested > 1 {
            anyhow::bail!(
                "choose only one local diff source: --staged, --base, --diff-file, or --local-dir"
            );
        }
        Ok(if args.staged {
            Some(Self::Staged)
        } else if let Some(base) = args.base.as_ref() {
            Some(Self::Base(base.clone()))
        } else if let Some(path) = args.local_dir.as_ref() {
            Some(Self::LocalDir(path.clone()))
        } else {
            args.diff_file
                .as_ref()
                .map(|path| Self::DiffFile(path.clone()))
        })
    }

    fn label(&self) -> String {
        match self {
            Self::Staged => "staged changes".to_string(),
            Self::Base(base) => format!("{base}...HEAD"),
            Self::DiffFile(path) => format!("diff file {}", path.display()),
            Self::LocalDir(path) => format!("local directory {}", path.display()),
        }
    }

    fn read(&self, limit: usize) -> Result<String> {
        let diff = match self {
            Self::Staged => git_diff(&[
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=80",
            ])?,
            Self::Base(base) => {
                let range = format!("{base}...HEAD");
                git_diff(&[
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--unified=80",
                    &range,
                ])?
            }
            Self::DiffFile(path) => {
                fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
            }
            Self::LocalDir(path) => return local::collect_diff(path, limit),
        };
        Ok(limit_text(diff, limit))
    }

    fn load_repo_config(&self) -> Result<postil_cli::config::RepoReviewConfig> {
        match self {
            Self::LocalDir(path) => local::load_repo_config(path),
            Self::Staged | Self::Base(_) | Self::DiffFile(_) => load_local_repo_config(),
        }
    }
}

fn git_diff(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            stderr.trim().chars().take(400).collect::<String>()
        );
    }
    String::from_utf8(output.stdout).context("read git diff output")
}

fn load_local_repo_config() -> Result<postil_cli::config::RepoReviewConfig> {
    for path in [".postil.yaml", ".postil.yml", ".postil.json"] {
        let path_ref = Path::new(path);
        if path_ref.exists() {
            let text = fs::read_to_string(path_ref)
                .with_context(|| format!("read {}", path_ref.display()))?;
            return postil_cli::config::RepoReviewConfig::from_text(path, &text);
        }
    }
    Ok(postil_cli::config::RepoReviewConfig::default())
}

fn review_user_content(source_label: &str, diff: &str) -> String {
    format!("Review source: {source_label}\n\nUnified diff:\n\n{diff}")
}

fn json_repair_user_content(source_label: &str, diff: &str, previous_output: &str) -> String {
    let previous = limit_text(previous_output.to_string(), 4_000);
    format!(
        "The previous response was not valid Postil JSON or was truncated. Return ONLY one compact valid JSON object matching the schema from the system prompt. Do not include markdown, reasoning, or prose.\n\nReview source: {source_label}\n\nPrevious invalid output excerpt:\n{previous}\n\nUnified diff:\n\n{diff}"
    )
}

fn render_local_findings(envelope: &ReviewEnvelope) -> String {
    envelope
        .findings
        .iter()
        .map(|finding| {
            format!(
                "{} {}:{} {}",
                finding.severity.as_str().to_uppercase(),
                finding.path,
                finding.line,
                finding.body
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
