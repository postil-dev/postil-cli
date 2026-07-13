//! Interactive bot: reply to an @postil mention on a PR or issue.
//!
//! Scope is review and answer only — Postil never opens PRs or pushes commits.
//! Works across every forge the reviewer supports. PR/MR mentions are grounded
//! on the diff; issue mentions on the issue body. GitHub and GitLab cover both
//! issues and pulls; Bitbucket and Azure DevOps are scoped to PRs (their issue
//! trackers / work items use endpoints we cannot verify against a live host).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

use crate::config::Config;
use crate::diff;
use crate::forge::{
    Forge, ThreadKind, azure::Azure, bitbucket::Bitbucket, github::GitHub, gitlab::GitLab,
};
use crate::llm::{Answer, LlmClient};
use crate::prompt;
use crate::review::ForgeKind;

pub struct RespondArgs {
    pub forge: ForgeKind,
    pub repo: Option<String>,
    /// The PR number, when the mention is on a pull request.
    pub pr: Option<u64>,
    /// The issue number, when the mention is on an issue.
    pub issue: Option<u64>,
    /// The maintainer's comment text (the mention). When None, read from the
    /// POSTIL_COMMENT environment variable — the safe path for automation.
    pub comment: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    /// Print the answer instead of posting it.
    pub no_post: bool,
}

const MAX_DIFF_BYTES: usize = 200_000;
const USAGE_RECEIPT_PATH_ENV: &str = "POSTIL_USAGE_RECEIPT_PATH";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespondUsageReceipt<'a> {
    version: u32,
    operation: &'static str,
    prompt_tokens: u64,
    completion_tokens: u64,
    models: Vec<RespondModelUsage<'a>>,
    usage_accounting_complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespondModelUsage<'a> {
    model: &'a str,
    prompt_tokens: u64,
    completion_tokens: u64,
}

// PID separates concurrent processes; this sequence separates writers within
// one process. create_new below also fails closed if a path already exists.
static RECEIPT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct UsageReceiptWriter {
    file: Option<File>,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl UsageReceiptWriter {
    fn from_env() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os(USAGE_RECEIPT_PATH_ENV) else {
            return Ok(None);
        };
        anyhow::ensure!(
            !path.is_empty(),
            "{USAGE_RECEIPT_PATH_ENV} must not be empty"
        );
        let final_path = PathBuf::from(path);
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path
            .file_name()
            .ok_or_else(|| anyhow!("{USAGE_RECEIPT_PATH_ENV} must name a file"))?
            .to_string_lossy();
        let sequence = RECEIPT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            // Usage receipts contain private provider-accounting metadata.
            .mode(0o600)
            .open(&temp_path)
            .context("creating private usage receipt temporary file")?;
        Ok(Some(Self {
            file: Some(file),
            temp_path,
            final_path,
        }))
    }

    fn commit(mut self, answer: &Answer) -> Result<()> {
        let receipt = RespondUsageReceipt {
            version: 1,
            operation: "respond",
            prompt_tokens: answer.usage.prompt_tokens,
            completion_tokens: answer.usage.completion_tokens,
            models: answer
                .models
                .iter()
                .map(|model| RespondModelUsage {
                    model: &model.model,
                    prompt_tokens: model.prompt_tokens,
                    completion_tokens: model.completion_tokens,
                })
                .collect(),
            usage_accounting_complete: answer.usage_accounting_complete,
        };
        let file = self.file.as_mut().expect("usage receipt file is present");
        serde_json::to_writer(&mut *file, &receipt).context("serializing usage receipt")?;
        file.write_all(b"\n").context("writing usage receipt")?;
        // Publish only after file contents are durable. The directory sync
        // below makes the rename durable before stdout or forge delivery.
        file.sync_all().context("syncing usage receipt")?;
        drop(self.file.take());
        std::fs::rename(&self.temp_path, &self.final_path)
            .context("atomically publishing usage receipt")?;
        if let Some(parent) = self.final_path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("syncing usage receipt directory")?;
        }
        Ok(())
    }
}

impl Drop for UsageReceiptWriter {
    fn drop(&mut self) {
        // Drop cannot return cleanup errors. Best-effort removal is safe: an
        // unpublished temp file is never treated as a committed receipt, and
        // create_new prevents a later writer from clobbering it.
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

pub async fn run(args: RespondArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let mut cfg = Config::load(&cwd, args.config.as_deref())?;
    if let Some(m) = &args.model {
        cfg.model = m.clone();
    }
    let repo = args
        .repo
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .ok_or_else(|| anyhow!("--repo is required"))?;
    let comment = args
        .comment
        .clone()
        .or_else(|| std::env::var("POSTIL_COMMENT").ok())
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| anyhow!("the mention text is required: --comment or POSTIL_COMMENT"))?;
    let usage_receipt = UsageReceiptWriter::from_env()?;

    // The number the mention is on, and whether it is a PR/MR or an issue.
    let (number, kind) = match (args.pr, args.issue) {
        (Some(pr), _) => (pr, ThreadKind::Pull),
        (None, Some(issue)) => (issue, ThreadKind::Issue),
        (None, None) => return Err(anyhow!("one of --pr or --issue is required")),
    };

    // Same flow for every forge; the trait carries the per-host endpoints. The
    // forge is monomorphized (the trait uses `async fn` and is not dyn-safe), so
    // dispatch by kind here, exactly as the reviewer does.
    match args.forge {
        ForgeKind::GitHub => {
            respond_with(
                GitHub::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::GitLab => {
            respond_with(
                GitLab::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Bitbucket => {
            respond_with(
                Bitbucket::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Azure => {
            respond_with(
                Azure::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Local => Err(anyhow!("postil respond needs a remote forge, not --local")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn respond_with<F: Forge>(
    forge: F,
    cfg: &Config,
    repo: &str,
    number: u64,
    kind: ThreadKind,
    comment: &str,
    no_post: bool,
    usage_receipt: Option<UsageReceiptWriter>,
) -> Result<i32> {
    let context = build_context(&forge, repo, number, kind).await?;

    let system = prompt::respond_system_prompt(cfg);
    let user = format!(
        "{context}\n--- Maintainer's message to you ---\n{}\n\nReply to the message above.",
        comment.trim()
    );
    let client = LlmClient::from_env(cfg)?;
    let answer = client.answer(cfg, &system, &user).await?;

    let reply = format!(
        "{}\n\n<sub>Postil · {}</sub>",
        answer.content, answer.model_used
    );

    // Hosted execution requires the durable usage receipt before any external
    // delivery. Commit it before stdout or forge posting so the control plane
    // can reconcile spend and own idempotent delivery.
    if let Some(writer) = usage_receipt {
        writer.commit(&answer)?;
    }
    if no_post {
        println!("{reply}");
    } else {
        forge
            .post_comment(number, kind, &reply)
            .await
            .context("posting reply")?;
        eprintln!("postil: replied on {repo}#{number}");
    }
    Ok(0)
}

/// Build the grounding context for the model: a PR/MR mention gets the annotated
/// diff, an issue mention gets the issue body.
async fn build_context<F: Forge>(
    forge: &F,
    repo: &str,
    number: u64,
    kind: ThreadKind,
) -> Result<String> {
    match kind {
        ThreadKind::Pull => {
            let meta = forge.fetch_pr_meta().await?;
            let raw = forge.fetch_diff().await.context("fetching PR diff")?;
            let parsed = diff::parse(&raw);
            let (annotated, truncated) = diff::render_annotated(&parsed, MAX_DIFF_BYTES);
            let mut ctx = format!(
                "Context: pull request #{number} in {repo}\nTitle: {}\n",
                meta.title
            );
            if !meta.body.trim().is_empty() {
                let body: String = meta.body.chars().take(1500).collect();
                ctx.push_str(&format!("Description:\n{body}\n"));
            }
            ctx.push_str("\nDiff (left-margin numbers are new-file lines):\n\n");
            ctx.push_str(&annotated);
            if truncated {
                ctx.push_str("\n[diff truncated at the size limit]\n");
            }
            Ok(ctx)
        }
        ThreadKind::Issue => {
            let (title, body) = forge.fetch_thread(number, kind).await?;
            let body: String = body.chars().take(4000).collect();
            Ok(format!(
                "Context: issue #{number} in {repo}\nTitle: {title}\n\nIssue body:\n{body}\n"
            ))
        }
    }
}
