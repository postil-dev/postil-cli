//! Interactive bot: reply to an @postil mention on a PR or issue.
//!
//! Scope is review and answer only — Postil never opens PRs or pushes commits.
//! v1 targets GitHub (the same `GITHUB_TOKEN`/`GITHUB_API_URL` the reviewer
//! uses); other forges return a clear "not yet supported" error.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use crate::config::Config;
use crate::diff;
use crate::forge::{Forge, github::GitHub};
use crate::llm::LlmClient;
use crate::prompt;
use crate::review::ForgeKind;

pub struct RespondArgs {
    pub forge: ForgeKind,
    pub repo: Option<String>,
    /// The PR number, when the mention is on a pull request.
    pub pr: Option<u64>,
    /// The issue number, when the mention is on an issue.
    pub issue: Option<u64>,
    /// The maintainer's comment text (the mention).
    pub comment: String,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    /// Print the answer instead of posting it.
    pub no_post: bool,
}

const MAX_DIFF_BYTES: usize = 200_000;

pub async fn run(args: RespondArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let mut cfg = Config::load(&cwd, args.config.as_deref())?;
    if let Some(m) = &args.model {
        cfg.model = m.clone();
    }
    if args.forge != ForgeKind::GitHub {
        return Err(anyhow!(
            "postil respond currently supports --forge github only"
        ));
    }
    let repo = args
        .repo
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .ok_or_else(|| anyhow!("--repo owner/name is required"))?;

    // PR mentions get the diff for grounding; issue mentions get the issue body.
    let (number, context) = if let Some(pr) = args.pr {
        let forge = GitHub::new(&repo, pr)?;
        let meta = forge.fetch_pr_meta().await?;
        let raw = forge.fetch_diff().await.context("fetching PR diff")?;
        let parsed = diff::parse(&raw);
        let (annotated, truncated) = diff::render_annotated(&parsed, MAX_DIFF_BYTES);
        let mut ctx = format!(
            "Context: pull request #{pr} in {repo}\nTitle: {}\n",
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
        (pr, ctx)
    } else if let Some(issue) = args.issue {
        // The issues API needs any PR number for construction; issue ops ignore it.
        let forge = GitHub::new(&repo, issue)?;
        let (title, body) = forge.fetch_issue(issue).await?;
        let body: String = body.chars().take(4000).collect();
        (
            issue,
            format!("Context: issue #{issue} in {repo}\nTitle: {title}\n\nIssue body:\n{body}\n"),
        )
    } else {
        return Err(anyhow!("one of --pr or --issue is required"));
    };

    let system = prompt::respond_system_prompt(&cfg);
    let user = format!(
        "{context}\n--- Maintainer's message to you ---\n{}\n\nReply to the message above.",
        args.comment.trim()
    );
    let client = LlmClient::from_env(&cfg)?;
    let (answer, model_used) = client.answer(&cfg, &system, &user).await?;

    let reply = format!("{answer}\n\n<sub>Postil · {model_used}</sub>");

    if args.no_post {
        println!("{reply}");
    } else {
        let forge = GitHub::new(&repo, number)?;
        forge
            .post_issue_comment(number, &reply)
            .await
            .context("posting reply")?;
        eprintln!("postil: replied on {repo}#{number}");
    }
    Ok(0)
}
