//! Local diff acquisition: the same engine, before the PR exists.

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

pub enum LocalSource {
    /// `git diff --cached`
    Staged,
    /// `git diff <base>...HEAD` (merge-base semantics, like a PR diff)
    Base(String),
    /// A unified diff already on disk.
    DiffFile(std::path::PathBuf),
}

pub async fn acquire(source: &LocalSource) -> Result<String> {
    match source {
        LocalSource::DiffFile(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading diff file {}", path.display())),
        LocalSource::Staged => git_diff(&["diff", "--cached", "--no-color"]).await,
        LocalSource::Base(base) => {
            let range = format!("{base}...HEAD");
            git_diff(&["diff", "--no-color", &range]).await
        }
    }
}

async fn git_diff(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .await
        .context("running git (is git installed and is this a repository?)")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("git {} failed: {}", args.join(" "), stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub async fn head_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
