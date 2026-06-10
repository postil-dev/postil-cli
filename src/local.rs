//! Local diff producers. Used by `--staged`, `--base <ref>`, and `--diff-file`.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;

pub async fn staged_diff() -> Result<String> {
    run_git(&["diff", "--cached", "--no-color", "--unified=3"]).await
}

pub async fn base_diff(base: &str) -> Result<String> {
    run_git(&[
        "diff",
        "--no-color",
        "--unified=3",
        &format!("{base}..HEAD"),
    ])
    .await
}

pub async fn diff_from_file(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading diff file {}", path.display()))
}

async fn run_git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("running git (is it installed and in PATH?)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("git {} failed: {}", args.join(" "), err.trim());
    }
    String::from_utf8(out.stdout).context("git output was not UTF-8")
}
