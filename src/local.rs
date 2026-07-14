//! Local diff acquisition: the same engine, before the PR exists.

use std::io::{Read, Write};
use std::process::Stdio;

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

use crate::diff::{DiffSnapshot, DiffSpool};

pub enum LocalSource {
    /// `git diff --cached`
    Staged,
    /// `git diff <base>...HEAD` (merge-base semantics, like a PR diff)
    Base(String),
    /// A unified diff already on disk.
    DiffFile(std::path::PathBuf),
}

pub async fn acquire(source: &LocalSource) -> Result<DiffSnapshot> {
    match source {
        LocalSource::DiffFile(path) => DiffSnapshot::from_path(path),
        LocalSource::Staged => git_diff(&["diff", "--cached", "--no-color"]).await,
        LocalSource::Base(base) => {
            let range = format!("{base}...HEAD");
            git_diff(&["diff", "--no-color", &range]).await
        }
    }
}

async fn git_diff(args: &[&str]) -> Result<DiffSnapshot> {
    let owned: Vec<String> = args
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
    tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new("git")
            .args(&owned)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running git (is git installed and is this a repository?)")?;
        let mut stdout = child.stdout.take().context("capturing git stdout")?;
        let stderr = child.stderr.take().context("capturing git stderr")?;
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .take(4_096)
                .read_to_end(&mut bytes)
                .map(|_| String::from_utf8_lossy(&bytes).into_owned())
        });
        let mut spool = DiffSpool::new()?;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let count = stdout.read(&mut chunk).context("reading git diff")?;
            if count == 0 {
                break;
            }
            spool
                .write_all(&chunk[..count])
                .context("spooling git diff")?;
        }
        let status = child.wait().context("waiting for git")?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("joining git stderr reader"))?
            .context("reading git stderr")?;
        if !status.success() {
            return Err(anyhow!("git {} failed: {}", owned.join(" "), stderr.trim()));
        }
        spool.finish()
    })
    .await
    .context("joining git diff reader")?
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
