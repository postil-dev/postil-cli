//! Local diff acquisition: the same engine, before the PR exists.

use std::io::Read;
use std::process::Stdio;

use anyhow::{Context, Result, anyhow, ensure};
use tokio::process::Command;

use crate::diff::MAX_RAW_DIFF_ACQUISITION_BYTES;

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
        LocalSource::DiffFile(path) => {
            let size = std::fs::metadata(path)
                .with_context(|| format!("reading diff file metadata {}", path.display()))?
                .len();
            ensure!(
                size <= MAX_RAW_DIFF_ACQUISITION_BYTES as u64,
                "diff input exceeds the {} byte acquisition limit",
                MAX_RAW_DIFF_ACQUISITION_BYTES
            );
            let file = std::fs::File::open(path)
                .with_context(|| format!("opening diff file {}", path.display()))?;
            let mut bytes = Vec::with_capacity(size as usize);
            file.take((MAX_RAW_DIFF_ACQUISITION_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading diff file {}", path.display()))?;
            ensure!(
                bytes.len() <= MAX_RAW_DIFF_ACQUISITION_BYTES,
                "diff input exceeds the {} byte acquisition limit",
                MAX_RAW_DIFF_ACQUISITION_BYTES
            );
            String::from_utf8(bytes).context("diff file is not valid UTF-8")
        }
        LocalSource::Staged => git_diff(&["diff", "--cached", "--no-color"]).await,
        LocalSource::Base(base) => {
            let range = format!("{base}...HEAD");
            git_diff(&["diff", "--no-color", &range]).await
        }
    }
}

async fn git_diff(args: &[&str]) -> Result<String> {
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
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let count = stdout.read(&mut chunk).context("reading git diff")?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > MAX_RAW_DIFF_ACQUISITION_BYTES {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stderr_reader.join();
                return Err(anyhow!(
                    "git diff exceeds the {} byte acquisition limit",
                    MAX_RAW_DIFF_ACQUISITION_BYTES
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let status = child.wait().context("waiting for git")?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("joining git stderr reader"))?
            .context("reading git stderr")?;
        if !status.success() {
            return Err(anyhow!("git {} failed: {}", owned.join(" "), stderr.trim()));
        }
        String::from_utf8(bytes).context("git diff is not valid UTF-8")
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
