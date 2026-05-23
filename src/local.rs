use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};

use crate::config::{RepoReviewConfig, translate_coderabbit, translate_kodo};
use crate::text::limit_text;

pub fn collect_diff(dir: &Path, limit: usize) -> Result<String> {
    let root = repo_root(dir)?;
    let mut diff = tracked_diff(&root)?;
    diff = limit_text(diff, limit);
    let untracked = untracked_files(&root)?;
    for path in untracked {
        if diff.len() >= limit {
            break;
        }
        if let Some(file_diff) = untracked_file_diff(&root, &path, limit - diff.len())? {
            if !diff.is_empty() {
                diff.push('\n');
            }
            diff.push_str(&file_diff);
            diff = limit_text(diff, limit);
        }
    }
    Ok(diff)
}

pub fn load_repo_config(dir: &Path) -> Result<RepoReviewConfig> {
    let root = repo_root(dir)?;
    let candidates = [
        (".postil.yaml", "postil"),
        (".postil.yml", "postil"),
        (".postil.json", "postil"),
        (".coderabbit.yaml", "coderabbit"),
        (".coderabbit.yml", "coderabbit"),
        (".kodo.yaml", "kodo"),
        (".kodo.yml", "kodo"),
    ];
    for (path, kind) in candidates {
        let full_path = root.join(path);
        if !full_path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&full_path)
            .with_context(|| format!("read local config {}", full_path.display()))?;
        let parsed = match kind {
            "postil" => RepoReviewConfig::from_text(path, &text),
            "coderabbit" => translate_coderabbit(&text),
            "kodo" => translate_kodo(&text),
            _ => unreachable!(),
        };
        if let Ok(config) = parsed {
            return Ok(config);
        }
    }
    Ok(RepoReviewConfig::default())
}

fn repo_root(dir: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .with_context(|| format!("resolve git repository for {}", dir.display()))?;
    if !output.status.success() {
        return Err(anyhow!("{} is not inside a git repository", dir.display()));
    }
    let root = String::from_utf8(output.stdout).context("read git repository root")?;
    Ok(PathBuf::from(root.trim()))
}

fn tracked_diff(root: &Path) -> Result<String> {
    let baseline = if has_head(root)? {
        vec!["diff", "--no-ext-diff", "--unified=3", "HEAD", "--", "."]
    } else {
        vec!["diff", "--no-ext-diff", "--unified=3", "--", "."]
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(baseline)
        .output()
        .with_context(|| format!("collect git diff in {}", root.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).context("read git diff output")
}

fn has_head(root: &Path) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .with_context(|| format!("check git HEAD in {}", root.display()))?;
    Ok(output.status.success())
}

fn untracked_files(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .with_context(|| format!("list untracked files in {}", root.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output
        .stdout
        .split(|b| *b == 0)
        .filter(|item| !item.is_empty())
        .filter_map(|item| String::from_utf8(item.to_vec()).ok())
        .map(PathBuf::from)
        .collect())
}

fn untracked_file_diff(root: &Path, path: &Path, max_bytes: usize) -> Result<Option<String>> {
    if max_bytes == 0 {
        return Ok(None);
    }
    let full_path = root.join(path);
    let metadata = fs::metadata(&full_path)
        .with_context(|| format!("read untracked file metadata {}", full_path.display()))?;
    if metadata.len() > max_bytes as u64 {
        return Ok(None);
    }
    let bytes = fs::read(&full_path)
        .with_context(|| format!("read untracked file {}", full_path.display()))?;
    if bytes.contains(&0) {
        return Ok(None);
    }
    let text = String::from_utf8(bytes)
        .with_context(|| format!("read untracked file as UTF-8 {}", full_path.display()))?;
    let path = path.to_string_lossy().replace('\\', "/");
    let mut diff = format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\nindex 0000000..0000000\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{} @@\n",
        text.lines().count()
    );
    for line in text.lines() {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    Ok(Some(diff))
}
