use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};

use crate::config::{RepoReviewConfig, translate_coderabbit, translate_kodo};
use crate::text::limit_text;

pub fn collect_diff(dir: &Path, limit: usize) -> Result<String> {
    let root = repo_root(dir)?;
    let scope = repo_scope(&root, dir)?;
    let mut diff = tracked_diff(&root, &scope)?;
    diff = limit_text(diff, limit);
    let untracked = untracked_files(&root, &scope)?;
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

fn repo_scope(root: &Path, dir: &Path) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve git repository root {}", root.display()))?;
    let dir = dir
        .canonicalize()
        .with_context(|| format!("resolve local directory {}", dir.display()))?;
    let scope = dir
        .strip_prefix(&root)
        .with_context(|| format!("{} is not inside {}", dir.display(), root.display()))?;
    Ok(if scope.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        scope.to_path_buf()
    })
}

fn tracked_diff(root: &Path, scope: &Path) -> Result<String> {
    let scope = git_pathspec(scope);
    let baseline = if has_head(root)? {
        vec![
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            "HEAD",
            "--",
            &scope,
        ]
    } else {
        vec![
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            "--",
            &scope,
        ]
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

fn git_pathspec(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
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

fn untracked_files(root: &Path, scope: &Path) -> Result<Vec<PathBuf>> {
    let scope = git_pathspec(scope);
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            &scope,
        ])
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
    let metadata = fs::symlink_metadata(&full_path)
        .with_context(|| format!("read untracked file metadata {}", full_path.display()))?;
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let file = fs::File::open(&full_path)
        .with_context(|| format!("open untracked file {}", full_path.display()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read untracked file {}", full_path.display()))?;
    if bytes.contains(&0) {
        return Ok(None);
    }
    let truncated = metadata.len() > max_bytes as u64;
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => {
            let valid_up_to = err.utf8_error().valid_up_to();
            if valid_up_to == 0 {
                return Ok(None);
            }
            let bytes = err.into_bytes();
            String::from_utf8(bytes[..valid_up_to].to_vec())
                .with_context(|| format!("read untracked file as UTF-8 {}", full_path.display()))?
        }
    };
    let path = path.to_string_lossy().replace('\\', "/");
    let line_count = text.lines().count() + usize::from(truncated);
    let mut diff = format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\nindex 0000000..0000000\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{} @@\n",
        line_count
    );
    for line in text.lines() {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    if truncated {
        diff.push_str("+[untracked file truncated]\n");
    }
    Ok(Some(diff))
}

#[cfg(test)]
mod tests {
    use super::collect_diff;
    use std::{fs, path::Path};

    use tempfile::tempdir;

    fn git<const N: usize>(repo: &Path, args: [&str; N]) {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
            ])
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn scopes_diff_to_requested_subdirectory() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, ["init"]);
        git(&repo, ["config", "user.email", "test@example.com"]);
        git(&repo, ["config", "user.name", "Test User"]);
        fs::create_dir(repo.join("nested")).unwrap();
        fs::write(repo.join("root.txt"), "root\n").unwrap();
        fs::write(repo.join("nested/inside.txt"), "inside\n").unwrap();
        git(&repo, ["add", "."]);
        git(&repo, ["commit", "-m", "initial"]);
        fs::write(repo.join("root.txt"), "root changed\n").unwrap();
        fs::write(repo.join("nested/inside.txt"), "inside changed\n").unwrap();
        fs::write(repo.join("nested/untracked.txt"), "nested new\n").unwrap();
        fs::write(repo.join("untracked.txt"), "outside new\n").unwrap();

        let diff = collect_diff(&repo.join("nested"), 16_384).unwrap();
        assert!(diff.contains("nested/inside.txt"));
        assert!(diff.contains("nested/untracked.txt"));
        assert!(!diff.contains("diff --git a/root.txt"));
        assert!(!diff.contains("outside new"));
    }

    #[test]
    fn truncates_large_untracked_files_instead_of_skipping_them() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, ["init"]);
        git(&repo, ["config", "user.email", "test@example.com"]);
        git(&repo, ["config", "user.name", "Test User"]);
        fs::write(repo.join("tracked.txt"), "tracked\n").unwrap();
        git(&repo, ["add", "."]);
        git(&repo, ["commit", "-m", "initial"]);
        fs::write(repo.join("large.txt"), "x".repeat(4_096)).unwrap();

        let diff = collect_diff(&repo, 128).unwrap();
        assert!(diff.contains("large.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_untracked_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        let outside = dir.path().join("secret.txt");
        fs::create_dir(&repo).unwrap();
        fs::write(&outside, "super secret\n").unwrap();
        git(&repo, ["init"]);
        git(&repo, ["config", "user.email", "test@example.com"]);
        git(&repo, ["config", "user.name", "Test User"]);
        fs::write(repo.join("tracked.txt"), "tracked\n").unwrap();
        git(&repo, ["add", "."]);
        git(&repo, ["commit", "-m", "initial"]);
        symlink(&outside, repo.join("link.txt")).unwrap();

        let diff = collect_diff(&repo, 16_384).unwrap();
        assert!(!diff.contains("super secret"));
        assert!(!diff.contains("link.txt"));
    }
}
