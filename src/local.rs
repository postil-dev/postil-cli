//! Local diff acquisition: the same engine, before the PR exists.

use std::io::{Read, Write};
use std::process::Stdio;

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::diff::{DiffSnapshot, DiffSpool};

pub enum LocalSource {
    /// `git diff --cached`
    Staged,
    /// `git diff <base>...HEAD` (merge-base semantics, like a PR diff)
    Base(String),
    /// A unified diff already on disk.
    DiffFile(std::path::PathBuf),
    /// Read-only staged selection for bare `postil review`.
    AutoStaged { fence: LocalStateFence },
    /// A clean branch range has an immutable HEAD revision. A dirty branch
    /// range includes the working tree and deliberately has no revision.
    AutoBranch {
        base_ref: String,
        base_oid: String,
        include_worktree: bool,
        fence: LocalStateFence,
    },
    /// Tracked working-tree changes only, never untracked files.
    WorkingTree { fence: LocalStateFence },
    /// A clean repository has a valid empty review without a model request.
    Clean { fence: LocalStateFence },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStateFence {
    index_tree: String,
    tracked_worktree_sha256: String,
    tracked_worktree_dirty: bool,
    untracked_paths: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultBranch {
    reference: String,
    oid: String,
}

pub struct AutoSelection {
    pub source: LocalSource,
    pub warning: Option<&'static str>,
}

/// Select the least surprising local diff without fetching or changing Git
/// refs or the index. Capturing the index may materialize its immutable tree.
pub async fn auto_select(
    repository_root: &std::path::Path,
    head_sha: Option<&str>,
) -> Result<AutoSelection> {
    let fence = capture_local_state(repository_root).await?;
    let warning = (!fence.untracked_paths.trim().is_empty()).then_some(
        "untracked files were not reviewed; add the files you want reviewed, then rerun `postil review`",
    );
    let index_base = match head_sha {
        Some(head_sha) => head_sha.to_string(),
        None => empty_tree(repository_root).await?,
    };
    if git_has_changes(
        repository_root,
        &[
            "diff",
            "--quiet",
            index_base.as_str(),
            fence.index_tree.as_str(),
            "--",
        ],
    )
    .await?
    {
        return Ok(AutoSelection {
            source: LocalSource::AutoStaged { fence },
            warning,
        });
    }
    let default_branch = if head_sha.is_some() {
        Some(default_branch(repository_root).await?.ok_or_else(|| {
            anyhow!(
                "could not determine the repository default branch without fetching; rerun with `--base <ref>`, or use `--staged` or `--diff-file <path>` for an explicit review source"
            )
        })?)
    } else {
        None
    };
    if let (Some(base), Some(head_sha)) = (default_branch, head_sha) {
        let range = format!("{}...{head_sha}", base.oid);
        if git_has_changes(repository_root, &["diff", "--quiet", &range, "--"]).await? {
            let include_worktree = fence.tracked_worktree_dirty;
            return Ok(AutoSelection {
                source: LocalSource::AutoBranch {
                    base_ref: base.reference,
                    base_oid: base.oid,
                    include_worktree,
                    fence,
                },
                warning,
            });
        }
    }
    if fence.tracked_worktree_dirty {
        return Ok(AutoSelection {
            source: LocalSource::WorkingTree { fence },
            warning,
        });
    }
    Ok(AutoSelection {
        source: LocalSource::Clean { fence },
        warning,
    })
}

pub struct LocalReviewSnapshot {
    pub diff: DiffSnapshot,
    /// Immutable Git object that contains the repository state reviewed by the
    /// repository-context search. A diff file has no independently proven
    /// repository identity, so it deliberately has no revision.
    pub repository_revision: Option<String>,
}

pub async fn acquire(
    source: &LocalSource,
    head_sha: Option<&str>,
    repository_root: &std::path::Path,
) -> Result<LocalReviewSnapshot> {
    match source {
        LocalSource::DiffFile(path) => Ok(LocalReviewSnapshot {
            diff: DiffSnapshot::from_path(path)?,
            repository_revision: None,
        }),
        LocalSource::Staged => acquire_index_snapshot(head_sha, repository_root).await,
        LocalSource::AutoStaged { fence } => {
            acquire_automatic(
                repository_root,
                head_sha,
                fence,
                None,
                acquire_index_tree_snapshot(head_sha, &fence.index_tree, repository_root),
            )
            .await
        }
        LocalSource::Base(base) => {
            let base_oid = resolve_commit_oid(repository_root, base).await?;
            let range = format!("{base_oid}...{}", head_sha.unwrap_or("HEAD"));
            Ok(LocalReviewSnapshot {
                diff: git_diff(repository_root, &["diff", "--no-color", &range]).await?,
                repository_revision: head_sha.map(str::to_string),
            })
        }
        LocalSource::AutoBranch {
            base_ref,
            base_oid,
            include_worktree,
            fence,
        } => {
            let head_sha = head_sha.context("automatic branch review requires a captured HEAD")?;
            anyhow::ensure!(
                crate::repository_search::valid_full_object_id(head_sha),
                "automatic branch review captured an invalid HEAD object id"
            );
            acquire_automatic(
                repository_root,
                Some(head_sha),
                fence,
                Some((base_ref.as_str(), base_oid.as_str())),
                async {
                    let merge_base = git_output(
                        repository_root,
                        &["merge-base", base_oid.as_str(), head_sha],
                    )
                    .await?;
                    let range = format!("{base_oid}...{head_sha}");
                    let diff = if *include_worktree {
                        git_diff(
                            repository_root,
                            &["diff", "--no-color", merge_base.as_str(), "--"],
                        )
                        .await?
                    } else {
                        git_diff(
                            repository_root,
                            &["diff", "--no-color", range.as_str(), "--"],
                        )
                        .await?
                    };
                    Ok(LocalReviewSnapshot {
                        diff,
                        repository_revision: (!include_worktree).then(|| head_sha.to_string()),
                    })
                },
            )
            .await
        }
        LocalSource::WorkingTree { fence } => {
            acquire_automatic(repository_root, head_sha, fence, None, async {
                Ok(LocalReviewSnapshot {
                    diff: git_diff(repository_root, &["diff", "--no-color", "--"]).await?,
                    repository_revision: None,
                })
            })
            .await
        }
        LocalSource::Clean { fence } => {
            acquire_automatic(repository_root, head_sha, fence, None, async {
                Ok(LocalReviewSnapshot {
                    diff: DiffSnapshot::from_bytes(b"")?,
                    repository_revision: head_sha.map(str::to_string),
                })
            })
            .await
        }
    }
}

async fn acquire_automatic<T>(
    repository_root: &std::path::Path,
    captured_head: Option<&str>,
    fence: &LocalStateFence,
    base: Option<(&str, &str)>,
    acquisition: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    ensure_automatic_state(
        repository_root,
        captured_head,
        fence,
        base,
        "after automatic review selection",
    )
    .await?;
    let value = acquisition.await?;
    ensure_automatic_state(
        repository_root,
        captured_head,
        fence,
        base,
        "while acquiring the automatic review",
    )
    .await?;
    Ok(value)
}

async fn acquire_index_snapshot(
    head_sha: Option<&str>,
    repository_root: &std::path::Path,
) -> Result<LocalReviewSnapshot> {
    let index_tree = capture_index_tree(repository_root).await?;
    acquire_index_tree_snapshot(head_sha, &index_tree, repository_root).await
}

async fn acquire_index_tree_snapshot(
    head_sha: Option<&str>,
    index_tree: &str,
    repository_root: &std::path::Path,
) -> Result<LocalReviewSnapshot> {
    let base_revision = match head_sha {
        Some(head_sha) => head_sha.to_string(),
        None => empty_tree(repository_root).await?,
    };
    if !crate::repository_search::valid_full_object_id(index_tree) {
        return Err(anyhow!("git write-tree returned an invalid object id"));
    }
    Ok(LocalReviewSnapshot {
        diff: git_diff(
            repository_root,
            &["diff", "--no-color", &base_revision, index_tree, "--"],
        )
        .await?,
        repository_revision: Some(index_tree.to_string()),
    })
}

async fn capture_local_state(repository_root: &std::path::Path) -> Result<LocalStateFence> {
    let index_tree = capture_index_tree(repository_root).await?;
    let tracked = git_diff(
        repository_root,
        &[
            "diff",
            "--no-color",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--",
        ],
    )
    .await?;
    let tracked_worktree_dirty = !tracked.as_bytes().is_empty();
    let tracked_worktree_sha256 = Sha256::digest(tracked.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let untracked_paths = git_succeeds(
        repository_root,
        &["ls-files", "--others", "--exclude-standard"],
    )
    .await?;
    Ok(LocalStateFence {
        index_tree,
        tracked_worktree_sha256,
        tracked_worktree_dirty,
        untracked_paths,
    })
}

async fn capture_index_tree(repository_root: &std::path::Path) -> Result<String> {
    let index_tree = git_output(repository_root, &["write-tree"]).await?;
    anyhow::ensure!(
        crate::repository_search::valid_full_object_id(&index_tree),
        "git write-tree returned an invalid object id"
    );
    Ok(index_tree)
}

async fn empty_tree(repository_root: &std::path::Path) -> Result<String> {
    git_output(repository_root, &["mktree"]).await
}

async fn ensure_automatic_state(
    repository_root: &std::path::Path,
    captured_head: Option<&str>,
    fence: &LocalStateFence,
    base: Option<(&str, &str)>,
    timing: &str,
) -> Result<()> {
    ensure_captured_head(repository_root, captured_head, timing).await?;
    if let Some((base_ref, base_oid)) = base {
        let current_base = resolve_commit_oid(repository_root, base_ref).await.ok();
        anyhow::ensure!(
            current_base.as_deref() == Some(base_oid),
            "default branch {base_ref} changed {timing}; rerun `postil review`"
        );
    }
    let current = capture_local_state(repository_root).await?;
    anyhow::ensure!(
        current.index_tree == fence.index_tree,
        "index changed {timing}; rerun `postil review`"
    );
    anyhow::ensure!(
        current.tracked_worktree_sha256 == fence.tracked_worktree_sha256,
        "tracked working tree changed {timing}; rerun `postil review`"
    );
    anyhow::ensure!(
        current.untracked_paths == fence.untracked_paths,
        "untracked file set changed {timing}; rerun `postil review`"
    );
    Ok(())
}

async fn ensure_captured_head(
    repository_root: &std::path::Path,
    captured_head: Option<&str>,
    timing: &str,
) -> Result<()> {
    let current_head = head_sha(repository_root).await?;
    anyhow::ensure!(
        current_head.as_deref() == captured_head,
        "HEAD changed {timing}; rerun `postil review`"
    );
    Ok(())
}

async fn git_succeeds(repository_root: &std::path::Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .await
        .context("running git")?;
    if !output.status.success() {
        return Err(anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).context("git output is not UTF-8")
}

async fn git_has_changes(repository_root: &std::path::Path, args: &[&str]) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .await
        .context("running git")?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

async fn default_branch(repository_root: &std::path::Path) -> Result<Option<DefaultBranch>> {
    let current = git_output(repository_root, &["branch", "--show-current"])
        .await
        .ok()
        .filter(|branch| !branch.is_empty());
    let configured_remote = if let Some(current) = current.as_deref() {
        git_output(
            repository_root,
            &["config", "--get", &format!("branch.{current}.remote")],
        )
        .await
        .ok()
    } else {
        None
    };
    let known_remotes = git_output(repository_root, &["remote"])
        .await
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|remote| !remote.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut remotes = Vec::new();
    if let Some(remote) = configured_remote.filter(|remote| !remote.is_empty() && remote != ".") {
        remotes.push(remote);
    }
    if known_remotes.iter().any(|remote| remote == "origin")
        && !remotes.iter().any(|remote| remote == "origin")
    {
        remotes.push("origin".to_string());
    }
    for remote in known_remotes {
        if !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    for remote in remotes {
        let mut candidates = Vec::new();
        if let Ok(symbolic) = git_output(
            repository_root,
            &[
                "symbolic-ref",
                "--quiet",
                "--short",
                &format!("refs/remotes/{remote}/HEAD"),
            ],
        )
        .await
        {
            candidates.push(symbolic);
        }
        candidates.extend([
            format!("refs/remotes/{remote}/main"),
            format!("refs/remotes/{remote}/master"),
            format!("refs/remotes/{remote}/trunk"),
        ]);
        if let Some(branch) = first_resolved_branch(repository_root, candidates).await? {
            return Ok(Some(branch));
        }
    }
    first_resolved_branch(
        repository_root,
        ["main", "master", "trunk"]
            .into_iter()
            .filter(|candidate| current.as_deref() != Some(*candidate))
            .map(str::to_string),
    )
    .await
}

async fn first_resolved_branch(
    repository_root: &std::path::Path,
    candidates: impl IntoIterator<Item = String>,
) -> Result<Option<DefaultBranch>> {
    for candidate in candidates {
        if let Ok(oid) = resolve_commit_oid(repository_root, &candidate).await {
            return Ok(Some(DefaultBranch {
                reference: candidate,
                oid,
            }));
        }
    }
    Ok(None)
}

async fn resolve_commit_oid(repository_root: &std::path::Path, reference: &str) -> Result<String> {
    let oid = git_output(
        repository_root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{reference}^{{commit}}"),
        ],
    )
    .await?;
    anyhow::ensure!(
        crate::repository_search::valid_full_object_id(&oid),
        "git rev-parse returned an invalid commit object id"
    );
    Ok(oid)
}

async fn git_output(repository_root: &std::path::Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .await
        .context("running git")?;
    if !output.status.success() {
        return Err(anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .context("git output is not UTF-8")
        .map(|value| value.trim().to_string())
}

async fn git_diff(repository_root: &std::path::Path, args: &[&str]) -> Result<DiffSnapshot> {
    let repository_root = repository_root.to_path_buf();
    let owned: Vec<String> = args
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
    tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository_root)
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

pub async fn head_sha(repository_root: &std::path::Path) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()
        .await
        .context("running git rev-parse")?;
    match output.status.code() {
        Some(0) => {
            let head = String::from_utf8(output.stdout)
                .context("git rev-parse output is not UTF-8")?
                .trim()
                .to_string();
            anyhow::ensure!(
                crate::repository_search::valid_full_object_id(&head),
                "git rev-parse returned an invalid HEAD object id"
            );
            Ok(Some(head))
        }
        Some(1) => Ok(None),
        _ => Err(anyhow!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run_git(root: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn create_commit(root: &Path) -> String {
        run_git(root, &["add", "-A"]);
        let tree = run_git(root, &["write-tree"]);
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["commit-tree", &tree, "-m", "fixture"])
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(output.status.success());
        let commit = String::from_utf8(output.stdout).unwrap().trim().to_string();
        run_git(root, &["update-ref", "HEAD", &commit]);
        commit
    }

    fn commit_from_head(root: &Path) -> String {
        run_git(root, &["add", "-A"]);
        let tree = run_git(root, &["write-tree"]);
        let parent = run_git(root, &["rev-parse", "HEAD"]);
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["commit-tree", &tree, "-p", &parent, "-m", "fixture"])
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(output.status.success());
        let commit = String::from_utf8(output.stdout).unwrap().trim().to_string();
        run_git(root, &["update-ref", "HEAD", &commit]);
        commit
    }

    fn repository_with_main_and_feature(root: &Path) -> String {
        run_git(root, &["init", "--quiet"]);
        std::fs::write(root.join("tracked.txt"), "base\n").unwrap();
        let base = create_commit(root);
        if run_git(root, &["branch", "--show-current"]) != "main" {
            run_git(root, &["branch", "main", &base]);
        }
        run_git(root, &["checkout", "--quiet", "-b", "feature"]);
        base
    }

    #[tokio::test]
    async fn bare_selection_prefers_one_immutable_staged_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "staged\n").unwrap();
        run_git(root, &["add", "tracked.txt"]);
        std::fs::write(root.join("tracked.txt"), "working\n").unwrap();

        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::AutoStaged { .. }));
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+staged"));
        assert!(!snapshot.diff.as_str().contains("+working"));
        let revision = snapshot.repository_revision.as_deref().unwrap();
        assert_eq!(
            run_git(root, &["show", &format!("{revision}:tracked.txt")]),
            "staged"
        );
    }

    #[tokio::test]
    async fn bare_selection_uses_current_remote_symbolic_default_before_main_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let base = run_git(root, &["rev-parse", "main"]);
        run_git(root, &["update-ref", "refs/remotes/origin/trunk", &base]);
        run_git(
            root,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/trunk",
            ],
        );
        run_git(root, &["config", "branch.feature.remote", "origin"]);
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        let head = commit_from_head(root);

        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(
            matches!(selection.source, LocalSource::AutoBranch { ref base_ref, include_worktree: false, .. } if base_ref == "origin/trunk")
        );
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+committed"));
        assert_eq!(snapshot.repository_revision.as_deref(), Some(head.as_str()));
    }

    #[tokio::test]
    async fn bare_selection_uses_remote_default_without_a_branch_upstream() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let base = run_git(root, &["rev-parse", "main"]);
        run_git(root, &["update-ref", "refs/remotes/origin/trunk", &base]);
        run_git(
            root,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/trunk",
            ],
        );
        run_git(
            root,
            &[
                "remote",
                "add",
                "origin",
                "https://example.invalid/repository.git",
            ],
        );
        assert!(
            std::process::Command::new("git")
                .args([
                    "-C",
                    root.to_str().unwrap(),
                    "config",
                    "--get",
                    "branch.feature.remote"
                ])
                .output()
                .unwrap()
                .stdout
                .is_empty()
        );
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        let head = commit_from_head(root);

        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(
            matches!(selection.source, LocalSource::AutoBranch { ref base_ref, include_worktree: false, .. } if base_ref == "origin/trunk")
        );
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+committed"));
        assert_eq!(snapshot.repository_revision.as_deref(), Some(head.as_str()));
    }

    #[tokio::test]
    async fn bare_selection_uses_remote_trunk_without_a_symbolic_remote_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let base = run_git(root, &["rev-parse", "main"]);
        run_git(
            root,
            &[
                "remote",
                "add",
                "origin",
                "https://example.invalid/repository.git",
            ],
        );
        run_git(root, &["update-ref", "refs/remotes/origin/trunk", &base]);
        run_git(root, &["branch", "-D", "main"]);
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        let head = commit_from_head(root);

        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(
            matches!(selection.source, LocalSource::AutoBranch { ref base_ref, include_worktree: false, .. } if base_ref == "refs/remotes/origin/trunk")
        );
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+committed"));
        assert_eq!(snapshot.repository_revision.as_deref(), Some(head.as_str()));
    }

    #[tokio::test]
    async fn bare_selection_fails_closed_when_the_default_branch_is_unresolved() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        run_git(root, &["init", "--quiet"]);
        run_git(root, &["symbolic-ref", "HEAD", "refs/heads/feature"]);
        std::fs::write(root.join("tracked.txt"), "committed\n").unwrap();
        let head = create_commit(root);

        let error = match auto_select(root, Some(&head)).await {
            Ok(_) => panic!("an unresolved default branch must not produce a partial review"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("could not determine the repository default branch"));
        assert!(message.contains("--base <ref>"));
        assert!(message.contains("--staged"));
        assert!(message.contains("--diff-file <path>"));
    }

    #[tokio::test]
    async fn bare_selection_rejects_the_current_local_default_branch_without_a_remote() {
        for branch in ["main", "trunk"] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            run_git(root, &["init", "--quiet"]);
            run_git(
                root,
                &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
            );
            std::fs::write(root.join("tracked.txt"), "committed\n").unwrap();
            let head = create_commit(root);

            let error = match auto_select(root, Some(&head)).await {
                Ok(_) => panic!(
                    "the checked-out local {branch} branch must not be its own automatic base"
                ),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains("could not determine the repository default branch"));
            assert!(message.contains("--base <ref>"));
            assert!(message.contains("--staged"));
            assert!(message.contains("--diff-file <path>"));
        }
    }

    #[tokio::test]
    async fn configured_remote_main_precedes_another_remote_symbolic_default() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let base = run_git(root, &["rev-parse", "main"]);
        run_git(
            root,
            &[
                "remote",
                "add",
                "upstream",
                "https://example.invalid/upstream.git",
            ],
        );
        run_git(
            root,
            &[
                "remote",
                "add",
                "origin",
                "https://example.invalid/origin.git",
            ],
        );
        run_git(root, &["update-ref", "refs/remotes/upstream/main", &base]);
        run_git(root, &["update-ref", "refs/remotes/origin/trunk", &base]);
        run_git(
            root,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/trunk",
            ],
        );
        run_git(root, &["config", "branch.feature.remote", "upstream"]);
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        let head = commit_from_head(root);

        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(
            selection.source,
            LocalSource::AutoBranch {
                ref base_ref,
                include_worktree: false,
                ..
            } if base_ref == "refs/remotes/upstream/main"
        ));
    }

    #[tokio::test]
    async fn clean_automatic_branch_review_rejects_a_changed_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("captured.txt"), "captured\n").unwrap();
        let captured_head = commit_from_head(root);

        let selection = auto_select(root, Some(&captured_head)).await.unwrap();
        assert!(matches!(
            selection.source,
            LocalSource::AutoBranch {
                include_worktree: false,
                ..
            }
        ));

        std::fs::write(root.join("later.txt"), "later\n").unwrap();
        let later_head = commit_from_head(root);
        assert_ne!(captured_head, later_head);

        let error = match acquire(&selection.source, Some(&captured_head), root).await {
            Ok(_) => panic!("a clean automatic branch review must reject a moving HEAD"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HEAD changed"));
    }

    #[tokio::test]
    async fn dirty_automatic_branch_review_rejects_a_changed_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("captured.txt"), "captured\n").unwrap();
        let captured_head = commit_from_head(root);
        std::fs::write(root.join("tracked.txt"), "dirty\n").unwrap();

        let selection = auto_select(root, Some(&captured_head)).await.unwrap();
        assert!(matches!(
            selection.source,
            LocalSource::AutoBranch {
                include_worktree: true,
                ..
            }
        ));

        commit_from_head(root);
        let error = match acquire(&selection.source, Some(&captured_head), root).await {
            Ok(_) => panic!("a dirty automatic review must not follow a moving HEAD"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HEAD changed"));
    }

    #[tokio::test]
    async fn automatic_staged_review_rejects_a_changed_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "staged\n").unwrap();
        run_git(root, &["add", "tracked.txt"]);
        let captured_head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&captured_head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::AutoStaged { .. }));

        commit_from_head(root);
        let error = match acquire(&selection.source, Some(&captured_head), root).await {
            Ok(_) => panic!("an automatic staged review must reject a moving HEAD"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HEAD changed"));
    }

    #[tokio::test]
    async fn automatic_worktree_review_rejects_a_changed_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "working\n").unwrap();
        let captured_head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&captured_head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::WorkingTree { .. }));

        commit_from_head(root);
        let error = match acquire(&selection.source, Some(&captured_head), root).await {
            Ok(_) => panic!("an automatic worktree review must reject a moving HEAD"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HEAD changed"));
    }

    #[tokio::test]
    async fn automatic_clean_review_rejects_a_changed_head() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let captured_head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&captured_head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::Clean { .. }));

        std::fs::write(root.join("later.txt"), "later\n").unwrap();
        commit_from_head(root);
        let error = match acquire(&selection.source, Some(&captured_head), root).await {
            Ok(_) => panic!("an automatic clean review must reject a moving HEAD"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HEAD changed"));
    }

    #[tokio::test]
    async fn automatic_acquisition_rejects_a_head_change_after_reading_the_source() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let captured_head = run_git(root, &["rev-parse", "HEAD"]);
        let fence = capture_local_state(root).await.unwrap();

        let error = acquire_automatic(root, Some(&captured_head), &fence, None, async {
            let acquired_head = run_git(root, &["rev-parse", "HEAD"]);
            std::fs::write(root.join("later.txt"), "later\n").unwrap();
            commit_from_head(root);
            Ok(acquired_head)
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HEAD changed while acquiring the automatic review")
        );
    }

    #[tokio::test]
    async fn automatic_branch_review_rejects_a_moved_base_ref() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        let head = commit_from_head(root);
        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::AutoBranch { .. }));

        run_git(root, &["update-ref", "refs/heads/main", &head]);
        let error = match acquire(&selection.source, Some(&head), root).await {
            Ok(_) => panic!("an automatic branch review must reject a moved base ref"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("default branch main changed"));
    }

    #[tokio::test]
    async fn automatic_staged_review_rejects_an_index_change() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "staged-one\n").unwrap();
        run_git(root, &["add", "tracked.txt"]);
        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();

        std::fs::write(root.join("tracked.txt"), "staged-two\n").unwrap();
        run_git(root, &["add", "tracked.txt"]);
        let error = match acquire(&selection.source, Some(&head), root).await {
            Ok(_) => panic!("an automatic staged review must reject an index change"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("index changed"));
    }

    #[tokio::test]
    async fn automatic_worktree_review_rejects_a_tracked_change() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "working-one\n").unwrap();
        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();

        std::fs::write(root.join("tracked.txt"), "working-two\n").unwrap();
        let error = match acquire(&selection.source, Some(&head), root).await {
            Ok(_) => panic!("an automatic worktree review must reject a tracked change"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("tracked working tree changed"));
    }

    #[tokio::test]
    async fn automatic_clean_review_rejects_a_new_tracked_change() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();

        std::fs::write(root.join("tracked.txt"), "later\n").unwrap();
        let error = match acquire(&selection.source, Some(&head), root).await {
            Ok(_) => panic!("an automatic clean review must reject a tracked change"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("tracked working tree changed"));
    }

    #[tokio::test]
    async fn bare_selection_combines_committed_branch_and_tracked_worktree_changes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("branch.txt"), "committed\n").unwrap();
        commit_from_head(root);
        std::fs::write(root.join("tracked.txt"), "working\n").unwrap();

        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(
            selection.source,
            LocalSource::AutoBranch {
                include_worktree: true,
                ..
            }
        ));
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+committed"));
        assert!(snapshot.diff.as_str().contains("+working"));
        assert!(snapshot.repository_revision.is_none());
    }

    #[tokio::test]
    async fn bare_selection_falls_back_to_tracked_worktree_then_clean_diff() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("tracked.txt"), "working\n").unwrap();
        let head = run_git(root, &["rev-parse", "HEAD"]);
        let working = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(working.source, LocalSource::WorkingTree { .. }));

        std::fs::write(root.join("tracked.txt"), "base\n").unwrap();
        let clean = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(clean.source, LocalSource::Clean { .. }));
        assert!(
            acquire(&clean.source, Some(&head), root)
                .await
                .unwrap()
                .diff
                .as_str()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bare_selection_warns_about_untracked_files_without_claiming_them_reviewed() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        repository_with_main_and_feature(root);
        std::fs::write(root.join("new.txt"), "untracked\n").unwrap();
        let head = run_git(root, &["rev-parse", "HEAD"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(selection.source, LocalSource::Clean { .. }));
        assert!(
            selection
                .warning
                .unwrap()
                .contains("untracked files were not reviewed")
        );
    }

    #[tokio::test]
    async fn automatic_staged_review_matches_explicit_diff_and_searches_the_same_index_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        run_git(root, &["init", "--quiet"]);
        std::fs::write(root.join("config.yaml"), "version: base\n").unwrap();
        let head = create_commit(root);

        std::fs::write(root.join("config.yaml"), "version: staged-one\n").unwrap();
        run_git(root, &["add", "config.yaml"]);
        let selection = auto_select(root, Some(&head)).await.unwrap();
        let automatic = acquire(&selection.source, Some(&head), root).await.unwrap();
        let explicit = acquire(&LocalSource::Staged, Some(&head), root)
            .await
            .unwrap();
        assert_eq!(automatic.diff.as_str(), explicit.diff.as_str());
        assert_eq!(automatic.repository_revision, explicit.repository_revision);

        std::fs::write(root.join("config.yaml"), "version: staged-two\n").unwrap();
        run_git(root, &["add", "config.yaml"]);
        let revision = automatic.repository_revision.as_deref().unwrap();
        assert_eq!(
            run_git(root, &["show", &format!("{revision}:config.yaml")]),
            "version: staged-one"
        );
        assert!(automatic.diff.as_str().contains("+version: staged-one"));
        assert!(!automatic.diff.as_str().contains("staged-two"));

        let finding = crate::envelope::Finding {
            path: "config.yaml".into(),
            line: 1,
            end_line: None,
            severity: crate::envelope::Severity::Warn,
            kind: crate::envelope::Kind::Uncertainty,
            confidence: 0.8,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: Some(crate::envelope::RepositoryClaim {
                kind: crate::envelope::RepositoryClaimKind::Absence,
                resources: vec![],
                values: vec!["staged-one".into(), "staged-two".into()],
                versions: vec![],
                paths: vec![],
                identifiers: vec![],
            }),
            machine_claim: None,
            machine_claim_deferred: false,
            title: "Repository state".into(),
            body: "The immutable index tree contains the reviewed value.".into(),
            evidence: Some("version: staged-one".into()),
            id: None,
        };
        let receipt = crate::repository_search::search(
            &crate::repository_search::RepositorySource::Local(root),
            Some(revision),
            std::iter::once(&finding),
        )
        .await;
        assert_eq!(
            receipt.state,
            crate::envelope::RepositorySearchState::Complete
        );
        assert_eq!(receipt.head_sha.as_deref(), Some(revision));
        assert!(receipt.tree_sha256.is_some());
        assert_eq!(receipt.queries.len(), 2);
        assert_eq!(receipt.matched_query_sha256.len(), 1);
    }

    #[tokio::test]
    async fn arbitrary_diff_file_has_no_proven_repository_revision() {
        let diff = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(diff.path(), "diff --git a/a b/a\n").unwrap();
        let snapshot = acquire(
            &LocalSource::DiffFile(diff.path().into()),
            None,
            Path::new("."),
        )
        .await
        .unwrap();
        assert!(snapshot.repository_revision.is_none());
    }
}
