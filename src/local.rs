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
    /// Read-only staged selection for bare `postil review`.
    AutoStaged,
    /// A clean branch range has an immutable HEAD revision. A dirty branch
    /// range includes the working tree and deliberately has no revision.
    AutoBranch {
        base: String,
        include_worktree: bool,
    },
    /// Tracked working-tree changes only, never untracked files.
    WorkingTree,
    /// A clean repository has a valid empty review without a model request.
    Clean,
}

pub struct AutoSelection {
    pub source: LocalSource,
    pub warning: Option<&'static str>,
}

/// Select the least surprising local diff without fetching, writing Git
/// objects, or changing the index. Explicit local modes bypass this selector.
pub async fn auto_select(
    repository_root: &std::path::Path,
    head_sha: Option<&str>,
) -> Result<AutoSelection> {
    let untracked = !git_succeeds(
        repository_root,
        &["ls-files", "--others", "--exclude-standard"],
    )
    .await?
    .trim()
    .is_empty();
    let warning = untracked.then_some(
        "untracked files were not reviewed; add the files you want reviewed, then rerun `postil review`",
    );
    if git_has_changes(repository_root, &["diff", "--cached", "--quiet", "--"]).await? {
        return Ok(AutoSelection {
            source: LocalSource::AutoStaged,
            warning,
        });
    }
    if let (Some(base), Some(head_sha)) = (default_branch(repository_root).await?, head_sha) {
        let range = format!("{base}...{head_sha}");
        if git_has_changes(repository_root, &["diff", "--quiet", &range, "--"]).await? {
            let include_worktree =
                git_has_changes(repository_root, &["diff", "--quiet", "--"]).await?;
            return Ok(AutoSelection {
                source: LocalSource::AutoBranch {
                    base,
                    include_worktree,
                },
                warning,
            });
        }
    }
    if git_has_changes(repository_root, &["diff", "--quiet", "--"]).await? {
        return Ok(AutoSelection {
            source: LocalSource::WorkingTree,
            warning,
        });
    }
    Ok(AutoSelection {
        source: LocalSource::Clean,
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
        LocalSource::AutoStaged => {
            acquire_automatic(
                repository_root,
                head_sha,
                acquire_index_snapshot(head_sha, repository_root),
            )
            .await
        }
        LocalSource::Base(base) => {
            let range = format!("{base}...{}", head_sha.unwrap_or("HEAD"));
            Ok(LocalReviewSnapshot {
                diff: git_diff(repository_root, &["diff", "--no-color", &range]).await?,
                repository_revision: head_sha.map(str::to_string),
            })
        }
        LocalSource::AutoBranch {
            base,
            include_worktree,
        } => {
            let head_sha = head_sha.context("automatic branch review requires a captured HEAD")?;
            anyhow::ensure!(
                crate::repository_search::valid_full_object_id(head_sha),
                "automatic branch review captured an invalid HEAD object id"
            );
            acquire_automatic(repository_root, Some(head_sha), async {
                let merge_base =
                    git_output(repository_root, &["merge-base", base, head_sha]).await?;
                let range = format!("{base}...{head_sha}");
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
            })
            .await
        }
        LocalSource::WorkingTree => {
            acquire_automatic(repository_root, head_sha, async {
                Ok(LocalReviewSnapshot {
                    diff: git_diff(repository_root, &["diff", "--no-color", "--"]).await?,
                    repository_revision: None,
                })
            })
            .await
        }
        LocalSource::Clean => {
            acquire_automatic(repository_root, head_sha, async {
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
    acquisition: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    ensure_captured_head(
        repository_root,
        captured_head,
        "after automatic review selection",
    )
    .await?;
    let value = acquisition.await?;
    ensure_captured_head(
        repository_root,
        captured_head,
        "while acquiring the automatic review",
    )
    .await?;
    Ok(value)
}

async fn acquire_index_snapshot(
    head_sha: Option<&str>,
    repository_root: &std::path::Path,
) -> Result<LocalReviewSnapshot> {
    let base_revision = match head_sha {
        Some(head_sha) => head_sha.to_string(),
        None => git_output(repository_root, &["mktree"]).await?,
    };
    let index_tree = git_output(repository_root, &["write-tree"]).await?;
    if !crate::repository_search::valid_full_object_id(&index_tree) {
        return Err(anyhow!("git write-tree returned an invalid object id"));
    }
    Ok(LocalReviewSnapshot {
        diff: git_diff(
            repository_root,
            &["diff", "--no-color", &base_revision, &index_tree, "--"],
        )
        .await?,
        repository_revision: Some(index_tree),
    })
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

async fn default_branch(repository_root: &std::path::Path) -> Result<Option<String>> {
    let current = match git_output(repository_root, &["branch", "--show-current"]).await {
        Ok(branch) if !branch.is_empty() => branch,
        _ => return Ok(None),
    };
    let configured_remote = git_output(
        repository_root,
        &["config", "--get", &format!("branch.{current}.remote")],
    )
    .await
    .ok();
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
    let mut candidates = Vec::new();
    for remote in &remotes {
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
    }
    for remote in remotes {
        candidates.extend([
            format!("refs/remotes/{remote}/main"),
            format!("refs/remotes/{remote}/master"),
        ]);
    }
    candidates.extend(["main".to_string(), "master".to_string()]);
    for candidate in candidates {
        if candidate != current
            && git_output(
                repository_root,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("{candidate}^{{commit}}"),
                ],
            )
            .await
            .is_ok()
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
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
        assert!(matches!(selection.source, LocalSource::AutoStaged));
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
            matches!(selection.source, LocalSource::AutoBranch { ref base, include_worktree: false } if base == "origin/trunk")
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
            matches!(selection.source, LocalSource::AutoBranch { ref base, include_worktree: false } if base == "origin/trunk")
        );
        let snapshot = acquire(&selection.source, Some(&head), root).await.unwrap();
        assert!(snapshot.diff.as_str().contains("+committed"));
        assert_eq!(snapshot.repository_revision.as_deref(), Some(head.as_str()));
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
        assert!(matches!(selection.source, LocalSource::AutoStaged));

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
        assert!(matches!(selection.source, LocalSource::WorkingTree));

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
        assert!(matches!(selection.source, LocalSource::Clean));

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

        let error = acquire_automatic(root, Some(&captured_head), async {
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
        assert!(matches!(working.source, LocalSource::WorkingTree));

        std::fs::write(root.join("tracked.txt"), "base\n").unwrap();
        let clean = auto_select(root, Some(&head)).await.unwrap();
        assert!(matches!(clean.source, LocalSource::Clean));
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
        assert!(matches!(selection.source, LocalSource::Clean));
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
        let automatic = acquire(&LocalSource::AutoStaged, Some(&head), root)
            .await
            .unwrap();
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
