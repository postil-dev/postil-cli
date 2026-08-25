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
        LocalSource::Staged => {
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
        LocalSource::Base(base) => {
            let range = format!("{base}...{}", head_sha.unwrap_or("HEAD"));
            Ok(LocalReviewSnapshot {
                diff: git_diff(repository_root, &["diff", "--no-color", &range]).await?,
                repository_revision: head_sha.map(str::to_string),
            })
        }
    }
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

    #[tokio::test]
    async fn staged_review_binds_diff_and_repository_to_one_index_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        run_git(root, &["init", "--quiet"]);
        std::fs::write(root.join("config.yaml"), "version: base\n").unwrap();
        let head = create_commit(root);

        std::fs::write(root.join("config.yaml"), "version: staged-one\n").unwrap();
        run_git(root, &["add", "config.yaml"]);
        let snapshot = acquire(&LocalSource::Staged, Some(&head), root)
            .await
            .unwrap();

        std::fs::write(root.join("config.yaml"), "version: staged-two\n").unwrap();
        run_git(root, &["add", "config.yaml"]);
        let revision = snapshot.repository_revision.as_deref().unwrap();
        assert_eq!(
            run_git(root, &["show", &format!("{revision}:config.yaml")]),
            "version: staged-one"
        );
        assert!(snapshot.diff.as_str().contains("+version: staged-one"));
        assert!(!snapshot.diff.as_str().contains("staged-two"));

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
