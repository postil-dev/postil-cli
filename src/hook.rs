//! `postil hook install`: a pre-push hook running the same engine locally.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# Installed by `postil hook install`. Reviews the exact outgoing branch diffs.
set -eu

remote_name=${1:-origin}
zero=0000000000000000000000000000000000000000
umask 077
tmp=$(mktemp "${TMPDIR:-/tmp}/postil-pre-push.XXXXXX") || {
    echo "postil: could not create a secure temporary diff" >&2
    exit 1
}
trap 'rm -f "$tmp"' EXIT HUP INT TERM

while read -r local_ref local_oid remote_ref remote_oid; do
    [ -n "${local_ref:-}" ] || continue

    # Deletions contain no outgoing code. Tags are deliberately ignored because
    # reviewing a tag as a branch diff would invent an unreliable base.
    [ "$local_oid" = "$zero" ] && continue
    case "$local_ref" in
        refs/heads/*) ;;
        *) continue ;;
    esac

    if [ "$remote_oid" != "$zero" ] && ! git cat-file -e "$remote_oid^{commit}" 2>/dev/null; then
        git fetch --quiet --no-tags "$remote_name" "$remote_oid" 2>/dev/null ||
            git fetch --quiet --no-tags "$remote_name" "$remote_ref" 2>/dev/null || true
        if ! git cat-file -e "$remote_oid^{commit}" 2>/dev/null; then
            echo "postil: cannot obtain exact remote base $remote_oid for $remote_ref; refusing an incomplete review" >&2
            exit 1
        fi
    fi

    if [ "$remote_oid" != "$zero" ]; then
        git diff --find-renames "$remote_oid" "$local_oid" -- >"$tmp"
    else
        remote_head=$(git symbolic-ref -q "refs/remotes/$remote_name/HEAD" 2>/dev/null || true)
        if [ -n "$remote_head" ] && git rev-parse --verify -q "$remote_head^{commit}" >/dev/null; then
            base=$(git merge-base "$local_oid" "$remote_head" || true)
            if [ -n "$base" ]; then
                git diff --find-renames "$base" "$local_oid" -- >"$tmp"
            else
                empty_tree=$(git hash-object -t tree /dev/null)
                git diff --find-renames "$empty_tree" "$local_oid" -- >"$tmp"
            fi
        else
            empty_tree=$(git hash-object -t tree /dev/null)
            git diff --find-renames "$empty_tree" "$local_oid" -- >"$tmp"
        fi
    fi

    [ -s "$tmp" ] || continue
    postil review --bounded --diff-file "$tmp"
done
"#;

fn git_output(repo_root: &Path, args: &[&str]) -> Result<std::process::Output> {
    let mut command = Command::new("git");
    command.current_dir(repo_root).args(args);
    #[cfg(test)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    command
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

fn hooks_dir(repo_root: &Path) -> Result<PathBuf> {
    let configured = git_output(repo_root, &["config", "--get", "core.hooksPath"])?;
    if configured.status.success() && !configured.stdout.is_empty() {
        return Err(anyhow!(
            "core.hooksPath is already configured; install Postil through that managed hook path instead"
        ));
    }

    let output = git_output(repo_root, &["rev-parse", "--git-path", "hooks"])?;
    if !output.status.success() {
        return Err(anyhow!("run `postil hook install` inside a git repository"));
    }
    let value = String::from_utf8(output.stdout)
        .context("git returned a non-UTF-8 hooks path")?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(anyhow!("git returned an empty hooks path"));
    }
    let path = PathBuf::from(value);
    Ok(if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    })
}

pub fn install(repo_root: &Path, force: bool) -> Result<()> {
    let hooks_dir = hooks_dir(repo_root)?;
    std::fs::create_dir_all(&hooks_dir).context("creating git hooks directory")?;
    let hook = hooks_dir.join("pre-push");
    if hook.exists() && !force {
        return Err(anyhow!(
            "{} already exists; re-run with --force to overwrite",
            hook.display()
        ));
    }
    std::fs::write(&hook, HOOK_SCRIPT).context("writing pre-push hook")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))?;
    }
    eprintln!("postil: installed {}", hook.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Stdio;

    fn init_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(path)
            .status()
            .unwrap();
        assert!(status.success());
        git(
            path,
            &["config", "user.email", "postil-test@example.invalid"],
        );
        git(path, &["config", "user.name", "Postil Test"]);
    }

    fn git(path: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(path)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
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

    fn commit_file(path: &Path, name: &str, content: &str) -> String {
        std::fs::write(path.join(name), content).unwrap();
        git(path, &["add", name]);
        git(path, &["commit", "-m", name]);
        git(path, &["rev-parse", "HEAD"])
    }

    fn run_hook(
        repo: &Path,
        hook: &Path,
        remote: &Path,
        input: &str,
        fake_bin: &Path,
        log: &Path,
    ) -> std::process::Output {
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // Executable permissions are asserted separately. Invoking the script
        // through its interpreter avoids a transient ETXTBSY race on filesystems
        // that delay releasing a newly written script for direct execution.
        let mut child = Command::new("sh")
            .arg(hook)
            .args(["origin", &remote.to_string_lossy()])
            .current_dir(repo)
            .env("PATH", path)
            .env("POSTIL_TEST_LOG", log)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn fake_postil(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("postil");
        std::fs::write(
            &path,
            "#!/bin/sh\nset -eu\n[ \"$1\" = review ]\n[ \"$2\" = --bounded ]\n[ \"$3\" = --diff-file ]\nprintf '%s\\n' '--- review ---' >>\"$POSTIL_TEST_LOG\"\ncat \"$4\" >>\"$POSTIL_TEST_LOG\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn installs_in_git_resolved_path_and_respects_existing() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        install(dir.path(), false).unwrap();
        let hook = dir.path().join(".git/hooks/pre-push");
        let script = std::fs::read_to_string(&hook).unwrap();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("while read -r local_ref local_oid"));
        assert!(script.contains("git diff --find-renames \"$remote_oid\" \"$local_oid\""));
        assert!(script.contains("postil review --bounded --diff-file \"$tmp\""));
        assert!(!script.contains("--no-verify"));
        assert!(script.contains("git hash-object -t tree /dev/null"));
        assert!(install(dir.path(), false).is_err());
        install(dir.path(), true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111);
        }
    }

    #[test]
    fn declines_managed_core_hooks_path() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let status = Command::new("git")
            .args(["config", "core.hooksPath", ".managed-hooks"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(status.success());

        let error = install(dir.path(), false).unwrap_err();
        assert!(error.to_string().contains("core.hooksPath"));
        assert!(!dir.path().join(".managed-hooks/pre-push").exists());
    }

    #[test]
    fn installs_from_a_linked_worktree_git_path() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let linked = dir.path().join("linked");
        std::fs::create_dir(&main).unwrap();
        init_repo(&main);
        commit_file(&main, "base.txt", "base\n");
        git(
            &main,
            &[
                "worktree",
                "add",
                "--quiet",
                "--detach",
                linked.to_str().unwrap(),
                "HEAD",
            ],
        );

        install(&linked, false).unwrap();
        let resolved = git(&linked, &["rev-parse", "--git-path", "hooks"]);
        let hooks = PathBuf::from(resolved);
        let hooks = if hooks.is_absolute() {
            hooks
        } else {
            linked.join(hooks)
        };
        assert!(hooks.join("pre-push").is_file());
    }

    #[test]
    fn installed_hook_reviews_exact_refs_and_skips_non_branches() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let remote = dir.path().join("remote.git");
        let fake_bin = dir.path().join("bin");
        let log = dir.path().join("reviews.log");
        std::fs::create_dir(&repo).unwrap();
        init_repo(&repo);
        let base = commit_file(&repo, "base.txt", "base\n");
        git(&repo, &["branch", "-M", "main"]);
        git(
            dir.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                repo.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&repo, &["update-ref", "refs/remotes/origin/main", &base]);
        git(
            &repo,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        );
        let head = commit_file(&repo, "next.txt", "next\n");
        install(&repo, false).unwrap();
        fake_postil(&fake_bin);
        let hook = repo.join(".git/hooks/pre-push");
        let zero = "0000000000000000000000000000000000000000";
        let input = format!(
            "refs/heads/main {head} refs/heads/main {base}\nrefs/heads/topic {head} refs/heads/topic {zero}\nrefs/tags/v1 {head} refs/tags/v1 {zero}\n(delete) {zero} refs/heads/old {base}\n"
        );
        let output = run_hook(&repo, &hook, &remote, &input, &fake_bin, &log);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reviewed = std::fs::read_to_string(&log).unwrap();
        assert_eq!(reviewed.matches("--- review ---").count(), 2);
        assert!(reviewed.contains("next.txt"));

        git(&repo, &["checkout", "--quiet", "--orphan", "orphan"]);
        git(&repo, &["rm", "-rf", "--quiet", "."]);
        let orphan = commit_file(&repo, "orphan.txt", "orphan\n");
        std::fs::remove_file(&log).unwrap();
        let input = format!("refs/heads/orphan {orphan} refs/heads/orphan {zero}\n");
        let output = run_hook(&repo, &hook, &remote, &input, &fake_bin, &log);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            std::fs::read_to_string(&log)
                .unwrap()
                .contains("orphan.txt")
        );
    }

    #[test]
    fn executable_hook_fetches_exact_missing_old_or_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let remote = dir.path().join("remote.git");
        let pusher = dir.path().join("pusher");
        let fake_bin = dir.path().join("bin");
        let log = dir.path().join("reviews.log");
        std::fs::create_dir(&repo).unwrap();
        init_repo(&repo);
        commit_file(&repo, "base.txt", "base\n");
        git(&repo, &["branch", "-M", "main"]);
        git(
            dir.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                repo.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        git(
            dir.path(),
            &[
                "clone",
                "--quiet",
                remote.to_str().unwrap(),
                pusher.to_str().unwrap(),
            ],
        );
        git(
            &pusher,
            &["config", "user.email", "postil-test@example.invalid"],
        );
        git(&pusher, &["config", "user.name", "Postil Test"]);
        let remote_old = commit_file(&pusher, "remote.txt", "remote\n");
        git(
            &pusher,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "push",
                "--quiet",
                "origin",
                "HEAD:main",
            ],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let local = commit_file(&repo, "local.txt", "local\n");
        install(&repo, false).unwrap();
        fake_postil(&fake_bin);
        let hook = repo.join(".git/hooks/pre-push");

        let input = format!("refs/heads/main {local} refs/heads/main {remote_old}\n");
        let output = run_hook(&repo, &hook, &remote, &input, &fake_bin, &log);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        std::fs::remove_file(&log).unwrap();
        let absent = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let input = format!("refs/heads/main {local} refs/heads/missing {absent}\n");
        let output = run_hook(&repo, &hook, &remote, &input, &fake_bin, &log);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("refusing an incomplete review"));
        assert!(!log.exists());
    }
}
