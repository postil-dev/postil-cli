//! `postil hook install`: a pre-push hook running the same engine locally.

use std::path::Path;

use anyhow::{Context, Result, anyhow};

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# Installed by `postil hook install`. Reviews outgoing commits before push.
# Bypass once with: git push --no-verify

upstream=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null)
base=${upstream:-origin/HEAD}

exec postil review --base "$base"
"#;

pub fn install(repo_root: &Path, force: bool) -> Result<()> {
    let hooks_dir = repo_root.join(".git").join("hooks");
    if !hooks_dir.is_dir() {
        return Err(anyhow!(
            "{} not found — run inside a git repository",
            hooks_dir.display()
        ));
    }
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

    #[test]
    fn installs_and_respects_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        install(dir.path(), false).unwrap();
        let hook = dir.path().join(".git/hooks/pre-push");
        assert!(hook.is_file());
        // Second install without --force refuses.
        assert!(install(dir.path(), false).is_err());
        // --force overwrites.
        install(dir.path(), true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111);
        }
    }
}
