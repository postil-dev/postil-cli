//! End-to-end CLI tests: spawn the binary, exercise the surface.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn version_flag_prints_version() {
    Command::cargo_bin("postil")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_describes_review() {
    Command::cargo_bin("postil")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("review"));
}

#[test]
fn prompt_subcommand_prints_doctrine() {
    Command::cargo_bin("postil")
        .unwrap()
        .arg("prompt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Silence is a feature"))
        .stdout(predicate::str::contains("humanEscalation"));
}

#[test]
fn validate_config_accepts_minimal() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        "enabled: true\nignore: ['dist/**']\nseverityThreshold: warn\n"
    )
    .unwrap();
    let path = f.path().to_path_buf();
    // Rename to .postil.yaml so the loader picks the right translator.
    let dir = path.parent().unwrap().to_path_buf();
    let renamed = dir.join(".postil.yaml");
    std::fs::copy(&path, &renamed).unwrap();
    let result = Command::cargo_bin("postil")
        .unwrap()
        .arg("validate-config")
        .arg(&renamed)
        .assert()
        .success();
    let _ = std::fs::remove_file(&renamed);
    result.stdout(predicate::str::contains("ok:"));
}

#[test]
fn review_local_diff_file_with_no_api_key_fails_closed() {
    // Build a tiny unified-diff file and review it without OPENROUTER_API_KEY.
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(
        b"diff --git a/x.txt b/x.txt\n--- a/x.txt\n+++ b/x.txt\n@@ -1,1 +1,2 @@\n hello\n+world\n",
    )
    .unwrap();
    Command::cargo_bin("postil")
        .unwrap()
        .env_remove("OPENROUTER_API_KEY")
        .arg("--diff-file")
        .arg(f.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("OPENROUTER_API_KEY"));
}

#[test]
fn review_requires_source() {
    Command::cargo_bin("postil")
        .unwrap()
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_EVENT_PATH")
        .assert()
        .failure();
}

#[test]
fn empty_diff_file_completes_cleanly() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f).unwrap();
    Command::cargo_bin("postil")
        .unwrap()
        .arg("--diff-file")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no merge-relevant findings"));
}
