use std::{fs, path::PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use tempfile::tempdir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};

#[tokio::test]
async fn reviews_local_directory_without_github_context() {
    let openrouter = MockServer::start().await;
    let openrouter_uri = openrouter.uri();
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, ["init"]);
    git(&repo, ["config", "user.email", "test@example.com"]);
    git(&repo, ["config", "user.name", "Test User"]);
    fs::write(repo.join("src.txt"), "old\n").unwrap();
    git(&repo, ["add", "."]);
    git(&repo, ["commit", "-m", "initial"]);
    fs::write(repo.join("src.txt"), "old\nnew\n").unwrap();

    let output = dir.path().join("result.json");
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"Needs work.\",\"findings\":[{\"path\":\"src.txt\",\"line\":2,\"severity\":\"warn\",\"body\":\"Check this change.\"}]}"} }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .env_remove("GITHUB_TOKEN")
        .env("OPENROUTER_API_KEY", "test-openrouter")
        .args([
            "review",
            "--local-dir",
            repo.to_str().unwrap(),
            "--openrouter-api-url",
            &openrouter_uri,
            "--review-model",
            "xiaomi/mimo-v2.5-pro",
            "--output-json",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("local diff (local directory"))
        .stdout(predicate::str::contains("neutral (1 findings"));

    let result: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(result["modelUsed"], "xiaomi/mimo-v2.5-pro");
    assert_eq!(result["findings"][0]["path"], "src.txt");
}

#[tokio::test]
async fn truncates_local_directory_diff_on_utf8_boundary() {
    let openrouter = MockServer::start().await;
    let openrouter_uri = openrouter.uri();
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, ["init"]);
    git(&repo, ["config", "user.email", "test@example.com"]);
    git(&repo, ["config", "user.name", "Test User"]);
    fs::write(repo.join("src.txt"), "old\n").unwrap();
    git(&repo, ["add", "."]);
    git(&repo, ["commit", "-m", "initial"]);
    fs::write(repo.join("src.txt"), "old\né\n").unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("[diff truncated]"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .env_remove("GITHUB_TOKEN")
        .env("OPENROUTER_API_KEY", "test-openrouter")
        .args([
            "review",
            "--local-dir",
            repo.to_str().unwrap(),
            "--openrouter-api-url",
            &openrouter_uri,
            "--review-model",
            "xiaomi/mimo-v2.5-pro",
            "--diff-limit",
            "63",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("local diff (local directory"));
}

#[tokio::test]
async fn skips_large_untracked_files_in_local_directory_mode() {
    let openrouter = MockServer::start().await;
    let openrouter_uri = openrouter.uri();
    let dir = tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, ["init"]);
    git(&repo, ["config", "user.email", "test@example.com"]);
    git(&repo, ["config", "user.name", "Test User"]);
    fs::write(repo.join("src.txt"), "old\n").unwrap();
    git(&repo, ["add", "."]);
    git(&repo, ["commit", "-m", "initial"]);
    fs::write(repo.join("large.txt"), "x".repeat(4096)).unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("large.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .env_remove("GITHUB_TOKEN")
        .env("OPENROUTER_API_KEY", "test-openrouter")
        .args([
            "review",
            "--local-dir",
            repo.to_str().unwrap(),
            "--openrouter-api-url",
            &openrouter_uri,
            "--review-model",
            "xiaomi/mimo-v2.5-pro",
            "--diff-limit",
            "128",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("local diff (local directory"))
        .stdout(predicate::str::contains("success (0 findings"));
}

#[tokio::test]
async fn posts_review_check_and_json_output() {
    let github = MockServer::start().await;
    let openrouter = MockServer::start().await;
    let dir = tempdir().unwrap();
    let config = dir.path().join("postil.yaml");
    let output = dir.path().join("result.json");
    fs::write(
        &config,
        format!(
            r#"
githubToken: test-github
openrouterApiKey: test-openrouter
githubApiUrl: {}
openrouterApiUrl: {}
repo: owner/repo
pr: 42
sha: abc123
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
review:
  severityThreshold: info
  maxFindings: 25
  review:
    enabled: true
"#,
            github.uri(),
            openrouter.uri()
        ),
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/repos/owner/repo/pulls/42"))
        .and(header("accept", "application/vnd.github.v3.diff"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("diff --git a/src/lib.rs b/src/lib.rs\n+let x = 1;"),
        )
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"Needs work.\",\"findings\":[{\"path\":\"src/lib.rs\",\"line\":1,\"severity\":\"warn\",\"body\":\"This can fail.\"}]}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })))
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/pulls/42/reviews"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&github)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args([
            "review",
            "--config",
            config.to_str().unwrap(),
            "--output-json",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("neutral (1 findings"));

    let result: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(result["modelUsed"], "xiaomi/mimo-v2.5-pro");
    assert_eq!(result["findings"][0]["severity"], "warn");
}

fn git<const N: usize>(repo: &std::path::Path, args: [&str; N]) {
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

#[tokio::test]
async fn exits_nonzero_when_fail_on_matches() {
    let github = MockServer::start().await;
    let openrouter = MockServer::start().await;
    let dir = tempdir().unwrap();
    let config = dir.path().join("postil.yaml");
    fs::write(
        &config,
        format!(
            r#"
githubToken: test-github
openrouterApiKey: test-openrouter
githubApiUrl: {}
openrouterApiUrl: {}
repo: owner/repo
pr: 42
sha: abc123
reviewModel: xiaomi/mimo-v2.5-pro
failOn: warn
noInline: true
review:
  review:
    enabled: true
"#,
            github.uri(),
            openrouter.uri()
        ),
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/repos/owner/repo/pulls/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("diff\n+bug"))
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"Needs work.\",\"findings\":[{\"path\":\"src/lib.rs\",\"line\":1,\"severity\":\"warn\",\"body\":\"This can fail.\"}]}"} }]
        })))
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&github)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--config", config.to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("neutral (1 findings"));
}

#[tokio::test]
async fn cascades_models_after_provider_failure() {
    let github = MockServer::start().await;
    let openrouter = MockServer::start().await;
    let dir = tempdir().unwrap();
    let config = dir.path().join("postil.yaml");
    fs::write(
        &config,
        format!(
            r#"
githubToken: test-github
openrouterApiKey: test-openrouter
githubApiUrl: {}
openrouterApiUrl: {}
repo: owner/repo
pr: 42
sha: abc123
reviewModelCascade: bad/model, xiaomi/mimo-v2.5-pro
noInline: true
review:
  review:
    enabled: false
"#,
            github.uri(),
            openrouter.uri()
        ),
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/repos/owner/repo/pulls/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("diff\n+ok"))
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .up_to_n_times(1)
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&github)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("model: xiaomi/mimo-v2.5-pro"));
}

#[tokio::test]
async fn skips_clean_review_by_default() {
    let github = MockServer::start().await;
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("clean-review-skip");
    let config = dir.join("postil.yaml");
    fs::write(
        &config,
        format!(
            r#"
githubToken: test-github
openrouterApiKey: test-openrouter
githubApiUrl: {}
openrouterApiUrl: {}
repo: owner/repo
pr: 42
sha: abc123
reviewModel: xiaomi/mimo-v2.5-pro
review:
  review:
    enabled: true
"#,
            github.uri(),
            openrouter.uri()
        ),
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/repos/owner/repo/pulls/42"))
        .and(header("accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string("diff\n+ok"))
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&github)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("success (0 findings"));

    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn updates_existing_check_run_without_head_sha() {
    let github = MockServer::start().await;
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("check-run-update-no-sha");
    let config = dir.join("postil.yaml");
    fs::write(
        &config,
        format!(
            r#"
githubToken: test-github
openrouterApiKey: test-openrouter
githubApiUrl: {}
openrouterApiUrl: {}
repo: owner/repo
pr: 42
checkRunId: 123
reviewModel: xiaomi/mimo-v2.5-pro
noInline: true
"#,
            github.uri(),
            openrouter.uri()
        ),
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/repos/owner/repo/pulls/42"))
        .and(header("accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string("diff\n+ok"))
        .mount(&github)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/owner/repo/check-runs/123"))
        .and(body_string_contains(r#""status":"completed""#))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&github)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("success (0 findings"));

    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn reviews_local_diff_file_without_github_config() {
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("local-diff-file");
    let config = dir.join("postil.yaml");
    let diff = dir.join("change.diff");
    let output = dir.join("nested").join("result.json");
    fs::write(
        &config,
        format!(
            r#"
openrouterApiKey: test-openrouter
openrouterApiUrl: {}
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
review:
  reviewer:
    focus:
      - security-sensitive behavior
"#,
            openrouter.uri()
        ),
    )
    .unwrap();
    fs::write(
        &diff,
        "diff --git a/src/lib.rs b/src/lib.rs\n@@ -1 +1 @@\n+let token = user_input;",
    )
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("security-sensitive behavior"))
        .and(body_string_contains("Review source: diff file"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"Needs human review before merge.\",\"findings\":[{\"path\":\"src/lib.rs\",\"line\":1,\"severity\":\"warn\",\"body\":\"This security-sensitive path needs accountable human review before merge.\"}]}"} }]
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args([
            "review",
            "--config",
            config.to_str().unwrap(),
            "--diff-file",
            diff.to_str().unwrap(),
            "--output-json",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("local diff"))
        .stdout(predicate::str::contains("accountable human review"));

    let result: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    assert_eq!(result["findings"][0]["severity"], "warn");
    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn truncates_local_diff_on_utf8_boundary() {
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("utf8-diff-limit");
    let config = dir.join("postil.yaml");
    let diff = dir.join("change.diff");
    fs::write(
        &config,
        format!(
            r#"
openrouterApiKey: test-openrouter
openrouterApiUrl: {}
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
"#,
            openrouter.uri()
        ),
    )
    .unwrap();
    fs::write(&diff, "diff --git a/src/lib.rs b/src/lib.rs\n+é").unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("[diff truncated]"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args([
            "review",
            "--config",
            config.to_str().unwrap(),
            "--diff-file",
            diff.to_str().unwrap(),
            "--diff-limit",
            "39",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("local diff"));

    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn invalid_model_output_fails_local_review() {
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("invalid-model-output");
    let config = dir.join("postil.yaml");
    let diff = dir.join("change.diff");
    fs::write(
        &config,
        format!(
            r#"
openrouterApiKey: test-openrouter
openrouterApiUrl: {}
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
"#,
            openrouter.uri()
        ),
    )
    .unwrap();
    fs::write(&diff, "diff --git a/src/lib.rs b/src/lib.rs\n+bug").unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "not json"} }]
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args([
            "review",
            "--config",
            config.to_str().unwrap(),
            "--diff-file",
            diff.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "Model output was not valid Postil JSON",
        ));

    fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn retries_invalid_model_output_once() {
    let openrouter = MockServer::start().await;
    let dir = cache_test_dir("invalid-model-output-retry");
    let config = dir.join("postil.yaml");
    let diff = dir.join("change.diff");
    fs::write(
        &config,
        format!(
            r#"
openrouterApiKey: test-openrouter
openrouterApiUrl: {}
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
"#,
            openrouter.uri()
        ),
    )
    .unwrap();
    fs::write(&diff, "diff --git a/src/lib.rs b/src/lib.rs\n+let x = 1;").unwrap();

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"oops\",\"findings\":["}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 16000, "total_tokens": 16010}
        })))
        .up_to_n_times(1)
        .mount(&openrouter)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains(
            "previous response was not valid Postil JSON",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"} }]
        })))
        .mount(&openrouter)
        .await;

    Command::cargo_bin("postil")
        .unwrap()
        .args([
            "review",
            "--config",
            config.to_str().unwrap(),
            "--diff-file",
            diff.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("success (0 findings"));

    fs::remove_dir_all(dir).unwrap();
}

fn cache_test_dir(name: &str) -> PathBuf {
    let dir = std::env::current_dir()
        .unwrap()
        .join(".cache")
        .join("tests")
        .join(format!("{}-{}", name, std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    dir
}
