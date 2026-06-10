//! End-to-end tests: the real binary against mocked LLM and forge endpoints.

use assert_cmd::Command;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DIFF: &str = "\
diff --git a/src/auth.rs b/src/auth.rs
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -40,6 +40,8 @@ fn login() {
 context line
+let token = format!(\"{}\", user_input);
+exec_query(&token);
 trailing context
";

fn llm_content(findings: Value) -> Value {
    json!({
        "choices": [{"message": {"content": json!({
            "summary": "SQL injection risk in auth path.",
            "findings": findings
        }).to_string()}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50}
    })
}

fn finding_at(line: u32, severity: &str, confidence: f64) -> Value {
    json!({
        "path": "src/auth.rs",
        "line": line,
        "severity": severity,
        "kind": "risk",
        "confidence": confidence,
        "title": "Unsanitized input reaches query",
        "body": "user_input flows into exec_query without sanitization."
    })
}

fn postil() -> Command {
    let mut cmd = Command::cargo_bin("postil").unwrap();
    // Isolate from developer environment and repo config discovery.
    cmd.env_remove("REVIEW_MODEL")
        .env_remove("REVIEW_MODEL_CASCADE")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("POSTIL_API_KEY")
        .env_remove("POSTIL_API_BASE")
        .env("POSTIL_API_KEY", "test-key");
    cmd
}

fn write_diff(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("change.diff");
    std::fs::write(&p, DIFF).unwrap();
    p
}

#[tokio::test]
async fn local_review_reports_grounded_finding_and_gates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.92)]))),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1); // gate fails on error severity
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["silent"], false);
    assert_eq!(env["findings"][0]["path"], "src/auth.rs");
    assert_eq!(env["findings"][0]["line"], 41);
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["counts"]["error"], 1);
    assert_eq!(env["usage"]["promptTokens"], 100);
}

#[tokio::test]
async fn clean_diff_is_silent_and_exits_zero() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["silent"], true);
    assert_eq!(env["summary"], "");
    assert_eq!(env["gate"]["failing"], false);
}

#[tokio::test]
async fn low_confidence_findings_are_suppressed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([
            finding_at(41, "warn", 0.3) // below default minConfidence 0.6
        ]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["silent"], true);
    assert_eq!(env["counts"]["suppressed"], 1);
}

#[tokio::test]
async fn ungrounded_output_fails_closed() {
    let server = MockServer::start().await;
    // Model cites line 999 which is not in the diff. Twice (initial + repair is
    // not triggered for valid-but-ungrounded JSON), so one mock suffices.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(999, "error", 0.9)]))),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    assert_eq!(env["gate"]["failing"], true);
}

#[tokio::test]
async fn garbage_output_fails_closed_after_repair_attempt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "I cannot review this diff, sorry."}}]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    // Initial call + repair call.
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn cascade_falls_back_to_next_model() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("backup-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["modelUsed"], "backup-model");
}

#[tokio::test]
async fn hosted_path_completes_provided_check_run_ids_without_creating_new_ones() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "h1"}, "base": {"sha": "b1"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/(901|902)$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args([
            "review",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--sha",
            "h1",
            "--check-run-id",
            "901",
            "--gate-check-run-id",
            "902",
            "--output-json",
        ])
        .assert()
        .code(0);

    let reqs = server.received_requests().await.unwrap();
    // The worker owns check-run creation; the CLI must not create its own.
    assert!(
        !reqs.iter().any(|r| r.method == wiremock::http::Method::POST
            && r.url.path() == "/repos/acme/api/check-runs")
    );
    // Both pre-created runs completed.
    let patched: Vec<&str> = reqs
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PATCH)
        .map(|r| r.url.path())
        .collect();
    assert!(patched.contains(&"/repos/acme/api/check-runs/901"));
    assert!(patched.contains(&"/repos/acme/api/check-runs/902"));
}

#[tokio::test]
async fn github_flow_posts_review_and_completes_both_checks() {
    let server = MockServer::start().await;
    // LLM
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.95)]))),
        )
        .mount(&server)
        .await;
    // PR meta (default Accept) and diff (v3.diff Accept) on the same path.
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login", "body": "PR body",
            "head": {"sha": "headsha111"}, "base": {"sha": "basesha222"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 11})))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/pulls/7/reviews"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["headSha"], "headsha111");
    assert_eq!(env["baseSha"], "basesha222");

    let reqs = server.received_requests().await.unwrap();
    // Two check-run creations.
    let creates: Vec<_> = reqs
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST && r.url.path() == "/repos/acme/api/check-runs"
        })
        .collect();
    assert_eq!(creates.len(), 2);
    let names: Vec<String> = creates
        .iter()
        .map(|r| {
            r.body_json::<Value>().unwrap()["name"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(names.contains(&"postil/review".to_string()));
    assert!(names.contains(&"postil/gate".to_string()));
    // Both completed; gate concluded failure, advisory success.
    let patches: Vec<Value> = reqs
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PATCH)
        .map(|r| r.body_json().unwrap())
        .collect();
    assert_eq!(patches.len(), 2);
    let conclusions: Vec<&str> = patches
        .iter()
        .map(|p| p["conclusion"].as_str().unwrap())
        .collect();
    assert!(conclusions.contains(&"success"));
    assert!(conclusions.contains(&"failure"));
    // Inline review posted with the finding at the cited line.
    let review = reqs
        .iter()
        .find(|r| r.url.path() == "/repos/acme/api/pulls/7/reviews")
        .expect("review posted");
    let body: Value = review.body_json().unwrap();
    assert_eq!(body["comments"][0]["path"], "src/auth.rs");
    assert_eq!(body["comments"][0]["line"], 41);
}

#[tokio::test]
async fn github_clean_pr_stays_silent_but_completes_checks() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "h1"}, "base": {"sha": "b1"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 11})))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7"])
        .assert()
        .code(0);

    let reqs = server.received_requests().await.unwrap();
    // Silence is a feature: no review comment posted on a clean PR.
    assert!(!reqs.iter().any(|r| r.url.path().ends_with("/reviews")));
    // But both checks completed successfully.
    let conclusions: Vec<String> = reqs
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PATCH)
        .map(|r| {
            r.body_json::<Value>().unwrap()["conclusion"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(conclusions, vec!["success", "success"]);
}

#[tokio::test]
async fn incremental_review_resolves_and_carries_baseline_findings() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path()); // touches src/auth.rs:40-47

    // Baseline: one finding inside the touched range (resolved), one elsewhere (carried).
    let baseline = json!({
        "version": 1, "summary": "", "silent": false,
        "findings": [
            {"path": "src/auth.rs", "line": 41, "severity": "error", "kind": "risk",
             "confidence": 0.9, "title": "old auth bug", "body": "fixed now"},
            {"path": "src/db.rs", "line": 10, "severity": "error", "kind": "risk",
             "confidence": 0.9, "title": "still broken", "body": "not addressed"}
        ],
        "resolved": [], "counts": {"info": 0, "warn": 0, "error": 2, "suppressed": 0},
        "confidenceBuckets": [0,0,0,0,2],
        "gate": {"failOn": "error", "failing": true},
        "modelUsed": "m", "usage": {"promptTokens": 0, "completionTokens": 0},
        "baseSha": null, "headSha": null, "sinceSha": null
    });
    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(&baseline_path, baseline.to_string()).unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--since-sha", "abc123", "--baseline"])
        .arg(&baseline_path)
        .arg("--output-json")
        .assert()
        .code(1); // carried error finding keeps the gate failing
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["resolved"][0]["title"], "old auth bug");
    assert_eq!(env["findings"][0]["title"], "still broken");
    assert!(
        env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .starts_with("[carried")
    );
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["sinceSha"], "abc123");
}

#[test]
fn init_writes_starter_and_config_shows_provenance() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("postil")
        .unwrap()
        .current_dir(dir.path())
        .args(["init"])
        .assert()
        .success();
    assert!(dir.path().join(".postil.yaml").is_file());
    // Second init refuses without --force.
    Command::cargo_bin("postil")
        .unwrap()
        .current_dir(dir.path())
        .args(["init"])
        .assert()
        .code(2);

    let out = Command::cargo_bin("postil")
        .unwrap()
        .current_dir(dir.path())
        .env_remove("REVIEW_MODEL")
        .env_remove("POSTIL_API_BASE")
        .args(["config"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("source: .postil.yaml"));
    assert!(stdout.contains("gate.failOn: error"));
}

#[test]
fn coderabbit_config_is_translated() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".coderabbit.yaml"),
        "reviews:\n  profile: chill\n  path_filters:\n    - \"!**/generated/**\"\n",
    )
    .unwrap();
    let out = Command::cargo_bin("postil")
        .unwrap()
        .current_dir(dir.path())
        .env_remove("REVIEW_MODEL")
        .env_remove("POSTIL_API_BASE")
        .args(["config"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains(".coderabbit.yaml (translated)"));
    assert!(stdout.contains("**/generated/**"));
    assert!(stdout.contains("minConfidence: 0.75"));
}

#[test]
fn plan_replays_envelopes_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let envelopes = dir.path().join("envelopes");
    std::fs::create_dir(&envelopes).unwrap();
    let envelope = json!({
        "version": 1, "summary": "s", "silent": false,
        "findings": [
            {"path": "src/a.rs", "line": 1, "severity": "error", "kind": "risk",
             "confidence": 0.65, "title": "real bug", "body": "b"},
            {"path": "vendor/x.js", "line": 2, "severity": "warn", "kind": "risk",
             "confidence": 0.9, "title": "vendored", "body": "b"}
        ],
        "resolved": [], "counts": {"info": 0, "warn": 1, "error": 1, "suppressed": 0},
        "confidenceBuckets": [0,0,0,1,1],
        "gate": {"failOn": "error", "failing": true},
        "modelUsed": "m", "usage": {"promptTokens": 1, "completionTokens": 1},
        "baseSha": null, "headSha": null, "sinceSha": null
    });
    std::fs::write(envelopes.join("r1.json"), envelope.to_string()).unwrap();
    // Candidate config raises the confidence floor and ignores vendor/.
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "minConfidence: 0.7\nignore:\n  - \"vendor/**\"\n",
    )
    .unwrap();

    let out = Command::cargo_bin("postil")
        .unwrap()
        .current_dir(dir.path())
        .args(["plan", "--envelopes"])
        .arg(&envelopes)
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("2 -> 0 finding(s)"));
    assert!(stderr.contains("gate: FAILING -> passing"));
    assert!(stderr.contains("would suppress: src/a.rs:1"));
    assert!(stderr.contains("2 finding(s) would be suppressed; 1 gate outcome(s) would change"));
}
