//! End-to-end tests: the real binary against mocked LLM and forge endpoints.

use assert_cmd::Command;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, path_regex, query_param};
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
    // The contract requires summary and findings to agree: an empty findings
    // array must come with an empty summary.
    let summary = if findings.as_array().is_none_or(|a| a.is_empty()) {
        ""
    } else {
        "SQL injection risk in auth path."
    };
    json!({
        "choices": [{"message": {"content": json!({
            "summary": summary,
            "findings": findings
        }).to_string()}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50}
    })
}

fn llm_contradictory() -> Value {
    json!({
        "choices": [{"message": {"content": json!({
            "summary": "SQL injection risk in auth path.",
            "findings": []
        }).to_string()}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50}
    })
}

fn llm_text(text: &str) -> Value {
    json!({
        "choices": [{"message": {"content": text}}],
        "usage": {"prompt_tokens": 80, "completion_tokens": 30}
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
async fn sarif_is_written_for_local_review() {
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
    let sarif_path = dir.path().join("out.sarif");
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--sarif")
        .arg(&sarif_path)
        .assert()
        .code(1);
    let sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "postil/risk");
    assert_eq!(result["level"], "error");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/auth.rs"
    );
    assert_eq!(sarif["runs"][0]["properties"]["gateFailing"], true);
}

#[tokio::test]
async fn advisory_on_error_lets_gate_stand_aside() {
    let server = MockServer::start().await;
    // Non-retryable model error so the run fails fast; it becomes an
    // operational fail-closed finding rather than a propagated error.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
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
            "title": "t", "body": "b",
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
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "gate:\n  onError: advisory\n",
    )
    .unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(0); // fail-open: an outage does not block the merge

    let reqs = server.received_requests().await.unwrap();
    let patches: Vec<Value> = reqs
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PATCH)
        .map(|r| r.body_json().unwrap())
        .collect();
    assert_eq!(patches.len(), 2);
    // The gate stands aside (success) but the outage stays visible: the
    // advisory check goes neutral, never green-on-green.
    let conclusions: Vec<&str> = patches
        .iter()
        .map(|p| p["conclusion"].as_str().unwrap())
        .collect();
    assert_eq!(conclusions, vec!["neutral", "success"]);
}

// Shared setup for the pre-review diff-fetch-failure tests: PR meta succeeds,
// the diff fetch (v3.diff Accept) fails, check-runs create/complete, and the
// error review comment posts. Parameterized by the .postil.yaml gate policy.
async fn diff_fetch_failure_server() -> MockServer {
    let server = MockServer::start().await;
    // The diff fetch (v3.diff Accept) fails after meta already succeeded.
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": "b",
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
    server
}

#[tokio::test]
async fn diff_fetch_failure_advisory_emits_envelope_and_exits_zero() {
    // A pre-review diff fetch failure under gate.onError: advisory must not exit
    // 2 with no output. The error envelope is emitted (machine output preserved)
    // and the gate stands aside (exit 0).
    let server = diff_fetch_failure_server().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "gate:\n  onError: advisory\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    // The envelope survived: provider-class error, gate passing under advisory.
    assert_eq!(env["findings"][0]["path"], ".postil/provider");
    assert_eq!(env["gate"]["failing"], false);
    assert_eq!(env["headSha"], "headsha111");

    // The advisory check went neutral, the gate success.
    let reqs = server.received_requests().await.unwrap();
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
    assert_eq!(conclusions, vec!["neutral", "success"]);
}

#[tokio::test]
async fn diff_fetch_failure_block_emits_envelope_and_exits_one() {
    // Same pre-review failure with the default (block) policy fails closed:
    // exit 1 with the envelope emitted, not exit 2 with no output.
    let server = diff_fetch_failure_server().await;
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
    assert_eq!(env["findings"][0]["path"], ".postil/provider");
    assert_eq!(env["gate"]["failing"], true);
}

#[tokio::test]
async fn advisory_does_not_bypass_unusable_output() {
    let server = MockServer::start().await;
    // Valid HTTP, garbage content twice (initial + repair): content-class
    // failure. A malicious diff can induce this, so advisory must not bypass.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "I cannot review this diff, sorry."}}]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "gate:\n  onError: advisory\n",
    )
    .unwrap();
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
async fn error_default_fails_closed_and_blocks() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    // No config: default gate.onError is block — an unusable review fails closed.
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
    assert_eq!(env["gate"]["failing"], true);
    // An HTTP-level model failure is provider-class, not unusable output.
    assert_eq!(env["findings"][0]["path"], ".postil/provider");
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
async fn narrated_risk_without_findings_fails_closed() {
    // The predecessor product's worst failure mode: risk prose in the summary,
    // zero structured findings, green status. The model gets one corrective
    // retry; if the contradiction persists the review fails closed.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_contradictory()))
        .expect(2) // initial call + one semantic retry
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
    assert_eq!(env["silent"], false);
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    assert_eq!(
        env["findings"][0]["title"],
        "Model narrated risk without structured findings"
    );
    // The narrated concern is preserved, not silently dropped.
    assert!(
        env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .contains("SQL injection risk in auth path.")
    );
}

#[tokio::test]
async fn narrated_risk_retry_recovers_structured_finding() {
    // First response contradicts itself; the corrective retry returns a
    // properly structured finding, which is used as the review result.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_contradictory()))
        .up_to_n_times(1)
        .mount(&server)
        .await;
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
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], "src/auth.rs");
    assert_eq!(env["findings"][0]["line"], 41);
    assert_eq!(env["counts"]["error"], 1);
}

#[tokio::test]
async fn low_confidence_only_finding_with_risk_summary_fails_closed() {
    // M1 regression: the model returns one grounded finding below minConfidence
    // (suppressed) WHILE its summary narrates risk. Policy emptying the kept set
    // must not let a risk-narrating run pass silently — the narrated-risk guard
    // keys on the post-filter kept set, so this fails closed with the narration
    // preserved (the same hole, reached through the suppression door instead of
    // the empty-findings door).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([
            finding_at(41, "warn", 0.3) // grounded but below default minConfidence 0.6
        ]))))
        // The model returns one (non-empty) raw finding, so the LLM-client
        // semantic retry (which fires only on empty raw findings) does not run;
        // the kept set empties later, in the filter. One call.
        .expect(1)
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
        .code(1); // fails closed, not a silent pass
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["silent"], false);
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    assert_eq!(
        env["findings"][0]["title"],
        "Model narrated risk without structured findings"
    );
    // The suppressed finding still counts as suppressed, and the narrated
    // concern is preserved rather than blanked.
    assert_eq!(env["counts"]["suppressed"], 1);
    assert!(
        env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .contains("SQL injection risk in auth path.")
    );
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

#[tokio::test]
async fn disabled_review_does_not_carry_baseline_findings() {
    // M2 regression: a repo with `enabled: false` plus a supplied baseline must
    // not have baseline Errors reconciled and carried into the gate. With review
    // off there is no fresh model run, so reconcile is skipped entirely and the
    // gate stays clean. No LLM call should be made.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .expect(0) // disabled: the model is never called
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    std::fs::write(dir.path().join(".postil.yaml"), "enabled: false\n").unwrap();

    let baseline = json!({
        "version": 1, "summary": "", "silent": false,
        "findings": [
            {"path": "src/db.rs", "line": 10, "severity": "error", "kind": "risk",
             "confidence": 0.9, "title": "still broken", "body": "not addressed"}
        ],
        "resolved": [], "counts": {"info": 0, "warn": 0, "error": 1, "suppressed": 0},
        "confidenceBuckets": [0,0,0,0,1],
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
        .code(0); // disabled + no carry => gate passes
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["gate"]["failing"], false);
    assert_eq!(
        env["findings"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "disabled review carried a baseline finding into the gate"
    );
    assert_eq!(env["silent"], true);
}

#[tokio::test]
async fn bitbucket_flow_posts_comment_and_sets_statuses() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.95)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "summary": {"raw": "PR body"},
            "source": {"commit": {"hash": "headsha111"}},
            "destination": {"commit": {"hash": "basesha222"}}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7/diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/repositories/acme/api/commit/.+/statuses/build$",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repositories/acme/api/pullrequests/7/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("BITBUCKET_API_URL", server.uri())
        .env("BITBUCKET_TOKEN", "bb-test-token")
        .env_remove("BITBUCKET_USER")
        .args([
            "review",
            "--forge",
            "bitbucket",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--output-json",
        ])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["headSha"], "headsha111");

    let reqs = server.received_requests().await.unwrap();
    let statuses: Vec<Value> = reqs
        .iter()
        .filter(|r| r.url.path().ends_with("/statuses/build"))
        .map(|r| r.body_json().unwrap())
        .collect();
    // Two on start (INPROGRESS) + two on complete.
    assert_eq!(statuses.len(), 4);
    let gate_final = statuses
        .iter()
        .rev()
        .find(|s| s["key"] == "postil/gate")
        .unwrap();
    assert_eq!(gate_final["state"], "FAILED");
    let review_final = statuses
        .iter()
        .rev()
        .find(|s| s["key"] == "postil/review")
        .unwrap();
    assert_eq!(review_final["state"], "SUCCESSFUL");
    // Inline comment anchored to the cited path/line.
    let comment = reqs
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/comments")
                && r.body_json::<Value>()
                    .map(|b| b.get("inline").is_some())
                    .unwrap_or(false)
        })
        .expect("inline comment posted");
    let body: Value = comment.body_json().unwrap();
    assert_eq!(body["inline"]["path"], "src/auth.rs");
    assert_eq!(body["inline"]["to"], 41);
}

#[tokio::test]
async fn azure_flow_reconstructs_diff_and_posts_thread() {
    let server = MockServer::start().await;
    // Small file: line 2 changes; the model flags line 2.
    let old_content = "fn login() {\n    let token = sanitize(user_input);\n}\n";
    let new_content = "fn login() {\n    let token = user_input;\n}\n";
    let az_finding = json!([{
        "path": "src/auth.rs", "line": 2, "severity": "error", "kind": "risk",
        "confidence": 0.95, "title": "Unsanitized input reaches query",
        "body": "user_input flows into the token without sanitization."
    }]);
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(az_finding)))
        .mount(&server)
        .await;
    let pr_path = "/myorg/myproj/_apis/git/repositories/myrepo/pullRequests/7";
    Mock::given(method("GET"))
        .and(path(pr_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login", "description": "PR body",
            "lastMergeSourceCommit": {"commitId": "HEAD"},
            "lastMergeTargetCommit": {"commitId": "BASE"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/diffs/commits",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "changes": [{"item": {"path": "/src/auth.rs"}, "changeType": "edit"}]
        })))
        .mount(&server)
        .await;
    let items_path = "/myorg/myproj/_apis/git/repositories/myrepo/items";
    Mock::given(method("GET"))
        .and(path(items_path))
        .and(query_param("version", "BASE"))
        .respond_with(ResponseTemplate::new(200).set_body_string(old_content))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(items_path))
        .and(query_param("version", "HEAD"))
        .respond_with(ResponseTemplate::new(200).set_body_string(new_content))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/pullRequests/7/statuses",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/pullRequests/7/threads",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("AZURE_DEVOPS_API_URL", server.uri())
        .env("AZURE_DEVOPS_TOKEN", "az-test-pat")
        .args([
            "review",
            "--forge",
            "azure",
            "--repo",
            "myorg/myproj/myrepo",
            "--pr",
            "7",
            "--output-json",
        ])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    // The finding survived: reconstruction grounded line 2 in the rebuilt diff.
    assert_eq!(env["headSha"], "HEAD");
    assert_eq!(env["findings"][0]["line"], 2);
    assert_eq!(env["gate"]["failing"], true);

    let reqs = server.received_requests().await.unwrap();
    let thread = reqs
        .iter()
        .find(|r| r.url.path().ends_with("/threads"))
        .expect("review thread posted");
    let body: Value = thread.body_json().unwrap();
    assert_eq!(body["threadContext"]["filePath"], "/src/auth.rs");
    assert_eq!(body["threadContext"]["rightFileStart"]["line"], 2);
}

#[tokio::test]
async fn respond_to_pr_mention_posts_grounded_reply() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "Line 41 interpolates `user_input` straight into the query — that is the \
             injection risk. Parameterize it.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/5"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login", "body": "PR body",
            "head": {"sha": "h"}, "base": {"sha": "b"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/issues/5/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--pr",
            "5",
            "--comment",
            "@postil is this safe?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    let comment = reqs
        .iter()
        .find(|r| r.url.path() == "/repos/acme/api/issues/5/comments")
        .expect("reply posted");
    let body: Value = comment.body_json().unwrap();
    let text = body["body"].as_str().unwrap();
    assert!(text.contains("injection risk"));
    assert!(text.contains("Postil ·")); // footer with model attribution
}

#[tokio::test]
async fn respond_to_issue_mention_uses_issue_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "This looks like a connection-pool exhaustion under load, not a logic bug.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Timeouts under load",
            "body": "Requests hang after ~200 concurrent users."
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/issues/9/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "9",
            "--comment",
            "@postil what do you think is happening?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    // The model was given the issue body as grounding.
    let llm = reqs
        .iter()
        .find(|r| r.url.path() == "/chat/completions")
        .unwrap();
    let sent: Value = llm.body_json().unwrap();
    let user_msg = sent["messages"][1]["content"].as_str().unwrap();
    assert!(user_msg.contains("200 concurrent users"));
    assert!(reqs.iter().any(|r| {
        r.method == wiremock::http::Method::POST
            && r.url.path() == "/repos/acme/api/issues/9/comments"
    }));
}

#[tokio::test]
async fn respond_gitlab_mr_mention_posts_note() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "Line 41 interpolates `user_input` into the query — parameterize it.",
        )))
        .mount(&server)
        .await;
    // MR metadata (title/description + diff refs) for grounding.
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/5$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "description": "MR body",
            "diff_refs": {"base_sha": "b", "start_sha": "s", "head_sha": "h"}
        })))
        .mount(&server)
        .await;
    // MR file diffs (paginated; one short page ends iteration).
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/5/diffs$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "old_path": "src/auth.rs", "new_path": "src/auth.rs",
            "diff": "@@ -40,6 +40,8 @@ fn login() {\n context line\n+let token = format!(\"{}\", user_input);\n+exec_query(&token);\n trailing context\n",
            "new_file": false, "deleted_file": false
        }])))
        .mount(&server)
        .await;
    // The reply note endpoint.
    Mock::given(method("POST"))
        .and(path_regex(r"^/projects/.+/merge_requests/5/notes$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITLAB_API_URL", server.uri())
        .env("GITLAB_TOKEN", "gl-test-token")
        .args([
            "respond",
            "--forge",
            "gitlab",
            "--repo",
            "acme/api",
            "--pr",
            "5",
            "--comment",
            "@postil is this safe?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    let note = reqs
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/merge_requests/5/notes")
        })
        .expect("reply note posted to the MR");
    let body: Value = note.body_json().unwrap();
    let text = body["body"].as_str().unwrap();
    assert!(text.contains("parameterize"));
    assert!(text.contains("Postil ·")); // footer with model attribution
}

#[tokio::test]
async fn respond_gitlab_issue_mention_uses_issue_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "This looks like connection-pool exhaustion under load, not a logic bug.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/issues/9$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Timeouts under load",
            "description": "Requests hang after ~200 concurrent users."
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/projects/.+/issues/9/notes$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITLAB_API_URL", server.uri())
        .env("GITLAB_TOKEN", "gl-test-token")
        .args([
            "respond",
            "--forge",
            "gitlab",
            "--repo",
            "acme/api",
            "--issue",
            "9",
            "--comment",
            "@postil what is happening?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    // The model was grounded on the issue body.
    let llm = reqs
        .iter()
        .find(|r| r.url.path() == "/chat/completions")
        .unwrap();
    let sent: Value = llm.body_json().unwrap();
    let user_msg = sent["messages"][1]["content"].as_str().unwrap();
    assert!(user_msg.contains("200 concurrent users"));
    // The reply landed on the issue notes endpoint, not the MR one.
    assert!(reqs.iter().any(|r| {
        r.method == wiremock::http::Method::POST && r.url.path().ends_with("/issues/9/notes")
    }));
}

#[tokio::test]
async fn respond_bitbucket_pr_mention_posts_comment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "Line 41 interpolates `user_input` — that is the injection risk.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "summary": {"raw": "PR body"},
            "source": {"commit": {"hash": "headsha111"}},
            "destination": {"commit": {"hash": "basesha222"}}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7/diff"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DIFF))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repositories/acme/api/pullrequests/7/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("BITBUCKET_API_URL", server.uri())
        .env("BITBUCKET_TOKEN", "bb-test-token")
        .env_remove("BITBUCKET_USER")
        .args([
            "respond",
            "--forge",
            "bitbucket",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--comment",
            "@postil is this safe?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    let comment = reqs
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path() == "/repositories/acme/api/pullrequests/7/comments"
        })
        .expect("reply comment posted to the PR");
    let body: Value = comment.body_json().unwrap();
    let text = body["content"]["raw"].as_str().unwrap();
    assert!(text.contains("injection risk"));
    assert!(text.contains("Postil ·"));
}

#[tokio::test]
async fn respond_azure_pr_mention_posts_thread() {
    let server = MockServer::start().await;
    let old_content = "fn login() {\n    let token = sanitize(user_input);\n}\n";
    let new_content = "fn login() {\n    let token = user_input;\n}\n";
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text(
            "Line 2 drops the sanitize() call — that is the risk.",
        )))
        .mount(&server)
        .await;
    let pr_path = "/myorg/myproj/_apis/git/repositories/myrepo/pullRequests/7";
    Mock::given(method("GET"))
        .and(path(pr_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login", "description": "PR body",
            "lastMergeSourceCommit": {"commitId": "HEAD"},
            "lastMergeTargetCommit": {"commitId": "BASE"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/diffs/commits",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "changes": [{"item": {"path": "/src/auth.rs"}, "changeType": "edit"}]
        })))
        .mount(&server)
        .await;
    let items_path = "/myorg/myproj/_apis/git/repositories/myrepo/items";
    Mock::given(method("GET"))
        .and(path(items_path))
        .and(query_param("version", "BASE"))
        .respond_with(ResponseTemplate::new(200).set_body_string(old_content))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(items_path))
        .and(query_param("version", "HEAD"))
        .respond_with(ResponseTemplate::new(200).set_body_string(new_content))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/pullRequests/7/threads",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("AZURE_DEVOPS_API_URL", server.uri())
        .env("AZURE_DEVOPS_TOKEN", "az-test-pat")
        .args([
            "respond",
            "--forge",
            "azure",
            "--repo",
            "myorg/myproj/myrepo",
            "--pr",
            "7",
            "--comment",
            "@postil is this safe?",
        ])
        .assert()
        .success();

    let reqs = server.received_requests().await.unwrap();
    let thread = reqs
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/pullRequests/7/threads")
        })
        .expect("reply thread posted to the PR");
    let body: Value = thread.body_json().unwrap();
    let text = body["comments"][0]["content"].as_str().unwrap();
    assert!(text.contains("risk"));
    assert!(text.contains("Postil ·"));
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
