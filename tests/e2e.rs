//! End-to-end tests: the real binary against mocked LLM and forge endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const DIFF: &str = "\
diff --git a/src/auth.rs b/src/auth.rs
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -40,2 +40,4 @@ fn login() {
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
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "cost": 0.000123}
    })
}

fn scorer_content(scores: Value) -> Value {
    json!({
        "choices": [{"message": {"content": scores.to_string()}}],
        "usage": {"prompt_tokens": 30, "completion_tokens": 10, "cost": 0.000045}
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

fn respond_payload(answer: &str, diagram: Option<&str>) -> String {
    json!({"answer": answer, "diagram": diagram}).to_string()
}

fn respond_text(answer: &str) -> Value {
    llm_text(&respond_payload(answer, None))
}

fn respond_article_slop() -> String {
    let prefix = "I reviewed the full diff. Here's my assessment.\n\n\
## What this PR does\n\nA broad implementation tour.\n\n\
## Correctness\n\nSeveral paragraphs of non-actionable narration.\n\n\
## Issues and risks\n\n\
1. First item.\n2. Second item.\n3. Third item.\n\
4. Fourth item.\n5. Fifth item.\n6. Sixth item.\n\n\
## Verdict\n\nA long conclusion.\n\n";
    let padding = 7_186 - prefix.chars().count();
    format!("{prefix}{}", "x".repeat(padding))
}

fn anthropic_content(findings: Value, input_tokens: u64, output_tokens: u64) -> Value {
    let summary = if findings.as_array().is_none_or(|items| items.is_empty()) {
        ""
    } else {
        "SQL injection risk in auth path."
    };
    json!({
        "content": [
            {"type": "thinking", "thinking": "omitted"},
            {"type": "text", "text": json!({
                "summary": summary,
                "findings": findings
            }).to_string()}
        ],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
    })
}

fn anthropic_text(text: &str, input_tokens: u64, output_tokens: u64) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
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

fn finding_at_with_kind(line: u32, severity: &str, kind: &str, confidence: f64) -> Value {
    json!({
        "path": "src/auth.rs",
        "line": line,
        "severity": severity,
        "kind": kind,
        "confidence": confidence,
        "title": "Unsanitized input reaches query",
        "body": "user_input flows into exec_query without sanitization."
    })
}

fn finding_with_text(line: u32, severity: &str, confidence: f64, title: &str, body: &str) -> Value {
    json!({
        "path": "src/auth.rs",
        "line": line,
        "severity": severity,
        "kind": "risk",
        "confidence": confidence,
        "title": title,
        "body": body
    })
}

fn fixture_credential(label: &str) -> String {
    format!("postil-fixture-{label}-{}", std::process::id())
}

#[derive(Clone)]
struct GitHubSourceResponder;

impl Respond for GitHubSourceResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let base = request.url.query_pairs().any(|(name, value)| {
            name == "ref" && (value.starts_with('b') || value.starts_with('c'))
        });
        let mut lines = (1..40)
            .map(|line| format!("// context {line}\n"))
            .collect::<String>();
        lines.push_str("context line\n");
        if !base {
            lines.push_str("let token = format!(\"{}\", user_input);\nexec_query(&token);\n");
        }
        lines.push_str("trailing context\n");
        ResponseTemplate::new(200).set_body_string(lines)
    }
}

#[derive(Clone)]
struct GitHubHeadRaceResponder {
    calls: Arc<AtomicUsize>,
}

impl Respond for GitHubHeadRaceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let head = if call < 2 { "aaaaaaaa" } else { "cccccccc" };
        ResponseTemplate::new(200).set_body_json(json!({
            "title": "t",
            "body": "b",
            "head": {"sha": head},
            "base": {"sha": "bbbbbbbb"},
            "changed_files": 1
        }))
    }
}

async fn mount_github_complete_diff(server: &MockServer, pr: u64) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/repos/acme/api/compare/b+\.\.\.a+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "bbbbbbbb"},
            "files": []
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/api/pulls/{pr}/files")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "filename": "src/auth.rs",
            "status": "modified",
            "changes": 2
        }])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/contents/src/auth.rs"))
        .respond_with(GitHubSourceResponder)
        .mount(server)
        .await;
}

#[derive(Clone)]
struct GitHubLargeLockfileResponder;

impl Respond for GitHubLargeLockfileResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let base = request
            .url
            .query()
            .is_some_and(|query| query.contains("ref=bbbbbbbb"));
        let version = if base { "1.2.2" } else { "1.2.3" };
        ResponseTemplate::new(200).set_body_string(format!(
            "name = \"large-dependency\"\nversion = \"{version}\"\nchecksum = \"{}\"\n",
            "x".repeat(33 * 1024 * 1024),
        ))
    }
}

#[derive(Clone)]
struct BitbucketSourceResponder;

impl Respond for BitbucketSourceResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let base =
            request.url.path().contains("/bbbbbbbb/") || request.url.path().contains("/cccccccc/");
        let mut lines = (1..40)
            .map(|line| format!("// context {line}\n"))
            .collect::<String>();
        lines.push_str("context line\n");
        if !base {
            lines.push_str("let token = format!(\"{}\", user_input);\nexec_query(&token);\n");
        }
        lines.push_str("trailing context\n");
        ResponseTemplate::new(200).set_body_string(lines)
    }
}

async fn mount_bitbucket_merge_base(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/repositories/acme/api/merge-base/b+\.\.a+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hash": "bbbbbbbb"
        })))
        .mount(server)
        .await;
}

async fn mount_bitbucket_complete_diff(server: &MockServer) {
    mount_bitbucket_merge_base(server).await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7/diffstat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{
                "status": "modified",
                "old": {"path": "src/auth.rs"},
                "new": {"path": "src/auth.rs"}
            }]
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/repositories/acme/api/src/.+/src/auth\.rs$"))
        .respond_with(BitbucketSourceResponder)
        .mount(server)
        .await;
}

#[derive(Clone)]
struct GitLabSourceResponder;

impl Respond for GitLabSourceResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let base = request
            .url
            .query_pairs()
            .any(|(name, value)| name == "ref" && (value == "b" || value == "base"));
        let old = "context line\ntrailing context\n";
        let marker = if request.url.path().contains("late") {
            "let AUTHORITATIVE_LAST_PAGE = true;\n"
        } else {
            ""
        };
        let new = format!(
            "context line\nlet token = user_input;\nexec_query(token);\n{marker}trailing context\n"
        );
        ResponseTemplate::new(200).set_body_string(if base { old.to_string() } else { new })
    }
}

async fn mount_gitlab_source_files(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/repository/files/.+/raw$"))
        .respond_with(GitLabSourceResponder)
        .mount(server)
        .await;
}

async fn mount_azure_merge_base(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(
            "/myorg/myproj/_apis/git/repositories/myrepo/commits/BASE/mergebases",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "commitId": "BASE"
        }])))
        .mount(server)
        .await;
}

fn postil() -> Command {
    let mut cmd = Command::cargo_bin("postil").unwrap();
    // Isolate from developer environment and repo config discovery.
    cmd.env_remove("REVIEW_MODEL")
        .env_remove("REVIEW_MODEL_CASCADE")
        .env_remove("REVIEW_SCORER_MODEL")
        .env_remove("REVIEW_SCORER_MODEL_CASCADE")
        .env_remove("POSTIL_DISABLE_SCORER")
        .env_remove("POSTIL_HOSTED_MODE")
        .env_remove("POSTIL_QUALIFICATION_CANDIDATE_PROFILE")
        .env_remove("POSTIL_QUALIFICATION_PLAN_ONLY")
        .env_remove("POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY")
        .env_remove("POSTIL_LLM_REQUEST_TIMEOUT_SECS")
        .env_remove("POSTIL_LLM_TOTAL_TIMEOUT_SECS")
        .env_remove("MODEL_API_KEY")
        .env_remove("LLM_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("POSTIL_API_KEY")
        .env_remove("POSTIL_API_BASE")
        .env_remove("POSTIL_API_FORMAT")
        .env_remove("POSTIL_ENDPOINT_AUTH_HEADER")
        .env_remove("POSTIL_ENDPOINT_AUTH_VALUE")
        .env_remove("POSTIL_ALLOW_PRIVATE_API_BASE")
        .env_remove("POSTIL_DETAILS_URL")
        .env_remove("POSTIL_PREVENTION_HINT")
        .env_remove("POSTIL_PREVENTION_COMMANDS_JSON")
        .env_remove("GITHUB_SERVER_URL")
        .env_remove("POSTIL_ENABLE_BITBUCKET_INCREMENTAL")
        .env("REVIEW_MODEL", "openai/gpt-5-mini")
        .env("MODEL_API_KEY", fixture_credential("provider"))
        // Mock providers bind loopback. Production and normal CLI invocations
        // reject private API endpoints unless this explicit local-only escape
        // hatch is set by the caller.
        .env("POSTIL_ALLOW_PRIVATE_API_BASE", "1");
    cmd
}

fn assert_model_usage_matches_aggregate(envelope: &Value) {
    let model_usage = envelope["modelUsage"].as_array().unwrap();
    let ordinals = model_usage
        .iter()
        .map(|entry| entry["callOrdinal"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ordinals, (1..=ordinals.len() as u64).collect::<Vec<_>>());
    let prompt_tokens: u64 = model_usage
        .iter()
        .map(|entry| entry["promptTokens"].as_u64().unwrap())
        .sum();
    let completion_tokens: u64 = model_usage
        .iter()
        .map(|entry| entry["completionTokens"].as_u64().unwrap())
        .sum();
    assert_eq!(
        prompt_tokens,
        envelope["usage"]["promptTokens"].as_u64().unwrap()
    );
    assert_eq!(
        completion_tokens,
        envelope["usage"]["completionTokens"].as_u64().unwrap()
    );
}

#[tokio::test]
async fn native_anthropic_review_uses_messages_shape_auth_and_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header("x-api-key", "anthropic-provider-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .and(header("authorization", "Bearer private-endpoint-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_content(json!([]), 11, 7)))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("MODEL_API_KEY", "anthropic-provider-key")
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .env("POSTIL_ENDPOINT_AUTH_HEADER", "Authorization")
        .env(
            "POSTIL_ENDPOINT_AUTH_VALUE",
            "Bearer private-endpoint-secret",
        )
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["usage"]["promptTokens"], 11);
    assert_eq!(envelope["usage"]["completionTokens"], 7);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: Value = requests[0].body_json().unwrap();
    assert!(body["system"].as_str().is_some());
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["max_tokens"], 8_000);
    assert!(body.get("choices").is_none());
}

#[tokio::test]
async fn native_anthropic_findings_skip_incompatible_default_scorer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header("x-api-key", "anthropic-provider-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_content(
            json!([finding_at(42, "warn", 0.9)]),
            17,
            9,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("MODEL_API_KEY", "anthropic-provider-key")
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"].as_array().unwrap().len(), 1);
    assert!(envelope["scorerModel"].is_null());
    assert!(envelope["scorerError"].is_null());
    assert_eq!(envelope["usage"]["promptTokens"], 17);
    assert_eq!(envelope["usage"]["completionTokens"], 9);
}

#[tokio::test]
async fn native_anthropic_findings_use_explicit_native_scorer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_string_contains("\"model\":\"claude-sonnet-4-6\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_content(
            json!([finding_at(42, "warn", 0.9)]),
            17,
            9,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_string_contains("\"model\":\"claude-haiku-4-5\""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(anthropic_text(
                &json!([{
                    "index": 0,
                    "confidence": 0.82,
                    "kind": "risk",
                    "reason": "The changed line contains the reported flow."
                }])
                .to_string(),
                5,
                3,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("MODEL_API_KEY", "anthropic-provider-key")
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .env("REVIEW_MODEL", "claude-sonnet-4-6")
        .env("REVIEW_SCORER_MODEL", "claude-haiku-4-5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["scorerModel"], "claude-haiku-4-5");
    assert_eq!(envelope["findings"][0]["scorerConfidence"], 0.82);
    assert_eq!(envelope["usage"]["promptTokens"], 22);
    assert_eq!(envelope["usage"]["completionTokens"], 12);
}

#[tokio::test]
async fn openai_successful_generator_without_usage_marks_accounting_incomplete() {
    let server = MockServer::start().await;
    let mut response = llm_content(json!([]));
    response.as_object_mut().unwrap().remove("usage");
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("\"model\":\"generator-model\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["usageAccountingComplete"], false);
    assert_eq!(envelope["usage"]["promptTokens"], 0);
    assert_eq!(envelope["usage"]["completionTokens"], 0);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains(
        "llm usage accounting incomplete phase=review model=generator-model attempt=1 reason=missing"
    ));
}

#[tokio::test]
async fn openai_successful_scorer_with_zero_usage_marks_accounting_incomplete() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 0.9)]),
    )
    .await;
    let scorer_response = json!({
        "choices": [{"message": {"content": json!([{
            "index": 0,
            "confidence": 0.82,
            "kind": "risk",
            "reason": "The changed line contains the reported flow."
        }]).to_string()}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0}
    });
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("\"model\":\"scorer-model\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(scorer_response))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "scorer-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["scorerModel"], "scorer-model");
    assert_eq!(envelope["usageAccountingComplete"], false);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains(
        "llm usage accounting incomplete phase=scorer model=scorer-model attempt=1 reason=nonpositive"
    ));
}

#[tokio::test]
async fn anthropic_successful_generator_without_usage_marks_accounting_incomplete() {
    let server = MockServer::start().await;
    let mut response = anthropic_content(json!([]), 11, 7);
    response.as_object_mut().unwrap().remove("usage");
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_string_contains("\"model\":\"generator-model\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .env("REVIEW_MODEL", "generator-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["usageAccountingComplete"], false);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains(
        "llm usage accounting incomplete phase=review model=generator-model attempt=1 reason=missing"
    ));
}

#[tokio::test]
async fn anthropic_successful_scorer_with_zero_usage_marks_accounting_incomplete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_string_contains("\"model\":\"generator-model\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_content(
            json!([finding_at(41, "warn", 0.9)]),
            17,
            9,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(body_string_contains("\"model\":\"scorer-model\""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(anthropic_text(
                &json!([{
                    "index": 0,
                    "confidence": 0.82,
                    "kind": "risk",
                    "reason": "The changed line contains the reported flow."
                }])
                .to_string(),
                0,
                0,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "scorer-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["scorerModel"], "scorer-model");
    assert_eq!(envelope["usageAccountingComplete"], false);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains(
        "llm usage accounting incomplete phase=scorer model=scorer-model attempt=1 reason=nonpositive"
    ));
}

#[tokio::test]
async fn openai_compatible_rejects_additional_authorization_without_leaking() {
    let server = MockServer::start().await;
    let endpoint_secret = "Bearer endpoint-secret-never-print";
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_ENDPOINT_AUTH_HEADER", "Authorization")
        .env("POSTIL_ENDPOINT_AUTH_VALUE", endpoint_secret)
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(!stdout.contains(endpoint_secret));
    assert!(!stderr.contains(endpoint_secret));
    assert!(stderr.contains("cannot override provider-managed header"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn native_anthropic_retries_transient_status_with_the_same_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(529).set_body_string("overloaded"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_content(json!([]), 3, 2)))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("retryable HTTP 529"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() == "/messages")
    );
}

#[tokio::test]
async fn provider_errors_redact_provider_and_endpoint_auth_secrets() {
    let server = MockServer::start().await;
    let provider_secret = "provider-secret-never-print";
    let endpoint_secret = "endpoint-secret-never-print";
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!(
            "bad credentials: {provider_secret} and {endpoint_secret}"
        )))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("MODEL_API_KEY", provider_secret)
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .env("POSTIL_ENDPOINT_AUTH_HEADER", "X-Private-Endpoint-Token")
        .env("POSTIL_ENDPOINT_AUTH_VALUE", endpoint_secret)
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(!stderr.contains(provider_secret));
    assert!(!stderr.contains(endpoint_secret));
    assert!(!stdout.contains(provider_secret));
    assert!(!stdout.contains(endpoint_secret));
    assert!(!stderr.contains("bad credentials"));
    assert!(!stdout.contains("bad credentials"));
    assert!(stderr.contains("status=401"));
    assert!(stderr.contains("category=unclassified"));
}

#[tokio::test]
async fn provider_403_redacts_key_management_url_from_cli_and_finding() {
    let server = MockServer::start().await;
    let key_url = "https://openrouter.ai/settings/keys/key-management-identifier";
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-request-id", "request-safe-1")
                .set_body_json(json!({
                    "error": {
                        "message": format!("Manage this key at {key_url}"),
                        "metadata": {"error_type": key_url}
                    }
                })),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    for output in [&stderr, &stdout] {
        assert!(!output.contains(key_url));
        assert!(!output.contains("key-management-identifier"));
        assert!(!output.contains("Manage this key"));
    }
    assert!(stderr.contains("category=provider"));
    assert_eq!(
        serde_json::from_str::<Value>(&stdout).unwrap()["findings"][0]["title"],
        "Model provider unavailable"
    );
}

#[tokio::test]
async fn byok_reported_spend_is_not_subject_to_the_hosted_operation_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "{\"summary\":\"\",\"findings\":[]}"}}],
            "usage": {"prompt_tokens": 20_000_001_u64, "completion_tokens": 1}
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert!(envelope["findings"].as_array().unwrap().is_empty());
    assert_eq!(envelope["modelUsage"][0]["promptTokens"], 20_000_001_u64);
}

#[cfg(feature = "qualification-candidate")]
#[test]
fn qualification_candidate_preflights_the_bounded_hosted_path_without_provider_contact() {
    let dir = tempfile::tempdir().unwrap();
    let diff_path = dir.path().join("bounded.diff");
    let mut diff = String::new();
    for file in 0..7 {
        let path = format!("src/churn-{file}.rs");
        diff.push_str(&format!(
            "diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,130 @@\n"
        ));
        for line in 0..130 {
            diff.push_str(&format!(
                "+const CHURN_{file}_{line}: &str = \"{}\";\n",
                "x".repeat(900)
            ));
        }
    }
    std::fs::write(&diff_path, diff).unwrap();

    let metadata = postil_cli::config::qualification_metadata();
    let generator_chain = vec!["openai/gpt-5-mini".to_string()];
    let scorer_chain = vec!["openai/gpt-5-mini".to_string()];
    let mut models = generator_chain.clone();
    models.extend(scorer_chain.clone());
    models.sort();
    models.dedup();
    let profile_path = dir.path().join("candidate.json");
    std::fs::write(
        &profile_path,
        serde_json::to_vec(&json!({
            "benchmarkProviderIdentity": postil_cli::config::MANAGED_OPENROUTER_PROVIDER_IDENTITY,
            "apiBase": metadata.default_api_base,
            "apiFormat": metadata.default_api_format,
            "generatorChain": generator_chain,
            "consensus": 1,
            "scorerChain": scorer_chain,
            "modelPriceBounds": models.into_iter().map(|model| json!({
                "model": model,
                "inputMicrosPerMillionTokens": 1,
                "outputMicrosPerMillionTokens": 1
            })).collect::<Vec<_>>()
        }))
        .unwrap(),
    )
    .unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("CI", "true")
        .env("GITHUB_API_URL", "http://127.0.0.1:9")
        .env("POSTIL_BENCH_REQUIRE_HOSTED_PROVIDER_PRIVACY", "1")
        .env("POSTIL_QUALIFICATION_CANDIDATE_PROFILE", &profile_path)
        .env("POSTIL_QUALIFICATION_PLAN_ONLY", "1")
        .args(["review", "--diff-file"])
        .arg(&diff_path)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["reviewCoverage"]["mode"], "bounded");
    assert!(
        envelope["reviewCoverage"]["selectedBatches"]
            .as_u64()
            .unwrap()
            < envelope["reviewCoverage"]["totalBatches"].as_u64().unwrap()
    );
    assert!(
        envelope["reviewAdmission"]["projectedCostMicros"]
            .as_u64()
            .unwrap()
            <= 1_000_000
    );
    assert!(envelope.get("modelUsage").is_none());
}

#[tokio::test]
async fn provider_response_body_above_hard_cap_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 512 * 1024 + 1]))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(
        envelope["findings"][0]["title"],
        "Model provider unavailable"
    );
    assert!(!String::from_utf8_lossy(&out.get_output().stderr).contains(&"x".repeat(128)));
}

#[tokio::test]
async fn zero_token_failed_attempt_cost_is_recorded_once_per_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "cost": 0.001}
        })))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "model:\n  name: one-model\n  cascade: []\n",
    )
    .unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsage"].as_array().unwrap().len(), 2);
    assert!(
        envelope["modelUsage"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| {
                entry["costMicros"] == 1_000
                    && entry["promptTokens"] == 0
                    && entry["completionTokens"] == 0
                    && entry["costSource"] == "providerReported"
                    && entry["accountingComplete"] == true
            })
    );
}

#[tokio::test]
async fn doctor_probes_native_anthropic_format() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": "p"}],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_API_FORMAT", "anthropic")
        .arg("doctor")
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("using anthropic"));
}

#[tokio::test]
async fn doctor_probes_openai_compatible_format_by_default() {
    let server = MockServer::start().await;
    let provider_credential = fixture_credential("provider");
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header(
            "authorization",
            format!("Bearer {provider_credential}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text("p")))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .arg("doctor")
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("using openai-compatible"));
}

#[tokio::test]
async fn doctor_does_not_follow_provider_redirect_or_forward_auth() {
    let redirect_target = MockServer::start().await;
    let provider = MockServer::start().await;
    let provider_credential = fixture_credential("provider-redirect");
    let endpoint_credential = fixture_credential("endpoint-redirect");
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header(
            "authorization",
            format!("Bearer {provider_credential}"),
        ))
        .and(header(
            "x-private-endpoint-token",
            endpoint_credential.as_str(),
        ))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/captured", redirect_target.uri())),
        )
        .expect(1)
        .mount(&provider)
        .await;

    let dir = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let out = postil()
        .current_dir(dir.path())
        .env("MODEL_API_KEY", &provider_credential)
        .env("POSTIL_API_BASE", provider.uri())
        .env("POSTIL_ENDPOINT_AUTH_HEADER", "X-Private-Endpoint-Token")
        .env("POSTIL_ENDPOINT_AUTH_VALUE", &endpoint_credential)
        .arg("doctor")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("307"));
    assert!(!stderr.contains(&provider_credential));
    assert!(!stderr.contains(&endpoint_credential));
    assert!(
        redirect_target
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

fn write_diff(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("change.diff");
    std::fs::write(&p, DIFF).unwrap();
    p
}

fn parse_csv_rows(csv: &str) -> Vec<BTreeMap<String, String>> {
    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    let headers = reader.headers().unwrap().clone();
    reader
        .records()
        .map(|record| {
            headers
                .iter()
                .zip(record.unwrap().iter())
                .map(|(header, value)| (header.to_string(), value.to_string()))
                .collect()
        })
        .collect()
}

async fn mock_review(server: &MockServer, findings: Value) {
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(findings)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn remote_diff_reader_rejects_explicit_truncation_signals() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/truncated.diff"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-diff-truncated", "true")
                .set_body_string("partial"),
        )
        .mount(&server)
        .await;
    let response = reqwest::get(format!("{}/truncated.diff", server.uri()))
        .await
        .unwrap();
    let error = postil_cli::forge::bounded_response_text(response, "test diff")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reported truncated content"));
}

#[tokio::test]
async fn remote_page_reader_rejects_declared_oversized_bodies_before_buffering() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oversized.diff"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
            b'x';
            postil_cli::diff::MAX_FORGE_RESPONSE_BYTES
                + 1
        ]))
        .mount(&server)
        .await;
    let response = reqwest::get(format!("{}/oversized.diff", server.uri()))
        .await
        .unwrap();
    let error = postil_cli::forge::bounded_response_text(response, "test diff")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exceeds the 33554432 byte acquisition limit")
    );
}

#[tokio::test]
async fn generated_named_source_is_not_omitted_from_review() {
    let server = MockServer::start().await;
    let finding = json!({
        "path": "src/client.generated.ts",
        "line": 1,
        "severity": "error",
        "kind": "risk",
        "confidence": 0.99,
        "title": "Remove code execution",
        "body": "Untrusted input reaches eval. Parse the input without executing it."
    });
    mock_review(&server, json!([finding])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("generated-source.diff");
    std::fs::write(
        &diff,
        "diff --git a/src/client.generated.ts b/src/client.generated.ts\n--- a/src/client.generated.ts\n+++ b/src/client.generated.ts\n@@ -0,0 +1 @@\n+eval(userInput);\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .failure();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], "src/client.generated.ts");
    assert_eq!(envelope["findings"][0]["line"], 1);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("src/client.generated.ts"));
    assert!(body.contains("eval(userInput)"));
}

#[tokio::test]
async fn large_source_diff_reviews_every_bounded_batch_and_aggregates_findings() {
    use std::fmt::Write as _;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let body = String::from_utf8_lossy(&request.body);
            let findings = if body.contains("dangerous_final_call") {
                json!([finding_at(10_000, "warn", 0.95)])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(llm_content(findings))
        })
        .mount(&server)
        .await;

    let mut source = String::new();
    writeln!(
        source,
        "diff --git a/src/auth.rs b/src/auth.rs\n--- a/src/auth.rs\n+++ b/src/auth.rs\n@@ -0,0 +1,10000 @@"
    )
    .unwrap();
    for line in 1..10_000 {
        writeln!(
            source,
            "+let reviewed_{line:05} = validate(input_{line:05}); // {}",
            "x".repeat(3_500),
        )
        .unwrap();
    }
    source.push_str("+dangerous_final_call(user_input);\n");
    assert!(source.len() > 32 * 1024 * 1024);

    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("large-source.diff");
    std::fs::write(&diff, source).unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], "src/auth.rs");
    assert_eq!(envelope["findings"][0]["line"], 10_000);
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.len() > 1,
        "large source changes must use multiple batches"
    );
    assert!(
        requests
            .iter()
            .all(|request| { !String::from_utf8_lossy(&request.body).contains("diff truncated") })
    );
}

#[tokio::test]
async fn deletion_only_auth_change_is_reviewed_through_numbered_metadata() {
    let server = MockServer::start().await;
    let finding = json!({
        "path": ".postil/change-metadata",
        "line": 1,
        "severity": "error",
        "kind": "risk",
        "confidence": 0.99,
        "title": "Restore the authorization check",
        "body": "The deleted file enforced administrator access. Preserve the check in the replacement path."
    });
    mock_review(&server, json!([finding])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("deleted-auth.diff");
    std::fs::write(
        &diff,
        "diff --git a/src/auth.rs b/src/auth.rs\ndeleted file mode 100644\n--- a/src/auth.rs\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-fn authorize(user: &User) {\n-    require_admin(user);\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .failure();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], ".postil/change-metadata");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("require_admin"));
    assert!(body.contains("src/auth.rs: deleted"));
}

#[tokio::test]
async fn final_synthesis_detects_cross_batch_validation_sink_relationship() {
    use std::fmt::Write as _;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let body = String::from_utf8_lossy(&request.body);
            let findings = if body.contains("validate_pair") && body.contains("dangerous_sink") {
                json!([{
                    "path": "src/sink.rs",
                    "line": 1100,
                    "severity": "warn",
                    "kind": "risk",
                    "confidence": 0.95,
                    "title": "Keep the validated value",
                    "body": "The sink uses the original input instead of the validated pair. Pass the validated value to dangerous_sink."
                }])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(llm_content(findings))
        })
        .mount(&server)
        .await;

    let mut source = String::from(
        "diff --git a/src/validate.rs b/src/validate.rs\n--- a/src/validate.rs\n+++ b/src/validate.rs\n@@ -0,0 +1,2201 @@\n",
    );
    for line in 1..=2201 {
        if line == 1100 {
            source.push_str("+let validated = validate_pair(left, right);\n");
        } else {
            writeln!(
                source,
                "+let padding_a_{line:04} = trusted; // {}",
                "a".repeat(1_000)
            )
            .unwrap();
        }
    }
    source.push_str(
        "diff --git a/src/sink.rs b/src/sink.rs\n--- a/src/sink.rs\n+++ b/src/sink.rs\n@@ -0,0 +1,2201 @@\n",
    );
    for line in 1..=2201 {
        if line == 1100 {
            source.push_str("+dangerous_sink(original);\n");
        } else {
            writeln!(
                source,
                "+let padding_b_{line:04} = original; // {}",
                "b".repeat(1_000)
            )
            .unwrap();
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("cross-batch.diff");
    std::fs::write(&diff, source).unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], "src/sink.rs");
    assert_eq!(envelope["findings"][0]["line"], 1100);
    let requests = server.received_requests().await.unwrap();
    assert!(requests.len() >= 3);
    assert!(requests.iter().any(|request| {
        let body = String::from_utf8_lossy(&request.body);
        body.contains("bounded synthesis window")
            && body.contains("validate_pair")
            && body.contains("dangerous_sink")
    }));
    assert!(
        requests
            .iter()
            .filter(|request| {
                let body = String::from_utf8_lossy(&request.body);
                body.contains("validate_pair") && body.contains("dangerous_sink")
            })
            .all(|request| {
                String::from_utf8_lossy(&request.body).contains("Cross-window semantic digests")
            })
    );
}

#[tokio::test]
async fn oversized_line_tail_remains_reviewable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let body = String::from_utf8_lossy(&request.body);
            let findings = if body.contains("TAIL_DEFECT_eval") {
                json!([{
                    "path": "src/packed.js",
                    "line": 1,
                    "severity": "warn",
                    "kind": "risk",
                    "confidence": 0.99,
                    "title": "Remove tail code execution",
                    "body": "The packed line executes untrusted input at its tail. Replace eval with a parser."
                }])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(llm_content(findings))
        })
        .mount(&server)
        .await;

    let source = format!(
        "diff --git a/src/packed.js b/src/packed.js\n--- a/src/packed.js\n+++ b/src/packed.js\n@@ -0,0 +1 @@\n+{}TAIL_DEFECT_eval(userInput);\n",
        "x".repeat(40_000)
    );
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("oversized-line.diff");
    std::fs::write(&diff, source).unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], "src/packed.js");
    assert_eq!(envelope["findings"][0]["line"], 1);
}

#[tokio::test]
async fn multiline_finding_range_is_collapsed_when_endpoint_is_not_in_same_segment() {
    use std::fmt::Write as _;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let body = String::from_utf8_lossy(&request.body);
            let findings = if body.contains("range_start_marker") {
                json!([{
                    "path": "src/range.rs",
                    "line": 1,
                    "endLine": 4000,
                    "severity": "warn",
                    "kind": "risk",
                    "confidence": 0.95,
                    "title": "Keep the comment range local",
                    "body": "The first changed line is risky. Fix that line."
                }])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(llm_content(findings))
        })
        .mount(&server)
        .await;
    let mut source = String::from(
        "diff --git a/src/range.rs b/src/range.rs\n--- a/src/range.rs\n+++ b/src/range.rs\n@@ -0,0 +1,4000 @@\n+range_start_marker();\n",
    );
    for line in 2..=4000 {
        writeln!(source, "+let range_padding_{line:04} = value;").unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("range.diff");
    std::fs::write(&diff, source).unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["line"], 1);
    assert!(envelope["findings"][0].get("endLine").is_none());
}

#[tokio::test]
async fn model_chain_above_hard_cap_fails_before_provider_calls() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let config = dir.path().join("postil.yml");
    std::fs::write(
        &config,
        "model:\n  name: model/one\n  cascade:\n    - model/two\n    - model/three\n    - model/four\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--config")
        .arg(&config)
        .args(["--output", "json"])
        .assert()
        .code(1);
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["title"], "Review incomplete");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn staged_diff_compacts_large_generated_noise_and_reviews_late_source() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let body = String::from_utf8_lossy(&request.body);
            let findings = if body.contains("late_dangerous_call") {
                json!([{
                    "path": "late.rs",
                    "line": 1,
                    "severity": "warn",
                    "kind": "risk",
                    "confidence": 0.99,
                    "title": "Validate the late call",
                    "body": "The late call receives untrusted input without validation."
                }])
            } else {
                json!([])
            };
            ResponseTemplate::new(200).set_body_json(llm_content(findings))
        })
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        dir.path().join("bundle.min.js"),
        format!(
            "/* generated by esbuild; do not edit */{}",
            "x".repeat(33 * 1024 * 1024)
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("late.rs"),
        "late_dangerous_call(user_input);\n",
    )
    .unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["add", "bundle.min.js", "late.rs"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success()
    );
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--staged", "--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], "late.rs");
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        String::from_utf8_lossy(&request.body).contains("verified generated artifact")
    }));
    assert!(
        requests
            .iter()
            .all(|request| request.body.len() < 512 * 1024)
    );
}

#[tokio::test]
async fn lockfile_only_diff_is_reviewed_from_compact_dependency_evidence() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("lockfile-only.diff");
    let padding = "x".repeat(33 * 1024 * 1024);
    std::fs::write(&diff, format!(
        "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,3 +1,3 @@\n name = \"dangerous-dependency\"\n-version = \"1.2.2\"\n+version = \"1.2.3\"\n checksum = \"{padding}\"\n"
    ))
    .unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"], json!([]));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("dangerous-dependency@1.2.3"));
    assert!(!body.contains(&padding[..4096]));
    assert!(body.contains("Cargo.lock"));
    assert!(body.contains("dangerous-dependency"));
    assert!(body.contains("removed dangerous-dependency@1.2.2"));
    assert!(body.contains("added dangerous-dependency@1.2.3"));
}

#[tokio::test]
async fn quoted_lockfile_path_is_decoded_and_raw_content_never_reaches_provider() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("quoted-lockfile.diff");
    std::fs::write(
        &diff,
        "diff --git \"a/deps space/Cargo.lock\" \"b/deps space/Cargo.lock\"\n--- \"a/deps space/Cargo.lock\"\n+++ \"b/deps space/Cargo.lock\"\n@@ -1,3 +1,3 @@\n name = \"package-one\"\n-version = \"1.0.0\"\n+version = \"2.0.0\"\n checksum = \"RAW_LOCKFILE_SENTINEL\"\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"], json!([]));
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("deps space/Cargo.lock"));
    assert!(body.contains("removed package-one@1.0.0"));
    assert!(body.contains("added package-one@2.0.0"));
    assert!(!body.contains("RAW_LOCKFILE_SENTINEL"));
}

#[tokio::test]
async fn c_quoted_prompt_path_round_trips_into_canonical_finding_path() {
    let server = MockServer::start().await;
    let canonical = "src/tab\tline\rbreak\nquote\"slash\\日.rs";
    let displayed = postil_cli::diff::display_path(canonical);
    mock_review(
        &server,
        json!([{
            "path": displayed,
            "line": 1,
            "severity": "warn",
            "kind": "risk",
            "confidence": 0.9,
            "title": "Hostile path remains grounded",
            "body": "The changed call is unsafe. Replace it with a checked operation."
        }]),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("quoted-path.diff");
    let old = postil_cli::diff::display_path(&format!("a/{canonical}"));
    let new = postil_cli::diff::display_path(&format!("b/{canonical}"));
    std::fs::write(
        &diff,
        format!(
            "diff --git {old} {new}\n--- {old}\n+++ {new}\n@@ -0,0 +1 @@\n+dangerous_call();\n"
        ),
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"][0]["path"], canonical);
}

#[tokio::test]
async fn malformed_lockfile_falls_back_to_source_review() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;
    let dir = tempfile::tempdir().unwrap();
    let diff = dir.path().join("malformed-lockfile.diff");
    std::fs::write(
        &diff,
        "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1 +1 @@\n-checksum = \"old\"\n+checksum = \"new\"\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert!(envelope["findings"].as_array().unwrap().is_empty());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains(r#"checksum = \"new\""#));
}

async fn mock_review_model(server: &MockServer, model: &str, findings: Value) {
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains(format!(
            "\"model\":\"{model}\""
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(findings)))
        .mount(server)
        .await;
}

async fn mock_scorer_model(server: &MockServer, model: &str, scores: Value) {
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains(format!(
            "\"model\":\"{model}\""
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(scorer_content(scores)))
        .mount(server)
        .await;
}

#[test]
fn hosted_config_ignores_repository_model_provider_and_scorer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "model:\n  name: anthropic/claude-opus-4.1\n  cascade: [attacker/fallback]\n  scorer: anthropic/claude-haiku-4.5\n  apiBase: https://attacker.invalid/v1\n  apiFormat: anthropic\n  consensus: 3\n",
    )
    .unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_HOSTED_MODE", "1")
        .env("REVIEW_MODEL", "stale/primary")
        .env("REVIEW_MODEL_CASCADE", "stale/fallback")
        .env("REVIEW_SCORER_MODEL", "stale/scorer")
        .args(["config"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("model.name: "));
    assert!(stdout.contains("model.cascade: []"));
    assert!(stdout.contains("model.scorer: "));
    assert!(stdout.contains("model.apiBase: https://openrouter.ai/api/v1"));
    assert!(stdout.contains("model.apiFormat: openai-compatible"));
    assert!(stdout.contains("model.consensus: 1"));
    assert!(!stdout.contains("anthropic/"));
    assert!(!stdout.contains("attacker"));
    assert!(!stdout.contains("stale/"));
}

#[tokio::test]
async fn local_review_reports_grounded_finding_and_gates() {
    let server = MockServer::start().await;
    mock_review(&server, json!([finding_at(41, "error", 0.92)])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1); // gate fails on error severity
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["silent"], false);
    assert_eq!(env["findings"][0]["path"], "src/auth.rs");
    assert_eq!(env["findings"][0]["line"], 41);
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["counts"]["error"], 1);
    // Embedded scoring is disabled unless the user explicitly configures it.
    assert_eq!(env["usage"]["promptTokens"], 100);
    assert_eq!(env["usageAccountingComplete"], true);
    let model_usage = env["modelUsage"].as_array().unwrap();
    assert!(!model_usage.is_empty());
    assert_eq!(model_usage[0]["role"], "reviewGenerator");
    assert_eq!(model_usage[0]["phase"], "initial");
    assert_eq!(model_usage[0]["callOrdinal"], 1);
    assert_eq!(model_usage[0]["attempt"], 1);
    assert_eq!(model_usage[0]["accountingComplete"], true);
    assert_eq!(
        model_usage
            .iter()
            .map(|entry| entry["promptTokens"].as_u64().unwrap())
            .sum::<u64>(),
        env["usage"]["promptTokens"].as_u64().unwrap()
    );

    let requests = server.received_requests().await.unwrap();
    let request: Value = requests[0].body_json().unwrap();
    assert_eq!(request["max_tokens"], 8_000);
    assert_eq!(request["messages"].as_array().unwrap().len(), 2);
    let prompt_bytes = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap().len())
        .sum::<usize>();
    assert!(
        prompt_bytes <= 8_200 + DIFF.len(),
        "qualification prompt bound is too small: {prompt_bytes} bytes"
    );
}

#[test]
fn review_without_an_explicit_model_exits_before_provider_access() {
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env_remove("REVIEW_MODEL")
        .env_remove("REVIEW_MODEL_CASCADE")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .assert()
        .code(2);

    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("no review model is configured"));
}

#[tokio::test]
async fn weak_human_escalation_remains_visible_without_blocking_gate() {
    let server = MockServer::start().await;
    mock_review(
        &server,
        json!([finding_at_with_kind(41, "error", "humanEscalation", 0.05)]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".postil.yaml"), "minConfidence: 0\n").unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);
    let env: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();

    assert_eq!(env["findings"][0]["kind"], "humanEscalation");
    assert_eq!(env["findings"][0]["confidence"], 0.05);
    assert_eq!(env["gate"]["failing"], false);
}

#[tokio::test]
async fn human_escalation_at_floor_blocks_even_at_warn_severity() {
    let server = MockServer::start().await;
    mock_review(
        &server,
        json!([finding_at_with_kind(41, "warn", "humanEscalation", 0.30)]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".postil.yaml"), "minConfidence: 0\n").unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);
    let env: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();

    assert_eq!(env["findings"][0]["severity"], "warn");
    assert_eq!(env["gate"]["failing"], true);
}

#[tokio::test]
async fn scorer_lowers_confidence_and_stores_both_values() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("generator-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "warn", 0.92)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(scorer_content(json!([{
                "index": 0,
                "confidence": 0.7,
                "kind": "risk",
                "reason": "The finding is plausible, but its impact depends on query behavior."
            }]))),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    let finding = &env["findings"][0];
    assert_eq!(env["scorerModel"], "anthropic/claude-haiku-4.5");
    assert_eq!(env["scorerDisagreements"], 0);
    assert_eq!(finding["confidence"], 0.7);
    assert_eq!(finding["generatorConfidence"], 0.92);
    assert_eq!(finding["scorerConfidence"], 0.7);
    assert_eq!(finding["kind"], "risk");
    assert_eq!(finding["generatorKind"], "risk");
    assert_eq!(finding["scorerKind"], "risk");
    assert_eq!(env["usage"]["promptTokens"], 130);
    assert_eq!(env["usage"]["completionTokens"], 60);
    assert_eq!(env["modelUsage"].as_array().unwrap().len(), 2);
    assert_eq!(env["modelUsage"][0]["costMicros"], 123);
    assert_eq!(env["modelUsage"][1]["costMicros"], 45);
    assert_model_usage_matches_aggregate(&env);
    assert!(stderr.contains("postil: attempting model: generator-model"));
    assert!(stderr.contains("postil: model generator-model responded in"));
    assert!(stderr.contains("postil: running scorer with anthropic/claude-haiku-4.5"));
    assert!(stderr.contains("postil: scorer anthropic/claude-haiku-4.5 completed successfully in"));

    let requests = server.received_requests().await.unwrap();
    let scorer_request: Value = requests
        .iter()
        .map(|request| request.body_json::<Value>().unwrap())
        .find(|body| body["model"] == "anthropic/claude-haiku-4.5")
        .unwrap();
    assert_eq!(scorer_request["temperature"], 0.0);
    assert_eq!(scorer_request["max_tokens"], 896);
    let scorer_prompt_bytes = scorer_request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap().len())
        .sum::<usize>();
    assert!(
        scorer_prompt_bytes <= 17_000,
        "qualification scorer prompt bound is too small: {scorer_prompt_bytes} bytes"
    );
    let scorer_user = scorer_request["messages"][1]["content"].as_str().unwrap();
    assert!(!scorer_user.contains("0.92"));
    assert!(!scorer_user.contains("\"kind\": \"risk\""));
    assert!(scorer_user.contains("diffHunk"));
}

#[tokio::test]
async fn same_model_generator_and_scorer_emit_separate_balanced_usage_rows() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("same-model"))
        .and(body_string_contains(
            "Postil's independent second-model scorer",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(scorer_content(json!([{
                "index": 0,
                "confidence": 0.8,
                "kind": "risk",
                "reason": "The changed line contains the reported unsafe data flow."
            }]))),
        )
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("same-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "warn", 0.92)]))),
        )
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "same-model")
        .env("REVIEW_SCORER_MODEL", "same-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["usage"]["promptTokens"], 130);
    assert_eq!(envelope["usage"]["completionTokens"], 60);
    assert_eq!(envelope["modelUsage"].as_array().unwrap().len(), 2);
    assert!(
        envelope["modelUsage"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["model"] == "same-model")
    );
    assert_eq!(envelope["modelUsage"][0]["role"], "reviewGenerator");
    assert_eq!(envelope["modelUsage"][1]["role"], "findingScorer");
    assert_eq!(envelope["modelUsage"][0]["callOrdinal"], 1);
    assert_eq!(envelope["modelUsage"][1]["callOrdinal"], 2);
    assert_model_usage_matches_aggregate(&envelope);
}

#[tokio::test]
async fn scorer_confidence_below_minimum_is_suppressed_and_nonblocking() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("generator-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.92)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(scorer_content(json!([{
                "index": 0,
                "confidence": 0.1,
                "kind": "risk",
                "reason": "Independent evidence does not support the generator claim."
            }]))),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".postil.yaml"), "minConfidence: 0.6\n").unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["findings"].as_array().unwrap().len(), 0);
    assert_eq!(envelope["silent"], true);
    assert_eq!(envelope["gate"]["failing"], false);
    assert_eq!(envelope["counts"]["error"], 0);
    assert_eq!(envelope["counts"]["suppressed"], 1);
    assert_eq!(envelope["suppressedFindings"].as_array().unwrap().len(), 1);
    assert_eq!(
        envelope["suppressedFindings"][0]["reason"],
        "belowConfidence"
    );
    assert_eq!(
        envelope["suppressedFindings"][0]["finding"]["path"],
        "src/auth.rs"
    );
    assert_eq!(envelope["scorerModel"], "anthropic/claude-haiku-4.5");
}

#[tokio::test]
async fn malformed_scorer_reason_gets_one_same_model_schema_repair() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 0.92)]),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .and(body_string_contains("failed schema validation"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(scorer_content(json!([{
                "index": 0,
                "confidence": 0.75,
                "kind": "risk",
                "reason": "This is a concrete defect."
            }]))),
        )
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(scorer_content(json!([{
                "index": 0,
                "confidence": 0.75,
                "kind": "risk",
                "reason": "This reason is incomplete"
            }]))),
        )
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert_eq!(envelope["scorerModel"], "anthropic/claude-haiku-4.5");
    assert_eq!(envelope["findings"][0]["scorerKind"], "risk");
    assert_eq!(envelope["modelIncidents"][0]["phase"], "scorer");
    assert_eq!(envelope["modelIncidents"][0]["category"], "invalidOutput");
    assert_eq!(envelope["modelIncidents"][0]["recovered"], true);
    assert_eq!(envelope["modelIncidents"][0]["recovery"], "repair");
    assert_eq!(envelope["usage"]["promptTokens"], 160);
    assert_eq!(envelope["usage"]["completionTokens"], 70);
    assert_eq!(envelope["modelUsage"].as_array().unwrap().len(), 3);
    assert_eq!(envelope["modelUsage"][1]["role"], "findingScorer");
    assert_eq!(envelope["modelUsage"][1]["phase"], "initial");
    assert_eq!(envelope["modelUsage"][2]["role"], "findingScorer");
    assert_eq!(envelope["modelUsage"][2]["phase"], "schemaRepair");
    assert_eq!(envelope["modelUsage"][2]["callOrdinal"], 3);
    assert_model_usage_matches_aggregate(&envelope);
    assert!(stderr.contains("requesting one schema repair"));
}

#[tokio::test]
async fn slow_explicit_scorer_times_out_without_unqualified_fallback() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 0.92)]),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(scorer_content(json!([]))),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "1")
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert!(env.get("scorerModel").is_none());
    assert!(env["scorerError"].as_str().unwrap().contains("timed out"));
    assert_eq!(env["usageAccountingComplete"], false);
    assert_eq!(env["modelIncidents"][0]["phase"], "scorer");
    assert_eq!(env["modelIncidents"][0]["category"], "timeout");
    assert_eq!(env["modelIncidents"][0]["recovered"], false);
    assert!(env["modelIncidents"][0].get("recovery").is_none());
    let models: Vec<_> = env["modelUsage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["model"].as_str().unwrap())
        .collect();
    assert!(models.contains(&"generator-model"));
    // The timed-out call is retained as an incomplete row with no invented
    // token count.
    assert!(models.contains(&"anthropic/claude-haiku-4.5"));
    assert!(stderr.contains("postil: scorer anthropic/claude-haiku-4.5 timed out after"));
    assert!(stderr.contains("no fallback scorers remain"));
    assert!(!stderr.contains("openai/gpt-5-mini"));
}

#[tokio::test]
async fn scorer_kind_escalation_into_configured_blocking_kind_takes_effect() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 0.9)]),
    )
    .await;
    mock_scorer_model(
        &server,
        "anthropic/claude-haiku-4.5",
        json!([{
            "index": 0,
            "confidence": 0.88,
            "kind": "guardrail",
            "reason": "The finding violates the configured rule."
        }]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "gate:\n  blockOnKinds:\n    - guardrail\n",
    )
    .unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["findings"][0]["kind"], "guardrail");
    assert_eq!(env["findings"][0]["generatorKind"], "risk");
    assert_eq!(env["findings"][0]["scorerKind"], "guardrail");
    assert_eq!(env["gate"]["failing"], true);
}

#[tokio::test]
async fn scorer_kind_deescalation_from_blocking_kind_is_ignored() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at_with_kind(41, "warn", "guardrail", 0.9)]),
    )
    .await;
    mock_scorer_model(
        &server,
        "anthropic/claude-haiku-4.5",
        json!([{
            "index": 0,
            "confidence": 0.88,
            "kind": "risk",
            "reason": "The finding is not a guardrail violation."
        }]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "gate:\n  blockOnKinds:\n    - guardrail\n",
    )
    .unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["findings"][0]["kind"], "guardrail");
    assert_eq!(env["findings"][0]["generatorKind"], "guardrail");
    assert_eq!(env["findings"][0]["scorerKind"], "risk");
    assert_eq!(env["gate"]["failing"], true);
}

#[tokio::test]
async fn large_confidence_disagreement_escalates_to_uncertainty_with_default_gate() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 1.0)]),
    )
    .await;
    mock_scorer_model(
        &server,
        "anthropic/claude-haiku-4.5",
        json!([{
            "index": 0,
            "confidence": 0.6,
            "kind": "risk",
            "reason": "The finding has weak supporting evidence."
        }]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["findings"][0]["confidence"], 0.6);
    assert_eq!(env["findings"][0]["kind"], "uncertainty");
    assert_eq!(env["findings"][0]["generatorKind"], "risk");
    assert_eq!(env["findings"][0]["scorerKind"], "risk");
    assert_eq!(env["scorerDisagreements"], 1);
}

#[tokio::test]
async fn scorer_error_fails_open_and_preserves_generator_values() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("generator-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "warn", 0.92)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    let finding = &env["findings"][0];
    assert_eq!(env["gate"]["failing"], false);
    assert!(env.get("scorerModel").is_none());
    assert!(
        env["scorerError"]
            .as_str()
            .unwrap()
            .contains("scorer output invalid")
    );
    assert!(env.get("scorerDisagreements").is_none());
    assert_eq!(env["modelUsage"][0]["model"], "generator-model");
    assert_eq!(env["modelUsage"][1]["model"], "anthropic/claude-haiku-4.5");
    assert_eq!(env["modelUsage"].as_array().unwrap().len(), 3);
    assert_model_usage_matches_aggregate(&env);
    assert_eq!(finding["confidence"], 0.92);
    assert_eq!(finding["kind"], "risk");
    assert!(finding.get("generatorConfidence").is_none());
    assert!(finding.get("scorerConfidence").is_none());
    assert!(finding.get("generatorKind").is_none());
    assert!(finding.get("scorerKind").is_none());
    assert!(stderr.contains("postil: scorer anthropic/claude-haiku-4.5 failed after"));
    assert!(stderr.contains("no fallback scorers remain"));
    assert!(!stderr.contains("openai/gpt-5-mini"));
}

#[tokio::test]
async fn scorer_provider_error_cannot_inject_stderr_lines() {
    let server = MockServer::start().await;
    mock_review_model(
        &server,
        "generator-model",
        json!([finding_at(41, "warn", 0.92)]),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("anthropic/claude-haiku-4.5"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad\n[stderr] forged\u{1b}[31m"))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "generator-model")
        .env("REVIEW_SCORER_MODEL", "anthropic/claude-haiku-4.5")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!stderr.contains("\n[stderr] forged"));
    assert!(!stderr.contains('\u{1b}'));
    assert!(!stderr.contains("forged"));
    assert!(!stderr.contains("bad"));
    assert!(stderr.contains("status=400"));
    assert!(stderr.contains("postil: scorer failed open after all scorer models failed"));
}

#[tokio::test]
async fn local_review_prints_yaml_output() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "yaml"])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: serde_yaml::Value = serde_yaml::from_str(&stdout).unwrap();
    assert_eq!(env["silent"], true);
    assert_eq!(env["gate"]["failing"], false);
}

#[tokio::test]
async fn local_review_writes_csv_output_file_with_multiple_escaped_findings() {
    let server = MockServer::start().await;
    mock_review(
        &server,
        json!([
            finding_with_text(
                41,
                "warn",
                0.88,
                "Comma, quote \"and\" newline\nin title",
                "First body has a comma, a \"quote\", and a newline\nsecond line."
            ),
            finding_with_text(
                42,
                "info",
                0.77,
                "Second finding",
                "Body without CSV punctuation"
            )
        ]),
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let output = dir.path().join("review.csv");
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "csv", "--output-file"])
        .arg(&output)
        .assert()
        .success();

    assert!(out.get_output().stdout.is_empty());
    let csv = std::fs::read_to_string(output).unwrap();
    let rows = parse_csv_rows(&csv);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["version"], "1");
    assert_eq!(rows[0]["silent"], "false");
    assert_eq!(rows[0]["summary"], "SQL injection risk in auth path.");
    assert_eq!(rows[0]["path"], "src/auth.rs");
    assert_eq!(rows[0]["line"], "41");
    assert_eq!(rows[0]["endLine"], "");
    assert_eq!(rows[0]["severity"], "warn");
    assert_eq!(rows[0]["kind"], "risk");
    assert_eq!(rows[0]["confidence"], "0.88");
    assert_eq!(rows[0]["title"], "Comma, quote \"and\" newline in title");
    assert_eq!(
        rows[0]["body"],
        "First body has a comma, a \"quote\", and a newline\nsecond line."
    );
    assert_eq!(rows[0]["gateFailOn"], "error");
    assert_eq!(rows[0]["gateFailing"], "false");
    assert_eq!(rows[0]["promptTokens"], "100");
    assert_eq!(rows[0]["completionTokens"], "50");

    assert_eq!(rows[1]["path"], "src/auth.rs");
    assert_eq!(rows[1]["line"], "42");
    assert_eq!(rows[1]["severity"], "info");
    assert_eq!(rows[1]["title"], "Second finding");
    assert_eq!(rows[1]["body"], "Body without CSV punctuation");
}

#[tokio::test]
async fn local_review_writes_output_file_in_selected_format() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let output = dir.path().join("review.json");
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json", "--output-file"])
        .arg(&output)
        .assert()
        .success();

    assert!(out.get_output().stdout.is_empty());
    let env: Value = serde_json::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(env["silent"], true);
    assert_eq!(env["gate"]["failing"], false);
}

#[tokio::test]
async fn deprecated_output_json_alias_prints_json_with_warning() {
    let server = MockServer::start().await;
    mock_review(&server, json!([])).await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["silent"], true);
    assert!(
        stderr.contains("warning: --output-json is deprecated; use --output json instead"),
        "expected deprecation warning, got: {stderr}"
    );
}

#[test]
fn review_help_documents_machine_output_flags() {
    let out = Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("--output <OUTPUT>"));
    assert!(stdout.contains("--output-file <OUTPUT_FILE>"));
    assert!(stdout.contains("--output-json"));
    assert!(stdout.contains("Deprecated in v0.2.1: use --output json"));
}

#[test]
fn review_rejects_unknown_output_format() {
    Command::cargo_bin("postil")
        .unwrap()
        .args(["review", "--output", "xml"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "possible values: json, yaml, csv",
        ));
}

#[tokio::test]
async fn full_remote_review_uses_an_immutable_merge_base_snapshot() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
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
            "title": "t", "body": "b",
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
        })))
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
            "--no-post",
            "--output-json",
        ])
        .assert()
        .code(0);

    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().any(|request| {
        request.url.path() == "/repos/acme/api/compare/bbbbbbbbbbbb...aaaaaaaaaaaa"
    }));
}

#[tokio::test]
async fn github_large_lockfile_streams_past_legacy_response_limit_and_compacts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/repos/acme/api/compare/b+\.\.\.a+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "bbbbbbbb"},
            "files": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "filename": "Cargo.lock",
            "status": "modified",
            "changes": 2
        }])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/contents/Cargo.lock"))
        .respond_with(GitHubLargeLockfileResponder)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "large lockfile", "body": "",
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"},
            "changed_files": 1
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_DISABLE_SCORER", "1")
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args([
            "review",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--no-post",
            "--output-json",
        ])
        .assert()
        .success();

    let requests = server.received_requests().await.unwrap();
    let model = requests
        .iter()
        .find(|request| request.url.path() == "/chat/completions")
        .expect("model request");
    let body = String::from_utf8_lossy(&model.body);
    assert!(body.contains("large-dependency@1.2.3"));
    assert!(model.body.len() < 512 * 1024);
}

#[tokio::test]
async fn remote_setup_time_counts_against_total_llm_budget() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    let forge_delay = std::time::Duration::from_millis(1200);
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .and(header("Accept", "application/vnd.github.v3.diff"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(forge_delay)
                .set_body_string(DIFF),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(forge_delay)
                .set_body_json(json!({
                    "title": "t", "body": "b",
                    "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
                })),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "5")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "1")
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args([
            "review",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--no-post",
            "--output-json",
        ])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/provider");

    let reqs = server.received_requests().await.unwrap();
    let model_calls = reqs
        .iter()
        .filter(|r| r.url.path() == "/chat/completions")
        .count();
    assert_eq!(model_calls, 0);
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
    mount_github_complete_diff(&server, 7).await;
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
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
    Mock::given(method("GET"))
        .and(path_regex(r"^/repos/acme/api/compare/b+\.\.\.a+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "bbbbbbbb"},
            "files": []
        })))
        .mount(&server)
        .await;
    // The authoritative files fetch fails after meta already succeeded.
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7/files"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string("upstream down")
                .set_delay(std::time::Duration::from_millis(25)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": "b",
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
    assert_eq!(env["headSha"], "aaaaaaaaaaaa");

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
    assert!(env["durationMs"].as_u64().unwrap() >= 20);
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
    // No config: default gate.onError is block, so an unusable review fails closed.
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
    assert_eq!(env["usage"]["promptTokens"], 200);
    assert_eq!(env["usage"]["completionTokens"], 100);
    assert_eq!(env["modelUsage"].as_array().unwrap().len(), 2);
    assert_eq!(env["modelUsage"][0]["phase"], "initial");
    assert_eq!(env["modelUsage"][1]["phase"], "semanticRetry");
    assert_eq!(env["modelUsage"][0]["callOrdinal"], 1);
    assert_eq!(env["modelUsage"][1]["callOrdinal"], 2);
    assert_model_usage_matches_aggregate(&env);
    // The narrated concern is preserved, not silently dropped.
    assert!(
        env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .contains("SQL injection risk in auth path.")
    );
}

#[tokio::test]
async fn schema_repair_contradiction_fails_without_a_third_model_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_text("not json")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_contradictory()))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "test-model")
        .env("REVIEW_MODEL_CASCADE", "test-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    assert_eq!(env["modelUsage"].as_array().unwrap().len(), 2);
    assert_eq!(env["modelUsage"][0]["phase"], "initial");
    assert_eq!(env["modelUsage"][1]["phase"], "schemaRepair");
    assert_model_usage_matches_aggregate(&env);
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
    assert_eq!(env["usage"]["promptTokens"], 200);
    assert_eq!(env["usage"]["completionTokens"], 100);
    assert_model_usage_matches_aggregate(&env);
}

#[tokio::test]
async fn low_confidence_only_finding_with_risk_summary_fails_closed() {
    // M1 regression: the model returns one grounded finding below minConfidence
    // (suppressed) WHILE its summary narrates risk. Policy emptying the kept set
    // must not let a risk-narrating run pass silently. The narrated-risk guard
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
        .respond_with(
            ResponseTemplate::new(200).set_body_json(llm_text("I cannot review this diff, sorry.")),
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
    assert_eq!(env["usage"]["promptTokens"], 160);
    assert_eq!(env["usage"]["completionTokens"], 60);
    // Initial call plus one schema-repair call for the explicit model.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let models: Vec<String> = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(models, vec!["openai/gpt-5-mini", "openai/gpt-5-mini"]);
}

#[tokio::test]
async fn cascade_falls_back_to_next_model() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"metadata": {"error_type": "provider_unavailable"}},
            "usage": {"prompt_tokens": 12, "completion_tokens": 0}
        })))
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
    assert_eq!(env["modelIncidents"][0]["phase"], "review");
    assert_eq!(env["modelIncidents"][0]["category"], "providerError");
    assert_eq!(env["modelIncidents"][0]["recovered"], true);
    assert_eq!(env["modelIncidents"][0]["recovery"], "fallback");
    assert_eq!(env["usage"]["promptTokens"], 136);
    assert_eq!(env["usage"]["completionTokens"], 50);
    assert_eq!(env["modelUsage"][0]["model"], "primary-model");
    assert_eq!(env["modelUsage"].as_array().unwrap().len(), 4);
    assert!(
        env["modelUsage"].as_array().unwrap()[..3]
            .iter()
            .all(|entry| entry["model"] == "primary-model" && entry["promptTokens"] == 12)
    );
    assert_model_usage_matches_aggregate(&env);
    assert_eq!(env["usageAccountingComplete"], true);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("postil: attempting model: primary-model"));
    assert!(stderr.contains("postil: model primary-model returned retryable HTTP 500"));
    assert!(stderr.contains("retrying in 2.0s"));
    assert!(stderr.contains("postil: model primary-model failed after"));
    assert!(stderr.contains("falling back to next model"));
    assert!(stderr.contains("postil: attempting model: backup-model"));
    assert!(stderr.contains("postil: model backup-model responded in"));
}

#[tokio::test]
async fn consensus_logs_each_model_outcome() {
    let server = MockServer::start().await;
    for model in ["consensus-a", "consensus-b"] {
        mock_review_model(&server, model, json!([])).await;
    }

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".postil.yaml"), "model:\n  consensus: 2\n").unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "consensus-a")
        .env("REVIEW_MODEL_CASCADE", "consensus-b")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    for model in ["consensus-a", "consensus-b"] {
        assert!(stderr.contains(&format!("postil: attempting consensus model: {model}")));
        assert!(stderr.contains(&format!("postil: consensus model {model} responded in")));
    }
}

#[tokio::test]
async fn slow_model_request_retries_same_model_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(llm_content(json!([]))),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
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
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "1")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["modelUsed"], "primary-model");
    assert_eq!(env["usageAccountingComplete"], false);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("postil: model primary-model hit a request timeout after"));
    assert!(stderr.contains("timeout retry 1/1"));
    assert!(stderr.contains("postil: model primary-model responded in"));
    assert!(!stderr.contains("postil: attempting model: backup-model"));

    let requests = server.received_requests().await.unwrap();
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(models, vec!["primary-model", "primary-model"]);
}

#[tokio::test]
async fn empty_success_response_retries_same_model_and_accumulates_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "empty-attempt",
            "model": "primary-model",
            "provider": "test-provider",
            "choices": [],
            "usage": {"prompt_tokens": 12, "completion_tokens": 0}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
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
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsed"], "primary-model");
    assert_eq!(envelope["usage"]["promptTokens"], 112);
    assert_eq!(envelope["usage"]["completionTokens"], 50);
    assert_eq!(envelope["modelUsage"].as_array().unwrap().len(), 2);
    assert_eq!(envelope["modelUsage"][0]["promptTokens"], 12);
    assert_eq!(envelope["modelUsage"][1]["promptTokens"], 100);
    assert_eq!(envelope["modelUsage"][0]["attempt"], 1);
    assert_eq!(envelope["modelUsage"][1]["attempt"], 2);
    assert_eq!(envelope["usageAccountingComplete"], true);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("returned empty content"));
    assert!(stderr.contains("phase=review"));
    assert!(stderr.contains("provider=present"));
    assert!(stderr.contains("usage=present"));
    assert!(stderr.contains("response_id=present"));
    assert!(!stderr.contains("empty-attempt"));

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn empty_success_without_usage_marks_accounting_incomplete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices": []})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("REVIEW_MODEL", "primary-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);
    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["usageAccountingComplete"], false);
}

#[tokio::test]
async fn malformed_success_without_usage_marks_accounting_incomplete_before_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
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
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsed"], "backup-model");
    assert_eq!(envelope["usageAccountingComplete"], false);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("usage=missing"));
    assert!(!stderr.contains("not-json"));
}

#[tokio::test]
async fn malformed_success_with_usage_records_the_attempt_exactly_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": "invalid-shape",
            "usage": {"prompt_tokens": 12, "completion_tokens": 3}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
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
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsed"], "backup-model");
    assert_eq!(envelope["usage"]["promptTokens"], 112);
    assert_eq!(envelope["usage"]["completionTokens"], 53);
    assert_eq!(envelope["modelUsage"][0]["promptTokens"], 12);
    assert_eq!(envelope["modelUsage"][0]["completionTokens"], 3);
    assert_eq!(envelope["usageAccountingComplete"], true);
}

#[tokio::test]
async fn slow_empty_response_retry_times_out_then_preserves_the_cascade() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [],
            "usage": {"prompt_tokens": 12, "completion_tokens": 0}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(llm_content(json!([]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "1")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsed"], "backup-model");
    let requests = server.received_requests().await.unwrap();
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        models,
        vec!["primary-model", "primary-model", "backup-model"]
    );
}

#[tokio::test]
async fn empty_response_retry_http_failure_falls_back_without_a_third_primary_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [],
            "usage": {"prompt_tokens": 12, "completion_tokens": 0}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"metadata": {"error_type": "provider_unavailable"}}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "2")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(0);

    let envelope: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(envelope["modelUsed"], "backup-model");
    let requests = server.received_requests().await.unwrap();
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        models,
        vec!["primary-model", "primary-model", "backup-model"]
    );
}

#[test]
fn empty_response_retry_connection_failure_stops_without_a_third_request() {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 16_384];
        let _ = stream.read(&mut request).unwrap();
        let body = r#"{"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":0}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "model:\n  name: primary-model\n  cascade: []\n",
    )
    .unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", format!("http://{address}"))
        .env("REVIEW_MODEL", "primary-model")
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "5")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .args(["--output", "json"])
        .assert()
        .code(1);
    server.join().unwrap();

    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("model=primary-model attempt=2/3"),
        "unexpected log: {stderr}"
    );
    assert!(!stderr.contains("model=primary-model attempt=3/3"));
    assert!(!stderr.contains("127.0.0.1"));
}

#[tokio::test]
async fn timeout_http_status_retries_same_model_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(408).set_body_string("request timed out"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "5")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let envelope: Value =
        serde_json::from_slice(&out.get_output().stdout).expect("review output should be JSON");
    assert_eq!(envelope["modelUsed"], "primary-model");
    assert_eq!(envelope["usageAccountingComplete"], false);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("returned timeout HTTP 408 Request Timeout"));
    assert!(stderr.contains("timeout retry 1/1"));

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| { request.body_json::<Value>().unwrap()["model"] == "primary-model" })
    );
}

#[tokio::test]
async fn exhausted_timeout_retry_falls_back_to_next_model() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(llm_content(json!([]))),
        )
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
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "1")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "10")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let envelope: Value =
        serde_json::from_slice(&out.get_output().stdout).expect("review output should be JSON");
    assert_eq!(envelope["modelUsed"], "backup-model");

    let requests = server.received_requests().await.unwrap();
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        models,
        vec!["primary-model", "primary-model", "backup-model"]
    );
}

#[tokio::test]
async fn mixed_failures_share_the_existing_two_retry_cap() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(llm_content(json!([]))),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream still down"))
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
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "1")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "15")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(0);
    let envelope: Value =
        serde_json::from_slice(&out.get_output().stdout).expect("review output should be JSON");
    assert_eq!(envelope["modelUsed"], "backup-model");

    let requests = server.received_requests().await.unwrap();
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        models,
        vec![
            "primary-model",
            "primary-model",
            "primary-model",
            "backup-model"
        ]
    );
}

#[tokio::test]
async fn total_llm_timeout_caps_the_cascade() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1500))
                .set_body_json(llm_content(json!([]))),
        )
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
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "5")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "1")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/provider");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let model = requests[0].body_json::<Value>().unwrap()["model"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(model, "primary-model");
}

#[tokio::test]
async fn shared_total_budget_can_expire_during_cascade_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("primary-model"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_delay(std::time::Duration::from_millis(400))
                .set_body_string("bad request"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(wiremock::matchers::body_string_contains("backup-model"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(2200))
                .set_body_json(llm_content(json!([]))),
        )
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let diff = write_diff(dir.path());
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("POSTIL_LLM_REQUEST_TIMEOUT_SECS", "5")
        .env("POSTIL_LLM_TOTAL_TIMEOUT_SECS", "2")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .args(["review", "--diff-file"])
        .arg(&diff)
        .arg("--output-json")
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/provider");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let models = requests
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["model"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(models, vec!["primary-model", "backup-model"]);
}

#[tokio::test]
async fn forge_post_failure_on_success_path_keeps_gate_derived_exit_code() {
    // A completed review (gate failing on a real finding) whose forge comment
    // post then fails (rate limit, transient 5xx) must not discard the
    // already-computed envelope or exit 2: the exit code stays derived from
    // the gate, the envelope is still emitted, and both check runs still
    // complete. Only the review comment itself is lost, and only a stderr
    // warning marks that.
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.92)]))),
        )
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
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
    // The review comment post itself fails, which is the fault this test is pinning.
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/pulls/7/reviews"))
        .respond_with(ResponseTemplate::new(500).set_body_string("secondary rate limit"))
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
        .code(1); // gate-derived exit code, unaffected by the failed post

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let env: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(env["gate"]["failing"], true);
    assert_eq!(env["findings"][0]["path"], "src/auth.rs");

    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("could not post review comment"),
        "expected a warning about the failed post, got: {stderr}"
    );

    // Both check runs still completed despite the review-comment failure.
    let reqs = server.received_requests().await.unwrap();
    let patches = reqs
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PATCH)
        .count();
    assert_eq!(patches, 2);
    let review_posts = reqs
        .iter()
        .filter(|request| {
            request.method == wiremock::http::Method::POST
                && request.url.path() == "/repos/acme/api/pulls/7/reviews"
        })
        .count();
    assert_eq!(
        review_posts, 1,
        "ambiguous review POST must not be replayed"
    );
}

#[tokio::test]
async fn github_unresolved_inline_line_falls_back_once_to_summary_only() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.92)]))),
        )
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
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_string(r#"{"message":"Line could not be resolved"}"#),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/pulls/7/reviews"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .with_priority(2)
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

    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("category=unresolved-line"));
    assert!(stderr.contains("recovery=summary-only"));
    let requests = server.received_requests().await.unwrap();
    let review_bodies = requests
        .iter()
        .filter(|request| {
            request.method == wiremock::http::Method::POST
                && request.url.path() == "/repos/acme/api/pulls/7/reviews"
        })
        .map(|request| request.body_json::<Value>().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(review_bodies.len(), 2);
    assert!(review_bodies[0].get("comments").is_some());
    assert!(review_bodies[1].get("comments").is_none());
}

#[tokio::test]
async fn hosted_path_completes_provided_check_run_ids_without_creating_new_ones() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
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
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
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
            "aaaaaaaa",
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
    mount_github_complete_diff(&server, 7).await;
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
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
        .env(
            "POSTIL_DETAILS_URL",
            "https://postil.dev/orgs/acme/runs/review-7",
        )
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["headSha"], "aaaaaaaaaaaa");
    assert_eq!(env["baseSha"], "bbbbbbbb");

    let reqs = server.received_requests().await.unwrap();
    // Two check-run creations.
    let creates: Vec<_> = reqs
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST && r.url.path() == "/repos/acme/api/check-runs"
        })
        .collect();
    assert_eq!(creates.len(), 2);
    assert!(creates.iter().all(|request| {
        request.body_json::<Value>().unwrap()["details_url"]
            == "https://postil.dev/orgs/acme/runs/review-7"
    }));
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
    assert!(
        patches
            .iter()
            .all(|patch| { patch["details_url"] == "https://postil.dev/orgs/acme/runs/review-7" })
    );
    let conclusions: Vec<&str> = patches
        .iter()
        .map(|p| p["conclusion"].as_str().unwrap())
        .collect();
    assert!(conclusions.contains(&"success"));
    assert!(conclusions.contains(&"failure"));
    let gate_patch = patches
        .iter()
        .find(|patch| patch["conclusion"] == "failure")
        .unwrap();
    assert_eq!(gate_patch["output"]["title"], "Merge gate failed");
    assert_eq!(
        gate_patch["output"]["summary"],
        "Merge gate failed: 1 finding blocks under the configured policy (failOn: error).\n\n- `src/auth.rs:41` Unsanitized input reaches query\n"
    );
    // Inline review posted with the finding at the cited line.
    let review = reqs
        .iter()
        .find(|r| r.url.path() == "/repos/acme/api/pulls/7/reviews")
        .expect("review posted");
    let body: Value = review.body_json().unwrap();
    assert_eq!(body["comments"][0]["path"], "src/auth.rs");
    assert_eq!(body["comments"][0]["line"], 41);
    let summary = body["body"].as_str().unwrap();
    assert!(summary.starts_with(&format!(
        "{} **1 blocking finding**\n",
        postil_cli::forge::icon_md("error")
    )));
    assert!(!summary.contains("Unsanitized input reaches query"));
    assert!(!summary.contains("`src/auth.rs:41`"));
    assert!(!summary.contains("Review metadata"));
    assert!(!summary.contains("headsha"));
    assert!(!summary.contains("Tokens"));
    assert!(
        summary.contains("<sub>[Review details](https://postil.dev/orgs/acme/runs/review-7)</sub>")
    );
}

#[tokio::test]
async fn github_push_after_acquisition_suppresses_all_stale_publication() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.95)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(GitHubHeadRaceResponder {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 11})))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/pulls/7/reviews"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "publication skipped because the pull request head changed",
        ));
}

// An LLM response with a caller-provided summary and findings (used for
// content-policy scenarios where the finding is not the standard auth one).
fn llm_with_summary(summary: &str, findings: Value) -> Value {
    json!({
        "choices": [{"message": {"content": json!({
            "summary": summary,
            "findings": findings
        }).to_string()}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50}
    })
}

// Shared GitHub remote setup for the content-policy PR-description tests. The PR
// body carries prose the model flags; content policy is active by default.
async fn content_policy_pr_server(llm: Value) -> MockServer {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm))
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
            "title": "Add login",
            "body": "This file is untracked and was written by Claude.",
            "head": {"sha": "aaaaaaaaaaaa"}, "base": {"sha": "bbbbbbbbbbbb"}, "changed_files": 1
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
async fn content_policy_pr_body_finding_survives_grounding() {
    // A content-policy finding against the PR description grounds on the reserved
    // `.postil/pr-description` path instead of being dropped as ungrounded (which
    // would have spuriously fail-closed a run whose only finding was here).
    let cp_finding = json!([{
        "path": ".postil/pr-description", "line": 1, "severity": "warn",
        "kind": "contentPolicy", "confidence": 0.9,
        "title": "AI-authorship residue in PR description",
        "body": "Rule 3: the description contains model-authorship residue."
    }]);
    let server = content_policy_pr_server(llm_with_summary(
        "PR description contains model-authorship residue.",
        cp_finding,
    ))
    .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7", "--output-json"])
        .assert()
        .code(0); // warn severity: kept, but gate passes at default failOn=error
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    // The finding survived grounding: it is NOT a fail-closed model-output error.
    assert_eq!(env["findings"][0]["path"], ".postil/pr-description");
    assert_eq!(env["findings"][0]["kind"], "contentPolicy");
    assert_eq!(env["counts"]["ungrounded"], 0);
    assert_eq!(env["gate"]["failing"], false);

    // The model was shown the numbered PR-description block.
    let reqs = server.received_requests().await.unwrap();
    let llm = reqs
        .iter()
        .find(|r| r.url.path() == "/chat/completions")
        .unwrap();
    let sent: Value = llm.body_json().unwrap();
    let user_msg = sent["messages"][1]["content"].as_str().unwrap();
    assert!(user_msg.contains(".postil/pr-description"));
    assert!(user_msg.contains("     1   Add login"));

    // The reserved-path finding has no real line, so its bounded detail appears
    // in the PR summary instead of an inline comment.
    let review = reqs
        .iter()
        .find(|r| r.url.path() == "/repos/acme/api/pulls/7/reviews")
        .expect("review posted");
    let body: Value = review.body_json().unwrap();
    assert_eq!(
        body["comments"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "reserved-path finding was posted as an inline comment"
    );
    let summary = body["body"].as_str().unwrap();
    assert!(summary.contains(&format!(
        "{} **1 advisory finding**",
        postil_cli::forge::icon_md("info")
    )));
    assert!(summary.contains("AI-authorship residue in PR description"));
    assert!(summary.contains("in pull request description"));
    assert!(summary.contains("Rule 3: the description contains model-authorship residue."));
}

#[tokio::test]
async fn content_policy_clean_run_does_not_fail_close() {
    // With default content policy and no violations, the run stays clean: the numbered
    // PR-description block must not induce a spurious ungrounded/fail-closed run.
    let server = content_policy_pr_server(llm_with_summary("", json!([]))).await;

    let dir = tempfile::tempdir().unwrap();
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
    assert_eq!(env["silent"], true);
    assert_eq!(env["gate"]["failing"], false);
    assert_eq!(
        env["findings"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "a clean content-policy run produced a spurious finding"
    );
}

#[tokio::test]
async fn github_clean_pr_stays_silent_but_completes_checks() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
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
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
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
    let check_requests: Vec<Value> = reqs
        .iter()
        .filter(|request| {
            request.url.path().starts_with("/repos/acme/api/check-runs")
                && matches!(
                    request.method,
                    wiremock::http::Method::POST | wiremock::http::Method::PATCH
                )
        })
        .map(|request| request.body_json().unwrap())
        .collect();
    assert!(
        check_requests
            .iter()
            .all(|request| request.get("details_url").is_none())
    );
    let gate_patch = &check_requests[3];
    assert_eq!(gate_patch["output"]["title"], "Merge gate passed");
    assert_eq!(
        gate_patch["output"]["summary"],
        "Merge gate passed: no findings block under the configured policy (failOn: error).\n"
    );

    // The explicit onClean mode uses the same unified summary as finding-bearing
    // reviews instead of falling back to the former one-line clean message.
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/pulls/7/reviews"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    std::fs::write(
        dir.path().join(".postil.yaml"),
        "review:\n  onClean: comment\n",
    )
    .unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env(
            "POSTIL_DETAILS_URL",
            "https://postil.dev/orgs/acme/runs/clean-7",
        )
        .args(["review", "--repo", "acme/api", "--pr", "7"])
        .assert()
        .code(0);
    let reqs = server.received_requests().await.unwrap();
    let clean_review = reqs
        .iter()
        .rev()
        .find(|request| request.url.path().ends_with("/reviews"))
        .expect("onClean review posted");
    let clean_body: Value = clean_review.body_json().unwrap();
    let clean_summary = clean_body["body"].as_str().unwrap();
    assert!(clean_summary.starts_with("Postil reviewed this change"));
    assert!(clean_summary.contains("Postil reviewed this change and found nothing"));
    assert!(!clean_summary.contains("Review metadata"));
    assert!(
        clean_summary
            .contains("<sub>[Review details](https://postil.dev/orgs/acme/runs/clean-7)</sub>")
    );
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
async fn same_head_with_open_baseline_falls_back_to_full_review() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(2)
        .mount(&server)
        .await;

    let baseline = json!({
        "version": 1, "summary": "", "silent": false,
        "findings": [
            {"path": ".postil/change-metadata", "line": 1, "severity": "error", "kind": "risk",
             "confidence": 0.9, "title": "old dependency risk", "body": "fixed now"}
        ],
        "resolved": [], "counts": {"info": 0, "warn": 0, "error": 1, "suppressed": 0},
        "confidenceBuckets": [0,0,0,0,1],
        "gate": {"failOn": "error", "failing": true},
        "modelUsed": "m", "usage": {"promptTokens": 0, "completionTokens": 0},
        "baseSha": "bbbbbbbb", "headSha": "aaaaaaaa", "sinceSha": null
    });
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(&baseline_path, baseline.to_string()).unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7"])
        .args(["--sha", "aaaaaaaa", "--since-sha", "aaaaaaaa", "--baseline"])
        .arg(&baseline_path)
        .args([
            "--check-run-id",
            "11",
            "--gate-check-run-id",
            "12",
            "--output-json",
        ])
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["resolved"][0]["title"], "old dependency risk");
    assert_eq!(env["findings"], json!([]));
    assert_ne!(env["modelUsed"], "none (empty diff)");
    assert_eq!(env["gate"]["failing"], false);

    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .any(|request| { request.url.path() == "/repos/acme/api/compare/bbbbbbbb...aaaaaaaa" })
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().ends_with("/reviews"))
    );
    let llm_request = requests
        .iter()
        .find(|request| request.url.path() == "/chat/completions")
        .unwrap();
    let body: Value = llm_request.body_json().unwrap();
    assert!(
        !body["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("This is an INCREMENTAL review")
    );
}

#[tokio::test]
async fn same_head_without_open_baseline_keeps_empty_diff_noop() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/compare/bbbbbbbb...aaaaaaaa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "bbbbbbbb"},
            "files": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
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
            "aaaaaaaa",
            "--since-sha",
            "aaaaaaaa",
            "--no-post",
            "--output-json",
        ])
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["modelUsed"], "none (empty diff)");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "empty no-op fetched more than the immutable PR snapshot"
    );
}

#[tokio::test]
async fn carried_only_incremental_run_updates_checks_without_posting_review() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/compare/cccccccc...aaaaaaaa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "cccccccc"},
            "files": [{"filename": "src/auth.rs", "status": "modified", "changes": 2}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

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
        "baseSha": "bbbbbbbb", "headSha": "cccccccc", "sinceSha": null
    });
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(&baseline_path, baseline.to_string()).unwrap();

    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7"])
        .args(["--sha", "aaaaaaaa", "--since-sha", "cccccccc", "--baseline"])
        .arg(&baseline_path)
        .args([
            "--check-run-id",
            "11",
            "--gate-check-run-id",
            "12",
            "--output-json",
        ])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert!(
        env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .starts_with("[carried from previous review]")
    );
    assert_eq!(env["gate"]["failing"], true);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == wiremock::http::Method::PATCH)
            .count(),
        2
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().ends_with("/reviews"))
    );
}

#[tokio::test]
async fn identical_fresh_finding_set_does_not_post_duplicate_review() {
    let server = MockServer::start().await;
    mount_github_complete_diff(&server, 7).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(llm_content(json!([finding_at(41, "error", 0.95)]))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/compare/cccccccc...aaaaaaaa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "merge_base_commit": {"sha": "cccccccc"},
            "files": [{"filename": "src/auth.rs", "status": "modified", "changes": 2}]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/pulls/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "t", "body": null,
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/repos/acme/api/check-runs/\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let baseline = json!({
        "version": 1, "summary": "", "silent": false,
        "findings": [{
            "path": "src/auth.rs", "line": 41, "severity": "error", "kind": "risk",
            "confidence": 0.95, "title": "Unsanitized input reaches query",
            "body": "user_input flows into exec_query without sanitization."
        }],
        "resolved": [], "counts": {"info": 0, "warn": 0, "error": 1, "suppressed": 0},
        "confidenceBuckets": [0,0,0,0,1],
        "gate": {"failOn": "error", "failing": true},
        "modelUsed": "m", "usage": {"promptTokens": 0, "completionTokens": 0},
        "baseSha": "bbbbbbbb", "headSha": "cccccccc", "sinceSha": null
    });
    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.json");
    std::fs::write(&baseline_path, baseline.to_string()).unwrap();

    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .args(["review", "--repo", "acme/api", "--pr", "7"])
        .args(["--sha", "aaaaaaaa", "--since-sha", "cccccccc", "--baseline"])
        .arg(&baseline_path)
        .args([
            "--check-run-id",
            "11",
            "--gate-check-run-id",
            "12",
            "--output-json",
        ])
        .assert()
        .code(1);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == wiremock::http::Method::PATCH)
            .count(),
        2
    );
    assert!(
        !requests
            .iter()
            .any(|request| request.url.path().ends_with("/reviews"))
    );
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
    mount_bitbucket_complete_diff(&server).await;
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
            "source": {"commit": {"hash": "aaaaaaaa"}},
            "destination": {"commit": {"hash": "bbbbbbbb"}}
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
    assert_eq!(env["headSha"], "aaaaaaaa");

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
async fn bitbucket_incremental_is_disabled_without_verification_gate() {
    let server = MockServer::start().await;
    mount_bitbucket_merge_base(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "summary": {"raw": "PR body"},
            "source": {"commit": {"hash": "aaaaaaaa"}},
            "destination": {"commit": {"hash": "bbbbbbbb"}}
        })))
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
            "--sha",
            "aaaaaaaa",
            "--since-sha",
            "cccccccc",
            "--no-post",
            "--output-json",
        ])
        .assert()
        .code(1);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["findings"][0]["path"], ".postil/model-output");
    assert!(
        !env["findings"][0]["body"]
            .as_str()
            .unwrap()
            .contains("POSTIL_ENABLE_BITBUCKET_INCREMENTAL")
    );

    let reqs = server.received_requests().await.unwrap();
    assert!(
        !reqs
            .iter()
            .any(|request| request.url.path().contains("/diff/"))
    );
}

#[tokio::test]
async fn bitbucket_incremental_fetches_documented_compare_when_enabled() {
    let server = MockServer::start().await;
    mount_bitbucket_complete_diff(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(llm_content(json!([]))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "summary": {"raw": "PR body"},
            "source": {"commit": {"hash": "aaaaaaaa"}},
            "destination": {"commit": {"hash": "bbbbbbbb"}}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/diffstat/aaaaaaaa..cccccccc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{
                "status": "modified",
                "old": {"path": "src/auth.rs"},
                "new": {"path": "src/auth.rs"}
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("BITBUCKET_API_URL", server.uri())
        .env("BITBUCKET_TOKEN", "bb-test-token")
        .env("POSTIL_ENABLE_BITBUCKET_INCREMENTAL", "1")
        .env("REVIEW_MODEL", "test-model")
        .env_remove("BITBUCKET_USER")
        .args([
            "review",
            "--forge",
            "bitbucket",
            "--repo",
            "acme/api",
            "--pr",
            "7",
            "--sha",
            "aaaaaaaa",
            "--since-sha",
            "cccccccc",
            "--no-post",
            "--output-json",
        ])
        .assert()
        .code(0);
    let env: Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(env["sinceSha"], "cccccccc");
    assert_eq!(env["modelUsed"], "test-model");

    let reqs = server.received_requests().await.unwrap();
    let llm_request = reqs
        .iter()
        .find(|request| request.url.path() == "/chat/completions")
        .unwrap();
    let body: Value = llm_request.body_json().unwrap();
    assert!(
        body["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("This is an INCREMENTAL review")
    );
}

#[tokio::test]
async fn azure_flow_reconstructs_diff_and_posts_thread() {
    let server = MockServer::start().await;
    mount_azure_merge_base(&server).await;
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
            "changes": [{"item": {"path": "/src/auth.rs", "isFolder": false}, "changeType": "edit"}],
            "allChangesIncluded": true
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
    mount_github_complete_diff(&server, 5).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "Line 41 interpolates `user_input` straight into the query; that is the \
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
            "head": {"sha": "aaaaaaaa"}, "base": {"sha": "bbbbbbbb"}, "changed_files": 1
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
    assert!(!text.contains("Postil ·"));
}

#[tokio::test]
async fn respond_rejects_article_shape_and_preserves_usage_across_fallback() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    let slop = respond_article_slop();
    assert_eq!(slop.chars().count(), 7_186);
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("article-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": slop}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 900}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("compact-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": respond_payload(
                "`src/queue.rs:18` retries forever. Add a terminal state before merge.",
                None,
            )}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 15}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Queue retry", "body": "Review the retry behavior."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("respond-usage.json");
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "article-model")
        .env("REVIEW_MODEL_CASCADE", "compact-model")
        .env("POSTIL_USAGE_RECEIPT_PATH", &receipt_path)
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "9",
            "--comment",
            "@postil review this",
            "--no-post",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("Add a terminal state"));
    assert!(!stdout.contains("What this PR does"));
    assert!(!stdout.contains("Postil ·"));
    let receipt: Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["promptTokens"], 50);
    assert_eq!(receipt["completionTokens"], 915);
    assert_eq!(receipt["models"][0]["model"], "article-model");
    assert_eq!(receipt["models"][1]["model"], "compact-model");
    assert_eq!(
        std::fs::metadata(&receipt_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
    );
}

#[tokio::test]
async fn respond_rejects_generated_mermaid_even_when_requested() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("diagram-model"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(llm_text(&respond_payload(
                "The request is queued before a worker handles it.",
                Some("flowchart LR\n  API --> Queue\n  Queue --> Worker"),
            ))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("compact-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "The API writes the job to the queue before a worker claims it.",
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Queue flow", "body": "How does work reach a worker?"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "diagram-model")
        .env("REVIEW_MODEL_CASCADE", "compact-model")
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "10",
            "--comment",
            "@postil please include a Mermaid diagram of this flow",
            "--no-post",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("worker claims it"));
    assert!(!stdout.contains("```mermaid"));
    assert!(!stdout.contains("API --> Queue"));
}

#[tokio::test]
async fn respond_rejects_unrequested_mermaid_and_uses_compact_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("diagram-model"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(llm_text(&respond_payload(
                "The request enters a queue.",
                Some("flowchart LR\n  API --> Queue"),
            ))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("compact-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "The API writes the job to the queue before a worker claims it.",
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/11"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Queue flow", "body": "Explain the worker handoff."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "diagram-model")
        .env("REVIEW_MODEL_CASCADE", "compact-model")
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "11",
            "--comment",
            "@postil explain the worker handoff",
            "--no-post",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("worker claims it"));
    assert!(!stdout.contains("```mermaid"));
}

#[tokio::test]
async fn respond_rejects_unsafe_reply_before_direct_forge_posting() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("unsafe-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "Ask @maintainer to approve this.\n\n## Verdict\nLooks good.",
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("compact-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "`src/queue.rs:18` can retry forever. Add a terminal state before merge.",
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/12"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Queue retry", "body": "Review the retry behavior."
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/api/issues/12/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "unsafe-model")
        .env("REVIEW_MODEL_CASCADE", "compact-model")
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "12",
            "--comment",
            "@postil review the retry behavior",
        ])
        .assert()
        .success();

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|request| request.url.path() == "/repos/acme/api/issues/12/comments")
        .expect("validated fallback posted");
    let body: Value = post.body_json().unwrap();
    let reply = body["body"].as_str().unwrap();
    assert!(reply.contains("Add a terminal state"));
    assert!(!reply.contains("@maintainer"));
    assert!(!reply.contains("Verdict"));
}

#[tokio::test]
async fn respond_writes_private_usage_receipt_across_model_fallback() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2}
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": respond_payload("Use a bounded worker pool.", None)}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 3, "cost": 0.00000049}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Timeouts", "body": "Requests hang under load."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("respond-usage.json");
    std::fs::write(
        &receipt_path,
        b"stale receipt from an interrupted attempt\n",
    )
    .unwrap();
    let out = postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .env("POSTIL_USAGE_RECEIPT_PATH", &receipt_path)
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "9",
            "--comment",
            "@postil how should this be bounded?",
            "--no-post",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("Use a bounded worker pool."));
    assert!(!stdout.contains("promptTokens"));
    let receipt: Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["version"], 2);
    assert_eq!(receipt["models"][0]["role"], "mentionResponder");
    assert_eq!(receipt["models"][0]["phase"], "initial");
    assert!(receipt["models"][0]["callOrdinal"].is_number());
    assert!(receipt["models"][0]["attempt"].is_number());
    assert!(receipt["models"][0]["accountingComplete"].is_boolean());
    assert_eq!(receipt["operation"], "respond");
    assert_eq!(receipt["usageAccountingComplete"], true);
    assert_eq!(receipt["promptTokens"], 40);
    assert_eq!(receipt["completionTokens"], 7);
    assert_eq!(receipt["models"][0]["model"], "primary-model");
    assert_eq!(receipt["models"][0]["promptTokens"], 10);
    assert_eq!(receipt["models"][0]["completionTokens"], 2);
    assert_eq!(receipt["models"][1]["model"], "primary-model");
    assert_eq!(receipt["models"][1]["promptTokens"], 10);
    assert_eq!(receipt["models"][1]["completionTokens"], 2);
    assert_eq!(receipt["models"][2]["model"], "backup-model");
    assert_eq!(receipt["models"][2]["promptTokens"], 20);
    assert_eq!(receipt["models"][2]["completionTokens"], 3);
    assert_eq!(receipt["models"][2]["costProviderDecimal"], "0.00000049");
    assert_eq!(receipt["models"][2]["costMicros"], 0);
    assert_eq!(receipt["models"][2]["costSource"], "providerReported");
    assert_eq!(
        std::fs::metadata(&receipt_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
    );
}

#[tokio::test]
async fn respond_marks_receipt_incomplete_after_ambiguous_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("backup-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": respond_payload("Retry with a bounded backoff.", None)}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 3}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Retries", "body": "Requests fail intermittently."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("respond-usage.json");
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "backup-model")
        .env("POSTIL_USAGE_RECEIPT_PATH", &receipt_path)
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "10",
            "--comment",
            "@postil how should this retry?",
            "--no-post",
        ])
        .assert()
        .success();

    let receipt: Value = serde_json::from_slice(&std::fs::read(receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["usageAccountingComplete"], false);
    assert_eq!(receipt["models"].as_array().unwrap().len(), 4);
    assert_eq!(receipt["models"][3]["model"], "backup-model");
}

#[tokio::test]
async fn respond_marks_receipt_incomplete_after_internal_retry_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(408).set_body_string("request timed out"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_string_contains("primary-model"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": respond_payload("Use a bounded retry.", None)}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 3}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/issues/11"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Retries", "body": "Requests fail intermittently."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("respond-usage.json");
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_TOKEN", "gh-test-token")
        .env("REVIEW_MODEL", "primary-model")
        .env("REVIEW_MODEL_CASCADE", "")
        .env("POSTIL_USAGE_RECEIPT_PATH", &receipt_path)
        .args([
            "respond",
            "--repo",
            "acme/api",
            "--issue",
            "11",
            "--comment",
            "@postil how should this retry?",
            "--no-post",
        ])
        .assert()
        .success();

    let receipt: Value = serde_json::from_slice(&std::fs::read(receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["usageAccountingComplete"], false);
    assert_eq!(receipt["models"].as_array().unwrap().len(), 2);
    assert_eq!(receipt["models"][0]["model"], "primary-model");
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| { request.url.path() == "/chat/completions" })
            .count(),
        2
    );
}

#[tokio::test]
async fn respond_to_issue_mention_uses_issue_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
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
    mount_gitlab_source_files(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "Line 41 interpolates `user_input` into the query; parameterize it.",
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
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/5/versions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "state": "collected", "real_size": "1"
        }])))
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
        .env("GITLAB_TOKEN", fixture_credential("gitlab"))
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
    assert!(!text.contains("Postil ·"));
}

#[tokio::test]
async fn gitlab_diff_pagination_follows_authoritative_next_page_to_exhaustion() {
    let server = MockServer::start().await;
    mount_gitlab_source_files(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "The late-page change is included in the review context.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/6$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Paginated change",
            "description": "",
            "diff_refs": {"base_sha": "b", "start_sha": "s", "head_sha": "h"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/6/versions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "state": "collected", "real_size": "101"
        }])))
        .mount(&server)
        .await;
    let first_page: Vec<Value> = (0..100)
        .map(|index| {
            json!({
                "old_path": format!("src/early_{index}.rs"),
                "new_path": format!("src/early_{index}.rs"),
                "diff": "@@ -0,0 +1 @@\n+let early = true;\n",
                "new_file": false,
                "deleted_file": false,
                "collapsed": false,
                "too_large": false
            })
        })
        .collect();
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/6/diffs$"))
        .and(query_param("per_page", "100"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "2")
                .set_body_json(first_page),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/projects/.+/merge_requests/6/diffs$"))
        .and(query_param("per_page", "100"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "old_path": "src/late.rs",
            "new_path": "src/late.rs",
            "diff": "@@ -0,0 +1 @@\n+let AUTHORITATIVE_LAST_PAGE = true;\n",
            "new_file": false,
            "deleted_file": false,
            "collapsed": false,
            "too_large": false
        }])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/projects/.+/merge_requests/6/notes$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    postil()
        .current_dir(dir.path())
        .env("POSTIL_API_BASE", server.uri())
        .env("GITLAB_API_URL", server.uri())
        .env("GITLAB_TOKEN", fixture_credential("gitlab"))
        .args([
            "respond",
            "--forge",
            "gitlab",
            "--repo",
            "acme/api",
            "--pr",
            "6",
            "--comment",
            "@postil review this",
        ])
        .assert()
        .success();
    let requests = server.received_requests().await.unwrap();
    let model = requests
        .iter()
        .find(|request| request.url.path() == "/chat/completions")
        .unwrap();
    let body: Value = model.body_json().unwrap();
    let model_context = body["messages"][1]["content"].as_str().unwrap();
    assert!(
        model_context.contains("AUTHORITATIVE_LAST_PAGE"),
        "final paginated evidence missing from bounded context: {model_context}"
    );
}

#[tokio::test]
async fn respond_gitlab_issue_mention_uses_issue_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
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
        .env("GITLAB_TOKEN", fixture_credential("gitlab"))
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
    mount_bitbucket_complete_diff(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "Line 41 interpolates `user_input`; that is the injection risk.",
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repositories/acme/api/pullrequests/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Add login",
            "summary": {"raw": "PR body"},
            "source": {"commit": {"hash": "aaaaaaaa"}},
            "destination": {"commit": {"hash": "bbbbbbbb"}}
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
    assert!(!text.contains("Postil ·"));
}

#[tokio::test]
async fn respond_azure_pr_mention_posts_thread() {
    let server = MockServer::start().await;
    mount_azure_merge_base(&server).await;
    let old_content = "fn login() {\n    let token = sanitize(user_input);\n}\n";
    let new_content = "fn login() {\n    let token = user_input;\n}\n";
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(respond_text(
            "Line 2 drops the sanitize() call; that is the risk.",
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
            "changes": [{"item": {"path": "/src/auth.rs", "isFolder": false}, "changeType": "edit"}],
            "allChangesIncluded": true
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
    assert!(!text.contains("Postil ·"));
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
    assert!(stdout.contains("contentPolicy: active"));
}

#[test]
fn qualification_metadata_cli_emits_service_authority_fields() {
    let output = Command::cargo_bin("postil")
        .unwrap()
        .args(["qualification-metadata"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let metadata: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(metadata["qualificationIssuedAtUnixSeconds"], Value::Null);
    assert_eq!(metadata["qualificationExpiresAtUnixSeconds"], Value::Null);
    assert_eq!(metadata["qualificationMaxAgeDays"], Value::Null);
    assert!(metadata["admittedProfile"].is_null());
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
