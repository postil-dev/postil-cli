//! Drive the engine end-to-end against a wiremock OpenRouter server.

use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DIFF: &str = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,3 +1,4 @@
 fn one() {}
-fn two() {}
+fn two_v2() {}
+fn three() {}
 fn four() {}
";

fn write_diff_file() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{DIFF}").unwrap();
    f
}

fn or_response(content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
    })
}

#[tokio::test]
async fn clean_envelope_exits_zero_and_stays_silent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(or_response(r#"{"summary":"","findings":[]}"#)),
        )
        .mount(&server)
        .await;
    let diff = write_diff_file();
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no merge-relevant findings"));
}

#[tokio::test]
async fn finding_envelope_exits_one_on_error_severity() {
    let server = MockServer::start().await;
    let envelope = r#"{"summary":"one risk","findings":[
        {"path":"src/a.rs","line":3,"severity":"error","kind":"risk","body":"null deref on two_v2"}
    ]}"#;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(or_response(envelope)))
        .mount(&server)
        .await;
    let diff = write_diff_file();
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error"))
        .stdout(predicate::str::contains("null deref"));
}

#[tokio::test]
async fn invalid_json_with_failed_repair_fails_closed() {
    let server = MockServer::start().await;
    // Both calls return garbage.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(or_response("not json at all")))
        .mount(&server)
        .await;
    let diff = write_diff_file();
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains(".postil/model-output"));
}

#[tokio::test]
async fn provider_5xx_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&server)
        .await;
    let diff = write_diff_file();
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains(".postil/model-output"));
}

#[tokio::test]
async fn output_json_writes_envelope() {
    let server = MockServer::start().await;
    let envelope = r#"{"summary":"clean","findings":[]}"#;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(or_response(envelope)))
        .mount(&server)
        .await;
    let diff = write_diff_file();
    let out = NamedTempFile::new().unwrap();
    let out_path = out.path().to_path_buf();
    drop(out);
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .arg("--output-json")
        .arg(&out_path)
        .assert()
        .success();
    let body = std::fs::read_to_string(&out_path).unwrap();
    assert!(body.contains("\"findings\""));
    assert!(body.contains("\"cliVersion\""));
    let _ = std::fs::remove_file(&out_path);
}

#[tokio::test]
async fn ungrounded_finding_gets_filtered() {
    let server = MockServer::start().await;
    // Finding cites src/b.rs which isn't in the diff — filter should drop it,
    // and silence kicks in.
    let envelope = r#"{"summary":"x","findings":[
        {"path":"src/b.rs","line":1,"severity":"warn","kind":"risk","body":"phantom"}
    ]}"#;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(or_response(envelope)))
        .mount(&server)
        .await;
    let diff = write_diff_file();
    Command::cargo_bin("postil")
        .unwrap()
        .env("OPENROUTER_API_KEY", "test")
        .env("POSTIL_OPENROUTER_API_URL", server.uri())
        .arg("--diff-file")
        .arg(diff.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("no merge-relevant findings"));
}
