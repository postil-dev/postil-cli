use postil_cli::{
    config::RepoReviewConfig,
    openrouter::OpenRouterClient,
    review::{TokenUsage, parse_envelope, system_prompt},
};

#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY and makes a live provider request"]
async fn live_openrouter_smoke() {
    let key = std::env::var("OPENROUTER_API_KEY").expect("OPENROUTER_API_KEY must be set");
    let model = std::env::var("REVIEW_MODEL").unwrap_or_else(|_| "deepseek/deepseek-v4-pro".into());
    let client = OpenRouterClient::new("https://openrouter.ai/api/v1".into(), key).unwrap();
    let result = client
        .complete(
            &model,
            &system_prompt(&RepoReviewConfig::default()),
            "Diff:\n\ndiff --git a/src/lib.rs b/src/lib.rs\n+pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .await
        .unwrap();
    let envelope = parse_envelope(
        &result.content,
        TokenUsage::default(),
        result.model_used.clone(),
    );
    assert_eq!(result.model_used, model);
    assert!(
        envelope
            .findings
            .iter()
            .all(|finding| finding.path != ".postil/model-output")
    );
}
