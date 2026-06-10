//! Thin OpenRouter client. JSON-mode chat completions, model cascade, one-shot
//! JSON-repair retry on invalid envelope. No streaming — we want the whole
//! response before parsing.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::envelope::{Envelope, EnvelopeParseError, Usage, parse_envelope};

const HTTP_REFERER: &str = "https://postil.dev";
const X_TITLE: &str = "Postil";

pub struct OpenRouter {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct CompletionRequest<'a> {
    pub model: &'a str,
    pub system_prompt: &'a str,
    pub user_prompt: &'a str,
}

#[derive(Debug)]
pub struct CompletionResult {
    pub envelope: Envelope,
    pub model_used: String,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    temperature: f32,
    response_format: ResponseFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ResponseFormat {
    JsonObject,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<UsagePayload>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

#[derive(Deserialize, Default)]
struct UsagePayload {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    total_tokens: u64,
}

impl OpenRouter {
    pub fn new(base_url: impl Into<String>, api_key: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {api_key}"))
                .context("openrouter api key contains invalid characters")?,
        );
        headers.insert("HTTP-Referer", HeaderValue::from_static(HTTP_REFERER));
        headers.insert("X-Title", HeaderValue::from_static(X_TITLE));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(180))
            .build()
            .context("building OpenRouter HTTP client")?;

        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    /// Try the primary model, then each cascade entry in order. Each model
    /// gets a single JSON-repair retry on invalid envelope before we move on
    /// to the next one. If everything fails, the caller is expected to
    /// synthesize a fail-closed envelope.
    pub async fn review(
        &self,
        primary: &str,
        cascade: &[String],
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<CompletionResult, ReviewError> {
        let mut models = Vec::with_capacity(1 + cascade.len());
        models.push(primary.to_string());
        for m in cascade {
            if !models.iter().any(|x| x == m) {
                models.push(m.clone());
            }
        }

        let mut last_err: Option<ReviewError> = None;

        for model in &models {
            debug!(model = %model, "review attempt");
            match self
                .try_one_with_repair(model, system_prompt, user_prompt)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(model = %model, error = %e, "model attempt failed");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(ReviewError::AllModelsFailed("no models configured".into())))
    }

    async fn try_one_with_repair(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<CompletionResult, ReviewError> {
        let first = self.call(model, system_prompt, user_prompt, None).await?;
        match parse_envelope(&first.content) {
            Ok(mut env) => {
                env.usage = first.usage.clone();
                env.model_used = Some(model.to_string());
                Ok(CompletionResult {
                    envelope: env,
                    model_used: model.to_string(),
                })
            }
            Err(EnvelopeParseError::InvalidJson(detail)) => {
                let repaired = self
                    .call(model, system_prompt, user_prompt, Some(&first.content))
                    .await?;
                let mut env = parse_envelope(&repaired.content).map_err(|e| {
                    ReviewError::InvalidEnvelope(format!(
                        "repair failed: {e} (first error: {detail})"
                    ))
                })?;
                env.usage = Usage {
                    prompt_tokens: first.usage.prompt_tokens + repaired.usage.prompt_tokens,
                    completion_tokens: first.usage.completion_tokens
                        + repaired.usage.completion_tokens,
                    total_tokens: first.usage.total_tokens + repaired.usage.total_tokens,
                };
                env.model_used = Some(model.to_string());
                Ok(CompletionResult {
                    envelope: env,
                    model_used: model.to_string(),
                })
            }
            Err(other) => Err(ReviewError::InvalidEnvelope(other.to_string())),
        }
    }

    async fn call(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        repair_target: Option<&str>,
    ) -> Result<RawCompletion, ReviewError> {
        let user_msg_owned;
        let user_content: &str = if let Some(bad) = repair_target {
            user_msg_owned = format!(
                "The previous response was not valid JSON. Return ONLY the JSON envelope object now, with no prose and no code fences. Reconstruct the same intended findings if possible. Previous response:\n\n{bad}"
            );
            &user_msg_owned
        } else {
            user_prompt
        };

        let req = ChatRequest {
            model,
            messages: vec![
                Message {
                    role: "system",
                    content: system_prompt,
                },
                Message {
                    role: "user",
                    content: user_content,
                },
            ],
            temperature: 0.0,
            response_format: ResponseFormat::JsonObject,
            max_tokens: Some(2048),
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| ReviewError::Transport(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ReviewError::ProviderStatus(status.as_u16(), body));
        }

        let body: ChatResponse = resp
            .json()
            .await
            .map_err(|e| ReviewError::Transport(e.to_string()))?;
        let content = body
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| ReviewError::InvalidEnvelope("provider returned no content".into()))?;
        let usage = body
            .usage
            .map(|u| Usage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            })
            .unwrap_or_default();
        Ok(RawCompletion { content, usage })
    }
}

struct RawCompletion {
    content: String,
    usage: Usage,
}

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("provider returned HTTP {0}: {1}")]
    ProviderStatus(u16, String),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("all configured models failed: {0}")]
    AllModelsFailed(String),
}
