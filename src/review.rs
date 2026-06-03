use anyhow::{Context, Result};
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{RepoReviewConfig, Severity};

const STATUS_ICON_BASE_URL: &str = "https://postil.dev/status";

const BASE_SYSTEM_PROMPT: &str = r#"You are Postil, a low-noise review gate for agent-speed development. You receive a unified diff for a pull request and produce structured findings as JSON.

Product doctrine:
- Silence is a feature. Do not comment to prove that you reviewed the diff.
- Comment only when the finding can affect whether this change should merge.
- A valid finding must identify concrete risk, request a specific fix, block or warn against merge, request accountable human review, explain an intent mismatch, suggest a durable guardrail, or clarify uncertainty that materially affects merge safety.
- Escalate consequential decisions to accountable humans instead of pretending to own product, architecture, security, infrastructure, cost, data deletion, permissions, billing, migrations, persistent storage, external dependency, or major behavior-change tradeoffs.
- When an objective, recurring issue should be enforced outside review, suggest a durable guardrail in the finding body: test, lint rule, CI check, policy, pre-commit hook, or documented convention.

Rules:
- Focus on correctness, security, reliability, intent mismatch, and context-dependent merge risk.
- Do not flag style, formatting, imports, naming, summaries, praise, or preferences unless they create merge-relevant risk.
- Do not include self-dismissing findings. If the body would say there is no concrete risk, that behavior is acceptable, or the code is safe, omit the finding.
- Every finding cites a specific path and line number that exists in the diff.
- Severity is one of: info, warn, error.
- Use error only for concrete issues that should block merge until fixed. If uncertainty remains, use warn or info.
- Use warn for issues that should delay merge until fixed or accepted by a human.
- Use info only for merge-relevant human escalation, durable guardrail suggestions, or material uncertainty.
- If the diff has no merge-relevant findings, return an empty summary string and an empty findings array.
- Return at most 25 findings.
- Keep each finding body under 1200 characters.

Reply with ONLY a single JSON object, no prose, no markdown fence:
{
  "summary": "<empty string when clean; otherwise 1-2 sentences about merge risk only>",
  "findings": [ { "path": "...", "line": <int>, "severity": "info|warn|error", "kind": "risk|humanEscalation|guardrail|uncertainty", "body": "..." } ]
}"#;

pub fn system_prompt(cfg: &RepoReviewConfig) -> String {
    let mut prompt = BASE_SYSTEM_PROMPT.to_string();
    let focus = cfg
        .reviewer
        .focus
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if !focus.is_empty() {
        prompt.push_str("\n\nRepository review focus:\n");
        for item in focus {
            prompt.push_str("- ");
            prompt.push_str(item);
            prompt.push('\n');
        }
    }
    let tone = cfg.reviewer.tone.trim();
    if !tone.is_empty() && tone != "neutral" {
        prompt.push_str("\nReviewer tone preference: ");
        prompt.push_str(tone);
        prompt.push_str(". Keep the result direct and merge-relevant.");
    }
    prompt
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub line: u64,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FindingKind>,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingKind {
    Risk,
    HumanEscalation,
    Guardrail,
    Uncertainty,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewEnvelope {
    pub summary: String,
    pub findings: Vec<Finding>,
    pub usage: TokenUsage,
    pub model_used: String,
}

pub fn parse_envelope(text: &str, usage: TokenUsage, model_used: String) -> ReviewEnvelope {
    let raw = fenced_json(text).unwrap_or(text);
    if let Some(slice) = json_object_slice(raw) {
        if let Ok(value) = serde_json::from_str::<Value>(slice) {
            return parse_value(value, usage, model_used);
        }
    }
    invalid_model_output(
        "Model output was not valid Postil JSON; review must be retried before merge.",
        usage,
        model_used,
    )
}

pub fn is_model_output_error(envelope: &ReviewEnvelope) -> bool {
    envelope
        .findings
        .iter()
        .any(|finding| finding.path == ".postil/model-output")
}

fn parse_value(value: Value, usage: TokenUsage, model_used: String) -> ReviewEnvelope {
    let Some(summary) = value.get("summary").and_then(Value::as_str) else {
        return invalid_model_output(
            "Model output omitted the required summary string; review must be retried before merge.",
            usage,
            model_used,
        );
    };
    let Some(items) = value.get("findings").and_then(Value::as_array) else {
        return invalid_model_output(
            "Model output omitted the required findings array; review must be retried before merge.",
            usage,
            model_used,
        );
    };
    let mut findings = Vec::with_capacity(items.len());
    for item in items {
        let Ok(finding) = serde_json::from_value::<Finding>(item.clone()) else {
            return invalid_model_output(
                "Model output contained an invalid finding; review must be retried before merge.",
                usage,
                model_used,
            );
        };
        findings.push(finding);
    }
    ReviewEnvelope {
        summary: summary.to_string(),
        findings,
        usage,
        model_used,
    }
}

fn invalid_model_output(body: &str, usage: TokenUsage, model_used: String) -> ReviewEnvelope {
    ReviewEnvelope {
        summary: "Postil could not validate the model output.".to_string(),
        findings: vec![Finding {
            path: ".postil/model-output".to_string(),
            line: 1,
            severity: Severity::Error,
            kind: Some(FindingKind::Risk),
            body: body.to_string(),
        }],
        usage,
        model_used,
    }
}

fn fenced_json(text: &str) -> Option<&str> {
    let fence_start = text.find("```")?;
    let after_start = &text[fence_start + 3..];
    let content_start = after_start.find('\n').map(|i| i + 1).unwrap_or(0);
    let content = &after_start[content_start..];
    let fence_end = content.find("```")?;
    Some(content[..fence_end].trim())
}

fn json_object_slice(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(&text[start..=end])
}

pub fn apply_config(
    mut envelope: ReviewEnvelope,
    cfg: &RepoReviewConfig,
) -> Result<ReviewEnvelope> {
    let mut set = GlobSetBuilder::new();
    for glob in &cfg.ignore {
        set.add(Glob::new(glob).with_context(|| format!("invalid ignore glob {glob}"))?);
    }
    let ignore = set.build().context("build ignore glob set")?;
    let mut findings = envelope
        .findings
        .into_iter()
        .filter(|f| f.severity.rank() >= cfg.severity_threshold.rank())
        .filter(|f| f.path == ".postil/model-output" || !ignore.is_match(&f.path))
        .collect::<Vec<_>>();
    if !findings.iter().any(|f| f.path == ".postil/model-output") {
        findings.truncate(cfg.max_findings);
    }
    envelope.findings = findings;
    Ok(envelope)
}

pub fn status_line(envelope: &ReviewEnvelope, _inline_comments: usize, label: &str) -> String {
    let mut errors = 0;
    let mut warnings = 0;
    let mut infos = 0;
    for finding in &envelope.findings {
        match finding.severity {
            Severity::Error => errors += 1,
            Severity::Warn => warnings += 1,
            Severity::Info => infos += 1,
        }
    }
    let mut status = String::new();
    for _ in 0..errors {
        status.push_str(&status_icon("error"));
    }
    for _ in 0..warnings {
        status.push_str(&status_icon("warn"));
    }
    for _ in 0..infos {
        status.push_str(&status_icon("info"));
    }
    if status.is_empty() {
        status.push_str(&status_icon(if label == "clean" { "pass" } else { "warn" }));
    }
    format!("status: {status}")
}

fn status_icon(kind: &str) -> String {
    format!("![{kind}]({STATUS_ICON_BASE_URL}/{kind}.svg)")
}

pub fn append_status(body: &str, status: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        status.to_string()
    } else {
        format!("{trimmed}\n\n{status}")
    }
}

pub fn review_body(envelope: &ReviewEnvelope, inline_comments: usize, label: &str) -> String {
    append_status(
        if envelope.summary.trim().is_empty() && !envelope.findings.is_empty() {
            "Postil found merge-relevant review findings."
        } else {
            envelope.summary.trim()
        },
        &status_line(envelope, inline_comments, label),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fenced_json() {
        let env = parse_envelope(
            "```json\n{\"summary\":\"ok\",\"findings\":[{\"path\":\"src/lib.rs\",\"line\":3,\"severity\":\"warn\",\"kind\":\"humanEscalation\",\"body\":\"bug\"}]}\n```",
            TokenUsage::default(),
            "m".into(),
        );
        assert_eq!(env.summary, "ok");
        assert_eq!(env.findings.len(), 1);
        assert_eq!(env.findings[0].severity, Severity::Warn);
        assert_eq!(env.findings[0].kind, Some(FindingKind::HumanEscalation));
    }

    #[test]
    fn invalid_model_output_fails_closed() {
        let env = parse_envelope("plain output", TokenUsage::default(), "m".into());
        assert_eq!(env.summary, "Postil could not validate the model output.");
        assert_eq!(env.findings.len(), 1);
        assert_eq!(env.findings[0].severity, Severity::Error);
        assert_eq!(env.findings[0].path, ".postil/model-output");
    }

    #[test]
    fn invalid_finding_fails_closed() {
        let env = parse_envelope(
            "{\"summary\":\"s\",\"findings\":[{\"path\":\"src/lib.rs\",\"line\":\"bad\",\"severity\":\"warn\",\"body\":\"risk\"}]}",
            TokenUsage::default(),
            "m".into(),
        );
        assert_eq!(env.findings.len(), 1);
        assert_eq!(env.findings[0].severity, Severity::Error);
    }

    #[test]
    fn filters_findings() {
        let envelope = ReviewEnvelope {
            summary: "s".into(),
            usage: TokenUsage::default(),
            model_used: "m".into(),
            findings: vec![
                Finding {
                    path: "src/a.rs".into(),
                    line: 1,
                    severity: Severity::Info,
                    kind: None,
                    body: "i".into(),
                },
                Finding {
                    path: "dist/a.js".into(),
                    line: 1,
                    severity: Severity::Error,
                    kind: None,
                    body: "e".into(),
                },
                Finding {
                    path: "src/b.rs".into(),
                    line: 1,
                    severity: Severity::Warn,
                    kind: None,
                    body: "w".into(),
                },
            ],
        };
        let cfg = RepoReviewConfig {
            severity_threshold: Severity::Warn,
            ignore: vec!["dist/**".into()],
            ..RepoReviewConfig::default()
        };
        let filtered = apply_config(envelope, &cfg).unwrap();
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].path, "src/b.rs");
    }

    #[test]
    fn model_output_error_survives_ignore_and_max_findings() {
        let envelope = parse_envelope("plain output", TokenUsage::default(), "m".into());
        let cfg = RepoReviewConfig {
            ignore: vec![".postil/**".into()],
            max_findings: 0,
            ..RepoReviewConfig::default()
        };
        let filtered = apply_config(envelope, &cfg).unwrap();
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].path, ".postil/model-output");
    }

    #[test]
    fn prompt_encodes_low_noise_doctrine() {
        let prompt = system_prompt(&RepoReviewConfig::default());
        assert!(prompt.contains("Silence is a feature"));
        assert!(prompt.contains("Comment only when"));
        assert!(prompt.contains("durable guardrail"));
        assert!(prompt.contains("accountable humans"));
        assert!(prompt.contains("self-dismissing findings"));
        assert!(prompt.contains("empty summary string"));
    }

    #[test]
    fn review_body_uses_merge_relevant_fallback_only_for_findings() {
        let clean = ReviewEnvelope {
            summary: String::new(),
            findings: Vec::new(),
            usage: TokenUsage::default(),
            model_used: "m".into(),
        };
        assert_eq!(
            review_body(&clean, 0, "clean"),
            "status: ![pass](https://postil.dev/status/pass.svg)"
        );

        let dirty = ReviewEnvelope {
            summary: String::new(),
            findings: vec![Finding {
                path: "src/lib.rs".into(),
                line: 1,
                severity: Severity::Warn,
                kind: None,
                body: "risk".into(),
            }],
            usage: TokenUsage::default(),
            model_used: "m".into(),
        };
        assert!(review_body(&dirty, 1, "needs-attention").contains("merge-relevant"));
    }
}
