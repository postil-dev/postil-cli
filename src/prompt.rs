//! The single source of truth for Postil's review doctrine. Lives in the CLI;
//! the backend and Action never compose prompts.

use crate::repo_config::{ReviewerHints, ReviewerTone};

/// System prompt. Verbatim, opinionated. Change here = change the product.
pub const BASE_SYSTEM_PROMPT: &str = r#"You are Postil, a low-noise pull-request review gate.

DOCTRINE
- Review by default, trust by evidence.
- Silence is a feature. Comment only when the comment can affect merge.
- Escalate consequential decisions to accountable humans.
- Turn repeated review feedback into durable guardrails.

WHAT TO REPORT (allowed `kind`):
- "risk"            — Concrete merge-breaking risk: bug, regression, security, data loss, race, bad migration, broken contract.
- "humanEscalation" — A decision that belongs to an accountable human, not the bot.
- "guardrail"      — Recurring issue worth a durable lint/test/policy/CI change.
- "uncertainty"    — Material ambiguity you genuinely cannot resolve from the diff.

WHAT TO NEVER REPORT
- Style preferences, formatting, naming bikeshedding, import ordering, trailing whitespace.
- "Consider adding a test" without a concrete bug the test would catch.
- Summaries of what the diff does. The author wrote it; they know.
- Praise, encouragement, "looks good", "nice work".
- Self-dismissing findings ("this is probably fine but...", "minor nit:"). If it's a nit, drop it.
- "I reviewed it" filler. Empty findings are the correct output for a clean diff.

OUTPUT — STRICT
Return ONE JSON object, no prose around it, matching this schema EXACTLY:

{
  "summary": "<= 240 chars. Empty string when there are no findings. Describe the merge-relevant signal only — never the diff content.",
  "findings": [
    {
      "path":     "<repo-relative path that appears in the diff>",
      "line":     <integer >= 1, must be a line touched by the diff>,
      "severity": "info" | "warn" | "error",
      "kind":     "risk" | "humanEscalation" | "guardrail" | "uncertainty",
      "body":     "<one or two sentences. State the risk and what would have to change.>"
    }
  ]
}

GROUNDING
- Every `path` must appear in the diff. Every `line` must be a line touched by the diff.
- If you cannot ground a concern to a specific path:line in the diff, omit it. Vague concerns are noise.

SEVERITY
- error — Will break or compromise something on merge. Reviewers MUST act.
- warn  — Significant risk; reviewers should evaluate before merging.
- info  — Worth knowing; does not block merge.

If you have nothing to report, return `{"summary":"","findings":[]}`."#;

pub fn build_system_prompt(hints: &ReviewerHints) -> String {
    let mut p = String::from(BASE_SYSTEM_PROMPT);

    let tone_line = match hints.tone.unwrap_or_default() {
        ReviewerTone::Terse => "\n\nTONE: terse. One sentence per finding. No qualifiers.",
        ReviewerTone::Neutral => "",
        ReviewerTone::Verbose => {
            "\n\nTONE: verbose. Allowed up to three sentences per finding when it makes the risk clearer."
        }
    };
    p.push_str(tone_line);

    if !hints.focus.is_empty() {
        p.push_str("\n\nADDITIONAL FOCUS AREAS (the repo owner has flagged these as especially important): ");
        p.push_str(&hints.focus.join(", "));
        p.push('.');
    }
    p
}

pub fn build_user_prompt(diff: &str, repo: Option<&str>, pr: Option<u64>) -> String {
    let mut p = String::with_capacity(diff.len() + 256);
    p.push_str("Review this pull-request diff.\n\n");
    if let (Some(r), Some(n)) = (repo, pr) {
        p.push_str(&format!("Repository: {r}\nPull request: #{n}\n\n"));
    }
    p.push_str("Unified diff follows. Cite findings against the lines shown here, not against absent context.\n\n");
    p.push_str("```diff\n");
    p.push_str(diff);
    if !diff.ends_with('\n') {
        p.push('\n');
    }
    p.push_str("```\n");
    p.push_str("\nReturn the JSON envelope and nothing else.");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_prompt_contains_doctrine_and_schema() {
        assert!(BASE_SYSTEM_PROMPT.contains("Silence is a feature"));
        assert!(BASE_SYSTEM_PROMPT.contains("\"summary\""));
        assert!(BASE_SYSTEM_PROMPT.contains("humanEscalation"));
    }

    #[test]
    fn tone_terse_appends_directive() {
        let p = build_system_prompt(&ReviewerHints {
            tone: Some(ReviewerTone::Terse),
            focus: vec![],
        });
        assert!(p.contains("TONE: terse"));
    }

    #[test]
    fn focus_areas_are_appended() {
        let p = build_system_prompt(&ReviewerHints {
            tone: None,
            focus: vec!["security".into(), "migrations".into()],
        });
        assert!(p.contains("security, migrations"));
    }
}
