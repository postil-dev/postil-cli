//! Prompt construction. The system prompt is the noise policy.

use crate::config::Config;

pub struct PrContext<'a> {
    pub repo: Option<&'a str>,
    pub title: Option<&'a str>,
    pub body: Option<&'a str>,
    pub incremental: bool,
}

pub fn system_prompt(cfg: &Config) -> String {
    let mut p = String::from(
        "You are Postil, a merge-gate code reviewer. Your output decides whether a pull \
         request needs human attention before merging. You are not a style checker, a \
         linter, a formatter, or a mentor.\n\
         \n\
         Report a finding ONLY if it could change the merge decision:\n\
         - a bug, logic error, or regression introduced by this diff\n\
         - a security vulnerability or unsafe handling of untrusted input\n\
         - data loss, corruption, or breaking API/contract changes\n\
         - concurrency hazards (races, deadlocks, unguarded shared state)\n\
         - a consequential decision that an accountable human must confirm\n\
         \n\
         NEVER report: style, formatting, naming, missing docs/comments/tests, alternative \
         phrasings, refactor suggestions, performance micro-optimizations, or anything a \
         linter would catch. If the diff is acceptable to merge, return zero findings. \
         Silence is the correct and expected output for most diffs.\n\
         \n\
         Severity: error = merge is unsafe; warn = likely problem, human should look; \
         info = material context the merger needs. Kind: risk = concrete defect; \
         humanEscalation = needs an accountable human decision; guardrail = violates a \
         stated repo rule; uncertainty = you cannot verify something critical from the diff.\n\
         \n\
         Confidence is your honest probability the finding is real and merge-relevant. \
         Do not inflate it; low-confidence findings are suppressed and that is correct.\n\
         \n\
         Cite ONLY line numbers printed in the left margin of the diff (the new-file line \
         numbers). Findings citing other lines are discarded as ungrounded.\n",
    );
    if !cfg.focus.is_empty() {
        p.push_str(&format!(
            "\nThis repository asks for extra attention to: {}.\n",
            cfg.focus.join(", ")
        ));
    }
    p.push_str(&format!("\nTone for finding bodies: {}.\n", cfg.tone));
    p.push_str(
        "\nRespond with ONLY a JSON object, no markdown fences, no prose:\n\
         {\"summary\": \"1-3 sentences on merge-relevant risk, or empty string if none\",\n \
          \"findings\": [{\"path\": \"file path from the diff\", \"line\": <new-file line>,\n \
          \"endLine\": <optional>, \"severity\": \"info|warn|error\",\n \
          \"kind\": \"risk|humanEscalation|guardrail|uncertainty\", \"confidence\": <0..1>,\n \
          \"title\": \"short imperative title\", \"body\": \"specific, evidence-based markdown\"}]}\n",
    );
    p
}

pub fn user_prompt(ctx: &PrContext, annotated_diff: &str, max_findings: usize) -> String {
    let mut p = String::new();
    if let Some(repo) = ctx.repo {
        p.push_str(&format!("Repository: {repo}\n"));
    }
    if let Some(title) = ctx.title {
        p.push_str(&format!("PR title: {title}\n"));
    }
    if let Some(body) = ctx.body
        && !body.trim().is_empty()
    {
        let body: String = body.chars().take(2000).collect();
        p.push_str(&format!("PR description:\n{body}\n"));
    }
    if ctx.incremental {
        p.push_str(
            "\nThis is an INCREMENTAL review: the diff below covers only commits pushed \
             since the previous review. Earlier findings are tracked separately; review \
             only what is shown.\n",
        );
    }
    p.push_str(&format!(
        "\nReport at most {max_findings} findings; if more exist, keep the most severe.\n\
         \nDiff (left margin numbers are new-file line numbers — cite exactly these):\n\n"
    ));
    p.push_str(annotated_diff);
    p
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::config::Config;

    #[test]
    fn system_prompt_carries_focus_and_tone() {
        let mut cfg = Config::default();
        cfg.focus = vec!["security".into(), "concurrency".into()];
        let p = system_prompt(&cfg);
        assert!(p.contains("security, concurrency"));
        assert!(p.contains("Silence is the correct"));
        assert!(p.contains("no praise"));
    }

    #[test]
    fn user_prompt_marks_incremental() {
        let ctx = PrContext {
            repo: Some("o/r"),
            title: Some("t"),
            body: None,
            incremental: true,
        };
        let p = user_prompt(&ctx, "DIFF", 5);
        assert!(p.contains("INCREMENTAL"));
        assert!(p.contains("at most 5 findings"));
        assert!(p.ends_with("DIFF"));
    }
}
