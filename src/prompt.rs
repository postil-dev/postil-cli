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
         info = material context the merger needs. A correctness bug that silently loses \
         or corrupts data, or makes a function return wrong results, is error — not warn — \
         even when it is not a security issue; do not flinch on confident correctness \
         findings. Reserve warn for genuinely conditional problems (impact depends on \
         callers or context). Kind: risk = concrete defect; humanEscalation = needs an \
         accountable human decision; guardrail = violates a stated repo rule; uncertainty \
         = you cannot verify something critical from the diff.\n\
         \n\
         Confidence is your honest probability the finding is real and merge-relevant. \
         Do not inflate it; low-confidence findings are suppressed and that is correct.\n\
         \n\
         Every finding body MUST end with a concrete next step the author can act on \
         without further questions: the fix, or the exact thing to check (which callers, \
         which command, which test). Never end a finding by telling the reader that 'a \
         human must decide' without saying what to inspect to decide. State impact \
         precisely; do not overstate (e.g. a TypeScript-only return-type change is a \
         compile-time concern for callers that use the value, not a runtime break).\n\
         \n\
         For exposed secrets/credentials: flag at error regardless of whether the values \
         look like real or placeholder keys, and the body must say to (1) rotate the \
         credential, (2) purge it from git history (the commit is permanent otherwise), \
         and (3) move it to an environment variable or secrets store.\n\
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
    if let Some(rules) = &cfg.guardrails {
        // Guardrails are repo-specific merge rules. A violation is reportable
        // even when it is not a generic bug, and must name the rule it breaks.
        p.push_str(
            "\nThis repository defines guardrails below. A change that violates one IS \
             merge-relevant: report it with kind \"guardrail\" and quote the specific \
             rule it breaks in the body. Do not invent rules beyond these.\n\
             --- REPO GUARDRAILS ---\n",
        );
        let rules: String = rules.chars().take(4000).collect();
        p.push_str(&rules);
        p.push_str("\n--- END GUARDRAILS ---\n");
    }
    p.push_str(&format!("\nTone for finding bodies: {}.\n", cfg.tone));
    p.push_str(
        "\nRespond with ONLY a JSON object, no markdown fences, no prose:\n\
         {\"summary\": \"1-3 sentences on merge-relevant risk, or empty string if none\",\n \
          \"findings\": [{\"path\": \"file path from the diff\", \"line\": <new-file line>,\n \
          \"endLine\": <optional>, \"severity\": \"info|warn|error\",\n \
          \"kind\": \"risk|humanEscalation|guardrail|uncertainty\", \"confidence\": <0..1>,\n \
          \"title\": \"short imperative title\", \"body\": \"specific, evidence-based markdown\"}]}\n\
         \n\
         The summary and findings must agree. Every risk the summary mentions MUST appear as \
         a structured finding with its diff line; if findings is empty, summary MUST be the \
         empty string. A summary that narrates problems alongside an empty findings array is \
         invalid output and will fail the review.\n",
    );
    p
}

/// System prompt for the interactive bot answering a maintainer's mention.
/// Free-form prose (not the review JSON contract), but the same noise discipline.
pub fn respond_system_prompt(cfg: &Config) -> String {
    let mut p = String::from(
        "You are Postil, replying to a maintainer who mentioned you on a pull request or \
         issue. Answer their actual question directly and concisely in GitHub-flavored \
         markdown. Ground every claim in the diff or thread you are given; cite file:line \
         when you reference code. If they ask you to re-review, point to specific lines and \
         the merge risk. If something cannot be determined from what you were given, say so \
         plainly rather than guessing. No filler, no praise, no restating the question. You \
         do not open pull requests or push commits; if asked to, explain that you review and \
         answer only.",
    );
    if let Some(rules) = &cfg.guardrails {
        p.push_str("\n\nRepository guardrails you may reference:\n");
        let rules: String = rules.chars().take(2000).collect();
        p.push_str(&rules);
    }
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
    fn system_prompt_injects_guardrails() {
        let mut cfg = Config::default();
        cfg.guardrails = Some("All HTTP handlers must validate the tenant id.".to_string());
        let p = system_prompt(&cfg);
        assert!(p.contains("REPO GUARDRAILS"));
        assert!(p.contains("validate the tenant id"));
        assert!(p.contains("kind \"guardrail\""));
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
