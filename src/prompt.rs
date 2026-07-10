//! Prompt construction. The system prompt is the noise policy.

use crate::config::{BUILTIN_CONTENT_POLICY, Config};

pub struct PrContext<'a> {
    pub repo: Option<&'a str>,
    pub title: Option<&'a str>,
    pub body: Option<&'a str>,
    pub incremental: bool,
    /// When true, the PR title/description are also rendered as a numbered,
    /// groundable block (under the reserved content-policy path) so title/body
    /// content-policy findings survive grounding.
    pub content_policy: bool,
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
    // Keep the response contract ahead of every repository-specific section.
    // Implicit prompt caches match byte-identical prefixes, so global review
    // instructions and the built-in policy baseline must precede focus,
    // guardrails, policy additions, and tone.
    p.push_str(
        "\nRespond with ONLY a JSON object, no markdown fences, no prose or reasoning:\n\
         {\"summary\": \"empty when clean; otherwise one sentence of at most 40 words\",\n \
          \"findings\": [{\"path\": \"file path from the diff\", \"line\": <new-file line>,\n \
          \"endLine\": <optional>, \"severity\": \"info|warn|error\",\n \
          \"kind\": \"risk|humanEscalation|guardrail|uncertainty|contentPolicy\", \"confidence\": <0..1>,\n \
          \"title\": \"imperative title of at most 12 words\", \"body\": \"one concise paragraph of at most 60 words\"}]}\n\
         \n\
         Each body must state the evidence, impact, and concrete next step without \
         restating the diff or these rules. The summary and findings must agree. Every \
         risk the summary mentions MUST appear as a structured finding with its diff \
         line; if findings is empty, summary MUST be the empty string. A summary that \
         narrates problems alongside an empty findings array is invalid output and will \
         fail the review.\n",
    );

    // Config loading keeps the built-in policy at the start and appends optional
    // repository rules. Split them after applying the existing aggregate cap so
    // the stable baseline remains cacheable across repositories while the exact
    // effective policy text stays unchanged.
    let content_policy: Option<String> = cfg
        .content_policy
        .as_deref()
        .map(|policy| policy.chars().take(6000).collect());
    let (builtin_policy, repo_policy) = match content_policy.as_deref() {
        Some(policy) => match policy.strip_prefix(BUILTIN_CONTENT_POLICY) {
            Some(additions) => (Some(BUILTIN_CONTENT_POLICY), additions.trim()),
            None => (None, policy.trim()),
        },
        None => (None, ""),
    };
    if content_policy.is_some() {
        p.push_str(
            "\nThis repository has content-policy review enabled. Apply the numbered rules \
             below ONLY to human-readable prose in the diff (Markdown, code comments, \
             docstrings, user-facing/log strings, PR title/description) — never to code \
             logic, identifiers, or structured data. Report a violation with kind \
             \"contentPolicy\", name the rule number it breaks, and quote or paraphrase the \
             specific offending text in the body. A violation in the PR title or description \
             MUST cite the path `.postil/pr-description` and one of the numbered lines shown \
             for it; a violation in a diff file cites that file and a new-file line as usual. \
             Be conservative: this augments the rules above, it does not turn you into a style \
             linter; when a line is borderline, do not flag it.\n",
        );
        if let Some(policy) = builtin_policy {
            p.push_str("--- CONTENT POLICY BASELINE ---\n");
            p.push_str(policy);
            p.push_str("\n--- END CONTENT POLICY BASELINE ---\n");
        }
    }

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
    if !repo_policy.is_empty() {
        p.push_str("\n--- REPOSITORY CONTENT POLICY ---\n");
        p.push_str(repo_policy);
        p.push_str("\n--- END REPOSITORY CONTENT POLICY ---\n");
    }
    p.push_str(&format!("\nTone for finding bodies: {}.\n", cfg.tone));
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

/// Render the PR title and description as a numbered block under the reserved
/// content-policy path, mirroring the diff's left-margin line numbering so the
/// model can cite a real, groundable line. Returns the rendered text and the
/// number of numbered lines (0 when there is nothing to render). Line 1 is the
/// title; the body follows on subsequent lines. Used only when content policy is
/// active; the title/body are otherwise passed as unnumbered context.
pub fn render_pr_description(title: Option<&str>, body: Option<&str>) -> (String, u32) {
    let title = title.unwrap_or("").trim();
    // Truncation lives here, not in the callers: the grounding range in
    // review.rs and the prompt block in user_prompt must count the same
    // lines, or the index would accept line numbers the model never saw.
    let body: String = body.unwrap_or("").trim().chars().take(2000).collect();
    let body = body.trim_end();
    if title.is_empty() && body.is_empty() {
        return (String::new(), 0);
    }
    let mut out = format!("### {}\n", crate::envelope::PR_DESCRIPTION_PATH);
    let mut line_no: u32 = 0;
    // Title is always line 1 (even when empty, to keep a stable anchor) only if
    // there is any content at all; here at least one of title/body is non-empty.
    line_no += 1;
    out.push_str(&format!("{line_no:>6}   {title}\n"));
    for line in body.lines() {
        line_no += 1;
        out.push_str(&format!("{line_no:>6}   {line}\n"));
    }
    (out, line_no)
}

pub fn user_prompt(
    ctx: &PrContext,
    annotated_diff: &str,
    max_findings: usize,
    truncated: bool,
) -> String {
    let mut p =
        format!("Report at most {max_findings} findings; if more exist, keep the most severe.\n");
    if ctx.content_policy {
        p.push_str(
            "The PR title and description below are numbered so you can cite them. A \
             content-policy finding about the title/description MUST use the path \
             `.postil/pr-description` and one of those line numbers; findings there \
             cannot cite any other path.\n",
        );
    }
    if ctx.incremental {
        p.push_str(
            "This is an INCREMENTAL review: the diff covers only commits pushed since the \
             previous review. Earlier findings are tracked separately; review only what is \
             shown.\n",
        );
    }
    if truncated {
        p.push_str(
            "The diff is truncated at the size limit. Review only what is shown and do not \
             imply that the omitted remainder was assessed.\n",
        );
    }
    p.push_str("\n--- REVIEW CONTEXT ---\n");
    if let Some(repo) = ctx.repo {
        p.push_str(&format!("Repository: {repo}\n"));
    }
    // When content policy is active and there is a title/body, render the
    // title/description as a numbered, groundable block so the model can cite a
    // real line for a title/body content-policy finding (the reserved path).
    // Otherwise pass them as plain unnumbered context.
    let pr_block = if ctx.content_policy {
        // render_pr_description truncates the body itself, keeping the
        // rendered block in lockstep with the grounding range registered
        // in review.rs.
        let (block, _count) = render_pr_description(ctx.title, ctx.body);
        (!block.is_empty()).then_some(block)
    } else {
        None
    };
    if let Some(block) = &pr_block {
        p.push('\n');
        p.push_str(block);
    } else {
        if let Some(title) = ctx.title {
            p.push_str(&format!("PR title: {title}\n"));
        }
        let truncated_body: Option<String> = ctx
            .body
            .filter(|b| !b.trim().is_empty())
            .map(|b| b.chars().take(2000).collect());
        if let Some(body) = &truncated_body {
            p.push_str(&format!("PR description:\n{body}\n"));
        }
    }
    p.push_str(
        "--- END REVIEW CONTEXT ---\n\nDiff (left margin numbers are new-file line numbers — cite exactly these):\n\n",
    );
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
    fn system_prompt_injects_content_policy_when_active() {
        let mut cfg = Config::default();
        cfg.content_policy = Some("1. Never fabricate a claim.".to_string());
        let p = system_prompt(&cfg);
        assert!(p.contains("CONTENT POLICY"));
        assert!(p.contains("Never fabricate a claim"));
        assert!(p.contains("kind \"contentPolicy\""));
    }

    #[test]
    fn system_prompt_omits_content_policy_when_inactive() {
        let mut cfg = Config::default();
        cfg.content_policy = None;
        let p = system_prompt(&cfg);
        assert!(!p.contains("CONTENT POLICY"));
    }

    #[test]
    fn system_prompt_keeps_global_contract_and_baseline_before_repo_content() {
        let mut cfg = Config::default();
        cfg.focus = vec!["repository-specific focus".into()];
        cfg.guardrails = Some("repository-specific guardrail".into());
        cfg.content_policy = Some(format!(
            "{BUILTIN_CONTENT_POLICY}\n\n--- REPO-SPECIFIC ADDITIONS ---\nrepository-specific policy"
        ));
        cfg.tone = "repository-specific tone".into();

        let p = system_prompt(&cfg);
        let contract = p.find("Respond with ONLY a JSON object").unwrap();
        let baseline = p.find("CONTENT POLICY BASELINE").unwrap();
        for marker in [
            "repository-specific focus",
            "repository-specific guardrail",
            "repository-specific policy",
            "repository-specific tone",
        ] {
            let variable = p.find(marker).unwrap();
            assert!(contract < variable, "contract followed {marker}");
            assert!(baseline < variable, "baseline followed {marker}");
        }
    }

    #[test]
    fn render_pr_description_numbers_title_and_body() {
        let (block, count) = render_pr_description(Some("Fix login"), Some("line one\nline two"));
        assert_eq!(count, 3);
        assert!(block.contains(".postil/pr-description"));
        assert!(block.contains("     1   Fix login"));
        assert!(block.contains("     2   line one"));
        assert!(block.contains("     3   line two"));
        // Empty title and body render nothing groundable.
        let (empty, n) = render_pr_description(Some("  "), Some(""));
        assert!(empty.is_empty());
        assert_eq!(n, 0);
    }

    #[test]
    fn user_prompt_renders_numbered_pr_description_under_content_policy() {
        let ctx = PrContext {
            repo: Some("o/r"),
            title: Some("Add feature"),
            body: Some("Some body text"),
            incremental: false,
            content_policy: true,
        };
        let p = user_prompt(&ctx, "DIFF", 5, false);
        assert!(p.contains(".postil/pr-description"));
        assert!(p.contains("     1   Add feature"));
        assert!(p.contains("MUST use the path `.postil/pr-description`"));
    }

    #[test]
    fn user_prompt_leaves_pr_description_unnumbered_without_content_policy() {
        let ctx = PrContext {
            repo: None,
            title: Some("Add feature"),
            body: Some("Some body text"),
            incremental: false,
            content_policy: false,
        };
        let p = user_prompt(&ctx, "DIFF", 5, false);
        assert!(!p.contains(".postil/pr-description"));
        assert!(p.contains("PR title: Add feature"));
    }

    #[test]
    fn user_prompt_marks_incremental() {
        let ctx = PrContext {
            repo: Some("o/r"),
            title: Some("t"),
            body: None,
            incremental: true,
            content_policy: false,
        };
        let p = user_prompt(&ctx, "DIFF", 5, false);
        assert!(p.contains("INCREMENTAL"));
        assert!(p.contains("at most 5 findings"));
        assert!(p.ends_with("DIFF"));
    }

    #[test]
    fn user_prompt_places_instructions_before_metadata_and_diff_last() {
        let ctx = PrContext {
            repo: Some("variable/repository"),
            title: Some("Variable title"),
            body: Some("Variable body"),
            incremental: false,
            content_policy: true,
        };
        let p = user_prompt(&ctx, "VARIABLE DIFF", 7, true);
        let instructions = p.find("Report at most 7 findings").unwrap();
        let truncation = p.find("diff is truncated").unwrap();
        let metadata = p.find("Repository: variable/repository").unwrap();
        let diff = p.find("VARIABLE DIFF").unwrap();
        assert!(instructions < metadata);
        assert!(truncation < metadata);
        assert!(metadata < diff);
        assert!(p.ends_with("VARIABLE DIFF"));
    }
}
