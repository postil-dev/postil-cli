//! Interactive bot: reply to an @postil mention on a PR or issue.
//!
//! Scope is review and answer only — Postil never opens PRs or pushes commits.
//! Works across every forge the reviewer supports. PR/MR mentions are grounded
//! on the diff; issue mentions on the issue body. GitHub and GitLab cover both
//! issues and pulls; Bitbucket and Azure DevOps are scoped to PRs (their issue
//! trackers / work items use endpoints we cannot verify against a live host).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::diff;
use crate::forge::{
    Forge, ThreadKind, azure::Azure, bitbucket::Bitbucket, github::GitHub, gitlab::GitLab,
};
use crate::llm::{Answer, LlmClient};
use crate::prompt;
use crate::review::ForgeKind;

pub struct RespondArgs {
    pub forge: ForgeKind,
    pub repo: Option<String>,
    /// The PR number, when the mention is on a pull request.
    pub pr: Option<u64>,
    /// The issue number, when the mention is on an issue.
    pub issue: Option<u64>,
    /// The maintainer's comment text (the mention). When None, read from the
    /// POSTIL_COMMENT environment variable — the safe path for automation.
    pub comment: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    /// Print the answer instead of posting it.
    pub no_post: bool,
}

const MAX_DIFF_BYTES: usize = 200_000;
const USAGE_RECEIPT_PATH_ENV: &str = "POSTIL_USAGE_RECEIPT_PATH";
const RESPOND_MAX_CHARS: usize = 2_400;
const RESPOND_MAX_NONBLANK_LINES: usize = 24;
const RESPOND_MAX_HEADINGS: usize = 2;
const RESPOND_MAX_LIST_ITEMS: usize = 5;
const MERMAID_MAX_CHARS: usize = 1_200;
const MERMAID_MAX_NONBLANK_LINES: usize = 16;
const REPORT_HEADINGS: [&str; 4] = [
    "what this pr does",
    "correctness",
    "issues and risks",
    "verdict",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RespondOutput {
    answer: String,
    diagram: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespondUsageReceipt<'a> {
    version: u32,
    operation: &'static str,
    prompt_tokens: u64,
    completion_tokens: u64,
    models: Vec<RespondModelUsage<'a>>,
    usage_accounting_complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespondModelUsage<'a> {
    model: &'a str,
    prompt_tokens: u64,
    completion_tokens: u64,
}

// PID separates concurrent processes; this sequence separates writers within
// one process. create_new below also fails closed if a path already exists.
static RECEIPT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct UsageReceiptWriter {
    file: Option<File>,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl UsageReceiptWriter {
    fn from_env() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os(USAGE_RECEIPT_PATH_ENV) else {
            return Ok(None);
        };
        anyhow::ensure!(
            !path.is_empty(),
            "{USAGE_RECEIPT_PATH_ENV} must not be empty"
        );
        let final_path = PathBuf::from(path);
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = final_path
            .file_name()
            .ok_or_else(|| anyhow!("{USAGE_RECEIPT_PATH_ENV} must name a file"))?
            .to_string_lossy();
        let sequence = RECEIPT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            // Usage receipts contain private provider-accounting metadata.
            .mode(0o600)
            .open(&temp_path)
            .context("creating private usage receipt temporary file")?;
        Ok(Some(Self {
            file: Some(file),
            temp_path,
            final_path,
        }))
    }

    fn commit(mut self, answer: &Answer) -> Result<()> {
        let receipt = RespondUsageReceipt {
            version: 1,
            operation: "respond",
            prompt_tokens: answer.usage.prompt_tokens,
            completion_tokens: answer.usage.completion_tokens,
            models: answer
                .models
                .iter()
                .map(|model| RespondModelUsage {
                    model: &model.model,
                    prompt_tokens: model.prompt_tokens,
                    completion_tokens: model.completion_tokens,
                })
                .collect(),
            usage_accounting_complete: answer.usage_accounting_complete,
        };
        let file = self.file.as_mut().expect("usage receipt file is present");
        serde_json::to_writer(&mut *file, &receipt).context("serializing usage receipt")?;
        file.write_all(b"\n").context("writing usage receipt")?;
        // Publish only after file contents are durable. The directory sync
        // below makes the rename durable before stdout or forge delivery.
        file.sync_all().context("syncing usage receipt")?;
        drop(self.file.take());
        std::fs::rename(&self.temp_path, &self.final_path)
            .context("atomically publishing usage receipt")?;
        if let Some(parent) = self.final_path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("syncing usage receipt directory")?;
        }
        Ok(())
    }
}

impl Drop for UsageReceiptWriter {
    fn drop(&mut self) {
        // Drop cannot return cleanup errors. Best-effort removal is safe: an
        // unpublished temp file is never treated as a committed receipt, and
        // create_new prevents a later writer from clobbering it.
        let _ = std::fs::remove_file(&self.temp_path);
    }
}

pub async fn run(args: RespondArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let mut cfg = Config::load(&cwd, args.config.as_deref())?;
    if let Some(m) = &args.model {
        cfg.model = m.clone();
    }
    let repo = args
        .repo
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .ok_or_else(|| anyhow!("--repo is required"))?;
    let comment = args
        .comment
        .clone()
        .or_else(|| std::env::var("POSTIL_COMMENT").ok())
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| anyhow!("the mention text is required: --comment or POSTIL_COMMENT"))?;
    let usage_receipt = UsageReceiptWriter::from_env()?;

    // The number the mention is on, and whether it is a PR/MR or an issue.
    let (number, kind) = match (args.pr, args.issue) {
        (Some(pr), _) => (pr, ThreadKind::Pull),
        (None, Some(issue)) => (issue, ThreadKind::Issue),
        (None, None) => return Err(anyhow!("one of --pr or --issue is required")),
    };

    // Same flow for every forge; the trait carries the per-host endpoints. The
    // forge is monomorphized (the trait uses `async fn` and is not dyn-safe), so
    // dispatch by kind here, exactly as the reviewer does.
    match args.forge {
        ForgeKind::GitHub => {
            respond_with(
                GitHub::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::GitLab => {
            respond_with(
                GitLab::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Bitbucket => {
            respond_with(
                Bitbucket::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Azure => {
            respond_with(
                Azure::new(&repo, number)?,
                &cfg,
                &repo,
                number,
                kind,
                &comment,
                args.no_post,
                usage_receipt,
            )
            .await
        }
        ForgeKind::Local => Err(anyhow!("postil respond needs a remote forge, not --local")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn respond_with<F: Forge>(
    forge: F,
    cfg: &Config,
    repo: &str,
    number: u64,
    kind: ThreadKind,
    comment: &str,
    no_post: bool,
    usage_receipt: Option<UsageReceiptWriter>,
) -> Result<i32> {
    let context = build_context(&forge, repo, number, kind).await?;

    let system = prompt::respond_system_prompt(cfg);
    let user = format!(
        "{context}\n--- Maintainer's message to you ---\n{}\n\nReply to the message above.",
        comment.trim()
    );
    let client = LlmClient::from_env(cfg)?;
    let diagram_requested = explicitly_requests_diagram(comment);
    let answer = client
        .answer(cfg, &system, &user, |raw| {
            validate_respond_output(raw, diagram_requested)
        })
        .await?;
    let reply = answer.content.clone();

    // Hosted execution requires the durable usage receipt before any external
    // delivery. Commit it before stdout or forge posting so the control plane
    // can reconcile spend and own idempotent delivery.
    if let Some(writer) = usage_receipt {
        writer.commit(&answer)?;
    }
    if no_post {
        println!("{reply}");
    } else {
        forge
            .post_comment(number, kind, &reply)
            .await
            .context("posting reply")?;
        eprintln!("postil: replied on {repo}#{number}");
    }
    Ok(0)
}

fn validate_respond_output(raw: &str, diagram_requested: bool) -> Result<String> {
    if raw.chars().count() > RESPOND_MAX_CHARS {
        return Err(anyhow!(
            "reply exceeds the 2,400-character publication limit"
        ));
    }
    if nonblank_line_count(raw) > RESPOND_MAX_NONBLANK_LINES {
        return Err(anyhow!(
            "reply exceeds the {RESPOND_MAX_NONBLANK_LINES}-line publication limit"
        ));
    }

    let output: RespondOutput = serde_json::from_str(raw.trim())
        .context("reply must be the exact {answer, diagram} JSON object")?;
    let answer = normalize_newlines(output.answer.trim());
    if answer.is_empty() {
        return Err(anyhow!("reply answer is empty"));
    }
    validate_answer_publication(&answer)?;
    let lower_answer = answer.to_ascii_lowercase();
    if lower_answer.contains("```mermaid")
        || lower_answer.contains("~~~mermaid")
        || answer
            .lines()
            .any(|line| is_mermaid_declaration(line.trim()))
    {
        return Err(anyhow!("Mermaid must use the diagram field"));
    }
    let headings = markdown_heading_count(&answer);
    if headings > RESPOND_MAX_HEADINGS {
        return Err(anyhow!(
            "reply contains {headings} headings; at most {RESPOND_MAX_HEADINGS} are allowed"
        ));
    }
    let list_items = markdown_list_item_count(&answer);
    if list_items > RESPOND_MAX_LIST_ITEMS {
        return Err(anyhow!(
            "reply contains {list_items} list items; at most {RESPOND_MAX_LIST_ITEMS} are allowed"
        ));
    }

    let rendered = match output.diagram {
        None => answer,
        Some(diagram) => {
            if !diagram_requested {
                return Err(anyhow!("reply contains an unrequested Mermaid diagram"));
            }
            let diagram = normalize_newlines(diagram.trim());
            if diagram.is_empty() {
                return Err(anyhow!("reply diagram is empty"));
            }
            validate_mermaid_source(&diagram)?;
            format!("{answer}\n\n```mermaid\n{diagram}\n```")
        }
    };

    if rendered.chars().count() > RESPOND_MAX_CHARS {
        return Err(anyhow!(
            "rendered reply exceeds the 2,400-character publication limit"
        ));
    }
    if nonblank_line_count(&rendered) > RESPOND_MAX_NONBLANK_LINES {
        return Err(anyhow!(
            "rendered reply exceeds the {RESPOND_MAX_NONBLANK_LINES}-line publication limit"
        ));
    }
    Ok(rendered)
}

fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn validate_answer_publication(answer: &str) -> Result<()> {
    if contains_active_mention(answer) {
        return Err(anyhow!("reply contains an active mention"));
    }
    if contains_raw_html(answer) {
        return Err(anyhow!("reply contains raw HTML"));
    }
    if contains_markdown_image(answer) {
        return Err(anyhow!("reply contains a Markdown image"));
    }
    if contains_markdown_table(answer) {
        return Err(anyhow!("reply contains a Markdown table"));
    }
    if markdown_heading_names(answer)
        .iter()
        .any(|heading| REPORT_HEADINGS.contains(&heading.as_str()))
    {
        return Err(anyhow!("reply contains a report-shaped heading"));
    }
    Ok(())
}

fn contains_active_mention(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    for (index, ch) in chars.iter().enumerate() {
        if *ch != '@'
            || index
                .checked_sub(1)
                .and_then(|previous| chars.get(previous))
                .is_some_and(|previous| {
                    previous.is_ascii_alphanumeric() || matches!(previous, '_' | '-')
                })
        {
            continue;
        }
        let mut cursor = index + 1;
        let mut name_len = 0;
        while chars
            .get(cursor)
            .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '-')
            && name_len < 39
        {
            cursor += 1;
            name_len += 1;
        }
        if name_len > 0
            && chars.get(cursor).is_none_or(|boundary| {
                !boundary.is_ascii_alphanumeric() && !matches!(boundary, '_' | '-')
            })
        {
            return true;
        }
    }
    false
}

fn contains_raw_html(text: &str) -> bool {
    if text.contains("<!--") {
        return true;
    }
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'<' {
            continue;
        }
        let mut cursor = index + 1;
        if bytes.get(cursor) == Some(&b'/') {
            cursor += 1;
        }
        if bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic)
            && bytes[cursor + 1..].contains(&b'>')
        {
            return true;
        }
    }
    false
}

fn contains_markdown_image(text: &str) -> bool {
    let mut remaining = text;
    while let Some(start) = remaining.find("![") {
        remaining = &remaining[start + 2..];
        let Some(close_label) = remaining.find(']') else {
            return false;
        };
        if remaining[close_label + 1..].trim_start().starts_with('(') {
            return true;
        }
        remaining = &remaining[close_label + 1..];
    }
    false
}

fn contains_markdown_table(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    lines
        .windows(2)
        .any(|pair| pair[0].contains('|') && markdown_table_delimiter(pair[1].trim()))
}

fn markdown_table_delimiter(line: &str) -> bool {
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_suffix('|').unwrap_or(line);
    let cells: Vec<&str> = line.split('|').collect();
    cells.len() >= 2
        && cells.iter().all(|cell| {
            let cell = cell.trim();
            let cell = cell.strip_prefix(':').unwrap_or(cell);
            let cell = cell.strip_suffix(':').unwrap_or(cell);
            cell.len() >= 3 && cell.chars().all(|ch| ch == '-')
        })
}

fn markdown_heading_names(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut names = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
        if (1..=6).contains(&hashes) && trimmed.chars().nth(hashes).is_some_and(char::is_whitespace)
        {
            names.push(normalize_heading_name(&trimmed[hashes..]));
        } else if index > 0
            && !lines[index - 1].trim().is_empty()
            && !trimmed.is_empty()
            && (trimmed.chars().all(|ch| ch == '=') || trimmed.chars().all(|ch| ch == '-'))
        {
            names.push(normalize_heading_name(lines[index - 1].trim()));
        }
    }
    names
}

fn normalize_heading_name(heading: &str) -> String {
    heading
        .trim()
        .trim_end_matches('#')
        .trim()
        .trim_end_matches([':', '.', '!', '?'])
        .to_ascii_lowercase()
}

fn nonblank_line_count(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

fn markdown_heading_count(text: &str) -> usize {
    let mut in_fence = false;
    let mut count = 0;
    let mut previous_was_text = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            previous_was_text = false;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
        let atx_heading = (1..=6).contains(&hashes)
            && trimmed.chars().nth(hashes).is_some_and(char::is_whitespace);
        let setext_heading = previous_was_text
            && !trimmed.is_empty()
            && (trimmed.chars().all(|ch| ch == '=') || trimmed.chars().all(|ch| ch == '-'));
        if atx_heading || setext_heading {
            count += 1;
        }
        previous_was_text = !trimmed.is_empty();
    }
    count
}

fn markdown_list_item_count(text: &str) -> usize {
    let mut in_fence = false;
    let mut count = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let bullet = ["- ", "* ", "+ "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));
        let ordered = trimmed.split_once(". ").is_some_and(|(prefix, _)| {
            !prefix.is_empty() && prefix.chars().all(|ch| ch.is_ascii_digit())
        });
        if bullet || ordered {
            count += 1;
        }
    }
    count
}

fn explicitly_requests_diagram(comment: &str) -> bool {
    let lower = comment.to_ascii_lowercase();
    let subject = lower.contains("diagram")
        || lower.contains("mermaid")
        || lower.contains("flowchart")
        || lower.contains("sequence chart");
    if !subject
        || [
            "no diagram",
            "without a diagram",
            "don't include a diagram",
            "do not include a diagram",
            "don't add a diagram",
            "do not add a diagram",
        ]
        .iter()
        .any(|phrase| lower.contains(phrase))
    {
        return false;
    }
    [
        "please",
        "can you",
        "could you",
        "would you",
        "include",
        "add",
        "draw",
        "show",
        "make",
        "create",
        "provide",
        "give me",
        "render",
        "visualize",
        "visualise",
        "sketch",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

fn validate_mermaid_source(diagram: &str) -> Result<()> {
    if diagram.chars().count() > MERMAID_MAX_CHARS
        || nonblank_line_count(diagram) > MERMAID_MAX_NONBLANK_LINES
    {
        return Err(anyhow!("reply diagram exceeds its publication limit"));
    }
    if diagram.contains("```") || diagram.contains("~~~") {
        return Err(anyhow!("reply diagram must not contain markdown fences"));
    }
    if contains_active_mention(diagram) {
        return Err(anyhow!("reply diagram contains an active mention"));
    }
    if contains_raw_html(diagram) || contains_markdown_image(diagram) {
        return Err(anyhow!("reply diagram contains HTML or an image"));
    }
    let lower = diagram.to_ascii_lowercase();
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("%%{")
        || contains_disallowed_mermaid_word(&lower)
    {
        return Err(anyhow!("reply diagram contains a disallowed directive"));
    }

    let first = diagram
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .ok_or_else(|| anyhow!("reply diagram is empty"))?;
    let flowchart_parts: Vec<&str> = first.split_whitespace().collect();
    let valid_flowchart = matches!(
        flowchart_parts.as_slice(),
        ["flowchart", "TB" | "TD" | "BT" | "RL" | "LR"]
    );
    let valid_sequence = first == "sequenceDiagram";
    if !valid_flowchart && !valid_sequence {
        return Err(anyhow!(
            "reply diagram must be a directed flowchart or sequenceDiagram"
        ));
    }

    let declaration_count = diagram
        .lines()
        .filter(|line| is_mermaid_declaration(line.trim()))
        .count();
    if declaration_count != 1 {
        return Err(anyhow!(
            "reply diagram must contain exactly one Mermaid declaration"
        ));
    }
    Ok(())
}

fn is_mermaid_declaration(line: &str) -> bool {
    let declaration = line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    [
        "flowchart",
        "graph",
        "sequencediagram",
        "statediagram",
        "statediagram-v2",
        "classdiagram",
        "erdiagram",
        "journey",
        "gantt",
        "pie",
        "mindmap",
        "timeline",
        "gitgraph",
        "quadrantchart",
        "xychart-beta",
        "block-beta",
        "packet-beta",
        "architecture-beta",
        "kanban",
        "sankey-beta",
    ]
    .contains(&declaration.as_str())
}

fn contains_disallowed_mermaid_word(lower: &str) -> bool {
    lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|word| {
            matches!(
                word,
                "click" | "href" | "classdef" | "linkstyle" | "style" | "init"
            )
        })
}

/// Build the grounding context for the model: a PR/MR mention gets the annotated
/// diff, an issue mention gets the issue body.
async fn build_context<F: Forge>(
    forge: &F,
    repo: &str,
    number: u64,
    kind: ThreadKind,
) -> Result<String> {
    match kind {
        ThreadKind::Pull => {
            let meta = forge.fetch_pr_meta().await?;
            let raw = forge.fetch_diff().await.context("fetching PR diff")?;
            let parsed = diff::parse(&raw);
            let (annotated, truncated) = diff::render_annotated(&parsed, MAX_DIFF_BYTES);
            let mut ctx = format!(
                "Context: pull request #{number} in {repo}\nTitle: {}\n",
                meta.title
            );
            if !meta.body.trim().is_empty() {
                let body: String = meta.body.chars().take(1500).collect();
                ctx.push_str(&format!("Description:\n{body}\n"));
            }
            ctx.push_str("\nDiff (left-margin numbers are new-file lines):\n\n");
            ctx.push_str(&annotated);
            if truncated {
                ctx.push_str("\n[diff truncated at the size limit]\n");
            }
            Ok(ctx)
        }
        ThreadKind::Issue => {
            let (title, body) = forge.fetch_thread(number, kind).await?;
            let body: String = body.chars().take(4000).collect();
            Ok(format!(
                "Context: issue #{number} in {repo}\nTitle: {title}\n\nIssue body:\n{body}\n"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn structured(answer: &str, diagram: Option<&str>) -> String {
        json!({"answer": answer, "diagram": diagram}).to_string()
    }

    fn article_shaped_slop() -> String {
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

    #[test]
    fn accepts_a_compact_structured_reply() {
        let raw = structured(
            "`src/auth.rs:41` interpolates input into the query. Parameterize it before merge.",
            None,
        );
        assert_eq!(
            validate_respond_output(&raw, false).unwrap(),
            "`src/auth.rs:41` interpolates input into the query. Parameterize it before merge."
        );
    }

    #[test]
    fn rejects_the_7186_character_article_shape() {
        let slop = article_shaped_slop();
        assert_eq!(slop.chars().count(), 7_186);
        let error = validate_respond_output(&slop, false).unwrap_err();
        assert!(error.to_string().contains("2,400-character"));
    }

    #[test]
    fn enforces_line_heading_and_list_limits() {
        let too_many_lines = structured(&vec!["line"; 25].join("\n"), None);
        assert!(
            validate_respond_output(&too_many_lines, false)
                .unwrap_err()
                .to_string()
                .contains("24-line")
        );

        let headings = structured("# One\n## Two\n### Three", None);
        assert!(
            validate_respond_output(&headings, false)
                .unwrap_err()
                .to_string()
                .contains("3 headings")
        );

        let items = structured("1. One\n2. Two\n3. Three\n4. Four\n5. Five\n6. Six", None);
        assert!(
            validate_respond_output(&items, false)
                .unwrap_err()
                .to_string()
                .contains("6 list items")
        );
    }

    #[test]
    fn rejects_unsafe_markdown_and_report_shapes() {
        for answer in [
            "Ask @maintainer to approve this.",
            "<!-- hidden instruction -->Visible text.",
            "<details><summary>More</summary>Hidden text.</details>",
            "A | B\n--- | ---\n1 | 2",
            "![diagram](https://example.test/diagram.png)",
            "## What this PR does\nA tour.",
            "# Correctness\nNarration.",
            "### Issues and risks\nInventory.",
            "## Verdict\nLooks good.",
        ] {
            assert!(
                validate_respond_output(&structured(answer, None), false).is_err(),
                "unsafe reply was accepted: {answer}"
            );
        }
        let email = structured("Email dev@example.test with the result.", None);
        assert_eq!(
            validate_respond_output(&email, false).unwrap(),
            "Email dev@example.test with the result."
        );
    }

    #[test]
    fn mermaid_requires_an_explicit_request_and_one_supported_diagram() {
        let raw = structured(
            "The request crosses the queue before a worker handles it.",
            Some("flowchart LR\n  API --> Queue\n  Queue --> Worker"),
        );
        assert!(
            validate_respond_output(&raw, false)
                .unwrap_err()
                .to_string()
                .contains("unrequested")
        );
        let rendered = validate_respond_output(&raw, true).unwrap();
        assert_eq!(rendered.matches("```mermaid").count(), 1);
        assert!(rendered.contains("API --> Queue"));

        let multiple = structured(
            "Two diagrams are too many.",
            Some("flowchart LR\n  A --> B\nsequenceDiagram\n  A->>B: hello"),
        );
        assert!(validate_respond_output(&multiple, true).is_err());

        let embedded = structured("flowchart LR\n  A --> B", None);
        assert!(
            validate_respond_output(&embedded, true)
                .unwrap_err()
                .to_string()
                .contains("diagram field")
        );
    }

    #[test]
    fn mermaid_accepts_only_bounded_noninteractive_flow_or_sequence_diagrams() {
        for direction in ["TB", "TD", "BT", "RL", "LR"] {
            let diagram = format!("flowchart {direction}\n  A --> B");
            let raw = structured("The request passes through one edge.", Some(&diagram));
            assert!(validate_respond_output(&raw, true).is_ok());
        }
        let sequence = structured(
            "The caller sends one request.",
            Some("sequenceDiagram\n  Caller->>API: Request"),
        );
        assert!(validate_respond_output(&sequence, true).is_ok());

        let seventeen_lines = format!(
            "flowchart TD\n{}",
            (0..16)
                .map(|index| format!("  A{index} --> A{}", index + 1))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let oversized = format!("flowchart TD\n  A[{}] --> B", "x".repeat(1_200));
        for diagram in [
            "flowchart ZZ\n  A --> B".to_string(),
            "graph TD\n  A --> B".to_string(),
            "classDiagram\n  class A".to_string(),
            "flowchart TD\n  A --> B\n  click A https://example.test".to_string(),
            "flowchart TD\n  classDef danger fill:red".to_string(),
            "flowchart TD\n  linkStyle 0 stroke:red".to_string(),
            "flowchart TD\n  style A fill:red".to_string(),
            "%%{init: {}}%%\nflowchart TD\n  A --> B".to_string(),
            "flowchart TD\n  A[<b>unsafe</b>] --> B".to_string(),
            "```mermaid\nflowchart TD\n  A --> B\n```".to_string(),
            seventeen_lines,
            oversized,
        ] {
            let raw = structured("A diagram was requested.", Some(&diagram));
            assert!(
                validate_respond_output(&raw, true).is_err(),
                "unsafe diagram was accepted: {diagram}"
            );
        }
    }

    #[test]
    fn diagram_request_detection_is_explicit_and_respects_negation() {
        assert!(explicitly_requests_diagram(
            "@postil please include a Mermaid diagram of the queue flow"
        ));
        assert!(!explicitly_requests_diagram(
            "@postil review this change without a diagram"
        ));
        assert!(!explicitly_requests_diagram(
            "@postil is the current review correct?"
        ));
    }
}
