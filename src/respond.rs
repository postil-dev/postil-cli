//! Interactive bot: reply to an @postil mention on a PR or issue.
//!
//! Scope is review and answer only. Postil never opens PRs or pushes commits.
//! Works across every forge the reviewer supports. PR/MR mentions are grounded
//! on the diff; issue mentions on the issue body. GitHub and GitLab cover both
//! issues and pulls; Bitbucket and Azure DevOps are scoped to PRs (their issue
//! trackers / work items use endpoints we cannot verify against a live host).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::diff;
use crate::envelope::{ModelUsageCostSource, ModelUsagePhase, ModelUsageRole};
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
    /// POSTIL_COMMENT environment variable, the safe path for automation.
    pub comment: Option<String>,
    pub config: Option<PathBuf>,
    pub model: Option<String>,
    /// Print the answer instead of posting it.
    pub no_post: bool,
}

// Leave enough transport headroom for JSON escaping, the system prompt, PR
// metadata, and the maintainer message under either supported API shape.
const MAX_RESPOND_DIFF_CONTEXT_BYTES: usize = crate::llm::MAX_PROVIDER_REQUEST_BYTES / 12;
const MAX_RESPOND_MANIFEST_BYTES: usize = 24_000;
const MAX_RESPOND_REPO_BYTES: usize = 512;
const MAX_RESPOND_TITLE_BYTES: usize = 2 * 1024;
const MAX_RESPOND_DESCRIPTION_BYTES: usize = 4 * 1024;
const MAX_RESPOND_COMMENT_BYTES: usize = 8 * 1024;
const MAX_RESPOND_ISSUE_BODY_BYTES: usize = 8 * 1024;
const USAGE_RECEIPT_PATH_ENV: &str = "POSTIL_USAGE_RECEIPT_PATH";
const RESPOND_MAX_CHARS: usize = 2_400;
const RESPOND_MAX_NONBLANK_LINES: usize = 24;
const RESPOND_MAX_LIST_ITEMS: usize = 3;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RespondOutput {
    answer: String,
    diagram: serde_json::Value,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<ModelUsageRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<ModelUsagePhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
    prompt_tokens: u64,
    completion_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_micros: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_provider_decimal: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost_source: Option<ModelUsageCostSource>,
    accounting_complete: bool,
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
            version: 2,
            operation: "respond",
            prompt_tokens: answer.usage.prompt_tokens,
            completion_tokens: answer.usage.completion_tokens,
            models: answer
                .models
                .iter()
                .map(|model| RespondModelUsage {
                    model: &model.model,
                    role: model.role,
                    phase: model.phase,
                    call_ordinal: model.call_ordinal,
                    attempt: model.attempt,
                    prompt_tokens: model.prompt_tokens,
                    completion_tokens: model.completion_tokens,
                    cost_micros: model.cost_micros,
                    cost_provider_decimal: model.cost_provider_decimal.as_deref(),
                    cost_source: model.cost_source,
                    accounting_complete: model.accounting_complete,
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
    cfg.require_model()?;
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
    let user = respond_user_prompt(&context, comment);
    let client = LlmClient::from_env(cfg)?;
    client.preflight_respond_plan(cfg, &system, &user)?;
    let answer = client
        .answer(cfg, &system, &user, validate_respond_output)
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

fn respond_user_prompt(context: &str, comment: &str) -> String {
    let comment = prompt::bounded_untrusted_prompt_text(comment.trim(), MAX_RESPOND_COMMENT_BYTES);
    format!(
        "{context}\n--- Maintainer's message to you ---\n{comment}\n\nReply to the message above."
    )
}

fn validate_respond_output(raw: &str) -> Result<String> {
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
    if !output.diagram.is_null() {
        return Err(anyhow!("reply diagram must be null"));
    }
    let normalized_answer = normalize_newlines(&output.answer);
    let answer = trim_outer_blank_lines(&normalized_answer);
    if answer.is_empty() {
        return Err(anyhow!("reply answer is empty"));
    }
    let publication_text = mask_markdown_code(&answer);
    validate_answer_publication(&publication_text)?;
    if contains_mermaid_fence(&answer)
        || answer
            .lines()
            .any(|line| is_mermaid_declaration(line.trim()))
    {
        return Err(anyhow!("Mermaid must use the diagram field"));
    }
    if markdown_heading_count(&publication_text) > 0 {
        return Err(anyhow!(
            "reply contains a Markdown heading; conversational replies do not allow headings"
        ));
    }
    let list_items = markdown_list_item_count(&publication_text);
    if list_items > RESPOND_MAX_LIST_ITEMS {
        return Err(anyhow!(
            "reply contains {list_items} list items; at most {RESPOND_MAX_LIST_ITEMS} are allowed"
        ));
    }

    let rendered = answer;

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

fn trim_outer_blank_lines(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let Some(first) = lines.iter().position(|line| !line.trim().is_empty()) else {
        return String::new();
    };
    let last = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .expect("a first nonblank line has a matching last line");
    lines[first..=last].join("\n")
}

fn validate_answer_publication(publication_text: &str) -> Result<()> {
    if contains_active_mention(publication_text) {
        return Err(anyhow!("reply contains an active mention"));
    }
    if contains_raw_html(publication_text) {
        return Err(anyhow!("reply contains raw HTML"));
    }
    if contains_markdown_image(publication_text) {
        return Err(anyhow!("reply contains a Markdown image"));
    }
    if contains_markdown_table(publication_text) {
        return Err(anyhow!("reply contains a Markdown table"));
    }
    Ok(())
}

fn mask_markdown_code(text: &str) -> String {
    let mut masked = String::with_capacity(text.len());
    let mut fence: Option<(char, usize)> = None;
    let mut in_indented_block = false;
    let mut previous_line_was_blank = true;
    for line_with_newline in text.split_inclusive('\n') {
        let (line, newline) = line_with_newline
            .strip_suffix('\n')
            .map_or((line_with_newline, ""), |line| (line, "\n"));
        if let Some((marker, width)) = fence {
            let closes = markdown_fence_marker(line).is_some_and(|(candidate, candidate_width)| {
                candidate == marker
                    && candidate_width >= width
                    && fence_remainder(line, candidate, candidate_width)
                        .trim()
                        .is_empty()
            });
            masked.extend(std::iter::repeat_n(' ', line.chars().count()));
            masked.push_str(newline);
            if closes {
                fence = None;
                previous_line_was_blank = true;
            }
            continue;
        }
        if let Some(opening) = markdown_fence_opening(line) {
            fence = Some(opening);
            in_indented_block = false;
            masked.extend(std::iter::repeat_n(' ', line.chars().count()));
            masked.push_str(newline);
            continue;
        }
        if is_indented_code_line(line) && (in_indented_block || previous_line_was_blank) {
            in_indented_block = true;
            previous_line_was_blank = false;
            masked.extend(std::iter::repeat_n(' ', line.chars().count()));
            masked.push_str(newline);
            continue;
        }
        if line.trim().is_empty() {
            previous_line_was_blank = true;
            masked.push_str(line);
            masked.push_str(newline);
            continue;
        }
        in_indented_block = false;
        previous_line_was_blank = false;
        masked.push_str(&mask_inline_code(line));
        masked.push_str(newline);
    }
    masked
}

fn markdown_fence_marker(line: &str) -> Option<(char, usize)> {
    let indentation = line.chars().take_while(|ch| *ch == ' ').count();
    if indentation > 3 {
        return None;
    }
    let content = &line[indentation..];
    let marker = content.chars().next()?;
    if !matches!(marker, '`' | '~') {
        return None;
    }
    let width = content.chars().take_while(|ch| *ch == marker).count();
    (width >= 3).then_some((marker, width))
}

fn markdown_fence_opening(line: &str) -> Option<(char, usize)> {
    let (marker, width) = markdown_fence_marker(line)?;
    if marker == '`' && fence_remainder(line, marker, width).contains('`') {
        return None;
    }
    Some((marker, width))
}

fn is_indented_code_line(line: &str) -> bool {
    line.starts_with("    ") || line.starts_with('\t')
}

fn fence_remainder(line: &str, marker: char, width: usize) -> &str {
    let indentation = line.chars().take_while(|ch| *ch == ' ').count();
    let offset = indentation + marker.len_utf8() * width;
    &line[offset..]
}

fn contains_mermaid_fence(text: &str) -> bool {
    text.lines().any(|line| {
        markdown_fence_opening(line).is_some_and(|(marker, width)| {
            fence_remainder(line, marker, width)
                .split_whitespace()
                .next()
                .is_some_and(|language| language.eq_ignore_ascii_case("mermaid"))
        })
    })
}

fn mask_inline_code(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut masked = chars.clone();
    let mut cursor = 0;
    while cursor < chars.len() {
        if chars[cursor] != '`' {
            cursor += 1;
            continue;
        }
        let width = chars[cursor..].iter().take_while(|ch| **ch == '`').count();
        let mut closing = cursor + width;
        let mut found = None;
        while closing < chars.len() {
            if chars[closing] != '`' {
                closing += 1;
                continue;
            }
            let closing_width = chars[closing..].iter().take_while(|ch| **ch == '`').count();
            if closing_width == width {
                found = Some(closing + width);
                break;
            }
            closing += closing_width;
        }
        let Some(end) = found else {
            cursor += width;
            continue;
        };
        masked[cursor..end].fill(' ');
        cursor = end;
    }
    masked.into_iter().collect()
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
        if remaining.contains(']') {
            return true;
        }
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
        let ordered = [". ", ") "].iter().any(|delimiter| {
            trimmed.split_once(delimiter).is_some_and(|(prefix, _)| {
                !prefix.is_empty() && prefix.chars().all(|ch| ch.is_ascii_digit())
            })
        });
        if bullet || ordered {
            count += 1;
        }
    }
    count
}

fn is_mermaid_declaration(line: &str) -> bool {
    let line = line.trim();
    let Some(declaration) = line.split_whitespace().next() else {
        return false;
    };
    let rest = line[declaration.len()..].trim();
    match declaration.to_ascii_lowercase().as_str() {
        "flowchart" | "graph" => rest.split_whitespace().next().is_some_and(|direction| {
            matches!(
                direction.to_ascii_uppercase().as_str(),
                "TB" | "TD" | "BT" | "RL" | "LR"
            )
        }),
        "pie" => {
            let rest = rest.to_ascii_lowercase();
            rest.is_empty() || rest == "showdata" || rest.starts_with("title ")
        }
        "block-beta" => rest.is_empty() || rest.to_ascii_lowercase().starts_with("columns "),
        "gitgraph" => rest.is_empty() || rest.starts_with('{'),
        "sequencediagram" | "statediagram" | "statediagram-v2" | "classdiagram" | "erdiagram"
        | "journey" | "gantt" | "mindmap" | "timeline" | "quadrantchart" | "xychart-beta"
        | "packet-beta" | "architecture-beta" | "kanban" | "sankey-beta" => rest.is_empty(),
        _ => false,
    }
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
            let raw = forge.fetch_diff(&meta).await.context("fetching PR diff")?;
            let (annotated, reserved_anchor) = diff::bounded_respond_context(
                &raw,
                MAX_RESPOND_DIFF_CONTEXT_BYTES,
                MAX_RESPOND_MANIFEST_BYTES,
            )?;
            ensure!(
                !reserved_anchor,
                "pull request contains a path reserved for Postil's virtual review evidence"
            );
            let repo = prompt::bounded_untrusted_prompt_text(repo, MAX_RESPOND_REPO_BYTES);
            let title = prompt::bounded_untrusted_prompt_text(&meta.title, MAX_RESPOND_TITLE_BYTES);
            let mut ctx = format!(
                "Context: pull request #{number} in {repo}\nTitle: {}\n",
                title
            );
            if !meta.body.trim().is_empty() {
                let body = prompt::bounded_untrusted_prompt_text(
                    meta.body.trim(),
                    MAX_RESPOND_DESCRIPTION_BYTES,
                );
                ctx.push_str(&format!("Description:\n{body}\n"));
            }
            ctx.push_str("\nDiff (left-margin numbers are new-file lines):\n\n");
            ctx.push_str(&prompt::bounded_untrusted_prompt_text(
                &annotated,
                MAX_RESPOND_DIFF_CONTEXT_BYTES,
            ));
            Ok(ctx)
        }
        ThreadKind::Issue => {
            let (title, body) = forge.fetch_thread(number, kind).await?;
            let repo = prompt::bounded_untrusted_prompt_text(repo, MAX_RESPOND_REPO_BYTES);
            let title = prompt::bounded_untrusted_prompt_text(&title, MAX_RESPOND_TITLE_BYTES);
            let body = prompt::bounded_untrusted_prompt_text(&body, MAX_RESPOND_ISSUE_BODY_BYTES);
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

    #[test]
    fn hostile_respond_context_and_comment_fit_both_provider_shapes() {
        let hostile = format!(
            "{}{}{}",
            "\0".repeat(MAX_RESPOND_DIFF_CONTEXT_BYTES),
            "\"".repeat(MAX_RESPOND_DIFF_CONTEXT_BYTES),
            "\\".repeat(MAX_RESPOND_DIFF_CONTEXT_BYTES)
        );
        let diff = prompt::bounded_untrusted_prompt_text(&hostile, MAX_RESPOND_DIFF_CONTEXT_BYTES);
        let title = prompt::bounded_untrusted_prompt_text(&hostile, MAX_RESPOND_TITLE_BYTES);
        let description =
            prompt::bounded_untrusted_prompt_text(&hostile, MAX_RESPOND_DESCRIPTION_BYTES);
        let context = format!(
            "Context: pull request #1 in repository\nTitle: {title}\nDescription:\n{description}\nDiff:\n{diff}"
        );
        let user = respond_user_prompt(&context, &hostile);
        assert!(!user.contains('\0'));
        let system = prompt::respond_system_prompt(&Config::default());
        for body in [
            serde_json::json!({
                "model": "provider/model",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ]
            }),
            serde_json::json!({
                "model": "provider/model",
                "system": system,
                "messages": [{"role": "user", "content": user}]
            }),
        ] {
            assert!(
                serde_json::to_vec(&body).unwrap().len() < crate::llm::MAX_PROVIDER_REQUEST_BYTES
            );
        }
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
            validate_respond_output(&raw).unwrap(),
            "`src/auth.rs:41` interpolates input into the query. Parameterize it before merge."
        );
    }

    #[test]
    fn rejects_the_7186_character_article_shape() {
        let slop = article_shaped_slop();
        assert_eq!(slop.chars().count(), 7_186);
        let error = validate_respond_output(&slop).unwrap_err();
        assert!(error.to_string().contains("2,400-character"));
    }

    #[test]
    fn enforces_line_and_list_limits_and_rejects_headings() {
        let too_many_lines = structured(&vec!["line"; 25].join("\n"), None);
        assert!(
            validate_respond_output(&too_many_lines)
                .unwrap_err()
                .to_string()
                .contains("24-line")
        );

        let headings = structured("# One", None);
        assert!(
            validate_respond_output(&headings)
                .unwrap_err()
                .to_string()
                .contains("do not allow headings")
        );

        let items = structured("1. One\n2. Two\n3. Three\n4. Four", None);
        assert!(
            validate_respond_output(&items)
                .unwrap_err()
                .to_string()
                .contains("4 list items")
        );

        let parenthesized = structured("1) One\n2) Two\n3) Three\n4) Four", None);
        assert!(
            validate_respond_output(&parenthesized)
                .unwrap_err()
                .to_string()
                .contains("4 list items")
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
                validate_respond_output(&structured(answer, None)).is_err(),
                "unsafe reply was accepted: {answer}"
            );
        }
        let email = structured("Email dev@example.test with the result.", None);
        assert_eq!(
            validate_respond_output(&email).unwrap(),
            "Email dev@example.test with the result."
        );
    }

    #[test]
    fn rejects_all_generated_diagrams_and_mermaid_answers() {
        let diagram = structured(
            "The request crosses the queue before a worker handles it.",
            Some("flowchart LR\n  API --> Queue"),
        );
        assert!(
            validate_respond_output(&diagram)
                .unwrap_err()
                .to_string()
                .contains("must be null")
        );
        for answer in [
            "```mermaid\nflowchart TD\n  A --> B\n```",
            "``` mermaid\nA --> B\n```",
            "~~~mermaid\nsequenceDiagram\n  A->>B: hello\n~~~",
            "   ~~~ MERMAID\nA --> B\n   ~~~",
            "flowchart LR\n  A --> B",
            "graph TD\n  A --> B",
            "sequenceDiagram",
            "stateDiagram",
            "stateDiagram-v2",
            "classDiagram\n  class A",
            "erDiagram",
            "journey",
            "gantt",
            "pie showData",
            "mindmap",
            "timeline",
            "gitGraph {\"showBranches\": true}",
            "quadrantChart",
            "xychart-beta",
            "block-beta columns 3",
            "packet-beta",
            "architecture-beta",
            "kanban",
            "sankey-beta",
        ] {
            assert!(validate_respond_output(&structured(answer, None)).is_err());
        }
    }

    #[test]
    fn mermaid_detection_does_not_reject_ordinary_prose() {
        for answer in [
            "Graph construction is linear in the number of edges.",
            "A timeline helps explain the retry sequence.",
            "Pie is not relevant to this handler.",
            "The journey continues through the queue.",
            "Kanban boards are outside this change.",
        ] {
            assert_eq!(
                validate_respond_output(&structured(answer, None)).unwrap(),
                answer
            );
        }
    }

    #[test]
    fn rejects_report_shaped_headings() {
        for answer in [
            "# Analysis\nLong-form report prose.",
            "# Recommendations\nLong-form report prose.",
            "# Overview\nLong-form report prose.",
            "# Summary\nLong-form report prose.",
            "# What this pull request does\nLong-form report prose.",
            "# Issue and risk\nLong-form report prose.",
            "# Risks\nLong-form report prose.",
            "# Assessment\nLong-form report prose.",
            "# Review metadata\nLong-form report prose.",
            "# Summary)\nLong-form report prose.",
            "## Verdict: ###\nLong-form report prose.",
            "Correctness!\n------------\nLong-form report prose.",
        ] {
            let reply = structured(answer, None);
            assert!(
                validate_respond_output(&reply).is_err(),
                "report heading was accepted: {answer}",
            );
        }
    }

    #[test]
    fn contract_vectors_mask_code_and_reject_image_forms() {
        for answer in [
            "Use `@maintainer` as the literal test fixture.",
            "Unicode before code: é `@maintainer`.",
            "`<details>not HTML here</details>` is sample text.",
            "```markdown\n@maintainer\n<details>sample</details>\n![image][ref]\n## Verdict\nA | B\n--- | ---\n```",
            "    @maintainer",
            "\t@maintainer",
        ] {
            assert_eq!(
                validate_respond_output(&structured(answer, None)).unwrap(),
                answer
            );
        }

        for image in [
            "![inline](image.png)",
            "![reference][image-ref]",
            "![collapsed][]",
            "![shortcut]",
            "![multi\nline](image.png)",
        ] {
            assert!(validate_respond_output(&structured(image, None)).is_err());
        }

        for invalid in [
            r#"{"answer":"ok"}"#,
            r#"{"answer":"ok","diagram":null,"extra":true}"#,
            r#"{"answer":"ok","diagram":{}}"#,
            r#"{"answer":"ok","diagram":""}"#,
        ] {
            assert!(validate_respond_output(invalid).is_err());
        }
    }

    #[test]
    fn commonmark_masking_does_not_hide_active_mentions_in_live_prose() {
        for answer in [
            "Ask @maintainer to approve this.",
            "`unterminated @maintainer",
            "Unicode before unmatched code: é `unterminated @maintainer",
            "```rust`invalid info string\n@maintainer\n```",
            "This is a paragraph.\n    @maintainer remains live prose.",
        ] {
            let error = validate_respond_output(&structured(answer, None)).unwrap_err();
            assert!(
                error.to_string().contains("active mention"),
                "active mention was hidden by invalid code markup: {answer}"
            );
        }
    }

    #[test]
    fn outer_blank_line_trimming_preserves_indented_code() {
        let answer = "    @maintainer";
        assert_eq!(
            validate_respond_output(&structured("\n \n    @maintainer\n\t\n", None)).unwrap(),
            answer
        );
    }

    #[test]
    fn shape_limits_ignore_markers_inside_code() {
        for answer in [
            "    1) One\n    2) Two\n    3) Three\n    4) Four\n    5) Five\n    6) Six",
            "    # One\n    ## Two\n    ### Three",
            "`# One`\n`## Two`\n`### Three`\n`1) One`\n`2) Two`\n`3) Three`\n`4) Four`\n`5) Five`\n`6) Six`",
        ] {
            assert_eq!(
                validate_respond_output(&structured(answer, None)).unwrap(),
                answer
            );
        }
    }
}
