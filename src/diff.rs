//! Unified-diff parsing, the grounding index, and prompt-facing rendering.
//!
//! Grounding is the heart of Postil's trust model: a finding is only kept if it
//! cites a (path, line) that actually exists on the new side of the diff. To make
//! the model cite real numbers, the rendered diff annotates every kept/added line
//! with its new-file line number.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::RangeInclusive;

/// Why a changed file is excluded from model context. These files remain in
/// the parsed diff and grounding index, but deterministic artifacts do not
/// consume review-model context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmittedFileKind {
    Lockfile,
    Generated,
}

#[derive(Debug, Default)]
pub struct ReviewBatchPlan {
    pub batches: Vec<String>,
    pub omitted_lockfiles: usize,
    pub omitted_generated: usize,
}

pub struct SelectedDiff<'a> {
    pub text: Cow<'a, str>,
    pub omitted_lockfiles: usize,
    pub omitted_generated: usize,
}

#[derive(Debug, Clone)]
pub struct Hunk {
    pub old_start: u32,
    pub old_count: u32,
    pub new_start: u32,
    pub new_count: u32,
    /// Raw hunk lines including leading ' ', '+', '-'.
    pub lines: Vec<String>,
}

impl Hunk {
    pub fn old_range(&self) -> RangeInclusive<u32> {
        self.old_start..=self.old_start + self.old_count.saturating_sub(1)
    }

    pub fn new_range(&self) -> RangeInclusive<u32> {
        // A zero-count hunk (pure deletion) still anchors at new_start.
        self.new_start..=self.new_start + self.new_count.saturating_sub(1)
    }
}

#[derive(Debug, Clone)]
pub struct FileDiff {
    /// Old-side path ("a/" stripped). Used to reconcile findings anchored to
    /// the previously reviewed head, including across renames and deletions.
    pub old_path: String,
    /// New-side path ("b/" stripped). Deleted files keep the old path.
    pub path: String,
    pub deleted: bool,
    pub binary: bool,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Default)]
pub struct Diff {
    pub files: Vec<FileDiff>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.files.iter().all(|f| f.binary || (f.hunks.is_empty()))
    }
}

/// Index answering "does (path, line) fall inside a changed hunk's new side?"
#[derive(Debug, Default)]
pub struct DiffIndex {
    ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    old_ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    /// Reserved synthetic-path line ranges that only content-policy findings may
    /// ground against (e.g. the rendered PR title/description). Kept separate
    /// from `ranges` so a non-content-policy finding cannot exploit them.
    content_policy_ranges: HashMap<String, RangeInclusive<u32>>,
}

impl DiffIndex {
    pub fn build(diff: &Diff) -> Self {
        let mut ranges: HashMap<String, Vec<RangeInclusive<u32>>> = HashMap::new();
        let mut old_ranges: HashMap<String, Vec<RangeInclusive<u32>>> = HashMap::new();
        for file in &diff.files {
            if file.binary {
                continue;
            }
            for hunk in &file.hunks {
                if hunk.old_count > 0 {
                    old_ranges
                        .entry(file.old_path.clone())
                        .or_default()
                        .push(hunk.old_range());
                }
            }
            if file.deleted {
                continue;
            }
            let entry = ranges.entry(file.path.clone()).or_default();
            for hunk in &file.hunks {
                if hunk.new_count > 0 {
                    entry.push(hunk.new_range());
                }
            }
        }
        DiffIndex {
            ranges,
            old_ranges,
            content_policy_ranges: HashMap::new(),
        }
    }

    /// Register `path` as groundable for content-policy findings over lines
    /// `1..=count` (the numbered PR title/description block). No-op when
    /// `count == 0`.
    pub fn add_content_policy_path(&mut self, path: &str, count: u32) {
        if count > 0 {
            self.content_policy_ranges
                .insert(path.to_string(), 1..=count);
        }
    }

    /// True when `(path, line)` is a registered content-policy anchor. Used only
    /// for `kind: contentPolicy` findings; the normal `contains` path never
    /// consults these ranges.
    pub fn contains_content_policy(&self, path: &str, line: u32) -> bool {
        self.content_policy_ranges
            .get(path)
            .is_some_and(|r| r.contains(&line))
    }

    pub fn contains(&self, path: &str, line: u32) -> bool {
        self.ranges
            .get(path)
            .is_some_and(|rs| rs.iter().any(|r| r.contains(&line)))
    }

    /// True when both endpoints are on the new side of one diff hunk. Forge
    /// APIs reject multiline comments that cross hunk boundaries even when the
    /// individual line numbers both appear elsewhere in the file diff.
    pub fn contains_range(&self, path: &str, start: u32, end: u32) -> bool {
        start <= end
            && self.ranges.get(path).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|range| range.contains(&start) && range.contains(&end))
            })
    }

    /// True when `(path, line)` falls on the old side of a changed hunk. A
    /// baseline finding cites the previously reviewed head, so incremental
    /// reconciliation must use this coordinate space rather than new-file
    /// grounding ranges.
    pub fn contains_old(&self, path: &str, line: u32) -> bool {
        self.old_ranges
            .get(path)
            .is_some_and(|rs| rs.iter().any(|r| r.contains(&line)))
    }

    /// True when the diff touches any line in [start, end] of `path`.
    /// Used for baseline reconciliation in incremental reviews.
    pub fn touches(&self, path: &str, start: u32, end: u32) -> bool {
        self.ranges
            .get(path)
            .is_some_and(|rs| rs.iter().any(|r| *r.start() <= end && start <= *r.end()))
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Remove deterministic artifact file sections before the allocating parser.
/// The acquired diff already exists as one string; this prevents a large
/// lockfile or generated output from being copied into per-line parser state.
/// When no artifact is present, the original string is borrowed without copy.
pub fn select_reviewable_diff(text: &str) -> SelectedDiff<'_> {
    let starts: Vec<usize> = text
        .match_indices("diff --git ")
        .filter_map(|(index, _)| {
            (index == 0 || text.as_bytes().get(index.wrapping_sub(1)) == Some(&b'\n'))
                .then_some(index)
        })
        .collect();
    if starts.is_empty() {
        return SelectedDiff {
            text: Cow::Borrowed(text),
            omitted_lockfiles: 0,
            omitted_generated: 0,
        };
    }

    let mut omitted_lockfiles = 0;
    let mut omitted_generated = 0;
    let mut kept_sections = Vec::with_capacity(starts.len());
    for (position, start) in starts.iter().copied().enumerate() {
        let end = starts.get(position + 1).copied().unwrap_or(text.len());
        let section = &text[start..end];
        let header = section.lines().next().unwrap_or_default();
        let path = header
            .strip_prefix("diff --git ")
            .and_then(|rest| rest.rsplit_once(" b/").map(|(_, path)| path))
            .unwrap_or_default();
        match classify_omitted_file(path) {
            Some(OmittedFileKind::Lockfile) => omitted_lockfiles += 1,
            Some(OmittedFileKind::Generated) => omitted_generated += 1,
            None => kept_sections.push(section),
        }
    }
    if omitted_lockfiles == 0 && omitted_generated == 0 {
        return SelectedDiff {
            text: Cow::Borrowed(text),
            omitted_lockfiles,
            omitted_generated,
        };
    }

    let kept_len = text[..starts[0]].len()
        + kept_sections
            .iter()
            .map(|section| section.len())
            .sum::<usize>();
    let mut selected = String::with_capacity(kept_len);
    selected.push_str(&text[..starts[0]]);
    for section in kept_sections {
        selected.push_str(section);
    }
    SelectedDiff {
        text: Cow::Owned(selected),
        omitted_lockfiles,
        omitted_generated,
    }
}

/// Parse a unified diff (git format). Tolerant of mode lines, renames, and
/// "\ No newline at end of file" markers.
pub fn parse(text: &str) -> Diff {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    let mut current_hunk: Option<Hunk> = None;
    // Remaining old-side and new-side lines the current hunk header declared.
    // A hunk is closed once both reach zero so trailing content (notably a bare
    // blank line separating concatenated file diffs) is not absorbed as a
    // phantom line that would render an ungroundable numbered line.
    let mut old_left: u32 = 0;
    let mut new_left: u32 = 0;

    let flush_hunk = |file: &mut Option<FileDiff>, hunk: &mut Option<Hunk>| {
        if let (Some(f), Some(h)) = (file.as_mut(), hunk.take()) {
            f.hunks.push(h);
        }
    };

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush_hunk(&mut current, &mut current_hunk);
            if let Some(f) = current.take() {
                files.push(f);
            }
            // Seed the path from the header (binary diffs have no +++/--- lines);
            // the +++/--- lines that follow refine it for renames.
            let (old_path, path) = rest
                .rsplit_once(" b/")
                .map(|(a, b)| {
                    (
                        strip_prefix_ab(a).to_string(),
                        strip_prefix_ab(b).to_string(),
                    )
                })
                .unwrap_or_default();
            current = Some(FileDiff {
                old_path,
                path,
                deleted: false,
                binary: false,
                hunks: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            if let Some(f) = current.as_mut() {
                if rest == "/dev/null" {
                    f.deleted = true;
                } else {
                    f.path = strip_prefix_ab(rest).to_string();
                }
            }
        } else if let Some(rest) = line.strip_prefix("--- ") {
            if let Some(f) = current.as_mut()
                && rest != "/dev/null"
            {
                f.old_path = strip_prefix_ab(rest).to_string();
                // Keep the old path as a fallback for deletions (+++ /dev/null).
                if f.path.is_empty() {
                    f.path = f.old_path.clone();
                }
            }
        } else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            if let Some(f) = current.as_mut() {
                f.binary = true;
            }
        } else if let Some(header) = line.strip_prefix("@@ ") {
            flush_hunk(&mut current, &mut current_hunk);
            if let Some((old_start, old_count, new_start, new_count)) = parse_hunk_header(header) {
                current_hunk = Some(Hunk {
                    old_start,
                    old_count,
                    new_start,
                    new_count,
                    lines: Vec::new(),
                });
                old_left = old_count;
                new_left = new_count;
            }
        } else if let Some(h) = current_hunk.as_mut() {
            // The hunk is complete once every declared old- and new-side line has
            // been consumed. Anything after that (a blank separator, a stray
            // line) belongs to the next file, not this hunk.
            let complete = old_left == 0 && new_left == 0;
            if !complete && (line.starts_with(['+', '-', ' ']) || line.is_empty()) {
                // A bare blank line counts as an unchanged (context) line: it is
                // present on both sides.
                match line.chars().next() {
                    Some('+') => new_left = new_left.saturating_sub(1),
                    Some('-') => old_left = old_left.saturating_sub(1),
                    _ => {
                        old_left = old_left.saturating_sub(1);
                        new_left = new_left.saturating_sub(1);
                    }
                }
                h.lines.push(line.to_string());
            } else if line.starts_with('\\') {
                // "\ No newline at end of file" — not content.
            } else {
                // Hunk complete, or a trailer (e.g. next file's "index" line in
                // odd diffs): close the hunk.
                flush_hunk(&mut current, &mut current_hunk);
            }
        }
    }
    flush_hunk(&mut current, &mut current_hunk);
    if let Some(f) = current.take() {
        files.push(f);
    }
    files.retain(|f| !f.path.is_empty());
    Diff { files }
}

fn strip_prefix_ab(path: &str) -> &str {
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
        .trim_end()
}

/// "@@ -l,c +l,c @@ ctx" minus the leading "@@ ". Returns
/// (old_start, old_count, new_start, new_count). Counts default to 1 when a
/// header omits them (single-line hunk).
fn parse_hunk_header(header: &str) -> Option<(u32, u32, u32, u32)> {
    let range_of = |token: &str| -> Option<(u32, u32)> {
        let spec = &token[1..];
        match spec.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((spec.parse().ok()?, 1)),
        }
    };
    let (old_start, old_count) = header
        .split_whitespace()
        .find(|t| t.starts_with('-'))
        .and_then(range_of)
        .unwrap_or((0, 0));
    let (new_start, new_count) = header
        .split_whitespace()
        .find(|t| t.starts_with('+'))
        .and_then(range_of)?;
    Some((old_start, old_count, new_start, new_count))
}

/// Render the diff for the model with new-file line numbers on every line that
/// exists on the new side. Deleted lines carry no number (they cannot be cited).
pub fn render_annotated(diff: &Diff, max_bytes: usize) -> (String, bool) {
    let mut out = String::new();
    // Append `s`, returning true once the size cap is exceeded. Routing EVERY
    // push through this enforces the cap after each append, headers included — a
    // diff with hundreds of thousands of header-only files must still trip the
    // truncation flag rather than render unbounded output that reads as a full
    // pass.
    let push = |out: &mut String, s: &str| -> bool {
        out.push_str(s);
        out.len() > max_bytes
    };
    let mut truncated = false;
    'files: for file in &diff.files {
        if file.binary {
            if push(
                &mut out,
                &format!("### {} (binary, not reviewable)\n", file.path),
            ) {
                truncated = true;
                break 'files;
            }
            continue;
        }
        if file.deleted {
            if push(&mut out, &format!("### {} (deleted)\n", file.path)) {
                truncated = true;
                break 'files;
            }
            continue;
        }
        if push(&mut out, &format!("### {}\n", file.path)) {
            truncated = true;
            break 'files;
        }
        for hunk in &file.hunks {
            if push(
                &mut out,
                &format!("@@ starting at line {} @@\n", hunk.new_start),
            ) {
                truncated = true;
                break 'files;
            }
            let mut line_no = hunk.new_start;
            for raw in &hunk.lines {
                let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
                let rendered = match marker {
                    "+" => {
                        let s = format!("{line_no:>6} + {content}\n");
                        line_no += 1;
                        s
                    }
                    "-" => format!("       - {content}\n"),
                    _ => {
                        let s = format!("{line_no:>6}   {content}\n");
                        line_no += 1;
                        s
                    }
                };
                if push(&mut out, &rendered) {
                    truncated = true;
                    break 'files;
                }
            }
        }
        if push(&mut out, "\n") {
            truncated = true;
            break 'files;
        }
    }
    if truncated {
        out.push_str("\n[diff truncated: review scope limit reached]\n");
    }
    (out, truncated)
}

/// Split reviewable source changes into independently bounded model inputs.
///
/// Aggregate diff size is not a review failure. Lockfiles and paths that
/// explicitly identify generated outputs are omitted, then source hunks are
/// streamed into as many bounded batches as necessary. A single pathological
/// line is abbreviated rather than allowing one line to defeat the batch cap.
pub fn render_review_batches(diff: &Diff, max_bytes: usize) -> ReviewBatchPlan {
    assert!(
        max_bytes >= 1024,
        "review batch limit must leave room for context"
    );
    let mut plan = ReviewBatchPlan::default();
    let mut current = String::new();

    for file in &diff.files {
        match classify_omitted_file(&file.path) {
            Some(OmittedFileKind::Lockfile) => {
                plan.omitted_lockfiles += 1;
                continue;
            }
            Some(OmittedFileKind::Generated) => {
                plan.omitted_generated += 1;
                continue;
            }
            None => {}
        }
        if file.binary || file.deleted || file.hunks.is_empty() {
            continue;
        }

        let file_header = format!("### {}\n", file.path);
        for hunk in &file.hunks {
            let mut line_no = hunk.new_start;
            let mut hunk_header = format!("@@ starting at line {line_no} @@\n");
            let mut need_headers = true;
            for raw in &hunk.lines {
                let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
                let rendered_line = line_no;
                // Reserve enough room for either hunk-header form. This keeps
                // the cap exact even when an oversized hunk continues in a
                // later batch with a longer header.
                let line_budget = max_bytes.saturating_sub(file_header.len() + 64);
                let rendered = match marker {
                    "+" => {
                        let rendered = bounded_rendered_line(line_no, "+", content, line_budget);
                        line_no += 1;
                        rendered
                    }
                    "-" => bounded_rendered_line(0, "-", content, line_budget),
                    _ => {
                        let rendered = bounded_rendered_line(line_no, " ", content, line_budget);
                        line_no += 1;
                        rendered
                    }
                };
                let prefix_len = if need_headers {
                    file_header.len() + hunk_header.len()
                } else {
                    0
                };
                if !current.is_empty() && current.len() + prefix_len + rendered.len() > max_bytes {
                    plan.batches.push(std::mem::take(&mut current));
                    hunk_header = format!("@@ continuing at line {rendered_line} @@\n");
                    need_headers = true;
                }
                if need_headers {
                    current.push_str(&file_header);
                    current.push_str(&hunk_header);
                    need_headers = false;
                }
                current.push_str(&rendered);
                if current.len() >= max_bytes {
                    plan.batches.push(std::mem::take(&mut current));
                    hunk_header = format!("@@ continuing at line {line_no} @@\n");
                    need_headers = true;
                }
            }
            if !current.is_empty() {
                if current.len() < max_bytes {
                    current.push('\n');
                } else {
                    plan.batches.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        plan.batches.push(current);
    }
    plan
}

fn bounded_rendered_line(line_no: u32, marker: &str, content: &str, max_bytes: usize) -> String {
    let prefix = if marker == "-" {
        "       - ".to_string()
    } else {
        format!("{line_no:>6} {marker} ")
    };
    let max_content = max_bytes.saturating_sub(prefix.len() + 64);
    if content.len() <= max_content {
        return format!("{prefix}{content}\n");
    }
    let mut cut = max_content;
    while cut > 0 && !content.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{prefix}{} [line abbreviated: {} bytes omitted]\n",
        &content[..cut],
        content.len() - cut
    )
}

pub fn classify_omitted_file(path: &str) -> Option<OmittedFileKind> {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    let lockfile = matches!(
        name,
        "cargo.lock"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "bun.lockb"
            | "composer.lock"
            | "gemfile.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pipfile.lock"
            | "go.sum"
            | "mix.lock"
            | "pubspec.lock"
            | "gradle.lockfile"
            | "packages.lock.json"
            | ".terraform.lock.hcl"
    );
    if lockfile {
        return Some(OmittedFileKind::Lockfile);
    }

    let generated_component = normalized
        .split('/')
        .any(|part| matches!(part, "dist" | "coverage" | "node_modules"));
    let generated_name = name.contains(".generated.")
        || name.contains("_generated.")
        || name.ends_with(".g.dart")
        || name.contains(".pb.")
        || name.ends_with(".min.js")
        || name.ends_with(".min.css")
        || name.ends_with(".snap");
    (generated_component || generated_name).then_some(OmittedFileKind::Generated)
}

/// Confirm that a model citation was present in the exact annotated batch it
/// received. The full-diff index alone is insufficient for batched reviews: a
/// hallucinated citation from another batch is valid globally but was not
/// evidence available to this request.
pub fn review_batch_contains(annotated: &str, path: &str, line: u32) -> bool {
    let mut current_path: Option<&str> = None;
    for rendered in annotated.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            current_path = Some(header.trim());
            continue;
        }
        if current_path != Some(path) {
            continue;
        }
        let Some((number, _)) = rendered.trim_start().split_once(' ') else {
            continue;
        };
        if number.parse::<u32>().ok() == Some(line) {
            return true;
        }
    }
    false
}

/// Render the hunk around a cited new-file line for the independent scorer.
/// The scorer receives only a small local window, not the whole prompt-sized diff.
pub fn render_hunk_context(diff: &Diff, path: &str, line: u32, radius: u32) -> Option<String> {
    let file = diff
        .files
        .iter()
        .find(|f| !f.binary && !f.deleted && f.path == path)?;
    let hunk = file.hunks.iter().find(|h| h.new_range().contains(&line))?;
    let start = line.saturating_sub(radius);
    let end = line.saturating_add(radius);
    let mut out = format!(
        "### {}\n@@ starting at line {} @@\n",
        file.path, hunk.new_start
    );
    let mut line_no = hunk.new_start;
    for raw in &hunk.lines {
        let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
        match marker {
            "+" => {
                if (start..=end).contains(&line_no) {
                    out.push_str(&format!("{line_no:>6} + {content}\n"));
                }
                line_no += 1;
            }
            "-" => {
                if (start..=end).contains(&line_no) {
                    out.push_str(&format!("       - {content}\n"));
                }
            }
            _ => {
                if (start..=end).contains(&line_no) {
                    out.push_str(&format!("{line_no:>6}   {content}\n"));
                }
                line_no += 1;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
index 111..222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -10,4 +10,5 @@ fn ctx() {
 line ten
-removed
+added eleven
+added twelve
 line thirteen
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-bye
-bye
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
";

    #[test]
    fn parses_files_hunks_and_kinds() {
        let d = parse(SAMPLE);
        assert_eq!(d.files.len(), 3);
        assert_eq!(d.files[0].path, "src/lib.rs");
        assert_eq!(d.files[0].old_path, "src/lib.rs");
        assert_eq!(d.files[0].hunks.len(), 1);
        assert_eq!(d.files[0].hunks[0].old_start, 10);
        assert_eq!(d.files[0].hunks[0].old_count, 4);
        assert_eq!(d.files[0].hunks[0].new_start, 10);
        assert_eq!(d.files[0].hunks[0].new_count, 5);
        assert!(d.files[1].deleted);
        assert_eq!(d.files[1].path, "gone.txt");
        assert!(d.files[2].binary);
    }

    #[test]
    fn index_grounds_only_new_side() {
        let d = parse(SAMPLE);
        let idx = DiffIndex::build(&d);
        assert!(idx.contains("src/lib.rs", 10));
        assert!(idx.contains("src/lib.rs", 14));
        assert!(!idx.contains("src/lib.rs", 15));
        assert!(!idx.contains("src/lib.rs", 9));
        assert!(!idx.contains("gone.txt", 1));
        assert!(!idx.contains("img.png", 1));
        assert!(idx.contains_old("src/lib.rs", 10));
        assert!(idx.contains_old("src/lib.rs", 13));
        assert!(!idx.contains_old("src/lib.rs", 14));
        assert!(idx.contains_old("gone.txt", 1));
        assert!(idx.touches("src/lib.rs", 1, 10));
        assert!(!idx.touches("src/lib.rs", 1, 9));
    }

    #[test]
    fn annotated_render_numbers_new_lines() {
        let d = parse(SAMPLE);
        let (text, truncated) = render_annotated(&d, 1 << 20);
        assert!(!truncated);
        assert!(text.contains("    11 + added eleven"));
        assert!(text.contains("    12 + added twelve"));
        assert!(text.contains("       - removed"));
        assert!(text.contains("    13   line thirteen"));
        assert!(text.contains("(deleted)"));
        assert!(text.contains("(binary, not reviewable)"));
    }

    #[test]
    fn hunk_context_renders_local_cited_window() {
        let d = parse(SAMPLE);
        let context = render_hunk_context(&d, "src/lib.rs", 11, 20).unwrap();
        assert!(context.contains("### src/lib.rs"));
        assert!(context.contains("    11 + added eleven"));
        assert!(context.contains("       - removed"));
    }

    #[test]
    fn truncation_is_flagged() {
        let d = parse(SAMPLE);
        let (text, truncated) = render_annotated(&d, 40);
        assert!(truncated);
        assert!(text.contains("[diff truncated"));
    }

    #[test]
    fn review_batches_omit_artifacts_and_cover_all_source_lines() {
        let mut diff = Diff::default();
        for path in ["Cargo.lock", "web/schema.generated.ts"] {
            diff.files.push(FileDiff {
                old_path: path.into(),
                path: path.into(),
                deleted: false,
                binary: false,
                hunks: vec![Hunk {
                    old_start: 1,
                    old_count: 0,
                    new_start: 1,
                    new_count: 400,
                    lines: (0..400).map(|i| format!("+artifact-{i}")).collect(),
                }],
            });
        }
        diff.files.push(FileDiff {
            old_path: "src/lib.rs".into(),
            path: "src/lib.rs".into(),
            deleted: false,
            binary: false,
            hunks: vec![Hunk {
                old_start: 1,
                old_count: 0,
                new_start: 1,
                new_count: 200,
                lines: (1..=200)
                    .map(|i| format!("+let source_{i} = {i};"))
                    .collect(),
            }],
        });

        let plan = render_review_batches(&diff, 1024);
        assert_eq!(plan.omitted_lockfiles, 1);
        assert_eq!(plan.omitted_generated, 1);
        assert!(plan.batches.len() > 1);
        assert!(plan.batches.iter().all(|batch| batch.len() <= 1024));
        let rendered = plan.batches.join("\n");
        assert!(!rendered.contains("Cargo.lock"));
        assert!(!rendered.contains("schema.generated.ts"));
        assert!(rendered.contains("     1 + let source_1 = 1;"));
        assert!(rendered.contains("   200 + let source_200 = 200;"));
    }

    #[test]
    fn review_batches_abbreviate_one_pathological_source_line() {
        let diff = Diff {
            files: vec![FileDiff {
                old_path: "src/lib.rs".into(),
                path: "src/lib.rs".into(),
                deleted: false,
                binary: false,
                hunks: vec![Hunk {
                    old_start: 1,
                    old_count: 0,
                    new_start: 1,
                    new_count: 1,
                    lines: vec![format!("+{}", "x".repeat(10_000))],
                }],
            }],
        };

        let plan = render_review_batches(&diff, 1024);
        assert_eq!(plan.batches.len(), 1);
        assert!(plan.batches[0].len() <= 1024);
        assert!(plan.batches[0].contains("line abbreviated"));
    }

    #[test]
    fn artifact_classification_is_conservative() {
        assert_eq!(
            classify_omitted_file("frontend/package-lock.json"),
            Some(OmittedFileKind::Lockfile)
        );
        assert_eq!(
            classify_omitted_file("src/client.generated.ts"),
            Some(OmittedFileKind::Generated)
        );
        assert_eq!(classify_omitted_file("src/generated.rs"), None);
        assert_eq!(classify_omitted_file("vendor/security_patch.rs"), None);
    }

    #[test]
    fn artifacts_are_removed_before_allocating_parse_state() {
        let lock = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -0,0 +1,2 @@\n+first\n+second\n";
        let generated = "diff --git a/web/api.generated.ts b/web/api.generated.ts\n--- a/web/api.generated.ts\n+++ b/web/api.generated.ts\n@@ -0,0 +1 @@\n+generated\n";
        let mixed = format!("{lock}{generated}{SAMPLE}");

        let selected = select_reviewable_diff(&mixed);
        assert_eq!(selected.omitted_lockfiles, 1);
        assert_eq!(selected.omitted_generated, 1);
        assert!(!selected.text.contains("Cargo.lock"));
        assert!(!selected.text.contains("api.generated.ts"));
        assert!(selected.text.contains("src/lib.rs"));

        let unchanged = select_reviewable_diff(SAMPLE);
        assert!(matches!(unchanged.text, Cow::Borrowed(_)));
    }

    #[test]
    fn batch_grounding_is_scoped_to_the_exact_rendered_part() {
        let batch = "### src/a.rs\n    10 + first\n### src/b.rs\n    10 + second\n";
        assert!(review_batch_contains(batch, "src/a.rs", 10));
        assert!(review_batch_contains(batch, "src/b.rs", 10));
        assert!(!review_batch_contains(batch, "src/a.rs", 11));
        assert!(!review_batch_contains(batch, "src/c.rs", 10));
    }

    // Header-only files (binary/deleted or files with no hunks) still emit a
    // "### path" line each; without a size check on those pushes, a diff of many
    // thousands of such files would render unbounded output with truncated=false,
    // making a partial render read as a full pass. The cap must trip.
    #[test]
    fn header_only_files_respect_the_size_cap() {
        let mut diff = Diff::default();
        for i in 0..5000 {
            diff.files.push(FileDiff {
                old_path: format!("path/to/generated/file_{i:05}.bin"),
                path: format!("path/to/generated/file_{i:05}.bin"),
                deleted: false,
                binary: true,
                hunks: Vec::new(),
            });
        }
        let (text, truncated) = render_annotated(&diff, 2000);
        assert!(truncated, "header-only render bypassed the size cap");
        assert!(text.len() < 4000, "output ran past the cap unbounded");
        assert!(text.contains("[diff truncated"));
    }

    #[test]
    fn content_policy_ranges_are_separate_from_diff_ranges() {
        let d = parse(SAMPLE);
        let mut idx = DiffIndex::build(&d);
        idx.add_content_policy_path(".postil/pr-description", 3);
        // Registered content-policy anchor: lines 1..=3 groundable there.
        assert!(idx.contains_content_policy(".postil/pr-description", 1));
        assert!(idx.contains_content_policy(".postil/pr-description", 3));
        assert!(!idx.contains_content_policy(".postil/pr-description", 4));
        // The normal contains() never consults content-policy ranges.
        assert!(!idx.contains(".postil/pr-description", 1));
        // A zero-count registration is a no-op.
        idx.add_content_policy_path(".postil/empty", 0);
        assert!(!idx.contains_content_policy(".postil/empty", 1));
    }

    #[test]
    fn hunk_header_without_count() {
        assert_eq!(parse_hunk_header("-1 +5 @@"), Some((1, 1, 5, 1)));
        assert_eq!(parse_hunk_header("-1,2 +3,4 @@"), Some((1, 2, 3, 4)));
        assert_eq!(parse_hunk_header("-0,0 +1,3 @@"), Some((0, 0, 1, 3)));
    }

    #[test]
    fn old_side_index_uses_pre_change_path_for_renames() {
        let text = "\
diff --git a/old.rs b/new.rs
similarity index 80%
rename from old.rs
rename to new.rs
--- a/old.rs
+++ b/new.rs
@@ -9,2 +9,2 @@
-old
+new
 context
";
        let idx = DiffIndex::build(&parse(text));
        assert!(idx.contains_old("old.rs", 9));
        assert!(!idx.contains_old("new.rs", 9));
        assert!(idx.contains("new.rs", 9));
        assert!(!idx.contains("old.rs", 9));
    }

    // A bare blank line separating two concatenated file diffs must not be
    // absorbed as a phantom content line of the first hunk, which would render an
    // ungroundable numbered line just past the hunk's declared extent.
    #[test]
    fn blank_line_between_concatenated_file_diffs_is_not_absorbed() {
        let text = "\
diff --git a/one.rs b/one.rs
--- a/one.rs
+++ b/one.rs
@@ -1,1 +1,2 @@
 a
+b

diff --git a/two.rs b/two.rs
--- a/two.rs
+++ b/two.rs
@@ -1,1 +1,2 @@
 c
+d
";
        let d = parse(text);
        assert_eq!(d.files.len(), 2);
        // First hunk holds exactly its two declared new-side lines; the blank
        // separator is not one of them.
        let h = &d.files[0].hunks[0];
        assert_eq!(h.new_count, 2);
        assert_eq!(h.lines.len(), 2, "blank separator absorbed into hunk");
        // The first hunk's new side spans lines 1-2 only; line 3 is ungroundable.
        let idx = DiffIndex::build(&d);
        assert!(idx.contains("one.rs", 1));
        assert!(idx.contains("one.rs", 2));
        assert!(!idx.contains("one.rs", 3));
        assert!(idx.contains("two.rs", 2));
    }
}
