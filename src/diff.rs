//! Unified-diff parsing, the grounding index, and prompt-facing rendering.
//!
//! Grounding is the heart of Postil's trust model: a finding is only kept if it
//! cites a (path, line) that actually exists on the new side of the diff. To make
//! the model cite real numbers, the rendered diff annotates every kept/added line
//! with its new-file line number.

use std::collections::HashMap;
use std::ops::RangeInclusive;

#[derive(Debug, Clone)]
pub struct Hunk {
    pub new_start: u32,
    pub new_count: u32,
    /// Raw hunk lines including leading ' ', '+', '-'.
    pub lines: Vec<String>,
}

impl Hunk {
    pub fn new_range(&self) -> RangeInclusive<u32> {
        // A zero-count hunk (pure deletion) still anchors at new_start.
        self.new_start..=self.new_start + self.new_count.saturating_sub(1)
    }
}

#[derive(Debug, Clone)]
pub struct FileDiff {
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
    /// Reserved synthetic-path line ranges that only content-policy findings may
    /// ground against (e.g. the rendered PR title/description). Kept separate
    /// from `ranges` so a non-content-policy finding cannot exploit them.
    content_policy_ranges: HashMap<String, RangeInclusive<u32>>,
}

impl DiffIndex {
    pub fn build(diff: &Diff) -> Self {
        let mut ranges: HashMap<String, Vec<RangeInclusive<u32>>> = HashMap::new();
        for file in &diff.files {
            if file.deleted || file.binary {
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

/// Cap the raw diff text before parsing so a pathologically large fetched diff
/// (many thousands of files, a giant generated blob) cannot drive unbounded
/// parse/allocation work. Truncation happens at a line boundary at or before
/// `max_bytes`; the returned bool reports whether anything was cut so the caller
/// can force the truncation/uncertainty path (a truncated review must never read
/// as a full pass). `max_bytes` is expected to be a generous multiple of the
/// render cap so ordinary diffs are never touched.
pub fn cap_raw_diff(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    // The cap can land inside a multi-byte character; back up to a char
    // boundary before slicing, or the index below panics on non-ASCII input.
    let mut b = max_bytes;
    while b > 0 && !text.is_char_boundary(b) {
        b -= 1;
    }
    // Cut at the last newline at or before the cap so the final retained hunk
    // line stays intact; if there is none, hard-cut at the char boundary.
    let cut = text[..b].rfind('\n').map(|i| i + 1).unwrap_or(b);
    (&text[..cut], true)
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
            let seeded = rest
                .rsplit_once(" b/")
                .map(|(_, b)| b.trim().to_string())
                .unwrap_or_default();
            current = Some(FileDiff {
                path: seeded,
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
            // Keep the old path as a fallback for deletions (+++ /dev/null case).
            if let Some(f) = current.as_mut()
                && f.path.is_empty()
                && rest != "/dev/null"
            {
                f.path = strip_prefix_ab(rest).to_string();
            }
        } else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            if let Some(f) = current.as_mut() {
                f.binary = true;
            }
        } else if let Some(header) = line.strip_prefix("@@ ") {
            flush_hunk(&mut current, &mut current_hunk);
            if let Some((new_start, new_count, old_count)) = parse_hunk_header(header) {
                current_hunk = Some(Hunk {
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
/// (new_start, new_count, old_count). old_count defaults to 1 when the header
/// omits it (single-line hunk) and to 0 when the old side is absent.
fn parse_hunk_header(header: &str) -> Option<(u32, u32, u32)> {
    let count_of = |token: &str| -> Option<u32> {
        let spec = &token[1..];
        match spec.split_once(',') {
            Some((_, c)) => c.parse().ok(),
            None => Some(1),
        }
    };
    let plus = header.split_whitespace().find(|t| t.starts_with('+'))?;
    let spec = &plus[1..];
    let (new_start, new_count) = match spec.split_once(',') {
        Some((s, c)) => (s.parse().ok()?, c.parse().ok()?),
        None => (spec.parse().ok()?, 1),
    };
    let old_count = header
        .split_whitespace()
        .find(|t| t.starts_with('-'))
        .and_then(count_of)
        .unwrap_or(0);
    Some((new_start, new_count, old_count))
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
        assert_eq!(d.files[0].hunks.len(), 1);
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
    fn truncation_is_flagged() {
        let d = parse(SAMPLE);
        let (text, truncated) = render_annotated(&d, 40);
        assert!(truncated);
        assert!(text.contains("[diff truncated"));
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
    fn raw_diff_cap_truncates_at_line_boundary() {
        let big = format!("### header line\n{}", "some diff line\n".repeat(1000));
        let (capped, truncated) = cap_raw_diff(&big, 100);
        assert!(truncated);
        assert!(capped.len() <= 100);
        // Cut on a newline: the retained text ends cleanly, no partial line.
        assert!(capped.ends_with('\n'));
        // Under the cap: untouched.
        let (same, t) = cap_raw_diff("small\n", 100);
        assert!(!t);
        assert_eq!(same, "small\n");
    }

    #[test]
    fn raw_diff_cap_handles_multibyte_at_the_boundary() {
        // No newline anywhere, and the cap lands mid-character: the cut must
        // back up to a char boundary instead of panicking.
        let s = "é".repeat(100); // 2 bytes per char, 200 bytes total
        let (capped, truncated) = cap_raw_diff(&s, 99);
        assert!(truncated);
        assert_eq!(capped.len(), 98);
        assert!(capped.chars().all(|c| c == 'é'));
        // Newline present before a mid-character cap: still cuts on the line.
        let s2 = format!("line one\n{}", "é".repeat(100));
        let (capped2, truncated2) = cap_raw_diff(&s2, 15);
        assert!(truncated2);
        assert_eq!(capped2, "line one\n");
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
        assert_eq!(parse_hunk_header("-1 +5 @@"), Some((5, 1, 1)));
        assert_eq!(parse_hunk_header("-1,2 +3,4 @@"), Some((3, 4, 2)));
        assert_eq!(parse_hunk_header("-0,0 +1,3 @@"), Some((1, 3, 0)));
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
