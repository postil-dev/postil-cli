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
        DiffIndex { ranges }
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

/// Parse a unified diff (git format). Tolerant of mode lines, renames, and
/// "\ No newline at end of file" markers.
pub fn parse(text: &str) -> Diff {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    let mut current_hunk: Option<Hunk> = None;

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
            if let Some((new_start, new_count)) = parse_hunk_header(header) {
                current_hunk = Some(Hunk {
                    new_start,
                    new_count,
                    lines: Vec::new(),
                });
            }
        } else if let Some(h) = current_hunk.as_mut() {
            if line.starts_with(['+', '-', ' ']) || line.is_empty() {
                h.lines.push(line.to_string());
            } else if line.starts_with('\\') {
                // "\ No newline at end of file" — not content.
            } else {
                // Trailer (e.g. next file's "index" line in odd diffs): close hunk.
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

/// "@@ -l,c +l,c @@ ctx" minus the leading "@@ ". Returns (new_start, new_count).
fn parse_hunk_header(header: &str) -> Option<(u32, u32)> {
    let plus = header.split_whitespace().find(|t| t.starts_with('+'))?;
    let spec = &plus[1..];
    let (start, count) = match spec.split_once(',') {
        Some((s, c)) => (s.parse().ok()?, c.parse().ok()?),
        None => (spec.parse().ok()?, 1),
    };
    Some((start, count))
}

/// Render the diff for the model with new-file line numbers on every line that
/// exists on the new side. Deleted lines carry no number (they cannot be cited).
pub fn render_annotated(diff: &Diff, max_bytes: usize) -> (String, bool) {
    let mut out = String::new();
    let mut truncated = false;
    'files: for file in &diff.files {
        if file.binary {
            out.push_str(&format!("### {} (binary, not reviewable)\n", file.path));
            continue;
        }
        if file.deleted {
            out.push_str(&format!("### {} (deleted)\n", file.path));
            continue;
        }
        out.push_str(&format!("### {}\n", file.path));
        for hunk in &file.hunks {
            out.push_str(&format!("@@ starting at line {} @@\n", hunk.new_start));
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
                out.push_str(&rendered);
                if out.len() > max_bytes {
                    truncated = true;
                    break 'files;
                }
            }
        }
        out.push('\n');
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

    #[test]
    fn hunk_header_without_count() {
        assert_eq!(parse_hunk_header("-1 +5 @@"), Some((5, 1)));
        assert_eq!(parse_hunk_header("-1,2 +3,4 @@"), Some((3, 4)));
    }
}
