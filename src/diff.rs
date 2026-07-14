//! Unified-diff parsing, the grounding index, and prompt-facing rendering.
//!
//! Grounding is the heart of Postil's trust model: a finding is only kept if it
//! cites a (path, line) that actually exists on the new side of the diff. To make
//! the model cite real numbers, the rendered diff annotates every kept/added line
//! with its new-file line number.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::RangeInclusive;

const MAX_LOCKFILE_EVIDENCE_SECTIONS: usize = 1024;

#[derive(Debug, Default)]
pub struct ReviewBatchPlan {
    pub batches: Vec<String>,
    pub synthesis: Option<String>,
    pub incomplete: bool,
    pub projected_input_bytes: usize,
    pub metadata_count: u32,
}

#[derive(Debug, Clone)]
pub struct LockfileEvidence {
    pub path: String,
    pub added: usize,
    pub removed: usize,
    pub samples: Vec<String>,
}

#[derive(Debug)]
pub struct PreparedDiff<'a> {
    pub source: Option<Cow<'a, str>>,
    pub lockfiles: Vec<LockfileEvidence>,
    pub incomplete: bool,
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
    pub old_mode: Option<String>,
    pub new_mode: Option<String>,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Default)]
pub struct Diff {
    pub files: Vec<FileDiff>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.files
            .iter()
            .all(|file| file.binary || file.hunks.is_empty())
    }

    /// True when the model has source hunks or numbered non-line metadata to
    /// review. Binary, deletion, rename, and mode-only changes are evidence
    /// even though they remain empty under the legacy source-hunk predicate.
    pub fn has_review_evidence(&self) -> bool {
        !self.files.is_empty()
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

    pub fn add_change_metadata(&mut self, count: u32) {
        if count > 0 {
            self.ranges.insert(
                crate::envelope::CHANGE_METADATA_PATH.to_string(),
                vec![1..=count],
            );
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

/// Compact exact, known lockfile sections before parsing while retaining
/// bounded dependency-oriented evidence for the model. Every other path,
/// including names such as `generated`, `dist`, and `node_modules`, remains
/// ordinary untrusted source. The source-size check happens before allocation.
pub fn prepare_diff(text: &str, max_source_bytes: usize) -> PreparedDiff<'_> {
    let mut cursor = next_diff_start(text, 0);
    if cursor.is_none() {
        return PreparedDiff {
            source: (text.len() <= max_source_bytes).then_some(Cow::Borrowed(text)),
            lockfiles: Vec::new(),
            incomplete: text.len() > max_source_bytes,
        };
    }

    let preamble_len = cursor.unwrap_or(0);
    let mut kept_len = preamble_len;
    let mut lockfiles = Vec::new();
    let mut saw_lockfile = false;
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        let path = section_path(section);
        if is_known_lockfile(path) {
            saw_lockfile = true;
            lockfiles.push(lockfile_evidence(path, section));
            if lockfiles.len() > MAX_LOCKFILE_EVIDENCE_SECTIONS {
                return PreparedDiff {
                    source: None,
                    lockfiles: Vec::new(),
                    incomplete: true,
                };
            }
        } else {
            kept_len = kept_len.saturating_add(section.len());
        }
        cursor = (end < text.len()).then_some(end);
    }

    if kept_len > max_source_bytes {
        return PreparedDiff {
            source: None,
            lockfiles,
            incomplete: true,
        };
    }
    if !saw_lockfile {
        return PreparedDiff {
            source: Some(Cow::Borrowed(text)),
            lockfiles,
            incomplete: false,
        };
    }

    let mut source = String::with_capacity(kept_len);
    source.push_str(&text[..preamble_len]);
    cursor = next_diff_start(text, 0);
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        if !is_known_lockfile(section_path(section)) {
            source.push_str(section);
        }
        cursor = (end < text.len()).then_some(end);
    }
    PreparedDiff {
        source: Some(Cow::Owned(source)),
        lockfiles,
        incomplete: false,
    }
}

fn next_diff_start(text: &str, from: usize) -> Option<usize> {
    let tail = text.get(from..)?;
    if from == 0 && tail.starts_with("diff --git ") {
        return Some(0);
    }
    tail.find("\ndiff --git ").map(|offset| from + offset + 1)
}

fn section_path(section: &str) -> &str {
    section
        .lines()
        .next()
        .and_then(|header| header.strip_prefix("diff --git "))
        .and_then(|rest| rest.rsplit_once(" b/").map(|(_, path)| path))
        .unwrap_or_default()
}

fn lockfile_evidence(path: &str, section: &str) -> LockfileEvidence {
    let mut added = 0;
    let mut removed = 0;
    let mut samples = Vec::new();
    for line in section.lines() {
        let content = if line.starts_with('+') && !line.starts_with("+++") {
            added += 1;
            &line[1..]
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed += 1;
            &line[1..]
        } else {
            continue;
        };
        if samples.len() < 24
            && let Some(sample) = safe_lockfile_sample(content)
        {
            samples.push(sample);
        }
    }
    LockfileEvidence {
        path: path.to_string(),
        added,
        removed,
        samples,
    }
}

/// Keep only package-name and version fields. Lockfiles can contain registry
/// URLs and credentials, so arbitrary changed lines never enter model input.
fn safe_lockfile_sample(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let lower = trimmed.to_ascii_lowercase();
    let dependency_field = lower.starts_with("name ")
        || lower.starts_with("name=")
        || lower.starts_with("version ")
        || lower.starts_with("version=")
        || lower.starts_with("\"name\"")
        || lower.starts_with("\"version\"");
    let sensitive = [
        "token",
        "auth",
        "password",
        "secret",
        "api_key",
        "apikey",
        "credential",
        "private_key",
        "access_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let long_token = trimmed
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| part.len() > 40);
    if !dependency_field
        || sensitive
        || long_token
        || lower.contains("://")
        || lower.contains("git@")
        || lower.contains("ssh:")
    {
        return None;
    }
    Some(trimmed.chars().take(200).collect())
}

pub fn is_known_lockfile(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    matches!(
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
    )
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
                old_mode: None,
                new_mode: None,
                hunks: Vec::new(),
            });
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            if let Some(f) = current.as_mut() {
                f.old_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            if let Some(f) = current.as_mut() {
                f.new_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            if let Some(f) = current.as_mut() {
                f.new_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if let Some(f) = current.as_mut() {
                f.old_mode = Some(mode.to_string());
            }
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

const HUNK_OVERLAP_LINES: usize = 6;
const LINE_CHUNK_BYTES: usize = 16_000;
const LINE_CHUNK_OVERLAP: usize = 256;

struct ChangeManifest {
    text: String,
    metadata_count: u32,
    incomplete: bool,
}

/// Render every change type into a bounded number of bounded requests. Batches
/// split at file or hunk-segment boundaries and repeat a compact changed-file
/// manifest. Oversized hunks overlap, and oversized lines are segmented with
/// overlap so no unseen tail can produce a clean verdict.
pub fn render_review_batches(
    diff: &Diff,
    lockfiles: &[LockfileEvidence],
    max_bytes: usize,
    max_batches: usize,
    max_manifest_bytes: usize,
) -> ReviewBatchPlan {
    assert!(
        max_bytes >= 4096,
        "review batch limit must leave room for context"
    );
    let manifest = build_manifest(diff, lockfiles, max_manifest_bytes);
    let mut plan = ReviewBatchPlan {
        incomplete: manifest.incomplete || manifest.text.len() >= max_bytes,
        metadata_count: manifest.metadata_count,
        ..Default::default()
    };
    if plan.incomplete {
        return plan;
    }

    let mut current = String::new();
    for file in &diff.files {
        if file.binary || file.hunks.is_empty() {
            continue;
        }
        for hunk in &file.hunks {
            let Some(units) = render_hunk_units(
                file,
                hunk,
                max_bytes.saturating_sub(manifest.text.len()),
                max_batches.saturating_mul(16),
            ) else {
                plan.incomplete = true;
                return plan;
            };
            for unit in units {
                if !append_unit(
                    &mut plan,
                    &mut current,
                    &manifest.text,
                    &unit,
                    max_bytes,
                    max_batches,
                ) {
                    plan.incomplete = true;
                    return plan;
                }
            }
        }
    }
    if !current.is_empty() {
        if plan.batches.len() >= max_batches {
            plan.incomplete = true;
            return plan;
        }
        plan.batches.push(current);
    } else if plan.batches.is_empty() && (!diff.files.is_empty() || !lockfiles.is_empty()) {
        plan.batches.push(manifest.text.clone());
    }

    if plan.batches.len() > 1 {
        plan.synthesis = build_synthesis(&manifest.text, &plan.batches, max_bytes);
        if plan.synthesis.is_none() {
            plan.incomplete = true;
        }
    }
    plan.projected_input_bytes = plan.batches.iter().map(String::len).sum::<usize>()
        + plan.synthesis.as_ref().map_or(0, String::len);
    plan
}

fn build_manifest(diff: &Diff, lockfiles: &[LockfileEvidence], max_bytes: usize) -> ChangeManifest {
    let mut text = String::from("Changed-file manifest:\n");
    let mut metadata = Vec::new();
    let mut metadata_bytes = 0usize;
    for file in &diff.files {
        let renamed = file.old_path != file.path;
        let mode_changed =
            file.old_mode != file.new_mode && (file.old_mode.is_some() || file.new_mode.is_some());
        let status = if file.deleted {
            "deleted"
        } else if file.binary {
            "binary"
        } else if renamed {
            "renamed"
        } else if mode_changed {
            "mode changed"
        } else {
            "source"
        };
        let entry = format!("- {} [{status}]\n", manifest_path(&file.path));
        if text
            .len()
            .saturating_add(entry.len())
            .saturating_add(metadata_bytes)
            > max_bytes
        {
            return ChangeManifest {
                text,
                metadata_count: 0,
                incomplete: true,
            };
        }
        text.push_str(&entry);
        let mut changes = Vec::new();
        if file.deleted {
            changes.push("deleted".to_string());
        }
        if file.binary {
            changes.push("binary content changed".to_string());
        }
        if renamed {
            changes.push(format!("renamed from {}", manifest_path(&file.old_path)));
        }
        if mode_changed {
            changes.push(format!(
                "mode {} -> {}",
                file.old_mode.as_deref().unwrap_or("unknown"),
                file.new_mode.as_deref().unwrap_or("unknown")
            ));
        }
        if !changes.is_empty() {
            let entry = format!("{}: {}", manifest_path(&file.path), changes.join(", "));
            metadata_bytes = metadata_bytes.saturating_add(entry.len() + 16);
            if text.len().saturating_add(metadata_bytes) > max_bytes {
                return ChangeManifest {
                    text,
                    metadata_count: 0,
                    incomplete: true,
                };
            }
            metadata.push(entry);
        }
    }
    for lockfile in lockfiles {
        let manifest_entry = format!("- {} [lockfile summary]\n", manifest_path(&lockfile.path));
        if text
            .len()
            .saturating_add(manifest_entry.len())
            .saturating_add(metadata_bytes)
            > max_bytes
        {
            return ChangeManifest {
                text,
                metadata_count: 0,
                incomplete: true,
            };
        }
        text.push_str(&manifest_entry);
        let samples = if lockfile.samples.is_empty() {
            "no dependency-oriented lines after hash filtering".to_string()
        } else {
            lockfile.samples.join(" | ")
        };
        let entry = format!(
            "{}: lockfile changed, {} additions, {} deletions; {}",
            manifest_path(&lockfile.path),
            lockfile.added,
            lockfile.removed,
            samples
        );
        metadata_bytes = metadata_bytes.saturating_add(entry.len() + 16);
        if text.len().saturating_add(metadata_bytes) > max_bytes {
            return ChangeManifest {
                text,
                metadata_count: 0,
                incomplete: true,
            };
        }
        metadata.push(entry);
    }
    let metadata_count = metadata.len() as u32;
    if !metadata.is_empty() {
        text.push_str(&format!(
            "\n### {}\n@@ metadata segment @@\n",
            crate::envelope::CHANGE_METADATA_PATH
        ));
        for (index, line) in metadata.into_iter().enumerate() {
            text.push_str(&format!("{:>6} + {line}\n", index + 1));
        }
    }
    ChangeManifest {
        incomplete: text.len() > max_bytes,
        text,
        metadata_count,
    }
}

fn manifest_path(path: &str) -> String {
    path.replace(['\r', '\n'], " ").chars().take(240).collect()
}

fn render_hunk_units(
    file: &FileDiff,
    hunk: &Hunk,
    budget: usize,
    max_units: usize,
) -> Option<Vec<String>> {
    let file_header = if file.deleted {
        format!(
            "### {} (deleted; cite {} metadata line)\n",
            file.path,
            crate::envelope::CHANGE_METADATA_PATH
        )
    } else {
        format!("### {}\n", file.path)
    };
    let header_reserve = file_header.len() + 80;
    let segment_budget = budget.saturating_sub(header_reserve).max(1024);
    let mut units = Vec::new();
    let mut segment = String::new();
    let mut overlap: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut old_line = hunk.old_start;
    let mut new_line = hunk.new_start;
    let mut segment_start = new_line;

    for raw in &hunk.lines {
        let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
        let rendered = render_line_segments(marker, content, old_line, new_line, max_units)?;
        for rendered_line in rendered {
            if !segment.is_empty() && segment.len() + rendered_line.len() > segment_budget {
                if units.len() >= max_units {
                    return None;
                }
                units.push(format!(
                    "{file_header}@@ segment starting near new line {segment_start} @@\n{segment}"
                ));
                segment = overlap.iter().cloned().collect();
                while segment.len() + rendered_line.len() > segment_budget {
                    if overlap.pop_front().is_none() {
                        break;
                    }
                    segment = overlap.iter().cloned().collect();
                }
                segment_start = new_line;
            }
            segment.push_str(&rendered_line);
            overlap.push_back(rendered_line);
            while overlap.len() > HUNK_OVERLAP_LINES {
                overlap.pop_front();
            }
        }
        match marker {
            "+" => new_line = new_line.saturating_add(1),
            "-" => old_line = old_line.saturating_add(1),
            _ => {
                old_line = old_line.saturating_add(1);
                new_line = new_line.saturating_add(1);
            }
        }
    }
    if !segment.is_empty() {
        if units.len() >= max_units {
            return None;
        }
        units.push(format!(
            "{file_header}@@ segment starting near new line {segment_start} @@\n{segment}"
        ));
    }
    Some(units)
}

fn render_line_segments(
    marker: &str,
    content: &str,
    old_line: u32,
    new_line: u32,
    max_chunks: usize,
) -> Option<Vec<String>> {
    let prefix = match marker {
        "+" => format!("{new_line:>6} + "),
        "-" => format!("old {old_line:>6} - "),
        _ => format!("{new_line:>6}   "),
    };
    if content.len() <= LINE_CHUNK_BYTES {
        return Some(vec![format!("{prefix}{content}\n")]);
    }
    let step = LINE_CHUNK_BYTES.saturating_sub(LINE_CHUNK_OVERLAP).max(1);
    let projected_chunks = content.len().saturating_sub(1) / step + 1;
    if projected_chunks > max_chunks {
        return None;
    }
    let mut rendered = Vec::new();
    let mut start = 0;
    while start < content.len() {
        let mut end = (start + LINE_CHUNK_BYTES).min(content.len());
        while end > start && !content.is_char_boundary(end) {
            end -= 1;
        }
        rendered.push(format!(
            "{prefix}[columns {start}..{end}] {}\n",
            &content[start..end]
        ));
        if end == content.len() {
            break;
        }
        let mut next = end.saturating_sub(LINE_CHUNK_OVERLAP);
        while next < end && !content.is_char_boundary(next) {
            next += 1;
        }
        start = next;
    }
    Some(rendered)
}

fn append_unit(
    plan: &mut ReviewBatchPlan,
    current: &mut String,
    manifest: &str,
    unit: &str,
    max_bytes: usize,
    max_batches: usize,
) -> bool {
    if manifest.len() + unit.len() > max_bytes {
        return false;
    }
    if current.is_empty() {
        current.push_str(manifest);
        current.push('\n');
    }
    if current.len() + unit.len() > max_bytes {
        if plan.batches.len() >= max_batches {
            return false;
        }
        plan.batches.push(std::mem::take(current));
        current.push_str(manifest);
        current.push('\n');
    }
    current.push_str(unit);
    true
}

fn build_synthesis(manifest: &str, batches: &[String], max_bytes: usize) -> Option<String> {
    let mut synthesis = format!("{manifest}\nCross-batch evidence excerpts:\n");
    let available = max_bytes.checked_sub(synthesis.len() + 256)?;
    let per_batch = available.checked_div(batches.len())?;
    if per_batch < 512 {
        return None;
    }
    for (index, batch) in batches.iter().enumerate() {
        synthesis.push_str(&format!("\nBatch {} excerpt:\n", index + 1));
        let body = batch.strip_prefix(manifest).unwrap_or(batch).trim_start();
        synthesis.push_str(&batch_excerpt(body, per_batch));
    }
    (synthesis.len() <= max_bytes).then_some(synthesis)
}

fn batch_excerpt(body: &str, budget: usize) -> String {
    if body.len() <= budget {
        return body.to_string();
    }
    let marker = "\n[excerpt gap]\n";
    let half = budget.saturating_sub(marker.len()) / 2;
    let first_limit = floor_char_boundary(body, half.min(body.len()));
    let first_end = body[..first_limit]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let tail_target = body.len().saturating_sub(half);
    let tail_target = floor_char_boundary(body, tail_target);
    let header_from = body[..tail_target]
        .rfind("\n### ")
        .map(|index| index + 1)
        .or_else(|| {
            body[tail_target..]
                .find('\n')
                .map(|index| tail_target + index + 1)
        })
        .unwrap_or(body.len());
    let mut out = body[..first_end].to_string();
    out.push_str(marker);
    out.push_str(&body[header_from..]);
    if out.len() > budget {
        let limit = floor_char_boundary(&out, budget);
        let line_end = out[..limit].rfind('\n').map(|index| index + 1).unwrap_or(0);
        out.truncate(line_end);
    }
    out
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Return the segment that contains a citation in the exact model input.
fn review_batch_segments(annotated: &str, path: &str, line: u32) -> Vec<usize> {
    let mut current_path: Option<&str> = None;
    let mut segment = 0usize;
    let mut matches = Vec::new();
    for rendered in annotated.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            current_path = Some(header.split(" (").next().unwrap_or(header).trim());
            segment = segment.saturating_add(1);
            continue;
        }
        if rendered.starts_with("@@ ") || rendered == "[excerpt gap]" {
            segment = segment.saturating_add(1);
            continue;
        }
        if current_path != Some(path) {
            continue;
        }
        let Some((number, _)) = rendered.trim_start().split_once(' ') else {
            continue;
        };
        if number.parse::<u32>().ok() == Some(line) {
            matches.push(segment);
        }
    }
    matches
}

pub fn review_batch_contains_range(annotated: &str, path: &str, start: u32, end: u32) -> bool {
    start <= end
        && review_batch_segments(annotated, path, start)
            .iter()
            .any(|start_segment| {
                review_batch_segments(annotated, path, end).contains(start_segment)
            })
}

/// Render a bounded local window around a citation from the exact evidence a
/// review request saw. This also covers synthetic change-metadata anchors that
/// do not exist in the parsed new-side diff.
pub fn render_review_batch_context(
    annotated: &str,
    path: &str,
    line: u32,
    radius: usize,
    max_bytes: usize,
) -> Option<String> {
    let lines: Vec<&str> = annotated.lines().collect();
    let mut current_path: Option<&str> = None;
    let mut target = None;
    for (index, rendered) in lines.iter().enumerate() {
        if let Some(header) = rendered.strip_prefix("### ") {
            current_path = Some(header.split(" (").next().unwrap_or(header).trim());
            continue;
        }
        if current_path != Some(path) {
            continue;
        }
        let Some((number, _)) = rendered.trim_start().split_once(' ') else {
            continue;
        };
        if number.parse::<u32>().ok() == Some(line) {
            target = Some(index);
            break;
        }
    }
    let target = target?;
    let start = target.saturating_sub(radius);
    let end = (target + radius + 1).min(lines.len());
    let mut out = String::new();
    for rendered in &lines[start..end] {
        let required = rendered.len().saturating_add(1);
        if out.len().saturating_add(required) > max_bytes {
            break;
        }
        out.push_str(rendered);
        out.push('\n');
    }
    (!out.is_empty()).then_some(out)
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
    fn generated_named_source_is_reviewed_as_untrusted_code() {
        let source = "diff --git a/src/client.generated.ts b/src/client.generated.ts\n--- a/src/client.generated.ts\n+++ b/src/client.generated.ts\n@@ -0,0 +1 @@\n+eval(userInput);\n";
        let prepared = prepare_diff(source, 4096);
        assert!(!prepared.incomplete);
        assert!(
            prepared
                .source
                .as_deref()
                .unwrap()
                .contains("eval(userInput)")
        );
        assert!(prepared.lockfiles.is_empty());
    }

    #[test]
    fn only_exact_lockfiles_are_compacted_to_bounded_evidence() {
        let credential_marker = ["pass", "word"].concat();
        let scheme = ["ht", "tps"].concat();
        let user = ["us", "er"].concat();
        let token_key = ["auth", "token"].join("_");
        let token_marker = ["do", "not", "send"].join("-");
        let long_marker = "a".repeat(48);
        let lock = format!(
            "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -0,0 +1,6 @@\n+name = \"dangerous-dependency\"\n+checksum = \"large-hash\"\n+version = \"1.2.3\"\n+name = \"{scheme}://{user}:{credential_marker}@example.invalid/package\"\n+{token_key} = \"{token_marker}\"\n+version = \"{long_marker}\"\n"
        );
        let generated = "diff --git a/web/api.generated.ts b/web/api.generated.ts\n--- a/web/api.generated.ts\n+++ b/web/api.generated.ts\n@@ -0,0 +1 @@\n+eval(userInput);\n";
        let mixed = format!("{lock}{generated}");
        let prepared = prepare_diff(&mixed, 4096);
        assert_eq!(prepared.lockfiles.len(), 1);
        assert!(!prepared.source.as_deref().unwrap().contains("Cargo.lock"));
        assert!(
            prepared
                .source
                .as_deref()
                .unwrap()
                .contains("eval(userInput)")
        );
        assert!(
            prepared.lockfiles[0]
                .samples
                .iter()
                .any(|sample| sample.contains("dangerous-dependency"))
        );
        assert!(
            prepared.lockfiles[0]
                .samples
                .iter()
                .all(|sample| !sample.contains("checksum"))
        );
        let samples = prepared.lockfiles[0].samples.join("\n");
        assert!(!samples.contains(&credential_marker));
        assert!(!samples.contains(&token_marker));
        assert!(!samples.contains(&long_marker));
    }

    #[test]
    fn oversized_source_line_is_segmented_through_its_tail() {
        let tail = "TAIL_DEFECT_eval(user_input)";
        let source = format!(
            "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n+{}{tail}\n",
            "x".repeat(40_000)
        );
        let parsed = parse(&source);
        let plan = render_review_batches(&parsed, &[], 24_000, 8, 4096);
        assert!(!plan.incomplete);
        assert!(plan.batches.iter().any(|batch| batch.contains(tail)));
        assert!(plan.batches.iter().all(|batch| batch.len() <= 24_000));
    }

    #[test]
    fn batch_grounding_requires_both_range_endpoints_in_one_segment() {
        let batch = "### src/a.rs\n@@ first @@\n    10 + first\n    11 + second\n@@ second @@\n    20 + third\n";
        assert!(review_batch_contains_range(batch, "src/a.rs", 10, 11));
        assert!(!review_batch_contains_range(batch, "src/a.rs", 10, 20));
        assert!(!review_batch_contains_range(batch, "src/a.rs", 10, 21));
        assert!(!review_batch_contains_range(batch, "src/b.rs", 10, 10));
    }

    #[test]
    fn deletion_binary_rename_and_mode_changes_get_numbered_metadata() {
        let source = "diff --git a/src/auth.rs b/src/auth.rs\ndeleted file mode 100644\n--- a/src/auth.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-require_admin();\ndiff --git a/logo.bin b/logo.bin\nold mode 100644\nnew mode 100755\nBinary files a/logo.bin and b/logo.bin differ\ndiff --git a/old.rs b/new.rs\nsimilarity index 100%\nrename from old.rs\nrename to new.rs\n";
        let parsed = parse(source);
        let plan = render_review_batches(&parsed, &[], 32_000, 4, 4096);
        assert!(!plan.incomplete);
        assert_eq!(plan.metadata_count, 3);
        let rendered = plan.batches.join("\n");
        assert!(rendered.contains("require_admin"));
        assert!(rendered.contains("binary content changed"));
        assert!(rendered.contains("mode 100644 -> 100755"));
        assert!(rendered.contains("renamed from old.rs"));
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
                old_mode: None,
                new_mode: None,
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
