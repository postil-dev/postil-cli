//! Unified-diff parsing, the grounding index, and prompt-facing rendering.
//!
//! Grounding is the heart of Postil's trust model: a finding is only kept if it
//! cites a (path, line) that actually exists on the new side of the diff. To make
//! the model cite real numbers, the rendered diff annotates every kept/added line
//! with its new-file line number.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;

use anyhow::{Context, Result};
use memmap2::Mmap;

const MAX_LOCKFILE_DIRECTIONAL_CHANGES: usize = 256;
const MAX_LOCKFILE_PACKAGE_RECORDS: usize = 100_000;
/// Maximum size of one buffered forge metadata page. Changed-file bodies use
/// file-backed streaming and are deliberately not subject to this limit.
pub const MAX_FORGE_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const STREAM_WINDOW_BYTES: usize = 2 * 1024 * 1024;
const NORMALIZED_MANIFEST_RESERVE_BYTES: usize = 16 * 1024;

/// Immutable, file-backed diff snapshot. Acquisition writes to disk and review
/// maps it read-only, so aggregate diff size does not become aggregate heap.
pub struct DiffSnapshot {
    _file: File,
    map: Option<Mmap>,
    valid_utf8: bool,
}

impl DiffSnapshot {
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("opening diff snapshot {}", path.display()))?;
        Self::from_file(file)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut spool = DiffSpool::new()?;
        spool.write_all(bytes).context("writing diff snapshot")?;
        spool.finish()
    }

    fn from_file(file: File) -> Result<Self> {
        if file
            .metadata()
            .context("reading diff snapshot metadata")?
            .len()
            == 0
        {
            return Ok(Self {
                _file: file,
                map: None,
                valid_utf8: true,
            });
        }
        // SAFETY: the file handle remains owned by the snapshot and callers
        // receive only an immutable UTF-8 view. Acquisition never mutates a
        // snapshot after this point.
        let map = unsafe { Mmap::map(&file) }.context("mapping diff snapshot")?;
        std::str::from_utf8(&map).context("diff snapshot is not valid UTF-8")?;
        Ok(Self {
            _file: file,
            map: Some(map),
            valid_utf8: true,
        })
    }

    fn from_source_file(file: File) -> Result<Self> {
        if file
            .metadata()
            .context("reading source snapshot metadata")?
            .len()
            == 0
        {
            return Ok(Self {
                _file: file,
                map: None,
                valid_utf8: true,
            });
        }
        // SAFETY: the immutable mapping remains owned by the snapshot.
        let map = unsafe { Mmap::map(&file) }.context("mapping source snapshot")?;
        let valid_utf8 = std::str::from_utf8(&map).is_ok();
        Ok(Self {
            _file: file,
            map: Some(map),
            valid_utf8,
        })
    }

    pub fn as_str(&self) -> &str {
        assert!(self.valid_utf8, "binary source snapshot has no UTF-8 view");
        // Validated once in `from_file`; the immutable mapping cannot change.
        self.map.as_deref().map_or("", |map| {
            // SAFETY: `from_file` validates the complete immutable mapping.
            unsafe { std::str::from_utf8_unchecked(map) }
        })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_none()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.map.as_deref().unwrap_or_default()
    }

    pub fn source_str(&self) -> &str {
        if self.valid_utf8 { self.as_str() } else { "\0" }
    }
}

pub struct DiffSpool {
    file: File,
}

impl DiffSpool {
    pub fn new() -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile().context("creating diff spool")?,
        })
    }

    pub fn finish(mut self) -> Result<DiffSnapshot> {
        self.file.flush().context("flushing diff spool")?;
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding diff spool")?;
        DiffSnapshot::from_file(self.file)
    }

    pub fn finish_source(mut self) -> Result<DiffSnapshot> {
        self.file.flush().context("flushing source spool")?;
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding source spool")?;
        DiffSnapshot::from_source_file(self.file)
    }
}

impl Write for DiffSpool {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

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
    pub changes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GeneratedArtifactEvidence {
    pub path: String,
    pub added: usize,
    pub removed: usize,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct PreparedDiff<'a> {
    pub source: Option<Cow<'a, str>>,
    pub lockfiles: Vec<LockfileEvidence>,
    pub generated_artifacts: Vec<GeneratedArtifactEvidence>,
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

#[derive(Debug)]
pub struct Diff {
    pub files: Vec<FileDiff>,
    pub complete: bool,
}

impl Default for Diff {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            complete: true,
        }
    }
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

    pub fn extend(&mut self, diff: &Diff) {
        let next = Self::build(diff);
        for (path, ranges) in next.ranges {
            self.ranges.entry(path).or_default().extend(ranges);
        }
        for (path, ranges) in next.old_ranges {
            self.old_ranges.entry(path).or_default().extend(ranges);
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

/// Bounded, replayable review input. Each normalized unified-diff window is
/// length-prefixed on disk, while grounding ranges and compact artifact
/// evidence remain in memory.
pub struct PreparedReview {
    windows: File,
    pub index: DiffIndex,
    pub lockfiles: Vec<LockfileEvidence>,
    pub generated_artifacts: Vec<GeneratedArtifactEvidence>,
    pub has_source: bool,
    pub reserved_anchor: bool,
}

impl PreparedReview {
    pub fn rewind(&mut self) -> Result<()> {
        self.windows
            .seek(SeekFrom::Start(0))
            .context("rewinding review windows")?;
        Ok(())
    }

    pub fn next_window(&mut self) -> Result<Option<String>> {
        let mut length = [0u8; 8];
        match self.windows.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error).context("reading review window length"),
        }
        let length = usize::try_from(u64::from_le_bytes(length))
            .context("review window length does not fit this platform")?;
        anyhow::ensure!(
            length <= STREAM_WINDOW_BYTES,
            "review window exceeded its fixed memory bound"
        );
        let mut bytes = vec![0u8; length];
        self.windows
            .read_exact(&mut bytes)
            .context("reading review window")?;
        String::from_utf8(bytes)
            .map(Some)
            .context("normalized review window is not UTF-8")
    }
}

pub struct ModelBatchSpool {
    file: File,
    pub count: usize,
    pub metadata_count: u32,
}

impl ModelBatchSpool {
    pub fn next_batch(&mut self) -> Result<Option<String>> {
        read_length_prefixed(&mut self.file, "model batch")
    }
}

pub fn spool_model_batches(
    prepared: &mut PreparedReview,
    max_batch_bytes: usize,
    max_manifest_bytes: usize,
    force_empty: bool,
) -> Result<ModelBatchSpool> {
    let mut file = tempfile::tempfile().context("creating model-batch spool")?;
    let mut count = 0usize;
    let mut metadata_count = 0u32;
    let synthesis_header = "Cross-window semantic digests:\n";
    let mut cross_window = synthesis_header.to_string();
    let mut digest_ordinal = 0usize;
    prepared.rewind()?;
    while let Some(window) = prepared.next_window()? {
        let parsed = parse(&window);
        anyhow::ensure!(parsed.complete, "normalized review window is incomplete");
        let plan = render_review_batches(&parsed, &[], &[], max_batch_bytes, max_manifest_bytes);
        anyhow::ensure!(
            !plan.incomplete,
            "normalized review window could not be rendered"
        );
        metadata_count = metadata_count.max(plan.metadata_count);
        for batch in plan.batches {
            let digest = semantic_digest(&batch);
            if !digest.is_empty() {
                digest_ordinal = digest_ordinal
                    .checked_add(1)
                    .context("semantic digest ordinal overflowed")?;
                let entry = format!("\nSource window {digest_ordinal}:\n{digest}");
                if cross_window.len().saturating_add(entry.len()) > max_batch_bytes {
                    if cross_window.len() > synthesis_header.len() {
                        write_length_prefixed(
                            &mut file,
                            &cross_window,
                            max_batch_bytes,
                            "cross-window synthesis batch",
                        )?;
                        count = count
                            .checked_add(1)
                            .context("model batch count overflowed")?;
                    }
                    cross_window.clear();
                    cross_window.push_str(synthesis_header);
                }
                anyhow::ensure!(
                    cross_window.len().saturating_add(entry.len()) <= max_batch_bytes,
                    "one semantic digest exceeded the synthesis bound"
                );
                cross_window.push_str(&entry);
            }
            write_length_prefixed(&mut file, &batch, max_batch_bytes, "model batch")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
        }
        if let Some(synthesis) = plan.synthesis {
            write_length_prefixed(&mut file, &synthesis, max_batch_bytes, "model batch")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
        }
    }

    // Artifact evidence is already compact. Partition it so a repository with
    // many lockfiles or bundles cannot overflow one request manifest.
    let mut lock_start = 0usize;
    let mut artifact_start = 0usize;
    while lock_start < prepared.lockfiles.len()
        || artifact_start < prepared.generated_artifacts.len()
    {
        let lock_end = (lock_start + 16).min(prepared.lockfiles.len());
        let artifact_end = (artifact_start + 16).min(prepared.generated_artifacts.len());
        let plan = render_review_batches(
            &Diff::default(),
            &prepared.lockfiles[lock_start..lock_end],
            &prepared.generated_artifacts[artifact_start..artifact_end],
            max_batch_bytes,
            max_manifest_bytes,
        );
        if plan.incomplete {
            anyhow::bail!("compact artifact metadata could not fit a bounded model request");
        }
        metadata_count = metadata_count.max(plan.metadata_count);
        for batch in plan.batches.into_iter().chain(plan.synthesis) {
            write_length_prefixed(&mut file, &batch, max_batch_bytes, "artifact model batch")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
        }
        lock_start = lock_end;
        artifact_start = artifact_end;
    }
    if cross_window.len() > synthesis_header.len() && digest_ordinal > 1 {
        write_length_prefixed(
            &mut file,
            &cross_window,
            max_batch_bytes,
            "cross-window synthesis batch",
        )?;
        count = count
            .checked_add(1)
            .context("model batch count overflowed")?;
    }
    if count == 0 && force_empty {
        write_length_prefixed(&mut file, "", max_batch_bytes, "model batch")?;
        count = 1;
    }
    file.seek(SeekFrom::Start(0))
        .context("rewinding model-batch spool")?;
    Ok(ModelBatchSpool {
        file,
        count,
        metadata_count,
    })
}

fn write_length_prefixed(
    file: &mut File,
    value: &str,
    max_bytes: usize,
    context: &str,
) -> Result<()> {
    anyhow::ensure!(
        value.len() <= max_bytes,
        "{context} exceeded its fixed bound"
    );
    file.write_all(&(value.len() as u64).to_le_bytes())
        .with_context(|| format!("writing {context} length"))?;
    file.write_all(value.as_bytes())
        .with_context(|| format!("writing {context}"))?;
    Ok(())
}

fn read_length_prefixed(file: &mut File, context: &str) -> Result<Option<String>> {
    let mut length = [0u8; 8];
    match file.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {context} length")),
    }
    let length = usize::try_from(u64::from_le_bytes(length))
        .with_context(|| format!("{context} length does not fit this platform"))?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)
        .with_context(|| format!("reading {context}"))?;
    String::from_utf8(bytes)
        .map(Some)
        .with_context(|| format!("{context} is not UTF-8"))
}

pub fn prepare_review(snapshot: &DiffSnapshot) -> Result<PreparedReview> {
    let text = snapshot.as_str();
    let mut windows = tempfile::tempfile().context("creating review-window spool")?;
    let mut index = DiffIndex::default();
    let mut lockfiles = Vec::new();
    let mut generated_artifacts = Vec::new();
    let mut has_source = false;
    let mut reserved_anchor = false;
    let mut pending_window = String::new();
    let mut pending_manifest_bytes = 0usize;
    let Some(mut cursor) = next_diff_start(text, 0) else {
        anyhow::ensure!(text.trim().is_empty(), "review input is not a unified diff");
        return Ok(PreparedReview {
            windows,
            index,
            lockfiles,
            generated_artifacts,
            has_source,
            reserved_anchor,
        });
    };
    anyhow::ensure!(
        text[..cursor].trim().is_empty(),
        "review input has an invalid preamble"
    );
    while cursor < text.len() {
        let end = next_diff_start(text, cursor + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[cursor..end];
        let path = section_path(section).context("review section has an invalid path header")?;
        if is_known_lockfile(&path)
            && let Some(evidence) = lockfile_evidence(&path, section)
        {
            lockfiles.push(evidence);
        } else if is_compactable_generated_artifact(&path) || is_binary_section(section) {
            generated_artifacts.push(generated_artifact_evidence(&path, section));
        } else {
            for_each_section_window(section, STREAM_WINDOW_BYTES, |window| {
                let parsed = parse(window);
                anyhow::ensure!(parsed.complete, "review section is structurally incomplete");
                reserved_anchor |= parsed
                    .files
                    .iter()
                    .any(|file| crate::envelope::is_reserved_anchor(&file.path));
                index.extend(&parsed);
                has_source |= parsed.has_review_evidence();
                let window_manifest_bytes = parsed
                    .files
                    .iter()
                    .try_fold(0usize, |total, file| {
                        total.checked_add(manifest_path(&file.path).len().saturating_add(512))
                    })
                    .context("review-window manifest size overflowed")?;
                if !pending_window.is_empty()
                    && (pending_window.len().saturating_add(window.len()) > STREAM_WINDOW_BYTES
                        || pending_manifest_bytes.saturating_add(window_manifest_bytes)
                            > NORMALIZED_MANIFEST_RESERVE_BYTES)
                {
                    write_window(&mut windows, &pending_window)?;
                    pending_window.clear();
                    pending_manifest_bytes = 0;
                }
                pending_window.push_str(window);
                pending_manifest_bytes = pending_manifest_bytes
                    .checked_add(window_manifest_bytes)
                    .context("review-window manifest size overflowed")?;
                Ok(())
            })?;
        }
        cursor = end;
    }
    if !pending_window.is_empty() {
        write_window(&mut windows, &pending_window)?;
    }
    windows
        .seek(SeekFrom::Start(0))
        .context("rewinding review-window spool")?;
    Ok(PreparedReview {
        windows,
        index,
        lockfiles,
        generated_artifacts,
        has_source,
        reserved_anchor,
    })
}

fn write_window(file: &mut File, window: &str) -> Result<()> {
    anyhow::ensure!(
        window.len() <= STREAM_WINDOW_BYTES,
        "normalized review window exceeded its fixed bound"
    );
    file.write_all(&(window.len() as u64).to_le_bytes())
        .context("writing review window length")?;
    file.write_all(window.as_bytes())
        .context("writing review window")?;
    Ok(())
}

fn is_binary_section(section: &str) -> bool {
    section
        .lines()
        .any(|line| line.starts_with("Binary files ") || line == "GIT binary patch")
}

fn for_each_section_window(
    section: &str,
    max_bytes: usize,
    mut visit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    if section.len() <= max_bytes {
        return visit(section);
    }
    let first_hunk = section
        .find("\n@@ ")
        .map(|offset| offset + 1)
        .context("oversized non-binary diff section has no hunk")?;
    let prefix = &section[..first_hunk];
    anyhow::ensure!(
        prefix.len().saturating_add(128) < max_bytes,
        "diff section metadata is too large to normalize"
    );
    let mut cursor = first_hunk;
    while cursor < section.len() {
        let end = section[cursor + 1..]
            .find("\n@@ ")
            .map(|offset| cursor + 1 + offset + 1)
            .unwrap_or(section.len());
        split_hunk_window(prefix, &section[cursor..end], max_bytes, &mut visit)?;
        cursor = end;
    }
    Ok(())
}

fn split_hunk_window(
    prefix: &str,
    hunk: &str,
    max_bytes: usize,
    visit: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let header_end = hunk.find('\n').context("diff hunk has no body")?;
    let header = hunk[..header_end]
        .strip_prefix("@@ ")
        .context("diff hunk header is malformed")?;
    let (mut old_line, old_count, mut new_line, new_count) =
        parse_hunk_header(header).context("diff hunk range is malformed")?;
    let mut old_seen = 0u32;
    let mut new_seen = 0u32;
    let body_budget = max_bytes.saturating_sub(prefix.len() + 128);
    let mut body = String::new();
    let mut chunk_old_start = old_line;
    let mut chunk_new_start = new_line;
    let mut chunk_old = 0u32;
    let mut chunk_new = 0u32;

    let flush = |body: &mut String,
                 chunk_old_start: u32,
                 chunk_new_start: u32,
                 chunk_old: u32,
                 chunk_new: u32,
                 visit: &mut dyn FnMut(&str) -> Result<()>|
     -> Result<()> {
        if body.is_empty() {
            return Ok(());
        }
        let window = format!(
            "{prefix}@@ -{chunk_old_start},{chunk_old} +{chunk_new_start},{chunk_new} @@ streamed window\n{body}"
        );
        anyhow::ensure!(
            window.len() <= max_bytes,
            "streamed hunk window exceeded its bound"
        );
        visit(&window)?;
        body.clear();
        Ok(())
    };

    for raw in hunk[header_end + 1..].split_inclusive('\n') {
        if raw.starts_with('\\') {
            continue;
        }
        let marker = raw.as_bytes().first().copied().unwrap_or(b' ');
        let consumes_old = marker != b'+';
        let consumes_new = marker != b'-';
        if raw.len() > body_budget {
            flush(
                &mut body,
                chunk_old_start,
                chunk_new_start,
                chunk_old,
                chunk_new,
                visit,
            )?;
            body = String::new();
            chunk_old = 0;
            chunk_new = 0;
            let content = raw.strip_suffix('\n').unwrap_or(raw);
            let (marker_text, content) = content.split_at(content.len().min(1));
            let fragment_budget = body_budget.saturating_sub(marker_text.len() + 1).max(1);
            let mut from = 0usize;
            while from < content.len() {
                let mut to = (from + fragment_budget).min(content.len());
                while !content.is_char_boundary(to) {
                    to -= 1;
                }
                let fragment = &content[from..to];
                let fragment_body = format!("{marker_text}{fragment}\n");
                let window = format!(
                    "{prefix}@@ -{old_line},{} +{new_line},{} @@ streamed line fragment\n{fragment_body}",
                    u32::from(consumes_old),
                    u32::from(consumes_new),
                );
                visit(&window)?;
                from = to;
            }
        } else {
            if body.is_empty() {
                chunk_old_start = old_line;
                chunk_new_start = new_line;
            }
            if !body.is_empty() && body.len().saturating_add(raw.len()) > body_budget {
                flush(
                    &mut body,
                    chunk_old_start,
                    chunk_new_start,
                    chunk_old,
                    chunk_new,
                    visit,
                )?;
                chunk_old_start = old_line;
                chunk_new_start = new_line;
                chunk_old = 0;
                chunk_new = 0;
            }
            body.push_str(raw);
            chunk_old = chunk_old.saturating_add(u32::from(consumes_old));
            chunk_new = chunk_new.saturating_add(u32::from(consumes_new));
        }
        old_seen = old_seen.saturating_add(u32::from(consumes_old));
        new_seen = new_seen.saturating_add(u32::from(consumes_new));
        old_line = old_line.saturating_add(u32::from(consumes_old));
        new_line = new_line.saturating_add(u32::from(consumes_new));
    }
    flush(
        &mut body,
        chunk_old_start,
        chunk_new_start,
        chunk_old,
        chunk_new,
        visit,
    )?;
    anyhow::ensure!(
        old_seen == old_count && new_seen == new_count,
        "diff hunk body does not match its declared range"
    );
    Ok(())
}

/// Compact exact lockfiles and unmistakable build artifacts before parsing.
/// Generated-looking source names such as `client.generated.ts` remain normal
/// untrusted source. Only sourcemaps and minified bundles are summarized.
pub fn prepare_diff(text: &str) -> PreparedDiff<'_> {
    let mut cursor = next_diff_start(text, 0);
    if cursor.is_none() {
        return PreparedDiff {
            source: Some(Cow::Borrowed(text)),
            lockfiles: Vec::new(),
            generated_artifacts: Vec::new(),
            incomplete: false,
        };
    }

    let preamble_len = cursor.unwrap_or(0);
    let mut kept_len = preamble_len;
    let mut lockfiles = Vec::new();
    let mut generated_artifacts = Vec::new();
    let mut compacted = false;
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        let Some(path) = section_path(section) else {
            return PreparedDiff {
                source: None,
                lockfiles: Vec::new(),
                generated_artifacts: Vec::new(),
                incomplete: true,
            };
        };
        if is_known_lockfile(&path) {
            if let Some(evidence) = lockfile_evidence(&path, section) {
                compacted = true;
                lockfiles.push(evidence);
            } else {
                kept_len = kept_len.saturating_add(section.len());
            }
        } else if is_compactable_generated_artifact(&path) {
            compacted = true;
            generated_artifacts.push(generated_artifact_evidence(&path, section));
        } else {
            kept_len = kept_len.saturating_add(section.len());
        }
        cursor = (end < text.len()).then_some(end);
    }

    if !compacted {
        return PreparedDiff {
            source: Some(Cow::Borrowed(text)),
            lockfiles,
            generated_artifacts,
            incomplete: false,
        };
    }

    let mut source = String::with_capacity(kept_len);
    source.push_str(&text[..preamble_len]);
    cursor = next_diff_start(text, 0);
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        let Some(path) = section_path(section) else {
            return PreparedDiff {
                source: None,
                lockfiles: Vec::new(),
                generated_artifacts: Vec::new(),
                incomplete: true,
            };
        };
        let compact_lockfile =
            is_known_lockfile(&path) && lockfile_evidence(&path, section).is_some();
        if !compact_lockfile && !is_compactable_generated_artifact(&path) {
            source.push_str(section);
        }
        cursor = (end < text.len()).then_some(end);
    }
    PreparedDiff {
        source: Some(Cow::Owned(source)),
        lockfiles,
        generated_artifacts,
        incomplete: false,
    }
}

fn is_compactable_generated_artifact(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.ends_with(".map")
        || normalized.ends_with(".min.js")
        || normalized.ends_with(".min.css")
}

fn generated_artifact_evidence(path: &str, section: &str) -> GeneratedArtifactEvidence {
    let mut added = 0usize;
    let mut removed = 0usize;
    for line in section.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            added = added.saturating_add(1);
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed = removed.saturating_add(1);
        }
    }
    GeneratedArtifactEvidence {
        path: path.to_string(),
        added,
        removed,
        bytes: section.len(),
    }
}

fn next_diff_start(text: &str, from: usize) -> Option<usize> {
    let tail = text.get(from..)?;
    if from == 0 && tail.starts_with("diff --git ") {
        return Some(0);
    }
    tail.find("\ndiff --git ").map(|offset| from + offset + 1)
}

fn section_path(section: &str) -> Option<String> {
    section
        .lines()
        .next()
        .and_then(|header| header.strip_prefix("diff --git "))
        .and_then(parse_diff_header_paths)
        .map(|(_, path)| path)
}

fn parse_diff_header_paths(rest: &str) -> Option<(String, String)> {
    if rest.starts_with('"') {
        let (old, remainder) = parse_git_path_token(rest)?;
        let (new, trailing) = parse_git_path_token(remainder.trim_start())?;
        if !trailing.trim().is_empty() {
            return None;
        }
        return Some((
            strip_prefix_ab(&old).to_string(),
            strip_prefix_ab(&new).to_string(),
        ));
    }
    let (old, new) = rest.rsplit_once(" b/")?;
    Some((
        strip_prefix_ab(old).to_string(),
        strip_prefix_ab(new).to_string(),
    ))
}

fn parse_git_path_token(input: &str) -> Option<(String, &str)> {
    if !input.starts_with('"') {
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        return Some((input[..end].to_string(), &input[end..]));
    }
    let bytes = input.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let value = String::from_utf8(decoded).ok()?;
                return Some((value, &input[index + 1..]));
            }
            b'\\' => {
                index += 1;
                let escaped = *bytes.get(index)?;
                match escaped {
                    b'"' | b'\\' => decoded.push(escaped),
                    b't' => decoded.push(b'\t'),
                    b'n' => decoded.push(b'\n'),
                    b'r' => decoded.push(b'\r'),
                    b'0'..=b'7' => {
                        let mut value = (escaped - b'0') as u16;
                        let mut digits = 1;
                        while digits < 3
                            && index + 1 < bytes.len()
                            && matches!(bytes[index + 1], b'0'..=b'7')
                        {
                            index += 1;
                            value = value * 8 + (bytes[index] - b'0') as u16;
                            digits += 1;
                        }
                        decoded.push(u8::try_from(value).ok()?);
                    }
                    _ => return None,
                }
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    None
}

fn parse_git_marker_path(value: &str) -> Option<String> {
    if value == "/dev/null" {
        return Some(value.to_string());
    }
    let (decoded, trailing) = if value.starts_with('"') {
        parse_git_path_token(value)?
    } else {
        (value.split('\t').next()?.to_string(), "")
    };
    if !trailing.trim().is_empty() {
        return None;
    }
    Some(strip_prefix_ab(&decoded).to_string())
}

/// Reversible path spelling used in model prompts. Control characters,
/// quotes, backslashes, and non-ASCII bytes use Git's C-quoted convention so
/// a path can never create a prompt header or line of its own.
pub fn display_path(path: &str) -> String {
    let boundary_whitespace = path
        .as_bytes()
        .first()
        .into_iter()
        .chain(path.as_bytes().last())
        .any(u8::is_ascii_whitespace);
    if !boundary_whitespace
        && path.bytes().all(|byte| {
            byte.is_ascii() && !byte.is_ascii_control() && !matches!(byte, b'"' | b'\\')
        })
    {
        return path.to_string();
    }
    let mut out = String::from("\"");
    for byte in path.as_bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            0x20..=0x7e => out.push(char::from(*byte)),
            _ => out.push_str(&format!("\\{byte:03o}")),
        }
    }
    out.push('"');
    out
}

pub fn canonical_prompt_path(path: &str) -> Option<String> {
    if !path.starts_with('"') {
        return Some(path.to_string());
    }
    let (decoded, trailing) = parse_git_path_token(path)?;
    trailing.trim().is_empty().then_some(decoded)
}

fn prompt_header_path(header: &str) -> &str {
    header
}

fn prompt_paths_equal(left: &str, right: &str) -> bool {
    canonical_prompt_path(left)
        .zip(canonical_prompt_path(right))
        .is_some_and(|(left, right)| left == right)
}

fn lockfile_evidence(path: &str, section: &str) -> Option<LockfileEvidence> {
    let mut added = 0;
    let mut removed = 0;
    for line in section.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            added += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed += 1;
        }
    }
    let old = parse_lockfile_packages(
        path,
        section.lines().filter_map(|line| {
            if line.starts_with('-') && !line.starts_with("---") {
                Some(&line[1..])
            } else {
                line.strip_prefix(' ')
            }
        }),
    )?;
    let new = parse_lockfile_packages(
        path,
        section.lines().filter_map(|line| {
            if line.starts_with('+') && !line.starts_with("+++") {
                Some(&line[1..])
            } else {
                line.strip_prefix(' ')
            }
        }),
    )?;
    let mut changes = Vec::new();
    for package in old.difference(&new).take(MAX_LOCKFILE_DIRECTIONAL_CHANGES) {
        changes.push(format!("removed {package}"));
    }
    let remaining = MAX_LOCKFILE_DIRECTIONAL_CHANGES.saturating_sub(changes.len());
    for package in new.difference(&old).take(remaining) {
        changes.push(format!("added {package}"));
    }
    if changes.is_empty() {
        return None;
    }
    let total_changes = old.difference(&new).count() + new.difference(&old).count();
    if total_changes > changes.len() {
        changes.push(format!(
            "{} additional dependency changes summarized",
            total_changes - changes.len()
        ));
    }
    Some(LockfileEvidence {
        path: path.to_string(),
        added,
        removed,
        changes,
    })
}

fn parse_lockfile_packages<'a>(
    path: &str,
    lines: impl Iterator<Item = &'a str>,
) -> Option<BTreeSet<String>> {
    let name = path.rsplit('/').next()?.to_ascii_lowercase();
    match name.as_str() {
        "cargo.lock" => parse_named_version_records(lines, "name", "version"),
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock_records(lines),
        "yarn.lock" => parse_yarn_records(lines),
        "pnpm-lock.yaml" => parse_pnpm_records(lines),
        "go.sum" => parse_go_sum_records(lines),
        _ => None,
    }
}

fn parse_named_version_records<'a>(
    lines: impl Iterator<Item = &'a str>,
    name_key: &str,
    version_key: &str,
) -> Option<BTreeSet<String>> {
    let mut packages = BTreeSet::new();
    let mut package = None;
    for line in lines {
        let trimmed = line.trim();
        if let Some(value) = parse_assignment(trimmed, name_key) {
            package = Some(value);
        } else if let Some(version) = parse_assignment(trimmed, version_key)
            && let Some(name) = package.take()
        {
            packages.insert(format!("{name}@{version}"));
            if packages.len() > MAX_LOCKFILE_PACKAGE_RECORDS {
                return None;
            }
        }
    }
    (!packages.is_empty()).then_some(packages)
}

fn parse_assignment(line: &str, key: &str) -> Option<String> {
    let value = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    safe_package_atom(value.trim_matches(['"', '\'']))
}

fn safe_package_atom(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 200
        || value.contains("://")
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_string())
}

fn parse_package_lock_records<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Option<BTreeSet<String>> {
    let mut packages = BTreeSet::new();
    let mut package = None;
    for line in lines {
        let trimmed = line.trim().trim_end_matches(',');
        if let Some(path) = trimmed
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix("\": {"))
            .and_then(|value| value.rsplit_once("node_modules/").map(|(_, name)| name))
            .and_then(safe_package_atom)
        {
            package = Some(path);
        } else if let Some(name) = trimmed
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix("\": {"))
            .filter(|name| !matches!(*name, "dependencies" | "packages" | "requires"))
            .and_then(safe_package_atom)
        {
            // npm lockfileVersion 1 stores package records under the
            // dependency name rather than a node_modules path.
            package = Some(name);
        } else if let Some(version) = json_string_field(trimmed, "version")
            && let Some(name) = package.take()
        {
            packages.insert(format!("{name}@{version}"));
            if packages.len() > MAX_LOCKFILE_PACKAGE_RECORDS {
                return None;
            }
        }
    }
    (!packages.is_empty()).then_some(packages)
}

fn json_string_field(line: &str, field: &str) -> Option<String> {
    let prefix = format!("\"{field}\":");
    let value = line.strip_prefix(&prefix)?.trim().trim_end_matches(',');
    safe_package_atom(value.trim_matches('"'))
}

fn parse_yarn_records<'a>(lines: impl Iterator<Item = &'a str>) -> Option<BTreeSet<String>> {
    let mut packages = BTreeSet::new();
    let mut package = None;
    for line in lines {
        if line
            .chars()
            .next()
            .is_some_and(|character| !character.is_whitespace())
            && line.trim_end().ends_with(':')
        {
            let header = line.trim().trim_end_matches(':').trim_matches('"');
            let selector = header.split(',').next()?.trim();
            let name = selector
                .rsplit_once('@')
                .map(|(name, _)| name)
                .unwrap_or(selector);
            package = safe_package_atom(name);
        } else if let Some(version) = line
            .trim()
            .strip_prefix("version ")
            .or_else(|| line.trim().strip_prefix("version:"))
            && let Some(name) = package.take()
            && let Some(version) = safe_package_atom(version.trim().trim_matches('"'))
        {
            packages.insert(format!("{name}@{version}"));
            if packages.len() > MAX_LOCKFILE_PACKAGE_RECORDS {
                return None;
            }
        }
    }
    (!packages.is_empty()).then_some(packages)
}

fn parse_pnpm_records<'a>(lines: impl Iterator<Item = &'a str>) -> Option<BTreeSet<String>> {
    let mut packages = BTreeSet::new();
    for line in lines {
        let value = line.trim().trim_end_matches(':').trim_matches(['\'', '"']);
        if let Some((name, version)) = value.rsplit_once('@')
            && !name.is_empty()
            && version
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
        {
            packages.insert(format!(
                "{}@{}",
                safe_package_atom(name)?,
                safe_package_atom(version)?
            ));
            if packages.len() > MAX_LOCKFILE_PACKAGE_RECORDS {
                return None;
            }
        }
    }
    (!packages.is_empty()).then_some(packages)
}

fn parse_go_sum_records<'a>(lines: impl Iterator<Item = &'a str>) -> Option<BTreeSet<String>> {
    let mut packages = BTreeSet::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let name = safe_package_atom(fields.next()?)?;
        let version = safe_package_atom(fields.next()?)?;
        packages.insert(format!("{name}@{}", version.trim_end_matches("/go.mod")));
        if packages.len() > MAX_LOCKFILE_PACKAGE_RECORDS {
            return None;
        }
    }
    (!packages.is_empty()).then_some(packages)
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
    let mut complete = true;

    let flush_hunk = |file: &mut Option<FileDiff>,
                      hunk: &mut Option<Hunk>,
                      old_left: u32,
                      new_left: u32,
                      complete: &mut bool| {
        if let (Some(f), Some(h)) = (file.as_mut(), hunk.take()) {
            if old_left != 0 || new_left != 0 {
                *complete = false;
            }
            f.hunks.push(h);
        }
    };

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush_hunk(
                &mut current,
                &mut current_hunk,
                old_left,
                new_left,
                &mut complete,
            );
            if let Some(f) = current.take() {
                files.push(f);
            }
            // Seed the path from the header (binary diffs have no +++/--- lines);
            // the +++/--- lines that follow refine it for renames.
            let Some((old_path, path)) = parse_diff_header_paths(rest) else {
                complete = false;
                current = None;
                continue;
            };
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
                } else if let Some(path) = parse_git_marker_path(rest) {
                    f.path = path;
                }
            }
        } else if let Some(rest) = line.strip_prefix("--- ") {
            if let Some(f) = current.as_mut()
                && rest != "/dev/null"
                && let Some(old_path) = parse_git_marker_path(rest)
            {
                f.old_path = old_path;
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
            flush_hunk(
                &mut current,
                &mut current_hunk,
                old_left,
                new_left,
                &mut complete,
            );
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
            } else {
                complete = false;
            }
        } else if let Some(h) = current_hunk.as_mut() {
            // The hunk is complete once every declared old- and new-side line has
            // been consumed. Anything after that (a blank separator, a stray
            // line) belongs to the next file, not this hunk.
            let hunk_complete = old_left == 0 && new_left == 0;
            if !hunk_complete && (line.starts_with(['+', '-', ' ']) || line.is_empty()) {
                // A bare blank line counts as an unchanged (context) line: it is
                // present on both sides.
                let consumed = match line.chars().next() {
                    Some('+') if new_left > 0 => {
                        new_left -= 1;
                        true
                    }
                    Some('-') if old_left > 0 => {
                        old_left -= 1;
                        true
                    }
                    _ => {
                        if old_left == 0 || new_left == 0 {
                            false
                        } else {
                            old_left -= 1;
                            new_left -= 1;
                            true
                        }
                    }
                };
                if !consumed {
                    complete = false;
                }
                h.lines.push(line.to_string());
            } else if line.starts_with('\\') {
                // "\ No newline at end of file" is not content.
            } else {
                // Hunk complete, or a trailer (e.g. next file's "index" line in
                // odd diffs): close the hunk.
                if hunk_complete && line.starts_with(['+', '-', ' ']) {
                    complete = false;
                }
                flush_hunk(
                    &mut current,
                    &mut current_hunk,
                    old_left,
                    new_left,
                    &mut complete,
                );
            }
        }
    }
    flush_hunk(
        &mut current,
        &mut current_hunk,
        old_left,
        new_left,
        &mut complete,
    );
    if let Some(f) = current.take() {
        files.push(f);
    }
    files.retain(|f| !f.path.is_empty());
    Diff { files, complete }
}

fn strip_prefix_ab(path: &str) -> &str {
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
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
        .and_then(range_of)?;
    let (new_start, new_count) = header
        .split_whitespace()
        .find(|t| t.starts_with('+'))
        .and_then(range_of)?;
    old_start.checked_add(old_count.saturating_sub(1))?;
    new_start.checked_add(new_count.saturating_sub(1))?;
    Some((old_start, old_count, new_start, new_count))
}

/// Render the diff for the model with new-file line numbers on every line that
/// exists on the new side. Deleted lines carry no number (they cannot be cited).
pub fn render_annotated(diff: &Diff, max_bytes: usize) -> (String, bool) {
    let mut out = String::new();
    // Append `s`, returning true once the size cap is exceeded. Routing EVERY
    // push through this enforces the cap after each append, headers included. A
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
                &format!(
                    "### {}\n@@ binary, not reviewable @@\n",
                    display_path(&file.path)
                ),
            ) {
                truncated = true;
                break 'files;
            }
            continue;
        }
        if file.deleted {
            if push(
                &mut out,
                &format!("### {}\n@@ deleted @@\n", display_path(&file.path)),
            ) {
                truncated = true;
                break 'files;
            }
            continue;
        }
        if push(&mut out, &format!("### {}\n", display_path(&file.path))) {
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
                        let Some(next) = line_no.checked_add(1) else {
                            truncated = true;
                            break 'files;
                        };
                        line_no = next;
                        s
                    }
                    "-" => format!("       - {content}\n"),
                    _ => {
                        let s = format!("{line_no:>6}   {content}\n");
                        let Some(next) = line_no.checked_add(1) else {
                            truncated = true;
                            break 'files;
                        };
                        line_no = next;
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
    generated_artifacts: &[GeneratedArtifactEvidence],
    max_bytes: usize,
    max_manifest_bytes: usize,
) -> ReviewBatchPlan {
    assert!(
        max_bytes >= 4096,
        "review batch limit must leave room for context"
    );
    let manifest = build_manifest(diff, lockfiles, generated_artifacts, max_manifest_bytes);
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
            let Some(units) =
                render_hunk_units(file, hunk, max_bytes.saturating_sub(manifest.text.len()))
            else {
                plan.incomplete = true;
                return plan;
            };
            for unit in units {
                if !append_unit(&mut plan, &mut current, &manifest.text, &unit, max_bytes) {
                    plan.incomplete = true;
                    return plan;
                }
            }
        }
    }
    if !current.is_empty() {
        plan.batches.push(current);
    } else if plan.batches.is_empty()
        && (!diff.files.is_empty() || !lockfiles.is_empty() || !generated_artifacts.is_empty())
    {
        plan.batches.push(manifest.text.clone());
    }

    if plan.batches.len() > 1 {
        plan.synthesis = build_synthesis(&manifest.text, &plan.batches, max_bytes);
    }
    plan.projected_input_bytes = plan.batches.iter().map(String::len).sum::<usize>()
        + plan.synthesis.as_ref().map_or(0, String::len);
    plan
}

fn build_manifest(
    diff: &Diff,
    lockfiles: &[LockfileEvidence],
    generated_artifacts: &[GeneratedArtifactEvidence],
    max_bytes: usize,
) -> ChangeManifest {
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
        let entry = format!(
            "{}: lockfile changed, {} additions, {} deletions; {}",
            manifest_path(&lockfile.path),
            lockfile.added,
            lockfile.removed,
            lockfile.changes.join("; ")
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
    for artifact in generated_artifacts {
        let manifest_entry = format!(
            "- {} [generated artifact summary]\n",
            manifest_path(&artifact.path)
        );
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
        let entry = format!(
            "{}: generated artifact changed, {} additions, {} deletions, {} raw bytes compacted",
            manifest_path(&artifact.path),
            artifact.added,
            artifact.removed,
            artifact.bytes,
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
    display_path(path)
}

fn render_hunk_units(file: &FileDiff, hunk: &Hunk, budget: usize) -> Option<Vec<String>> {
    let file_header = if file.deleted {
        format!(
            "### {}\n@@ deleted; cite {} metadata line @@\n",
            display_path(&file.path),
            crate::envelope::CHANGE_METADATA_PATH
        )
    } else {
        format!("### {}\n", display_path(&file.path))
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
        let rendered = render_line_segments(marker, content, old_line, new_line);
        for rendered_line in rendered {
            if !segment.is_empty() && segment.len() + rendered_line.len() > segment_budget {
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
            "+" => new_line = new_line.checked_add(1)?,
            "-" => old_line = old_line.checked_add(1)?,
            _ => {
                old_line = old_line.checked_add(1)?;
                new_line = new_line.checked_add(1)?;
            }
        }
    }
    if !segment.is_empty() {
        units.push(format!(
            "{file_header}@@ segment starting near new line {segment_start} @@\n{segment}"
        ));
    }
    Some(units)
}

fn render_line_segments(marker: &str, content: &str, old_line: u32, new_line: u32) -> Vec<String> {
    let prefix = match marker {
        "+" => format!("{new_line:>6} + "),
        "-" => format!("old {old_line:>6} - "),
        _ => format!("{new_line:>6}   "),
    };
    if content.len() <= LINE_CHUNK_BYTES {
        return vec![format!("{prefix}{content}\n")];
    }
    let step = LINE_CHUNK_BYTES.saturating_sub(LINE_CHUNK_OVERLAP).max(1);
    let projected_chunks = content.len().saturating_sub(1) / step + 1;
    let mut rendered = Vec::with_capacity(projected_chunks);
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
    rendered
}

fn append_unit(
    plan: &mut ReviewBatchPlan,
    current: &mut String,
    manifest: &str,
    unit: &str,
    max_bytes: usize,
) -> bool {
    if manifest.len() + unit.len() > max_bytes {
        return false;
    }
    if current.is_empty() {
        current.push_str(manifest);
        current.push('\n');
    }
    if current.len() + unit.len() > max_bytes {
        plan.batches.push(std::mem::take(current));
        current.push_str(manifest);
        current.push('\n');
    }
    current.push_str(unit);
    true
}

fn build_synthesis(manifest: &str, batches: &[String], max_bytes: usize) -> Option<String> {
    let mut synthesis = format!("{manifest}\nCross-batch semantic digests:\n");
    for (index, batch) in batches.iter().enumerate() {
        let digest = semantic_digest(batch);
        if digest.is_empty() {
            return None;
        }
        let heading = format!("\nBatch {} semantic digest:\n", index + 1);
        if synthesis
            .len()
            .saturating_add(heading.len())
            .saturating_add(digest.len())
            > max_bytes
        {
            return None;
        }
        synthesis.push_str(&heading);
        synthesis.push_str(&digest);
    }
    Some(synthesis)
}

fn semantic_digest(batch: &str) -> String {
    const CATEGORIES: [(&str, &[&str]); 6] = [
        (
            "contracts",
            &["fn ", "def ", "class ", "interface ", "type ", "pub "],
        ),
        (
            "sources",
            &["input", "request", "user", "read", "recv", "source"],
        ),
        (
            "sinks",
            &[
                "sink", "exec", "query", "write", "send", "delete", "unsafe", "eval",
            ],
        ),
        (
            "validation",
            &["validate", "sanitize", "authoriz", "check", "guard"],
        ),
        (
            "lifecycle",
            &[
                "create", "close", "drop", "start", "stop", "retry", "commit", "rollback",
            ],
        ),
        (
            "dependencies",
            &["import", "require", "package", "dependency", " use "],
        ),
    ];
    struct Region {
        path: String,
        label: String,
        categories: Vec<Option<String>>,
        fallback: Option<String>,
    }

    fn flush_region(regions: &mut Vec<Region>, current: &mut Option<Region>) {
        if current
            .as_ref()
            .is_some_and(|region| region.fallback.is_some())
        {
            regions.push(current.take().expect("checked above"));
        } else {
            *current = None;
        }
    }

    let mut current_path = None::<String>;
    let mut current_region = None::<Region>;
    let mut regions = Vec::new();
    for rendered in batch.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            flush_region(&mut regions, &mut current_region);
            current_path = Some(prompt_header_path(header).to_string());
            continue;
        }
        if let Some(label) = rendered.strip_prefix("@@ ") {
            flush_region(&mut regions, &mut current_region);
            if let Some(path) = current_path.as_ref() {
                current_region = Some(Region {
                    path: path.clone(),
                    label: label.trim_end_matches(" @@").to_string(),
                    categories: vec![None; CATEGORIES.len()],
                    fallback: None,
                });
            }
            continue;
        }
        let Some(path) = current_path.as_ref() else {
            continue;
        };
        let trimmed = rendered.trim_start();
        let Some((number, content)) = trimmed.split_once(' ') else {
            continue;
        };
        if number.parse::<u32>().is_err() {
            continue;
        }
        let region = current_region.get_or_insert_with(|| Region {
            path: path.clone(),
            label: "source region".to_string(),
            categories: vec![None; CATEGORIES.len()],
            fallback: None,
        });
        let bounded: String = rendered.chars().take(360).collect();
        region.fallback.get_or_insert_with(|| bounded.clone());
        let lower = content.to_ascii_lowercase();
        for (category_index, (_, markers)) in CATEGORIES.iter().enumerate() {
            if region.categories[category_index].is_none()
                && markers.iter().any(|marker| lower.contains(marker))
            {
                region.categories[category_index] = Some(bounded.clone());
            }
        }
    }
    flush_region(&mut regions, &mut current_region);

    let mut out = String::new();
    for region in regions {
        out.push_str(&format!(
            "### {}\n@@ semantic region: {} @@\n",
            region.path, region.label
        ));
        let mut emitted = BTreeSet::new();
        for ((category, _), rendered) in CATEGORIES.iter().zip(region.categories) {
            if let Some(rendered) = rendered
                && emitted.insert(rendered.clone())
            {
                out.push_str(&format!("@@ semantic category={category} @@\n{rendered}\n"));
            }
        }
        if emitted.is_empty()
            && let Some(rendered) = region.fallback
        {
            out.push_str(&format!(
                "@@ semantic category=uncategorized @@\n{rendered}\n"
            ));
        }
    }
    out
}

/// Return the segment that contains a citation in the exact model input.
fn review_batch_segments(annotated: &str, path: &str, line: u32) -> Vec<usize> {
    let mut current_path: Option<&str> = None;
    let mut segment = 0usize;
    let mut matches = Vec::new();
    for rendered in annotated.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            current_path = Some(prompt_header_path(header));
            segment = segment.saturating_add(1);
            continue;
        }
        if rendered.starts_with("@@ ") {
            segment = segment.saturating_add(1);
            continue;
        }
        if !current_path.is_some_and(|current| prompt_paths_equal(current, path)) {
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
            current_path = Some(prompt_header_path(header));
            continue;
        }
        if !current_path.is_some_and(|current| prompt_paths_equal(current, path)) {
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
        display_path(&file.path),
        hunk.new_start
    );
    let mut line_no = hunk.new_start;
    for raw in &hunk.lines {
        let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
        match marker {
            "+" => {
                if (start..=end).contains(&line_no) {
                    out.push_str(&format!("{line_no:>6} + {content}\n"));
                }
                line_no = line_no.checked_add(1)?;
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
                line_no = line_no.checked_add(1)?;
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
 line fourteen
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
    fn empty_snapshot_is_a_valid_review_input() {
        let snapshot = DiffSnapshot::from_bytes(b"").unwrap();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.as_str(), "");
        let prepared = prepare_review(&snapshot).unwrap();
        assert!(!prepared.has_source);
    }

    #[test]
    fn parses_files_hunks_and_kinds() {
        let d = parse(SAMPLE);
        assert!(d.complete);
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
    fn rejects_truncated_and_malformed_hunks() {
        let truncated = parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1,2 +1,2 @@\n-old\n+new\n",
        );
        assert!(!truncated.complete);

        let malformed =
            parse("diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ not-a-range @@\n+new\n");
        assert!(!malformed.complete);

        let overfull = parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -0,0 +1,1 @@\n+one\n+two\n",
        );
        assert!(!overfull.complete);
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
        assert!(text.contains("@@ deleted @@"));
        assert!(text.contains("@@ binary, not reviewable @@"));
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
        let prepared = prepare_diff(source);
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
    fn git_c_quoted_paths_decode_without_losing_identity() {
        let source = "diff --git \"a/src/tab\\tquote\\\"slash\\\\\\346\\227\\245.rs\" \"b/src/tab\\tquote\\\"slash\\\\\\346\\227\\245.rs\"\n--- \"a/src/tab\\tquote\\\"slash\\\\\\346\\227\\245.rs\"\n+++ \"b/src/tab\\tquote\\\"slash\\\\\\346\\227\\245.rs\"\n@@ -0,0 +1 @@\n+safe();\n";
        let parsed = parse(source);
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, "src/tab\tquote\"slash\\日.rs");
        assert_eq!(parsed.files[0].old_path, "src/tab\tquote\"slash\\日.rs");
        let prepared = prepare_diff(source);
        assert!(!prepared.incomplete);
    }

    #[test]
    fn prompt_path_spelling_is_reversible_and_groundable() {
        let canonical = " src/odd (name)\ttab\rbreak\nquote\"slash\\日.rs ";
        let displayed = display_path(canonical);
        assert!(!displayed.contains('\t'));
        assert!(!displayed.contains('\r'));
        assert!(!displayed.contains('\n'));
        assert_eq!(
            canonical_prompt_path(&displayed).as_deref(),
            Some(canonical)
        );

        let batch = format!("### {displayed}\n@@ region @@\n     7 + dangerous_sink(input);\n");
        assert!(review_batch_contains_range(&batch, &displayed, 7, 7));
        assert!(review_batch_contains_range(&batch, canonical, 7, 7));
        assert!(render_review_batch_context(&batch, canonical, 7, 1, 4096).is_some());
    }

    #[test]
    fn semantic_digest_covers_every_region_not_only_early_keyword_hits() {
        let mut batch = String::new();
        for region in 1..=8 {
            batch.push_str(&format!(
                "### src/file_{region}.rs\n@@ region {region} @@\n{region:>6} + {}\n",
                if region == 8 {
                    "dangerous_sink(untrusted_input);"
                } else {
                    "validate_early_value();"
                }
            ));
        }
        let digest = semantic_digest(&batch);
        assert!(digest.contains("src/file_8.rs"));
        assert!(digest.contains("dangerous_sink(untrusted_input)"));
        assert_eq!(digest.matches("@@ semantic region:").count(), 8);
    }

    #[test]
    fn unquoted_paths_with_spaces_and_renames_parse_both_operands() {
        let source = "diff --git a/old name.rs b/new name.rs\nsimilarity index 90%\n--- a/old name.rs\n+++ b/new name.rs\n@@ -1 +1 @@\n-old();\n+new();\n";
        let parsed = parse(source);
        assert_eq!(parsed.files[0].old_path, "old name.rs");
        assert_eq!(parsed.files[0].path, "new name.rs");
    }

    #[test]
    fn only_exact_lockfiles_are_compacted_to_bounded_evidence() {
        let lock = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,3 +1,3 @@\n name = \"dangerous-dependency\"\n-version = \"1.2.2\"\n+version = \"1.2.3\"\n checksum = \"large-hash\"\n";
        let generated = "diff --git a/web/api.generated.ts b/web/api.generated.ts\n--- a/web/api.generated.ts\n+++ b/web/api.generated.ts\n@@ -0,0 +1 @@\n+eval(userInput);\n";
        let mixed = format!("{lock}{generated}");
        let prepared = prepare_diff(&mixed);
        assert_eq!(prepared.lockfiles.len(), 1);
        assert!(!prepared.source.as_deref().unwrap().contains("Cargo.lock"));
        assert!(
            prepared
                .source
                .as_deref()
                .unwrap()
                .contains("eval(userInput)")
        );
        assert_eq!(
            prepared.lockfiles[0].changes,
            [
                "removed dangerous-dependency@1.2.2",
                "added dangerous-dependency@1.2.3"
            ]
        );
    }

    #[test]
    fn malformed_and_unsupported_lockfiles_fall_back_to_source_review() {
        let malformed = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1 +1 @@\n-checksum = \"old\"\n+checksum = \"new\"\n";
        let malformed = prepare_diff(malformed);
        assert!(!malformed.incomplete);
        assert!(malformed.source.as_deref().unwrap().contains("checksum"));
        let unsupported = "diff --git a/composer.lock b/composer.lock\n--- a/composer.lock\n+++ b/composer.lock\n@@ -1 +1 @@\n-old\n+new\n";
        let unsupported = prepare_diff(unsupported);
        assert!(!unsupported.incomplete);
        assert!(
            unsupported
                .source
                .as_deref()
                .unwrap()
                .contains("composer.lock")
        );
    }

    #[test]
    fn supported_lockfile_larger_than_legacy_acquisition_limit_is_compacted() {
        let padding = "x".repeat(32 * 1024 * 1024 + 1);
        let source = format!(
            "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,3 +1,3 @@\n name = \"package-one\"\n-version = \"1.0.0\"\n+version = \"2.0.0\"\n checksum = \"{padding}\"\n"
        );
        let prepared = prepare_diff(&source);
        assert!(!prepared.incomplete);
        assert_eq!(prepared.source.as_deref(), Some(""));
        assert_eq!(prepared.lockfiles[0].changes.len(), 2);
    }

    #[test]
    fn yarn_berry_and_package_lock_v1_have_directional_evidence() {
        let yarn = "diff --git a/yarn.lock b/yarn.lock\n--- a/yarn.lock\n+++ b/yarn.lock\n@@ -1,2 +1,2 @@\n \"@scope/pkg@npm:^1.0.0\":\n-  version: 1.0.0\n+  version: 1.1.0\n";
        let yarn = prepare_diff(yarn);
        assert_eq!(
            yarn.lockfiles[0].changes,
            ["removed @scope/pkg@1.0.0", "added @scope/pkg@1.1.0"]
        );

        let npm = "diff --git a/package-lock.json b/package-lock.json\n--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1,3 +1,3 @@\n \"left-pad\": {\n-  \"version\": \"1.0.0\"\n+  \"version\": \"1.1.0\"\n";
        let npm = prepare_diff(npm);
        assert_eq!(
            npm.lockfiles[0].changes,
            ["removed left-pad@1.0.0", "added left-pad@1.1.0"]
        );
    }

    #[test]
    fn oversized_source_line_is_segmented_through_its_tail() {
        let tail = "TAIL_DEFECT_eval(user_input)";
        let source = format!(
            "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n+{}{tail}\n",
            "x".repeat(40_000)
        );
        let parsed = parse(&source);
        let plan = render_review_batches(&parsed, &[], &[], 24_000, 4096);
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
        let plan = render_review_batches(&parsed, &[], &[], 32_000, 4096);
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
    fn hunk_header_rejects_u32_coordinate_overflow() {
        assert_eq!(parse_hunk_header("-1 +4294967295,2 @@"), None);
        assert_eq!(parse_hunk_header("-4294967295,2 +1 @@"), None);
        let parsed = parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1 +4294967295,2 @@\n+x\n+y\n",
        );
        assert!(parsed.files[0].hunks.is_empty());
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
