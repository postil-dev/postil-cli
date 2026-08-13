//! Unified-diff parsing, the grounding index, and prompt-facing rendering.
//!
//! Grounding is the heart of Postil's trust model: a finding is only kept if it
//! cites a (path, line) that actually exists on the new side of the diff. To make
//! the model cite real numbers, the rendered diff annotates every kept/added line
//! with its new-file line number.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use memmap2::Mmap;
use sha2::{Digest, Sha256};

const MAX_LOCKFILE_DIRECTIONAL_CHANGES: usize = 256;
const MAX_LOCKFILE_PACKAGE_RECORDS: usize = 100_000;
/// Maximum size of one buffered forge metadata page. Changed-file bodies use
/// file-backed streaming and are deliberately not subject to this limit.
pub const MAX_FORGE_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const STREAM_WINDOW_BYTES: usize = 2 * 1024 * 1024;
/// Aggregate on-disk review workspace bound. The original snapshot, normalized
/// windows, and planned model batches must all fit before provider contact.
pub const MAX_REVIEW_SPOOL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DIFF_INDEX_PATHS: usize = 100_000;
const MAX_DIFF_INDEX_RANGES: usize = 250_000;
const NORMALIZED_MANIFEST_RESERVE_BYTES: usize = 16 * 1024;
/// Smallest batch that preserves source framing, planner evidence, and
/// recursive semantic synthesis. Provider admission applies separate exact
/// serialized-request and model-context bounds before rendering.
pub(crate) const MIN_REVIEW_BATCH_BYTES: usize = 4 * 1024;

#[derive(Clone)]
pub struct WorkspaceBudget {
    retained: Arc<Mutex<u64>>,
    limit: u64,
}

impl Default for WorkspaceBudget {
    fn default() -> Self {
        Self {
            retained: Arc::new(Mutex::new(0)),
            limit: MAX_REVIEW_SPOOL_BYTES,
        }
    }
}

impl WorkspaceBudget {
    pub fn new() -> Self {
        Self::default()
    }

    fn reserve(&self, bytes: u64) -> std::io::Result<()> {
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| std::io::Error::other("review workspace budget lock is poisoned"))?;
        let next = retained
            .checked_add(bytes)
            .ok_or_else(|| std::io::Error::other("review workspace size overflowed"))?;
        if next > self.limit {
            return Err(std::io::Error::other(format!(
                "review workspace exceeded the {} byte operation quota",
                self.limit
            )));
        }
        *retained = next;
        Ok(())
    }

    fn release(&self, bytes: u64) {
        if let Ok(mut retained) = self.retained.lock() {
            *retained = retained.saturating_sub(bytes);
        }
    }

    #[cfg(test)]
    pub fn retained_bytes(&self) -> u64 {
        *self.retained.lock().unwrap()
    }

    #[cfg(test)]
    pub fn with_limit(limit: u64) -> Self {
        Self {
            retained: Arc::new(Mutex::new(0)),
            limit,
        }
    }
}

struct WorkspaceLease {
    budget: WorkspaceBudget,
    bytes: u64,
}

impl WorkspaceLease {
    fn new(budget: WorkspaceBudget) -> Self {
        Self { budget, bytes: 0 }
    }

    fn reserve(&mut self, bytes: u64) -> std::io::Result<()> {
        self.budget.reserve(bytes)?;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    fn release(&mut self, bytes: u64) {
        self.budget.release(bytes);
        self.bytes = self.bytes.saturating_sub(bytes);
    }
}

impl Drop for WorkspaceLease {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// Immutable, file-backed diff snapshot. Acquisition writes to disk and review
/// maps it read-only, so aggregate diff size does not become aggregate heap.
pub struct DiffSnapshot {
    _file: File,
    map: Option<Mmap>,
    valid_utf8: bool,
    lease: WorkspaceLease,
}

impl DiffSnapshot {
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let mut source = File::open(path)
            .with_context(|| format!("opening diff snapshot {}", path.display()))?;
        let mut spool = DiffSpool::new()?;
        std::io::copy(&mut source, &mut spool)
            .with_context(|| format!("copying diff snapshot {}", path.display()))?;
        spool.finish()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut spool = DiffSpool::new()?;
        spool.write_all(bytes).context("writing diff snapshot")?;
        spool.finish()
    }

    pub fn from_bytes_in(bytes: &[u8], budget: WorkspaceBudget) -> Result<Self> {
        let mut spool = DiffSpool::new_in(budget)?;
        spool.write_all(bytes).context("writing diff snapshot")?;
        spool.finish()
    }

    fn from_file(file: File, lease: WorkspaceLease) -> Result<Self> {
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
                lease,
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
            lease,
        })
    }

    fn from_source_file(file: File, lease: WorkspaceLease) -> Result<Self> {
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
                lease,
            });
        }
        // SAFETY: the immutable mapping remains owned by the snapshot.
        let map = unsafe { Mmap::map(&file) }.context("mapping source snapshot")?;
        let valid_utf8 = std::str::from_utf8(&map).is_ok();
        Ok(Self {
            _file: file,
            map: Some(map),
            valid_utf8,
            lease,
        })
    }

    pub fn as_str(&self) -> &str {
        assert!(self.valid_utf8, "binary source snapshot has no UTF-8 view");
        std::str::from_utf8(self.as_bytes())
            .expect("private immutable diff snapshot was validated as UTF-8")
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_none()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.map.as_deref().unwrap_or_default()
    }

    pub fn len(&self) -> u64 {
        self.map.as_ref().map_or(0, |map| map.len() as u64)
    }

    pub fn source_str(&self) -> &str {
        if self.valid_utf8 { self.as_str() } else { "\0" }
    }

    pub fn workspace_budget(&self) -> WorkspaceBudget {
        self.lease.budget.clone()
    }
}

pub struct DiffSpool {
    file: File,
    written: u64,
    lease: Option<WorkspaceLease>,
}

impl DiffSpool {
    pub fn new() -> Result<Self> {
        Self::new_in(WorkspaceBudget::new())
    }

    pub fn new_in(budget: WorkspaceBudget) -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile().context("creating diff spool")?,
            written: 0,
            lease: Some(WorkspaceLease::new(budget)),
        })
    }

    pub fn finish(mut self) -> Result<DiffSnapshot> {
        self.file.flush().context("flushing diff spool")?;
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding diff spool")?;
        DiffSnapshot::from_file(
            self.file,
            self.lease.take().expect("unfinished spool owns its lease"),
        )
    }

    pub fn finish_source(mut self) -> Result<DiffSnapshot> {
        self.file.flush().context("flushing source spool")?;
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding source spool")?;
        DiffSnapshot::from_source_file(
            self.file,
            self.lease.take().expect("unfinished spool owns its lease"),
        )
    }
}

impl Write for DiffSpool {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| std::io::Error::other("diff spool size overflowed"))?;
        let lease = self
            .lease
            .as_mut()
            .expect("unfinished spool owns its lease");
        lease.reserve(buffer.len() as u64)?;
        let written = match self.file.write(buffer) {
            Ok(written) => written,
            Err(error) => {
                lease.release(buffer.len() as u64);
                return Err(error);
            }
        };
        lease.release((buffer.len() - written) as u64);
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug, Default)]
pub struct ReviewBatchPlan {
    pub batches: Vec<String>,
    batch_hunks: Vec<BTreeSet<HunkIdentity>>,
    pub synthesis: Option<String>,
    pub incomplete: bool,
    pub projected_input_bytes: usize,
    pub metadata_count: u32,
}

/// Stable identity for one hunk after forge input has been normalized into a
/// structurally complete review window. The digest distinguishes split hunks
/// that retain the same coordinate anchor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HunkIdentity {
    pub path: String,
    pub old_start: u32,
    pub old_count: u32,
    pub new_start: u32,
    pub new_count: u32,
    digest: [u8; 32],
}

impl HunkIdentity {
    fn new(path: &str, hunk: &Hunk) -> Self {
        let mut hasher = Sha256::new();
        for line in &hunk.lines {
            hasher.update((line.len() as u64).to_le_bytes());
            hasher.update(line.as_bytes());
        }
        Self {
            path: path.to_string(),
            old_start: hunk.old_start,
            old_count: hunk.old_count,
            new_start: hunk.new_start,
            new_count: hunk.new_count,
            digest: hasher.finalize().into(),
        }
    }

    fn canonical(&self) -> String {
        let digest = self
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.path, self.old_start, self.old_count, self.new_start, self.new_count, digest
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HunkDisposition {
    Direct { batch_ids: Vec<usize> },
    Semantic { summary_batch_ids: Vec<usize> },
    Unreviewed { reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkCoverageEntry {
    pub hunk: HunkIdentity,
    pub disposition: HunkDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCoverageReceipt {
    pub plan_sha256: String,
    pub entries: Vec<HunkCoverageEntry>,
    pub selected_batch_ids: BTreeSet<usize>,
}

impl BoundedCoverageReceipt {
    pub fn direct_hunks(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.disposition, HunkDisposition::Direct { .. }))
            .count()
    }

    pub fn unreviewed_hunks(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.disposition, HunkDisposition::Unreviewed { .. }))
            .count()
    }

    pub fn semantic_hunks(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.disposition, HunkDisposition::Semantic { .. }))
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct LockfileEvidence {
    pub path: String,
    pub added: usize,
    pub removed: usize,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompactedArtifactEvidence {
    pub path: String,
    pub kind: &'static str,
    pub added: usize,
    pub removed: usize,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct PreparedDiff<'a> {
    pub source: Option<Cow<'a, str>>,
    pub lockfiles: Vec<LockfileEvidence>,
    pub compacted_artifacts: Vec<CompactedArtifactEvidence>,
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
#[derive(Debug, Clone)]
pub struct DiffIndex {
    ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    old_ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    range_count: usize,
    complete: bool,
    /// Reserved synthetic-path line ranges that only content-policy findings may
    /// ground against (e.g. the rendered PR title/description). Kept separate
    /// from `ranges` so a non-content-policy finding cannot exploit them.
    content_policy_ranges: HashMap<String, RangeInclusive<u32>>,
    new_evidence: HashMap<(String, u32), String>,
    old_evidence: HashMap<(String, u32), String>,
    content_policy_evidence: HashMap<(String, u32), String>,
    rendered_evidence: HashMap<(String, u32), Vec<String>>,
    rendered_old_coordinates: HashSet<(String, u32)>,
    rendered_exact_ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    rendered_exact_old_ranges: HashMap<String, Vec<RangeInclusive<u32>>>,
    /// Old-to-new paths for files renamed by the reviewed change. Baseline
    /// findings cite the old head, so reconciliation must follow an unchanged
    /// evidence line represented in the diff across a rename instead of
    /// expiring or misplacing it.
    renamed_paths: HashMap<String, String>,
}

impl Default for DiffIndex {
    fn default() -> Self {
        Self {
            ranges: HashMap::new(),
            old_ranges: HashMap::new(),
            range_count: 0,
            complete: true,
            content_policy_ranges: HashMap::new(),
            new_evidence: HashMap::new(),
            old_evidence: HashMap::new(),
            content_policy_evidence: HashMap::new(),
            rendered_evidence: HashMap::new(),
            rendered_old_coordinates: HashSet::new(),
            rendered_exact_ranges: HashMap::new(),
            rendered_exact_old_ranges: HashMap::new(),
            renamed_paths: HashMap::new(),
        }
    }
}

impl DiffIndex {
    fn selected_exact_line(
        ranges: &HashMap<String, Vec<RangeInclusive<u32>>>,
        path: &str,
        line: u32,
    ) -> bool {
        ranges
            .get(path)
            .is_some_and(|ranges| ranges.iter().any(|range| range.contains(&line)))
    }

    pub fn build(diff: &Diff) -> Self {
        let mut index = Self::default();
        for file in &diff.files {
            if !file.deleted && file.old_path != file.path {
                index
                    .renamed_paths
                    .insert(file.old_path.clone(), file.path.clone());
            }
            if file.binary {
                continue;
            }
            for hunk in &file.hunks {
                if hunk.old_count > 0 {
                    index.insert_range(file.old_path.clone(), hunk.old_range(), true);
                }
            }
            if !file.deleted {
                for hunk in &file.hunks {
                    if hunk.new_count > 0 {
                        index.insert_range(file.path.clone(), hunk.new_range(), false);
                    }
                }
            }
            for hunk in &file.hunks {
                let mut old_line = hunk.old_start;
                let mut new_line = hunk.new_start;
                for raw in &hunk.lines {
                    let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
                    match marker {
                        "+" => {
                            index
                                .new_evidence
                                .insert((file.path.clone(), new_line), content.to_string());
                            new_line = new_line.saturating_add(1);
                        }
                        "-" => {
                            index
                                .old_evidence
                                .insert((file.old_path.clone(), old_line), content.to_string());
                            old_line = old_line.saturating_add(1);
                        }
                        _ => {
                            index
                                .new_evidence
                                .insert((file.path.clone(), new_line), content.to_string());
                            index
                                .old_evidence
                                .insert((file.old_path.clone(), old_line), content.to_string());
                            old_line = old_line.saturating_add(1);
                            new_line = new_line.saturating_add(1);
                        }
                    }
                }
            }
        }
        index
    }

    pub fn extend(&mut self, diff: &Diff) {
        let next = Self::build(diff);
        for (path, ranges) in next.ranges {
            for range in ranges {
                self.insert_range(path.clone(), range, false);
            }
        }
        for (path, ranges) in next.old_ranges {
            for range in ranges {
                self.insert_range(path.clone(), range, true);
            }
        }
        self.new_evidence.extend(next.new_evidence);
        self.old_evidence.extend(next.old_evidence);
        self.rendered_old_coordinates
            .extend(next.rendered_old_coordinates);
        self.renamed_paths.extend(next.renamed_paths);
    }

    fn insert_range(&mut self, path: String, range: RangeInclusive<u32>, old: bool) {
        if !self.complete {
            return;
        }
        let exists = if old {
            self.old_ranges.contains_key(&path)
        } else {
            self.ranges.contains_key(&path)
        };
        if !exists
            && self.ranges.len().saturating_add(self.old_ranges.len()) >= MAX_DIFF_INDEX_PATHS
        {
            self.complete = false;
            return;
        }
        let map = if old {
            &mut self.old_ranges
        } else {
            &mut self.ranges
        };
        let ranges = map.entry(path).or_default();
        if let Some(last) = ranges.last_mut()
            && range.start() <= &last.end().saturating_add(1)
        {
            let end = (*last.end()).max(*range.end());
            *last = *last.start()..=end;
            return;
        }
        if self.range_count >= MAX_DIFF_INDEX_RANGES {
            self.complete = false;
            return;
        }
        ranges.push(range);
        self.range_count += 1;
    }

    pub fn is_complete(&self) -> bool {
        self.complete
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

    pub fn add_content_policy_evidence(&mut self, path: &str, rendered: &str) {
        self.add_content_policy_path(path, rendered.lines().count() as u32);
        for line in rendered.lines() {
            let Some((number, marked)) = line.trim_start().split_once(' ') else {
                continue;
            };
            let Ok(number) = number.parse::<u32>() else {
                continue;
            };
            if let Some(content) = marked.strip_prefix("  ") {
                self.content_policy_evidence
                    .insert((path.to_string(), number), content.to_string());
            }
        }
    }

    pub fn add_rendered_evidence(&mut self, rendered: &str) {
        let exact_semantic = is_exact_semantic_batch(rendered);
        let mut current_path = None::<String>;
        for line in rendered.lines() {
            if let Some(header) = line.strip_prefix("### ") {
                current_path = Some(prompt_header_path(header).to_string());
                continue;
            }
            let Some(path) = current_path.as_ref() else {
                continue;
            };
            if let Some(old) = line.strip_prefix("old ")
                && let Some((number, marked)) = old.split_once(' ')
                && let Ok(number) = number.parse::<u32>()
            {
                if exact_semantic {
                    let Some(end_line) = marked
                        .strip_prefix("- ")
                        .and_then(|payload| exact_semantic_evidence_end_line(payload, number))
                    else {
                        continue;
                    };
                    self.rendered_exact_old_ranges
                        .entry(path.clone())
                        .or_default()
                        .push(number..=end_line);
                } else {
                    self.rendered_old_coordinates.insert((path.clone(), number));
                }
                continue;
            }
            let Some((number, marked)) = line.trim_start().split_once(' ') else {
                continue;
            };
            let Ok(number) = number.parse::<u32>() else {
                continue;
            };
            let Some(content) = marked
                .strip_prefix("+ ")
                .or_else(|| marked.strip_prefix("  "))
                .filter(|content| !content.trim().is_empty())
            else {
                continue;
            };
            if exact_semantic {
                let Some(end_line) = exact_semantic_evidence_end_line(content, number) else {
                    continue;
                };
                self.rendered_exact_ranges
                    .entry(path.clone())
                    .or_default()
                    .push(number..=end_line);
                continue;
            }
            let evidence = self
                .rendered_evidence
                .entry((path.clone(), number))
                .or_default();
            if !evidence.iter().any(|existing| existing == content) {
                evidence.push(content.to_string());
            }
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

    pub fn contains_exact_evidence(&self, finding: &crate::envelope::Finding) -> bool {
        let Some(evidence) = finding
            .evidence
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            return false;
        };
        self.rendered_evidence
            .get(&(finding.path.clone(), finding.line))
            .is_some_and(|values| values.iter().any(|actual| actual == evidence))
            || self
                .new_evidence
                .get(&(finding.path.clone(), finding.line))
                .or_else(|| {
                    (finding.kind == crate::envelope::Kind::ContentPolicy)
                        .then(|| {
                            self.content_policy_evidence
                                .get(&(finding.path.clone(), finding.line))
                        })
                        .flatten()
                })
                .is_some_and(|actual| actual == evidence)
    }

    pub fn old_evidence_matches(&self, finding: &crate::envelope::Finding) -> bool {
        finding.evidence.as_ref().is_some_and(|evidence| {
            self.old_evidence
                .get(&(finding.path.clone(), finding.line))
                .is_some_and(|actual| actual == evidence)
        })
    }

    fn nearest_evidence_anchor<'a, I>(
        finding: &crate::envelope::Finding,
        candidates: I,
    ) -> Option<(String, u32)>
    where
        I: IntoIterator<Item = (&'a (String, u32), &'a String)>,
    {
        let evidence = finding.evidence.as_deref()?;
        candidates
            .into_iter()
            .filter(|((path, _), actual)| path == &finding.path && actual.as_str() == evidence)
            .map(|((path, line), _)| (path.clone(), *line))
            .min_by_key(|(path, line)| {
                (
                    (path != &finding.path) as u8,
                    line.abs_diff(finding.line),
                    *line,
                )
            })
    }

    /// Locate the baseline's exact evidence in the current reviewed head.
    /// Duplicate text resolves deterministically to the nearest line, and a
    /// pure rename follows the new path.
    pub fn remap_current_evidence(
        &self,
        finding: &crate::envelope::Finding,
    ) -> Option<(String, u32)> {
        let current_path = self
            .renamed_paths
            .get(&finding.path)
            .unwrap_or(&finding.path);
        let mut candidate = finding.clone();
        candidate.path.clone_from(current_path);
        Self::nearest_evidence_anchor(&candidate, self.new_evidence.iter()).or_else(|| {
            Self::nearest_evidence_anchor(&candidate, self.content_policy_evidence.iter())
        })
    }

    /// Locate exact baseline evidence that a selected model request actually
    /// contained. A bounded full review may resolve a reproduced anchor only
    /// when that anchor was inside its reviewed evidence.
    pub fn remap_reviewed_evidence(
        &self,
        finding: &crate::envelope::Finding,
    ) -> Option<(String, u32)> {
        let evidence = finding.evidence.as_deref()?;
        let current_path = self
            .renamed_paths
            .get(&finding.path)
            .unwrap_or(&finding.path);
        let mut candidates = self
            .rendered_evidence
            .iter()
            .filter(|((path, _), values)| {
                path == current_path && values.iter().any(|actual| actual == evidence)
            })
            .map(|((path, line), _)| (path.clone(), *line))
            .collect::<Vec<_>>();
        candidates.extend(
            self.new_evidence
                .iter()
                .filter(|((path, line), actual)| {
                    path == current_path
                        && actual.as_str() == evidence
                        && Self::selected_exact_line(&self.rendered_exact_ranges, path, *line)
                })
                .map(|((path, line), _)| (path.clone(), *line)),
        );
        if finding.kind == crate::envelope::Kind::ContentPolicy {
            candidates.extend(
                self.content_policy_evidence
                    .iter()
                    .filter(|((path, _), actual)| path == current_path && *actual == evidence)
                    .map(|((path, line), _)| (path.clone(), *line)),
            );
        }
        candidates.into_iter().min_by_key(|(path, line)| {
            (
                (path != &finding.path) as u8,
                line.abs_diff(finding.line),
                *line,
            )
        })
    }

    /// True only when a selected model request contained the baseline's exact
    /// old coordinate or the corresponding current coordinate. This lets a
    /// completed bounded review resolve changed evidence it actually saw while
    /// keeping changed evidence outside the selected requests open.
    pub fn contains_reviewed_baseline_coordinate(
        &self,
        finding: &crate::envelope::Finding,
    ) -> bool {
        let current_path = self
            .renamed_paths
            .get(&finding.path)
            .unwrap_or(&finding.path);
        if self
            .rendered_old_coordinates
            .contains(&(finding.path.clone(), finding.line))
            || self
                .rendered_old_coordinates
                .contains(&(current_path.clone(), finding.line))
            || Self::selected_exact_line(
                &self.rendered_exact_old_ranges,
                &finding.path,
                finding.line,
            )
            || Self::selected_exact_line(
                &self.rendered_exact_old_ranges,
                current_path,
                finding.line,
            )
        {
            return true;
        }
        self.rendered_evidence
            .keys()
            .any(|(path, line)| path == current_path && *line == finding.line)
            || Self::selected_exact_line(&self.rendered_exact_ranges, current_path, finding.line)
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

    /// New-side lines on `path` whose canonical text contains `needle`, in
    /// ascending order. This is the same text the model was shown, so a lookup
    /// answers "where in this file does the construct the finding names
    /// actually appear" without re-reading the worktree.
    ///
    /// The comparison ignores case. Callers use this to decide whether to
    /// distrust a finding, so a case difference between prose and source must
    /// count as corroboration rather than as evidence against the anchor.
    pub fn new_side_lines_containing(&self, path: &str, needle: &str) -> Vec<u32> {
        if needle.is_empty() {
            return Vec::new();
        }
        let needle = needle.to_ascii_lowercase();
        let mut lines: Vec<u32> = self
            .new_evidence
            .iter()
            .filter(|((candidate, _), text)| {
                candidate == path && text.to_ascii_lowercase().contains(&needle)
            })
            .map(|((_, line), _)| *line)
            .collect();
        lines.sort_unstable();
        lines
    }

    /// True when the diff carries any new-side text for `path`. A path with no
    /// new-side coverage cannot corroborate or contradict an anchor.
    pub fn has_new_side_text(&self, path: &str) -> bool {
        self.new_evidence
            .keys()
            .any(|(candidate, _)| candidate == path)
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
    _window_lease: WorkspaceLease,
    snapshot_bytes: u64,
    window_bytes: u64,
    pub index: DiffIndex,
    pub lockfiles: Vec<LockfileEvidence>,
    pub compacted_artifacts: Vec<CompactedArtifactEvidence>,
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
    _lease: WorkspaceLease,
    pub count: usize,
    pub source_count: usize,
    pub metadata_count: u32,
    synthesis_ids: BTreeSet<usize>,
    exact_semantic_ids: BTreeSet<usize>,
    batch_hunks: HashMap<usize, BTreeSet<HunkIdentity>>,
    all_hunks: BTreeSet<HunkIdentity>,
    hunk_risk: HashMap<HunkIdentity, HunkRisk>,
    metadata_batch_ids: BTreeSet<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRequestPlan {
    pub plan_sha256: String,
    pub direct_hunks: usize,
    pub selected_batches: usize,
    pub total_batches: usize,
}

#[derive(Debug, Clone, Copy)]
struct HunkRisk {
    mandatory: bool,
    semantic_eligible: bool,
    score: usize,
}

pub struct HostedBatchCandidates {
    pub manifest: String,
    pub mandatory_ids: Vec<usize>,
    pub candidate_ids: BTreeSet<usize>,
    pub source_batch_count: usize,
}

const MAX_HOSTED_PLANNER_MANIFEST_BYTES: usize = 80 * 1024;

fn sanitize_planner_evidence(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push('\n'),
            '\t' | '\r' => output.push(' '),
            '"' => output.push('\''),
            '\\' => output.push('/'),
            character if character.is_control() => output.push(' '),
            character => output.push(character),
        }
    }
    output
}

impl ModelBatchSpool {
    pub fn next_batch(&mut self) -> Result<Option<String>> {
        read_length_prefixed(&mut self.file, "model batch")
    }

    /// Stable identity for the complete provider-request inventory. Reviews
    /// without a deterministic bounded receipt register this exhaustive plan
    /// before any planner, review, or scorer request reaches the worker proxy.
    pub fn durable_request_plan(&mut self) -> Result<DurableRequestPlan> {
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches for durable plan registration")?;
        let plan = (|| -> Result<DurableRequestPlan> {
            let mut hasher = Sha256::new();
            hasher.update(b"postil-durable-request-plan-v1\0");
            let mut batch_id = 0usize;
            while let Some(batch) = read_length_prefixed(&mut self.file, "durable plan batch")? {
                batch_id = batch_id
                    .checked_add(1)
                    .context("durable plan batch id overflowed")?;
                hasher.update((batch_id as u64).to_le_bytes());
                hasher.update((batch.len() as u64).to_le_bytes());
                hasher.update(batch.as_bytes());
            }
            anyhow::ensure!(
                batch_id == self.count,
                "durable plan batch inventory changed during registration"
            );
            Ok(DurableRequestPlan {
                plan_sha256: hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                direct_hunks: self.all_hunks.len(),
                selected_batches: batch_id,
                total_batches: batch_id,
            })
        })();
        let rewind = self
            .file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches after durable plan registration");
        let plan = plan?;
        rewind?;
        Ok(plan)
    }

    pub fn hosted_candidates(
        &mut self,
        selected_limit: usize,
        candidate_limit: usize,
    ) -> Result<HostedBatchCandidates> {
        anyhow::ensure!(
            selected_limit >= 5 && candidate_limit >= selected_limit,
            "hosted planning needs capacity for boundary, synthesis, and independent risk evidence"
        );
        #[derive(Clone)]
        struct Candidate {
            id: usize,
            score: usize,
            removal_score: usize,
            digest: String,
            synthesis: bool,
        }

        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches for hosted planning")?;
        let mut candidates = Vec::<Candidate>::new();
        let mut first_source = None;
        let mut last_source = None;
        let mut final_synthesis = None;
        let mut highest_removal = None::<Candidate>;
        let mut id = 0usize;
        while let Some(batch) = read_length_prefixed(&mut self.file, "hosted planner batch")? {
            id = id
                .checked_add(1)
                .context("hosted planner batch id overflowed")?;
            if self.exact_semantic_ids.contains(&id) {
                continue;
            }
            let synthesis = self.synthesis_ids.contains(&id);
            if synthesis {
                final_synthesis = Some(id);
            } else {
                first_source.get_or_insert(id);
                last_source = Some(id);
            }
            let mut digest = semantic_digest(&batch);
            if digest.is_empty() {
                digest = batch.chars().take(800).collect();
            } else {
                digest = compact_planner_digest(digest, 1_200)?;
            }
            digest = sanitize_planner_evidence(&digest);
            let candidate = Candidate {
                id,
                score: hosted_risk_score(&batch),
                removal_score: hosted_removal_risk_score(&batch),
                digest,
                synthesis,
            };
            if !candidate.synthesis
                && candidate.removal_score > 0
                && highest_removal.as_ref().is_none_or(|current| {
                    candidate.removal_score > current.removal_score
                        || (candidate.removal_score == current.removal_score
                            && candidate.id < current.id)
                })
            {
                highest_removal = Some(candidate.clone());
            }
            candidates.push(candidate);
            candidates.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| left.id.cmp(&right.id))
            });
            candidates.truncate(candidate_limit);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches after hosted planning")?;

        if let Some(candidate) = highest_removal.as_ref()
            && !candidates.iter().any(|current| current.id == candidate.id)
        {
            candidates.push(candidate.clone());
            candidates.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| left.id.cmp(&right.id))
            });
            if candidates.len() > candidate_limit {
                let removable = candidates
                    .iter()
                    .rposition(|current| current.id != candidate.id)
                    .expect("candidate limit retains the highest-risk removal");
                candidates.remove(removable);
            }
        }

        let mut mandatory = BTreeSet::new();
        if let Some(id) = first_source {
            mandatory.insert(id);
        }
        if let Some(id) = last_source {
            mandatory.insert(id);
        }
        if let Some(id) = final_synthesis {
            mandatory.insert(id);
        }
        if let Some(candidate) = candidates.iter().find(|candidate| !candidate.synthesis) {
            mandatory.insert(candidate.id);
        }
        if let Some(candidate) = highest_removal {
            mandatory.insert(candidate.id);
        }
        debug_assert!(mandatory.len() <= selected_limit);

        let mut manifest = format!(
            "The complete diff was normalized into {id} bounded batches. Select only batch IDs from this candidate set. Boundary, highest-risk, and global-synthesis batches are already mandatory.\nMandatory IDs: {:?}\n",
            mandatory.iter().copied().collect::<Vec<_>>()
        );
        let mut candidate_ids = BTreeSet::new();
        for candidate in &candidates {
            let entry = format!(
                "\nBatch {} risk={} kind={}\n{}",
                candidate.id,
                candidate.score,
                if candidate.synthesis {
                    "synthesis"
                } else {
                    "source"
                },
                candidate.digest
            );
            if manifest.len().saturating_add(entry.len()) > MAX_HOSTED_PLANNER_MANIFEST_BYTES {
                continue;
            }
            manifest.push_str(&entry);
            candidate_ids.insert(candidate.id);
        }
        anyhow::ensure!(
            manifest.len() <= MAX_HOSTED_PLANNER_MANIFEST_BYTES,
            "hosted planner manifest exceeded its fixed bound"
        );
        Ok(HostedBatchCandidates {
            manifest,
            mandatory_ids: mandatory.into_iter().collect(),
            candidate_ids,
            source_batch_count: self.source_count,
        })
    }

    pub fn selected_source_count(&self, ids: &BTreeSet<usize>) -> usize {
        ids.iter()
            .filter(|id| !self.synthesis_ids.contains(id) || self.exact_semantic_ids.contains(id))
            .count()
    }

    pub fn selected_batches(&mut self, ids: &BTreeSet<usize>) -> Result<Vec<String>> {
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches for selection")?;
        let mut selected = Vec::with_capacity(ids.len());
        let mut id = 0usize;
        while let Some(batch) = read_length_prefixed(&mut self.file, "selected model batch")? {
            id += 1;
            if ids.contains(&id) {
                selected.push(batch);
            }
        }
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches after selection")?;
        anyhow::ensure!(
            selected.len() == ids.len(),
            "hosted planner selected a batch outside the materialized spool"
        );
        Ok(selected)
    }

    fn batch_text_by_id(&mut self, ids: &BTreeSet<usize>) -> Result<HashMap<usize, String>> {
        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches for coverage validation")?;
        let batches = (|| -> Result<HashMap<usize, String>> {
            let mut selected = HashMap::new();
            let mut id = 0usize;
            while let Some(batch) = read_length_prefixed(&mut self.file, "coverage batch")? {
                id = id.checked_add(1).context("coverage batch id overflowed")?;
                if ids.contains(&id) {
                    selected.insert(id, batch);
                }
            }
            anyhow::ensure!(
                selected.len() == ids.len(),
                "coverage receipt selected a batch outside the materialized spool"
            );
            Ok(selected)
        })();
        let rewind = self
            .file
            .seek(SeekFrom::Start(0))
            .context("rewinding model batches after coverage validation");
        let batches = batches?;
        rewind?;
        Ok(batches)
    }

    /// Build the large-diff route without a provider-side planning call. Every
    /// normalized hunk receives exactly one receipt disposition. Mandatory
    /// security, control-plane, dependency, and executable-vendor evidence is
    /// admitted first; remaining capacity is filled by stable risk and path
    /// order. A mandatory hunk that cannot fit fails before provider contact.
    pub fn deterministic_bounded_receipt(
        &mut self,
        selected_limit: usize,
    ) -> Result<BoundedCoverageReceipt> {
        anyhow::ensure!(
            selected_limit > 0,
            "bounded review batch limit must be positive"
        );
        #[derive(Debug)]
        struct RankedHunk {
            hunk: HunkIdentity,
            direct_batch_ids: BTreeSet<usize>,
            semantic_batch_ids: BTreeSet<usize>,
            mandatory: bool,
            semantic_eligible: bool,
            score: usize,
        }

        let mut ranked = self
            .all_hunks
            .iter()
            .cloned()
            .map(|hunk| {
                let direct_batch_ids = self
                    .batch_hunks
                    .iter()
                    .filter_map(|(id, hunks)| {
                        (!self.synthesis_ids.contains(id) && hunks.contains(&hunk)).then_some(*id)
                    })
                    .collect::<BTreeSet<_>>();
                let semantic_batch_ids = self
                    .batch_hunks
                    .iter()
                    .filter_map(|(id, hunks)| {
                        (self.exact_semantic_ids.contains(id) && hunks.contains(&hunk))
                            .then_some(*id)
                    })
                    .collect::<BTreeSet<_>>();
                let risk = self.hunk_risk.get(&hunk).copied().unwrap_or(HunkRisk {
                    mandatory: true,
                    semantic_eligible: false,
                    score: usize::MAX,
                });
                RankedHunk {
                    mandatory: risk.mandatory,
                    semantic_eligible: risk.semantic_eligible,
                    score: risk.score,
                    hunk,
                    direct_batch_ids,
                    semantic_batch_ids,
                }
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .mandatory
                .cmp(&left.mandatory)
                .then_with(|| right.score.cmp(&left.score))
                .then_with(|| left.hunk.path.cmp(&right.hunk.path))
                .then_with(|| left.hunk.new_start.cmp(&right.hunk.new_start))
                .then_with(|| left.hunk.old_start.cmp(&right.hunk.old_start))
                .then_with(|| left.hunk.digest.cmp(&right.hunk.digest))
        });

        let mut selected = self.metadata_batch_ids.clone();
        anyhow::ensure!(
            selected.len() <= selected_limit,
            "mandatory dependency and artifact evidence needs {} batches, exceeding the {selected_limit} batch large-review limit",
            selected.len()
        );
        for candidate in ranked.iter().filter(|candidate| candidate.mandatory) {
            anyhow::ensure!(
                !candidate.direct_batch_ids.is_empty(),
                "mandatory hunk {}:{} has no materialized source batch",
                candidate.hunk.path,
                candidate.hunk.new_start
            );
            let additional = candidate.direct_batch_ids.difference(&selected).count();
            anyhow::ensure!(
                selected.len().saturating_add(additional) <= selected_limit,
                "mandatory hunk {}:{} cannot fit the {selected_limit} batch large-review limit; no provider request was made",
                candidate.hunk.path,
                candidate.hunk.new_start
            );
            selected.extend(candidate.direct_batch_ids.iter().copied());
        }
        for candidate in ranked.iter().filter(|candidate| !candidate.mandatory) {
            let direct_additional = candidate.direct_batch_ids.difference(&selected).count();
            let semantic_id = candidate
                .semantic_eligible
                .then(|| {
                    candidate
                        .semantic_batch_ids
                        .iter()
                        .copied()
                        .min_by_key(|id| {
                            (
                                !selected.contains(id),
                                std::cmp::Reverse(
                                    self.batch_hunks.get(id).map_or(0, BTreeSet::len),
                                ),
                                *id,
                            )
                        })
                })
                .flatten();
            let semantic_additional =
                semantic_id.map_or(usize::MAX, |id| usize::from(!selected.contains(&id)));
            let prefer_semantic = semantic_id.is_some_and(|id| {
                semantic_additional < direct_additional
                    || (semantic_additional == direct_additional
                        && self.batch_hunks.get(&id).map_or(0, BTreeSet::len) > 1)
            });
            if prefer_semantic
                && selected.len().saturating_add(semantic_additional) <= selected_limit
            {
                selected.insert(semantic_id.expect("preference requires a semantic batch"));
            } else if direct_additional <= semantic_additional
                && !candidate.direct_batch_ids.is_empty()
                && selected.len().saturating_add(direct_additional) <= selected_limit
            {
                selected.extend(candidate.direct_batch_ids.iter().copied());
            } else if let Some(id) = semantic_id
                && selected.len().saturating_add(semantic_additional) <= selected_limit
            {
                selected.insert(id);
            }
        }

        let entries = ranked
            .into_iter()
            .map(|candidate| {
                let direct = !candidate.direct_batch_ids.is_empty()
                    && candidate
                        .direct_batch_ids
                        .iter()
                        .all(|id| selected.contains(id));
                let semantic_batch_ids = candidate
                    .semantic_batch_ids
                    .iter()
                    .filter(|id| selected.contains(id))
                    .copied()
                    .collect::<Vec<_>>();
                HunkCoverageEntry {
                    hunk: candidate.hunk,
                    disposition: if direct {
                        HunkDisposition::Direct {
                            batch_ids: candidate.direct_batch_ids.into_iter().collect(),
                        }
                    } else if candidate.semantic_eligible && !semantic_batch_ids.is_empty() {
                        HunkDisposition::Semantic {
                            summary_batch_ids: semantic_batch_ids,
                        }
                    } else {
                        HunkDisposition::Unreviewed {
                            reason: "outside deterministic risk capacity",
                        }
                    },
                }
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            entries.len() == self.all_hunks.len(),
            "bounded coverage receipt lost a normalized hunk"
        );
        anyhow::ensure!(
            entries.windows(2).all(|pair| pair[0].hunk != pair[1].hunk),
            "bounded coverage receipt contains a duplicate hunk disposition"
        );

        let mut hasher = Sha256::new();
        hasher.update(format!("limit={selected_limit}\n").as_bytes());
        for id in &selected {
            hasher.update(format!("batch={id}\n").as_bytes());
        }
        for entry in &entries {
            hasher.update(entry.hunk.canonical().as_bytes());
            match &entry.disposition {
                HunkDisposition::Direct { batch_ids } => {
                    hasher.update(b"\0direct\0");
                    for id in batch_ids {
                        hasher.update((*id as u64).to_le_bytes());
                    }
                }
                HunkDisposition::Semantic { summary_batch_ids } => {
                    hasher.update(b"\0semantic\0");
                    for id in summary_batch_ids {
                        hasher.update((*id as u64).to_le_bytes());
                    }
                }
                HunkDisposition::Unreviewed { reason } => {
                    hasher.update(b"\0unreviewed\0");
                    hasher.update(reason.as_bytes());
                }
            }
        }
        let plan_sha256 = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let receipt = BoundedCoverageReceipt {
            plan_sha256,
            entries,
            selected_batch_ids: selected,
        };
        self.validate_coverage_receipt(&receipt)?;
        Ok(receipt)
    }

    fn validate_coverage_receipt(&mut self, receipt: &BoundedCoverageReceipt) -> Result<()> {
        let selected_batches = self.batch_text_by_id(&receipt.selected_batch_ids)?;
        for entry in &receipt.entries {
            let risk = self
                .hunk_risk
                .get(&entry.hunk)
                .context("bounded coverage receipt references an unknown normalized hunk")?;
            let ids = match &entry.disposition {
                HunkDisposition::Direct { batch_ids } => batch_ids,
                HunkDisposition::Semantic { summary_batch_ids } => {
                    anyhow::ensure!(
                        risk.semantic_eligible && !risk.mandatory,
                        "semantic coverage is not allowed for this hunk risk class"
                    );
                    summary_batch_ids
                }
                HunkDisposition::Unreviewed { .. } => continue,
            };
            anyhow::ensure!(
                !ids.is_empty(),
                "coverage disposition has no evidence batch"
            );
            for id in ids {
                anyhow::ensure!(
                    receipt.selected_batch_ids.contains(id),
                    "coverage disposition references an unselected evidence batch"
                );
                let expected_synthesis =
                    matches!(&entry.disposition, HunkDisposition::Semantic { .. });
                anyhow::ensure!(
                    self.synthesis_ids.contains(id) == expected_synthesis,
                    "coverage disposition references the wrong evidence batch kind"
                );
                if expected_synthesis {
                    anyhow::ensure!(
                        self.exact_semantic_ids.contains(id),
                        "semantic coverage is not bound to exact bounded evidence"
                    );
                }
                anyhow::ensure!(
                    self.batch_hunks
                        .get(id)
                        .is_some_and(|hunks| hunks.contains(&entry.hunk)),
                    "coverage evidence batch is not bound to the exact normalized hunk digest"
                );
                if expected_synthesis {
                    anyhow::ensure!(
                        selected_batches.get(id).is_some_and(|batch| {
                            final_model_visible_semantic_hunks(
                                batch,
                                &BTreeSet::from([entry.hunk.clone()]),
                            )
                            .contains(&entry.hunk)
                        }),
                        "semantic coverage proof is not visible in the selected provider prompt"
                    );
                }
            }
        }
        Ok(())
    }
}

fn security_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "auth",
        "permission",
        "access",
        "security",
        "secret",
        "credential",
        "crypto",
        "token",
        "session",
        "admin",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn control_plane_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "config",
        "policy",
        "billing",
        "migration",
        "release",
        "deploy",
        "workflow",
        ".github/",
        "dockerfile",
        "terraform",
        "kubernetes",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn executable_vendor_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    (lower.contains("vendor/") || lower.contains("vendored/"))
        && [
            ".rs", ".go", ".c", ".cc", ".cpp", ".h", ".js", ".ts", ".py", ".sh",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn mandatory_large_diff_hunk(path: &str, hunk: &Hunk) -> bool {
    if security_sensitive_path(path) || control_plane_path(path) || executable_vendor_path(path) {
        return true;
    }
    let removed = hunk
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix('-'))
        .flat_map(hosted_risk_tokens)
        .collect::<Vec<_>>();
    removed.iter().any(|token| {
        [
            "authoriz",
            "permission",
            "forbidden",
            "denied",
            "validate",
            "guard",
            "timeout",
            "encrypt",
            "signature",
            "verify",
        ]
        .iter()
        .any(|marker| token.starts_with(marker))
    })
}

fn stable_large_diff_risk_score(path: &str, hunk: &Hunk) -> usize {
    let path_score = if security_sensitive_path(path) {
        1_000
    } else if control_plane_path(path) {
        700
    } else if executable_vendor_path(path) {
        600
    } else if path.contains("test") || path.contains("spec") {
        100
    } else if path.ends_with(".md") || path.starts_with("docs/") {
        25
    } else {
        300
    };
    let changed = hunk
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix('+').or_else(|| line.strip_prefix('-')))
        .flat_map(hosted_risk_tokens)
        .collect::<Vec<_>>();
    let removed = hunk
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix('-'))
        .flat_map(hosted_risk_tokens)
        .collect::<Vec<_>>();
    path_score
        + hosted_token_risk_score(&changed)
        + hosted_token_risk_score(&removed).saturating_mul(2)
}

fn semantic_large_diff_hunk(path: &str, hunk: &Hunk) -> bool {
    !mandatory_large_diff_hunk(path, hunk)
}

const HOSTED_RISK_MARKERS: [(&str, usize); 19] = [
    ("unsafe", 12),
    ("eval", 12),
    ("exec", 10),
    ("authoriz", 10),
    ("permission", 10),
    ("forbidden", 10),
    ("denied", 10),
    ("secret", 9),
    ("password", 9),
    ("token", 7),
    ("query", 7),
    ("delete", 6),
    ("timeout", 5),
    ("retry", 4),
    ("validate", 4),
    ("guard", 4),
    ("unwrap", 2),
    ("privileged", 10),
    ("access", 8),
];

fn hosted_token_risk_score(tokens: &[String]) -> usize {
    HOSTED_RISK_MARKERS
        .into_iter()
        .map(|(marker, weight)| {
            tokens
                .iter()
                .filter(|token| token.starts_with(marker))
                .count()
                .min(8)
                * weight
        })
        .sum()
}

fn hosted_risk_score(batch: &str) -> usize {
    let tokens = batch
        .lines()
        .filter(|line| is_changed_evidence_line(line))
        .flat_map(hosted_risk_tokens)
        .collect::<Vec<_>>();
    hosted_token_risk_score(&tokens)
}

fn hosted_removal_risk_score(batch: &str) -> usize {
    let tokens = batch
        .lines()
        .filter(|line| line.trim_start().starts_with("old "))
        .filter(|line| is_changed_evidence_line(line))
        .flat_map(hosted_risk_tokens)
        .collect::<Vec<_>>();
    hosted_token_risk_score(&tokens)
}

fn is_changed_evidence_line(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    match fields.next() {
        Some("old") => fields.next().is_some() && fields.next() == Some("-"),
        Some(number) if number.parse::<u32>().is_ok() => fields.next() == Some("+"),
        _ => false,
    }
}

fn hosted_risk_tokens(line: &str) -> Vec<String> {
    let chars = line.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut token = String::new();
    for (index, character) in chars.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
            continue;
        }
        let camel_boundary = !token.is_empty()
            && character.is_ascii_uppercase()
            && chars[index.saturating_sub(1)].is_ascii_lowercase();
        let acronym_boundary = !token.is_empty()
            && character.is_ascii_uppercase()
            && chars[index.saturating_sub(1)].is_ascii_uppercase()
            && chars
                .get(index + 1)
                .is_some_and(|next| next.is_ascii_lowercase());
        if camel_boundary || acronym_boundary {
            tokens.push(std::mem::take(&mut token));
        }
        token.push(character.to_ascii_lowercase());
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

/// Build one bounded, line-grounded context for an interactive answer. Every
/// source window contributes semantic evidence; large inputs are reduced with
/// the same bounded fan-in used by review synthesis rather than byte truncation.
pub fn bounded_respond_context(
    snapshot: &DiffSnapshot,
    max_bytes: usize,
    max_manifest_bytes: usize,
) -> Result<(String, bool)> {
    let mut prepared = prepare_review(snapshot)?;
    let reserved_anchor = prepared.reserved_anchor;
    let mut batches = spool_model_batches(&mut prepared, max_bytes, max_manifest_bytes, false)?;
    if batches.count == 0 {
        return Ok((String::new(), reserved_anchor));
    }
    let mut first: Option<String> = None;
    let mut digests = Vec::with_capacity(batches.count.min(1_024));
    while let Some(batch) = batches.next_batch()? {
        if let Some(previous) = first.take() {
            if digests.is_empty() {
                digests.push(semantic_digest(&previous));
            }
            digests.push(semantic_digest(&batch));
        } else if digests.is_empty() {
            first = Some(batch);
        } else {
            digests.push(semantic_digest(&batch));
        }
    }
    if digests.is_empty() {
        return Ok((first.expect("one batch was counted"), reserved_anchor));
    }
    let mut level = 1usize;
    loop {
        let chunks = pack_semantic_digests(&digests, level, max_bytes)?;
        if chunks.len() == 1 {
            return Ok((
                chunks.into_iter().next().expect("checked above"),
                reserved_anchor,
            ));
        }
        anyhow::ensure!(
            chunks.len() < digests.len(),
            "interactive context synthesis did not reduce its bounded fan-in"
        );
        digests = chunks;
        level = level
            .checked_add(1)
            .context("interactive synthesis level overflowed")?;
    }
}

pub fn spool_model_batches(
    prepared: &mut PreparedReview,
    max_batch_bytes: usize,
    max_manifest_bytes: usize,
    force_empty: bool,
) -> Result<ModelBatchSpool> {
    spool_model_batches_with_synthesis_budget(
        prepared,
        max_batch_bytes,
        max_batch_bytes,
        max_manifest_bytes,
        force_empty,
    )
}

fn exact_rle_segments(content: &str) -> String {
    const MIN_REPEAT_RUN: usize = 16;

    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut characters = content.chars().peekable();
    while let Some(character) = characters.next() {
        let mut count = 1usize;
        while characters.peek().is_some_and(|next| *next == character) {
            characters.next();
            count = count.saturating_add(1);
        }
        if count >= MIN_REPEAT_RUN {
            if !literal.is_empty() {
                segments.push(format!(
                    "[\"l\",{}]",
                    serde_json::to_string(&std::mem::take(&mut literal)).unwrap()
                ));
            }
            segments.push(format!(
                "[\"r\",{count},{}]",
                serde_json::to_string(&character.to_string()).unwrap()
            ));
        } else {
            literal.extend(std::iter::repeat_n(character, count));
        }
    }
    if !literal.is_empty() {
        segments.push(format!(
            "[\"l\",{}]",
            serde_json::to_string(&literal).unwrap()
        ));
    }
    format!("[{}]", segments.join(","))
}

fn decode_exact_rle_segments(value: &serde_json::Value) -> Option<String> {
    let segments = value.as_array()?;
    let mut decoded = String::new();
    for segment in segments {
        let segment = segment.as_array()?;
        match segment.as_slice() {
            [kind, literal] if kind.as_str() == Some("l") => {
                let literal = literal.as_str()?;
                let next = decoded.len().checked_add(literal.len())?;
                (next <= LINE_CHUNK_BYTES).then_some(())?;
                decoded.push_str(literal);
            }
            [kind, count, scalar] if kind.as_str() == Some("r") => {
                let count = usize::try_from(count.as_u64()?).ok()?;
                let scalar = scalar.as_str()?;
                let mut characters = scalar.chars();
                let character = characters.next()?;
                characters.next().is_none().then_some(())?;
                let repeated_bytes = character.len_utf8().checked_mul(count)?;
                let next = decoded.len().checked_add(repeated_bytes)?;
                (next <= LINE_CHUNK_BYTES).then_some(())?;
                decoded.extend(std::iter::repeat_n(character, count));
            }
            _ => return None,
        }
    }
    Some(decoded)
}

struct DecodedExactTemplate {
    counter_end: u64,
    counter_start: u64,
    end_line: u32,
    prefix: String,
    suffix: String,
}

fn decode_exact_template(encoded: &str, start_line: u32) -> Option<DecodedExactTemplate> {
    let value = serde_json::from_str::<serde_json::Value>(encoded).ok()?;
    let object = value.as_object()?;
    (object.len() == 5).then_some(())?;
    let counter_end = object.get("counterEnd")?.as_u64()?;
    let counter_start = object.get("counterStart")?.as_u64()?;
    let end_line = u32::try_from(object.get("endLine")?.as_u64()?).ok()?;
    let prefix = decode_exact_rle_segments(object.get("prefix")?)?;
    let suffix = decode_exact_rle_segments(object.get("suffix")?)?;
    let line_count = end_line.checked_sub(start_line)?.checked_add(1)? as u64;
    let counter_count = counter_end.checked_sub(counter_start)?.checked_add(1)?;
    (line_count == counter_count && line_count <= MAX_DIFF_INDEX_RANGES as u64).then_some(())?;
    Some(DecodedExactTemplate {
        counter_end,
        counter_start,
        end_line,
        prefix,
        suffix,
    })
}

fn decode_exact_semantic_evidence(
    payload: &str,
    start_line: u32,
    requested_line: u32,
) -> Option<String> {
    if let Some(encoded) = payload.strip_prefix("exact-rle-v1 ") {
        (requested_line == start_line).then_some(())?;
        return decode_exact_rle_segments(&serde_json::from_str(encoded).ok()?);
    }
    if let Some(encoded) = payload.strip_prefix("exact-template-v1 ") {
        let template = decode_exact_template(encoded, start_line)?;
        (start_line..=template.end_line)
            .contains(&requested_line)
            .then_some(())?;
        let counter = template
            .counter_start
            .checked_add(u64::from(requested_line - start_line))?;
        (counter <= template.counter_end).then_some(())?;
        let rendered_bytes = template
            .prefix
            .len()
            .checked_add(counter.to_string().len())?
            .checked_add(template.suffix.len())?;
        (rendered_bytes <= LINE_CHUNK_BYTES).then_some(())?;
        return Some(format!("{}{counter}{}", template.prefix, template.suffix));
    }
    (requested_line == start_line).then(|| payload.to_string())
}

fn exact_semantic_evidence_end_line(payload: &str, start_line: u32) -> Option<u32> {
    if let Some(encoded) = payload.strip_prefix("exact-template-v1 ") {
        return Some(decode_exact_template(encoded, start_line)?.end_line);
    }
    if let Some(encoded) = payload.strip_prefix("exact-rle-v1 ") {
        decode_exact_rle_segments(&serde_json::from_str(encoded).ok()?)?;
    }
    Some(start_line)
}

fn is_exact_semantic_batch(annotated: &str) -> bool {
    annotated
        .lines()
        .take_while(|line| !line.starts_with("### "))
        .any(|line| line == "Exact bounded semantic evidence:")
}

fn exact_line_number_prefix(marker: &str, old_line: u32, new_line: u32) -> String {
    match marker {
        "+" => format!("{new_line} + "),
        "-" => format!("old {old_line} - "),
        _ => unreachable!(),
    }
}

fn exact_semantic_line(marker: &str, content: &str, old_line: u32, new_line: u32) -> String {
    const MIN_EXACT_RLE_LINE_BYTES: usize = 160;

    let rendered = render_line_segments(marker, content, old_line, new_line).concat();
    let reserved_prefix =
        content.starts_with("exact-rle-v1 ") || content.starts_with("exact-template-v1 ");
    if content.len() < MIN_EXACT_RLE_LINE_BYTES && !reserved_prefix {
        return rendered;
    }
    let encoded = format!(
        "{}exact-rle-v1 {}\n",
        exact_line_number_prefix(marker, old_line, new_line),
        exact_rle_segments(content)
    );
    if encoded.len() < rendered.len() || reserved_prefix {
        encoded
    } else {
        rendered
    }
}

#[derive(Clone, Copy)]
struct ExactChangedLine<'a> {
    marker: &'a str,
    content: &'a str,
    old_line: u32,
    new_line: u32,
}

fn decimal_runs(content: &str) -> Vec<(usize, usize, u64)> {
    let bytes = content.as_bytes();
    let mut runs = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        if !bytes[start].is_ascii_digit() {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if let Ok(number) = content[start..end].parse::<u64>()
            && content[start..end] == number.to_string()
        {
            runs.push((start, end, number));
        }
        start = end;
    }
    runs
}

fn sequential_template_length(lines: &[ExactChangedLine<'_>]) -> Option<(usize, usize, usize)> {
    const MIN_TEMPLATE_LINES: usize = 4;
    let first = lines.first()?;
    let mut best = None;
    for (start, end, first_counter) in decimal_runs(first.content).into_iter().rev() {
        let prefix = &first.content[..start];
        let suffix = &first.content[end..];
        let mut length = 1usize;
        for candidate in &lines[1..] {
            if candidate.marker != first.marker {
                break;
            }
            let expected_counter = first_counter.checked_add(length as u64)?;
            let expected_line = match first.marker {
                "+" => first.new_line.checked_add(length as u32)?,
                "-" => first.old_line.checked_add(length as u32)?,
                _ => unreachable!(),
            };
            let candidate_line = if first.marker == "+" {
                candidate.new_line
            } else {
                candidate.old_line
            };
            if candidate_line != expected_line {
                break;
            }
            let Some(middle) = candidate
                .content
                .strip_prefix(prefix)
                .and_then(|content| content.strip_suffix(suffix))
            else {
                break;
            };
            if middle != expected_counter.to_string() {
                break;
            }
            length += 1;
        }
        if length >= MIN_TEMPLATE_LINES
            && best.is_none_or(|(_, _, best_length)| length > best_length)
        {
            best = Some((start, end, length));
        }
    }
    best
}

fn exact_semantic_template(lines: &[ExactChangedLine<'_>]) -> Option<(String, usize)> {
    let first = *lines.first()?;
    let (start, end, length) = sequential_template_length(lines)?;
    let last = lines[length - 1];
    let first_counter = first.content[start..end].parse::<u64>().ok()?;
    let last_counter = first_counter.checked_add(length.saturating_sub(1) as u64)?;
    let end_line = if first.marker == "+" {
        last.new_line
    } else {
        last.old_line
    };
    let encoded = format!(
        "{}exact-template-v1 {{\"counterEnd\":{last_counter},\"counterStart\":{first_counter},\"endLine\":{end_line},\"prefix\":{},\"suffix\":{}}}\n",
        exact_line_number_prefix(first.marker, first.old_line, first.new_line),
        exact_rle_segments(&first.content[..start]),
        exact_rle_segments(&first.content[end..]),
    );
    let rendered_bytes = lines[..length]
        .iter()
        .map(|line| {
            exact_semantic_line(line.marker, line.content, line.old_line, line.new_line).len()
        })
        .sum::<usize>();
    (encoded.len() < rendered_bytes).then_some((encoded, length))
}

fn exact_semantic_hunk_proof(path: &str, hunk: &Hunk) -> Option<String> {
    let mut old_line = hunk.old_start;
    let mut new_line = hunk.new_start;
    let mut changed_lines = Vec::<ExactChangedLine<'_>>::new();
    let mut substantive_added = false;
    for raw in &hunk.lines {
        let (marker, content) = raw.split_at(if raw.is_empty() { 0 } else { 1 });
        if matches!(marker, "+" | "-") {
            if marker == "+"
                && hosted_risk_tokens(content)
                    .iter()
                    .any(|token| token.len() >= 2)
            {
                substantive_added = true;
            }
            changed_lines.push(ExactChangedLine {
                marker,
                content,
                old_line,
                new_line,
            });
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
    substantive_added.then_some(())?;
    let identity = hunk_receipt_identity(&HunkIdentity::new(path, hunk));
    let mut proof = format!(
        "### {}\n@@ exact bounded hunk identity={identity} old={},{} new={},{} @@\n",
        display_path(path),
        hunk.old_start,
        hunk.old_count,
        hunk.new_start,
        hunk.new_count,
    );
    let mut index = 0usize;
    while index < changed_lines.len() {
        if let Some((template, length)) = exact_semantic_template(&changed_lines[index..]) {
            proof.push_str(&template);
            index += length;
            continue;
        }
        let line = changed_lines[index];
        proof.push_str(&exact_semantic_line(
            line.marker,
            line.content,
            line.old_line,
            line.new_line,
        ));
        index += 1;
    }
    Some(proof)
}

fn exact_semantic_batch_header(hunks: &BTreeSet<HunkIdentity>) -> String {
    format!(
        "Exact bounded semantic evidence:\nEvery credited hunk below retains its repository path, every changed line, and a non-empty added line. `exact-rle-v1` concatenates literal `[\"l\", text]` and Unicode-scalar repeat `[\"r\", count, scalar]` segments. `exact-template-v1` is a JSON object that expands the inclusive `counterStart` through `counterEnd` range between its exact `prefix` and `suffix` for each source line through `endLine`. These lossless forms reconstruct the complete source; do not infer omitted context. A finding may cite any represented new-side line, but its `evidence` must be that line's complete reconstructed source text, never the encoding record.\nExact normalized hunk-set commitment (SHA-256): {}\n",
        hunk_set_sha256(hunks)
    )
}

fn hunk_receipt_identity(hunk: &HunkIdentity) -> String {
    Sha256::digest(hunk.canonical().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn final_model_visible_semantic_hunks(
    batch: &str,
    candidates: &BTreeSet<HunkIdentity>,
) -> BTreeSet<HunkIdentity> {
    let mut path = None::<&str>;
    let mut identity = None::<&str>;
    let mut visible = BTreeSet::new();
    for line in batch.lines() {
        if let Some(value) = line.strip_prefix("### ") {
            path = Some(prompt_header_path(value));
            identity = None;
            continue;
        }
        if let Some(value) = line
            .strip_prefix("@@ exact bounded hunk identity=")
            .and_then(|value| value.split_once(' ').map(|(identity, _)| identity))
        {
            identity = Some(value);
            continue;
        }
        let Some((number, marked)) = line.trim_start().split_once(' ') else {
            continue;
        };
        let Some(line_number) = number.parse::<u32>().ok() else {
            continue;
        };
        let Some(evidence) = marked.strip_prefix("+ ") else {
            continue;
        };
        if evidence.trim().is_empty() {
            continue;
        }
        let Some((path, identity)) = path.zip(identity) else {
            continue;
        };
        visible.extend(
            candidates
                .iter()
                .filter(|hunk| {
                    let Some(evidence_end) =
                        exact_semantic_evidence_end_line(evidence, line_number)
                    else {
                        return false;
                    };
                    let Some(hunk_end) =
                        hunk.new_start.checked_add(hunk.new_count.saturating_sub(1))
                    else {
                        return false;
                    };
                    prompt_paths_equal(path, &hunk.path)
                        && hunk_receipt_identity(hunk) == identity
                        && hunk.new_count > 0
                        && (hunk.new_start..=hunk_end).contains(&line_number)
                        && evidence_end <= hunk_end
                        && decode_exact_semantic_evidence(evidence, line_number, line_number)
                            .is_some_and(|decoded| !decoded.trim().is_empty())
                })
                .cloned(),
        );
    }
    visible
}

fn finalize_exact_semantic_batch(
    payload: String,
    candidates: BTreeSet<HunkIdentity>,
) -> Option<(String, BTreeSet<HunkIdentity>)> {
    let visible = final_model_visible_semantic_hunks(&payload, &candidates);
    if visible.is_empty() {
        return None;
    }
    let header = exact_semantic_batch_header(&visible);
    Some((format!("{header}{payload}"), visible))
}

fn exact_semantic_batches(
    proofs: BTreeMap<HunkIdentity, String>,
    max_batch_bytes: usize,
) -> Vec<(String, BTreeSet<HunkIdentity>)> {
    let header_reserve = exact_semantic_batch_header(&BTreeSet::new()).len();
    let payload_capacity = max_batch_bytes.saturating_sub(header_reserve);
    let mut batches = Vec::new();
    let mut payload = String::new();
    let mut hunks = BTreeSet::new();
    for (hunk, proof) in proofs {
        if proof.len() > payload_capacity {
            continue;
        }
        if !payload.is_empty()
            && payload.len().saturating_add(proof.len()) > payload_capacity
            && let Some(batch) = finalize_exact_semantic_batch(
                std::mem::take(&mut payload),
                std::mem::take(&mut hunks),
            )
        {
            batches.push(batch);
        }
        payload.push_str(&proof);
        hunks.insert(hunk);
    }
    if !payload.is_empty()
        && let Some(batch) = finalize_exact_semantic_batch(payload, hunks)
    {
        batches.push(batch);
    }
    batches
}

pub(crate) fn spool_model_batches_with_synthesis_budget(
    prepared: &mut PreparedReview,
    max_source_batch_bytes: usize,
    max_synthesis_batch_bytes: usize,
    max_manifest_bytes: usize,
    force_empty: bool,
) -> Result<ModelBatchSpool> {
    anyhow::ensure!(
        max_source_batch_bytes >= MIN_REVIEW_BATCH_BYTES,
        "source batch limit must leave room for context"
    );
    anyhow::ensure!(
        max_synthesis_batch_bytes >= MIN_REVIEW_BATCH_BYTES,
        "synthesis batch limit must leave room for context"
    );
    let mut file = tempfile::tempfile().context("creating model-batch spool")?;
    let mut lease = WorkspaceLease::new(prepared._window_lease.budget.clone());
    let mut spool_bytes = 0u64;
    let mut count = 0usize;
    let mut source_count = 0usize;
    let mut synthesis_ids = BTreeSet::new();
    let mut exact_semantic_ids = BTreeSet::new();
    let mut batch_hunks = HashMap::new();
    let mut all_hunks = BTreeSet::new();
    let mut hunk_risk = HashMap::new();
    let mut semantic_hunk_proofs = BTreeMap::new();
    let semantic_proof_capacity = max_synthesis_batch_bytes
        .saturating_sub(exact_semantic_batch_header(&BTreeSet::new()).len());
    let mut metadata_batch_ids = BTreeSet::new();
    let mut metadata_count = 0u32;
    let synthesis_header = "Cross-window semantic digests:\n";
    let mut cross_window = synthesis_header.to_string();
    let mut cross_window_hunks = BTreeSet::new();
    let mut synthesis_chunks = Vec::<(String, BTreeSet<HunkIdentity>)>::new();
    let mut digest_ordinal = 0usize;
    prepared.rewind()?;
    while let Some(window) = prepared.next_window()? {
        let parsed = parse(&window);
        anyhow::ensure!(parsed.complete, "normalized review window is incomplete");
        for file in &parsed.files {
            for hunk in &file.hunks {
                let identity = HunkIdentity::new(&file.path, hunk);
                hunk_risk.insert(
                    identity.clone(),
                    HunkRisk {
                        mandatory: mandatory_large_diff_hunk(&file.path, hunk),
                        semantic_eligible: semantic_large_diff_hunk(&file.path, hunk),
                        score: stable_large_diff_risk_score(&file.path, hunk),
                    },
                );
                if semantic_large_diff_hunk(&file.path, hunk)
                    && let Some(proof) = exact_semantic_hunk_proof(&file.path, hunk)
                    && proof.len() <= semantic_proof_capacity
                {
                    semantic_hunk_proofs.insert(identity, proof);
                }
            }
        }
        let plan = render_review_batches(
            &parsed,
            &[],
            &[],
            max_source_batch_bytes,
            max_manifest_bytes,
        );
        anyhow::ensure!(
            !plan.incomplete,
            "normalized review window could not be rendered"
        );
        let plan_hunks = plan
            .batch_hunks
            .iter()
            .flat_map(|hunks| hunks.iter().cloned())
            .collect::<BTreeSet<_>>();
        metadata_count = metadata_count.max(plan.metadata_count);
        for (batch, hunks) in plan.batches.into_iter().zip(plan.batch_hunks) {
            let digest = semantic_digest(&batch);
            if !digest.is_empty() {
                let next_ordinal = digest_ordinal
                    .checked_add(1)
                    .context("semantic digest ordinal overflowed")?;
                let heading = format!("\nSource window {next_ordinal}:\n");
                let digest_bound = max_synthesis_batch_bytes
                    .checked_sub(synthesis_header.len().saturating_add(heading.len()))
                    .context("semantic synthesis header exceeded its bound")?;
                let digest = compact_semantic_digest(digest, digest_bound)?;
                let entry = format!("{heading}{digest}");
                if cross_window.len().saturating_add(entry.len()) > max_synthesis_batch_bytes {
                    if cross_window.len() > synthesis_header.len() {
                        synthesis_chunks.push((
                            std::mem::take(&mut cross_window),
                            std::mem::take(&mut cross_window_hunks),
                        ));
                    }
                    cross_window.push_str(synthesis_header);
                }
                digest_ordinal = next_ordinal;
                cross_window.push_str(&entry);
                cross_window_hunks.extend(hunks.iter().cloned());
            }
            write_length_prefixed(
                &mut file,
                &mut lease,
                &batch,
                max_source_batch_bytes,
                "model batch",
            )?;
            spool_bytes = spool_bytes
                .checked_add(batch.len() as u64 + 8)
                .context("model-batch spool size overflowed")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
            source_count = source_count
                .checked_add(1)
                .context("source model batch count overflowed")?;
            all_hunks.extend(hunks.iter().cloned());
            batch_hunks.insert(count, hunks);
        }
        if let Some(synthesis) = plan.synthesis {
            let synthesis =
                bind_synthesis_hunks(synthesis, &plan_hunks, max_synthesis_batch_bytes)?;
            write_length_prefixed(
                &mut file,
                &mut lease,
                &synthesis,
                max_synthesis_batch_bytes,
                "model batch",
            )?;
            spool_bytes = spool_bytes
                .checked_add(synthesis.len() as u64 + 8)
                .context("model-batch spool size overflowed")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
            synthesis_ids.insert(count);
            batch_hunks.insert(count, plan_hunks);
        }
    }

    // Artifact evidence is already compact. Partition it so a repository with
    // many lockfiles or bundles cannot overflow one request manifest.
    let mut lock_start = 0usize;
    let mut artifact_start = 0usize;
    while lock_start < prepared.lockfiles.len()
        || artifact_start < prepared.compacted_artifacts.len()
    {
        let lock_end = (lock_start + 16).min(prepared.lockfiles.len());
        let artifact_end = (artifact_start + 16).min(prepared.compacted_artifacts.len());
        let plan = render_review_batches(
            &Diff::default(),
            &prepared.lockfiles[lock_start..lock_end],
            &prepared.compacted_artifacts[artifact_start..artifact_end],
            max_source_batch_bytes,
            max_manifest_bytes,
        );
        if plan.incomplete {
            anyhow::bail!("compact artifact metadata could not fit a bounded model request");
        }
        metadata_count = metadata_count.max(plan.metadata_count);
        for batch in plan.batches {
            write_length_prefixed(
                &mut file,
                &mut lease,
                &batch,
                max_source_batch_bytes,
                "artifact model batch",
            )?;
            spool_bytes = spool_bytes
                .checked_add(batch.len() as u64 + 8)
                .context("model-batch spool size overflowed")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
            source_count = source_count
                .checked_add(1)
                .context("source model batch count overflowed")?;
            metadata_batch_ids.insert(count);
        }
        if let Some(synthesis) = plan.synthesis {
            let synthesis = compact_semantic_digest(synthesis, max_synthesis_batch_bytes)?;
            write_length_prefixed(
                &mut file,
                &mut lease,
                &synthesis,
                max_synthesis_batch_bytes,
                "artifact synthesis batch",
            )?;
            spool_bytes = spool_bytes
                .checked_add(synthesis.len() as u64 + 8)
                .context("model-batch spool size overflowed")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
            synthesis_ids.insert(count);
        }
        lock_start = lock_end;
        artifact_start = artifact_end;
    }
    if cross_window.len() > synthesis_header.len() && digest_ordinal > 1 {
        synthesis_chunks.push((cross_window, cross_window_hunks));
    }
    if digest_ordinal > 1 {
        let mut level = 1usize;
        let mut chunks = synthesis_chunks;
        while !chunks.is_empty() {
            let chunk_count = chunks.len();
            let mut digests = Vec::with_capacity(chunk_count);
            let mut covered_hunks = Vec::with_capacity(chunk_count);
            for (chunk, hunks) in chunks {
                let chunk = bind_synthesis_hunks(chunk, &hunks, max_synthesis_batch_bytes)?;
                write_length_prefixed(
                    &mut file,
                    &mut lease,
                    &chunk,
                    max_synthesis_batch_bytes,
                    "cross-window synthesis batch",
                )?;
                spool_bytes = spool_bytes
                    .checked_add(chunk.len() as u64 + 8)
                    .context("model-batch spool size overflowed")?;
                count = count
                    .checked_add(1)
                    .context("model batch count overflowed")?;
                synthesis_ids.insert(count);
                batch_hunks.insert(count, hunks.clone());
                digests.push(chunk);
                covered_hunks.push(hunks);
            }
            if chunk_count == 1 {
                break;
            }
            let next_text = pack_semantic_digests(&digests, level + 1, max_synthesis_batch_bytes)?;
            let next_hunks = covered_hunks
                .chunks(2)
                .map(|pair| {
                    pair.iter()
                        .flat_map(|hunks| hunks.iter().cloned())
                        .collect::<BTreeSet<_>>()
                })
                .collect::<Vec<_>>();
            anyhow::ensure!(
                next_text.len() < chunk_count && next_text.len() == next_hunks.len(),
                "recursive synthesis did not reduce its bounded fan-in"
            );
            chunks = next_text.into_iter().zip(next_hunks).collect();
            level = level
                .checked_add(1)
                .context("recursive synthesis level overflowed")?;
        }
    }
    if source_count > crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES {
        for (batch, hunks) in
            exact_semantic_batches(semantic_hunk_proofs, max_synthesis_batch_bytes)
        {
            write_length_prefixed(
                &mut file,
                &mut lease,
                &batch,
                max_synthesis_batch_bytes,
                "exact semantic model batch",
            )?;
            spool_bytes = spool_bytes
                .checked_add(batch.len() as u64 + 8)
                .context("model-batch spool size overflowed")?;
            count = count
                .checked_add(1)
                .context("model batch count overflowed")?;
            synthesis_ids.insert(count);
            exact_semantic_ids.insert(count);
            batch_hunks.insert(count, hunks);
        }
    }
    if count == 0 && force_empty {
        write_length_prefixed(
            &mut file,
            &mut lease,
            "",
            max_source_batch_bytes,
            "model batch",
        )?;
        spool_bytes = spool_bytes.saturating_add(8);
        count = 1;
        source_count = 1;
    }
    let aggregate = prepared
        .snapshot_bytes
        .checked_add(prepared.window_bytes)
        .and_then(|bytes| bytes.checked_add(spool_bytes))
        .context("aggregate review spool size overflowed")?;
    anyhow::ensure!(
        aggregate <= MAX_REVIEW_SPOOL_BYTES,
        "review workspace needs {aggregate} bytes, exceeding the {MAX_REVIEW_SPOOL_BYTES} byte operation quota"
    );
    file.seek(SeekFrom::Start(0))
        .context("rewinding model-batch spool")?;
    Ok(ModelBatchSpool {
        file,
        _lease: lease,
        count,
        source_count,
        metadata_count,
        synthesis_ids,
        exact_semantic_ids,
        batch_hunks,
        all_hunks,
        hunk_risk,
        metadata_batch_ids,
    })
}

fn pack_semantic_digests(
    digests: &[String],
    level: usize,
    max_batch_bytes: usize,
) -> Result<Vec<String>> {
    let header = format!("Cross-window semantic digests level {level}:\n");
    let mut chunks = Vec::with_capacity(digests.len().div_ceil(2));
    for (pair_index, pair) in digests.chunks(2).enumerate() {
        let first_index = pair_index
            .checked_mul(2)
            .and_then(|index| index.checked_add(1))
            .context("synthesis group ordinal overflowed")?;
        let headings = (0..pair.len())
            .map(|offset| format!("\nSynthesis group {}:\n", first_index + offset))
            .collect::<Vec<_>>();
        let heading_bytes = headings.iter().map(String::len).sum::<usize>();
        let payload_bytes = max_batch_bytes
            .checked_sub(header.len().saturating_add(heading_bytes))
            .context("synthesis header exceeded its bound")?;
        anyhow::ensure!(
            payload_bytes >= pair.len(),
            "semantic digest capacity too small for synthesis payload"
        );

        let mut chunk = header.clone();
        let mut remaining = payload_bytes;
        for (offset, digest) in pair.iter().enumerate() {
            anyhow::ensure!(
                !digest.is_empty(),
                "synthesis digest lost all semantic evidence"
            );
            let remaining_items = pair.len() - offset;
            let digest_bound = remaining / remaining_items;
            let digest = compact_semantic_digest(digest.clone(), digest_bound)?;
            remaining = remaining.saturating_sub(digest.len());
            chunk.push_str(&headings[offset]);
            chunk.push_str(&digest);
        }
        anyhow::ensure!(
            chunk.len() <= max_batch_bytes,
            "synthesis packing exceeded its fixed bound"
        );
        chunks.push(chunk);
    }
    Ok(chunks)
}

fn hunk_set_sha256(hunks: &BTreeSet<HunkIdentity>) -> String {
    let mut hasher = Sha256::new();
    for hunk in hunks {
        let canonical = hunk.canonical();
        hasher.update((canonical.len() as u64).to_le_bytes());
        hasher.update(canonical.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bind_synthesis_hunks(
    synthesis: String,
    hunks: &BTreeSet<HunkIdentity>,
    max_batch_bytes: usize,
) -> Result<String> {
    anyhow::ensure!(
        !hunks.is_empty(),
        "semantic synthesis has no normalized hunk commitment"
    );
    let commitment = format!(
        "Exact normalized hunk-set commitment (SHA-256): {}\n",
        hunk_set_sha256(hunks)
    );
    let receipt_header = synthesis
        .lines()
        .next()
        .filter(|line| {
            line.starts_with("Cross-window semantic digests")
                || line.starts_with("Cross-batch semantic digests")
        })
        .map_or_else(
            || "Cross-window semantic digests (receipt-bound):\n".to_string(),
            |line| format!("{line}\n"),
        );
    let evidence_limit = max_batch_bytes
        .checked_sub(receipt_header.len().saturating_add(commitment.len()))
        .context("semantic hunk commitment exceeded its batch bound")?;
    let synthesis = compact_semantic_digest(synthesis, evidence_limit)?;
    let evidence = synthesis
        .split_once('\n')
        .filter(|(line, _)| {
            line.starts_with("Cross-window semantic digests")
                || line.starts_with("Cross-batch semantic digests")
        })
        .map_or(synthesis.as_str(), |(_, evidence)| evidence);
    Ok(format!("{receipt_header}{commitment}{evidence}"))
}

#[derive(Clone, Copy)]
struct SemanticEvidence<'a> {
    source_ordinal: Option<usize>,
    path: &'a str,
    category: &'static str,
    evidence: &'a str,
    changed: bool,
}

const SEMANTIC_CATEGORIES: [(&str, &[&str]); 6] = [
    (
        "sinks",
        &[
            "sink", "exec", "query", "write", "send", "delete", "unsafe", "eval",
        ],
    ),
    (
        "validation",
        &[
            "validate",
            "sanitize",
            "authoriz",
            "permission",
            "forbidden",
            "denied",
            "privileged",
            "access",
            "check",
            "guard",
        ],
    ),
    (
        "sources",
        &["input", "request", "user", "read", "recv", "source"],
    ),
    (
        "contracts",
        &["fn ", "def ", "class ", "interface ", "type ", "pub "],
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

fn compact_semantic_digest(digest: String, max_bytes: usize) -> Result<String> {
    if digest.len() <= max_bytes {
        return Ok(digest);
    }
    let records = parse_semantic_evidence(&digest);
    anyhow::ensure!(
        !records.is_empty(),
        "semantic digest contained no bounded evidence records"
    );

    let mut selected = BTreeSet::from([0, records.len() - 1]);
    if let Some(index) = records.iter().position(|record| record.changed) {
        selected.insert(index);
    }
    if let Some(index) = records.iter().rposition(|record| record.changed) {
        selected.insert(index);
    }
    for (category, _) in SEMANTIC_CATEGORIES {
        if let Some(index) = records
            .iter()
            .position(|record| record.category == category)
        {
            selected.insert(index);
        }
    }
    let selected = selected
        .into_iter()
        .map(|index| records[index])
        .collect::<Vec<_>>();
    render_semantic_evidence(&selected, max_bytes)
}

fn compact_planner_digest(digest: String, max_bytes: usize) -> Result<String> {
    if digest.len() <= max_bytes {
        return Ok(digest);
    }
    let records = parse_semantic_evidence(&digest);
    anyhow::ensure!(
        !records.is_empty(),
        "planner digest contained no bounded evidence records"
    );

    let mut selected = BTreeSet::from([0, records.len() - 1]);
    let fits = |indexes: &BTreeSet<usize>| {
        let selected = indexes
            .iter()
            .map(|index| records[*index])
            .collect::<Vec<_>>();
        render_semantic_evidence(&selected, max_bytes).is_ok()
    };

    // Planner evidence retains one identity per interior path while capacity
    // allows, even when another file owns the first high-signal token.
    let mut represented_paths = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        if !represented_paths.insert(record.path) || selected.contains(&index) {
            continue;
        }
        let mut candidate = selected.clone();
        candidate.insert(index);
        if fits(&candidate) {
            selected = candidate;
        }
    }
    for (category, _) in SEMANTIC_CATEGORIES {
        if let Some(index) = records
            .iter()
            .position(|record| record.category == category)
        {
            let mut candidate = selected.clone();
            candidate.insert(index);
            if fits(&candidate) {
                selected = candidate;
            }
        }
    }
    let selected = selected
        .into_iter()
        .map(|index| records[index])
        .collect::<Vec<_>>();
    render_semantic_evidence(&selected, max_bytes)
}

fn parse_semantic_evidence(digest: &str) -> Vec<SemanticEvidence<'_>> {
    let mut source_ordinal = None;
    let mut path = "";
    let mut category = "uncategorized";
    let mut records = Vec::new();
    for line in digest.lines() {
        if let Some(ordinal) = line
            .trim()
            .strip_prefix("Source window ")
            .and_then(|value| value.strip_suffix(':'))
            .and_then(|value| value.parse::<usize>().ok())
        {
            source_ordinal = Some(ordinal);
        } else if let Some(value) = line.strip_prefix("### ") {
            path = value;
            category = "uncategorized";
        } else if let Some(value) = line
            .strip_prefix("@@ semantic category=")
            .and_then(|value| value.strip_suffix(" @@"))
        {
            category = SEMANTIC_CATEGORIES
                .iter()
                .map(|(candidate, _)| *candidate)
                .find(|candidate| *candidate == value)
                .unwrap_or("uncategorized");
        } else if is_rendered_semantic_evidence(line) {
            records.push(SemanticEvidence {
                source_ordinal,
                path,
                category,
                evidence: line,
                changed: is_changed_rendered_semantic_evidence(line),
            });
        }
    }
    records
}

fn is_changed_rendered_semantic_evidence(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("old ") {
        return true;
    }
    trimmed.split_once(' ').is_some_and(|(number, rest)| {
        number.parse::<u32>().is_ok() && rest.trim_start().starts_with("+ ")
    })
}

fn is_rendered_semantic_evidence(line: &str) -> bool {
    let trimmed = line.trim_start();
    if let Some(deletion) = trimmed.strip_prefix("old ") {
        return deletion
            .trim_start()
            .split_once(' ')
            .is_some_and(|(number, rest)| number.parse::<u32>().is_ok() && rest.starts_with("- "));
    }
    trimmed
        .split_once(' ')
        .is_some_and(|(number, _)| number.parse::<u32>().is_ok())
}

fn render_semantic_evidence(records: &[SemanticEvidence<'_>], max_bytes: usize) -> Result<String> {
    const MIN_PATH_BYTES: usize = 48;
    const MAX_PATH_BYTES: usize = 240;
    const MIN_EVIDENCE_BYTES: usize = 80;
    const MAX_EVIDENCE_BYTES: usize = 480;

    let mut fixed_bytes = 0usize;
    let mut previous_ordinal = None;
    for record in records {
        if record.source_ordinal != previous_ordinal {
            if let Some(ordinal) = record.source_ordinal {
                fixed_bytes = fixed_bytes
                    .checked_add(format!("Source window {ordinal}:\n").len())
                    .context("semantic source heading size overflowed")?;
            }
            previous_ordinal = record.source_ordinal;
        }
        fixed_bytes = fixed_bytes
            .checked_add("### \n@@ semantic category= @@\n\n".len())
            .and_then(|bytes| bytes.checked_add(record.category.len()))
            .context("semantic record size overflowed")?;
    }

    let minimum_bytes = records.iter().try_fold(fixed_bytes, |total, record| {
        total
            .checked_add(record.path.len().min(MIN_PATH_BYTES))
            .and_then(|bytes| bytes.checked_add(record.evidence.len().min(MIN_EVIDENCE_BYTES)))
            .context("semantic evidence size overflowed")
    })?;
    anyhow::ensure!(
        minimum_bytes <= max_bytes,
        "semantic digest capacity too small for boundary and high-signal evidence"
    );

    let mut remaining = max_bytes - minimum_bytes;
    let mut remaining_fields = records.len().saturating_mul(2);
    let mut capacities = Vec::with_capacity(records.len());
    for record in records {
        let path_minimum = record.path.len().min(MIN_PATH_BYTES);
        let path_desired = record.path.len().min(MAX_PATH_BYTES);
        let path_extra = (path_desired - path_minimum).min(remaining / remaining_fields.max(1));
        let path_capacity = path_minimum + path_extra;
        remaining -= path_extra;
        remaining_fields -= 1;

        let evidence_minimum = record.evidence.len().min(MIN_EVIDENCE_BYTES);
        let evidence_desired = record.evidence.len().min(MAX_EVIDENCE_BYTES);
        let evidence_extra =
            (evidence_desired - evidence_minimum).min(remaining / remaining_fields.max(1));
        let evidence_capacity = evidence_minimum + evidence_extra;
        remaining -= evidence_extra;
        remaining_fields -= 1;
        capacities.push((path_capacity, evidence_capacity));
    }

    let mut rendered = String::with_capacity(max_bytes.min(16 * 1024));
    previous_ordinal = None;
    for (record, (path_capacity, evidence_capacity)) in records.iter().zip(capacities) {
        if record.source_ordinal != previous_ordinal {
            if let Some(ordinal) = record.source_ordinal {
                rendered.push_str(&format!("Source window {ordinal}:\n"));
            }
            previous_ordinal = record.source_ordinal;
        }
        let path = bound_utf8_identity(record.path, path_capacity)?;
        let evidence = bound_utf8_identity(record.evidence, evidence_capacity)?;
        rendered.push_str(&format!(
            "### {path}\n@@ semantic category={} @@\n{evidence}\n",
            record.category
        ));
    }
    anyhow::ensure!(
        rendered.len() <= max_bytes,
        "semantic digest rendering exceeded its fixed bound"
    );
    Ok(rendered)
}

fn bound_utf8_identity(value: &str, max_bytes: usize) -> Result<String> {
    if value.len() <= max_bytes {
        return Ok(value.to_string());
    }
    let digest = Sha256::digest(value.as_bytes());
    let identity = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let suffix = format!("…#{identity}");
    anyhow::ensure!(
        max_bytes >= suffix.len(),
        "semantic digest capacity too small for stable evidence identity"
    );
    let prefix_bytes = max_bytes - suffix.len();
    let mut split = prefix_bytes.min(value.len());
    while !value.is_char_boundary(split) {
        split -= 1;
    }
    Ok(format!("{}{suffix}", &value[..split]))
}

fn write_length_prefixed(
    file: &mut File,
    lease: &mut WorkspaceLease,
    value: &str,
    max_bytes: usize,
    context: &str,
) -> Result<()> {
    anyhow::ensure!(
        value.len() <= max_bytes,
        "{context} exceeded its fixed bound"
    );
    let bytes = value.len() as u64 + 8;
    lease
        .reserve(bytes)
        .with_context(|| format!("reserving {context} workspace"))?;
    if let Err(error) = file
        .write_all(&(value.len() as u64).to_le_bytes())
        .and_then(|_| file.write_all(value.as_bytes()))
    {
        lease.release(bytes);
        return Err(error).with_context(|| format!("writing {context}"));
    }
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
    prepare_review_with_ignore(snapshot, &[])
}

pub fn prepare_review_with_ignore(
    snapshot: &DiffSnapshot,
    ignore_patterns: &[String],
) -> Result<PreparedReview> {
    let text = snapshot.as_str();
    let ignore = crate::filter::build_ignore_set(ignore_patterns)?;
    let mut windows = tempfile::tempfile().context("creating review-window spool")?;
    let mut window_lease = WorkspaceLease::new(snapshot.workspace_budget());
    let mut index = DiffIndex::default();
    let mut lockfiles = Vec::new();
    let mut compacted_artifacts = Vec::new();
    let mut window_bytes = 0u64;
    let mut has_source = false;
    let mut reserved_anchor = false;
    let mut pending_window = String::new();
    let mut pending_manifest_bytes = 0usize;
    let Some(mut cursor) = next_diff_start(text, 0) else {
        anyhow::ensure!(text.trim().is_empty(), "review input is not a unified diff");
        return Ok(PreparedReview {
            windows,
            _window_lease: window_lease,
            index,
            lockfiles,
            compacted_artifacts,
            has_source,
            reserved_anchor,
            snapshot_bytes: snapshot.len(),
            window_bytes,
        });
    };
    anyhow::ensure!(
        text[..cursor].trim().is_empty(),
        "review input has an invalid preamble"
    );
    while cursor < text.len() {
        let end = next_diff_start(text, cursor + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[cursor..end];
        let paths = validated_section_paths(section).context("validating review section paths")?;
        let ignored = ignore.is_match(&paths.path) && ignore.is_match(&paths.old_path);
        let path = paths.path;
        if ignored {
            cursor = end;
            continue;
        }
        if is_known_lockfile(&path)
            && let Some(evidence) = lockfile_evidence(&path, section)
        {
            lockfiles.push(evidence);
        } else if is_compactable_generated_artifact(&path, section) || is_binary_section(section) {
            compacted_artifacts.push(compacted_artifact_evidence(&path, section));
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
                    write_window(&mut windows, &mut window_lease, &pending_window)?;
                    window_bytes = window_bytes
                        .checked_add(pending_window.len() as u64 + 8)
                        .context("review-window spool size overflowed")?;
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
        write_window(&mut windows, &mut window_lease, &pending_window)?;
        window_bytes = window_bytes
            .checked_add(pending_window.len() as u64 + 8)
            .context("review-window spool size overflowed")?;
    }
    anyhow::ensure!(
        index.is_complete(),
        "diff grounding index exceeded its fixed resource bound"
    );
    let initial_workspace = snapshot
        .len()
        .checked_add(window_bytes)
        .context("aggregate review spool size overflowed")?;
    anyhow::ensure!(
        initial_workspace <= MAX_REVIEW_SPOOL_BYTES,
        "review workspace needs {initial_workspace} bytes before batching, exceeding the {MAX_REVIEW_SPOOL_BYTES} byte operation quota"
    );
    windows
        .seek(SeekFrom::Start(0))
        .context("rewinding review-window spool")?;
    Ok(PreparedReview {
        windows,
        _window_lease: window_lease,
        index,
        lockfiles,
        compacted_artifacts,
        has_source,
        reserved_anchor,
        snapshot_bytes: snapshot.len(),
        window_bytes,
    })
}

fn write_window(file: &mut File, lease: &mut WorkspaceLease, window: &str) -> Result<()> {
    anyhow::ensure!(
        window.len() <= STREAM_WINDOW_BYTES,
        "normalized review window exceeded its fixed bound"
    );
    let bytes = window.len() as u64 + 8;
    lease
        .reserve(bytes)
        .context("reserving review-window workspace")?;
    if let Err(error) = file
        .write_all(&(window.len() as u64).to_le_bytes())
        .and_then(|_| file.write_all(window.as_bytes()))
    {
        lease.release(bytes);
        return Err(error).context("writing review window");
    }
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
            compacted_artifacts: Vec::new(),
            incomplete: false,
        };
    }

    let preamble_len = cursor.unwrap_or(0);
    let mut kept_len = preamble_len;
    let mut lockfiles = Vec::new();
    let mut compacted_artifacts = Vec::new();
    let mut compacted = false;
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        let Ok(paths) = validated_section_paths(section) else {
            return PreparedDiff {
                source: None,
                lockfiles: Vec::new(),
                compacted_artifacts: Vec::new(),
                incomplete: true,
            };
        };
        let path = paths.path;
        if is_known_lockfile(&path) {
            if let Some(evidence) = lockfile_evidence(&path, section) {
                compacted = true;
                lockfiles.push(evidence);
            } else {
                kept_len = kept_len.saturating_add(section.len());
            }
        } else if is_compactable_generated_artifact(&path, section) {
            compacted = true;
            compacted_artifacts.push(compacted_artifact_evidence(&path, section));
        } else {
            kept_len = kept_len.saturating_add(section.len());
        }
        cursor = (end < text.len()).then_some(end);
    }

    if !compacted {
        return PreparedDiff {
            source: Some(Cow::Borrowed(text)),
            lockfiles,
            compacted_artifacts,
            incomplete: false,
        };
    }

    let mut source = String::with_capacity(kept_len);
    source.push_str(&text[..preamble_len]);
    cursor = next_diff_start(text, 0);
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        let Ok(paths) = validated_section_paths(section) else {
            return PreparedDiff {
                source: None,
                lockfiles: Vec::new(),
                compacted_artifacts: Vec::new(),
                incomplete: true,
            };
        };
        let path = paths.path;
        let compact_lockfile =
            is_known_lockfile(&path) && lockfile_evidence(&path, section).is_some();
        if !compact_lockfile && !is_compactable_generated_artifact(&path, section) {
            source.push_str(section);
        }
        cursor = (end < text.len()).then_some(end);
    }
    PreparedDiff {
        source: Some(Cow::Owned(source)),
        lockfiles,
        compacted_artifacts,
        incomplete: false,
    }
}

fn is_compactable_generated_artifact(path: &str, section: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let mut prefix_end = section.len().min(64 * 1024);
    while !section.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let lower = section[..prefix_end].to_ascii_lowercase();
    let explicit_generator = [
        "@generated",
        "generated by ",
        "sourcemappingurl=",
        "source mappingurl=",
        "do not edit",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let structured_source_map = normalized.ends_with(".map")
        && lower.contains("\"version\"")
        && lower.contains("\"mappings\"")
        && lower.contains("\"sources\"");
    let minified_bundle = (normalized.ends_with(".min.js") || normalized.ends_with(".min.css"))
        && explicit_generator
        && section.lines().any(|line| {
            matches!(line.as_bytes().first(), Some(b'+') | Some(b'-')) && line.len() >= 4_096
        });
    structured_source_map || minified_bundle
}

fn compacted_artifact_evidence(path: &str, section: &str) -> CompactedArtifactEvidence {
    let mut added = 0usize;
    let mut removed = 0usize;
    for line in section.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            added = added.saturating_add(1);
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed = removed.saturating_add(1);
        }
    }
    CompactedArtifactEvidence {
        path: path.to_string(),
        kind: if is_binary_section(section) {
            "binary change"
        } else {
            "verified generated artifact"
        },
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SectionPaths {
    old_path: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiffMarkerPath {
    Null,
    Path(String),
}

fn valid_diff_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn canonical_side_path(value: &str, prefix: &str) -> Option<DiffMarkerPath> {
    if value == "/dev/null" {
        return Some(DiffMarkerPath::Null);
    }
    let path = value.strip_prefix(prefix)?;
    valid_diff_path(path).then(|| DiffMarkerPath::Path(path.to_string()))
}

fn parse_git_side_marker_path(value: &str, prefix: &str) -> Option<DiffMarkerPath> {
    if value == "/dev/null" {
        return Some(DiffMarkerPath::Null);
    }
    let (decoded, trailing) = if value.starts_with('"') {
        parse_git_path_token(value)?
    } else {
        (value.split('\t').next()?.to_string(), "")
    };
    trailing.trim().is_empty().then_some(())?;
    canonical_side_path(&decoded, prefix)
}

fn parse_git_extended_path(value: &str) -> Option<String> {
    let (decoded, trailing) = if value.starts_with('"') {
        parse_git_path_token(value)?
    } else {
        (value.to_string(), "")
    };
    (trailing.trim().is_empty() && valid_diff_path(&decoded)).then_some(decoded)
}

fn parse_binary_marker_path_candidates(
    line: &str,
) -> Option<Vec<(DiffMarkerPath, DiffMarkerPath)>> {
    let inner = line
        .strip_prefix("Binary files ")?
        .strip_suffix(" differ")?;
    if inner.starts_with('"') {
        let (old, remainder) = parse_git_path_token(inner)?;
        let (new, trailing) = parse_git_path_token(remainder.strip_prefix(" and ")?)?;
        trailing.trim().is_empty().then_some(())?;
        return Some(vec![(
            canonical_side_path(&old, "a/")?,
            canonical_side_path(&new, "b/")?,
        )]);
    }
    let candidates = inner
        .match_indices(" and ")
        .filter_map(|(index, separator)| {
            Some((
                canonical_side_path(&inner[..index], "a/")?,
                canonical_side_path(&inner[index + separator.len()..], "b/")?,
            ))
        })
        .collect::<Vec<_>>();
    (!candidates.is_empty()).then_some(candidates)
}

fn marker_pair_matches(old: &DiffMarkerPath, new: &DiffMarkerPath, paths: &SectionPaths) -> bool {
    match (old, new) {
        (DiffMarkerPath::Path(old), DiffMarkerPath::Path(new)) => {
            old == &paths.old_path && new == &paths.path
        }
        (DiffMarkerPath::Null, DiffMarkerPath::Path(new)) => {
            paths.old_path == paths.path && new == &paths.path
        }
        (DiffMarkerPath::Path(old), DiffMarkerPath::Null) => {
            paths.old_path == paths.path && old == &paths.old_path
        }
        (DiffMarkerPath::Null, DiffMarkerPath::Null) => false,
    }
}

fn consume_diff_hunk_line(line: &str, old_left: &mut u32, new_left: &mut u32) -> bool {
    if *old_left == 0 && *new_left == 0 {
        return false;
    }
    match line.chars().next() {
        Some('+') if *new_left > 0 => *new_left -= 1,
        Some('-') if *old_left > 0 => *old_left -= 1,
        Some(' ') if *old_left > 0 && *new_left > 0 => {
            *old_left -= 1;
            *new_left -= 1;
        }
        _ => return false,
    }
    true
}

fn validated_section_paths(section: &str) -> Result<SectionPaths> {
    section_paths(section, true)
}

fn section_paths(section: &str, require_complete_hunks: bool) -> Result<SectionPaths> {
    let mut lines = section.lines();
    let candidates = lines
        .next()
        .and_then(|header| header.strip_prefix("diff --git "))
        .and_then(parse_diff_header_path_candidates)
        .context("diff section has an invalid path header")?;
    let mut old_marker = None;
    let mut new_marker = None;
    let mut rename_from = None;
    let mut rename_to = None;
    let mut copy_from = None;
    let mut copy_to = None;
    let mut binary_paths = None;
    let mut index_mode = None::<Option<String>>;
    let mut explicit_old_mode = None::<String>;
    let mut explicit_new_mode = None::<String>;
    let mut saw_change = false;
    let mut saw_hunk = false;
    let mut old_left = 0;
    let mut new_left = 0;

    while let Some(line) = lines.next() {
        if consume_diff_hunk_line(line, &mut old_left, &mut new_left) {
            continue;
        }
        if old_left != 0 || new_left != 0 {
            if line == "\\ No newline at end of file" {
                continue;
            }
            if !require_complete_hunks {
                break;
            }
            anyhow::bail!("diff section hunk body does not match its declared range");
        }
        if line == "GIT binary patch" {
            anyhow::ensure!(
                !saw_hunk,
                "diff section mixes text hunks with a binary patch"
            );
            anyhow::ensure!(
                !lines.any(|remaining| remaining.starts_with("@@")),
                "diff section mixes a binary patch with text hunks"
            );
            saw_change = true;
            break;
        }
        if let Some(header) = line.strip_prefix("@@ ") {
            anyhow::ensure!(
                binary_paths.is_none(),
                "diff section mixes binary markers with text hunks"
            );
            let Some((_, old_count, _, new_count)) = parse_hunk_header(header) else {
                if require_complete_hunks {
                    anyhow::bail!("diff section has a malformed hunk range");
                }
                break;
            };
            saw_hunk = true;
            saw_change = true;
            old_left = old_count;
            new_left = new_count;
            continue;
        }
        if line.starts_with("@@") {
            if require_complete_hunks {
                anyhow::bail!("diff section has a malformed hunk range");
            }
            break;
        }
        if line.starts_with([' ', '+', '-'])
            && !line.starts_with("--- ")
            && !line.starts_with("+++ ")
        {
            if require_complete_hunks {
                anyhow::bail!(if saw_hunk {
                    "diff section hunk body exceeds its declared range"
                } else {
                    "diff section has changed content outside a hunk"
                });
            }
            break;
        }
        if line.starts_with("index ") {
            anyhow::ensure!(
                index_mode.is_none(),
                "diff section repeats its index metadata"
            );
            let mode = unchanged_index_mode(line)?;
            if let Some(mode) = mode {
                anyhow::ensure!(
                    explicit_old_mode.as_deref().is_none_or(|old| old == mode)
                        && explicit_new_mode.as_deref().is_none_or(|new| new == mode),
                    "diff section index and explicit mode disagree"
                );
            }
            index_mode = Some(mode.map(str::to_string));
        } else if let Some(value) = line.strip_prefix("--- ") {
            anyhow::ensure!(
                old_marker.is_none(),
                "diff section repeats its old path marker"
            );
            old_marker = Some(
                parse_git_side_marker_path(value, "a/")
                    .context("diff section has an invalid old path marker")?,
            );
        } else if let Some(value) = line.strip_prefix("+++ ") {
            anyhow::ensure!(
                new_marker.is_none(),
                "diff section repeats its new path marker"
            );
            new_marker = Some(
                parse_git_side_marker_path(value, "b/")
                    .context("diff section has an invalid new path marker")?,
            );
        } else if let Some(value) = line.strip_prefix("rename from ") {
            anyhow::ensure!(rename_from.is_none(), "diff section repeats rename-from");
            rename_from = Some(
                parse_git_extended_path(value)
                    .context("diff section has an invalid rename-from path")?,
            );
            saw_change = true;
        } else if let Some(value) = line.strip_prefix("rename to ") {
            anyhow::ensure!(rename_to.is_none(), "diff section repeats rename-to");
            rename_to = Some(
                parse_git_extended_path(value)
                    .context("diff section has an invalid rename-to path")?,
            );
            saw_change = true;
        } else if let Some(value) = line.strip_prefix("copy from ") {
            anyhow::ensure!(copy_from.is_none(), "diff section repeats copy-from");
            copy_from = Some(
                parse_git_extended_path(value)
                    .context("diff section has an invalid copy-from path")?,
            );
            saw_change = true;
        } else if let Some(value) = line.strip_prefix("copy to ") {
            anyhow::ensure!(copy_to.is_none(), "diff section repeats copy-to");
            copy_to = Some(
                parse_git_extended_path(value)
                    .context("diff section has an invalid copy-to path")?,
            );
            saw_change = true;
        } else if line.starts_with("Binary files ") {
            anyhow::ensure!(
                !saw_hunk,
                "diff section mixes text hunks with binary markers"
            );
            anyhow::ensure!(binary_paths.is_none(), "diff section repeats binary paths");
            binary_paths = Some(
                parse_binary_marker_path_candidates(line)
                    .context("diff section has invalid binary path markers")?,
            );
            saw_change = true;
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            anyhow::ensure!(explicit_old_mode.is_none(), "diff section repeats old mode");
            let mode = validated_git_mode(mode)?;
            anyhow::ensure!(
                index_mode
                    .as_ref()
                    .and_then(Option::as_deref)
                    .is_none_or(|index| index == mode),
                "diff section index and old mode disagree"
            );
            explicit_old_mode = Some(mode.to_string());
            saw_change = true;
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            anyhow::ensure!(explicit_new_mode.is_none(), "diff section repeats new mode");
            let mode = validated_git_mode(mode)?;
            anyhow::ensure!(
                index_mode
                    .as_ref()
                    .and_then(Option::as_deref)
                    .is_none_or(|index| index == mode),
                "diff section index and new mode disagree"
            );
            explicit_new_mode = Some(mode.to_string());
            saw_change = true;
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            anyhow::ensure!(explicit_new_mode.is_none(), "diff section repeats new mode");
            explicit_new_mode = Some(validated_git_mode(mode)?.to_string());
            saw_change = true;
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            anyhow::ensure!(explicit_old_mode.is_none(), "diff section repeats old mode");
            explicit_old_mode = Some(validated_git_mode(mode)?.to_string());
            saw_change = true;
        }
    }

    if require_complete_hunks {
        anyhow::ensure!(
            old_left == 0 && new_left == 0,
            "diff section hunk body does not match its declared range"
        );
        anyhow::ensure!(
            !saw_hunk || (old_marker.is_some() && new_marker.is_some()),
            "diff section hunk has no file path marker pair"
        );
        anyhow::ensure!(saw_change, "diff section has no complete change evidence");
    }
    match (&old_marker, &new_marker) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => anyhow::bail!("diff section has an incomplete file path marker pair"),
    }
    match (&rename_from, &rename_to) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => anyhow::bail!("diff section has an incomplete rename path pair"),
    }
    match (&copy_from, &copy_to) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => anyhow::bail!("diff section has an incomplete copy path pair"),
    }
    anyhow::ensure!(
        rename_from.is_none() || copy_from.is_none(),
        "diff section mixes rename and copy paths"
    );

    let markers_match = old_marker
        .as_ref()
        .zip(new_marker.as_ref())
        .is_none_or(|(old, new)| {
            candidates
                .iter()
                .any(|paths| marker_pair_matches(old, new, paths))
        });
    let rename_matches = rename_from
        .as_ref()
        .zip(rename_to.as_ref())
        .is_none_or(|(old, new)| {
            candidates
                .iter()
                .any(|paths| old == &paths.old_path && new == &paths.path)
        });
    let copy_matches = copy_from
        .as_ref()
        .zip(copy_to.as_ref())
        .is_none_or(|(old, new)| {
            candidates
                .iter()
                .any(|paths| old == &paths.old_path && new == &paths.path)
        });
    let binary_matches = binary_paths.as_ref().is_none_or(|markers| {
        candidates.iter().any(|paths| {
            markers
                .iter()
                .any(|(old, new)| marker_pair_matches(old, new, paths))
        })
    });
    let matches_metadata = |paths: &SectionPaths| {
        old_marker
            .as_ref()
            .zip(new_marker.as_ref())
            .is_none_or(|(old, new)| marker_pair_matches(old, new, paths))
            && rename_from
                .as_ref()
                .zip(rename_to.as_ref())
                .is_none_or(|(old, new)| old == &paths.old_path && new == &paths.path)
            && copy_from
                .as_ref()
                .zip(copy_to.as_ref())
                .is_none_or(|(old, new)| old == &paths.old_path && new == &paths.path)
            && binary_paths.as_ref().is_none_or(|markers| {
                markers
                    .iter()
                    .any(|(old, new)| marker_pair_matches(old, new, paths))
            })
    };
    let matching = candidates
        .iter()
        .filter(|paths| matches_metadata(paths))
        .cloned()
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [paths] => Ok(paths.clone()),
        [] if !markers_match => {
            anyhow::bail!("diff header and file path markers disagree")
        }
        [] if !rename_matches => anyhow::bail!("diff header and rename paths disagree"),
        [] if !copy_matches => anyhow::bail!("diff header and copy paths disagree"),
        [] if !binary_matches => anyhow::bail!("diff header and binary paths disagree"),
        [] => anyhow::bail!("diff header has no canonical path match"),
        _ => anyhow::bail!("diff section has an unresolved ambiguous path header"),
    }
}

fn diff_section_path_resolutions(text: &str) -> Vec<(Option<SectionPaths>, bool)> {
    let mut resolutions = Vec::new();
    let mut cursor = next_diff_start(text, 0);
    while let Some(start) = cursor {
        let end = next_diff_start(text, start + "diff --git ".len()).unwrap_or(text.len());
        let section = &text[start..end];
        resolutions.push((
            section_paths(section, false).ok(),
            section_paths(section, true).is_ok(),
        ));
        cursor = (end < text.len()).then_some(end);
    }
    resolutions
}

fn parse_diff_header_path_candidates(rest: &str) -> Option<Vec<SectionPaths>> {
    if rest.starts_with('"') {
        let (old, remainder) = parse_git_path_token(rest)?;
        let (new, trailing) = parse_git_path_token(remainder.trim_start())?;
        trailing.trim().is_empty().then_some(())?;
        let old = old.strip_prefix("a/")?;
        let new = new.strip_prefix("b/")?;
        return (valid_diff_path(old) && valid_diff_path(new)).then(|| {
            vec![SectionPaths {
                old_path: old.to_string(),
                path: new.to_string(),
            }]
        });
    }
    let candidates = rest
        .match_indices(" b/")
        .filter_map(|(index, _)| {
            let old = rest[..index].strip_prefix("a/")?;
            let new = rest[index + 1..].strip_prefix("b/")?;
            (valid_diff_path(old) && valid_diff_path(new)).then(|| SectionPaths {
                old_path: old.to_string(),
                path: new.to_string(),
            })
        })
        .collect::<Vec<_>>();
    (!candidates.is_empty()).then_some(candidates)
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
                    b'a' => decoded.push(0x07),
                    b'b' => decoded.push(0x08),
                    b't' => decoded.push(b'\t'),
                    b'n' => decoded.push(b'\n'),
                    b'v' => decoded.push(0x0b),
                    b'f' => decoded.push(0x0c),
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
    if !lockfile_changed_lines_are_represented(path, section) {
        return None;
    }
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

fn lockfile_changed_lines_are_represented(path: &str, section: &str) -> bool {
    let name = path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let represented = |content: &str| {
        let trimmed = content.trim().trim_end_matches(',');
        if trimmed.is_empty() {
            return true;
        }
        match name.as_str() {
            "cargo.lock" => {
                trimmed == "[[package]]"
                    || parse_assignment(trimmed, "name").is_some()
                    || parse_assignment(trimmed, "version").is_some()
            }
            "package-lock.json" | "npm-shrinkwrap.json" => {
                matches!(trimmed, "{" | "}" | "[" | "]")
                    || json_string_field(trimmed, "version").is_some()
                    || trimmed
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix("\": {"))
                        .is_some()
            }
            "yarn.lock" => {
                (!content.chars().next().is_some_and(char::is_whitespace) && trimmed.ends_with(':'))
                    || trimmed.strip_prefix("version ").is_some()
                    || trimmed.strip_prefix("version:").is_some()
            }
            "pnpm-lock.yaml" => {
                let value = trimmed.trim_end_matches(':').trim_matches(['\'', '"']);
                value.rsplit_once('@').is_some_and(|(package, version)| {
                    !package.is_empty()
                        && version
                            .chars()
                            .next()
                            .is_some_and(|character| character.is_ascii_digit())
                })
            }
            // A go.sum record includes a checksum that the compact package
            // identity does not reproduce. Keep the raw bounded diff.
            "go.sum" => false,
            _ => false,
        }
    };
    let mut old_unrepresented = Vec::new();
    let mut new_unrepresented = Vec::new();
    for line in section.lines() {
        let target = if let Some(content) =
            line.strip_prefix('+').filter(|_| !line.starts_with("+++"))
        {
            if represented(content) {
                continue;
            }
            &mut new_unrepresented
        } else if let Some(content) = line.strip_prefix('-').filter(|_| !line.starts_with("---")) {
            if represented(content) {
                continue;
            }
            &mut old_unrepresented
        } else {
            continue;
        };
        target.push(&line[1..]);
    }
    // Complete-source reconstruction can express unchanged fields as one
    // removal plus one addition. Exact side equality proves those fields did
    // not change; any partial, reordered, or modified unknown remains raw.
    old_unrepresented == new_unrepresented
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

fn validated_git_mode(mode: &str) -> Result<&str> {
    anyhow::ensure!(
        matches!(mode, "100644" | "100755" | "120000" | "160000"),
        "diff section has an invalid Git mode"
    );
    Ok(mode)
}

fn unchanged_index_mode(line: &str) -> Result<Option<&str>> {
    let value = line
        .strip_prefix("index ")
        .context("diff section has malformed index metadata")?;
    let mut fields = value.split_whitespace();
    let object_ids = fields
        .next()
        .context("diff section index is missing object IDs")?;
    let mode = fields.next();
    anyhow::ensure!(
        fields.next().is_none(),
        "diff section index has trailing metadata"
    );
    let (old, new) = object_ids
        .split_once("..")
        .context("diff section index has invalid object IDs")?;
    let valid_object_id = |value: &str| {
        (3..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    anyhow::ensure!(
        old.len() == new.len() && valid_object_id(old) && valid_object_id(new),
        "diff section index has invalid object IDs"
    );
    mode.map(validated_git_mode).transpose()
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
    let mut index_mode = None::<Option<String>>;
    let path_resolutions = diff_section_path_resolutions(text);
    let mut complete = path_resolutions.iter().all(|(_, valid)| *valid);
    let mut path_resolutions = path_resolutions.into_iter().map(|(paths, _)| paths);

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
        if (old_left > 0 || new_left > 0)
            && consume_diff_hunk_line(line, &mut old_left, &mut new_left)
            && let Some(hunk) = current_hunk.as_mut()
        {
            hunk.lines.push(line.to_string());
            continue;
        }
        if line.starts_with("diff --git ") {
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
            let Some(Some(paths)) = path_resolutions.next() else {
                complete = false;
                current = None;
                continue;
            };
            current = Some(FileDiff {
                old_path: paths.old_path,
                path: paths.path,
                deleted: false,
                binary: false,
                old_mode: None,
                new_mode: None,
                hunks: Vec::new(),
            });
            index_mode = None;
        } else if line.starts_with("index ") {
            let parsed_mode = unchanged_index_mode(line);
            if index_mode.is_some() || parsed_mode.is_err() {
                complete = false;
            }
            let mode = parsed_mode.ok().flatten().map(str::to_string);
            if let (Some(f), Some(mode)) = (current.as_mut(), mode.as_ref()) {
                if f.old_mode.as_ref().is_some_and(|old| old != mode)
                    || f.new_mode.as_ref().is_some_and(|new| new != mode)
                {
                    complete = false;
                }
                f.old_mode.get_or_insert_with(|| mode.clone());
                f.new_mode.get_or_insert_with(|| mode.clone());
            }
            index_mode = Some(mode);
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            if let Some(f) = current.as_mut() {
                if validated_git_mode(mode).is_err()
                    || index_mode
                        .as_ref()
                        .and_then(Option::as_ref)
                        .is_some_and(|index| index != mode)
                {
                    complete = false;
                }
                f.old_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            if let Some(f) = current.as_mut() {
                if validated_git_mode(mode).is_err()
                    || index_mode
                        .as_ref()
                        .and_then(Option::as_ref)
                        .is_some_and(|index| index != mode)
                {
                    complete = false;
                }
                f.new_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            if let Some(f) = current.as_mut() {
                if validated_git_mode(mode).is_err() {
                    complete = false;
                }
                f.new_mode = Some(mode.to_string());
            }
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            if let Some(f) = current.as_mut() {
                if validated_git_mode(mode).is_err() {
                    complete = false;
                }
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
        } else if line.starts_with("@@") {
            flush_hunk(
                &mut current,
                &mut current_hunk,
                old_left,
                new_left,
                &mut complete,
            );
            complete = false;
        } else if let Some(h) = current_hunk.as_mut() {
            // The hunk is complete once every declared old- and new-side line has
            // been consumed. Anything after that (a blank separator, a stray
            // line) belongs to the next file, not this hunk.
            let hunk_complete = old_left == 0 && new_left == 0;
            if !hunk_complete && line.starts_with(['+', '-', ' ']) {
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
            } else if line == "\\ No newline at end of file" {
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
pub(crate) fn parse_hunk_header(header: &str) -> Option<(u32, u32, u32, u32)> {
    let range_of = |spec: &str| -> Option<(u32, u32)> {
        let parse_number = |value: &str| {
            (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| value.parse().ok())
                .flatten()
        };
        match spec.split_once(',') {
            Some((start, count)) => Some((parse_number(start)?, parse_number(count)?)),
            None => Some((parse_number(spec)?, 1)),
        }
    };
    let (ranges, _) = header.split_once(" @@")?;
    let mut ranges = ranges.split_whitespace();
    let (old_start, old_count) = range_of(ranges.next()?.strip_prefix('-')?)?;
    let (new_start, new_count) = range_of(ranges.next()?.strip_prefix('+')?)?;
    if ranges.next().is_some() {
        return None;
    }
    if (old_count > 0 && old_start == 0) || (new_count > 0 && new_start == 0) {
        return None;
    }
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
    compacted_artifacts: &[CompactedArtifactEvidence],
    max_bytes: usize,
    max_manifest_bytes: usize,
) -> ReviewBatchPlan {
    assert!(
        max_bytes >= MIN_REVIEW_BATCH_BYTES,
        "review batch limit must leave room for context"
    );
    let manifest = build_manifest(diff, lockfiles, compacted_artifacts, max_manifest_bytes);
    let mut plan = ReviewBatchPlan {
        incomplete: manifest.incomplete || manifest.text.len() >= max_bytes,
        metadata_count: manifest.metadata_count,
        ..Default::default()
    };
    if plan.incomplete {
        return plan;
    }

    let mut current = String::new();
    let mut current_hunks = BTreeSet::new();
    for file in &diff.files {
        if file.binary || file.hunks.is_empty() {
            continue;
        }
        for hunk in &file.hunks {
            let hunk_identity = HunkIdentity::new(&file.path, hunk);
            let Some(units) =
                render_hunk_units(file, hunk, max_bytes.saturating_sub(manifest.text.len()))
            else {
                plan.incomplete = true;
                return plan;
            };
            for unit in units {
                if !append_unit(
                    &mut plan,
                    &mut current,
                    &mut current_hunks,
                    &manifest.text,
                    &unit,
                    &hunk_identity,
                    max_bytes,
                ) {
                    plan.incomplete = true;
                    return plan;
                }
            }
        }
    }
    if !current.is_empty() {
        plan.batches.push(current);
        plan.batch_hunks.push(current_hunks);
    } else if plan.batches.is_empty()
        && (!diff.files.is_empty() || !lockfiles.is_empty() || !compacted_artifacts.is_empty())
    {
        plan.batches.push(manifest.text.clone());
        plan.batch_hunks.push(BTreeSet::new());
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
    compacted_artifacts: &[CompactedArtifactEvidence],
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
    for artifact in compacted_artifacts {
        let manifest_entry = format!(
            "- {} [compacted {} evidence]\n",
            manifest_path(&artifact.path),
            artifact.kind,
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
            "{}: {}, {} additions, {} deletions, {} raw bytes represented by bounded evidence",
            manifest_path(&artifact.path),
            artifact.kind,
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
    current_hunks: &mut BTreeSet<HunkIdentity>,
    manifest: &str,
    unit: &str,
    hunk: &HunkIdentity,
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
        plan.batch_hunks.push(std::mem::take(current_hunks));
        current.push_str(manifest);
        current.push('\n');
    }
    current.push_str(unit);
    current_hunks.insert(hunk.clone());
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

fn semantic_category_matches(content: &str) -> [bool; SEMANTIC_CATEGORIES.len()] {
    let lower = content.to_ascii_lowercase();
    std::array::from_fn(|index| {
        SEMANTIC_CATEGORIES[index]
            .1
            .iter()
            .any(|marker| lower.contains(marker))
    })
}

fn semantic_digest(batch: &str) -> String {
    struct Region {
        path: String,
        label: String,
        categories: Vec<Option<String>>,
        fallback: Option<String>,
        last: Option<String>,
        lines: Vec<(String, &'static str)>,
        lines_overflowed: bool,
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
                    categories: vec![None; SEMANTIC_CATEGORIES.len()],
                    fallback: None,
                    last: None,
                    lines: Vec::new(),
                    lines_overflowed: false,
                });
            }
            continue;
        }
        let Some(path) = current_path.as_ref() else {
            continue;
        };
        let trimmed = rendered.trim_start();
        let content = if let Some(deletion) = trimmed.strip_prefix("old ") {
            let deletion = deletion.trim_start();
            let Some((number, deletion)) = deletion.split_once(' ') else {
                continue;
            };
            if number.parse::<u32>().is_err() {
                continue;
            }
            let Some(content) = deletion.strip_prefix("- ") else {
                continue;
            };
            content
        } else {
            let Some((number, content)) = trimmed.split_once(' ') else {
                continue;
            };
            if number.parse::<u32>().is_err() {
                continue;
            }
            content
        };
        let region = current_region.get_or_insert_with(|| Region {
            path: path.clone(),
            label: "source region".to_string(),
            categories: vec![None; SEMANTIC_CATEGORIES.len()],
            fallback: None,
            last: None,
            lines: Vec::new(),
            lines_overflowed: false,
        });
        let bounded: String = rendered.chars().take(360).collect();
        region.fallback.get_or_insert_with(|| bounded.clone());
        region.last = Some(bounded.clone());
        let category_matches = semantic_category_matches(content);
        let primary_category = category_matches
            .iter()
            .position(|matched| *matched)
            .map(|index| SEMANTIC_CATEGORIES[index].0)
            .unwrap_or("complete-small-region");
        if region.lines.len() < 8 {
            region.lines.push((bounded.clone(), primary_category));
        } else {
            region.lines_overflowed = true;
        }
        for (category_index, matched) in category_matches.into_iter().enumerate() {
            if region.categories[category_index].is_none() && matched {
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
        if !region.lines_overflowed {
            for (rendered, category) in region.lines {
                if emitted.insert(rendered.clone()) {
                    out.push_str(&format!("@@ semantic category={category} @@\n{rendered}\n"));
                }
            }
            continue;
        }
        for ((category, _), rendered) in SEMANTIC_CATEGORIES.iter().zip(region.categories) {
            if let Some(rendered) = rendered
                && emitted.insert(rendered.clone())
            {
                out.push_str(&format!("@@ semantic category={category} @@\n{rendered}\n"));
            }
        }
        if let Some(rendered) = region.fallback
            && emitted.insert(rendered.clone())
        {
            out.push_str(&format!(
                "@@ semantic category=uncategorized @@\n{rendered}\n"
            ));
        }
        if let Some(rendered) = region.last
            && emitted.insert(rendered.clone())
        {
            out.push_str(&format!(
                "@@ semantic category=region-boundary @@\n{rendered}\n"
            ));
        }
    }
    out
}

fn rendered_new_evidence_range(rendered: &str, exact_semantic: bool) -> Option<(u32, u32, &str)> {
    let (number, marked) = rendered.trim_start().split_once(' ')?;
    let number = number.parse::<u32>().ok()?;
    let payload = marked
        .strip_prefix("+ ")
        .or_else(|| marked.strip_prefix("  "))?;
    (!payload.trim().is_empty()).then_some(())?;
    let end_line = if exact_semantic {
        exact_semantic_evidence_end_line(payload, number)?
    } else {
        number
    };
    Some((number, end_line, payload))
}

/// Return the segment that contains a citation in the exact model input.
fn review_batch_segments(annotated: &str, path: &str, line: u32) -> Vec<usize> {
    let exact_semantic = is_exact_semantic_batch(annotated);
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
        let Some((start, end, _)) = rendered_new_evidence_range(rendered, exact_semantic) else {
            continue;
        };
        if (start..=end).contains(&line) {
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

/// Require the model to copy the exact, non-empty new-side text it cited.
/// Number-only grounding accepts blank anchors and cannot distinguish an old
/// deletion from its replacement; this proof binds the finding to what the
/// model actually saw after the new-side marker.
pub fn review_batch_contains_exact_evidence(
    annotated: &str,
    path: &str,
    line: u32,
    evidence: Option<&str>,
) -> bool {
    review_batch_canonical_evidence(annotated, path, line, evidence).is_some()
}

/// Resolve a prompt citation to the exact new-side text Postil rendered. The
/// model may omit outer presentation whitespace, but durable evidence remains
/// byte-exact after this ingestion boundary.
pub fn review_batch_canonical_evidence(
    annotated: &str,
    path: &str,
    line: u32,
    evidence: Option<&str>,
) -> Option<String> {
    let evidence = evidence.filter(|value| !value.trim().is_empty())?;
    let payloads = review_batch_evidence_payloads(annotated, path, line);
    if let Some(exact) = payloads.iter().find(|payload| payload.as_str() == evidence) {
        return Some(exact.clone());
    }
    let trimmed_matches = payloads
        .into_iter()
        .filter(|payload| payload.trim() == evidence.trim())
        .collect::<Vec<_>>();
    let first = trimmed_matches.first()?.clone();
    trimmed_matches
        .iter()
        .all(|payload| payload == &first)
        .then_some(first)
}

fn review_batch_evidence_payloads(annotated: &str, path: &str, line: u32) -> Vec<String> {
    let exact_semantic = is_exact_semantic_batch(annotated);
    let mut current_path: Option<&str> = None;
    let mut payloads = Vec::new();
    for rendered in annotated.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            current_path = Some(prompt_header_path(header));
            continue;
        }
        if !current_path.is_some_and(|current| prompt_paths_equal(current, path)) {
            continue;
        }
        let Some((start, end, payload)) = rendered_new_evidence_range(rendered, exact_semantic)
        else {
            continue;
        };
        if !(start..=end).contains(&line) {
            continue;
        }
        if exact_semantic {
            if let Some(payload) = decode_exact_semantic_evidence(payload, start, line) {
                payloads.push(payload);
            }
        } else {
            payloads.push(payload.to_string());
        }
    }
    payloads
}

/// Resolve a prompt citation to the exact non-empty new-side text the model
/// must copy. This is exposed to the correction prompt, while final acceptance
/// continues to require an exact match through `review_batch_canonical_evidence`.
pub fn review_batch_expected_evidence(annotated: &str, path: &str, line: u32) -> Option<String> {
    let payloads = review_batch_evidence_payloads(annotated, path, line);
    let first = payloads.first()?.clone();
    payloads
        .iter()
        .all(|payload| payload == &first)
        .then_some(first)
}

pub fn review_batch_has_evidence_anchor(annotated: &str, path: &str, line: u32) -> bool {
    !review_batch_evidence_payloads(annotated, path, line).is_empty()
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
    let exact_semantic = is_exact_semantic_batch(annotated);
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
        let Some((start, end, _)) = rendered_new_evidence_range(rendered, exact_semantic) else {
            continue;
        };
        if (start..=end).contains(&line) {
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

#[derive(Debug)]
struct ScorerEvidenceSection {
    path: String,
    text: String,
    order: usize,
}

#[derive(Debug)]
struct RelatedScorerEvidenceCandidate {
    score: usize,
    order: usize,
    same_path: bool,
    test_path: bool,
    path_related: bool,
    term_matches: usize,
    text: String,
}

fn scorer_evidence_sections(annotated: &str) -> Vec<ScorerEvidenceSection> {
    let mut sections = Vec::new();
    let mut current_path = None::<String>;
    let mut current_text = String::new();

    let flush = |sections: &mut Vec<ScorerEvidenceSection>,
                 path: &mut Option<String>,
                 text: &mut String| {
        if let Some(path) = path.take()
            && !text.is_empty()
        {
            sections.push(ScorerEvidenceSection {
                path,
                text: std::mem::take(text),
                order: sections.len(),
            });
        }
    };

    for rendered in annotated.lines() {
        if let Some(header) = rendered.strip_prefix("### ") {
            flush(&mut sections, &mut current_path, &mut current_text);
            current_path = canonical_prompt_path(prompt_header_path(header))
                .or_else(|| Some(prompt_header_path(header).to_string()));
        }
        if current_path.is_some() {
            current_text.push_str(rendered);
            current_text.push('\n');
        }
    }
    flush(&mut sections, &mut current_path, &mut current_text);
    sections
}

fn append_complete_lines(output: &mut String, text: &str, max_bytes: usize) {
    for line in text.split_inclusive('\n') {
        if output.len().saturating_add(line.len()) > max_bytes {
            break;
        }
        output.push_str(line);
    }
}

/// Retain a deterministic, section-balanced subset of one source request for
/// later scorer fact-checking. Every retained byte comes from the exact review
/// request, and the caller supplies the per-request bound.
pub fn bounded_scorer_batch_evidence(annotated: &str, max_bytes: usize) -> String {
    if max_bytes == 0 {
        return String::new();
    }
    if annotated.len() <= max_bytes {
        return annotated.to_string();
    }
    let sections = scorer_evidence_sections(annotated);
    if sections.is_empty() {
        let mut output = String::new();
        append_complete_lines(&mut output, annotated, max_bytes);
        return output;
    }

    let mut output = String::new();
    for (index, section) in sections.iter().enumerate() {
        let sections_left = sections.len() - index;
        let share = max_bytes.saturating_sub(output.len()) / sections_left;
        if share == 0 {
            break;
        }
        let section_limit = output.len().saturating_add(share).min(max_bytes);
        append_complete_lines(&mut output, &section.text, section_limit);
    }
    output
}

fn scorer_query_terms(query: &str) -> Vec<String> {
    const STOP_WORDS: &[&str] = &[
        "after", "before", "because", "change", "check", "could", "finding", "from", "function",
        "line", "should", "their", "there", "these", "this", "verify", "with", "would",
    ];
    let mut terms = BTreeSet::new();

    let mut in_code = false;
    let mut code = String::new();
    for character in query.chars() {
        if character == '`' {
            if in_code {
                let term = code.trim().to_ascii_lowercase();
                if (4..=96).contains(&term.len()) {
                    terms.insert(term);
                }
                code.clear();
            }
            in_code = !in_code;
        } else if in_code {
            code.push(character);
        }
    }

    let mut token = String::new();
    for character in query.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            token.push(character.to_ascii_lowercase());
            continue;
        }
        if (4..=96).contains(&token.len()) && !STOP_WORDS.contains(&token.as_str()) {
            terms.insert(std::mem::take(&mut token));
        } else {
            token.clear();
        }
    }
    terms.into_iter().take(32).collect()
}

fn scorer_path_stem(path: &str) -> Option<String> {
    let name = path.rsplit('/').next()?;
    let stem = name.split('.').next()?.to_ascii_lowercase();
    (stem.len() >= 4).then_some(stem)
}

/// Select bounded changed-file evidence that can confirm or contradict a
/// finding outside its cited local window. Selection preserves relevant
/// same-file, test, and caller evidence instead of letting one large section
/// consume the whole budget.
pub fn render_related_scorer_evidence(
    review_batches: &[String],
    finding_path: &str,
    query: &str,
    max_bytes: usize,
) -> Option<String> {
    if max_bytes == 0 {
        return None;
    }
    let terms = scorer_query_terms(query);
    let finding_stem = scorer_path_stem(finding_path);
    let mut candidates = Vec::<RelatedScorerEvidenceCandidate>::new();
    let mut seen = HashSet::new();

    for (batch_index, batch) in review_batches.iter().enumerate() {
        for section in scorer_evidence_sections(batch) {
            if !seen.insert(section.text.clone()) {
                continue;
            }
            let lower_text = section.text.to_ascii_lowercase();
            let lower_path = section.path.to_ascii_lowercase();
            let same_path = section.path == finding_path;
            let path_related = finding_stem
                .as_ref()
                .is_some_and(|stem| lower_path.contains(stem));
            let term_matches = terms
                .iter()
                .filter(|term| lower_text.contains(term.as_str()))
                .count();
            if !same_path && !path_related && term_matches == 0 {
                continue;
            }
            let test_path = lower_path.contains("test") || lower_path.contains("spec");
            let score = usize::from(same_path) * 10_000
                + usize::from(path_related) * 1_000
                + usize::from(test_path && term_matches > 0) * 500
                + term_matches * 100;
            let order = batch_index.saturating_mul(1_000_000) + section.order;
            candidates.push(RelatedScorerEvidenceCandidate {
                score,
                order,
                same_path,
                test_path,
                path_related,
                term_matches,
                text: section.text,
            });
        }
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then(left.order.cmp(&right.order))
    });
    let mut selected = Vec::new();
    let mut select_first = |predicate: &dyn Fn(&RelatedScorerEvidenceCandidate) -> bool| {
        if let Some((index, _)) = candidates
            .iter()
            .enumerate()
            .find(|(index, candidate)| !selected.contains(index) && predicate(candidate))
        {
            selected.push(index);
        }
    };
    select_first(&|candidate| candidate.same_path);
    select_first(&|candidate| {
        !candidate.same_path && candidate.test_path && candidate.term_matches > 0
    });
    select_first(&|candidate| {
        !candidate.same_path && !candidate.test_path && candidate.path_related
    });
    select_first(&|candidate| !candidate.same_path && candidate.term_matches > 0);
    for index in 0..candidates.len() {
        if selected.len() >= 4 {
            break;
        }
        if !selected.contains(&index) {
            selected.push(index);
        }
    }

    let mut output = String::new();
    for (position, index) in selected.iter().enumerate() {
        let section = &candidates[*index].text;
        if !output.is_empty() && output.len().saturating_add(1) <= max_bytes {
            output.push('\n');
        }
        let sections_left = selected.len() - position;
        let share = max_bytes.saturating_sub(output.len()) / sections_left;
        if share == 0 {
            break;
        }
        let section_limit = output.len().saturating_add(share).min(max_bytes);
        append_complete_lines(&mut output, section, section_limit);
    }
    (!output.is_empty()).then_some(output)
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
    fn external_snapshot_is_private_and_immutable_after_acquisition() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.diff");
        std::fs::write(&path, SAMPLE).unwrap();
        let snapshot = DiffSnapshot::from_path(&path).unwrap();
        std::fs::write(&path, b"\xff\x00mutated").unwrap();
        assert_eq!(snapshot.as_str(), SAMPLE);
        assert!(prepare_review(&snapshot).is_ok());
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
        let header_only = parse("diff --git a/a.rs b/a.rs\nindex 1111111..2222222 100644\n");
        assert!(!header_only.complete);

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

        let outside_hunk = parse(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n+hidden();\n@@ -1 +1 @@\n-old();\n+new();\n",
        );
        assert!(!outside_hunk.complete);
    }

    #[test]
    fn hunk_content_that_resembles_file_markers_remains_source() {
        let source = concat!(
            "diff --git a/config.rs b/config.rs\n",
            "--- a/config.rs\n",
            "+++ b/config.rs\n",
            "@@ -1 +1 @@\n",
            "-- disabled;\n",
            "+++ enabled;\n",
        );
        validated_section_paths(source).unwrap();
        let parsed = parse(source);
        assert!(parsed.complete);
        assert_eq!(parsed.files[0].path, "config.rs");
        assert_eq!(
            parsed.files[0].hunks[0].lines,
            vec!["-- disabled;", "+++ enabled;"]
        );
        assert!(prepare_review(&DiffSnapshot::from_bytes(source.as_bytes()).unwrap()).is_ok());
    }

    #[test]
    fn strict_raw_headers_resolve_ambiguous_and_quoted_paths() {
        let renamed = "diff --git a/old b/日.rs b/new b/日.rs\nsimilarity index 90%\nrename from old b/日.rs\nrename to new b/日.rs\n--- a/old b/日.rs\n+++ b/new b/日.rs\n@@ -1 +1 @@\n-old();\n+new();\n";
        let copied = "diff --git a/source b/name.rs b/copy b/name.rs\nsimilarity index 90%\ncopy from source b/name.rs\ncopy to copy b/name.rs\n--- a/source b/name.rs\n+++ b/copy b/name.rs\n@@ -1 +1 @@\n-old();\n+new();\n";
        let binary = "diff --git a/old and name.bin b/new and name.bin\nBinary files a/old and name.bin and b/new and name.bin differ\n";
        let quoted = "diff --git \"a/src/tab\\tname.rs\" \"b/src/tab\\tname.rs\"\n--- \"a/src/tab\\tname.rs\"\n+++ \"b/src/tab\\tname.rs\"\n@@ -0,0 +1 @@\n+safe();\n";

        for (source, old_path, path) in [
            (renamed, "old b/日.rs", "new b/日.rs"),
            (copied, "source b/name.rs", "copy b/name.rs"),
            (binary, "old and name.bin", "new and name.bin"),
            (quoted, "src/tab\tname.rs", "src/tab\tname.rs"),
        ] {
            let paths = validated_section_paths(source).unwrap();
            assert_eq!(paths.old_path, old_path, "{source}");
            assert_eq!(paths.path, path, "{source}");
            let parsed = parse(source);
            assert!(parsed.complete, "{source}");
            assert_eq!(parsed.files[0].old_path, old_path, "{source}");
            assert_eq!(parsed.files[0].path, path, "{source}");
        }
    }

    #[test]
    fn additions_and_deletions_match_their_canonical_header_identity() {
        for source in [
            "diff --git a/new.rs b/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/new.rs\n@@ -0,0 +1 @@\n+added();\n",
            "diff --git a/old.rs b/old.rs\ndeleted file mode 100644\n--- a/old.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-removed();\n",
        ] {
            let paths = validated_section_paths(source).unwrap();
            assert_eq!(paths.old_path, paths.path);
            assert!(parse(source).complete);
            assert!(!prepare_diff(source).incomplete);
        }
    }

    #[test]
    fn every_raw_path_identity_must_match_the_canonical_header() {
        let invalid = [
            "diff --git a/src/old.rs b/src/new.rs\n--- a/src/old.rs\n+++ b/src/other.rs\n@@ -1 +1 @@\n-old();\n+new();\n",
            "diff --git a/src/old.rs b/src/new.rs\nrename from Cargo.lock\nrename to src/new.rs\n--- a/src/old.rs\n+++ b/src/new.rs\n@@ -1 +1 @@\n-old();\n+new();\n",
            "diff --git a/src/old.rs b/src/new.rs\ncopy from vendor/lib/Runner.java\ncopy to src/new.rs\n--- a/src/old.rs\n+++ b/src/new.rs\n@@ -1 +1 @@\n-old();\n+new();\n",
            "diff --git a/assets/old.bin b/assets/new.bin\nBinary files a/src/auth/control.bin and b/assets/new.bin differ\n",
            "diff --git a/old b/name.rs b/new b/name.rs\nold mode 100644\nnew mode 100755\n",
        ];
        for source in invalid {
            assert!(
                validated_section_paths(source).is_err(),
                "accepted {source}"
            );
            assert!(!parse(source).complete, "parsed {source}");
            assert!(prepare_diff(source).incomplete, "prepared {source}");
        }
    }

    #[test]
    fn malformed_hunk_grammar_and_mixed_binary_sections_fail_before_planning() {
        for header in [
            "@@ +1 -1 @@",
            "@@ -1 +1",
            "@@ -1 +1 trailing @@",
            "@@ -1,+1 +1 @@",
        ] {
            let source = format!(
                "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n{header}\n-old();\n+new();\n"
            );
            assert!(
                validated_section_paths(&source).is_err(),
                "accepted {header}"
            );
            assert!(!parse(&source).complete, "parsed {header}");
        }
        let mixed = "diff --git a/src/lib.rs b/src/lib.rs\nBinary files a/src/lib.rs and b/src/lib.rs differ\n@@ -1 +1 @@\n-old();\n+new();\n";
        assert!(validated_section_paths(mixed).is_err());
        let missing_markers =
            "diff --git a/src/lib.rs b/src/lib.rs\n@@ -1 +1 @@\n-old();\n+new();\n";
        let snapshot = DiffSnapshot::from_bytes(missing_markers.as_bytes()).unwrap();
        assert!(prepare_review(&snapshot).is_err());
    }

    #[test]
    fn rename_ignore_requires_both_canonical_paths_to_match() {
        let source = "diff --git a/src/auth/permission.ts b/generated/permission.ts\nsimilarity index 100%\nrename from src/auth/permission.ts\nrename to generated/permission.ts\n";
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        assert!(
            prepare_review_with_ignore(&snapshot, &["generated/**".to_string()])
                .unwrap()
                .has_source
        );

        let ignored = "diff --git a/generated/old.ts b/generated/new.ts\nsimilarity index 100%\nrename from generated/old.ts\nrename to generated/new.ts\n";
        let snapshot = DiffSnapshot::from_bytes(ignored.as_bytes()).unwrap();
        assert!(
            !prepare_review_with_ignore(&snapshot, &["generated/**".to_string()])
                .unwrap()
                .has_source
        );
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
    fn git_named_control_escapes_decode_without_losing_identity() {
        let source = "diff --git \"a/src/alarm\\aback\\bvertical\\vform\\f.rs\" \"b/src/alarm\\aback\\bvertical\\vform\\f.rs\"\n--- \"a/src/alarm\\aback\\bvertical\\vform\\f.rs\"\n+++ \"b/src/alarm\\aback\\bvertical\\vform\\f.rs\"\n@@ -0,0 +1 @@\n+safe();\n";
        let parsed = parse(source);
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(
            parsed.files[0].path,
            "src/alarm\u{7}back\u{8}vertical\u{b}form\u{c}.rs"
        );
        assert!(!prepare_diff(source).incomplete);
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
    fn scorer_batch_evidence_balances_changed_file_sections_under_bound() {
        let batch = (1..=4)
            .map(|index| {
                format!(
                    "### src/file_{index}.rs\n@@ region @@\n{index:>6} + {}\n",
                    format!("value_{index}();").repeat(80)
                )
            })
            .collect::<String>();
        let retained = bounded_scorer_batch_evidence(&batch, 800);
        assert!(retained.len() <= 800);
        for index in 1..=4 {
            assert!(
                retained.contains(&format!("### src/file_{index}.rs")),
                "section {index} was starved by earlier evidence"
            );
        }
    }

    #[test]
    fn related_scorer_evidence_finds_same_file_guards_and_matching_tests() {
        let corpus = vec![
            "### src/orders.rs\n@@ first @@\n    20 + update_order(row);\n\
             ### src/orders.rs\n@@ guard @@\n    40 + let row = load_order_for_update(id);\n"
                .to_string(),
            "### tests/orders.rs\n@@ regression @@\n    15 + assert!(query.contains(\"FOR UPDATE\"));\n\
             ### docs/unrelated.md\n@@ prose @@\n     1 + unrelated release note\n"
                .to_string(),
        ];
        let evidence = render_related_scorer_evidence(
            &corpus,
            "src/orders.rs",
            "The update may race. Verify `load_order_for_update` issues `FOR UPDATE`.",
            1_024,
        )
        .unwrap();
        assert!(evidence.len() <= 1_024);
        assert!(evidence.contains("load_order_for_update"));
        assert!(evidence.contains("tests/orders.rs"));
        assert!(evidence.contains("FOR UPDATE"));
        assert!(!evidence.contains("unrelated release note"));
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
    fn generated_extension_alone_never_compacts_hand_maintained_source() {
        let source = "diff --git a/web/security.min.js b/web/security.min.js\n--- a/web/security.min.js\n+++ b/web/security.min.js\n@@ -0,0 +1 @@\n+eval(userInput);\n";
        let prepared = prepare_diff(source);
        assert!(prepared.compacted_artifacts.is_empty());
        assert!(
            prepared
                .source
                .as_deref()
                .unwrap()
                .contains("eval(userInput)")
        );
    }

    #[test]
    fn generated_bundle_and_structured_source_map_use_bounded_evidence() {
        let bundle = format!(
            "diff --git a/web/app.min.js b/web/app.min.js\n--- a/web/app.min.js\n+++ b/web/app.min.js\n@@ -0,0 +1 @@\n+/* generated by esbuild; do not edit */{}\n",
            "x".repeat(4_096)
        );
        let map = "diff --git a/web/app.js.map b/web/app.js.map\n--- a/web/app.js.map\n+++ b/web/app.js.map\n@@ -0,0 +1 @@\n+{\"version\":3,\"sources\":[\"app.ts\"],\"mappings\":\"AAAA\"}\n";
        let combined = format!("{bundle}{map}");
        let prepared = prepare_diff(&combined);
        assert_eq!(prepared.compacted_artifacts.len(), 2);
        assert_eq!(prepared.source.as_deref(), Some(""));
        assert!(
            prepared
                .compacted_artifacts
                .iter()
                .all(|artifact| artifact.kind == "verified generated artifact")
        );
    }

    #[test]
    fn recursive_synthesis_retains_distant_first_and_last_regions() {
        let digests = (1..=400)
            .map(|index| {
                format!(
                    "### src/file_{index:03}.rs\n@@ semantic region: source @@\n@@ semantic category=uncategorized @@\n{index:>6} + {}\n",
                    if index == 1 {
                        "validate_pair(input);"
                    } else if index == 400 {
                        "dangerous_sink(original);"
                    } else {
                        "ordinary_change();"
                    }
                )
            })
            .collect::<Vec<_>>();
        let mut level = pack_semantic_digests(&digests, 1, 24_000).unwrap();
        while level.len() > 1 {
            let previous = level.len();
            level = pack_semantic_digests(&level, 2, 24_000).unwrap();
            assert!(level.len() < previous);
        }
        assert!(level[0].contains("validate_pair(input)"));
        assert!(level[0].contains("dangerous_sink(original)"));
    }

    #[test]
    fn semantic_compaction_retains_middle_high_signal_evidence() {
        let digest = format!(
            "### src/first.rs\n@@ semantic category=uncategorized @@\n1 + FIRST_BOUNDARY {}\n\
             ### src/risk.rs\n@@ semantic category=sinks @@\n2 + MIDDLE_SINK dangerous_sink(input) {}\n\
             ### src/last.rs\n@@ semantic category=uncategorized @@\n3 + LAST_BOUNDARY {}\n",
            "a".repeat(1_500),
            "b".repeat(1_500),
            "c".repeat(1_500)
        );
        let compacted = compact_semantic_digest(digest, 1_200).unwrap();
        assert!(compacted.len() <= 1_200);
        assert!(compacted.contains("FIRST_BOUNDARY"));
        assert!(compacted.contains("MIDDLE_SINK dangerous_sink(input)"));
        assert!(compacted.contains("LAST_BOUNDARY"));
        assert!(compacted.contains("semantic category=sinks"));
    }

    #[test]
    fn semantic_compaction_bounds_long_unicode_identity_by_utf8_bytes() {
        let path = format!("src/{}.rs", "界".repeat(2_000));
        let evidence = format!("7 + dangerous_sink({})", "🧪".repeat(2_000));
        let digest = format!("### {path}\n@@ semantic category=sinks @@\n{evidence}\n");
        let compacted = compact_semantic_digest(digest, 4_096).unwrap();
        assert!(compacted.len() <= 4_096);
        assert!(compacted.contains("semantic category=sinks"));
        assert!(compacted.matches("…#").count() >= 2);
        assert!(compacted.is_char_boundary(compacted.len()));
    }

    #[test]
    fn truncated_sha256_identities_distinguish_long_shared_prefixes() {
        let shared = "same-prefix-".repeat(400);
        let first = bound_utf8_identity(&format!("{shared}first"), 64).unwrap();
        let second = bound_utf8_identity(&format!("{shared}second"), 64).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
        assert!(first.starts_with("same-prefix-"));
        assert!(second.starts_with("same-prefix-"));
    }

    #[test]
    fn semantic_compaction_obeys_exact_and_one_byte_over_capacity() {
        let digest = format!(
            "### src/exact.rs\n@@ semantic category=validation @@\n9 + validate(input); {}\n",
            "x".repeat(1_000)
        );
        let exact = digest.len();
        assert_eq!(
            compact_semantic_digest(digest.clone(), exact).unwrap(),
            digest
        );
        let compacted = compact_semantic_digest(digest, exact - 1).unwrap();
        assert!(compacted.len() < exact);
        assert!(compacted.contains("validate(input)"));
    }

    #[test]
    fn semantic_compaction_retains_uncategorized_changed_boundaries() {
        let digest = format!(
            "### src/late.rs\n@@ semantic category=uncategorized @@\n     1   context {}\n     2 + let AUTHORITATIVE_LAST_PAGE = true;\n     3   trailing {}\n",
            "a".repeat(2_000),
            "b".repeat(2_000),
        );
        let compacted = compact_semantic_digest(digest, 700).unwrap();
        assert!(compacted.contains("AUTHORITATIVE_LAST_PAGE"));
        assert!(compacted.contains("context"));
        assert!(compacted.contains("trailing"));
    }

    #[test]
    fn semantic_compaction_rejects_deterministically_too_small_capacity() {
        let digest = format!(
            "### src/tiny.rs\n@@ semantic category=sinks @@\n1 + dangerous_sink(input); {}\n",
            "x".repeat(1_000)
        );
        let error = compact_semantic_digest(digest, 32).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("capacity too small for boundary and high-signal evidence")
        );
    }

    #[test]
    fn semantic_digest_packing_halves_two_near_half_bound_inputs() {
        let digests = ["first", "second"]
            .map(|path| {
                format!(
                    "### src/{path}.rs\n@@ semantic category=contracts @@\n1 + fn {path}() {{}} // {}\n",
                    "x".repeat(2_400)
                )
            })
            .to_vec();
        let packed = pack_semantic_digests(&digests, 1, MIN_REVIEW_BATCH_BYTES).unwrap();
        assert_eq!(packed.len(), 1);
        assert!(packed[0].len() <= MIN_REVIEW_BATCH_BYTES);
        assert!(packed[0].contains("src/first.rs"));
        assert!(packed[0].contains("src/second.rs"));
    }

    #[test]
    fn semantic_compaction_retains_sequential_source_window_ordinals() {
        let digest = format!(
            "Source window 1:\n### src/one.rs\n@@ semantic category=uncategorized @@\n1 + FIRST {}\n\
             Source window 2:\n### src/two.rs\n@@ semantic category=sinks @@\n2 + dangerous_sink(input) {}\n\
             Source window 3:\n### src/three.rs\n@@ semantic category=uncategorized @@\n3 + LAST {}\n",
            "a".repeat(1_000),
            "b".repeat(1_000),
            "c".repeat(1_000)
        );
        let compacted = compact_semantic_digest(digest, 1_200).unwrap();
        let first = compacted.find("Source window 1:").unwrap();
        let second = compacted.find("Source window 2:").unwrap();
        let third = compacted.find("Source window 3:").unwrap();
        assert!(first < second && second < third);
    }

    #[test]
    fn interactive_context_streams_distant_evidence_without_byte_truncation() {
        use std::fmt::Write as _;

        let mut source = String::from(
            "diff --git a/src/flow.rs b/src/flow.rs\n--- a/src/flow.rs\n+++ b/src/flow.rs\n@@ -0,0 +1,400 @@\n",
        );
        for line in 1..=400 {
            if line == 1 {
                source.push_str("+let checked = validate_pair(input);\n");
            } else if line == 400 {
                source.push_str("+dangerous_sink(original);\n");
            } else {
                writeln!(
                    source,
                    "+let padding_{line} = ordinary; // {}",
                    "x".repeat(1_000)
                )
                .unwrap();
            }
        }
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let (context, reserved) = bounded_respond_context(&snapshot, 120_000, 24_000).unwrap();
        assert!(!reserved);
        assert!(context.len() <= 120_000);
        assert!(context.contains("validate_pair(input)"));
        assert!(context.contains("dangerous_sink(original)"));
        assert!(!context.contains("diff truncated"));
    }

    #[test]
    fn malformed_and_unsupported_lockfiles_use_bounded_source_review() {
        let malformed = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,5 +1,5 @@\n-checksum = \"old-one\"\n-source = \"old-two\"\n-checksum = \"old-interior\"\n-source = \"old-four\"\n-checksum = \"old-five\"\n+checksum = \"new-one\"\n+source = \"new-two\"\n+checksum = \"new-interior\"\n+source = \"new-four\"\n+checksum = \"new-five\"\n";
        let malformed = prepare_diff(malformed);
        assert!(!malformed.incomplete);
        assert!(malformed.lockfiles.is_empty());
        assert!(
            malformed
                .source
                .as_deref()
                .unwrap()
                .contains("new-interior")
        );
        let unsupported = "diff --git a/composer.lock b/composer.lock\n--- a/composer.lock\n+++ b/composer.lock\n@@ -1 +1 @@\n-old\n+new\n";
        let unsupported = prepare_diff(unsupported);
        assert!(!unsupported.incomplete);
        assert!(unsupported.lockfiles.is_empty());
        assert!(
            unsupported
                .source
                .as_deref()
                .unwrap()
                .contains("composer.lock")
        );
    }

    #[test]
    fn partial_lockfile_records_and_unrepresented_security_fields_stay_raw() {
        for source in [
            "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,4 +1,4 @@\n name = \"package-one\"\n-version = \"1.0.0\"\n+version = \"2.0.0\"\n-source = \"registry+https://trusted.example/index\"\n+source = \"registry+https://attacker.example/index\"\n",
            "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,4 +1,4 @@\n name = \"package-one\"\n version = \"1.0.0\"\n-checksum = \"trusted\"\n+checksum = \"attacker\"\n",
            "diff --git a/package-lock.json b/package-lock.json\n--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1,4 +1,4 @@\n \"left-pad\": {\n \"version\": \"1.0.0\",\n-\"resolved\": \"https://trusted.example/pkg.tgz\"\n+\"resolved\": \"https://attacker.example/pkg.tgz\"\n",
            "diff --git a/package-lock.json b/package-lock.json\n--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1,4 +1,4 @@\n \"left-pad\": {\n \"version\": \"1.0.0\",\n-\"integrity\": \"sha512-trusted\"\n+\"integrity\": \"sha512-attacker\"\n",
            "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,4 +1,4 @@\n name = \"package-one\"\n version = \"1.0.0\"\n-custom = \"trusted\"\n+custom = \"attacker\"\n",
        ] {
            let prepared = prepare_diff(source);
            assert!(prepared.lockfiles.is_empty());
            assert_eq!(prepared.source.as_deref(), Some(source));
        }
    }

    #[test]
    fn full_file_lockfile_reconstruction_compacts_exactly_unchanged_unknown_fields() {
        let source = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,3 +1,3 @@ bounded full-file reconstruction\n-name = \"large-dependency\"\n-version = \"1.2.2\"\n-checksum = \"same-large-hash\"\n+name = \"large-dependency\"\n+version = \"1.2.3\"\n+checksum = \"same-large-hash\"\n";
        let prepared = prepare_diff(source);
        assert_eq!(prepared.source.as_deref(), Some(""));
        assert_eq!(
            prepared.lockfiles[0].changes,
            [
                "removed large-dependency@1.2.2",
                "added large-dependency@1.2.3"
            ]
        );
    }

    #[test]
    fn vendor_source_is_reviewed_unless_generation_is_proven() {
        let source = "diff --git a/vendor/security.js b/vendor/security.js\n--- a/vendor/security.js\n+++ b/vendor/security.js\n@@ -0,0 +1 @@\n+eval(userInput);\n";
        let prepared = prepare_diff(source);
        assert!(prepared.lockfiles.is_empty());
        assert!(prepared.compacted_artifacts.is_empty());
        assert!(
            prepared
                .source
                .as_deref()
                .unwrap()
                .contains("eval(userInput)")
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
    fn exact_evidence_rejects_blank_and_deleted_anchors() {
        let batch = "### src/a.rs\n@@ first @@\n    10 - removed command\n    10 + replacement command\n    11 + \n    12   context\n    13 +   indented replacement\n";
        assert!(review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            10,
            Some("replacement command")
        ));
        assert!(!review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            10,
            Some("removed command")
        ));
        assert!(!review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            11,
            Some("")
        ));
        assert!(review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            12,
            Some("context")
        ));
        assert!(review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            13,
            Some("indented replacement")
        ));
        assert_eq!(
            review_batch_canonical_evidence(batch, "src/a.rs", 13, Some("indented replacement"))
                .as_deref(),
            Some("  indented replacement")
        );
        assert_eq!(
            review_batch_expected_evidence(batch, "src/a.rs", 10).as_deref(),
            Some("replacement command")
        );
        assert_eq!(
            review_batch_expected_evidence(batch, "src/a.rs", 13).as_deref(),
            Some("  indented replacement")
        );
        assert_eq!(review_batch_expected_evidence(batch, "src/a.rs", 11), None);
        assert_eq!(review_batch_expected_evidence(batch, "src/a.rs", 99), None);
        assert!(!review_batch_contains_exact_evidence(
            batch,
            "src/a.rs",
            13,
            Some("indented  replacement")
        ));

        let repeated = "### src/a.rs\n@@ first @@\n    13 + first slice\n@@ second @@\n    13 + second slice\n";
        assert_eq!(
            review_batch_expected_evidence(repeated, "src/a.rs", 13),
            None
        );
        assert!(review_batch_has_evidence_anchor(repeated, "src/a.rs", 13));
        assert_eq!(
            review_batch_canonical_evidence(repeated, "src/a.rs", 13, Some("second slice"))
                .as_deref(),
            Some("second slice")
        );

        let whitespace_distinct = "### src/a.rs\n@@ first @@\n    13 +  changed();\n@@ second @@\n    13 +   changed();\n";
        assert_eq!(
            review_batch_canonical_evidence(
                whitespace_distinct,
                "src/a.rs",
                13,
                Some("changed();")
            ),
            None
        );
        assert_eq!(
            review_batch_canonical_evidence(
                whitespace_distinct,
                "src/a.rs",
                13,
                Some("  changed();")
            )
            .as_deref(),
            Some("  changed();")
        );
        assert_eq!(
            review_batch_expected_evidence(whitespace_distinct, "src/a.rs", 13),
            None
        );
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

    #[test]
    fn workspace_budget_is_shared_across_live_spools() {
        let budget = WorkspaceBudget::with_limit(12);
        let mut first = DiffSpool::new_in(budget.clone()).unwrap();
        let mut second = DiffSpool::new_in(budget.clone()).unwrap();
        first.write_all(b"12345678").unwrap();
        assert_eq!(budget.retained_bytes(), 8);
        let error = second.write_all(b"12345").unwrap_err();
        assert!(error.to_string().contains("operation quota"));
        drop(first);
        second.write_all(b"12345").unwrap();
        assert_eq!(budget.retained_bytes(), 5);
    }

    #[test]
    fn hosted_planner_bounds_large_handwritten_diff_without_losing_global_synthesis() {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 1..=80 {
            writeln!(
                source,
                "diff --git a/src/file_{file}.rs b/src/file_{file}.rs\n--- a/src/file_{file}.rs\n+++ b/src/file_{file}.rs\n@@ -0,0 +1 @@\n+fn changed_{file}() {{ validate(input); {} }}",
                "x".repeat(2_000)
            )
            .unwrap();
        }
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            MIN_REVIEW_BATCH_BYTES,
            MIN_REVIEW_BATCH_BYTES / 3,
            false,
        )
        .unwrap();
        assert!(batches.count > 22);
        assert!(batches.source_count < batches.count);
        let candidates = batches.hosted_candidates(5, 32).unwrap();
        assert_eq!(candidates.source_batch_count, batches.source_count);
        assert!(candidates.mandatory_ids.len() <= 5);
        assert!(candidates.mandatory_ids.contains(&1));
        assert!(candidates.mandatory_ids.iter().any(|id| *id > 22));
        let selected_ids = candidates
            .mandatory_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let selected_source_count = batches.selected_source_count(&selected_ids);
        let selected = batches.selected_batches(&selected_ids).unwrap();
        assert_eq!(selected.len(), candidates.mandatory_ids.len());
        assert!(selected_source_count < selected.len());
        assert!(
            selected
                .iter()
                .any(|batch| batch.contains("Cross-window semantic digests"))
        );
    }

    #[test]
    fn hosted_planner_retains_an_interior_file_path_in_compacted_evidence() {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 0..8 {
            if file == 4 {
                source.push_str(
                    "diff --git a/src/ui/copy.ts b/src/ui/copy.ts\n--- a/src/ui/copy.ts\n+++ b/src/ui/copy.ts\n@@ -42,3 +42,4 @@\n export const heading = 'Account';\n export const description = 'Manage your account';\n+export const validatedHint = 'Changes save automatically';\n export const action = 'Save';\n",
                );
            }
            let path = format!("src/ordinary/segment-{file}.ts");
            writeln!(
                source,
                "diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,200 @@"
            )
            .unwrap();
            for line in 0..200 {
                if file == 0 && line == 0 {
                    source.push_str(
                        "+export const accessPermissionLabel = 'Account access'; // ordinary display copy\n",
                    );
                } else {
                    writeln!(
                        source,
                        "+export const ordinary_{file}_{line} = {}; // ordinary source behavior",
                        file + line
                    )
                    .unwrap();
                }
            }
        }

        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            MIN_REVIEW_BATCH_BYTES,
            MIN_REVIEW_BATCH_BYTES / 3,
            false,
        )
        .unwrap();
        let candidates = batches.hosted_candidates(5, 96).unwrap();
        let target_in_source = candidates.manifest.split("\nBatch ").skip(1).any(|entry| {
            entry
                .lines()
                .next()
                .is_some_and(|header| header.ends_with("kind=source"))
                && entry.contains("### src/ui/copy.ts\n")
        });
        assert!(
            target_in_source,
            "interior path missing from source candidate evidence"
        );
    }

    #[test]
    fn separate_batch_budgets_reject_a_source_limit_below_the_semantic_floor() {
        let snapshot = DiffSnapshot::from_bytes(
            b"diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n",
        )
        .unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let error = spool_model_batches_with_synthesis_budget(
            &mut prepared,
            MIN_REVIEW_BATCH_BYTES - 1,
            MIN_REVIEW_BATCH_BYTES,
            MIN_REVIEW_BATCH_BYTES / 3,
            false,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("source batch limit"));
    }

    fn deterministic_large_fixture(security_hunks: usize) -> String {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 0..30 {
            let security = file < security_hunks;
            let path = if security {
                format!("src/auth/permission-{file}.ts")
            } else if file == 29 {
                "vendor/runtime/dispatch.ts".to_string()
            } else {
                format!("src/churn/file-{file}.ts")
            };
            writeln!(
                source,
                "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@"
            )
            .unwrap();
            if security {
                writeln!(
                    source,
                    "-if (!actor.can('admin')) throw new Error('Forbidden');"
                )
                .unwrap();
                writeln!(
                    source,
                    "+await privilegedWrite(input); // {}",
                    "x".repeat(10_000)
                )
                .unwrap();
            } else {
                writeln!(source, "-const value = {file};").unwrap();
                writeln!(source, "+const value = {file}; // {}", "x".repeat(10_000)).unwrap();
            }
        }
        source
    }

    fn exact_bounded_risk_fixture() -> String {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 0..30 {
            writeln!(
                source,
                "diff --git a/src/module-{file}.rs b/src/module-{file}.rs"
            )
            .unwrap();
            writeln!(source, "--- a/src/module-{file}.rs").unwrap();
            writeln!(source, "+++ b/src/module-{file}.rs").unwrap();
            writeln!(source, "@@ -1,81 +1,81 @@").unwrap();
            writeln!(source, "-let mode = \"old\";").unwrap();
            writeln!(source, "+let retry_mode = \"bounded\";").unwrap();
            for _ in 0..80 {
                writeln!(source, " {}", "context".repeat(64)).unwrap();
            }
        }
        source
    }

    #[test]
    fn exact_semantic_proof_losslessly_compacts_repeated_long_lines() {
        let content = format!("{} eval(hidden) {}", "x".repeat(400), "y".repeat(400));
        let source = format!(
            "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -1 +1 @@\n-old\n+{content}\n"
        );
        let parsed = parse(&source);
        let hunk = &parsed.files[0].hunks[0];
        let proof = exact_semantic_hunk_proof("src/long.ts", hunk).unwrap();

        assert!(proof.contains("exact-rle-v1"));
        assert!(proof.contains("[\"r\",400,\"x\"]"));
        assert!(proof.contains("eval(hidden)"));
        assert!(proof.contains("[\"r\",400,\"y\"]"));
        assert!(!proof.contains(&content));
        assert!(proof.len() < 1_000);
    }

    #[test]
    fn exact_semantic_templates_round_trip_added_and_removed_lines() {
        let padding = "x".repeat(200);
        let removed = (1..=4)
            .map(|counter| format!("const old_{counter} = actor.id; // {padding}"))
            .collect::<Vec<_>>();
        let added = (5..=8)
            .map(|counter| format!("const new_{counter} = actor.id; // {padding}"))
            .collect::<Vec<_>>();
        let source = format!(
            "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -10,4 +20,4 @@\n{}\n{}\n",
            removed
                .iter()
                .map(|line| format!("-{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            added
                .iter()
                .map(|line| format!("+{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let parsed = parse(&source);
        let proof = exact_semantic_hunk_proof("src/long.ts", &parsed.files[0].hunks[0]).unwrap();
        let templates = proof
            .lines()
            .filter_map(|line| {
                line.split_once("exact-template-v1 ")
                    .map(|(prefix, encoded)| (prefix, serde_json::from_str(encoded).unwrap()))
            })
            .collect::<Vec<(&str, serde_json::Value)>>();
        assert_eq!(templates.len(), 2);

        for ((line_prefix, template), (expected_marker, expected)) in
            templates.iter().zip([("-", &removed), ("+", &added)])
        {
            let (marker, start_line) = if let Some(line) = line_prefix.strip_prefix("old ") {
                (
                    "-",
                    line.strip_suffix(" - ").unwrap().parse::<u32>().unwrap(),
                )
            } else {
                (
                    "+",
                    line_prefix
                        .strip_suffix(" + ")
                        .unwrap()
                        .parse::<u32>()
                        .unwrap(),
                )
            };
            let counter_start = template["counterStart"].as_u64().unwrap();
            let counter_end = template["counterEnd"].as_u64().unwrap();
            let end_line = template["endLine"].as_u64().unwrap() as u32;
            let prefix = decode_exact_rle_segments(&template["prefix"]).unwrap();
            let suffix = decode_exact_rle_segments(&template["suffix"]).unwrap();
            let reconstructed = (counter_start..=counter_end)
                .map(|counter| format!("{prefix}{counter}{suffix}"))
                .collect::<Vec<_>>();

            assert_eq!(&reconstructed, expected);
            assert_eq!(end_line, start_line + expected.len() as u32 - 1);
            assert_eq!(marker, expected_marker);
        }
    }

    #[test]
    fn exact_semantic_grounding_uses_reconstructed_source_not_transport_records() {
        let padding = "x".repeat(200);
        let removed = (1..=4)
            .map(|counter| format!("const old_{counter} = actor.id; // {padding}"))
            .collect::<Vec<_>>();
        let added = (5..=8)
            .map(|counter| format!("const new_{counter} = actor.id; // {padding}"))
            .collect::<Vec<_>>();
        let source = format!(
            "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -10,4 +20,4 @@\n{}\n{}\n",
            removed
                .iter()
                .map(|line| format!("-{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            added
                .iter()
                .map(|line| format!("+{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let parsed = parse(&source);
        let proof = exact_semantic_hunk_proof("src/long.ts", &parsed.files[0].hunks[0]).unwrap();
        let batch = format!("{}{}", exact_semantic_batch_header(&BTreeSet::new()), proof);
        let transport = batch
            .lines()
            .find_map(|line| line.split_once("20 + ").map(|(_, payload)| payload))
            .unwrap();

        for (offset, expected) in added.iter().enumerate() {
            let line = 20 + offset as u32;
            assert_eq!(
                review_batch_expected_evidence(&batch, "src/long.ts", line).as_deref(),
                Some(expected.as_str())
            );
            assert_eq!(
                review_batch_canonical_evidence(&batch, "src/long.ts", line, Some(expected))
                    .as_deref(),
                Some(expected.as_str())
            );
            assert!(
                review_batch_canonical_evidence(&batch, "src/long.ts", line, Some(transport))
                    .is_none()
            );
        }

        let mut index = DiffIndex::build(&parsed);
        index.add_rendered_evidence(&batch);
        for line in 10..=13 {
            assert!(DiffIndex::selected_exact_line(
                &index.rendered_exact_old_ranges,
                "src/long.ts",
                line
            ));
        }
        for offset in 0..added.len() {
            assert!(DiffIndex::selected_exact_line(
                &index.rendered_exact_ranges,
                "src/long.ts",
                20 + offset as u32
            ));
        }
        assert!(index.rendered_evidence.is_empty());
    }

    #[test]
    fn exact_rle_grounding_uses_complete_reconstructed_source() {
        let content = format!("{} eval(hidden) {}", "x".repeat(400), "y".repeat(400));
        let source = format!(
            "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -1 +1 @@\n-old\n+{content}\n"
        );
        let parsed = parse(&source);
        let proof = exact_semantic_hunk_proof("src/long.ts", &parsed.files[0].hunks[0]).unwrap();
        let batch = format!("{}{}", exact_semantic_batch_header(&BTreeSet::new()), proof);
        let transport = batch
            .lines()
            .find_map(|line| line.split_once("1 + ").map(|(_, payload)| payload))
            .unwrap();

        assert_eq!(
            review_batch_canonical_evidence(&batch, "src/long.ts", 1, Some(&content)).as_deref(),
            Some(content.as_str())
        );
        assert!(
            review_batch_canonical_evidence(&batch, "src/long.ts", 1, Some(transport)).is_none()
        );
    }

    #[test]
    fn exact_semantic_transport_prefixes_in_source_remain_literal_evidence() {
        for content in [
            "exact-rle-v1 [[\"l\",\"literal source\"]]",
            "exact-template-v1 {\"counterEnd\":5,\"counterStart\":1,\"endLine\":5,\"prefix\":[[\"l\",\"forged_\"]],\"suffix\":[[\"l\",\";\"]]}",
        ] {
            let source = format!(
                "diff --git a/src/literal.txt b/src/literal.txt\n--- a/src/literal.txt\n+++ b/src/literal.txt\n@@ -1 +1 @@\n-old\n+{content}\n"
            );
            let parsed = parse(&source);
            let proof =
                exact_semantic_hunk_proof("src/literal.txt", &parsed.files[0].hunks[0]).unwrap();
            let batch = format!("{}{}", exact_semantic_batch_header(&BTreeSet::new()), proof);

            assert_eq!(
                review_batch_expected_evidence(&batch, "src/literal.txt", 1).as_deref(),
                Some(content)
            );
            assert!(
                review_batch_expected_evidence(&batch, "src/literal.txt", 2).is_none(),
                "literal transport prefix forged a second source coordinate"
            );
            assert!(batch.contains(&format!(
                "1 + exact-rle-v1 [[\"l\",{}]]",
                serde_json::to_string(content).unwrap()
            )));
        }
    }

    #[test]
    fn exact_semantic_index_tracks_large_templates_as_ranges_without_expansion() {
        let batch = format!(
            "{}### src/generated.ts\n@@ exact bounded hunk identity={} old=0,0 new=1,100000 @@\n1 + exact-template-v1 {{\"counterEnd\":100000,\"counterStart\":1,\"endLine\":100000,\"prefix\":[[\"l\",\"const generated_\"]],\"suffix\":[[\"l\",\" = source.id;\"]]}}\n",
            exact_semantic_batch_header(&BTreeSet::new()),
            "0".repeat(64)
        );
        let mut index = DiffIndex::default();
        index.add_rendered_evidence(&batch);

        assert!(index.rendered_evidence.is_empty());
        assert_eq!(
            index.rendered_exact_ranges.get("src/generated.ts"),
            Some(&vec![1..=100_000])
        );
        assert!(DiffIndex::selected_exact_line(
            &index.rendered_exact_ranges,
            "src/generated.ts",
            75_000
        ));
        assert_eq!(
            review_batch_expected_evidence(&batch, "src/generated.ts", 75_000).as_deref(),
            Some("const generated_75000 = source.id;")
        );
    }

    fn deterministic_receipt_for(source: &str) -> BoundedCoverageReceipt {
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        assert!(batches.source_count > crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES);
        batches
            .deterministic_bounded_receipt(crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES)
            .unwrap()
    }

    fn durable_request_plan_for(source: &str) -> DurableRequestPlan {
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        batches.durable_request_plan().unwrap()
    }

    #[test]
    fn ordinary_request_plan_is_stable_and_binds_the_complete_batch_inventory() {
        let source = deterministic_large_fixture(1);
        let first = durable_request_plan_for(&source);
        let second = durable_request_plan_for(&source);
        let changed =
            durable_request_plan_for(&source.replace("const value = 1", "const value = 2"));

        assert_eq!(first, second);
        assert_ne!(first.plan_sha256, changed.plan_sha256);
        assert_eq!(first.selected_batches, first.total_batches);
        assert!(first.direct_hunks > 0);
    }

    #[test]
    fn deterministic_large_receipt_is_stable_and_keeps_security_and_vendor_hunks() {
        let source = deterministic_large_fixture(1);
        let first = deterministic_receipt_for(&source);
        let second = deterministic_receipt_for(&source);

        assert_eq!(first.plan_sha256, second.plan_sha256);
        assert_eq!(first.entries, second.entries);
        assert_eq!(first.entries.len(), 30);
        assert!(first.selected_batch_ids.len() <= crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES);
        assert!(first.direct_hunks() >= 2);
        assert!(first.semantic_hunks() > 0);
        assert_eq!(first.unreviewed_hunks(), 0);
        for path in ["src/auth/permission-0.ts", "vendor/runtime/dispatch.ts"] {
            let entry = first
                .entries
                .iter()
                .find(|entry| entry.hunk.path == path)
                .unwrap();
            assert!(
                matches!(entry.disposition, HunkDisposition::Direct { .. }),
                "mandatory {path} hunk was not reviewed directly"
            );
        }
        let unique = first
            .entries
            .iter()
            .map(|entry| entry.hunk.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), first.entries.len());
    }

    #[test]
    fn exact_bounded_evidence_covers_nonmandatory_risk_markers() {
        let source = exact_bounded_risk_fixture();
        let receipt = deterministic_receipt_for(&source);

        assert_eq!(receipt.entries.len(), 30);
        assert_eq!(receipt.unreviewed_hunks(), 0);
        assert!(receipt.semantic_hunks() > 0);
        assert!(receipt.selected_batch_ids.len() <= crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES);
    }

    #[test]
    fn semantic_receipt_rejects_a_missing_exact_hunk_mapping() {
        let source = exact_bounded_risk_fixture();
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        let receipt = batches
            .deterministic_bounded_receipt(crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES)
            .unwrap();
        let (hunk, summary_id) = receipt
            .entries
            .iter()
            .find_map(|entry| match &entry.disposition {
                HunkDisposition::Semantic { summary_batch_ids } => {
                    Some((entry.hunk.clone(), summary_batch_ids[0]))
                }
                _ => None,
            })
            .unwrap();
        batches
            .batch_hunks
            .get_mut(&summary_id)
            .unwrap()
            .remove(&hunk);
        let error = batches.validate_coverage_receipt(&receipt).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not bound to the exact normalized hunk digest")
        );
    }

    #[test]
    fn semantic_receipt_prompt_commits_to_its_exact_normalized_hunk_set() {
        let source = exact_bounded_risk_fixture();
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        let receipt = batches
            .deterministic_bounded_receipt(crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES)
            .unwrap();
        let summary_id = receipt
            .entries
            .iter()
            .find_map(|entry| match &entry.disposition {
                HunkDisposition::Semantic { summary_batch_ids } => Some(summary_batch_ids[0]),
                _ => None,
            })
            .unwrap();
        let expected = hunk_set_sha256(batches.batch_hunks.get(&summary_id).unwrap());
        let selected = batches
            .selected_batches(&BTreeSet::from([summary_id]))
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert!(selected[0].contains(&format!(
            "Exact normalized hunk-set commitment (SHA-256): {expected}"
        )));
    }

    #[test]
    fn semantic_receipt_rejects_a_tampered_summary_batch_identity() {
        let source = exact_bounded_risk_fixture();
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        let mut receipt = batches
            .deterministic_bounded_receipt(crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES)
            .unwrap();
        let direct_id = batches
            .batch_hunks
            .keys()
            .find(|id| !batches.synthesis_ids.contains(id))
            .copied()
            .unwrap();
        let semantic = receipt
            .entries
            .iter_mut()
            .find(|entry| matches!(entry.disposition, HunkDisposition::Semantic { .. }))
            .unwrap();
        semantic.disposition = HunkDisposition::Semantic {
            summary_batch_ids: vec![direct_id],
        };
        receipt.selected_batch_ids.insert(direct_id);
        let error = batches.validate_coverage_receipt(&receipt).unwrap_err();
        assert!(error.to_string().contains("wrong evidence batch kind"));
    }

    #[test]
    fn deterministic_large_plan_rejects_an_unselected_security_hunk() {
        let source = deterministic_large_fixture(25);
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 16_000, 4_096, false).unwrap();
        let error = batches
            .deterministic_bounded_receipt(crate::review::MAX_LARGE_DIFF_SELECTED_BATCHES)
            .unwrap_err();
        assert!(error.to_string().contains("mandatory hunk"));
        assert!(error.to_string().contains("cannot fit"));
    }

    #[test]
    fn hosted_planner_sanitizes_hostile_multibatch_evidence_within_json_bound() {
        use std::fmt::Write as _;

        let hostile = format!(
            "{}{}{}",
            "\0".repeat(900),
            "\"".repeat(900),
            "\\".repeat(900)
        );
        let mut source = String::new();
        for file in 0..24 {
            let path = format!("src/hostile-{file}.rs");
            writeln!(
                source,
                "diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+const VALUE_{file}: &str = {hostile};"
            )
            .unwrap();
        }
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(&mut prepared, 4_096, 1_024, false).unwrap();
        assert!(batches.source_count > 1);
        let candidates = batches.hosted_candidates(5, 96).unwrap();

        assert!(candidates.manifest.len() <= MAX_HOSTED_PLANNER_MANIFEST_BYTES);
        assert!(!candidates.manifest.contains(['\0', '\r', '\t', '"', '\\']));
        let serialized = serde_json::to_vec(&serde_json::json!({
            "messages": [{"role": "user", "content": candidates.manifest}]
        }))
        .unwrap();
        assert!(serialized.len() < crate::llm::MAX_PROVIDER_REQUEST_BYTES);
    }

    #[test]
    fn hosted_planner_keeps_fixture_51_permission_change_in_mandatory_evidence() {
        use std::fmt::Write as _;

        fn push_churn(source: &mut String, side: &str, file: usize) {
            let path = format!("src/churn/{side}-{file}.ts");
            writeln!(
                source,
                "diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,131 @@"
            )
            .unwrap();
            writeln!(
                source,
                "+export function ordinary_{side}_{file}(actor: Actor) {{"
            )
            .unwrap();
            for line in 2..130 {
                writeln!(
                    source,
                    "+  const ordinary_{side}_{file}_{line} = actor.id; // {}",
                    "x".repeat(900)
                )
                .unwrap();
            }
            writeln!(source, "+  return actor.id;\n+}}").unwrap();
        }

        fn push_change(source: &mut String, line: usize, before: &str, after: &str) {
            writeln!(source, "@@ -{line},1 +{line},1 @@\n- {before}\n+ {after}").unwrap();
        }

        let mut source = String::new();
        for file in 0..3 {
            push_churn(&mut source, "prefix", file);
        }
        source.push_str("diff --git a/src/admin/bulk-edit.ts b/src/admin/bulk-edit.ts\nindex 1111111..2222222 100644\n--- a/src/admin/bulk-edit.ts\n+++ b/src/admin/bulk-edit.ts\n");
        push_change(
            &mut source,
            6,
            "const title = 'Bulk edit';",
            "const title = 'Bulk edit ';",
        );
        push_change(
            &mut source,
            18,
            "const batchSize=50;",
            "const batchSize = 50;",
        );
        push_change(
            &mut source,
            33,
            "logger.debug('bulk edit start');",
            "logger.debug('bulk edit started');",
        );
        push_change(
            &mut source,
            57,
            "const summary = buildSummary(changeSet);",
            "const editSummary = buildSummary(changeSet);",
        );
        push_change(
            &mut source,
            88,
            "if (!actor.can('bulkEdit')) throw new Error('Forbidden');",
            "await applyBulkEdit(changeSet);",
        );
        push_change(
            &mut source,
            122,
            "return { ok: true, summary };",
            "return { ok: true, summary: editSummary };",
        );
        push_change(
            &mut source,
            147,
            "metrics.increment('bulk_edit.done');",
            "metrics.increment('bulk_edit.completed');",
        );
        for file in 0..3 {
            push_churn(&mut source, "suffix", file);
        }
        assert_eq!(source.len(), 728_616);
        assert_eq!(
            Sha256::digest(source.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "21abd4b0305bb11f3314dbc68725ba2373a00848094fe94fbf842461718e3b2d"
        );

        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            crate::review::MAX_HOSTED_REVIEW_BATCH_BYTES,
            crate::review::MAX_REVIEW_MANIFEST_BYTES
                .min(crate::review::MAX_HOSTED_REVIEW_BATCH_BYTES / 3),
            false,
        )
        .unwrap();
        assert!(batches.source_count > crate::review::MAX_HOSTED_SELECTED_BATCHES);
        let candidates = batches
            .hosted_candidates(
                crate::review::MAX_HOSTED_SELECTED_BATCHES,
                crate::review::MAX_HOSTED_PLANNER_CANDIDATES,
            )
            .unwrap();
        let mandatory = candidates
            .mandatory_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let selected = batches.selected_batches(&mandatory).unwrap();
        assert!(
            selected.iter().any(|batch| {
                batch.contains("src/admin/bulk-edit.ts")
                    && batch.contains("actor.can('bulkEdit')")
                    && batch.contains("applyBulkEdit")
            }),
            "permission-removal batch was not mandatory; mandatory={mandatory:?}"
        );
        assert!(selected.iter().any(|batch| {
            batch.contains("Cross-window semantic digests")
                && batch.contains("actor.can('bulkEdit')")
                && batch.contains("Forbidden")
        }));
    }

    #[test]
    fn hosted_risk_scoring_ignores_keywords_inside_opaque_tokens() {
        fn noise(mut state: u64) -> String {
            const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
            let mut out = String::with_capacity(2_000);
            for _ in 0..2_000 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                out.push(ALPHABET[(state as usize) % ALPHABET.len()] as char);
            }
            out
        }

        let opaque = format!(
            "### src/churn.ts\n     1 + const payload = \"{}start{}delete{}permission{}\";",
            noise(1),
            noise(2),
            noise(3),
            noise(4)
        );
        let permission_removal = "### src/admin/bulk-edit.ts\nold     88 - if (!actor.can('bulkEdit')) throw new Error('Forbidden');\n    88 + await applyBulkEdit(changeSet);";

        assert_eq!(hosted_risk_score(&opaque), 0);
        assert!(hosted_risk_score(permission_removal) >= 10);

        let noisy_manifest = "Changed-file manifest:\n- src/admin/permission/authorization.ts [source]\n### src/admin/permission/authorization.ts\n     1   permission authorization forbidden context\n     2 + ordinary_change();";
        assert_eq!(hosted_risk_score(noisy_manifest), 0);
    }

    #[test]
    fn planner_fallback_keeps_highest_risk_removal_beside_keyword_decoy() {
        use std::fmt::Write as _;

        fn push_padding_file(source: &mut String, path: &str) {
            writeln!(
                source,
                "diff --git a/{path} b/{path}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,1 @@\n+const ordinary = \"{}\";",
                "x".repeat(20_000)
            )
            .unwrap();
        }

        let mut source = String::new();
        for index in 0..3 {
            push_padding_file(&mut source, &format!("src/prefix-{index}.ts"));
        }
        writeln!(
            source,
            "diff --git a/src/decoy.ts b/src/decoy.ts\n--- /dev/null\n+++ b/src/decoy.ts\n@@ -0,0 +1,1 @@\n+unsafe eval exec authorization permission secret password token query delete timeout retry validate guard unwrap {}",
            "x".repeat(20_000)
        )
        .unwrap();
        writeln!(
            source,
            "diff --git a/src/admin/bulk-edit.ts b/src/admin/bulk-edit.ts\n--- a/src/admin/bulk-edit.ts\n+++ b/src/admin/bulk-edit.ts\n@@ -88,2 +88,2 @@\n-if (!actor.can('bulkEdit')) throw new Error('Forbidden');\n+await applyBulkEdit(changeSet);\n {}",
            "x".repeat(20_000)
        )
        .unwrap();
        for index in 0..3 {
            push_padding_file(&mut source, &format!("src/suffix-{index}.ts"));
        }

        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            crate::review::MAX_HOSTED_REVIEW_BATCH_BYTES,
            crate::review::MAX_REVIEW_MANIFEST_BYTES
                .min(crate::review::MAX_HOSTED_REVIEW_BATCH_BYTES / 3),
            false,
        )
        .unwrap();
        let candidates = batches
            .hosted_candidates(
                crate::review::MAX_HOSTED_SELECTED_BATCHES,
                crate::review::MAX_HOSTED_PLANNER_CANDIDATES,
            )
            .unwrap();
        let mandatory = candidates
            .mandatory_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let selected = batches.selected_batches(&mandatory).unwrap();

        assert!(selected.iter().any(|batch| batch.contains("src/decoy.ts")));
        assert!(selected.iter().any(|batch| {
            batch.contains("src/admin/bulk-edit.ts")
                && batch.contains("actor.can('bulkEdit')")
                && batch.contains("Forbidden")
        }));
        assert!(selected.iter().any(|batch| {
            batch.contains("Cross-window semantic digests")
                && batch.contains("actor.can('bulkEdit')")
                && batch.contains("Forbidden")
        }));
    }

    #[test]
    fn oversized_semantic_digest_compacts_before_spooling() {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 1..=400 {
            writeln!(
                source,
                "diff --git a/src/tiny_{file}.rs b/src/tiny_{file}.rs\n--- a/src/tiny_{file}.rs\n+++ b/src/tiny_{file}.rs\n@@ -0,0 +1 @@\n+fn changed_{file}(input: &str) {{ validate(input); write(input); }}"
            )
            .unwrap();
        }
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            MIN_REVIEW_BATCH_BYTES,
            MIN_REVIEW_BATCH_BYTES / 3,
            false,
        )
        .unwrap();
        let mut saw_synthesis = false;
        while let Some(batch) = batches.next_batch().unwrap() {
            assert!(batch.len() <= MIN_REVIEW_BATCH_BYTES);
            saw_synthesis |= batch.contains("Cross-window semantic digests");
        }
        assert!(saw_synthesis);
    }

    #[test]
    fn multilevel_spool_retains_sole_middle_sink_from_tiny_region() {
        use std::fmt::Write as _;

        let mut source = String::new();
        for file in 1..=1_440 {
            let change = if file == 720 {
                "dangerous_sink(untrusted_input);".to_string()
            } else {
                format!("let ordinary_{file} = constant;")
            };
            writeln!(
                source,
                "diff --git a/src/tiny_{file}.rs b/src/tiny_{file}.rs\n--- a/src/tiny_{file}.rs\n+++ b/src/tiny_{file}.rs\n@@ -0,0 +1 @@\n+{change}"
            )
            .unwrap();
        }
        let snapshot = DiffSnapshot::from_bytes(source.as_bytes()).unwrap();
        let mut prepared = prepare_review(&snapshot).unwrap();
        let mut batches = spool_model_batches(
            &mut prepared,
            MIN_REVIEW_BATCH_BYTES,
            MIN_REVIEW_BATCH_BYTES / 3,
            false,
        )
        .unwrap();
        let source_count = batches.source_count;
        let total_count = batches.count;
        let mut recursive_levels = BTreeSet::new();
        let mut final_level = 0usize;
        let mut final_synthesis = String::new();
        while let Some(batch) = batches.next_batch().unwrap() {
            assert!(batch.len() <= MIN_REVIEW_BATCH_BYTES);
            if let Some(level) = batch
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("Cross-window semantic digests level "))
                .and_then(|value| value.strip_suffix(':'))
                .and_then(|value| value.parse::<usize>().ok())
            {
                recursive_levels.insert(level);
                if level >= final_level {
                    final_level = level;
                    final_synthesis = batch;
                }
            }
        }
        assert!(
            recursive_levels.len() >= 2,
            "test did not exercise multiple levels: recursive={recursive_levels:?}, source={source_count}, total={total_count}"
        );
        assert!(final_synthesis.contains("dangerous_sink(untrusted_input)"));
        assert!(final_synthesis.contains("semantic category=sinks"));
    }
}
