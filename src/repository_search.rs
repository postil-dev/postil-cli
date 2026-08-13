use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::io::Read;
use std::path::Path;
use std::process::Stdio;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::process::Command;

use crate::envelope::{
    Finding, RepositoryClaim, RepositorySearchMatch, RepositorySearchQuery,
    RepositorySearchQueryKind, RepositorySearchReceipt, RepositorySearchState, SuppressedFinding,
    SuppressionReason,
};
use crate::forge::github::GitHub;

const MAX_SEARCH_TERMS: usize = 64;
const MAX_TERM_BYTES: usize = 256;
const MAX_TERM_TOTAL_BYTES: usize = 8 * 1024;
const MAX_TREE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 100_000;
const MAX_TREE_DEPTH: usize = 256;
const MAX_GITHUB_TREE_OBJECTS: usize = 256;
const MAX_SEARCH_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORDED_MATCHES: usize = 128;
const GITHUB_REQUEST_CAP: usize = 256;
const GITHUB_OBJECT_CAP: usize = 512;
const GITHUB_AGGREGATE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const LOCAL_AGGREGATE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_BATCH_HEADER_BYTES: usize = 256;

#[derive(Clone, Copy)]
pub(crate) enum RepositorySource<'a> {
    Local(&'a Path),
    GitHub(&'a GitHub),
    Unavailable,
}

#[derive(Debug, Clone)]
pub(crate) struct SearchTerm {
    pub(crate) kind: RepositorySearchQueryKind,
    normalized: Vec<u8>,
    pub(crate) query_sha256: String,
}

impl SearchTerm {
    pub(crate) fn normalized(&self) -> &[u8] {
        &self.normalized
    }
}

pub(crate) async fn search(
    source: &RepositorySource<'_>,
    head_sha: Option<&str>,
    findings: impl Iterator<Item = &Finding>,
) -> RepositorySearchReceipt {
    let claims = findings
        .filter_map(|finding| finding.repository_claim.as_ref())
        .collect::<Vec<_>>();
    let terms = match search_terms(claims.iter().copied()) {
        Ok(terms) => terms,
        Err(()) => {
            return head_sha
                .filter(|value| !value.is_empty())
                .map_or_else(|| unavailable(None), exhausted);
        }
    };
    if terms.is_empty() {
        return unavailable(head_sha.filter(|value| !value.is_empty()));
    }
    let Some(head_sha) = head_sha.filter(|value| !value.is_empty()) else {
        return unavailable_with_terms(None, &terms);
    };
    match source {
        RepositorySource::Local(root) => search_local(root, head_sha, terms).await,
        RepositorySource::GitHub(github) => github.search_repository_at_head(head_sha, terms).await,
        RepositorySource::Unavailable => unavailable_with_terms(Some(head_sha), &terms),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepositoryClaimVerdict {
    Supported,
    Refuted,
    Unresolved,
}

pub(crate) fn claim_verdict(
    claim: &RepositoryClaim,
    receipt: &RepositorySearchReceipt,
    snapshot_id: &str,
) -> RepositoryClaimVerdict {
    let searched = receipt
        .queries
        .iter()
        .map(|query| query.query_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let complete_snapshot = receipt.state == RepositorySearchState::Complete
        && receipt.head_sha.as_deref() == Some(snapshot_id)
        && valid_full_object_id(snapshot_id)
        && receipt.tree_sha256.as_deref().is_some_and(valid_sha256)
        && !receipt.matches_truncated;
    let complete_claim = complete_snapshot
        && claim_query_hashes(claim)
            .is_some_and(|hashes| hashes.iter().all(|hash| searched.contains(hash.as_str())));
    if !complete_claim {
        RepositoryClaimVerdict::Unresolved
    } else if claim_has_refutation_candidate(claim, receipt) {
        // A search match is lexical evidence only. It can identify the exact
        // snapshot path and query hashes for an adjudicator, but cannot prove
        // that a construct exists rather than being mentioned in prose.
        RepositoryClaimVerdict::Unresolved
    } else {
        RepositoryClaimVerdict::Supported
    }
}

pub(crate) fn enforce_receipt(
    findings: &mut Vec<Finding>,
    receipt: &RepositorySearchReceipt,
) -> Vec<SuppressedFinding> {
    let snapshot_id = receipt.head_sha.as_deref().unwrap_or_default();
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings.drain(..) {
        let exposes_boundary = publication_exposes_evidence_boundary(&finding);
        let unstructured_repository_claim =
            finding.repository_claim.is_none() && prose_requires_repository_search(&finding);
        let refuted = finding.repository_claim.as_ref().is_some_and(|claim| {
            claim_verdict(claim, receipt, snapshot_id) == RepositoryClaimVerdict::Refuted
        });
        if !exposes_boundary && !unstructured_repository_claim && !refuted {
            kept.push(finding);
        } else {
            suppressed.push(SuppressedFinding {
                finding,
                reason: if unstructured_repository_claim || refuted {
                    SuppressionReason::RepositoryClaimUnsupported
                } else {
                    SuppressionReason::NonActionable
                },
            });
        }
    }
    *findings = kept;
    suppressed
}

pub(crate) fn search_terms<'a>(
    claims: impl Iterator<Item = &'a RepositoryClaim>,
) -> Result<Vec<SearchTerm>, ()> {
    let mut values = BTreeSet::new();
    let mut total = 0usize;
    for (kind, value) in claims.flat_map(RepositoryClaim::typed_values) {
        let value = value.trim();
        if value.len() < 2
            || value.len() > MAX_TERM_BYTES
            || value.contains('\0')
            || (kind == RepositorySearchQueryKind::Identifier && !valid_identifier(value))
        {
            return Err(());
        }
        if values.insert((kind, value.to_string())) {
            total = total.checked_add(value.len()).ok_or(())?;
            if values.len() > MAX_SEARCH_TERMS || total > MAX_TERM_TOTAL_BYTES {
                return Err(());
            }
        }
    }
    Ok(values
        .into_iter()
        .map(|(kind, value)| SearchTerm {
            kind,
            normalized: ascii_lower(value.as_bytes()),
            query_sha256: query_sha256(kind, value.as_bytes()),
        })
        .collect())
}

fn claim_query_hashes(claim: &RepositoryClaim) -> Option<Vec<String>> {
    search_terms(std::iter::once(claim))
        .ok()
        .filter(|terms| !terms.is_empty())
        .map(|terms| terms.into_iter().map(|term| term.query_sha256).collect())
}

pub(crate) fn claim_is_valid(claim: &RepositoryClaim) -> bool {
    let valid_terms = claim_query_hashes(claim).is_some();
    match claim.kind {
        crate::envelope::RepositoryClaimKind::Absence => valid_terms,
        crate::envelope::RepositoryClaimKind::Mismatch => {
            valid_terms
                && (!claim.resources.is_empty()
                    || !claim.paths.is_empty()
                    || !claim.identifiers.is_empty())
                && (!claim.values.is_empty() || !claim.versions.is_empty())
        }
    }
}

fn claim_has_refutation_candidate(
    claim: &RepositoryClaim,
    receipt: &RepositorySearchReceipt,
) -> bool {
    if receipt.matches_truncated || !claim_is_valid(claim) {
        return false;
    }
    let categories = claim_category_hashes(claim);
    receipt_match_units(receipt)
        .values()
        .any(|matched| category_hashes_match(&categories, matched))
}

pub(crate) fn refutation_evidence_is_grounded(
    _claim: &RepositoryClaim,
    _receipt: &RepositorySearchReceipt,
    _snapshot_id: &str,
    _evidence: &str,
) -> bool {
    // Repository matches are lexical routing evidence. The receipt does not
    // retain source snippets or syntax roles, so a filename, comment, or
    // unrelated declaration cannot safely refute a finding.
    false
}

fn receipt_match_units(receipt: &RepositorySearchReceipt) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut units = BTreeMap::<&str, BTreeSet<&str>>::new();
    for matched in &receipt.matches {
        units
            .entry(matched.path.as_str())
            .or_default()
            .insert(matched.query_sha256.as_str());
    }
    units
}

fn category_hashes_match(categories: &[Vec<String>], matched: &BTreeSet<&str>) -> bool {
    categories.iter().all(|category| {
        category.is_empty() || category.iter().all(|hash| matched.contains(hash.as_str()))
    })
}

fn claim_category_hashes(claim: &RepositoryClaim) -> Vec<Vec<String>> {
    let hashes = |kind, values: &[String]| {
        values
            .iter()
            .map(|value| query_sha256(kind, value.trim().as_bytes()))
            .collect::<Vec<_>>()
    };
    vec![
        hashes(RepositorySearchQueryKind::Resource, &claim.resources),
        hashes(RepositorySearchQueryKind::Value, &claim.values),
        hashes(RepositorySearchQueryKind::Version, &claim.versions),
        hashes(RepositorySearchQueryKind::Path, &claim.paths),
        hashes(RepositorySearchQueryKind::Identifier, &claim.identifiers),
    ]
}

pub(crate) fn publication_exposes_evidence_boundary(finding: &Finding) -> bool {
    let prose = format!("{} {}", finding.title, finding.body).to_ascii_lowercase();
    [
        "in the diff",
        "in this diff",
        "the diff shows",
        "this diff shows",
        "the diff adds",
        "this diff adds",
        "the diff does not",
        "this diff does not",
        "the diff contains",
        "this diff contains",
        "supplied diff",
        "provided diff",
        "available context",
        "supplied context",
        "retrieval limit",
        "search limit",
        "search the repository",
        "search for ",
        "look for ",
        "grep for ",
        "run rg ",
        "check whether",
        "please check",
        "confirm that",
        "please confirm",
        "verify that",
        "please verify",
        "inspect `",
        "inspect the",
    ]
    .iter()
    .any(|phrase| prose.contains(phrase))
}

pub(crate) fn prose_requires_repository_search(finding: &Finding) -> bool {
    let prose = format!("{} {}", finding.title, finding.body).to_ascii_lowercase();
    let fixed_scope = [
        "absent from the repository",
        "missing from the repository",
        "nowhere in the repository",
        "repository has no",
        "repository does not contain",
        "repository-wide",
        "no other caller",
        "no other consumer",
        "no other reference",
        "no other manifest",
        "other callers",
        "other consumers",
        "other references",
        "only caller",
        "only consumer",
        "only reference",
        "all callers",
        "all consumers",
        "every caller",
        "every consumer",
        "unchanged counterpart",
        "unchanged caller",
        "unchanged consumer",
        "unchanged manifest",
        "generated counterpart",
        "counterpart still",
        "counterparts do not",
        "remains on ",
        "remain on ",
        "still uses ",
        "still use ",
        "still runs ",
        "still run ",
        "is still on ",
        "are still on ",
        "was not updated",
        "were not updated",
        "has not been updated",
        "have not been updated",
        "does not match",
        "do not match",
        "does not use ",
        "do not use ",
        "mismatches ",
        "mismatched with",
        "differs from ",
        "different from ",
        "inconsistent with ",
        "does not agree with ",
        "out of sync",
        "newer than ",
        "older than ",
    ]
    .iter()
    .any(|phrase| prose.contains(phrase));
    let exclusive_update = [
        "updates only ",
        "only updates ",
        "changes only ",
        "only changes ",
    ]
    .iter()
    .any(|phrase| prose.contains(phrase))
        && [
            " while ",
            " whereas ",
            " but ",
            " leaving ",
            " without updating ",
        ]
        .iter()
        .any(|phrase| prose.contains(phrase));
    let version_relation = version_like_token_count(&prose) >= 2
        && [
            " while ",
            " whereas ",
            " but ",
            " compared to ",
            " differs",
            " different",
            " mismatch",
            " than ",
        ]
        .iter()
        .any(|phrase| prose.contains(phrase));
    fixed_scope || exclusive_update || version_relation
}

fn version_like_token_count(prose: &str) -> usize {
    prose
        .split_ascii_whitespace()
        .map(|token| {
            token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '.' && character != '-'
            })
        })
        .filter(|token| {
            let token = token.strip_prefix('v').unwrap_or(token);
            token.contains('.')
                && token.bytes().any(|byte| byte.is_ascii_digit())
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
        })
        .count()
}

fn query_sha256(kind: RepositorySearchQueryKind, value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.as_str().as_bytes());
    digest.update([0]);
    digest.update(value);
    hex_digest(digest.finalize())
}

pub(crate) struct SearchAccumulator {
    terms: Vec<SearchTerm>,
    matched_queries: BTreeSet<String>,
    matches: BTreeMap<(String, String), u64>,
    match_count: u64,
    searched_blobs: u64,
    searched_bytes: u64,
}

impl SearchAccumulator {
    pub(crate) fn new(terms: Vec<SearchTerm>) -> Self {
        Self {
            terms,
            matched_queries: BTreeSet::new(),
            matches: BTreeMap::new(),
            match_count: 0,
            searched_blobs: 0,
            searched_bytes: 0,
        }
    }

    pub(crate) fn scan_path(&mut self, path: &str) {
        let normalized = ascii_lower(path.as_bytes());
        for index in 0..self.terms.len() {
            let occurrences = count_occurrences(&normalized, &self.terms[index]);
            self.record(index, path, occurrences);
        }
    }

    pub(crate) fn scan_gitlink(&mut self, path: &str, object_id: &str) {
        let mut metadata = Vec::with_capacity(path.len() + object_id.len() + 1);
        metadata.extend_from_slice(path.as_bytes());
        metadata.push(0);
        metadata.extend_from_slice(object_id.as_bytes());
        let normalized = ascii_lower(&metadata);
        for index in 0..self.terms.len() {
            let occurrences = count_occurrences(&normalized, &self.terms[index]);
            self.record(index, path, occurrences);
        }
    }

    #[cfg(test)]
    pub(crate) fn scan_reader(
        &mut self,
        path: &str,
        reader: &mut impl Read,
        expected_size: u64,
    ) -> std::io::Result<()> {
        let mut scanner = StreamMatcher::new(&self.terms);
        let mut read = 0u64;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("repository search byte count overflowed"))?;
            scanner.push(&chunk[..count]);
        }
        scanner.finish();
        if read != expected_size {
            return Err(std::io::Error::other(
                "repository blob size did not match tree metadata",
            ));
        }
        self.finish_blob(path, read, scanner.counts);
        Ok(())
    }

    async fn scan_batch_reader(
        &mut self,
        path: &str,
        object_id: &str,
        reader: &mut (impl AsyncBufRead + Unpin),
        expected_size: u64,
    ) -> std::io::Result<()> {
        let mut header = Vec::with_capacity(MAX_BATCH_HEADER_BYTES);
        reader
            .take((MAX_BATCH_HEADER_BYTES + 1) as u64)
            .read_until(b'\n', &mut header)
            .await?;
        if !valid_batch_header(&header, object_id, expected_size) {
            return Err(std::io::Error::other(
                "git batch output did not match the tree entry",
            ));
        }

        let mut scanner = StreamMatcher::new(&self.terms);
        let mut read = 0u64;
        let mut remaining = expected_size;
        let mut chunk = [0u8; 64 * 1024];
        while remaining > 0 {
            let available = usize::try_from(remaining.min(chunk.len() as u64))
                .map_err(|_| std::io::Error::other("repository blob size overflowed"))?;
            let count = reader.read(&mut chunk[..available]).await?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "git batch output truncated a repository blob",
                ));
            }
            read = read
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("repository search byte count overflowed"))?;
            remaining = remaining.saturating_sub(count as u64);
            scanner.push(&chunk[..count]);
        }
        let mut terminator = [0u8; 1];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\n" {
            return Err(std::io::Error::other(
                "git batch output omitted its blob delimiter",
            ));
        }
        scanner.finish();
        self.finish_blob(path, read, scanner.counts);
        Ok(())
    }

    pub(crate) async fn scan_response(
        &mut self,
        path: &str,
        expected_object_id: &str,
        mut response: reqwest::Response,
        expected_size: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            response.status() != reqwest::StatusCode::PARTIAL_CONTENT,
            "repository blob returned partial content"
        );
        if let Some(size) = response.content_length() {
            anyhow::ensure!(size == expected_size, "repository blob size changed");
        }
        let mut scanner = StreamMatcher::new(&self.terms);
        let mut object_hash = GitBlobHash::new(expected_size);
        let mut read = 0u64;
        while let Some(chunk) = response.chunk().await? {
            read = read
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("repository search byte count overflowed"))?;
            object_hash.update(&chunk);
            scanner.push(&chunk);
        }
        scanner.finish();
        anyhow::ensure!(read == expected_size, "repository blob size changed");
        anyhow::ensure!(
            object_hash.matches(expected_object_id),
            "repository blob did not match its tree object id"
        );
        self.finish_blob(path, read, scanner.counts);
        Ok(())
    }

    fn finish_blob(&mut self, path: &str, bytes: u64, counts: Vec<u64>) {
        self.searched_blobs = self.searched_blobs.saturating_add(1);
        self.searched_bytes = self.searched_bytes.saturating_add(bytes);
        for (index, occurrences) in counts.into_iter().enumerate() {
            self.record(index, path, occurrences);
        }
    }

    fn record(&mut self, term_index: usize, path: &str, occurrences: u64) {
        if occurrences == 0 {
            return;
        }
        let digest = self.terms[term_index].query_sha256.clone();
        self.matched_queries.insert(digest.clone());
        self.match_count = self.match_count.saturating_add(occurrences);
        let entry = self.matches.entry((digest, path.to_string())).or_default();
        *entry = entry.saturating_add(occurrences);
    }

    pub(crate) fn complete(self, head_sha: &str, tree_sha256: String) -> RepositorySearchReceipt {
        self.finish(head_sha, tree_sha256, RepositorySearchState::Complete)
    }

    pub(crate) fn incomplete(self, head_sha: &str, tree_sha256: String) -> RepositorySearchReceipt {
        self.finish(head_sha, tree_sha256, RepositorySearchState::Unavailable)
    }

    fn finish(
        self,
        head_sha: &str,
        tree_sha256: String,
        state: RepositorySearchState,
    ) -> RepositorySearchReceipt {
        let queries = self
            .terms
            .iter()
            .map(|term| RepositorySearchQuery {
                kind: term.kind,
                query_sha256: term.query_sha256.clone(),
            })
            .collect();
        let matches_truncated = self.matches.len() > MAX_RECORDED_MATCHES;
        RepositorySearchReceipt {
            head_sha: Some(head_sha.to_string()),
            state,
            tree_sha256: Some(tree_sha256),
            queries,
            searched_blobs: self.searched_blobs,
            searched_bytes: self.searched_bytes,
            match_count: self.match_count,
            matched_query_sha256: self.matched_queries.into_iter().collect(),
            matches: self
                .matches
                .into_iter()
                .take(MAX_RECORDED_MATCHES)
                .map(
                    |((query_sha256, path), occurrences)| RepositorySearchMatch {
                        query_sha256,
                        path,
                        occurrences,
                    },
                )
                .collect(),
            matches_truncated,
        }
    }
}

struct GitBlobHash {
    sha1: Sha1,
    sha256: Sha256,
}

impl GitBlobHash {
    fn new(size: u64) -> Self {
        let header = format!("blob {size}\0");
        let mut sha1 = Sha1::new();
        sha1.update(header.as_bytes());
        let mut sha256 = Sha256::new();
        sha256.update(header.as_bytes());
        Self { sha1, sha256 }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    fn matches(self, expected: &str) -> bool {
        let actual = match expected.len() {
            40 => hex_digest(self.sha1.finalize()),
            64 => hex_digest(self.sha256.finalize()),
            _ => return false,
        };
        actual.eq_ignore_ascii_case(expected)
    }
}

#[cfg(test)]
pub(crate) fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut hash = GitBlobHash::new(bytes.len() as u64);
    hash.update(bytes);
    hex_digest(hash.sha1.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepositorySnapshotEntryKind {
    Blob,
    Gitlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepositorySnapshotEntry {
    pub(crate) path: String,
    pub(crate) object_id: String,
    pub(crate) mode: String,
    pub(crate) kind: RepositorySnapshotEntryKind,
    pub(crate) size: Option<u64>,
}

struct StreamMatcher {
    terms: Vec<SearchTerm>,
    counts: Vec<u64>,
    tail: Vec<u8>,
    overlap: usize,
}

impl StreamMatcher {
    fn new(terms: &[SearchTerm]) -> Self {
        Self {
            terms: terms.to_vec(),
            counts: vec![0; terms.len()],
            tail: Vec::new(),
            overlap: terms
                .iter()
                // Retain one byte before the longest term so an identifier
                // match that reaches the next chunk can validate its left boundary.
                .map(|term| term.normalized.len().saturating_add(1))
                .max()
                .unwrap_or(0),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let tail_len = self.tail.len();
        let mut combined = Vec::with_capacity(tail_len.saturating_add(chunk.len()));
        combined.extend_from_slice(&self.tail);
        combined.extend_from_slice(chunk);
        let combined = ascii_lower(&combined);
        for (index, term) in self.terms.iter().enumerate() {
            for position in occurrence_positions(&combined, term.normalized()) {
                let end = position.saturating_add(term.normalized().len());
                let newly_observable = end > tail_len
                    || (term.kind == RepositorySearchQueryKind::Identifier
                        && end == tail_len
                        && combined.get(end).is_some());
                if newly_observable
                    && (term.kind != RepositorySearchQueryKind::Identifier
                        || (end < combined.len()
                            && identifier_has_boundaries(&combined, position, term.normalized())))
                {
                    self.counts[index] = self.counts[index].saturating_add(1);
                }
            }
        }
        let keep = self.overlap.min(combined.len());
        self.tail.clear();
        self.tail
            .extend_from_slice(&combined[combined.len() - keep..]);
    }

    fn finish(&mut self) {
        for (index, term) in self.terms.iter().enumerate() {
            if term.kind == RepositorySearchQueryKind::Identifier
                && occurrence_positions(&self.tail, term.normalized()).any(|position| {
                    position.saturating_add(term.normalized().len()) == self.tail.len()
                        && identifier_has_boundaries(&self.tail, position, term.normalized())
                })
            {
                self.counts[index] = self.counts[index].saturating_add(1);
            }
        }
    }
}

async fn search_local(
    root: &Path,
    head_sha: &str,
    terms: Vec<SearchTerm>,
) -> RepositorySearchReceipt {
    let fallback_terms = terms.clone();
    match tokio::time::timeout(
        LOCAL_AGGREGATE_DEADLINE,
        search_local_inner(root, head_sha, terms),
    )
    .await
    {
        Err(_) => exhausted_with_terms(head_sha, &fallback_terms),
        Ok(Ok(receipt)) => receipt,
        Ok(Err(LocalSearchFailure::Exhausted)) => exhausted_with_terms(head_sha, &fallback_terms),
        Ok(Err(LocalSearchFailure::Unavailable)) => {
            unavailable_with_terms(Some(head_sha), &fallback_terms)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalSearchFailure {
    Unavailable,
    Exhausted,
}

async fn search_local_inner(
    root: &Path,
    head_sha: &str,
    terms: Vec<SearchTerm>,
) -> Result<RepositorySearchReceipt, LocalSearchFailure> {
    if !valid_full_object_id(head_sha) {
        return Err(LocalSearchFailure::Unavailable);
    }
    let object_type = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "-t", head_sha])
        .kill_on_drop(true)
        .output()
        .await;
    if !object_type.is_ok_and(|output| {
        output.status.success() && matches!(output.stdout.as_slice(), b"commit\n" | b"tree\n")
    }) {
        return Err(LocalSearchFailure::Unavailable);
    }
    let output = local_tree_bytes(root, head_sha).await?;
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    let mut entry_count = 0usize;
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        entry_count = match entry_count.checked_add(1) {
            Some(count) => count,
            None => return Err(LocalSearchFailure::Exhausted),
        };
        if entry_count > MAX_TREE_ENTRIES {
            return Err(LocalSearchFailure::Exhausted);
        }
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(LocalSearchFailure::Unavailable);
        };
        let metadata = match std::str::from_utf8(&record[..tab]) {
            Ok(value) => value,
            Err(_) => return Err(LocalSearchFailure::Unavailable),
        };
        let path = match std::str::from_utf8(&record[tab + 1..]) {
            Ok(value) if crate::forge::valid_repository_path(value) => value.to_string(),
            _ => return Err(LocalSearchFailure::Unavailable),
        };
        if path.bytes().filter(|byte| *byte == b'/').count() > MAX_TREE_DEPTH {
            return Err(LocalSearchFailure::Exhausted);
        }
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || !valid_full_object_id(fields[2]) {
            return Err(LocalSearchFailure::Unavailable);
        }
        let (kind, size) = match (fields[0], fields[1], fields[3]) {
            ("100644" | "100755" | "120000", "blob", raw_size) => {
                let size = match raw_size.parse::<u64>() {
                    Ok(size) => size,
                    Err(_) => return Err(LocalSearchFailure::Unavailable),
                };
                total_bytes = match total_bytes.checked_add(size) {
                    Some(total) => total,
                    None => return Err(LocalSearchFailure::Exhausted),
                };
                (RepositorySnapshotEntryKind::Blob, Some(size))
            }
            ("160000", "commit", "-") => (RepositorySnapshotEntryKind::Gitlink, None),
            _ => return Err(LocalSearchFailure::Unavailable),
        };
        entries.push(RepositorySnapshotEntry {
            path,
            object_id: fields[2].to_string(),
            mode: fields[0].to_string(),
            kind,
            size,
        });
    }
    if total_bytes > MAX_SEARCH_BYTES {
        return Err(LocalSearchFailure::Exhausted);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let tree_sha256 = tree_sha256(&entries);
    let mut search = SearchAccumulator::new(terms);
    let mut has_gitlinks = false;
    let mut batch = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    let mut input = batch.stdin.take().ok_or(LocalSearchFailure::Unavailable)?;
    let output = batch.stdout.take().ok_or(LocalSearchFailure::Unavailable)?;
    let mut output = BufReader::new(output);
    for entry in entries {
        if entry.kind == RepositorySnapshotEntryKind::Gitlink {
            has_gitlinks = true;
            search.scan_gitlink(&entry.path, &entry.object_id);
            continue;
        }
        search.scan_path(&entry.path);
        let size = entry.size.expect("blob snapshot entry has a size");
        scan_batch_object(
            &mut search,
            &entry.path,
            &entry.object_id,
            &mut input,
            &mut output,
            size,
        )
        .await
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    }
    drop(input);
    drop(output);
    if !batch.wait().await.is_ok_and(|status| status.success()) {
        return Err(LocalSearchFailure::Unavailable);
    }
    if has_gitlinks {
        Ok(search.incomplete(head_sha, tree_sha256))
    } else {
        Ok(search.complete(head_sha, tree_sha256))
    }
}

async fn local_tree_bytes(root: &Path, head_sha: &str) -> Result<Vec<u8>, LocalSearchFailure> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-tree", "-rlz", "--full-tree", head_sha, "--"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    let mut stdout = child.stdout.take().ok_or(LocalSearchFailure::Unavailable)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = stdout
            .read(&mut chunk)
            .await
            .map_err(|_| LocalSearchFailure::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_TREE_BYTES {
            return Err(LocalSearchFailure::Exhausted);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    drop(stdout);
    if !child.wait().await.is_ok_and(|status| status.success()) {
        return Err(LocalSearchFailure::Unavailable);
    }
    Ok(bytes)
}

fn valid_batch_header(header: &[u8], object_id: &str, expected_size: u64) -> bool {
    if header.len() > MAX_BATCH_HEADER_BYTES || !header.ends_with(b"\n") {
        return false;
    }
    let Ok(header) = std::str::from_utf8(&header[..header.len().saturating_sub(1)]) else {
        return false;
    };
    let mut fields = header.split_ascii_whitespace();
    fields.next().is_some_and(|value| value == object_id)
        && fields.next() == Some("blob")
        && fields
            .next()
            .is_some_and(|value| value.parse::<u64>().ok() == Some(expected_size))
        && fields.next().is_none()
}

async fn scan_batch_object(
    search: &mut SearchAccumulator,
    path: &str,
    object_id: &str,
    input: &mut (impl AsyncWrite + Unpin),
    output: &mut (impl AsyncBufRead + Unpin),
    expected_size: u64,
) -> std::io::Result<()> {
    input.write_all(format!("{object_id}\n").as_bytes()).await?;
    input.flush().await?;
    search
        .scan_batch_reader(path, object_id, output, expected_size)
        .await
}

pub(crate) fn unavailable(head_sha: Option<&str>) -> RepositorySearchReceipt {
    unavailable_with_terms(head_sha, &[])
}

pub(crate) fn unavailable_with_terms(
    head_sha: Option<&str>,
    terms: &[SearchTerm],
) -> RepositorySearchReceipt {
    RepositorySearchReceipt {
        head_sha: head_sha.map(str::to_string),
        state: RepositorySearchState::Unavailable,
        queries: receipt_queries(terms),
        ..RepositorySearchReceipt::default()
    }
}

pub(crate) fn exhausted(head_sha: &str) -> RepositorySearchReceipt {
    exhausted_with_terms(head_sha, &[])
}

pub(crate) fn exhausted_with_terms(
    head_sha: &str,
    terms: &[SearchTerm],
) -> RepositorySearchReceipt {
    RepositorySearchReceipt {
        head_sha: Some(head_sha.to_string()),
        state: RepositorySearchState::Exhausted,
        queries: receipt_queries(terms),
        ..RepositorySearchReceipt::default()
    }
}

fn receipt_queries(terms: &[SearchTerm]) -> Vec<RepositorySearchQuery> {
    terms
        .iter()
        .map(|term| RepositorySearchQuery {
            kind: term.kind,
            query_sha256: term.query_sha256.clone(),
        })
        .collect()
}

pub(crate) fn tree_sha256(entries: &[RepositorySnapshotEntry]) -> String {
    let mut digest = Sha256::new();
    for entry in entries {
        digest.update((entry.path.len() as u64).to_be_bytes());
        digest.update(entry.path.as_bytes());
        digest.update((entry.mode.len() as u64).to_be_bytes());
        digest.update(entry.mode.as_bytes());
        digest.update(entry.object_id.as_bytes());
        digest.update([match entry.kind {
            RepositorySnapshotEntryKind::Blob => 0,
            RepositorySnapshotEntryKind::Gitlink => 1,
        }]);
        match entry.size {
            Some(size) => {
                digest.update([1]);
                digest.update(size.to_be_bytes());
            }
            None => digest.update([0]),
        }
    }
    hex_digest(digest.finalize())
}

pub(crate) fn valid_full_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn search_byte_cap() -> u64 {
    MAX_SEARCH_BYTES
}

pub(crate) fn tree_entry_cap() -> usize {
    MAX_TREE_ENTRIES
}

pub(crate) fn tree_depth_cap() -> usize {
    MAX_TREE_DEPTH
}

pub(crate) fn github_tree_object_cap() -> usize {
    MAX_GITHUB_TREE_OBJECTS
}

pub(crate) fn github_request_cap() -> usize {
    GITHUB_REQUEST_CAP
}

pub(crate) fn github_object_cap() -> usize {
    GITHUB_OBJECT_CAP
}

pub(crate) fn github_aggregate_deadline() -> std::time::Duration {
    GITHUB_AGGREGATE_DEADLINE
}

#[cfg(test)]
fn sha256_hex(value: &[u8]) -> String {
    hex_digest(Sha256::digest(value))
}

pub(crate) fn hex_digest(value: impl AsRef<[u8]>) -> String {
    value
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ascii_lower(value: &[u8]) -> Vec<u8> {
    value.iter().map(u8::to_ascii_lowercase).collect()
}

fn count_occurrences(haystack: &[u8], term: &SearchTerm) -> u64 {
    if term.kind == RepositorySearchQueryKind::Identifier {
        return identifier_occurrences(haystack, term.normalized());
    }
    occurrence_positions(haystack, term.normalized()).count() as u64
}

fn identifier_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    occurrence_positions(haystack, needle)
        .filter(|position| identifier_has_boundaries(haystack, *position, needle))
        .count() as u64
}

fn identifier_has_boundaries(haystack: &[u8], position: usize, needle: &[u8]) -> bool {
    let before = position
        .checked_sub(1)
        .and_then(|index| haystack.get(index));
    let after = haystack.get(position.saturating_add(needle.len()));
    !before.is_some_and(|byte| is_identifier_byte(*byte))
        && !after.is_some_and(|byte| is_identifier_byte(*byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii()
}

fn valid_identifier(value: &str) -> bool {
    value
        .split('.')
        .flat_map(|part| part.split("::"))
        .all(valid_identifier_segment)
}

fn valid_identifier_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && characters.all(|character| {
            character == '_' || character.is_alphabetic() || character.is_numeric()
        })
}

fn occurrence_positions<'a>(
    haystack: &'a [u8],
    needle: &'a [u8],
) -> impl Iterator<Item = usize> + 'a {
    let width = needle.len().max(1);
    haystack
        .windows(width)
        .enumerate()
        .filter_map(move |(index, window)| (window == needle).then_some(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Kind, RepositoryClaimKind, Severity};

    struct ChunkedReader<'a> {
        bytes: &'a [u8],
        chunks: &'a [usize],
        chunk_index: usize,
        position: usize,
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.position == self.bytes.len() {
                return Ok(0);
            }
            let chunk = self.chunks[self.chunk_index.min(self.chunks.len() - 1)];
            self.chunk_index = self.chunk_index.saturating_add(1);
            let count = chunk
                .min(buffer.len())
                .min(self.bytes.len().saturating_sub(self.position));
            buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    fn run_git(root: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn commit_index(root: &Path, parent: Option<&str>) -> String {
        run_git(root, &["add", "-A"]);
        let tree = run_git(root, &["write-tree"]);
        let mut command = std::process::Command::new("git");
        command
            .arg("-C")
            .arg(root)
            .args(["commit-tree", &tree, "-m", "fixture"])
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid");
        if let Some(parent) = parent {
            command.args(["-p", parent]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "git commit-tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let commit = String::from_utf8(output.stdout).unwrap().trim().to_string();
        run_git(root, &["update-ref", "HEAD", &commit]);
        commit
    }

    fn finding(claim: RepositoryClaim) -> Finding {
        Finding {
            path: "changed.yaml".into(),
            line: 1,
            end_line: None,
            severity: Severity::Warn,
            kind: Kind::Uncertainty,
            confidence: 0.8,
            generator_confidence: None,
            scorer_confidence: None,
            generator_kind: None,
            scorer_kind: None,
            scorer_reason: None,
            repository_claim: Some(claim),
            title: "Repository claim".into(),
            body: "The reviewed head has no matching value; add the required counterpart.".into(),
            evidence: Some("value: new".into()),
            id: None,
        }
    }

    fn claim(term: &str) -> RepositoryClaim {
        RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![term.into()],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        }
    }

    fn typed_claim() -> RepositoryClaim {
        RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec!["19.2.5".into()],
            versions: vec!["19.2.5".into()],
            paths: vec!["generated/releases/cluster.yaml".into()],
            identifiers: vec!["cephVersion".into()],
        }
    }

    #[test]
    fn stream_matcher_finds_multiple_and_cross_chunk_matches() {
        let terms = search_terms([&claim("version-19.2.5")].into_iter()).unwrap();
        let mut search = SearchAccumulator::new(terms);
        let bytes = b"version-19.2.5 and VERSION-19.2.5";
        search
            .scan_reader("generated/values.yaml", &mut &bytes[..], bytes.len() as u64)
            .unwrap();
        let receipt = search.complete("head", sha256_hex(b"tree"));
        assert_eq!(receipt.match_count, 2);
        assert_eq!(receipt.matches[0].occurrences, 2);
    }

    #[tokio::test]
    async fn batch_reader_uses_one_protocol_for_multiple_blobs() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, duplex};

        let claim = claim("needle");
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let first = "a".repeat(40);
        let second = "b".repeat(40);
        let (mut input, requests) = duplex(1024);
        let (mut responses, output) = duplex(1024);
        let expected = vec![
            (first.clone(), b"first needle\n".to_vec()),
            (second.clone(), b"second needle\n".to_vec()),
        ];
        let server = tokio::spawn(async move {
            let mut requests = BufReader::new(requests);
            let mut seen = Vec::new();
            for (object_id, body) in expected {
                let mut request = String::new();
                requests.read_line(&mut request).await.unwrap();
                seen.push(request.trim().to_string());
                responses
                    .write_all(format!("{object_id} blob {}\n", body.len()).as_bytes())
                    .await
                    .unwrap();
                responses.write_all(&body).await.unwrap();
                responses.write_all(b"\n").await.unwrap();
            }
            seen
        });
        let mut output = BufReader::new(output);

        scan_batch_object(
            &mut search,
            "first.yaml",
            &first,
            &mut input,
            &mut output,
            13,
        )
        .await
        .unwrap();
        scan_batch_object(
            &mut search,
            "second.yaml",
            &second,
            &mut input,
            &mut output,
            14,
        )
        .await
        .unwrap();
        drop(input);

        assert_eq!(server.await.unwrap(), vec![first, second]);
        assert_eq!(search.searched_blobs, 2);
        assert_eq!(search.searched_bytes, 27);
    }

    #[tokio::test]
    async fn batch_reader_fails_closed_on_malformed_or_truncated_output() {
        use tokio::io::{AsyncWriteExt, duplex};

        let object_id = "a".repeat(40);
        let truncated = format!("{object_id} blob 6\nshort");
        for response in [b"not-a-git-batch-header\n".as_slice(), truncated.as_bytes()] {
            let claim = claim("needle");
            let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
            let (mut input, _requests) = duplex(1024);
            let (mut writer, output) = duplex(1024);
            writer.write_all(response).await.unwrap();
            drop(writer);
            let mut output = BufReader::new(output);

            assert!(
                scan_batch_object(
                    &mut search,
                    "config.yaml",
                    &object_id,
                    &mut input,
                    &mut output,
                    6,
                )
                .await
                .is_err()
            );
            assert_eq!(search.searched_blobs, 0);
            assert_eq!(search.searched_bytes, 0);
        }
    }

    #[test]
    fn identifier_queries_require_token_boundaries() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["allow".into()],
        };
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let bytes = b"disallow allowance allow\n";
        search
            .scan_reader("src/policy.rs", &mut &bytes[..], bytes.len() as u64)
            .unwrap();
        let receipt = search.complete("head", sha256_hex(b"tree"));
        assert_eq!(receipt.match_count, 1);
        assert_eq!(receipt.matches[0].occurrences, 1);
    }

    #[test]
    fn identifier_queries_support_qualified_and_unicode_terms_in_paths_and_streams() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["Client::send".into(), "Δοκιμή::send".into()],
        };
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let qualified = terms
            .iter()
            .find(|term| term.normalized() == b"client::send")
            .unwrap()
            .query_sha256
            .clone();
        let unicode = terms
            .iter()
            .find(|term| term.normalized() == "Δοκιμή::send".as_bytes())
            .unwrap()
            .query_sha256
            .clone();
        let mut search = SearchAccumulator::new(terms);

        search.scan_path("src/Client::send.rs");
        let bytes = "NotClient::send Client::sender Client::send\nΔοκιμή::send\n".as_bytes();
        let mut reader = ChunkedReader {
            bytes,
            chunks: &[9, 4, 7, 3, 5, 2, 11],
            chunk_index: 0,
            position: 0,
        };
        search
            .scan_reader("src/client.rs", &mut reader, bytes.len() as u64)
            .unwrap();
        let receipt = search.complete("head", sha256_hex(b"tree"));

        assert_eq!(receipt.match_count, 3);
        assert_eq!(
            receipt
                .matches
                .iter()
                .filter(|matched| matched.query_sha256 == qualified)
                .map(|matched| matched.occurrences)
                .sum::<u64>(),
            2
        );
        assert_eq!(
            receipt
                .matches
                .iter()
                .find(|matched| matched.query_sha256 == unicode)
                .map(|matched| matched.occurrences),
            Some(1)
        );
    }

    #[test]
    fn malformed_identifier_queries_fail_closed() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["Client::".into()],
        };

        assert!(search_terms(std::iter::once(&claim)).is_err());
    }

    #[test]
    fn lexical_match_is_an_unresolved_repository_candidate() {
        let claim = claim("CephCluster");
        let queries = receipt_queries(&search_terms(std::iter::once(&claim)).unwrap());
        let digest = queries[0].query_sha256.clone();
        let mut findings = vec![finding(claim.clone())];
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            queries,
            matched_query_sha256: vec![digest.clone()],
            matches: vec![RepositorySearchMatch {
                query_sha256: digest,
                path: "generated/cluster.yaml".into(),
                occurrences: 1,
            }],
            ..RepositorySearchReceipt::default()
        };
        let suppressed = enforce_receipt(&mut findings, &receipt);
        assert_eq!(findings.len(), 1);
        assert!(suppressed.is_empty());
        assert_eq!(
            claim_verdict(
                findings[0].repository_claim.as_ref().unwrap(),
                &receipt,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            RepositoryClaimVerdict::Unresolved
        );
    }

    #[test]
    fn typed_queries_keep_equal_text_in_distinct_categories() {
        let terms = search_terms([&typed_claim()].into_iter()).unwrap();
        let queries = receipt_queries(&terms);
        assert_eq!(queries.len(), 5);
        let value = queries
            .iter()
            .find(|query| query.kind == RepositorySearchQueryKind::Value)
            .unwrap();
        let version = queries
            .iter()
            .find(|query| query.kind == RepositorySearchQueryKind::Version)
            .unwrap();
        assert_ne!(value.query_sha256, version.query_sha256);
    }

    #[test]
    fn mismatch_claim_requires_target_and_compared_dimensions() {
        let no_target = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec![],
            values: vec![],
            versions: vec!["19.2.5".into()],
            paths: vec![],
            identifiers: vec![],
        };
        let no_value = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        assert!(!claim_is_valid(&no_target));
        assert!(!claim_is_valid(&no_value));
    }

    #[test]
    fn mismatch_requires_target_and_compared_value_in_one_evidence_unit() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec![],
            versions: vec!["19.2.5".into()],
            paths: vec![],
            identifiers: vec!["cephVersion".into()],
        };
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let mut search = SearchAccumulator::new(terms);
        let backup = b"image: quay.io/ceph/ceph:v19.2.5\n";
        search
            .scan_reader(
                "k8s/backup/cronjob-ceph-meta.yaml",
                &mut &backup[..],
                backup.len() as u64,
            )
            .unwrap();
        let cluster =
            b"kind: CephCluster\nspec:\n  cephVersion:\n    image: quay.io/ceph/ceph:v19.2.3\n";
        search
            .scan_reader(
                "k8s/ceph/cluster.yaml",
                &mut &cluster[..],
                cluster.len() as u64,
            )
            .unwrap();
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));
        let mut findings = vec![finding(claim)];

        assert!(enforce_receipt(&mut findings, &receipt).is_empty());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn matching_target_scoped_value_remains_lexical_only() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec![],
            versions: vec!["19.2.5".into()],
            paths: vec![],
            identifiers: vec!["cephVersion".into()],
        };
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let mut search = SearchAccumulator::new(terms);
        let cluster = b"kind: CephCluster\ncephVersion: 19.2.5\n";
        search
            .scan_reader(
                "k8s/ceph/cluster.yaml",
                &mut &cluster[..],
                cluster.len() as u64,
            )
            .unwrap();
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));
        let mut findings = vec![finding(claim.clone())];

        assert!(enforce_receipt(&mut findings, &receipt).is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            claim_verdict(&claim, &receipt, &"a".repeat(40)),
            RepositoryClaimVerdict::Unresolved
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "k8s/ceph/cluster.yaml",
        ));
    }

    #[test]
    fn every_declared_hash_must_match_one_evidence_unit() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![
                "first-required-value".into(),
                "second-required-value".into(),
            ],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        let mut one = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let first = b"first-required-value\n";
        one.scan_reader("config.yaml", &mut &first[..], first.len() as u64)
            .unwrap();
        let one = one.complete(&"a".repeat(40), "b".repeat(64));
        assert_eq!(
            claim_verdict(&claim, &one, &"a".repeat(40)),
            RepositoryClaimVerdict::Supported
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &one,
            &"a".repeat(40),
            "config.yaml",
        ));

        let mut both = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let values = b"first-required-value second-required-value\n";
        both.scan_reader("config.yaml", &mut &values[..], values.len() as u64)
            .unwrap();
        let both = both.complete(&"a".repeat(40), "b".repeat(64));
        assert_eq!(
            claim_verdict(&claim, &both, &"a".repeat(40)),
            RepositoryClaimVerdict::Unresolved
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &both,
            &"a".repeat(40),
            "config.yaml",
        ));
    }

    #[test]
    fn filename_and_comment_hits_remain_unresolved_candidates() {
        let claim = claim("required-construct");
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let mut filename = SearchAccumulator::new(terms.clone());
        filename.scan_path("docs/required-construct.md");
        let filename = filename.complete(&"a".repeat(40), "b".repeat(64));
        assert_eq!(
            claim_verdict(&claim, &filename, &"a".repeat(40)),
            RepositoryClaimVerdict::Unresolved
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &filename,
            &"a".repeat(40),
            "docs/required-construct.md",
        ));

        let mut comment = SearchAccumulator::new(terms);
        let content = b"# required-construct is documented here\n";
        comment
            .scan_reader("src/config.rs", &mut &content[..], content.len() as u64)
            .unwrap();
        let comment = comment.complete(&"a".repeat(40), "b".repeat(64));
        assert_eq!(
            claim_verdict(&claim, &comment, &"a".repeat(40)),
            RepositoryClaimVerdict::Unresolved
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &comment,
            &"a".repeat(40),
            "src/config.rs",
        ));
    }

    #[test]
    fn complete_search_without_a_match_supports_a_bounded_claim() {
        let claim = claim("missing");
        let queries = receipt_queries(&search_terms(std::iter::once(&claim)).unwrap());
        let mut findings = vec![finding(claim)];
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            queries,
            ..RepositorySearchReceipt::default()
        };
        assert!(enforce_receipt(&mut findings, &receipt).is_empty());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn complete_receipt_without_the_claim_query_leaves_it_unresolved() {
        let mut findings = vec![finding(claim("missing"))];
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            ..RepositorySearchReceipt::default()
        };

        assert!(enforce_receipt(&mut findings, &receipt).is_empty());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn unavailable_and_exhausted_search_leave_a_claim_unresolved() {
        for state in [
            RepositorySearchState::Unavailable,
            RepositorySearchState::Exhausted,
        ] {
            let mut findings = vec![finding(claim("missing"))];
            let receipt = RepositorySearchReceipt {
                head_sha: Some("head".into()),
                state,
                ..RepositorySearchReceipt::default()
            };
            assert!(enforce_receipt(&mut findings, &receipt).is_empty());
            assert_eq!(findings.len(), 1);
        }
    }

    #[test]
    fn undeclared_universal_claim_and_boundary_language_are_suppressed() {
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            ..RepositorySearchReceipt::default()
        };
        let mut universal = finding(claim("unused"));
        universal.repository_claim = None;
        universal.body = "No other caller handles this value; add a compatible caller.".into();
        let mut boundary = finding(claim("unused"));
        boundary.repository_claim = None;
        boundary.body =
            "No CephCluster image change appears in this diff; update it to v19.2.5.".into();
        let mut findings = vec![universal, boundary];

        assert_eq!(enforce_receipt(&mut findings, &receipt).len(), 2);
        assert!(findings.is_empty());
    }

    #[test]
    fn undeclared_relational_version_claim_is_suppressed() {
        let mut finding = finding(claim("unused"));
        finding.repository_claim = None;
        finding.body =
            "This PR updates only the backup image; CephCluster remains on v19.2.3.".into();
        let mut findings = vec![finding];
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            ..RepositorySearchReceipt::default()
        };

        assert_eq!(enforce_receipt(&mut findings, &receipt).len(), 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn detailed_match_recording_is_bounded_without_losing_matched_queries() {
        let terms = search_terms([&claim("present")].into_iter()).unwrap();
        let digest = terms[0].query_sha256.clone();
        let mut search = SearchAccumulator::new(terms);
        for index in 0..=MAX_RECORDED_MATCHES {
            let bytes = b"present";
            search
                .scan_reader(
                    &format!("generated/{index}.yaml"),
                    &mut &bytes[..],
                    bytes.len() as u64,
                )
                .unwrap();
        }
        let receipt = search.complete(&"a".repeat(40), sha256_hex(b"tree"));
        assert_eq!(receipt.matches.len(), MAX_RECORDED_MATCHES);
        assert!(receipt.matches_truncated);
        assert_eq!(receipt.match_count, (MAX_RECORDED_MATCHES + 1) as u64);
        assert_eq!(receipt.matched_query_sha256, vec![digest]);
    }

    #[tokio::test]
    async fn query_limit_produces_explicit_exhaustion() {
        let claims = (0..=MAX_SEARCH_TERMS)
            .map(|index| claim(&format!("identifier-{index}")))
            .collect::<Vec<_>>();
        let findings = claims.into_iter().map(finding).collect::<Vec<_>>();
        let receipt = search(
            &RepositorySource::Unavailable,
            Some(&"a".repeat(40)),
            findings.iter(),
        )
        .await;
        assert_eq!(receipt.state, RepositorySearchState::Exhausted);
    }

    #[tokio::test]
    async fn unavailable_source_keeps_the_bounded_typed_queries() {
        let finding = finding(typed_claim());
        let receipt = search(
            &RepositorySource::Unavailable,
            Some(&"a".repeat(40)),
            std::iter::once(&finding),
        )
        .await;
        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert_eq!(receipt.queries.len(), 5);
    }

    #[tokio::test]
    async fn zero_terms_short_circuit_before_source_traversal() {
        let mut finding = finding(claim("unused"));
        finding.repository_claim = None;
        let receipt = search(
            &RepositorySource::Local(Path::new("/path/that/does/not/exist")),
            Some(&"a".repeat(40)),
            std::iter::once(&finding),
        )
        .await;

        assert_eq!(receipt.state, RepositorySearchState::Unavailable);
        assert!(receipt.queries.is_empty());
    }

    #[tokio::test]
    async fn gitlink_metadata_is_hashed_and_never_yields_a_complete_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        run_git(root, &["init", "--quiet"]);
        let first = "1".repeat(40);
        run_git(
            root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{first},vendor/ceph"),
            ],
        );
        let first_tree = run_git(root, &["write-tree"]);
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![first.clone()],
            versions: vec![],
            paths: vec!["vendor/ceph".into()],
            identifiers: vec![],
        };
        let first_receipt = search_local(
            root,
            &first_tree,
            search_terms(std::iter::once(&claim)).unwrap(),
        )
        .await;

        assert_eq!(first_receipt.state, RepositorySearchState::Unavailable);
        assert!(first_receipt.tree_sha256.is_some());
        assert_eq!(first_receipt.matched_query_sha256.len(), 2);

        let second = "2".repeat(40);
        run_git(
            root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{second},vendor/ceph"),
            ],
        );
        let second_tree = run_git(root, &["write-tree"]);
        let second_receipt = search_local(
            root,
            &second_tree,
            search_terms(std::iter::once(&claim)).unwrap(),
        )
        .await;
        assert_ne!(first_receipt.tree_sha256, second_receipt.tree_sha256);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_search_uses_the_exact_commit_after_head_and_worktree_mutate() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        run_git(root, &["init", "--quiet"]);
        std::fs::create_dir_all(root.join("generated/releases")).unwrap();
        std::fs::write(
            root.join("generated/releases/cluster.yaml"),
            "kind: CephCluster\nclusterVersion: 19.2.5\nimage: ceph:19.2.5\ncommitted-value\n",
        )
        .unwrap();
        std::fs::write(root.join("hostile\nname.yaml"), "hostileIdentifier\n").unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "outside-secret-term\n").unwrap();
        symlink(outside.path(), root.join("outside-link")).unwrap();
        let reviewed_head = commit_index(root, None);

        std::fs::rename(
            root.join("generated/releases/cluster.yaml"),
            root.join("cluster-moved.yaml"),
        )
        .unwrap();
        std::fs::write(
            root.join("cluster-moved.yaml"),
            "kind: CephCluster\nclusterVersion: 20.0.0\nworktree-only\n",
        )
        .unwrap();
        let new_head = commit_index(root, Some(&reviewed_head));
        std::fs::write(root.join("cluster-moved.yaml"), "worktree-only-secret\n").unwrap();
        assert_ne!(reviewed_head, new_head);

        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["CephCluster".into()],
            values: vec![
                "committed-value".into(),
                "worktree-only".into(),
                "outside-secret-term".into(),
            ],
            versions: vec!["19.2.5".into(), "20.0.0".into()],
            paths: vec!["generated/releases/cluster.yaml".into()],
            identifiers: vec!["clusterVersion".into(), "hostileIdentifier".into()],
        };
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let expected = terms
            .iter()
            .map(|term| (term.kind, term.query_sha256.clone()))
            .collect::<BTreeMap<_, _>>();
        let receipt = search_local(root, &reviewed_head, terms).await;

        assert_eq!(receipt.head_sha.as_deref(), Some(reviewed_head.as_str()));
        assert_eq!(receipt.state, RepositorySearchState::Complete);
        assert_eq!(receipt.searched_blobs, 3);
        for kind in [
            RepositorySearchQueryKind::Resource,
            RepositorySearchQueryKind::Path,
            RepositorySearchQueryKind::Identifier,
        ] {
            assert!(receipt.matched_query_sha256.contains(&expected[&kind]));
        }
        let version_hash = query_sha256(RepositorySearchQueryKind::Version, b"19.2.5");
        let new_version_hash = query_sha256(RepositorySearchQueryKind::Version, b"20.0.0");
        let worktree_hash = query_sha256(RepositorySearchQueryKind::Value, b"worktree-only");
        let outside_hash = query_sha256(RepositorySearchQueryKind::Value, b"outside-secret-term");
        assert!(receipt.matched_query_sha256.contains(&version_hash));
        assert!(!receipt.matched_query_sha256.contains(&new_version_hash));
        assert!(!receipt.matched_query_sha256.contains(&worktree_hash));
        assert!(!receipt.matched_query_sha256.contains(&outside_hash));
        assert!(receipt.matches.iter().any(|matched| {
            matched.path == "generated/releases/cluster.yaml" && matched.occurrences >= 2
        }));
        assert!(
            receipt
                .matches
                .iter()
                .any(|matched| matched.path == "hostile\nname.yaml")
        );
    }
}
