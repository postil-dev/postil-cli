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
    Finding, RepositoryClaim, RepositorySearchEvidence, RepositorySearchMatch,
    RepositorySearchQuery, RepositorySearchQueryKind, RepositorySearchReceipt,
    RepositorySearchState, SuppressedFinding, SuppressionReason,
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
const MAX_REPOSITORY_EVIDENCE_LINES: usize = 256;
const MAX_REPOSITORY_EVIDENCE_LINE_BYTES: usize = 512;
const MAX_REPOSITORY_EVIDENCE_BYTES: usize = 6 * 1024;
const REPOSITORY_EVIDENCE_WINDOW_RADIUS: u32 = 6;

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
    evidence: Vec<u8>,
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
            evidence: value.as_bytes().to_vec(),
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
    claim: &RepositoryClaim,
    receipt: &RepositorySearchReceipt,
    snapshot_id: &str,
    evidence: &str,
) -> bool {
    if evidence.trim().is_empty()
        || receipt.state != RepositorySearchState::Complete
        || receipt.head_sha.as_deref() != Some(snapshot_id)
        || !valid_full_object_id(snapshot_id)
        || !receipt.tree_sha256.as_deref().is_some_and(valid_sha256)
        || receipt.matches_truncated
        || receipt.evidence_truncated
        || !claim_is_valid(claim)
    {
        return false;
    }
    let searched = receipt
        .queries
        .iter()
        .map(|query| query.query_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let Some(claim_hashes) = claim_query_hashes(claim) else {
        return false;
    };
    if !claim_hashes
        .iter()
        .all(|hash| searched.contains(hash.as_str()))
    {
        return false;
    }
    let categories = claim_category_hashes(claim);
    let expected = match claim.kind {
        crate::envelope::RepositoryClaimKind::Absence => categories
            .iter()
            .flatten()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        crate::envelope::RepositoryClaimKind::Mismatch => categories[1]
            .iter()
            .chain(&categories[2])
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
    };
    if expected.is_empty() {
        return false;
    }
    let mut grounded = 0usize;
    for candidate in receipt
        .evidence
        .iter()
        .filter(|candidate| candidate.source == evidence)
    {
        let candidate_hashes = candidate
            .query_sha256
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let source_has_expected = match claim.kind {
            crate::envelope::RepositoryClaimKind::Absence => {
                expected.iter().any(|hash| candidate_hashes.contains(hash))
            }
            crate::envelope::RepositoryClaimKind::Mismatch => {
                expected.iter().all(|hash| candidate_hashes.contains(hash))
            }
        };
        if !source_has_expected {
            continue;
        }
        let window_hashes = receipt
            .evidence
            .iter()
            .filter(|entry| {
                entry.path == candidate.path
                    && entry.line.abs_diff(candidate.line) <= REPOSITORY_EVIDENCE_WINDOW_RADIUS
            })
            .flat_map(|entry| entry.query_sha256.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        if category_hashes_match(&categories, &window_hashes) {
            grounded += 1;
            if grounded > 1 {
                return false;
            }
        }
    }
    grounded == 1
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
    crate::envelope::publication_exposes_evidence_boundary(finding)
}

pub(crate) fn prose_requires_repository_search(finding: &Finding) -> bool {
    let prose = format!("{}. {}", finding.title, finding.body).to_ascii_lowercase();
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
        && version_like_token_count(&prose) >= 1
        && [
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
    fixed_scope || quantified_repository_relation(&prose) || exclusive_update || version_relation
}

fn quantified_repository_relation(prose: &str) -> bool {
    let normalized = prose
        .replace(['’', '‘'], "'")
        .replace("aren't", "are not")
        .replace("isn't", "is not")
        .replace("wasn't", "was not")
        .replace("weren't", "were not")
        .replace("don't", "do not")
        .replace("doesn't", "does not")
        .replace("didn't", "did not")
        .replace("hasn't", "has not")
        .replace("haven't", "have not")
        .replace("hadn't", "had not")
        .replace("can't", "cannot")
        .replace("couldn't", "could not")
        .replace("won't", "will not")
        .replace("wouldn't", "would not")
        .replace("shouldn't", "should not");
    let is_relation_noun = |words: &[&str], index: usize, word: &str| {
        matches!(
            word,
            "callee"
                | "callees"
                | "caller"
                | "callers"
                | "consumer"
                | "consumers"
                | "counterpart"
                | "counterparts"
                | "declaration"
                | "declarations"
                | "definition"
                | "definitions"
                | "export"
                | "exports"
                | "handler"
                | "handlers"
                | "implementation"
                | "implementations"
                | "import"
                | "imports"
                | "invocation"
                | "invocations"
                | "manifest"
                | "manifests"
                | "reference"
                | "references"
                | "registration"
                | "registrations"
                | "route"
                | "routes"
                | "usage"
                | "usages"
        ) || (word == "call"
            && words
                .get(index + 1)
                .is_some_and(|next| matches!(*next, "site" | "sites")))
    };
    let is_relation_action = |word: &str| {
        matches!(
            word,
            "called"
                | "calls"
                | "consume"
                | "consumed"
                | "consumes"
                | "exported"
                | "exporting"
                | "imported"
                | "importing"
                | "invoke"
                | "invoked"
                | "invokes"
                | "referenced"
                | "referencing"
                | "use"
                | "used"
                | "uses"
        )
    };
    let is_intrinsic_repository_noun = |words: &[&str], index: usize, word: &str| {
        matches!(
            word,
            "callee"
                | "callees"
                | "caller"
                | "callers"
                | "consumer"
                | "consumers"
                | "counterpart"
                | "counterparts"
                | "declaration"
                | "declarations"
                | "definition"
                | "definitions"
                | "export"
                | "exports"
                | "import"
                | "imports"
                | "invocation"
                | "invocations"
                | "manifest"
                | "manifests"
                | "reference"
                | "references"
                | "registration"
                | "registrations"
                | "usage"
                | "usages"
        ) || (word == "call"
            && words
                .get(index + 1)
                .is_some_and(|next| matches!(*next, "site" | "sites")))
    };
    normalized
        .split(['.', '!', '?', ';', ':', ',', '\n'])
        .any(|clause| {
            let words = clause
                .split(|character: char| !character.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>();
            let bound_relation_noun = words.iter().enumerate().any(|(index, word)| {
                if !is_relation_noun(&words, index, word) {
                    return false;
                }
                let establishes_repository_relation =
                    is_intrinsic_repository_noun(&words, index, word)
                        || words[index + 1..]
                            .iter()
                            .any(|candidate| is_relation_action(candidate));
                if !establishes_repository_relation {
                    return false;
                }
                let preceding = &words[index.saturating_sub(4)..index];
                if preceding.iter().any(|word| {
                    matches!(
                        *word,
                        "all"
                            | "every"
                            | "generated"
                            | "no"
                            | "only"
                            | "remaining"
                            | "unchanged"
                            | "zero"
                    )
                }) || preceding
                    .windows(3)
                    .any(|window| window == ["not", "a", "single"])
                {
                    return true;
                }

                let Some(any_index) = words[..index]
                    .iter()
                    .rposition(|candidate| *candidate == "any")
                else {
                    return false;
                };
                index.saturating_sub(any_index) <= 3
                    && words[any_index.saturating_sub(6)..any_index].contains(&"not")
                    && words[any_index.saturating_sub(6)..any_index]
                        .iter()
                        .any(|candidate| {
                            matches!(*candidate, "are" | "exist" | "exists" | "have" | "has")
                        })
            });
            let existential_relation = words.iter().enumerate().any(|(index, word)| {
                matches!(*word, "nobody" | "none" | "nothing")
                    && words[index + 1..].iter().any(|candidate| {
                        is_relation_action(candidate)
                            || matches!(*candidate, "unreferenced" | "unused")
                    })
            });
            let universal_action = words.iter().enumerate().any(|(index, word)| {
                if *word != "no" {
                    return false;
                }
                let subject_end = (index + 5).min(words.len());
                let Some(path_offset) = words[index + 1..subject_end]
                    .iter()
                    .position(|candidate| matches!(*candidate, "path" | "paths"))
                else {
                    return false;
                };
                let path_index = index + 1 + path_offset;
                words[index + 1..path_index]
                    .iter()
                    .any(|candidate| matches!(*candidate, "code" | "execution"))
                    && words[path_index + 1..]
                        .iter()
                        .any(|candidate| is_relation_action(candidate))
            });
            let global_relation = words.iter().any(|word| {
                matches!(
                    *word,
                    "anywhere" | "codebase" | "elsewhere" | "nowhere" | "repository"
                )
            }) && words.iter().enumerate().any(|(index, word)| {
                is_intrinsic_repository_noun(&words, index, word)
                    || is_relation_action(word)
                    || matches!(*word, "unreferenced" | "unused")
            });

            bound_relation_noun || existential_relation || universal_action || global_relation
        })
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

struct RepositoryEvidenceCollector<'a> {
    path: &'a str,
    terms: &'a [SearchTerm],
    path_hashes: Vec<String>,
    line: Vec<u8>,
    line_number: u64,
    line_overflowed: bool,
    lines: Vec<RepositorySearchEvidence>,
    evidence_bytes: usize,
    block_comment_depth: u32,
    html_comment: bool,
    comment_quote: Option<u8>,
    comment_quote_escaped: bool,
    comment_raw_string_hashes: Option<usize>,
    literal_quote: Option<u8>,
    literal_quote_escaped: bool,
    literal_raw_string_hashes: Option<usize>,
    yaml_block_scalar_parent_indent: Option<usize>,
    truncated: bool,
}

impl<'a> RepositoryEvidenceCollector<'a> {
    fn new(path: &'a str, terms: &'a [SearchTerm]) -> Self {
        let path_hashes = terms
            .iter()
            .filter(|term| {
                term.kind == RepositorySearchQueryKind::Path && path.as_bytes() == term.evidence
            })
            .map(|term| term.query_sha256.clone())
            .collect();
        Self {
            path,
            terms,
            path_hashes,
            line: Vec::new(),
            line_number: 1,
            line_overflowed: false,
            lines: Vec::new(),
            evidence_bytes: 0,
            block_comment_depth: 0,
            html_comment: false,
            comment_quote: None,
            comment_quote_escaped: false,
            comment_raw_string_hashes: None,
            literal_quote: None,
            literal_quote_escaped: false,
            literal_raw_string_hashes: None,
            yaml_block_scalar_parent_indent: None,
            truncated: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if *byte == b'\n' {
                self.finish_line();
                self.line_number = self.line_number.saturating_add(1);
                continue;
            }
            if *byte == b'\r' {
                continue;
            }
            if self.line.len() < MAX_REPOSITORY_EVIDENCE_LINE_BYTES {
                self.line.push(*byte);
            } else {
                self.line_overflowed = true;
            }
        }
    }

    fn finish(&mut self) {
        if !self.line.is_empty() || self.line_overflowed {
            self.finish_line();
        }
    }

    fn into_parts(self) -> (Vec<RepositorySearchEvidence>, bool) {
        (self.lines, self.truncated)
    }

    fn finish_line(&mut self) {
        if self.line_overflowed {
            self.truncated = true;
            self.line.clear();
            self.line_overflowed = false;
            return;
        }
        let Ok(source) = std::str::from_utf8(&self.line) else {
            self.line.clear();
            return;
        };
        let Some(kind) = repository_evidence_kind(self.path) else {
            self.line.clear();
            return;
        };
        if matches!(kind, RepositoryEvidenceKind::ColonKey) {
            let indent = source
                .as_bytes()
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            if let Some(parent_indent) = self.yaml_block_scalar_parent_indent {
                if source.trim().is_empty() || indent > parent_indent {
                    self.line.clear();
                    return;
                }
                self.yaml_block_scalar_parent_indent = None;
            }
        }
        let uncommented = source_without_comments(
            source.as_bytes(),
            kind.comment_syntax(),
            &mut self.block_comment_depth,
            &mut self.html_comment,
            &mut self.comment_quote,
            &mut self.comment_quote_escaped,
            &mut self.comment_raw_string_hashes,
        );
        if uncommented.iter().all(u8::is_ascii_whitespace) {
            self.line.clear();
            return;
        }
        if matches!(kind, RepositoryEvidenceKind::ColonKey)
            && yaml_block_scalar_indicator(&uncommented)
        {
            self.yaml_block_scalar_parent_indent = Some(
                uncommented
                    .iter()
                    .take_while(|byte| byte.is_ascii_whitespace())
                    .count(),
            );
        }
        let executable = source_without_literals(
            &uncommented,
            kind.comment_syntax(),
            &mut self.literal_quote,
            &mut self.literal_quote_escaped,
            &mut self.literal_raw_string_hashes,
        );
        let mut hashes = self
            .terms
            .iter()
            .filter(|term| match (kind, term.kind) {
                (RepositoryEvidenceKind::Code(_), _) => {
                    structured_bytes_match(&executable, &term.evidence)
                }
                (RepositoryEvidenceKind::ColonKey, RepositorySearchQueryKind::Identifier)
                | (RepositoryEvidenceKind::EqualsKey, RepositorySearchQueryKind::Identifier) => {
                    identifier_source_match(kind, &executable, &term.evidence)
                }
                (_, _) => structured_bytes_match(&executable, &term.evidence),
            })
            .map(|term| term.query_sha256.clone())
            .collect::<BTreeSet<_>>();
        if hashes.is_empty() {
            self.line.clear();
            return;
        }
        hashes.extend(self.path_hashes.iter().cloned());
        let Ok(line) = u32::try_from(self.line_number) else {
            self.truncated = true;
            self.line.clear();
            return;
        };
        let query_sha256 = hashes.into_iter().collect::<Vec<_>>();
        let evidence_bytes = repository_evidence_size(self.path, source, &query_sha256);
        if self.lines.len() == MAX_REPOSITORY_EVIDENCE_LINES
            || self
                .evidence_bytes
                .checked_add(evidence_bytes)
                .is_none_or(|total| total > MAX_REPOSITORY_EVIDENCE_BYTES)
        {
            self.truncated = true;
        } else {
            self.lines.push(RepositorySearchEvidence {
                path: self.path.to_string(),
                line,
                source: source.to_string(),
                query_sha256,
            });
            self.evidence_bytes += evidence_bytes;
        }
        self.line.clear();
    }
}

fn path_is_documentation(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or_default();
    normalized
        .split('/')
        .any(|component| matches!(component, "doc" | "docs" | "documentation"))
        || file_name.starts_with("readme")
        || file_name.starts_with("changelog")
        || matches!(
            file_name.rsplit_once('.').map(|(_, extension)| extension),
            Some("adoc" | "md" | "mdx" | "rst" | "txt")
        )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RepositoryCodeSyntax {
    CStyle,
    Python,
    Rust,
}

#[derive(Clone, Copy)]
enum RepositoryEvidenceKind {
    Code(RepositoryCodeSyntax),
    ColonKey,
    EqualsKey,
}

impl RepositoryEvidenceKind {
    fn comment_syntax(self) -> RepositoryCodeSyntax {
        match self {
            Self::Code(syntax) => syntax,
            Self::ColonKey | Self::EqualsKey => RepositoryCodeSyntax::Python,
        }
    }
}

fn repository_evidence_kind(path: &str) -> Option<RepositoryEvidenceKind> {
    if path_is_documentation(path) {
        return None;
    }
    let normalized = path.replace('\\', "/");
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match file_name.rsplit_once('.').map(|(_, extension)| extension) {
        Some("c" | "go" | "h" | "java" | "js" | "jsx" | "mjs" | "ts" | "tsx") => {
            Some(RepositoryEvidenceKind::Code(RepositoryCodeSyntax::CStyle))
        }
        Some("py") => Some(RepositoryEvidenceKind::Code(RepositoryCodeSyntax::Python)),
        Some("rs") => Some(RepositoryEvidenceKind::Code(RepositoryCodeSyntax::Rust)),
        Some("yaml" | "yml") => Some(RepositoryEvidenceKind::ColonKey),
        Some("conf" | "ini" | "toml") => Some(RepositoryEvidenceKind::EqualsKey),
        _ => None,
    }
}

fn identifier_source_match(kind: RepositoryEvidenceKind, text: &[u8], pattern: &[u8]) -> bool {
    text.windows(pattern.len())
        .enumerate()
        .any(|(start, candidate)| {
            if candidate != pattern
                || !structured_bytes_have_boundaries(text, start, start + pattern.len(), pattern)
            {
                return false;
            }
            let suffix = text[start + pattern.len()..]
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace());
            match kind {
                RepositoryEvidenceKind::Code(_) => true,
                RepositoryEvidenceKind::ColonKey => suffix == Some(b':'),
                RepositoryEvidenceKind::EqualsKey => suffix == Some(b'='),
            }
        })
}

fn source_without_comments(
    source: &[u8],
    syntax: RepositoryCodeSyntax,
    block_comment_depth: &mut u32,
    html_comment: &mut bool,
    quote: &mut Option<u8>,
    escaped: &mut bool,
    raw_string_hashes: &mut Option<usize>,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0usize;
    while index < source.len() {
        if let Some(hashes) = *raw_string_hashes {
            if let Some(length) = rust_raw_string_end(source, index, hashes) {
                output.extend_from_slice(&source[index..index + length]);
                *raw_string_hashes = None;
                index += length;
            } else {
                output.push(source[index]);
                index += 1;
            }
            continue;
        }
        if *html_comment {
            if source.get(index..index + 3) == Some(b"-->") {
                *html_comment = false;
                index += 3;
            } else {
                index += 1;
            }
            continue;
        }
        if *block_comment_depth > 0 {
            if source.get(index..index + 2) == Some(b"/*") {
                *block_comment_depth = block_comment_depth.saturating_add(1);
                index += 2;
            } else if source.get(index..index + 2) == Some(b"*/") {
                *block_comment_depth = block_comment_depth.saturating_sub(1);
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if source.get(index..index + 4) == Some(b"<!--") {
            *html_comment = true;
            index += 4;
            continue;
        }
        if source.get(index..index + 2) == Some(b"/*") {
            *block_comment_depth = 1;
            index += 2;
            continue;
        }
        if syntax == RepositoryCodeSyntax::Rust
            && let Some((length, hashes)) = rust_raw_string_start(source, index)
        {
            output.extend_from_slice(&source[index..index + length]);
            *raw_string_hashes = Some(hashes);
            index += length;
            continue;
        }
        let byte = source[index];
        if let Some(delimiter) = *quote {
            output.push(byte);
            if *escaped {
                *escaped = false;
            } else if byte == b'\\' {
                *escaped = true;
            } else if byte == delimiter {
                *quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            *quote = Some(byte);
            output.push(byte);
            index += 1;
            continue;
        }
        let line_comment = match syntax {
            RepositoryCodeSyntax::CStyle | RepositoryCodeSyntax::Rust => {
                source.get(index..index + 2) == Some(b"//")
            }
            RepositoryCodeSyntax::Python => byte == b'#',
        };
        if line_comment {
            break;
        }
        output.push(byte);
        index += 1;
    }
    output
}

fn source_without_literals(
    source: &[u8],
    syntax: RepositoryCodeSyntax,
    quote: &mut Option<u8>,
    escaped: &mut bool,
    raw_string_hashes: &mut Option<usize>,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0usize;
    while index < source.len() {
        if let Some(hashes) = *raw_string_hashes {
            if let Some(length) = rust_raw_string_end(source, index, hashes) {
                output.resize(output.len() + length, b' ');
                *raw_string_hashes = None;
                index += length;
            } else {
                output.push(b' ');
                index += 1;
            }
            continue;
        }
        if syntax == RepositoryCodeSyntax::Rust
            && quote.is_none()
            && let Some((length, hashes)) = rust_raw_string_start(source, index)
        {
            output.resize(output.len() + length, b' ');
            *raw_string_hashes = Some(hashes);
            index += length;
            continue;
        }
        let byte = source[index];
        if let Some(delimiter) = *quote {
            output.push(b' ');
            if *escaped {
                *escaped = false;
            } else if byte == b'\\' {
                *escaped = true;
            } else if byte == delimiter {
                *quote = None;
            }
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            *quote = Some(byte);
            output.push(b' ');
        } else {
            output.push(byte);
        }
        index += 1;
    }
    output
}

fn rust_raw_string_start(source: &[u8], index: usize) -> Option<(usize, usize)> {
    if index > 0
        && source
            .get(index - 1)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return None;
    }
    let mut cursor = index;
    if source.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if source.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hash_start = cursor;
    while source.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (source.get(cursor) == Some(&b'"')).then_some((cursor - index + 1, cursor - hash_start))
}

fn rust_raw_string_end(source: &[u8], index: usize, hashes: usize) -> Option<usize> {
    if source.get(index) != Some(&b'"') {
        return None;
    }
    let end = index.checked_add(1 + hashes)?;
    let suffix = source.get(index + 1..end)?;
    suffix
        .iter()
        .all(|byte| *byte == b'#')
        .then_some(1 + hashes)
}

fn repository_evidence_size(path: &str, source: &str, query_sha256: &[String]) -> usize {
    path.len()
        .saturating_add(source.len())
        .saturating_add(
            query_sha256
                .iter()
                .map(String::len)
                .fold(0usize, usize::saturating_add),
        )
        .saturating_add(64)
}

fn structured_bytes_match(text: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || pattern.len() > text.len() {
        return false;
    }
    text.windows(pattern.len())
        .enumerate()
        .any(|(start, candidate)| {
            candidate == pattern
                && structured_bytes_have_boundaries(text, start, start + pattern.len(), pattern)
        })
}

fn structured_bytes_have_boundaries(text: &[u8], start: usize, end: usize, pattern: &[u8]) -> bool {
    let word_byte = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let starts_with_word = pattern.first().copied().is_some_and(word_byte);
    let ends_with_word = pattern.last().copied().is_some_and(word_byte);
    (!starts_with_word || start == 0 || !text.get(start - 1).copied().is_some_and(word_byte))
        && (!ends_with_word || end == text.len() || !text.get(end).copied().is_some_and(word_byte))
}

fn yaml_block_scalar_indicator(source: &[u8]) -> bool {
    let Some(end) = source.iter().rposition(|byte| !byte.is_ascii_whitespace()) else {
        return false;
    };
    let start = source[..=end]
        .iter()
        .rposition(|byte| byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    let marker = &source[start..=end];
    let Some(first) = marker.first() else {
        return false;
    };
    if !matches!(first, b'|' | b'>') || marker.len() > 3 {
        return false;
    }
    let modifiers = &marker[1..];
    modifiers
        .iter()
        .all(|byte| matches!(byte, b'+' | b'-' | b'1'..=b'9'))
        && modifiers
            .iter()
            .filter(|byte| matches!(byte, b'+' | b'-'))
            .count()
            <= 1
        && modifiers
            .iter()
            .filter(|byte| matches!(byte, b'1'..=b'9'))
            .count()
            <= 1
}

pub(crate) struct SearchAccumulator {
    terms: Vec<SearchTerm>,
    matched_queries: BTreeSet<String>,
    matches: BTreeMap<(String, String), u64>,
    match_count: u64,
    searched_blobs: u64,
    searched_bytes: u64,
    evidence: Vec<RepositorySearchEvidence>,
    evidence_bytes: usize,
    evidence_truncated: bool,
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
            evidence: Vec::new(),
            evidence_bytes: 0,
            evidence_truncated: false,
        }
    }

    pub(crate) fn scan_path(&mut self, path: &str) {
        let normalized = ascii_lower(path.as_bytes());
        let mut path_hashes = Vec::new();
        for index in 0..self.terms.len() {
            let occurrences = count_occurrences(&normalized, &self.terms[index]);
            if self.terms[index].kind == RepositorySearchQueryKind::Path
                && path.as_bytes() == self.terms[index].evidence
            {
                path_hashes.push(self.terms[index].query_sha256.clone());
            }
            self.record(index, path, occurrences);
        }
        if !path_hashes.is_empty() {
            self.record_evidence(RepositorySearchEvidence {
                path: path.to_string(),
                line: 0,
                source: path.to_string(),
                query_sha256: path_hashes,
            });
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
        let mut evidence = RepositoryEvidenceCollector::new(path, &self.terms);
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
            evidence.push(&chunk[..count]);
        }
        scanner.finish();
        evidence.finish();
        if read != expected_size {
            return Err(std::io::Error::other(
                "repository blob size did not match tree metadata",
            ));
        }
        let (evidence, evidence_truncated) = evidence.into_parts();
        self.finish_blob(path, read, scanner.counts, evidence, evidence_truncated);
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
        let mut evidence = RepositoryEvidenceCollector::new(path, &self.terms);
        let mut object_hash = GitObjectHash::new("blob", expected_size);
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
            object_hash.update(&chunk[..count]);
            scanner.push(&chunk[..count]);
            evidence.push(&chunk[..count]);
        }
        let mut terminator = [0u8; 1];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\n" {
            return Err(std::io::Error::other(
                "git batch output omitted its blob delimiter",
            ));
        }
        scanner.finish();
        evidence.finish();
        if !object_hash.matches(object_id) {
            return Err(std::io::Error::other(
                "git batch blob did not match its object id",
            ));
        }
        let (evidence, evidence_truncated) = evidence.into_parts();
        self.finish_blob(path, read, scanner.counts, evidence, evidence_truncated);
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
        let mut evidence = RepositoryEvidenceCollector::new(path, &self.terms);
        let mut object_hash = GitObjectHash::new("blob", expected_size);
        let mut read = 0u64;
        while let Some(chunk) = response.chunk().await? {
            read = read
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("repository search byte count overflowed"))?;
            object_hash.update(&chunk);
            scanner.push(&chunk);
            evidence.push(&chunk);
        }
        scanner.finish();
        evidence.finish();
        anyhow::ensure!(read == expected_size, "repository blob size changed");
        anyhow::ensure!(
            object_hash.matches(expected_object_id),
            "repository blob did not match its tree object id"
        );
        let (evidence, evidence_truncated) = evidence.into_parts();
        self.finish_blob(path, read, scanner.counts, evidence, evidence_truncated);
        Ok(())
    }

    fn finish_blob(
        &mut self,
        path: &str,
        bytes: u64,
        counts: Vec<u64>,
        evidence: Vec<RepositorySearchEvidence>,
        evidence_truncated: bool,
    ) {
        self.searched_blobs = self.searched_blobs.saturating_add(1);
        self.searched_bytes = self.searched_bytes.saturating_add(bytes);
        for (index, occurrences) in counts.into_iter().enumerate() {
            self.record(index, path, occurrences);
        }
        self.evidence_truncated |= evidence_truncated;
        for line in evidence {
            if !self.record_evidence(line) {
                break;
            }
        }
    }

    fn record_evidence(&mut self, line: RepositorySearchEvidence) -> bool {
        let evidence_bytes = repository_evidence_size(&line.path, &line.source, &line.query_sha256);
        if self.evidence.len() == MAX_REPOSITORY_EVIDENCE_LINES
            || self
                .evidence_bytes
                .checked_add(evidence_bytes)
                .is_none_or(|total| total > MAX_REPOSITORY_EVIDENCE_BYTES)
        {
            self.evidence_truncated = true;
            return false;
        }
        self.evidence.push(line);
        self.evidence_bytes += evidence_bytes;
        true
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
            evidence: self.evidence,
            evidence_truncated: self.evidence_truncated,
        }
    }
}

pub(crate) struct GitObjectHash {
    sha1: Sha1,
    sha256: Sha256,
}

impl GitObjectHash {
    pub(crate) fn new(kind: &str, size: u64) -> Self {
        let header = format!("{kind} {size}\0");
        let mut sha1 = Sha1::new();
        sha1.update(header.as_bytes());
        let mut sha256 = Sha256::new();
        sha256.update(header.as_bytes());
        Self { sha1, sha256 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    pub(crate) fn matches(self, expected: &str) -> bool {
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
    let mut hash = GitObjectHash::new("blob", bytes.len() as u64);
    hash.update(bytes);
    hex_digest(hash.sha1.finalize())
}

pub(crate) fn git_tree_matches<'a>(
    expected: &str,
    entries: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
) -> bool {
    git_tree_object_id(expected.len(), entries)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn git_tree_object_id<'a>(
    object_id_hex_len: usize,
    entries: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
) -> Option<String> {
    if !matches!(object_id_hex_len, 40 | 64) {
        return None;
    }
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| git_tree_name_cmp(left.0, left.1, right.0, right.1));
    if entries
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return None;
    }
    let object_id_bytes = object_id_hex_len / 2;
    let mut payload_size = 0u64;
    for (path, mode, object_id) in &entries {
        let mode = canonical_tree_mode(mode)?;
        if path.is_empty()
            || path.contains('/')
            || path.contains('\0')
            || object_id.len() != object_id_hex_len
            || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        payload_size = payload_size
            .checked_add(mode.len() as u64)?
            .checked_add(1)?
            .checked_add(path.len() as u64)?
            .checked_add(1)?
            .checked_add(object_id_bytes as u64)?;
    }
    let mut hash = GitObjectHash::new("tree", payload_size);
    let mut decoded = [0u8; 32];
    for (path, mode, object_id) in entries {
        let mode = canonical_tree_mode(mode)?;
        hash.update(mode.as_bytes());
        hash.update(b" ");
        hash.update(path.as_bytes());
        hash.update(b"\0");
        decode_hex_into(object_id, &mut decoded[..object_id_bytes])?;
        hash.update(&decoded[..object_id_bytes]);
    }
    Some(match object_id_hex_len {
        40 => hex_digest(hash.sha1.finalize()),
        64 => hex_digest(hash.sha256.finalize()),
        _ => unreachable!(),
    })
}

fn canonical_tree_mode(mode: &str) -> Option<&str> {
    match mode {
        "040000" | "40000" => Some("40000"),
        "100644" | "100755" | "120000" | "160000" => Some(mode),
        _ => None,
    }
}

fn git_tree_name_cmp(
    left_path: &str,
    left_mode: &str,
    right_path: &str,
    right_mode: &str,
) -> std::cmp::Ordering {
    let left = left_path.as_bytes();
    let right = right_path.as_bytes();
    let shared = left.len().min(right.len());
    let prefix = left[..shared].cmp(&right[..shared]);
    if prefix != std::cmp::Ordering::Equal {
        return prefix;
    }
    let left_suffix = left.get(shared).copied().unwrap_or({
        if matches!(left_mode, "040000" | "40000") {
            b'/'
        } else {
            0
        }
    });
    let right_suffix = right.get(shared).copied().unwrap_or({
        if matches!(right_mode, "040000" | "40000") {
            b'/'
        } else {
            0
        }
    });
    left_suffix.cmp(&right_suffix)
}

fn decode_hex_into(value: &str, output: &mut [u8]) -> Option<()> {
    if value.len() != output.len().checked_mul(2)? {
        return None;
    }
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = hex_nibble(pair[0])?.checked_mul(16)? + hex_nibble(pair[1])?;
    }
    Some(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn git_tree_sha1<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
) -> String {
    git_tree_object_id(40, entries).expect("valid fixture tree")
}

pub(crate) fn reconstructed_root_tree_matches(
    entries: &[RepositorySnapshotEntry],
    expected: &str,
) -> bool {
    if !valid_full_object_id(expected) {
        return false;
    }
    let mut directories = BTreeMap::<String, Vec<(String, String, String)>>::new();
    directories.entry(String::new()).or_default();
    for entry in entries {
        let components = entry.path.split('/').collect::<Vec<_>>();
        if components.is_empty() || components.iter().any(|component| component.is_empty()) {
            return false;
        }
        let name = components.last().expect("non-empty components").to_string();
        let parent = components[..components.len() - 1].join("/");
        for depth in 0..components.len() {
            directories
                .entry(components[..depth].join("/"))
                .or_default();
        }
        directories.entry(parent).or_default().push((
            name,
            entry.mode.clone(),
            entry.object_id.clone(),
        ));
    }
    let mut paths = directories.keys().cloned().collect::<Vec<_>>();
    paths.sort_by(|left, right| {
        right
            .bytes()
            .filter(|byte| *byte == b'/')
            .count()
            .cmp(&left.bytes().filter(|byte| *byte == b'/').count())
            .then_with(|| right.len().cmp(&left.len()))
    });
    let mut root = None;
    for path in paths {
        let children = directories.remove(&path).unwrap_or_default();
        let Some(object_id) = git_tree_object_id(
            expected.len(),
            children
                .iter()
                .map(|(name, mode, object_id)| (name.as_str(), mode.as_str(), object_id.as_str())),
        ) else {
            return false;
        };
        if path.is_empty() {
            root = Some(object_id);
            continue;
        }
        let (parent, name) = path
            .rsplit_once('/')
            .map_or(("", path.as_str()), |(parent, name)| (parent, name));
        let Some(siblings) = directories.get_mut(parent) else {
            return false;
        };
        siblings.push((name.to_string(), "040000".to_string(), object_id));
    }
    root.is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
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
    let root_tree_id = local_root_tree_id(root, head_sha).await?;
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
    if !reconstructed_root_tree_matches(&entries, &root_tree_id) {
        return Err(LocalSearchFailure::Unavailable);
    }
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

async fn local_root_tree_id(root: &Path, head_sha: &str) -> Result<String, LocalSearchFailure> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    let mut input = child.stdin.take().ok_or(LocalSearchFailure::Unavailable)?;
    input
        .write_all(format!("{head_sha}\n").as_bytes())
        .await
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    drop(input);
    let output = child.stdout.take().ok_or(LocalSearchFailure::Unavailable)?;
    let mut output = BufReader::new(output);
    let mut header = Vec::with_capacity(MAX_BATCH_HEADER_BYTES);
    let mut limited_header = (&mut output).take((MAX_BATCH_HEADER_BYTES + 1) as u64);
    limited_header
        .read_until(b'\n', &mut header)
        .await
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    drop(limited_header);
    if header.len() > MAX_BATCH_HEADER_BYTES || !header.ends_with(b"\n") {
        return Err(LocalSearchFailure::Unavailable);
    }
    let header = std::str::from_utf8(&header[..header.len() - 1])
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 3
        || !fields[0].eq_ignore_ascii_case(head_sha)
        || !matches!(fields[1], "commit" | "tree")
    {
        return Err(LocalSearchFailure::Unavailable);
    }
    let size = fields[2]
        .parse::<usize>()
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    if size > MAX_TREE_BYTES {
        return Err(LocalSearchFailure::Exhausted);
    }
    let mut bytes = vec![0u8; size];
    output
        .read_exact(&mut bytes)
        .await
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    let mut delimiter = [0u8; 1];
    output
        .read_exact(&mut delimiter)
        .await
        .map_err(|_| LocalSearchFailure::Unavailable)?;
    if delimiter != *b"\n" {
        return Err(LocalSearchFailure::Unavailable);
    }
    drop(output);
    if !child.wait().await.is_ok_and(|status| status.success()) {
        return Err(LocalSearchFailure::Unavailable);
    }
    let mut object_hash = GitObjectHash::new(fields[1], size as u64);
    object_hash.update(&bytes);
    if !object_hash.matches(head_sha) {
        return Err(LocalSearchFailure::Unavailable);
    }
    if fields[1] == "tree" {
        return Ok(head_sha.to_ascii_lowercase());
    }
    let Some(line_end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return Err(LocalSearchFailure::Unavailable);
    };
    let Some(raw_tree) = bytes[..line_end].strip_prefix(b"tree ") else {
        return Err(LocalSearchFailure::Unavailable);
    };
    let tree = std::str::from_utf8(raw_tree).map_err(|_| LocalSearchFailure::Unavailable)?;
    if tree.len() != head_sha.len() || !valid_full_object_id(tree) {
        return Err(LocalSearchFailure::Unavailable);
    }
    Ok(tree.to_ascii_lowercase())
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

    #[test]
    fn canonical_tree_hash_matches_git_for_nested_prefix_names() {
        let directory = tempfile::tempdir().unwrap();
        run_git(directory.path(), &["init", "--quiet"]);
        std::fs::create_dir(directory.path().join("foo")).unwrap();
        std::fs::write(directory.path().join("foo/nested"), "nested\n").unwrap();
        std::fs::write(directory.path().join("foo.bar"), "root\n").unwrap();
        run_git(directory.path(), &["add", "foo/nested", "foo.bar"]);
        let expected = run_git(directory.path(), &["write-tree"]);
        let nested_blob = git_blob_sha1(b"nested\n");
        let root_blob = git_blob_sha1(b"root\n");
        let nested_tree = git_tree_sha1([("nested", "100644", nested_blob.as_str())]);
        let actual = git_tree_sha1([
            ("foo", "040000", nested_tree.as_str()),
            ("foo.bar", "100644", root_blob.as_str()),
        ]);

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn batch_reader_uses_one_protocol_for_multiple_blobs() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, duplex};

        let claim = claim("needle");
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let first_body = b"first needle\n".to_vec();
        let second_body = b"second needle\n".to_vec();
        let first = git_blob_sha1(&first_body);
        let second = git_blob_sha1(&second_body);
        let (mut input, requests) = duplex(1024);
        let (mut responses, output) = duplex(1024);
        let expected = vec![(first.clone(), first_body), (second.clone(), second_body)];
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

    #[tokio::test]
    async fn batch_reader_rejects_blob_bytes_that_do_not_match_the_object_id() {
        use tokio::io::{AsyncWriteExt, duplex};

        let expected = git_blob_sha1(b"wanted");
        let response = format!("{expected} blob 6\nforged\n");
        let claim = claim("forged");
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let (mut input, _requests) = duplex(1024);
        let (mut writer, output) = duplex(1024);
        writer.write_all(response.as_bytes()).await.unwrap();
        drop(writer);
        let mut output = BufReader::new(output);

        assert!(
            scan_batch_object(
                &mut search,
                "config.yaml",
                &expected,
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
        assert!(refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "cephVersion: 19.2.5",
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

        let mut both = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let values = b"first-required-value second-required-value\n";
        both.scan_reader("config.yaml", &mut &values[..], values.len() as u64)
            .unwrap();
        let both = both.complete(&"a".repeat(40), "b".repeat(64));
        assert_eq!(
            claim_verdict(&claim, &both, &"a".repeat(40)),
            RepositoryClaimVerdict::Unresolved
        );
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

        let mut comment = SearchAccumulator::new(terms);
        let content = b"// required-construct is documented here\n";
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
            "// required-construct is documented here",
        ));
    }

    #[test]
    fn immutable_tree_source_can_refute_a_false_absence_claim() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["legacy_api".into()],
        };
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let source = b"fn caller() {\n    legacy_api();\n}\n";
        search
            .scan_reader("src/caller.rs", &mut &source[..], source.len() as u64)
            .unwrap();
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));

        assert!(refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "    legacy_api();",
        ));
    }

    #[test]
    fn immutable_identifier_evidence_excludes_strings_comments_and_documentation() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["legacy_api".into()],
        };
        let terms = search_terms(std::iter::once(&claim)).unwrap();
        let mut search = SearchAccumulator::new(terms);
        for (path, source) in [
            ("src/help.rs", "const HELP: &str = \"legacy_api\";\n"),
            ("src/inline.rs", "let value = 1; // legacy_api();\n"),
            ("src/block.rs", "/*\nlegacy_api();\n*/\n"),
            ("docs/api.md", "legacy_api();\n"),
            ("templates/help.html", "<!-- legacy_api(); -->\n"),
            ("config/help.yaml", "help: |\n  legacy_api();\n"),
        ] {
            search
                .scan_reader(path, &mut source.as_bytes(), source.len() as u64)
                .unwrap();
        }
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));

        assert_eq!(receipt.match_count, 6);
        for evidence in [
            "const HELP: &str = \"legacy_api\";",
            "let value = 1; // legacy_api();",
            "legacy_api();",
        ] {
            assert!(!refutation_evidence_is_grounded(
                &claim,
                &receipt,
                &"a".repeat(40),
                evidence,
            ));
        }
    }

    #[test]
    fn immutable_source_evidence_excludes_multiline_literals_and_non_code_values() {
        let absence = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["legacy_api".into()],
        };
        let mut source = SearchAccumulator::new(search_terms(std::iter::once(&absence)).unwrap());
        for (path, content) in [
            ("src/help.py", "HELP = \"\"\"\nlegacy_api();\n\"\"\"\n"),
            ("src/help.ts", "const help = `\nlegacy_api();\n`;\n"),
            (
                "src/help.rs",
                "const HELP: &str = \"first\nlegacy_api();\nlast\";\n",
            ),
            (
                "src/raw_help.rs",
                "const HELP: &str = r#\"text \" legacy_api();\"#;\n",
            ),
            ("scripts/help.ps1", "<#\nlegacy_api();\n#>\n"),
            (
                "config/help.yaml",
                "description: \"legacy_api: deprecated\"\n",
            ),
            (
                "config/block-help.yaml",
                "description: |\n  auth true\n  legacy_api();\nenabled: false\n",
            ),
            (
                "config/folded-help.yaml",
                "description: >-\n  auth true\n  legacy_api();\nenabled: false\n",
            ),
            (
                "config/quoted-help.yaml",
                "\"description: text\": |\n  auth true\n  legacy_api();\nenabled: false\n",
            ),
            (
                "config/anchored-help.yaml",
                "description: &help |\n  auth true\n  legacy_api();\nenabled: false\n",
            ),
            (
                "config/list-help.yaml",
                "descriptions:\n  - |\n    auth true\n    legacy_api();\nenabled: false\n",
            ),
        ] {
            source
                .scan_reader(path, &mut content.as_bytes(), content.len() as u64)
                .unwrap();
        }
        let source = source.complete(&"a".repeat(40), "b".repeat(64));
        assert!(!refutation_evidence_is_grounded(
            &absence,
            &source,
            &"a".repeat(40),
            "legacy_api();",
        ));

        let mismatch = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["auth".into()],
            values: vec!["true".into()],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        let mut help = SearchAccumulator::new(search_terms(std::iter::once(&mismatch)).unwrap());
        let content = "const HELP: &str = \"auth true\";\n";
        help.scan_reader("src/help.rs", &mut content.as_bytes(), content.len() as u64)
            .unwrap();
        let content = "description: \"auth true\"\n";
        help.scan_reader(
            "config/help.yaml",
            &mut content.as_bytes(),
            content.len() as u64,
        )
        .unwrap();
        let content = "description: |\n  auth true\nenabled: false\n";
        help.scan_reader(
            "config/block-help.yaml",
            &mut content.as_bytes(),
            content.len() as u64,
        )
        .unwrap();
        let content = "\"description: text\": &help |\n  auth true\nenabled: false\n";
        help.scan_reader(
            "config/anchored-help.yaml",
            &mut content.as_bytes(),
            content.len() as u64,
        )
        .unwrap();
        let help = help.complete(&"a".repeat(40), "b".repeat(64));
        assert!(!refutation_evidence_is_grounded(
            &mismatch,
            &help,
            &"a".repeat(40),
            "const HELP: &str = \"auth true\";",
        ));
    }

    #[test]
    fn immutable_evidence_matching_is_case_sensitive() {
        let identifier = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec![],
            identifiers: vec!["sendMail".into()],
        };
        let mut source =
            SearchAccumulator::new(search_terms(std::iter::once(&identifier)).unwrap());
        let content = "sendmail();\n";
        source
            .scan_reader("src/mail.rs", &mut content.as_bytes(), content.len() as u64)
            .unwrap();
        let source = source.complete(&"a".repeat(40), "b".repeat(64));
        assert!(!refutation_evidence_is_grounded(
            &identifier,
            &source,
            &"a".repeat(40),
            "sendmail();",
        ));

        let path = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec!["Config/Release.yaml".into()],
            identifiers: vec![],
        };
        let mut tree = SearchAccumulator::new(search_terms(std::iter::once(&path)).unwrap());
        tree.scan_path("config/release.yaml");
        let tree = tree.complete(&"a".repeat(40), "b".repeat(64));
        assert!(!refutation_evidence_is_grounded(
            &path,
            &tree,
            &"a".repeat(40),
            "config/release.yaml",
        ));
    }

    #[test]
    fn immutable_tree_path_entry_can_refute_a_false_path_absence_claim() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Absence,
            resources: vec![],
            values: vec![],
            versions: vec![],
            paths: vec!["config/release.yaml".into()],
            identifiers: vec![],
        };
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        search.scan_path("config/release.yaml");
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));

        assert!(refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "config/release.yaml",
        ));

        let mut suffix = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        suffix.scan_path("archive/config/release.yaml.bak");
        let suffix = suffix.complete(&"a".repeat(40), "b".repeat(64));
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &suffix,
            &"a".repeat(40),
            "archive/config/release.yaml.bak",
        ));
    }

    #[test]
    fn immutable_tree_evidence_uses_exact_values_and_boundaries() {
        let claim = RepositoryClaim {
            kind: RepositoryClaimKind::Mismatch,
            resources: vec!["auth".into()],
            values: vec!["true".into()],
            versions: vec![],
            paths: vec![],
            identifiers: vec![],
        };
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        let source = b"author: untrue\n";
        search
            .scan_reader("config.yml", &mut &source[..], source.len() as u64)
            .unwrap();
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));

        assert!(!refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "author: untrue",
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
    fn undeclared_repository_scope_paraphrases_are_suppressed() {
        let receipt = RepositorySearchReceipt {
            head_sha: Some("a".repeat(40)),
            state: RepositorySearchState::Complete,
            tree_sha256: Some("b".repeat(64)),
            ..RepositorySearchReceipt::default()
        };
        let bodies = [
            "No call sites invoke `legacy_api`; remove its export.",
            "`legacy_api` is never referenced anywhere; remove it.",
            "Only one import consumes `legacy_api`; keep that import compatible.",
            "Every registered handler still uses `legacy_api`; update the handlers.",
            "Nothing invokes `legacy_api`; remove it.",
            "`legacy_api` is not called anywhere; remove it.",
            "There are zero call sites for `legacy_api`; remove it.",
            "Nothing in code outside the compatibility package invokes `legacy_api`.",
            "Nobody invokes `legacy_api` outside compatibility.",
            "Not a single call site references `legacy_api`.",
            "There aren't any call sites for `legacy_api`.",
            "There aren’t any callers for `legacy_api`.",
            "`legacy_api` doesn't have any callers; remove it.",
            "No code path invokes `legacy_api`; remove it.",
        ];

        for body in bodies {
            let mut candidate = finding(claim("legacy_api"));
            candidate.repository_claim = None;
            candidate.body = body.into();
            let mut findings = vec![candidate];
            let suppressed = enforce_receipt(&mut findings, &receipt);
            assert_eq!(suppressed.len(), 1, "body: {body}");
            assert!(findings.is_empty(), "body: {body}");
        }
    }

    #[test]
    fn operational_no_verdict_prose_is_not_a_repository_claim() {
        let mut candidate = finding(claim("unused"));
        candidate.repository_claim = None;
        candidate.title = "Model output could not be validated".into();
        candidate.body = "Postil could not validate the configured model response against cited code evidence. No clean verdict was issued. Detail: model output remained unusable after its correction call.".into();

        assert!(!prose_requires_repository_search(&candidate));
    }

    #[test]
    fn local_quantifier_is_not_a_repository_claim() {
        let mut candidate = finding(claim("unused"));
        candidate.repository_claim = None;
        candidate.body = "This handler accepts any malformed token; reject it.".into();

        assert!(!prose_requires_repository_search(&candidate));

        candidate.body =
            "This handler does not match the route parameter's case; normalize both values.".into();
        assert!(!prose_requires_repository_search(&candidate));

        candidate.body =
            "This handler never returns after lock acquisition; restore the early return.".into();
        assert!(!prose_requires_repository_search(&candidate));

        candidate.body = "This handler only updates the cache while holding the mutex; move the update outside the critical section.".into();
        assert!(!prose_requires_repository_search(&candidate));

        candidate.body =
            "This handler accepts only signed routes; reject unsigned route identifiers.".into();
        assert!(!prose_requires_repository_search(&candidate));

        candidate.body = "This parameter is unused; remove it.".into();
        assert!(!prose_requires_repository_search(&candidate));
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

    #[test]
    fn repository_source_evidence_is_globally_bounded_and_fails_closed() {
        let claim = claim("present");
        let mut search = SearchAccumulator::new(search_terms(std::iter::once(&claim)).unwrap());
        for index in 0..128 {
            let source = format!("let present_{index} = present;\n");
            search
                .scan_reader(
                    &format!("generated/configuration-{index}.rs"),
                    &mut source.as_bytes(),
                    source.len() as u64,
                )
                .unwrap();
        }
        let receipt = search.complete(&"a".repeat(40), "b".repeat(64));

        assert!(receipt.evidence_truncated);
        assert!(
            receipt
                .evidence
                .iter()
                .map(|entry| repository_evidence_size(
                    &entry.path,
                    &entry.source,
                    &entry.query_sha256
                ))
                .sum::<usize>()
                <= MAX_REPOSITORY_EVIDENCE_BYTES
        );
        assert!(!refutation_evidence_is_grounded(
            &claim,
            &receipt,
            &"a".repeat(40),
            "let present_0 = present;",
        ));
        let public_receipt = serde_json::to_value(&receipt).unwrap();
        assert!(public_receipt.get("evidence").is_none());
        assert!(public_receipt.get("evidenceTruncated").is_none());
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
