//! Deterministic, no-execution verification for narrowly typed source claims.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Attribute, FnArg, GenericArgument, Item, PathArguments, ReturnType, Token, Type};

use crate::envelope::{
    ClaimEvidenceRole, ClaimVerificationEvidence, ClaimVerificationReceipt, ClaimVerificationState,
    ClaimVerificationVerdict, MachineClaim, MachineClaimKind, MachineReceiver, MachineSignature,
    VerifiedMachineClaim,
};
use crate::repository_search::RepositorySource;

pub(crate) const VERIFIER_VERSION: &str = "postil-source-v1";
pub(crate) const MAX_CLAIMS: usize = 20;
pub(crate) const MAX_SOURCE_FILES: usize = 128;
pub(crate) const MAX_SOURCE_FILE_BYTES: usize = 512 * 1024;
pub(crate) const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TREE_ENTRIES: usize = 20_000;
pub(crate) const MAX_EVIDENCE_PER_CLAIM: usize = 4;
pub(crate) const MAX_SYNTAX_NODES: usize = 200_000;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_SYMBOL_BYTES: usize = 512;
const MAX_SIGNATURE_PARAMETERS: usize = 16;
const MAX_SIGNATURE_TYPE_BYTES: usize = 256;
const MAX_SIGNATURE_TOTAL_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct MachineSourceFile {
    pub(crate) path: String,
    pub(crate) source: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MachineSourceSnapshot {
    pub(crate) head_sha: String,
    pub(crate) tree_sha256: String,
    pub(crate) files: Vec<MachineSourceFile>,
}

pub(crate) async fn verify(
    source: &RepositorySource<'_>,
    head_sha: Option<&str>,
    findings: impl Iterator<Item = &crate::envelope::Finding>,
) -> Option<ClaimVerificationReceipt> {
    let mut claims = findings
        .filter_map(|finding| finding.machine_claim.as_ref())
        .cloned()
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    claims.retain(|claim| seen.insert(claim_input_sha256(claim)));
    if claims.is_empty() {
        return None;
    }
    let Some(head_sha) = head_sha.filter(|value| !value.is_empty()) else {
        return Some(unavailable_receipt(None, &claims));
    };
    if claims.len() > MAX_CLAIMS || !crate::repository_search::valid_full_object_id(head_sha) {
        return Some(exhausted_receipt(Some(head_sha), &claims));
    }
    match source {
        RepositorySource::GitHub(github) => Some(
            github
                .verify_machine_claims_at_head(head_sha, &claims)
                .await,
        ),
        // A moving worktree is not exact-head evidence. Local review remains
        // fail-closed until immutable object reads can be performed without a
        // subprocess or build-capable repository helper.
        RepositorySource::Local(_) | RepositorySource::Unavailable => {
            Some(unavailable_receipt(Some(head_sha), &claims))
        }
    }
}

pub(crate) fn claim_is_valid(claim: &MachineClaim) -> bool {
    normalize_claim(claim).is_some()
}

pub(crate) fn regular_rust_source_entry(path: &str, mode: &str) -> bool {
    matches!(mode, "100644" | "100755") && valid_rust_path(path) && module_for_path(path).is_some()
}

pub(crate) fn receipt_verdict(
    receipt: Option<&ClaimVerificationReceipt>,
    claim: &MachineClaim,
    expected_head_sha: Option<&str>,
) -> Option<ClaimVerificationVerdict> {
    let receipt = receipt?;
    let expected_head_sha = expected_head_sha?;
    if receipt.verifier != VERIFIER_VERSION
        || receipt.state != ClaimVerificationState::Complete
        || receipt.head_sha.as_deref() != Some(expected_head_sha)
        || !crate::repository_search::valid_full_object_id(expected_head_sha)
        || !receipt.tree_sha256.as_deref().is_some_and(valid_sha256)
        || receipt.claims.len() > MAX_CLAIMS
        || receipt.claims.iter().any(|proof| {
            !valid_sha256(&proof.claim_input_sha256)
                || proof.evidence.len() > MAX_EVIDENCE_PER_CLAIM
                || proof.evidence.iter().any(|evidence| {
                    !valid_sha256(&evidence.path_sha256)
                        || !valid_sha256(&evidence.source_sha256)
                        || !valid_sha256(&evidence.span_sha256)
                })
        })
        || serde_json::to_vec(receipt)
            .map_or(true, |serialized| serialized.len() > MAX_RECEIPT_BYTES)
    {
        return None;
    }
    let input = claim_input_sha256(claim);
    let mut matches = receipt
        .claims
        .iter()
        .filter(|proof| proof.claim_input_sha256 == input);
    let first = matches.next()?;
    matches.next().is_none().then_some(first.verdict)
}

pub(crate) fn verify_snapshot(
    snapshot: MachineSourceSnapshot,
    claims: &[MachineClaim],
) -> ClaimVerificationReceipt {
    if claims.len() > MAX_CLAIMS
        || snapshot.files.len() > MAX_SOURCE_FILES
        || !crate::repository_search::valid_full_object_id(&snapshot.head_sha)
        || !valid_sha256(&snapshot.tree_sha256)
    {
        return exhausted_receipt(Some(&snapshot.head_sha), claims);
    }
    let mut source_bytes = 0usize;
    let mut seen_paths = BTreeSet::new();
    for file in &snapshot.files {
        source_bytes = match source_bytes.checked_add(file.source.len()) {
            Some(total) => total,
            None => return exhausted_receipt(Some(&snapshot.head_sha), claims),
        };
        if file.source.len() > MAX_SOURCE_FILE_BYTES
            || source_bytes > MAX_SOURCE_BYTES
            || !valid_rust_path(&file.path)
            || !seen_paths.insert(file.path.as_str())
        {
            return exhausted_receipt(Some(&snapshot.head_sha), claims);
        }
    }

    let Some(repository) = ParsedRepository::parse(&snapshot.files) else {
        return exhausted_receipt(Some(&snapshot.head_sha), claims);
    };
    let fallback_head_sha = snapshot.head_sha.clone();
    let verified = claims
        .iter()
        .map(|claim| repository.verify(claim, &snapshot.tree_sha256))
        .collect::<Vec<_>>();
    bounded_receipt(ClaimVerificationReceipt {
        verifier: VERIFIER_VERSION.to_string(),
        head_sha: Some(snapshot.head_sha),
        tree_sha256: Some(snapshot.tree_sha256),
        state: ClaimVerificationState::Complete,
        claims: verified,
    })
    .unwrap_or_else(|| exhausted_receipt(Some(&fallback_head_sha), claims))
}

pub(crate) fn unavailable_receipt(
    head_sha: Option<&str>,
    claims: &[MachineClaim],
) -> ClaimVerificationReceipt {
    state_receipt(ClaimVerificationState::Unavailable, head_sha, claims)
}

pub(crate) fn exhausted_receipt(
    head_sha: Option<&str>,
    claims: &[MachineClaim],
) -> ClaimVerificationReceipt {
    state_receipt(ClaimVerificationState::Exhausted, head_sha, claims)
}

fn state_receipt(
    state: ClaimVerificationState,
    head_sha: Option<&str>,
    claims: &[MachineClaim],
) -> ClaimVerificationReceipt {
    let claims = claims
        .iter()
        .take(MAX_CLAIMS)
        .map(|claim| VerifiedMachineClaim {
            claim_input_sha256: claim_input_sha256(claim),
            verdict: ClaimVerificationVerdict::Unresolved,
            evidence: Vec::new(),
        })
        .collect();
    ClaimVerificationReceipt {
        verifier: VERIFIER_VERSION.to_string(),
        head_sha: head_sha
            .filter(|value| crate::repository_search::valid_full_object_id(value))
            .map(|value| value.to_ascii_lowercase()),
        tree_sha256: None,
        state,
        claims,
    }
}

fn bounded_receipt(receipt: ClaimVerificationReceipt) -> Option<ClaimVerificationReceipt> {
    (serde_json::to_vec(&receipt).ok()?.len() <= MAX_RECEIPT_BYTES).then_some(receipt)
}

#[derive(Debug, Clone)]
struct NormalizedClaim {
    kind: MachineClaimKind,
    path: String,
    symbol: String,
    expected_signature: Option<MachineSignature>,
}

fn normalize_claim(claim: &MachineClaim) -> Option<NormalizedClaim> {
    let path = claim.path.trim();
    let symbol = claim.symbol.trim();
    if path != claim.path
        || symbol != claim.symbol
        || path.len() > MAX_PATH_BYTES
        || symbol.len() > MAX_SYMBOL_BYTES
        || !valid_rust_path(path)
        || !valid_qualified_symbol(symbol)
    {
        return None;
    }
    let module = module_for_path(path)?;
    if symbol != module && !symbol.starts_with(&format!("{module}::")) {
        return None;
    }
    let expected_signature = match claim.kind {
        MachineClaimKind::SignatureMismatch => {
            Some(normalize_signature(claim.expected_signature.as_ref()?)?)
        }
        MachineClaimKind::RustCopyMoveOut | MachineClaimKind::SymbolAbsent => {
            if claim.expected_signature.is_some() {
                return None;
            }
            None
        }
    };
    Some(NormalizedClaim {
        kind: claim.kind,
        path: path.to_string(),
        symbol: symbol.to_string(),
        expected_signature,
    })
}

fn normalize_signature(signature: &MachineSignature) -> Option<MachineSignature> {
    if signature.parameters.len() > MAX_SIGNATURE_PARAMETERS {
        return None;
    }
    let mut total = signature.returns.len();
    let mut parameters = Vec::with_capacity(signature.parameters.len());
    for parameter in &signature.parameters {
        total = total.checked_add(parameter.len())?;
        if parameter.len() > MAX_SIGNATURE_TYPE_BYTES || total > MAX_SIGNATURE_TOTAL_BYTES {
            return None;
        }
        parameters.push(canonical_type(&syn::parse_str::<Type>(parameter).ok()?)?);
    }
    if signature.returns.len() > MAX_SIGNATURE_TYPE_BYTES || total > MAX_SIGNATURE_TOTAL_BYTES {
        return None;
    }
    let returns = canonical_type(&syn::parse_str::<Type>(&signature.returns).ok()?)?;
    Some(MachineSignature {
        receiver: signature.receiver,
        parameters,
        returns,
        is_async: signature.is_async,
        is_unsafe: signature.is_unsafe,
    })
}

fn claim_input_sha256(claim: &MachineClaim) -> String {
    let bytes = normalize_claim(claim)
        .and_then(|claim| serde_json::to_vec(&CanonicalClaim::from(claim)).ok())
        .or_else(|| serde_json::to_vec(claim).ok())
        .unwrap_or_default();
    sha256_hex(&bytes)
}

pub(crate) fn claim_identity_sha256(claim: &MachineClaim) -> String {
    claim_input_sha256(claim)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalClaim {
    kind: MachineClaimKind,
    path: String,
    symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_signature: Option<MachineSignature>,
}

impl From<NormalizedClaim> for CanonicalClaim {
    fn from(claim: NormalizedClaim) -> Self {
        Self {
            kind: claim.kind,
            path: claim.path,
            symbol: claim.symbol,
            expected_signature: claim.expected_signature,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    DataType,
    Callable,
    Other,
}

#[derive(Debug, Clone)]
struct SymbolRecord {
    symbol: String,
    path: String,
    source_sha256: String,
    fingerprint: String,
    kind: SymbolKind,
    signature: Option<MachineSignature>,
    copy_derive_present: bool,
    conditional: bool,
    generic: bool,
}

impl SymbolRecord {
    fn evidence(&self, role: ClaimEvidenceRole) -> ClaimVerificationEvidence {
        let role_text = format!("{role:?}");
        ClaimVerificationEvidence {
            role,
            path_sha256: sha256_hex(self.path.as_bytes()),
            source_sha256: self.source_sha256.clone(),
            span_sha256: sha256_hex(
                format!(
                    "{}\0{}\0{}\0{}",
                    self.path, self.symbol, role_text, self.fingerprint
                )
                .as_bytes(),
            ),
        }
    }
}

struct SyntaxWorkBudget {
    remaining: usize,
    exhausted: bool,
}

impl SyntaxWorkBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    fn consume(&mut self) -> bool {
        if self.remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        true
    }
}

impl<'ast> Visit<'ast> for SyntaxWorkBudget {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if self.consume() {
            syn::visit::visit_attribute(self, node);
        }
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if self.consume() {
            syn::visit::visit_expr(self, node);
        }
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        if self.consume() {
            syn::visit::visit_impl_item(self, node);
        }
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if self.consume() {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        if self.consume() {
            syn::visit::visit_trait_item(self, node);
        }
    }

    fn visit_type(&mut self, node: &'ast Type) {
        if self.consume() {
            syn::visit::visit_type(self, node);
        }
    }
}

#[derive(Default)]
struct ParsedRepository {
    symbols: BTreeMap<String, Vec<SymbolRecord>>,
    copy_implementations: BTreeMap<String, Vec<SymbolRecord>>,
    possibly_aliased_copy_implementations: BTreeSet<String>,
    ambiguous_trait_impl_names: BTreeSet<String>,
    trait_implementation_targets: Vec<String>,
    trait_implementation_target_incomplete: bool,
    macro_modules: BTreeSet<String>,
    uncertain_namespace_modules: BTreeSet<String>,
    parse_incomplete: bool,
    proven_modules: BTreeSet<String>,
    source_scopes: BTreeMap<String, SymbolRecord>,
    module_sources: BTreeMap<String, Vec<String>>,
    reachable_paths: BTreeMap<String, String>,
    module_declarations: BTreeSet<String>,
}

struct ParsedSourceFile {
    source_sha256: String,
    source_len: usize,
    parsed: Option<syn::File>,
}

impl ParsedRepository {
    fn parse(files: &[MachineSourceFile]) -> Option<Self> {
        let mut repository = Self::default();
        let mut syntax_work = SyntaxWorkBudget::new(MAX_SYNTAX_NODES);
        let mut parsed_files = BTreeMap::new();
        for file in files {
            parsed_files.insert(
                file.path.clone(),
                ParsedSourceFile {
                    source_sha256: sha256_hex(file.source.as_bytes()),
                    source_len: file.source.len(),
                    parsed: syn::parse_file(&file.source).ok(),
                },
            );
        }

        let roots = ["src/lib.rs", "src/main.rs"]
            .into_iter()
            .filter(|path| parsed_files.contains_key(*path))
            .collect::<Vec<_>>();
        if roots.len() != 1 {
            repository.parse_incomplete = true;
            return Some(repository);
        }
        repository.collect_reachable_file(
            roots[0],
            "crate",
            "src",
            &parsed_files,
            &mut syntax_work,
        );
        if syntax_work.exhausted {
            return None;
        }
        Some(repository)
    }

    fn collect_reachable_file(
        &mut self,
        path: &str,
        module: &str,
        child_directory: &str,
        files: &BTreeMap<String, ParsedSourceFile>,
        syntax_work: &mut SyntaxWorkBudget,
    ) {
        if let Some(existing_module) = self.reachable_paths.get(path) {
            if existing_module != module {
                self.parse_incomplete = true;
            }
            return;
        }
        if self
            .module_sources
            .get(module)
            .is_some_and(|paths| !paths.is_empty())
        {
            self.parse_incomplete = true;
            return;
        }
        let Some(file) = files.get(path) else {
            self.parse_incomplete = true;
            return;
        };
        self.reachable_paths
            .insert(path.to_string(), module.to_string());
        self.module_sources
            .insert(module.to_string(), vec![path.to_string()]);
        self.proven_modules.insert(module.to_string());
        self.source_scopes.insert(
            path.to_string(),
            SymbolRecord {
                symbol: module.to_string(),
                path: path.to_string(),
                source_sha256: file.source_sha256.clone(),
                fingerprint: format!("source:{}", file.source_len),
                kind: SymbolKind::Other,
                signature: None,
                copy_derive_present: false,
                conditional: false,
                generic: false,
            },
        );
        let Some(parsed) = file.parsed.as_ref() else {
            self.parse_incomplete = true;
            return;
        };
        syntax_work.visit_file(parsed);
        if syntax_work.exhausted {
            return;
        }
        if attrs_are_conditional_or_expansive(&parsed.attrs) {
            self.parse_incomplete = true;
            return;
        }
        self.collect_items(&parsed.items, module, path, &file.source_sha256, false);
        self.collect_module_graph(
            &parsed.items,
            module,
            path,
            child_directory,
            files,
            syntax_work,
        );
    }

    fn collect_module_graph(
        &mut self,
        items: &[Item],
        module: &str,
        source_path: &str,
        child_directory: &str,
        files: &BTreeMap<String, ParsedSourceFile>,
        syntax_work: &mut SyntaxWorkBudget,
    ) {
        for item in items {
            let Item::Mod(item) = item else {
                continue;
            };
            let child_module = qualified(module, &item.ident);
            if !self.module_declarations.insert(child_module.clone()) {
                self.parse_incomplete = true;
                continue;
            }
            if module_mapping_is_uncertain(&item.attrs) {
                self.parse_incomplete = true;
                continue;
            }
            let child_directory = format!("{child_directory}/{}", item.ident);
            if let Some((_, inline_items)) = &item.content {
                self.proven_modules.insert(child_module.clone());
                self.module_sources
                    .insert(child_module.clone(), vec![source_path.to_string()]);
                self.collect_module_graph(
                    inline_items,
                    &child_module,
                    source_path,
                    &child_directory,
                    files,
                    syntax_work,
                );
                continue;
            }

            let flat_path = format!("{child_directory}.rs");
            let directory_path = format!("{child_directory}/mod.rs");
            let candidates = [flat_path.as_str(), directory_path.as_str()]
                .into_iter()
                .filter(|path| files.contains_key(*path))
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                self.parse_incomplete = true;
                continue;
            }
            self.collect_reachable_file(
                candidates[0],
                &child_module,
                &child_directory,
                files,
                syntax_work,
            );
        }
    }

    fn collect_items(
        &mut self,
        items: &[Item],
        module: &str,
        path: &str,
        source_sha256: &str,
        inherited_conditional: bool,
    ) {
        for item in items {
            if item_attrs_can_expand_siblings(item) {
                self.uncertain_namespace_modules.insert(module.to_string());
            }
            match item {
                Item::Struct(item) => self.record_type(
                    module,
                    &item.ident,
                    &item.attrs,
                    !item.generics.params.is_empty(),
                    "struct",
                    path,
                    source_sha256,
                    inherited_conditional,
                ),
                Item::Enum(item) => self.record_type(
                    module,
                    &item.ident,
                    &item.attrs,
                    !item.generics.params.is_empty(),
                    "enum",
                    path,
                    source_sha256,
                    inherited_conditional,
                ),
                Item::Union(item) => self.record_type(
                    module,
                    &item.ident,
                    &item.attrs,
                    !item.generics.params.is_empty(),
                    "union",
                    path,
                    source_sha256,
                    inherited_conditional,
                ),
                Item::Type(item) => self.record_named(
                    qualified(module, &item.ident),
                    path,
                    source_sha256,
                    "type",
                    SymbolKind::Other,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::Fn(item) => self.record_callable(
                    qualified(module, &item.sig.ident),
                    &item.sig,
                    &item.attrs,
                    path,
                    source_sha256,
                    inherited_conditional,
                ),
                Item::Const(item) => self.record_named(
                    qualified(module, &item.ident),
                    path,
                    source_sha256,
                    "const",
                    SymbolKind::Other,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::Static(item) => self.record_named(
                    qualified(module, &item.ident),
                    path,
                    source_sha256,
                    "static",
                    SymbolKind::Other,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::Trait(item) => {
                    let trait_symbol = qualified(module, &item.ident);
                    let conditional =
                        inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs);
                    self.record_named(
                        trait_symbol.clone(),
                        path,
                        source_sha256,
                        "trait",
                        SymbolKind::Other,
                        conditional,
                    );
                    for trait_item in &item.items {
                        match trait_item {
                            syn::TraitItem::Fn(method) => self.record_callable(
                                qualified(&trait_symbol, &method.sig.ident),
                                &method.sig,
                                &method.attrs,
                                path,
                                source_sha256,
                                conditional,
                            ),
                            syn::TraitItem::Const(item) => self.record_named(
                                qualified(&trait_symbol, &item.ident),
                                path,
                                source_sha256,
                                "trait-const",
                                SymbolKind::Other,
                                conditional || attrs_are_conditional_or_expansive(&item.attrs),
                            ),
                            syn::TraitItem::Type(item) => self.record_named(
                                qualified(&trait_symbol, &item.ident),
                                path,
                                source_sha256,
                                "trait-type",
                                SymbolKind::Other,
                                conditional || attrs_are_conditional_or_expansive(&item.attrs),
                            ),
                            syn::TraitItem::Macro(_) => {
                                self.macro_modules.insert(trait_symbol.clone());
                            }
                            syn::TraitItem::Verbatim(_) => self.parse_incomplete = true,
                            _ => {}
                        }
                    }
                }
                Item::TraitAlias(item) => self.record_named(
                    qualified(module, &item.ident),
                    path,
                    source_sha256,
                    "trait-alias",
                    SymbolKind::Other,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::Mod(item) => {
                    let symbol = qualified(module, &item.ident);
                    let conditional =
                        inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs);
                    self.record_named(
                        symbol.clone(),
                        path,
                        source_sha256,
                        "module",
                        SymbolKind::Other,
                        conditional,
                    );
                    if let Some((_, items)) = &item.content {
                        self.collect_items(items, &symbol, path, source_sha256, conditional);
                    }
                }
                Item::Impl(item) => {
                    if item.trait_.is_some()
                        && let Some(name) = unqualified_type_name(item.self_ty.as_ref())
                    {
                        self.ambiguous_trait_impl_names.insert(name);
                    }
                    let Some(target) = resolve_type_path(module, item.self_ty.as_ref()) else {
                        if item.trait_.is_some() {
                            self.trait_implementation_target_incomplete = true;
                        }
                        continue;
                    };
                    if item.trait_.is_some() {
                        self.trait_implementation_targets.push(target.clone());
                    }
                    let conditional = inherited_conditional
                        || attrs_are_conditional_or_expansive(&item.attrs)
                        || !item.generics.params.is_empty();
                    if let Some((_, trait_path, _)) = item.trait_.as_ref()
                        && path_is_explicit_copy_trait(trait_path)
                    {
                        self.copy_implementations
                            .entry(target.clone())
                            .or_default()
                            .push(SymbolRecord {
                                symbol: target.clone(),
                                path: path.to_string(),
                                source_sha256: source_sha256.to_string(),
                                fingerprint: format!("impl-copy:{target}"),
                                kind: SymbolKind::DataType,
                                signature: None,
                                copy_derive_present: false,
                                conditional,
                                generic: !item.generics.params.is_empty(),
                            });
                    } else if item.trait_.is_some() {
                        // Without name resolution, any other trait path can be
                        // an import or re-export alias for `Copy`.
                        self.possibly_aliased_copy_implementations
                            .insert(target.clone());
                    }
                    for impl_item in &item.items {
                        match impl_item {
                            syn::ImplItem::Fn(method) => self.record_callable(
                                qualified(&target, &method.sig.ident),
                                &method.sig,
                                &method.attrs,
                                path,
                                source_sha256,
                                conditional,
                            ),
                            syn::ImplItem::Const(item) => self.record_named(
                                qualified(&target, &item.ident),
                                path,
                                source_sha256,
                                "impl-const",
                                SymbolKind::Other,
                                conditional || attrs_are_conditional_or_expansive(&item.attrs),
                            ),
                            syn::ImplItem::Type(item) => self.record_named(
                                qualified(&target, &item.ident),
                                path,
                                source_sha256,
                                "impl-type",
                                SymbolKind::Other,
                                conditional || attrs_are_conditional_or_expansive(&item.attrs),
                            ),
                            syn::ImplItem::Macro(_) => {
                                self.macro_modules.insert(target.clone());
                            }
                            syn::ImplItem::Verbatim(_) => self.parse_incomplete = true,
                            _ => {}
                        }
                    }
                }
                Item::Use(item) => self.record_use_tree(
                    module,
                    &item.tree,
                    &[],
                    path,
                    source_sha256,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::ExternCrate(item) => self.record_named(
                    qualified(
                        module,
                        item.rename
                            .as_ref()
                            .map_or(&item.ident, |(_, rename)| rename),
                    ),
                    path,
                    source_sha256,
                    "extern-crate",
                    SymbolKind::Other,
                    inherited_conditional || attrs_are_conditional_or_expansive(&item.attrs),
                ),
                Item::Macro(item) => {
                    if let Some(ident) = item.ident.as_ref() {
                        self.record_named(
                            qualified(module, ident),
                            path,
                            source_sha256,
                            "macro",
                            SymbolKind::Other,
                            inherited_conditional
                                || attrs_are_conditional_or_expansive(&item.attrs),
                        );
                    } else {
                        self.macro_modules.insert(module.to_string());
                    }
                }
                Item::ForeignMod(_) => {
                    self.uncertain_namespace_modules.insert(module.to_string());
                }
                Item::Verbatim(_) => self.parse_incomplete = true,
                _ => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_type(
        &mut self,
        module: &str,
        ident: &syn::Ident,
        attrs: &[Attribute],
        generic: bool,
        item_kind: &str,
        path: &str,
        source_sha256: &str,
        inherited_conditional: bool,
    ) {
        let symbol = qualified(module, ident);
        let copy_derive_present = derives_copy(attrs);
        self.symbols
            .entry(symbol.clone())
            .or_default()
            .push(SymbolRecord {
                symbol,
                path: path.to_string(),
                source_sha256: source_sha256.to_string(),
                fingerprint: format!(
                    "{item_kind}:{}:copy-derive={copy_derive_present}:generic={generic}",
                    ident
                ),
                kind: SymbolKind::DataType,
                signature: None,
                copy_derive_present,
                conditional: inherited_conditional || attrs_are_conditional_or_expansive(attrs),
                generic,
            });
    }

    fn record_named(
        &mut self,
        symbol: String,
        path: &str,
        source_sha256: &str,
        item_kind: &str,
        kind: SymbolKind,
        conditional: bool,
    ) {
        self.symbols
            .entry(symbol.clone())
            .or_default()
            .push(SymbolRecord {
                fingerprint: format!("{item_kind}:{symbol}"),
                symbol,
                path: path.to_string(),
                source_sha256: source_sha256.to_string(),
                kind,
                signature: None,
                copy_derive_present: false,
                conditional,
                generic: false,
            });
    }

    fn record_callable(
        &mut self,
        symbol: String,
        signature: &syn::Signature,
        attrs: &[Attribute],
        path: &str,
        source_sha256: &str,
        inherited_conditional: bool,
    ) {
        let normalized = canonical_signature(signature);
        self.symbols
            .entry(symbol.clone())
            .or_default()
            .push(SymbolRecord {
                fingerprint: normalized
                    .as_ref()
                    .and_then(|value| serde_json::to_string(value).ok())
                    .unwrap_or_else(|| format!("unsupported-signature:{symbol}")),
                symbol,
                path: path.to_string(),
                source_sha256: source_sha256.to_string(),
                kind: SymbolKind::Callable,
                signature: normalized,
                copy_derive_present: false,
                conditional: inherited_conditional || attrs_are_conditional_or_expansive(attrs),
                generic: !signature.generics.params.is_empty(),
            });
    }

    #[allow(clippy::too_many_arguments)]
    fn record_use_tree(
        &mut self,
        module: &str,
        tree: &syn::UseTree,
        prefix: &[String],
        path: &str,
        source_sha256: &str,
        conditional: bool,
    ) {
        match tree {
            syn::UseTree::Path(value) => {
                let mut nested_prefix = prefix.to_vec();
                nested_prefix.push(value.ident.to_string());
                self.record_use_tree(
                    module,
                    value.tree.as_ref(),
                    &nested_prefix,
                    path,
                    source_sha256,
                    conditional,
                );
            }
            syn::UseTree::Name(value) => {
                let local = if value.ident == "self" {
                    prefix.last().cloned()
                } else {
                    Some(value.ident.to_string())
                };
                if let Some(local) = local {
                    self.record_named(
                        format!("{module}::{local}"),
                        path,
                        source_sha256,
                        "use",
                        SymbolKind::Other,
                        conditional,
                    );
                }
            }
            syn::UseTree::Rename(value) => self.record_named(
                qualified(module, &value.rename),
                path,
                source_sha256,
                "use-rename",
                SymbolKind::Other,
                conditional,
            ),
            syn::UseTree::Glob(_) => {
                self.uncertain_namespace_modules.insert(module.to_string());
            }
            syn::UseTree::Group(value) => {
                for item in &value.items {
                    self.record_use_tree(module, item, prefix, path, source_sha256, conditional);
                }
            }
        }
    }

    fn verify(&self, claim: &MachineClaim, tree_sha256: &str) -> VerifiedMachineClaim {
        let hash = claim_input_sha256(claim);
        let Some(claim) = normalize_claim(claim) else {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        };
        if self.parse_incomplete {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        if !self.claim_scope_is_unique(&claim) {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        }
        match claim.kind {
            MachineClaimKind::RustCopyMoveOut => self.verify_copy_move_out(hash, &claim),
            MachineClaimKind::SymbolAbsent => self.verify_symbol_absent(hash, &claim, tree_sha256),
            MachineClaimKind::SignatureMismatch => self.verify_signature(hash, &claim),
        }
    }

    fn verify_copy_move_out(&self, hash: String, claim: &NormalizedClaim) -> VerifiedMachineClaim {
        let candidates = self
            .symbols
            .get(&claim.symbol)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if candidates.len() != 1 || candidates[0].path != claim.path {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        }
        let candidate = &candidates[0];
        if candidate.kind != SymbolKind::DataType
            || candidate.conditional
            || candidate.generic
            || self.symbol_has_conditional_ancestor(&claim.symbol)
        {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        if candidate.copy_derive_present {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        let implementations = self
            .copy_implementations
            .get(&claim.symbol)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if implementations.len() == 1
            && !implementations[0].conditional
            && !implementations[0].generic
        {
            return proof(
                hash,
                ClaimVerificationVerdict::Refuted,
                vec![implementations[0].evidence(ClaimEvidenceRole::CopyImplementation)],
            );
        }
        if implementations.len() > 1 {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        }
        if implementations.len() == 1
            || self
                .possibly_aliased_copy_implementations
                .contains(&claim.symbol)
            || claim
                .symbol
                .rsplit("::")
                .next()
                .is_some_and(|name| self.ambiguous_trait_impl_names.contains(name))
            || self.trait_implementation_target_may_be_an_alias()
            || !self.macro_modules.is_empty()
        {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        proof(
            hash,
            ClaimVerificationVerdict::Supported,
            vec![candidate.evidence(ClaimEvidenceRole::SymbolDefinition)],
        )
    }

    fn verify_symbol_absent(
        &self,
        hash: String,
        claim: &NormalizedClaim,
        tree_sha256: &str,
    ) -> VerifiedMachineClaim {
        let candidates = self
            .symbols
            .get(&claim.symbol)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if candidates.len() == 1 && candidates[0].path == claim.path && !candidates[0].conditional {
            return proof(
                hash,
                ClaimVerificationVerdict::Refuted,
                vec![candidates[0].evidence(ClaimEvidenceRole::SymbolDefinition)],
            );
        }
        if !candidates.is_empty() {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        }
        let target_module = claim
            .symbol
            .rsplit_once("::")
            .map_or("crate", |(module, _)| module);
        if !self.proven_modules.contains(target_module)
            || !self
                .module_sources
                .get(target_module)
                .is_some_and(|paths| paths.as_slice() == [claim.path.as_str()])
            || self.symbol_has_conditional_ancestor(&claim.symbol)
            || self.namespace_is_uncertain(target_module)
            || self.macro_modules.iter().any(|module| {
                target_module == module || target_module.starts_with(&format!("{module}::"))
            })
        {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        let Some(scope) = self.source_scopes.get(&claim.path) else {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        };
        let mut evidence = scope.evidence(ClaimEvidenceRole::SourceScope);
        evidence.span_sha256 = sha256_hex(
            format!(
                "{}\0{}\0{}",
                evidence.span_sha256, claim.symbol, tree_sha256
            )
            .as_bytes(),
        );
        proof(hash, ClaimVerificationVerdict::Supported, vec![evidence])
    }

    fn verify_signature(&self, hash: String, claim: &NormalizedClaim) -> VerifiedMachineClaim {
        let candidates = self
            .symbols
            .get(&claim.symbol)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if candidates.len() != 1 || candidates[0].path != claim.path {
            return proof(hash, ClaimVerificationVerdict::Unresolved, Vec::new());
        }
        let candidate = &candidates[0];
        if candidate.kind != SymbolKind::Callable
            || candidate.conditional
            || candidate.generic
            || candidate.signature.is_none()
            || self.parse_incomplete
            || self.symbol_has_conditional_ancestor(&claim.symbol)
            || self.namespace_is_uncertain(&claim.symbol)
            || !self.macro_modules.is_empty()
        {
            return proof(hash, ClaimVerificationVerdict::Unsupported, Vec::new());
        }
        let verdict = if candidate.signature.as_ref() == claim.expected_signature.as_ref() {
            ClaimVerificationVerdict::Refuted
        } else {
            ClaimVerificationVerdict::Supported
        };
        proof(
            hash,
            verdict,
            vec![candidate.evidence(ClaimEvidenceRole::Signature)],
        )
    }

    fn symbol_has_conditional_ancestor(&self, symbol: &str) -> bool {
        let segments = symbol.split("::").collect::<Vec<_>>();
        (2..segments.len()).any(|length| {
            self.symbols
                .get(&segments[..length].join("::"))
                .is_some_and(|records| records.iter().any(|record| record.conditional))
        })
    }

    fn namespace_is_uncertain(&self, symbol_or_module: &str) -> bool {
        let segments = symbol_or_module.split("::").collect::<Vec<_>>();
        (1..=segments.len()).any(|length| {
            self.uncertain_namespace_modules
                .contains(&segments[..length].join("::"))
        })
    }

    fn claim_scope_is_unique(&self, claim: &NormalizedClaim) -> bool {
        let Some(module) = module_for_path(&claim.path) else {
            return false;
        };
        self.module_sources
            .get(&module)
            .is_some_and(|paths| paths.as_slice() == [claim.path.as_str()])
    }

    fn trait_implementation_target_may_be_an_alias(&self) -> bool {
        self.trait_implementation_target_incomplete
            || self.trait_implementation_targets.iter().any(|target| {
                !self.symbols.get(target).is_some_and(|records| {
                    records.len() == 1 && records[0].kind == SymbolKind::DataType
                })
            })
    }
}

fn proof(
    claim_input_sha256: String,
    verdict: ClaimVerificationVerdict,
    mut evidence: Vec<ClaimVerificationEvidence>,
) -> VerifiedMachineClaim {
    evidence.truncate(MAX_EVIDENCE_PER_CLAIM);
    VerifiedMachineClaim {
        claim_input_sha256,
        verdict,
        evidence,
    }
}

fn canonical_signature(signature: &syn::Signature) -> Option<MachineSignature> {
    if signature.constness.is_some()
        || signature.abi.is_some()
        || signature.variadic.is_some()
        || !signature.generics.params.is_empty()
        || signature.generics.where_clause.is_some()
        || signature.inputs.len() > MAX_SIGNATURE_PARAMETERS + 1
    {
        return None;
    }
    let mut receiver = MachineReceiver::None;
    let mut parameters = Vec::new();
    for argument in &signature.inputs {
        match argument {
            FnArg::Receiver(value) => {
                if receiver != MachineReceiver::None
                    || value.colon_token.is_some()
                    || value
                        .reference
                        .as_ref()
                        .is_some_and(|(_, lifetime)| lifetime.is_some())
                {
                    return None;
                }
                receiver = match (value.reference.is_some(), value.mutability.is_some()) {
                    (true, false) => MachineReceiver::Shared,
                    (true, true) => MachineReceiver::Mutable,
                    (false, _) => MachineReceiver::Value,
                };
            }
            FnArg::Typed(value) => parameters.push(canonical_type(value.ty.as_ref())?),
        }
    }
    let returns = match &signature.output {
        ReturnType::Default => "()".to_string(),
        ReturnType::Type(_, value) => canonical_type(value.as_ref())?,
    };
    Some(MachineSignature {
        receiver,
        parameters,
        returns,
        is_async: signature.asyncness.is_some(),
        is_unsafe: signature.unsafety.is_some(),
    })
}

fn canonical_type(value: &Type) -> Option<String> {
    match value {
        Type::Path(value) if value.qself.is_none() => {
            if !resolution_free_type_path(&value.path) {
                return None;
            }
            let mut output = value
                .path
                .leading_colon
                .map(|_| "::")
                .unwrap_or_default()
                .to_string();
            for (index, segment) in value.path.segments.iter().enumerate() {
                if index > 0 {
                    output.push_str("::");
                }
                output.push_str(&segment.ident.to_string());
                match &segment.arguments {
                    PathArguments::None => {}
                    PathArguments::AngleBracketed(arguments) => {
                        let mut types = Vec::new();
                        for argument in &arguments.args {
                            match argument {
                                GenericArgument::Type(value) => types.push(canonical_type(value)?),
                                _ => return None,
                            }
                        }
                        output.push('<');
                        output.push_str(&types.join(","));
                        output.push('>');
                    }
                    PathArguments::Parenthesized(_) => return None,
                }
            }
            Some(output)
        }
        Type::Reference(value) if value.lifetime.is_none() => {
            let mut output = if value.mutability.is_some() {
                "&mut "
            } else {
                "&"
            }
            .to_string();
            output.push_str(&canonical_type(value.elem.as_ref())?);
            Some(output)
        }
        Type::Tuple(value) => Some(format!(
            "({}{})",
            value
                .elems
                .iter()
                .map(canonical_type)
                .collect::<Option<Vec<_>>>()?
                .join(","),
            if value.elems.len() == 1 { "," } else { "" }
        )),
        Type::Slice(value) => Some(format!("[{}]", canonical_type(value.elem.as_ref())?)),
        Type::Paren(value) => canonical_type(value.elem.as_ref()),
        Type::Group(value) => canonical_type(value.elem.as_ref()),
        Type::Never(_) => Some("!".to_string()),
        _ => None,
    }
}

fn resolution_free_type_path(path: &syn::Path) -> bool {
    let mut segments = path.segments.iter();
    let Some(first) = segments.next() else {
        return false;
    };
    let remaining = segments.count();
    if remaining == 0 {
        return path.leading_colon.is_none()
            && matches!(first.arguments, PathArguments::None)
            && matches!(
                first.ident.to_string().as_str(),
                "bool"
                    | "char"
                    | "str"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "f32"
                    | "f64"
            );
    }
    matches!(first.arguments, PathArguments::None)
        && matches!(first.ident.to_string().as_str(), "crate" | "std" | "core")
        && (path.leading_colon.is_none() || first.ident != "crate")
}

fn derives_copy(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        attribute.path().is_ident("derive")
            && attribute
                .parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
                .is_ok_and(|paths| paths.iter().any(path_names_copy_derive))
    })
}

fn attrs_are_conditional_or_expansive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        let path = attribute.path();
        !(path.is_ident("doc")
            || (path.is_ident("derive") && derive_uses_only_builtin_macros(attribute))
            || path.is_ident("allow")
            || path.is_ident("warn")
            || path.is_ident("deny")
            || path.is_ident("forbid")
            || path.is_ident("must_use")
            || path.is_ident("non_exhaustive")
            || path.is_ident("repr")
            || path.is_ident("cold")
            || path.is_ident("inline")
            || path.is_ident("track_caller"))
    })
}

fn module_mapping_is_uncertain(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        let path = attribute.path();
        path.is_ident("path")
            || path.is_ident("cfg")
            || path.is_ident("cfg_attr")
            || attrs_are_conditional_or_expansive(std::slice::from_ref(attribute))
    })
}

fn item_attrs_can_expand_siblings(item: &Item) -> bool {
    let attrs = match item {
        Item::Const(value) => &value.attrs,
        Item::Enum(value) => &value.attrs,
        Item::ExternCrate(value) => &value.attrs,
        Item::Fn(value) => &value.attrs,
        Item::ForeignMod(value) => &value.attrs,
        Item::Impl(value) => &value.attrs,
        Item::Macro(value) => &value.attrs,
        Item::Mod(value) => &value.attrs,
        Item::Static(value) => &value.attrs,
        Item::Struct(value) => &value.attrs,
        Item::Trait(value) => &value.attrs,
        Item::TraitAlias(value) => &value.attrs,
        Item::Type(value) => &value.attrs,
        Item::Union(value) => &value.attrs,
        Item::Use(value) => &value.attrs,
        Item::Verbatim(_) => return false,
        _ => return false,
    };
    attrs.iter().any(|attribute| {
        let path = attribute.path();
        if path.is_ident("derive") {
            return !derive_uses_only_builtin_macros(attribute);
        }
        !(path.is_ident("cfg")
            || path.is_ident("doc")
            || path.is_ident("allow")
            || path.is_ident("warn")
            || path.is_ident("deny")
            || path.is_ident("forbid")
            || path.is_ident("must_use")
            || path.is_ident("non_exhaustive")
            || path.is_ident("repr")
            || path.is_ident("cold")
            || path.is_ident("inline")
            || path.is_ident("track_caller")
            || path.is_ident("deprecated")
            || path.is_ident("test")
            || path.is_ident("ignore")
            || path.is_ident("should_panic"))
    })
}

fn derive_uses_only_builtin_macros(attribute: &Attribute) -> bool {
    attribute
        .parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
        .is_ok_and(|paths| {
            paths.iter().all(|path| {
                let mut segments = path.segments.iter();
                let Some(name) = segments.next().map(|segment| segment.ident.to_string()) else {
                    return false;
                };
                segments.next().is_none()
                    && matches!(
                        name.as_str(),
                        "Clone"
                            | "Copy"
                            | "Debug"
                            | "Default"
                            | "Eq"
                            | "Hash"
                            | "Ord"
                            | "PartialEq"
                            | "PartialOrd"
                    )
            })
        })
}

fn path_names_copy_derive(path: &syn::Path) -> bool {
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [copy] if copy == "Copy")
        || matches!(segments.as_slice(), [root, marker, copy]
            if matches!(root.as_str(), "std" | "core") && marker == "marker" && copy == "Copy")
}

fn path_is_explicit_copy_trait(path: &syn::Path) -> bool {
    if path.leading_colon.is_none()
        || path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return false;
    }
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [root, marker, copy]
        if matches!(root.as_str(), "std" | "core") && marker == "marker" && copy == "Copy")
}

fn resolve_type_path(module: &str, value: &Type) -> Option<String> {
    let Type::Path(value) = value else {
        return None;
    };
    if value.qself.is_some()
        || value
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return None;
    }
    let segments = value
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let first = segments.first()?.as_str();
    match first {
        "crate" => Some(segments.join("::")),
        "self" => Some(
            std::iter::once(module.to_string())
                .chain(segments.into_iter().skip(1))
                .collect::<Vec<_>>()
                .join("::"),
        ),
        "super" => {
            let mut module_segments = module.split("::").map(str::to_string).collect::<Vec<_>>();
            let mut consumed = 0usize;
            while segments
                .get(consumed)
                .is_some_and(|segment| segment == "super")
            {
                if module_segments.len() <= 1 {
                    return None;
                }
                module_segments.pop();
                consumed += 1;
            }
            module_segments.extend(segments.into_iter().skip(consumed));
            Some(module_segments.join("::"))
        }
        _ => Some(format!("{module}::{}", segments.join("::"))),
    }
}

fn unqualified_type_name(value: &Type) -> Option<String> {
    let Type::Path(value) = value else {
        return None;
    };
    if value.qself.is_some()
        || value.path.leading_colon.is_some()
        || value.path.segments.len() != 1
        || !matches!(value.path.segments[0].arguments, PathArguments::None)
    {
        return None;
    }
    Some(value.path.segments[0].ident.to_string())
}

fn module_for_path(path: &str) -> Option<String> {
    if path == "src/lib.rs" || path == "src/main.rs" {
        return Some("crate".to_string());
    }
    let rest = path.strip_prefix("src/")?.strip_suffix(".rs")?;
    if rest.starts_with("bin/") || rest == "bin" {
        return None;
    }
    let rest = rest.strip_suffix("/mod").unwrap_or(rest);
    if rest.is_empty() || rest.split('/').any(|segment| !valid_identifier(segment)) {
        return None;
    }
    Some(format!("crate::{}", rest.replace('/', "::")))
}

fn qualified(module: &str, ident: &syn::Ident) -> String {
    format!("{module}::{ident}")
}

fn valid_rust_path(path: &str) -> bool {
    path.ends_with(".rs")
        && path.len() <= MAX_PATH_BYTES
        && crate::forge::valid_repository_path(path)
}

fn valid_qualified_symbol(symbol: &str) -> bool {
    let mut segments = symbol.split("::");
    segments.next() == Some("crate")
        && segments.clone().count() >= 1
        && segments.all(valid_identifier)
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: MachineClaimKind, symbol: &str) -> MachineClaim {
        MachineClaim {
            kind,
            path: "src/identity.rs".into(),
            symbol: symbol.into(),
            expected_signature: None,
        }
    }

    fn snapshot(source: &str) -> MachineSourceSnapshot {
        MachineSourceSnapshot {
            head_sha: "a".repeat(40),
            tree_sha256: "b".repeat(64),
            files: vec![
                MachineSourceFile {
                    path: "src/lib.rs".into(),
                    source: "mod identity;\n".into(),
                },
                MachineSourceFile {
                    path: "src/identity.rs".into(),
                    source: source.into(),
                },
            ],
        }
    }

    #[test]
    fn copy_derive_is_not_conclusive_without_semantic_proof() {
        let receipt = verify_snapshot(
            snapshot("#[derive(Debug, Clone, Copy)]\npub struct IdentityFailure(String);\n"),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(receipt.state, ClaimVerificationState::Complete);
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
        assert!(receipt.claims[0].evidence.is_empty());
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("IdentityFailure(String)"));
    }

    #[test]
    fn concrete_copy_derive_remains_unsupported_without_semantic_proof() {
        let receipt = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod llm;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/llm.rs".into(),
                        source: include_str!("llm.rs").into(),
                    },
                ],
            },
            &[MachineClaim {
                kind: MachineClaimKind::RustCopyMoveOut,
                path: "src/llm.rs".into(),
                symbol: "crate::llm::AtomicAttributionIdentityFailure".into(),
                expected_signature: None,
            }],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn non_copy_type_supports_move_out_claim() {
        let receipt = verify_snapshot(
            snapshot("pub enum IdentityFailure { Missing }\n"),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Supported
        );
    }

    #[test]
    fn manual_copy_impl_refutes_but_aliasable_trait_impl_is_unsupported() {
        let source = "pub struct IdentityFailure;\nimpl ::core::marker::Copy for IdentityFailure {}\nimpl Clone for IdentityFailure { fn clone(&self) -> Self { *self } }\n";
        let receipt = verify_snapshot(
            snapshot(source),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(receipt.claims[0].verdict, ClaimVerificationVerdict::Refuted);
        assert_eq!(
            receipt.claims[0].evidence[0].role,
            ClaimEvidenceRole::CopyImplementation
        );

        let aliasable = verify_snapshot(
            snapshot("pub struct IdentityFailure;\nimpl MaybeCopy for IdentityFailure {}\n"),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            aliasable.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let custom_derive = verify_snapshot(
            snapshot("#[derive(External)] pub struct IdentityFailure;\n"),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            custom_derive.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn imported_copy_impl_cannot_support_a_move_out_claim() {
        let receipt = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod identity;\nmod other;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct Failure;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/other.rs".into(),
                        source: "use crate::identity::Failure;\nimpl Copy for Failure {}\nimpl Clone for Failure { fn clone(&self) -> Self { *self } }\n".into(),
                    },
                ],
            },
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::Failure",
            )],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let renamed_alias = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod identity;\nmod other;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct Failure;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/other.rs".into(),
                        source: "use crate::identity::Failure as Alias;\nimpl ::core::marker::Copy for Alias {}\n".into(),
                    },
                ],
            },
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::Failure",
            )],
        );
        assert_eq!(
            renamed_alias.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn bare_or_shadowed_copy_traits_never_refute() {
        for source in [
            "pub trait Copy {}\npub struct IdentityFailure;\nimpl Copy for IdentityFailure {}\n",
            "mod traits { pub trait Copy {} }\nuse traits::Copy;\npub struct IdentityFailure;\nimpl Copy for IdentityFailure {}\n",
            "mod core { pub mod marker { pub trait Copy {} } }\npub struct IdentityFailure;\nimpl core::marker::Copy for IdentityFailure {}\n",
        ] {
            let receipt = verify_snapshot(
                snapshot(source),
                &[claim(
                    MachineClaimKind::RustCopyMoveOut,
                    "crate::identity::IdentityFailure",
                )],
            );
            assert_eq!(
                receipt.claims[0].verdict,
                ClaimVerificationVerdict::Unsupported
            );
            assert!(receipt.claims[0].evidence.is_empty());
        }
    }

    #[test]
    fn ambiguous_symbols_are_unresolved() {
        let receipt = verify_snapshot(
            snapshot(
                "#[cfg(a)] pub struct IdentityFailure;\n#[cfg(b)] pub struct IdentityFailure;\n",
            ),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unresolved
        );

        let duplicate_module = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod identity;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity/mod.rs".into(),
                        source: String::new(),
                    },
                ],
            },
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            duplicate_module.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn macro_generated_symbols_are_unsupported() {
        let receipt = verify_snapshot(
            snapshot("make_identity_failure!();\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let imported = verify_snapshot(
            snapshot("pub use crate::other::IdentityFailure;\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            imported.claims[0].verdict,
            ClaimVerificationVerdict::Refuted
        );

        let glob = verify_snapshot(
            snapshot("pub use crate::other::*;\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            glob.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let sibling_attribute = verify_snapshot(
            snapshot("#[external] pub struct Source;\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            sibling_attribute.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let sibling_derive = verify_snapshot(
            snapshot("#[derive(External)] pub struct Source;\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            sibling_derive.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let conditional_sibling_attribute = verify_snapshot(
            snapshot("#[cfg_attr(feature = \"generated\", external)] pub struct Source;\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            conditional_sibling_attribute.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn absence_is_supported_only_under_a_proven_module_namespace() {
        let claims = [
            claim(MachineClaimKind::SymbolAbsent, "crate::identity::Missing"),
            claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::State::Ready",
            ),
            claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::Record::value",
            ),
            claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::Unknown::Missing",
            ),
        ];
        let receipt = verify_snapshot(
            snapshot("pub enum State { Ready }\npub struct Record { value: usize }\n"),
            &claims,
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Supported
        );
        for proof in &receipt.claims[1..] {
            assert!(matches!(
                proof.verdict,
                ClaimVerificationVerdict::Unsupported | ClaimVerificationVerdict::Unresolved
            ));
        }
    }

    #[test]
    fn only_unambiguously_reachable_modules_contribute_proofs() {
        let source_claim = claim(
            MachineClaimKind::RustCopyMoveOut,
            "crate::identity::IdentityFailure",
        );
        let orphan = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: String::new(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                ],
            },
            std::slice::from_ref(&source_claim),
        );
        assert_eq!(
            orphan.claims[0].verdict,
            ClaimVerificationVerdict::Unresolved
        );

        let nested_claim = MachineClaim {
            kind: MachineClaimKind::RustCopyMoveOut,
            path: "src/outer/nested.rs".into(),
            symbol: "crate::outer::nested::IdentityFailure".into(),
            expected_signature: None,
        };
        let reachable = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod outer;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/outer.rs".into(),
                        source: "mod nested;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/outer/nested.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                ],
            },
            &[nested_claim],
        );
        assert_eq!(
            reachable.claims[0].verdict,
            ClaimVerificationVerdict::Supported
        );

        for root_source in [
            "#[path = \"identity.rs\"] mod identity;\n",
            "#[cfg(feature = \"identity\")] mod identity;\n",
        ] {
            let uncertain = verify_snapshot(
                MachineSourceSnapshot {
                    head_sha: "a".repeat(40),
                    tree_sha256: "b".repeat(64),
                    files: vec![
                        MachineSourceFile {
                            path: "src/lib.rs".into(),
                            source: root_source.into(),
                        },
                        MachineSourceFile {
                            path: "src/identity.rs".into(),
                            source: "pub struct IdentityFailure;\n".into(),
                        },
                    ],
                },
                std::slice::from_ref(&source_claim),
            );
            assert!(matches!(
                uncertain.claims[0].verdict,
                ClaimVerificationVerdict::Unsupported | ClaimVerificationVerdict::Unresolved
            ));
        }

        for crate_attribute in [
            "#![cfg(feature = \"identity\")]\n",
            "#![cfg_attr(feature = \"minimal\", no_std)]\n",
        ] {
            let root_source = format!("{crate_attribute}mod identity;\n");
            let conditional_crate = MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: root_source,
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                ],
            };
            let claims = [
                source_claim.clone(),
                claim(MachineClaimKind::SymbolAbsent, "crate::identity::Missing"),
            ];
            let uncertain = verify_snapshot(conditional_crate, &claims);
            assert!(uncertain.claims.iter().all(|proof| matches!(
                proof.verdict,
                ClaimVerificationVerdict::Unsupported | ClaimVerificationVerdict::Unresolved
            )));
        }

        let duplicate_roots = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod identity;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/main.rs".into(),
                        source: "mod identity;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                ],
            },
            &[source_claim],
        );
        assert!(matches!(
            duplicate_roots.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported | ClaimVerificationVerdict::Unresolved
        ));
    }

    #[test]
    fn conditional_parent_modules_make_nested_symbols_unsupported() {
        let mut nested_claim = claim(
            MachineClaimKind::RustCopyMoveOut,
            "crate::identity::conditional::IdentityFailure",
        );
        let receipt = verify_snapshot(
            snapshot(
                "#[cfg(feature = \"conditional\")] mod conditional { pub struct IdentityFailure; }\n",
            ),
            std::slice::from_ref(&nested_claim),
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let external_module_claim = claim(
            MachineClaimKind::RustCopyMoveOut,
            "crate::identity::IdentityFailure",
        );
        let receipt = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "#[cfg(feature = \"identity\")] mod identity;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub struct IdentityFailure;\n".into(),
                    },
                ],
            },
            &[external_module_claim],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        nested_claim.kind = MachineClaimKind::SignatureMismatch;
        nested_claim.symbol = "crate::identity::conditional::IdentityFailure::check".into();
        nested_claim.expected_signature = Some(MachineSignature {
            receiver: MachineReceiver::Shared,
            parameters: Vec::new(),
            returns: "bool".into(),
            is_async: false,
            is_unsafe: false,
        });
        let receipt = verify_snapshot(
            snapshot(
                "#[cfg(feature = \"conditional\")] mod conditional { pub struct IdentityFailure; impl IdentityFailure { pub fn check(&self) -> bool { true } } }\n",
            ),
            &[nested_claim],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn malformed_source_is_unsupported_and_symlinks_are_rejected() {
        let receipt = verify_snapshot(
            snapshot("pub struct Broken {\n"),
            &[claim(
                MachineClaimKind::SymbolAbsent,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
        assert!(regular_rust_source_entry("src/identity.rs", "100644"));
        assert!(!regular_rust_source_entry("src/identity.rs", "120000"));
        assert!(!regular_rust_source_entry("src/*.rs", "100644"));
    }

    #[test]
    fn signature_claims_use_the_bounded_type_grammar() {
        let mut mismatch = claim(
            MachineClaimKind::SignatureMismatch,
            "crate::identity::IdentityFailure::reason",
        );
        mismatch.expected_signature = Some(MachineSignature {
            receiver: MachineReceiver::Shared,
            parameters: vec!["&str".into()],
            returns: "bool".into(),
            is_async: false,
            is_unsafe: false,
        });
        let source = "pub struct IdentityFailure;\nimpl IdentityFailure { pub fn reason(&self, value: &str) -> bool { !value.is_empty() } }\n";
        let matching = verify_snapshot(snapshot(source), &[mismatch.clone()]);
        assert_eq!(
            matching.claims[0].verdict,
            ClaimVerificationVerdict::Refuted
        );
        mismatch.expected_signature.as_mut().unwrap().returns = "usize".into();
        let different = verify_snapshot(snapshot(source), &[mismatch]);
        assert_eq!(
            different.claims[0].verdict,
            ClaimVerificationVerdict::Supported
        );

        let mut aliased = claim(
            MachineClaimKind::SignatureMismatch,
            "crate::identity::aliased",
        );
        aliased.expected_signature = Some(MachineSignature {
            receiver: MachineReceiver::None,
            parameters: Vec::new(),
            returns: "crate::types::Expected".into(),
            is_async: false,
            is_unsafe: false,
        });
        let alias = verify_snapshot(
            snapshot(
                "use crate::types::Expected as Actual;\npub fn aliased() -> Actual { todo!() }\n",
            ),
            &[aliased.clone()],
        );
        assert_eq!(
            alias.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let parse_incomplete = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files: vec![
                    MachineSourceFile {
                        path: "src/lib.rs".into(),
                        source: "mod identity;\nmod broken;\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/identity.rs".into(),
                        source: "pub fn aliased() -> crate::types::Actual { todo!() }\n".into(),
                    },
                    MachineSourceFile {
                        path: "src/broken.rs".into(),
                        source: "pub struct Broken {\n".into(),
                    },
                ],
            },
            &[aliased],
        );
        assert_eq!(
            parse_incomplete.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn invalid_signature_syntax_is_unsupported() {
        let mut mismatch = claim(
            MachineClaimKind::SignatureMismatch,
            "crate::identity::reason",
        );
        mismatch.expected_signature = Some(MachineSignature {
            receiver: MachineReceiver::None,
            parameters: vec!["impl Display".into()],
            returns: "bool".into(),
            is_async: false,
            is_unsafe: false,
        });
        let receipt = verify_snapshot(
            snapshot("pub fn reason(value: impl std::fmt::Display) -> bool { true }\n"),
            &[mismatch],
        );
        assert_eq!(
            receipt.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );

        let alias = verify_snapshot(
            snapshot("pub type IdentityFailure = u8;\n"),
            &[claim(
                MachineClaimKind::RustCopyMoveOut,
                "crate::identity::IdentityFailure",
            )],
        );
        assert_eq!(
            alias.claims[0].verdict,
            ClaimVerificationVerdict::Unsupported
        );
    }

    #[test]
    fn missing_source_is_unavailable_and_stale_receipts_are_ignored() {
        let source_claim = claim(
            MachineClaimKind::RustCopyMoveOut,
            "crate::identity::IdentityFailure",
        );
        let unavailable =
            unavailable_receipt(Some(&"a".repeat(40)), std::slice::from_ref(&source_claim));
        assert_eq!(unavailable.state, ClaimVerificationState::Unavailable);
        assert_eq!(
            receipt_verdict(Some(&unavailable), &source_claim, Some(&"a".repeat(40))),
            None
        );

        let complete = verify_snapshot(
            snapshot("#[derive(Copy, Clone)] pub struct IdentityFailure;\n"),
            std::slice::from_ref(&source_claim),
        );
        assert_eq!(
            receipt_verdict(Some(&complete), &source_claim, Some(&"c".repeat(40))),
            None
        );
    }

    #[test]
    fn source_and_claim_bounds_fail_closed() {
        let claims = (0..=MAX_CLAIMS)
            .map(|index| {
                claim(
                    MachineClaimKind::SymbolAbsent,
                    &format!("crate::identity::Missing{index}"),
                )
            })
            .collect::<Vec<_>>();
        let receipt = verify_snapshot(snapshot("pub struct Present;\n"), &claims);
        assert_eq!(receipt.state, ClaimVerificationState::Exhausted);

        let files = (0..=MAX_SOURCE_FILES)
            .map(|index| MachineSourceFile {
                path: format!("src/module_{index}.rs"),
                source: String::new(),
            })
            .collect();
        let receipt = verify_snapshot(
            MachineSourceSnapshot {
                head_sha: "a".repeat(40),
                tree_sha256: "b".repeat(64),
                files,
            },
            &[],
        );
        assert_eq!(receipt.state, ClaimVerificationState::Exhausted);
    }

    #[test]
    fn syntax_work_and_receipt_cardinality_fail_closed() {
        let parsed = syn::parse_file("pub fn one() -> bool { true }\n").unwrap();
        let mut syntax_work = SyntaxWorkBudget::new(1);
        syntax_work.visit_file(&parsed);
        assert!(syntax_work.exhausted);

        let source_claim = claim(
            MachineClaimKind::RustCopyMoveOut,
            "crate::identity::IdentityFailure",
        );
        let mut receipt = verify_snapshot(
            snapshot("#[derive(Copy, Clone)] pub struct IdentityFailure;\n"),
            std::slice::from_ref(&source_claim),
        );
        receipt.claims.push(receipt.claims[0].clone());
        assert_eq!(
            receipt_verdict(Some(&receipt), &source_claim, Some(&"a".repeat(40))),
            None
        );

        let invalid_head = "a".repeat(MAX_RECEIPT_BYTES + 1);
        let bounded = exhausted_receipt(Some(&invalid_head), &[source_claim]);
        assert!(bounded.head_sha.is_none());
        assert!(serde_json::to_vec(&bounded).unwrap().len() <= MAX_RECEIPT_BYTES);
    }
}
