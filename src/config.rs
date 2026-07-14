//! Resolved review configuration.
//!
//! Precedence: CLI flags > environment > `.postil.{yaml,yml,json}` >
//! `.coderabbit.yaml` (translated) > defaults.
//!
//! Exception: `model.apiBase` from a config file is repo-controlled, and the
//! resolved base URL receives the deployment's bearer key. It is ignored by
//! default and honored only when `POSTIL_ALLOW_CONFIG_API_BASE=1` (single-user
//! local setups with a trusted repo). `POSTIL_API_BASE` (env) always applies.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::envelope::{Kind, Severity};

const MODEL_DEFAULTS_TOML: &str = include_str!("../config.toml");
const QUALIFIED_MODELS_JSON: &str = include_str!("../qualified-models.json");
const REVIEW_CONTRACT_SOURCES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../Cargo.toml")),
    ("Cargo.lock", include_str!("../Cargo.lock")),
    ("src/api_key.rs", include_str!("api_key.rs")),
    ("src/cli.rs", include_str!("cli.rs")),
    ("src/config.rs", include_str!("config.rs")),
    ("src/doctor.rs", include_str!("doctor.rs")),
    ("src/forge/azure.rs", include_str!("forge/azure.rs")),
    ("src/forge/bitbucket.rs", include_str!("forge/bitbucket.rs")),
    ("src/forge/github.rs", include_str!("forge/github.rs")),
    ("src/forge/gitlab.rs", include_str!("forge/gitlab.rs")),
    ("src/forge/mod.rs", include_str!("forge/mod.rs")),
    ("src/hook.rs", include_str!("hook.rs")),
    ("src/lib.rs", include_str!("lib.rs")),
    ("src/local.rs", include_str!("local.rs")),
    ("src/main.rs", include_str!("main.rs")),
    ("src/output.rs", include_str!("output.rs")),
    ("src/plan.rs", include_str!("plan.rs")),
    ("src/prompt.rs", include_str!("prompt.rs")),
    ("src/llm.rs", include_str!("llm.rs")),
    ("src/envelope.rs", include_str!("envelope.rs")),
    ("src/respond.rs", include_str!("respond.rs")),
    ("src/review.rs", include_str!("review.rs")),
    ("src/sarif.rs", include_str!("sarif.rs")),
    ("src/diff.rs", include_str!("diff.rs")),
    ("src/filter.rs", include_str!("filter.rs")),
];
const BENCH_FIXTURES_SOURCE: &str = include_str!("../bench/fixtures/cases.ts");
const BENCH_PACKAGE_JSON: &str = include_str!("../bench/package.json");
const BENCH_BUN_LOCK: &str = include_str!("../bench/bun.lock");
const EVALUATOR_CONTRACT_SOURCES: &[(&str, &str)] = &[
    ("bench/package.json", BENCH_PACKAGE_JSON),
    ("bench/bun.lock", BENCH_BUN_LOCK),
    ("bench/fixtures/cases.ts", BENCH_FIXTURES_SOURCE),
    (
        "bench/src/api-key.ts",
        include_str!("../bench/src/api-key.ts"),
    ),
    (
        "bench/src/harness.ts",
        include_str!("../bench/src/harness.ts"),
    ),
    (
        "bench/src/livemodels-score.ts",
        include_str!("../bench/src/livemodels-score.ts"),
    ),
    (
        "bench/src/livemodels.ts",
        include_str!("../bench/src/livemodels.ts"),
    ),
    ("bench/src/run.ts", include_str!("../bench/src/run.ts")),
];
pub const DEFAULT_API_BASE: &str = "https://openrouter.ai/api/v1";
pub const MAX_FINDINGS: usize = 20;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApiFormat {
    #[default]
    OpenaiCompatible,
    Anthropic,
}

impl ApiFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai-compatible" => Ok(Self::OpenaiCompatible),
            "anthropic" => Ok(Self::Anthropic),
            _ => anyhow::bail!("invalid API format {value:?} (openai-compatible|anthropic)"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiCompatible => "openai-compatible",
            Self::Anthropic => "anthropic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDefaults {
    pub version: u64,
    pub source_sha256: String,
    pub default_model: String,
    pub cascade: Vec<String>,
    pub consensus: usize,
    pub api_base: String,
    pub api_format: ApiFormat,
    pub scorer_enabled: bool,
    pub scorer_model: String,
    pub scorer_fallback: String,
    pub scorer_qualification_candidates: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationManifest {
    pub version: u64,
    pub model_defaults_sha256: String,
    pub profiles: Vec<QualificationProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationProfile {
    pub id: String,
    pub api_format: ApiFormat,
    pub api_base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_provider_identity: Option<String>,
    pub generator_chain: Vec<String>,
    pub consensus: usize,
    pub scorer_chain: Vec<String>,
    pub review_contract_sha256: String,
    pub fixture_set_sha256: String,
    pub evaluator_contract_sha256: String,
    pub evaluator_runtime_identity: String,
    pub report_sha256: String,
    pub repeated_runs: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelDefaultsFile {
    version: u64,
    default_model: String,
    cascade: Vec<String>,
    consensus: usize,
    api_base: String,
    api_format: ApiFormat,
    scorer: ScorerDefaultsFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScorerDefaultsFile {
    enabled: bool,
    default_model: String,
    fallback: String,
    qualification_candidates: Vec<String>,
}

pub fn model_defaults() -> &'static ModelDefaults {
    static MODEL_DEFAULTS: OnceLock<ModelDefaults> = OnceLock::new();
    MODEL_DEFAULTS.get_or_init(|| {
        parse_model_defaults(MODEL_DEFAULTS_TOML).expect("embedded model defaults must parse")
    })
}

pub fn default_model() -> &'static str {
    model_defaults().default_model.as_str()
}

pub fn default_cascade() -> &'static [String] {
    model_defaults().cascade.as_slice()
}

pub fn default_scorer_model() -> &'static str {
    model_defaults().scorer_model.as_str()
}

pub fn default_scorer_fallback() -> &'static str {
    model_defaults().scorer_fallback.as_str()
}

pub fn scorer_qualification_candidates() -> &'static [String] {
    model_defaults().scorer_qualification_candidates.as_slice()
}

pub fn qualification_manifest() -> &'static QualificationManifest {
    static MANIFEST: OnceLock<QualificationManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        parse_qualification_manifest(QUALIFIED_MODELS_JSON)
            .expect("embedded qualification manifest must parse and match model defaults")
    })
}

pub fn review_contract_sha256() -> String {
    sha256_named_sources(REVIEW_CONTRACT_SOURCES)
}

pub fn fixture_set_sha256() -> String {
    sha256_named_sources(&[("bench/fixtures/cases.ts", BENCH_FIXTURES_SOURCE)])
}

pub fn evaluator_contract_sha256() -> String {
    sha256_named_sources(EVALUATOR_CONTRACT_SOURCES)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualificationMetadata {
    pub model_defaults_sha256: String,
    pub review_contract_sha256: String,
    pub fixture_set_sha256: String,
    pub evaluator_contract_sha256: String,
    pub evaluator_runtime_identity: String,
    pub default_api_base: String,
    pub default_api_format: ApiFormat,
    pub generator_chain: Vec<String>,
    pub consensus: usize,
    pub scorer_chain: Vec<String>,
    pub admitted_profile: Option<QualificationProfile>,
}

/// Immutable qualification inputs embedded in this exact binary.
pub fn qualification_metadata() -> QualificationMetadata {
    let defaults = model_defaults();
    let manifest = qualification_manifest();
    let admitted_profile = admitted_profile_for(defaults, manifest);
    let (generator_chain, scorer_chain, api_base) = qualification_defaults(defaults);
    QualificationMetadata {
        model_defaults_sha256: defaults.source_sha256.clone(),
        review_contract_sha256: review_contract_sha256(),
        fixture_set_sha256: fixture_set_sha256(),
        evaluator_contract_sha256: evaluator_contract_sha256(),
        evaluator_runtime_identity: evaluator_runtime_identity(),
        default_api_base: api_base,
        default_api_format: defaults.api_format,
        generator_chain,
        consensus: defaults.consensus,
        scorer_chain,
        admitted_profile,
    }
}

fn qualification_defaults(defaults: &ModelDefaults) -> (Vec<String>, Vec<String>, String) {
    let mut generator_chain = Vec::new();
    if !defaults.default_model.is_empty() {
        generator_chain.push(defaults.default_model.clone());
    }
    generator_chain.extend(defaults.cascade.clone());
    let mut scorer_chain = Vec::new();
    if defaults.scorer_enabled && !defaults.scorer_model.is_empty() {
        scorer_chain.push(defaults.scorer_model.clone());
        if !defaults.scorer_fallback.is_empty() && defaults.scorer_fallback != defaults.scorer_model
        {
            scorer_chain.push(defaults.scorer_fallback.clone());
        }
    }
    let api_base =
        normalize_api_base(&defaults.api_base).expect("embedded API base must be canonicalizable");
    (generator_chain, scorer_chain, api_base)
}

fn admitted_profile_for(
    defaults: &ModelDefaults,
    manifest: &QualificationManifest,
) -> Option<QualificationProfile> {
    let (generator_chain, scorer_chain, api_base) = qualification_defaults(defaults);
    manifest
        .profiles
        .iter()
        .find(|profile| {
            profile.generator_chain == generator_chain
                && profile.consensus == defaults.consensus
                && profile.scorer_chain == scorer_chain
                && profile.api_base == api_base
                && profile.api_format == defaults.api_format
        })
        .cloned()
}

fn evaluator_runtime_identity() -> String {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BenchPackage {
        package_manager: String,
    }
    let package: BenchPackage =
        serde_json::from_str(BENCH_PACKAGE_JSON).expect("bench package.json must parse");
    let version = package
        .package_manager
        .strip_prefix("bun@")
        .expect("bench packageManager must pin Bun");
    let parts = version.split('.').collect::<Vec<_>>();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "bench packageManager must pin an exact Bun runtime version"
    );
    package.package_manager
}

fn sha256_named_sources(sources: &[(&str, &str)]) -> String {
    let mut hasher = Sha256::new();
    for (path, contents) in sources {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(contents.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn parse_qualification_manifest(raw: &str) -> Result<QualificationManifest> {
    let manifest: QualificationManifest = serde_json::from_str(raw)?;
    anyhow::ensure!(
        manifest.version > 0,
        "qualification manifest version must be greater than zero"
    );
    anyhow::ensure!(
        manifest.model_defaults_sha256 == model_defaults().source_sha256,
        "qualification manifest does not match the embedded model defaults"
    );
    let mut profile_ids = Vec::with_capacity(manifest.profiles.len());
    let current_review_contract = review_contract_sha256();
    let current_fixture_set = fixture_set_sha256();
    let current_evaluator_contract = evaluator_contract_sha256();
    for profile in &manifest.profiles {
        anyhow::ensure!(
            !profile.id.trim().is_empty(),
            "qualification profile id must not be empty"
        );
        anyhow::ensure!(
            !profile.generator_chain.is_empty(),
            "qualification profile generator chain must not be empty"
        );
        anyhow::ensure!(
            !profile.scorer_chain.is_empty(),
            "qualification profile scorer chain must not be empty"
        );
        anyhow::ensure!(
            (1..=profile.generator_chain.len()).contains(&profile.consensus),
            "qualification profile consensus must fit its generator chain"
        );
        anyhow::ensure!(
            normalize_api_base(&profile.api_base)? == profile.api_base,
            "qualification profile apiBase must use its canonical form"
        );
        if let Some(provider) = profile.benchmark_provider_identity.as_deref() {
            anyhow::ensure!(
                !provider.trim().is_empty() && !provider.contains(['\n', '\r']),
                "qualification profile benchmark provider identity must be one line"
            );
        }
        for model in &profile.generator_chain {
            validate_model_id("qualification profile generator chain", model)?;
        }
        for model in &profile.scorer_chain {
            validate_model_id("qualification profile scorer chain", model)?;
        }
        anyhow::ensure!(
            profile.repeated_runs >= 3,
            "qualification profile must record at least three repeated runs"
        );
        for (field, digest) in [
            ("reviewContractSha256", &profile.review_contract_sha256),
            ("fixtureSetSha256", &profile.fixture_set_sha256),
            (
                "evaluatorContractSha256",
                &profile.evaluator_contract_sha256,
            ),
            ("reportSha256", &profile.report_sha256),
        ] {
            anyhow::ensure!(
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "qualification profile {field} must be a SHA-256 digest"
            );
        }
        anyhow::ensure!(
            profile.review_contract_sha256 == current_review_contract,
            "qualification profile review contract is stale"
        );
        anyhow::ensure!(
            profile.fixture_set_sha256 == current_fixture_set,
            "qualification profile fixture set is stale"
        );
        anyhow::ensure!(
            profile.evaluator_contract_sha256 == current_evaluator_contract,
            "qualification profile evaluator contract is stale"
        );
        anyhow::ensure!(
            profile.evaluator_runtime_identity == evaluator_runtime_identity(),
            "qualification profile evaluator runtime is stale"
        );
        let mut generators = profile.generator_chain.clone();
        generators.sort();
        generators.dedup();
        anyhow::ensure!(
            generators.len() == profile.generator_chain.len(),
            "qualification profile generator chain must not repeat models"
        );
        let mut scorers = profile.scorer_chain.clone();
        scorers.sort();
        scorers.dedup();
        anyhow::ensure!(
            scorers.len() == profile.scorer_chain.len(),
            "qualification profile scorer chain must not repeat models"
        );
        profile_ids.push(profile.id.clone());
    }
    profile_ids.sort();
    profile_ids.dedup();
    anyhow::ensure!(
        profile_ids.len() == manifest.profiles.len(),
        "qualification profile ids must be unique"
    );
    Ok(manifest)
}

fn parse_model_defaults(raw: &str) -> Result<ModelDefaults> {
    let file: ModelDefaultsFile = toml::from_str(raw)?;
    anyhow::ensure!(
        file.version > 0,
        "model defaults version must be greater than zero"
    );
    if !file.default_model.is_empty() {
        validate_model_id("defaultModel", &file.default_model)?;
    } else {
        anyhow::ensure!(
            file.cascade.is_empty(),
            "cascade must be empty when defaultModel is empty"
        );
    }
    for model in &file.cascade {
        validate_model_id("cascade entries", model)?;
    }
    let mut generator_chain = Vec::new();
    if !file.default_model.is_empty() {
        generator_chain.push(file.default_model.as_str());
    }
    generator_chain.extend(file.cascade.iter().map(String::as_str));
    let unique_generators = generator_chain
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    anyhow::ensure!(
        unique_generators.len() == generator_chain.len(),
        "embedded generator chain must not repeat models"
    );
    let generator_count = usize::from(!file.default_model.is_empty()) + file.cascade.len();
    if generator_count == 0 {
        anyhow::ensure!(
            file.consensus == 1,
            "empty model defaults require consensus = 1"
        );
    } else {
        anyhow::ensure!(
            (1..=generator_count).contains(&file.consensus),
            "consensus must fit the embedded generator chain"
        );
    }
    normalize_api_base(&file.api_base).context("invalid embedded model API base")?;
    if !file.scorer.default_model.is_empty() {
        validate_model_id("scorer.defaultModel", &file.scorer.default_model)?;
    } else {
        anyhow::ensure!(
            !file.scorer.enabled
                && file.scorer.fallback.is_empty()
                && file.scorer.qualification_candidates.is_empty(),
            "scorer configuration must be empty when scorer.defaultModel is empty"
        );
    }
    if !file.scorer.fallback.is_empty() {
        validate_model_id("scorer.fallback", &file.scorer.fallback)?;
        anyhow::ensure!(
            file.scorer.fallback != file.scorer.default_model,
            "scorer fallback must differ from scorer.defaultModel"
        );
    }
    for model in &file.scorer.qualification_candidates {
        validate_model_id("scorer.qualificationCandidates entries", model)?;
    }
    Ok(ModelDefaults {
        version: file.version,
        source_sha256: sha256_hex(raw),
        default_model: file.default_model,
        cascade: file.cascade,
        consensus: file.consensus,
        api_base: file.api_base,
        api_format: file.api_format,
        scorer_enabled: file.scorer.enabled,
        scorer_model: file.scorer.default_model,
        scorer_fallback: file.scorer.fallback,
        scorer_qualification_candidates: file.scorer.qualification_candidates,
    })
}

fn validate_model_id(field: &str, value: &str) -> Result<()> {
    anyhow::ensure!(!value.trim().is_empty(), "{field} must not be empty");
    anyhow::ensure!(
        !value.contains(['\n', '\r']),
        "{field} must not contain line breaks"
    );
    Ok(())
}

fn sha256_hex(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn yaml_scalar(value: &str) -> String {
    serde_yaml::to_string(value)
        .expect("model default scalar must serialize")
        .lines()
        .filter(|line| *line != "...")
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnClean {
    /// Complete the check-runs, post nothing. Silence is the product.
    Skip,
    /// Post a one-line confirmation comment.
    Comment,
}

/// What the gate does when the review cannot complete (model outage, rate-limit
/// exhaustion). Default is fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    /// Operational error fails the gate. Nothing merges on a broken review.
    Block,
    /// Provider outage passes the gate (advisory only): an outage does not
    /// freeze every merge in the org; the review check goes neutral. Unusable
    /// model output still blocks because that class is attacker-influenceable.
    Advisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateLevel {
    Severity(Severity),
    Never,
}

impl GateLevel {
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("never") {
            return Some(GateLevel::Never);
        }
        Severity::parse(s).map(GateLevel::Severity)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            GateLevel::Never => "never",
            GateLevel::Severity(s) => s.as_str(),
        }
    }

    pub fn fails(&self, sev: Severity) -> bool {
        match self {
            GateLevel::Never => false,
            GateLevel::Severity(threshold) => sev >= *threshold,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub ignore: Vec<String>,
    /// Findings strictly below this severity are suppressed.
    pub severity_threshold: Severity,
    /// Findings below this confidence are suppressed. The low-noise default.
    pub min_confidence: f64,
    pub max_findings: usize,
    pub tone: String,
    pub focus: Vec<String>,
    pub on_clean: OnClean,
    pub gate_fail_on: GateLevel,
    /// Gate behavior on operational error. Default: fail closed.
    pub gate_on_error: OnError,
    /// Finding kinds that block regardless of severity. Human escalations must
    /// also meet the calibrated 0.30 gate confidence floor. Default: [HumanEscalation].
    pub block_on_kinds: Vec<Kind>,
    pub model: String,
    pub cascade: Vec<String>,
    pub scorer: String,
    pub scorer_fallback: String,
    /// Embedded scoring remains disabled until a candidate passes the repeated
    /// qualification gate. BYOK can select a scorer and one fallback.
    pub scorer_enabled: bool,
    pub api_base: String,
    pub api_format: ApiFormat,
    /// Run the first N models of [model + cascade] and keep agreeing findings.
    pub consensus: usize,
    /// Contents of `.postil/guardrails.md`, injected into the prompt as repo
    /// rules. Findings that violate one are emitted as `kind: guardrail`.
    pub guardrails: Option<String>,
    /// Active content-policy rules (built-in baseline, optionally extended by
    /// `.postil/content-policy.md`), or `None` after an explicit opt-out.
    /// Findings are emitted as `kind: contentPolicy`. See [`load`](Self::load).
    pub content_policy: Option<String>,
    /// Set by an explicit `contentPolicy: { enabled: false }`, so a repo can
    /// opt out even when a `.postil/content-policy.md` file is present (e.g.
    /// inherited from a template).
    pub content_policy_disabled: bool,
    /// Where the config came from, for `postil config` provenance.
    pub source: String,
}

impl Default for Config {
    fn default() -> Self {
        let defaults = model_defaults();
        Config {
            enabled: true,
            ignore: Vec::new(),
            severity_threshold: Severity::Info,
            min_confidence: 0.6,
            max_findings: 20,
            tone: "concise, dry, lightly sardonic, never hostile; no praise or filler".to_string(),
            focus: Vec::new(),
            on_clean: OnClean::Skip,
            gate_fail_on: GateLevel::Severity(Severity::Error),
            gate_on_error: OnError::Block,
            block_on_kinds: vec![Kind::HumanEscalation],
            model: defaults.default_model.clone(),
            cascade: defaults.cascade.clone(),
            scorer: defaults.scorer_model.clone(),
            scorer_fallback: defaults.scorer_fallback.clone(),
            scorer_enabled: defaults.scorer_enabled,
            api_base: defaults.api_base.clone(),
            api_format: defaults.api_format,
            consensus: defaults.consensus,
            guardrails: None,
            content_policy: Some(BUILTIN_CONTENT_POLICY.to_string()),
            content_policy_disabled: false,
            source: "defaults".to_string(),
        }
    }
}

/// On-disk `.postil.yaml` shape. Everything optional; unknown keys rejected so
/// typos fail loudly instead of being silently ignored (the PR-Agent failure mode).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileConfig {
    pub enabled: Option<bool>,
    pub ignore: Option<Vec<String>>,
    pub severity_threshold: Option<String>,
    pub min_confidence: Option<f64>,
    pub max_findings: Option<usize>,
    pub reviewer: Option<ReviewerSection>,
    pub review: Option<ReviewSection>,
    pub gate: Option<GateSection>,
    pub model: Option<ModelSection>,
    pub content_policy: Option<ContentPolicySection>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewerSection {
    pub tone: Option<String>,
    pub focus: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewSection {
    pub on_clean: Option<OnClean>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateSection {
    pub fail_on: Option<String>,
    pub on_error: Option<OnError>,
    pub block_on_kinds: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelSection {
    pub name: Option<String>,
    pub cascade: Option<Vec<String>>,
    pub scorer: Option<String>,
    pub api_base: Option<String>,
    pub api_format: Option<ApiFormat>,
    pub consensus: Option<usize>,
}

/// Reviews prose in the diff (comments, docstrings, Markdown, PR title/body)
/// against a built-in content-policy baseline: fabricated or contradicted
/// documentation claims, self-contradictions the same PR creates, authoring-
/// process narration and AI-authorship residue, leaked conversation/transcript
/// text, and (low severity) stale temporal/TODO residue and house style.
/// On by default; `contentPolicy: { enabled: false }` fully disables it.
/// Findings are reported as `kind: contentPolicy`.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContentPolicySection {
    pub enabled: Option<bool>,
}

impl Config {
    /// Resolve config for a repo root. `explicit` (from --config) bypasses discovery.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Config> {
        let mut cfg = if let Some(path) = explicit {
            let mut c = Self::from_postil_file(path)
                .with_context(|| format!("reading config {}", path.display()))?;
            c.source = path.display().to_string();
            c
        } else if let Some(path) =
            find_first(root, &[".postil.yaml", ".postil.yml", ".postil.json"])
        {
            let mut c = Self::from_postil_file(&path)
                .with_context(|| format!("reading config {}", path.display()))?;
            c.source = rel_name(&path);
            c
        } else if let Some(path) = find_first(root, &[".coderabbit.yaml", ".coderabbit.yml"]) {
            let mut c = Self::from_coderabbit(&path)
                .with_context(|| format!("translating {}", path.display()))?;
            c.source = format!("{} (translated)", rel_name(&path));
            c
        } else {
            Config::default()
        };
        cfg.apply_env()?;
        // Repo guardrails are a separate file so they can be long-form prose.
        let guardrails_path = root.join(".postil").join("guardrails.md");
        if let Ok(text) = std::fs::read_to_string(&guardrails_path) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                cfg.guardrails = Some(trimmed.to_string());
            }
        }
        // Repo-specific content-policy rules extend the built-in baseline,
        // unless the repository explicitly opted out above.
        if !cfg.content_policy_disabled {
            let content_policy_path = root.join(".postil").join("content-policy.md");
            if let Ok(text) = std::fs::read_to_string(&content_policy_path) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    let mut rules = cfg
                        .content_policy
                        .take()
                        .unwrap_or_else(|| BUILTIN_CONTENT_POLICY.to_string());
                    rules.push_str("\n\n--- REPO-SPECIFIC ADDITIONS ---\n");
                    rules.push_str(trimmed);
                    cfg.content_policy = Some(rules);
                }
            }
        }
        Ok(cfg)
    }

    fn from_postil_file(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)?;
        let file: FileConfig = if path.extension().is_some_and(|e| e == "json") {
            serde_json::from_str(&raw)?
        } else {
            serde_yaml::from_str(&raw)?
        };
        let mut cfg = Config::default();
        cfg.apply_file(file)?;
        Ok(cfg)
    }

    pub fn apply_file(&mut self, f: FileConfig) -> Result<()> {
        self.apply_file_inner(f, allow_config_api_base(), repository_model_config_locked())
    }

    /// Core of [`apply_file`]. `allow_api_base` decides whether a
    /// repo-controlled `model.apiBase` is honored; the public wrapper derives it
    /// from the environment. Split out so tests can drive it deterministically
    /// without mutating global process environment.
    fn apply_file_inner(
        &mut self,
        f: FileConfig,
        allow_api_base: bool,
        hosted_mode: bool,
    ) -> Result<()> {
        if let Some(v) = f.enabled {
            self.enabled = v;
        }
        if let Some(v) = f.ignore {
            self.ignore = v;
        }
        if let Some(v) = f.severity_threshold {
            self.severity_threshold = Severity::parse(&v)
                .with_context(|| format!("invalid severityThreshold {v:?} (info|warn|error)"))?;
        }
        if let Some(v) = f.min_confidence {
            anyhow::ensure!((0.0..=1.0).contains(&v), "minConfidence must be in 0..1");
            self.min_confidence = v;
        }
        if let Some(v) = f.max_findings {
            anyhow::ensure!(
                (1..=MAX_FINDINGS).contains(&v),
                "maxFindings must be in 1..={MAX_FINDINGS}"
            );
            self.max_findings = v;
        }
        if let Some(r) = f.reviewer {
            if let Some(t) = r.tone {
                self.tone = t;
            }
            if let Some(fo) = r.focus {
                self.focus = fo;
            }
        }
        if let Some(r) = f.review
            && let Some(oc) = r.on_clean
        {
            self.on_clean = oc;
        }
        if let Some(g) = f.gate {
            if let Some(fo) = g.fail_on {
                self.gate_fail_on = GateLevel::parse(&fo).with_context(|| {
                    format!("invalid gate.failOn {fo:?} (info|warn|error|never)")
                })?;
            }
            if let Some(oe) = g.on_error {
                self.gate_on_error = oe;
            }
            if let Some(kinds) = g.block_on_kinds {
                let mut parsed_kinds = Vec::new();
                for kind_name in kinds {
                    parsed_kinds.push(Kind::parse(&kind_name).with_context(|| {
                        format!("invalid gate.blockOnKinds entry {kind_name:?} (risk|humanEscalation|guardrail|uncertainty|contentPolicy)")
                    })?);
                }
                self.block_on_kinds = parsed_kinds;
            }
        }
        if let Some(m) = f.model {
            if hosted_mode {
                eprintln!(
                    "postil: ignoring repository model configuration in hosted mode; hosted inference selects the provider and model roster"
                );
            } else {
                if let Some(n) = m.name {
                    self.model = n;
                }
                if let Some(c) = m.cascade {
                    self.cascade = c;
                }
                if let Some(s) = m.scorer {
                    self.scorer = s;
                    self.scorer_fallback.clear();
                    self.scorer_enabled = true;
                }
                if let Some(b) = m.api_base {
                    // `model.apiBase` from `.postil.yaml` is repo-controlled, and the
                    // resolved base URL receives the deployment's bearer key. Honoring
                    // it by default would let a repo redirect the inference credential,
                    // so it is ignored unless explicitly opted in for a trusted
                    // single-user local setup. `POSTIL_API_BASE` (env) and `--config`
                    // discovery of the base are unaffected: apply_env still runs after
                    // this and takes precedence.
                    if allow_api_base {
                        self.api_base = b;
                    } else {
                        eprintln!(
                            "postil: ignoring model.apiBase from config ({b:?}); set \
                             POSTIL_ALLOW_CONFIG_API_BASE=1 to honor it, or use the \
                             POSTIL_API_BASE environment variable"
                        );
                    }
                }
                if let Some(format) = m.api_format {
                    self.api_format = format;
                }
                if let Some(n) = m.consensus {
                    anyhow::ensure!(n >= 1, "model.consensus must be >= 1");
                    self.consensus = n;
                }
            }
        }
        if let Some(cp) = f.content_policy {
            match cp.enabled {
                Some(true) => {
                    self.content_policy = Some(BUILTIN_CONTENT_POLICY.to_string());
                    self.content_policy_disabled = false;
                }
                Some(false) => {
                    self.content_policy = None;
                    self.content_policy_disabled = true;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Best-effort `.coderabbit.yaml` translation so migration costs nothing.
    /// Mapped: reviews.path_filters (exclusions), reviews.profile, enabled flags.
    fn from_coderabbit(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)?;
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw)?;
        let mut cfg = Config::default();
        let reviews = doc.get("reviews");
        if let Some(filters) = reviews
            .and_then(|r| r.get("path_filters"))
            .and_then(|v| v.as_sequence())
        {
            // CodeRabbit: "!pattern" excludes. Postil's ignore list is exclusions only.
            cfg.ignore = filters
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.strip_prefix('!'))
                .map(str::to_string)
                .collect();
        }
        if let Some(profile) = reviews
            .and_then(|r| r.get("profile"))
            .and_then(|v| v.as_str())
        {
            // "chill" reviewers say less; "assertive" say more.
            cfg.min_confidence = match profile {
                "chill" => 0.75,
                "assertive" => 0.5,
                _ => cfg.min_confidence,
            };
        }
        if let Some(enabled) = reviews
            .and_then(|r| r.get("enabled"))
            .and_then(|v| v.as_bool())
        {
            cfg.enabled = enabled;
        }
        Ok(cfg)
    }

    fn apply_env(&mut self) -> Result<()> {
        if hosted_mode() {
            return Ok(());
        }
        if let Ok(m) = std::env::var("REVIEW_MODEL")
            && !m.is_empty()
        {
            self.model = m;
        }
        if let Ok(c) = std::env::var("REVIEW_MODEL_CASCADE")
            && !c.is_empty()
        {
            self.cascade = c.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(value) = std::env::var("REVIEW_MODEL_CONSENSUS")
            && !value.trim().is_empty()
        {
            let consensus = value
                .trim()
                .parse::<usize>()
                .context("REVIEW_MODEL_CONSENSUS must be a positive integer")?;
            anyhow::ensure!(consensus >= 1, "REVIEW_MODEL_CONSENSUS must be >= 1");
            self.consensus = consensus;
        }
        if let Ok(s) = std::env::var("REVIEW_SCORER_MODEL")
            && !s.is_empty()
        {
            self.scorer = s;
            self.scorer_fallback.clear();
            self.scorer_enabled = true;
        }
        if let Ok(cascade) = std::env::var("REVIEW_SCORER_MODEL_CASCADE")
            && !cascade.trim().is_empty()
        {
            let models = cascade
                .split(',')
                .map(str::trim)
                .filter(|model| !model.is_empty())
                .collect::<Vec<_>>();
            anyhow::ensure!(
                models.len() == 1,
                "REVIEW_SCORER_MODEL_CASCADE supports exactly one embedded scorer fallback"
            );
            validate_model_id("REVIEW_SCORER_MODEL_CASCADE", models[0])?;
            self.scorer_fallback = models[0].to_string();
            self.scorer_enabled = true;
        }
        if std::env::var("POSTIL_DISABLE_SCORER")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            self.scorer_enabled = false;
        }
        if let Ok(b) = std::env::var("POSTIL_API_BASE")
            && !b.is_empty()
        {
            self.api_base = b;
        }
        if let Ok(format) = std::env::var("POSTIL_API_FORMAT")
            && !format.trim().is_empty()
        {
            self.api_format = ApiFormat::parse(&format)?;
        }
        Ok(())
    }

    /// All models to try, in order, deduplicated.
    pub fn model_chain(&self) -> Vec<String> {
        let mut chain = Vec::new();
        if !self.model.trim().is_empty() {
            chain.push(self.model.clone());
        }
        for m in &self.cascade {
            if !m.trim().is_empty() && !chain.contains(m) {
                chain.push(m.clone());
            }
        }
        chain
    }

    pub fn require_model(&self) -> Result<()> {
        self.require_model_for(hosted_mode())
    }

    fn require_model_for(&self, hosted: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let generator_chain = self.model_chain();
        anyhow::ensure!(
            !generator_chain.is_empty(),
            "no review model is configured; pass --model, set REVIEW_MODEL, or set model.name in a trusted local config"
        );
        if hosted {
            let manifest = qualification_manifest();
            let scorer_chain = self.scorer_chain();
            anyhow::ensure!(
                manifest.profiles.iter().any(|profile| {
                    profile.generator_chain == generator_chain
                        && profile.consensus == self.consensus
                        && profile.scorer_chain == scorer_chain
                        && profile.api_format == self.api_format
                        && normalize_api_base(&self.api_base).ok().as_deref()
                            == Some(profile.api_base.as_str())
                }),
                "hosted inference configuration does not exactly match a deployed qualification profile"
            );
        }
        Ok(())
    }

    /// Scorer models to try, in order, deduplicated.
    pub fn scorer_chain(&self) -> Vec<String> {
        if !self.scorer_enabled || self.scorer.trim().is_empty() {
            return Vec::new();
        }
        let mut chain = vec![self.scorer.clone()];
        if !self.scorer_fallback.trim().is_empty() && !chain.contains(&self.scorer_fallback) {
            chain.push(self.scorer_fallback.clone());
        }
        chain
    }

    pub fn scorer_enabled(&self) -> bool {
        !self.scorer_chain().is_empty()
    }
}

/// Whether a repo-controlled `model.apiBase` may be applied. Opt-in only:
/// intended for single-user local setups where the checked-out repo is trusted.
/// The deployment's inference credential is sent to the resolved base URL, so a
/// repo redirecting it would capture that credential; the default is to ignore.
fn allow_config_api_base() -> bool {
    std::env::var("POSTIL_ALLOW_CONFIG_API_BASE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Hosted deployments own inference credentials and the complete model roster.
/// Repository configuration is untrusted input, so it cannot select a model,
/// scorer, provider interface, or credential destination in this mode. Trusted
/// deployment environment overrides are applied after repository config.
pub(crate) fn hosted_mode() -> bool {
    std::env::var("POSTIL_HOSTED_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn repository_model_config_locked() -> bool {
    hosted_mode()
        || std::env::var("POSTIL_IGNORE_REPOSITORY_MODEL_CONFIG")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

fn normalize_api_base(value: &str) -> Result<String> {
    let url = reqwest::Url::parse(value).context("model API base must be an absolute URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "model API base must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "model API base must not contain credentials"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "model API base must not contain a query or fragment"
    );
    let hostname = url
        .host_str()
        .context("model API base must include a hostname")?
        .to_ascii_lowercase();
    let hostname = if hostname.contains(':') {
        format!("[{hostname}]")
    } else {
        hostname
    };
    let port = url
        .port_or_known_default()
        .context("model API base must include an effective port")?;
    let path = url.path().trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    Ok(format!("{}://{hostname}:{port}{path}", url.scheme()))
}

fn find_first(root: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| root.join(n)).find(|p| p.is_file())
}

fn rel_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

const STARTER_CONFIG_TEMPLATE: &str = r#"# Postil review configuration. Docs: https://postil.dev/docs/config
# Every key is optional; unknown keys are rejected so typos fail loudly.

# ignore:
#   - "**/dist/**"
#   - "**/*.generated.*"

severityThreshold: info   # suppress findings below: info | warn | error
minConfidence: 0.6        # suppress findings the model is not confident about
maxFindings: 20

reviewer:
  tone: "concise, dry, lightly sardonic, never hostile; no praise or filler"
  # focus:
  #   - security
  #   - concurrency

review:
  onClean: skip           # skip = stay silent on clean PRs (default) | comment

gate:
  failOn: error           # the postil/gate check fails at/above: info | warn | error | never
  blockOnKinds:           # kinds that block regardless of severity; humanEscalation requires confidence >= 0.30
    - humanEscalation     # genuine owner/product decisions only; concrete bugs remain risk
  # onError: block          # block (default, fail closed) | advisory: gate outcome when
  #                         # the review itself errors (model outage). advisory keeps an
  #                         # outage from freezing merges; the review check goes neutral, not green.

model:
  name: __DEFAULT_MODEL__
  cascade:
__DEFAULT_CASCADE__  # scorer: provider/model  # explicit BYOK opt-in; embedded scoring is disabled
  # apiBase: https://openrouter.ai/api/v1   # OpenAI-compatible or Anthropic endpoint base URL.
  # apiFormat: openai-compatible             # openai-compatible (default) or anthropic.
  #                                         # Ignored from config by default (a repo could redirect
  #                                         # the inference credential). Prefer POSTIL_API_BASE; to
  #                                         # honor this key set POSTIL_ALLOW_CONFIG_API_BASE=1 for a
  #                                         # trusted local repo.
  # consensus: 1

# Content policy is on by default. Repo rules in .postil/content-policy.md extend
# the built-in baseline. Uncomment this explicit opt-out to fully disable it.
# contentPolicy:
#   enabled: false          # See https://postil.dev/docs/content-policy
"#;

pub fn starter_config() -> &'static str {
    static STARTER_CONFIG: OnceLock<String> = OnceLock::new();
    STARTER_CONFIG.get_or_init(|| {
        let defaults = model_defaults();
        let cascade = defaults
            .cascade
            .iter()
            .map(|model| format!("    - {}\n", yaml_scalar(model)))
            .collect::<String>();
        STARTER_CONFIG_TEMPLATE
            .replace("__DEFAULT_MODEL__", &yaml_scalar(&defaults.default_model))
            .replace("__DEFAULT_CASCADE__", &cascade)
    })
}

/// Built-in content-policy baseline, active whenever the dimension is on
/// (see [`Config::content_policy`]). Scoped to human-readable prose only:
/// comments, docstrings, Markdown, and PR title/body, never code logic,
/// identifiers, or structured data. Kept conservative and low-noise on
/// purpose. This augments, rather than replacing, Postil's core "silence is
/// the correct output for most diffs" stance.
pub const BUILTIN_CONTENT_POLICY: &str = "\
1. Fabricated or contradicted claims (report at error). A changed comment, \
docstring, or doc line that contradicts the code/config/files in this diff or \
repo, or that describes a command, flag, path, env var, or behavior that does \
not exist. A good-faith, plausible description of the system is NOT a \
violation merely because the diff does not prove it; flag only a claim you \
can show is false or invented.\n\
\n\
2. Self-contradiction the change creates (report at warn). A changed doc or \
comment asserts something (not tracked, created by hand, does not exist, \
excluded) that another file changed in this SAME diff plainly refutes (e.g. a \
comment says a file is untracked while this diff adds and commits it). Both \
sides of the contradiction must be in this diff; do not infer one from \
unchanged files.\n\
\n\
3. Authoring-process narration and AI-authorship residue (report at warn). \
Prose that narrates the act of writing the code rather than stating what it \
does (\"I decided to cache X after trying Y\", \"as discussed\", \"here's what \
I did\"), or that surfaces the text as assistant/model output (\"as an AI\", \
\"I cannot help with that\", \"let me know if you need anything else\", \
\"written by Claude/ChatGPT/Copilot/Gemini\"). A plain mention of an AI/LLM as \
a product feature or integration (\"this service calls the Gemini API\") is \
NOT a violation; flag only text that narrates the authoring process or \
speaks as the model that produced it.\n\
\n\
4. Conversation and transcript leakage (report at error). Pasted chat logs, \
turn markers (\"User:\", \"Assistant:\"), narration of what \"the user\" asked, \
tool-call/tool-result dumps, or chain-of-thought leaking into committed text.\n\
\n\
5. Stale temporal and TODO residue in reference documentation (report at \
info, and only when it reads as genuinely stale, not a dated changelog entry \
or explicit roadmap section): \"currently\", \"for now\", \"at the moment\", a \
dangling TODO/FIXME/XXX with no owner or ticket, \"previously\"/\"used to\"/\"no \
longer\" phrasing describing an already-completed transition.\n\
\n\
6. House writing style (report at info, and only when the SAME pattern \
appears 3 or more times in one file - a single instance is not worth \
flagging): em-dashes; flowery/themed language (\"behold\", \"journey\" as \
metaphor, medieval/fantasy framing); hype filler (\"delve\", \"seamless\", \
\"robust\" as a buzzword, \"leverage\" as a verb, \"unlock\", \"empower\", \"game-\
changer\", \"it's not about X, it's about Y\", \"here's the kicker\", \"let's dive \
in\").\n\
\n\
Scope: apply these rules ONLY to human-readable prose - Markdown files, code \
comments, docstrings, and user-facing or log strings, plus the PR title/\
description. Do NOT apply them to code logic, identifiers, config keys/\
values, URLs, or any text that is itself an example of a banned pattern \
inside documentation ABOUT this policy. When a line is borderline, do not \
flag it; this augments the core reviewer, it does not turn Postil into a \
style linter.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, content: &str) {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn default_cascade() -> Vec<String> {
        model_defaults().cascade.clone()
    }

    #[test]
    fn embedded_model_defaults_match_root_config_file() {
        let parsed = parse_model_defaults(MODEL_DEFAULTS_TOML).unwrap();
        let raw: toml::Value = toml::from_str(MODEL_DEFAULTS_TOML).unwrap();
        assert_eq!(parsed.version, raw["version"].as_integer().unwrap() as u64);
        assert_eq!(parsed.source_sha256, sha256_hex(MODEL_DEFAULTS_TOML));
        assert_eq!(parsed.source_sha256.len(), 64);
        assert_eq!(parsed.default_model, raw["default_model"].as_str().unwrap());
        assert_eq!(
            parsed.cascade,
            raw["cascade"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            parsed.scorer_model,
            raw["scorer"]["default_model"].as_str().unwrap()
        );
        assert_eq!(
            parsed.scorer_fallback,
            raw["scorer"]["fallback"].as_str().unwrap()
        );
        assert_eq!(
            parsed.scorer_enabled,
            raw["scorer"]["enabled"].as_bool().unwrap()
        );
        assert_eq!(
            parsed.scorer_qualification_candidates,
            raw["scorer"]["qualification_candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(&parsed, model_defaults());
    }

    #[test]
    fn model_default_accessors_expose_embedded_values() {
        let defaults = model_defaults();
        assert_eq!(default_model(), defaults.default_model);
        assert_eq!(super::default_cascade(), defaults.cascade);
        assert_eq!(default_scorer_model(), defaults.scorer_model);
        assert_eq!(default_scorer_fallback(), defaults.scorer_fallback);
        assert_eq!(
            scorer_qualification_candidates(),
            defaults.scorer_qualification_candidates
        );
    }

    #[test]
    fn malformed_model_defaults_fail_loudly() {
        let err = parse_model_defaults(
            r#"version = 1
default_model = "example/model"
cascade = ["example/fallback"]
consensus = 1
api_base = "https://openrouter.ai/api/v1"
api_format = "openai-compatible"
unexpected_key = "typo"

[scorer]
enabled = false
default_model = "example/scorer"
fallback = "example/scorer-fallback"
qualification_candidates = ["example/scorer"]
"#,
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("unknown field"));
        assert!(message.contains("unexpected_key"));
    }

    #[test]
    fn malformed_model_defaults_reject_invalid_values() {
        let cases = [
            (
                "version = 0\n\
                 default_model = \"example/model\"\n\
                 cascade = [\"example/fallback\"]\n\
                 consensus = 1\n\
                 api_base = \"https://openrouter.ai/api/v1\"\n\
                 api_format = \"openai-compatible\"\n\
                 scorer = { enabled = false, default_model = \"example/scorer\", fallback = \"example/scorer-fallback\", qualification_candidates = [\"example/scorer\"] }\n",
                "version must be greater than zero",
            ),
            (
                "version = 1\n\
                 default_model = \"\"\n\
                 cascade = [\"example/fallback\"]\n\
                 consensus = 1\n\
                 api_base = \"https://openrouter.ai/api/v1\"\n\
                 api_format = \"openai-compatible\"\n\
                 scorer = { enabled = false, default_model = \"example/scorer\", fallback = \"example/scorer-fallback\", qualification_candidates = [\"example/scorer\"] }\n",
                "cascade must be empty when defaultModel is empty",
            ),
            (
                "version = 1\n\
                 default_model = \"example/model\"\n\
                 cascade = [\"\"]\n\
                 consensus = 1\n\
                 api_base = \"https://openrouter.ai/api/v1\"\n\
                 api_format = \"openai-compatible\"\n\
                 scorer = { enabled = false, default_model = \"example/scorer\", fallback = \"example/scorer-fallback\", qualification_candidates = [\"example/scorer\"] }\n",
                "cascade entries must not be empty",
            ),
            (
                "version = 1\n\
                 default_model = \"example/model\"\n\
                 cascade = [\"example/fallback\"]\n\
                 consensus = 1\n\
                 api_base = \"https://openrouter.ai/api/v1\"\n\
                 api_format = \"openai-compatible\"\n\
                 scorer = { enabled = false, default_model = \"\", fallback = \"example/scorer-fallback\", qualification_candidates = [\"example/scorer\"] }\n",
                "scorer configuration must be empty when scorer.defaultModel is empty",
            ),
        ];
        for (raw, expected) in cases {
            let err = parse_model_defaults(raw).unwrap_err();
            assert!(
                format!("{err:#}").contains(expected),
                "expected {expected:?} in {err:#}"
            );
        }
    }

    #[test]
    fn model_defaults_reject_duplicate_generator_and_scorer_entries() {
        let duplicate_generator = r#"version = 1
default_model = "provider/model"
cascade = ["provider/model"]
consensus = 2
api_base = "https://openrouter.ai/api/v1"
api_format = "openai-compatible"
scorer = { enabled = true, default_model = "provider/scorer", fallback = "", qualification_candidates = [] }
"#;
        assert!(
            parse_model_defaults(duplicate_generator)
                .unwrap_err()
                .to_string()
                .contains("must not repeat")
        );

        let duplicate_scorer = r#"version = 1
default_model = "provider/model"
cascade = []
consensus = 1
api_base = "https://openrouter.ai/api/v1"
api_format = "openai-compatible"
scorer = { enabled = true, default_model = "provider/scorer", fallback = "provider/scorer", qualification_candidates = [] }
"#;
        assert!(
            parse_model_defaults(duplicate_scorer)
                .unwrap_err()
                .to_string()
                .contains("fallback must differ")
        );
    }

    #[test]
    fn starter_config_yaml_quotes_model_defaults_when_needed() {
        assert_eq!(yaml_scalar("plain/model"), "plain/model");
        assert_eq!(
            serde_yaml::from_str::<String>(&yaml_scalar("model: with # yaml")).unwrap(),
            "model: with # yaml"
        );
    }

    #[test]
    fn provider_guide_requires_qualified_explicit_models() {
        let readme = include_str!("../README.md");
        assert!(readme.contains("docs/model-providers.md"));
        let provider_guide = include_str!("../docs/model-providers.md");
        assert!(provider_guide.contains("no implicit model or fallback chain"));
        assert!(provider_guide.contains("qualification manifest"));
    }

    #[test]
    fn defaults_are_low_noise() {
        let c = Config::default();
        assert_eq!(c.min_confidence, 0.6);
        assert_eq!(c.on_clean, OnClean::Skip);
        assert!(matches!(
            c.gate_fail_on,
            GateLevel::Severity(Severity::Error)
        ));
    }

    #[test]
    fn max_findings_is_bounded_for_scorer_admission() {
        let mut accepted = Config::default();
        let file: FileConfig = serde_yaml::from_str("maxFindings: 20\n").unwrap();
        accepted.apply_file(file).unwrap();
        assert_eq!(accepted.max_findings, MAX_FINDINGS);

        for value in [0, 21, usize::MAX] {
            let mut rejected = Config::default();
            let file: FileConfig =
                serde_yaml::from_str(&format!("maxFindings: {value}\n")).unwrap();
            assert!(rejected.apply_file(file).is_err());
        }
    }

    #[test]
    fn defaults_require_an_explicit_model_roster() {
        let c = Config::default();
        let defaults = model_defaults();
        assert_eq!(c.model, defaults.default_model);
        assert_eq!(c.cascade, default_cascade());
        assert_eq!(c.scorer, defaults.scorer_model);
        assert!(!c.scorer_enabled);
        assert!(c.scorer_chain().is_empty());
        assert!(c.model_chain().is_empty());
    }

    #[test]
    fn postil_yaml_wins_over_coderabbit() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".coderabbit.yaml",
            "reviews:\n  profile: assertive\n",
        );
        write(dir.path(), ".postil.yaml", "minConfidence: 0.9\n");
        let c = Config::load(dir.path(), None).unwrap();
        assert_eq!(c.min_confidence, 0.9);
        assert_eq!(c.source, ".postil.yaml");
    }

    #[test]
    fn coderabbit_translation() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".coderabbit.yaml",
            "reviews:\n  profile: chill\n  path_filters:\n    - \"!**/dist/**\"\n    - \"src/**\"\n",
        );
        let c = Config::load(dir.path(), None).unwrap();
        assert_eq!(c.ignore, vec!["**/dist/**".to_string()]);
        assert_eq!(c.min_confidence, 0.75);
        assert!(c.source.contains("translated"));
    }

    #[test]
    fn unknown_keys_fail_loudly() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".postil.yaml", "severtyThreshold: warn\n");
        assert!(Config::load(dir.path(), None).is_err());
    }

    #[test]
    fn starter_config_parses() {
        let f: FileConfig = serde_yaml::from_str(starter_config()).unwrap();
        let mut c = Config::default();
        c.apply_file(f).unwrap();
        let defaults = model_defaults();
        assert_eq!(c.max_findings, 20);
        assert_eq!(c.model, defaults.default_model);
        assert_eq!(c.cascade, default_cascade());
        assert_eq!(c.scorer, defaults.scorer_model);
    }

    #[test]
    fn model_scorer_parses_from_postil_config() {
        let f: FileConfig = serde_yaml::from_str("model:\n  scorer: custom/scorer\n").unwrap();
        let mut c = Config::default();
        c.apply_file(f).unwrap();
        assert_eq!(c.scorer, "custom/scorer");
        assert!(c.scorer_enabled);
        assert_eq!(c.scorer_chain(), vec!["custom/scorer"]);
    }

    #[test]
    fn trusted_runtime_can_ignore_the_complete_repository_model_section() {
        let f: FileConfig = serde_yaml::from_str(
            "model:\n  name: anthropic/claude-opus-4.1\n  cascade:\n    - attacker/fallback\n  scorer: anthropic/claude-haiku-4.5\n  apiBase: https://attacker.invalid/v1\n  apiFormat: anthropic\n  consensus: 3\n",
        )
        .unwrap();
        let mut config = Config::default();
        let expected = Config::default();

        config.apply_file_inner(f, true, true).unwrap();

        assert_eq!(config.model_chain(), expected.model_chain());
        assert_eq!(config.scorer, expected.scorer);
        assert!(!config.scorer_enabled());
        assert_eq!(config.api_base, DEFAULT_API_BASE);
        assert_eq!(config.api_format, ApiFormat::OpenaiCompatible);
        assert_eq!(config.consensus, 1);
    }

    #[test]
    fn empty_and_hosted_model_admission_fail_closed() {
        let empty = Config::default();
        assert!(empty.require_model_for(false).is_err());

        let explicit = Config {
            model: "provider/qualified-model".to_string(),
            ..Config::default()
        };
        explicit.require_model_for(false).unwrap();
        assert!(explicit.require_model_for(true).is_err());

        let disabled = Config {
            enabled: false,
            ..Config::default()
        };
        disabled.require_model_for(true).unwrap();
        assert!(qualification_manifest().profiles.is_empty());
    }

    #[test]
    fn scorer_chain_preserves_the_ordered_fallback() {
        let config = Config {
            scorer: "qualified/scorer".into(),
            scorer_fallback: "qualified/fallback".into(),
            scorer_enabled: true,
            ..Config::default()
        };
        assert_eq!(
            config.scorer_chain(),
            vec!["qualified/scorer", "qualified/fallback"]
        );
    }

    #[test]
    fn qualification_profile_rejects_stale_embedded_contract_hashes() {
        let raw = serde_json::json!({
            "version": 1,
            "modelDefaultsSha256": model_defaults().source_sha256,
            "profiles": [{
                "id": "candidate",
                "apiFormat": "openai-compatible",
                "apiBase": "https://openrouter.ai:443/api/v1",
                "benchmarkProviderIdentity": "openrouter:test-route",
                "generatorChain": ["provider/model"],
                "consensus": 1,
                "scorerChain": ["provider/scorer"],
                "reviewContractSha256": "0".repeat(64),
                "fixtureSetSha256": fixture_set_sha256(),
                "evaluatorContractSha256": evaluator_contract_sha256(),
                "evaluatorRuntimeIdentity": evaluator_runtime_identity(),
                "reportSha256": "1".repeat(64),
                "repeatedRuns": 3
            }]
        });
        let error = parse_qualification_manifest(&raw.to_string()).unwrap_err();
        assert!(error.to_string().contains("review contract is stale"));
    }

    #[test]
    fn qualification_profile_requires_three_complete_repeats() {
        let raw = serde_json::json!({
            "version": 1,
            "modelDefaultsSha256": model_defaults().source_sha256,
            "profiles": [{
                "id": "candidate",
                "apiFormat": "openai-compatible",
                "apiBase": "https://openrouter.ai:443/api/v1",
                "generatorChain": ["provider/model"],
                "consensus": 1,
                "scorerChain": ["provider/scorer"],
                "reviewContractSha256": review_contract_sha256(),
                "fixtureSetSha256": fixture_set_sha256(),
                "evaluatorContractSha256": evaluator_contract_sha256(),
                "evaluatorRuntimeIdentity": evaluator_runtime_identity(),
                "reportSha256": "1".repeat(64),
                "repeatedRuns": 2
            }]
        });
        let error = parse_qualification_manifest(&raw.to_string()).unwrap_err();
        assert!(error.to_string().contains("at least three repeated runs"));
    }

    #[test]
    fn qualification_profile_rejects_a_stale_evaluator_runtime() {
        let raw = serde_json::json!({
            "version": 1,
            "modelDefaultsSha256": model_defaults().source_sha256,
            "profiles": [{
                "id": "candidate",
                "apiFormat": "openai-compatible",
                "apiBase": "https://openrouter.ai:443/api/v1",
                "generatorChain": ["provider/model"],
                "consensus": 1,
                "scorerChain": ["provider/scorer"],
                "reviewContractSha256": review_contract_sha256(),
                "fixtureSetSha256": fixture_set_sha256(),
                "evaluatorContractSha256": evaluator_contract_sha256(),
                "evaluatorRuntimeIdentity": "bun@0.0.0",
                "reportSha256": "1".repeat(64),
                "repeatedRuns": 3
            }]
        });
        let error = parse_qualification_manifest(&raw.to_string()).unwrap_err();
        assert!(error.to_string().contains("evaluator runtime is stale"));
    }

    #[test]
    fn qualification_hash_framing_matches_cross_language_vector() {
        assert_eq!(
            sha256_named_sources(&[("a.txt", "alpha"), ("b/β.txt", "line\n")]),
            "1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba"
        );
        assert_eq!(
            normalize_api_base("HTTPS://OpenRouter.AI/api/v1/").unwrap(),
            "https://openrouter.ai:443/api/v1"
        );
        assert!(normalize_api_base("https://example.com/v1?route=x").is_err());
    }

    #[test]
    fn qualification_metadata_attests_only_an_exact_default_profile() {
        let defaults = ModelDefaults {
            version: 1,
            source_sha256: "a".repeat(64),
            default_model: "provider/generator".into(),
            cascade: vec!["provider/fallback".into()],
            consensus: 1,
            api_base: "https://models.example/v1".into(),
            api_format: ApiFormat::OpenaiCompatible,
            scorer_enabled: true,
            scorer_model: "provider/scorer".into(),
            scorer_fallback: "provider/scorer-fallback".into(),
            scorer_qualification_candidates: Vec::new(),
        };
        let profile = QualificationProfile {
            id: "qualified-profile".into(),
            api_format: ApiFormat::OpenaiCompatible,
            api_base: "https://models.example:443/v1".into(),
            benchmark_provider_identity: Some("provider-route".into()),
            generator_chain: vec!["provider/generator".into(), "provider/fallback".into()],
            consensus: 1,
            scorer_chain: vec!["provider/scorer".into(), "provider/scorer-fallback".into()],
            review_contract_sha256: "b".repeat(64),
            fixture_set_sha256: "c".repeat(64),
            evaluator_contract_sha256: "d".repeat(64),
            evaluator_runtime_identity: "bun@1.3.14".into(),
            report_sha256: "e".repeat(64),
            repeated_runs: 3,
        };
        let manifest = QualificationManifest {
            version: 1,
            model_defaults_sha256: defaults.source_sha256.clone(),
            profiles: vec![profile.clone()],
        };

        assert_eq!(admitted_profile_for(&defaults, &manifest), Some(profile));

        for tamper in ["generator", "consensus", "scorer", "apiBase", "apiFormat"] {
            let mut altered = defaults.clone();
            match tamper {
                "generator" => altered.default_model = "provider/other".into(),
                "consensus" => altered.consensus = 2,
                "scorer" => altered.scorer_model = "provider/other-scorer".into(),
                "apiBase" => altered.api_base = "https://other.example/v1".into(),
                "apiFormat" => altered.api_format = ApiFormat::Anthropic,
                _ => unreachable!(),
            }
            assert_eq!(admitted_profile_for(&altered, &manifest), None, "{tamper}");
        }

        let empty = QualificationManifest {
            profiles: Vec::new(),
            ..manifest
        };
        assert_eq!(admitted_profile_for(&defaults, &empty), None);
    }

    #[test]
    fn native_anthropic_skips_implicit_openrouter_scorers() {
        let mut config = Config {
            api_format: ApiFormat::Anthropic,
            ..Config::default()
        };
        assert!(!config.scorer_enabled());
        assert!(config.scorer_chain().is_empty());

        let generated_default: FileConfig = serde_yaml::from_str(&format!(
            "model:\n  scorer: {}\n",
            model_defaults().scorer_model
        ))
        .unwrap();
        config.apply_file(generated_default).unwrap();
        assert!(config.scorer_chain().is_empty());

        let file: FileConfig =
            serde_yaml::from_str("model:\n  scorer: claude-haiku-4-5\n").unwrap();
        config.apply_file(file).unwrap();
        assert!(config.scorer_enabled());
        assert_eq!(config.scorer_chain(), vec!["claude-haiku-4-5"]);
    }

    #[test]
    fn hosted_roster_is_empty_until_qualification_admits_models() {
        let defaults = model_defaults();
        assert!(defaults.default_model.is_empty());
        assert!(defaults.cascade.is_empty());
        assert!(defaults.scorer_model.is_empty());
        assert!(defaults.scorer_fallback.is_empty());
        assert!(defaults.scorer_qualification_candidates.is_empty());
    }

    #[test]
    fn anthropic_api_format_parses_from_postil_config() {
        let f: FileConfig = serde_yaml::from_str("model:\n  apiFormat: anthropic\n").unwrap();
        let mut config = Config::default();
        config.apply_file(f).unwrap();
        assert_eq!(config.api_format, ApiFormat::Anthropic);
    }

    #[test]
    fn openai_compatible_is_the_default_api_format() {
        assert_eq!(Config::default().api_format, ApiFormat::OpenaiCompatible);
    }

    #[test]
    fn guardrails_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".postil")).unwrap();
        write(
            dir.path(),
            ".postil/guardrails.md",
            "# Rules\n- No raw SQL in handlers.\n",
        );
        let c = Config::load(dir.path(), None).unwrap();
        assert!(c.guardrails.as_deref().unwrap().contains("No raw SQL"));
    }

    #[test]
    fn gate_on_error_parses() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".postil.yaml", "gate:\n  onError: advisory\n");
        let c = Config::load(dir.path(), None).unwrap();
        assert_eq!(c.gate_on_error, OnError::Advisory);
    }

    #[test]
    fn gate_level_semantics() {
        let g = GateLevel::parse("warn").unwrap();
        assert!(g.fails(Severity::Warn));
        assert!(g.fails(Severity::Error));
        assert!(!g.fails(Severity::Info));
        assert!(!GateLevel::parse("never").unwrap().fails(Severity::Error));
    }

    #[test]
    fn content_policy_on_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(dir.path(), None).unwrap();
        assert_eq!(c.content_policy.as_deref(), Some(BUILTIN_CONTENT_POLICY));
        assert!(!c.content_policy_disabled);
    }

    #[test]
    fn content_policy_enabled_by_config_gets_the_builtin_baseline() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".postil.yaml",
            "contentPolicy:\n  enabled: true\n",
        );
        let c = Config::load(dir.path(), None).unwrap();
        assert!(c.content_policy.as_deref().unwrap().contains("Fabricated"));
    }

    #[test]
    fn builtin_content_policy_severity_profile_matches_default_gate() {
        assert_eq!(BUILTIN_CONTENT_POLICY.matches("report at error").count(), 2);
        assert_eq!(BUILTIN_CONTENT_POLICY.matches("report at warn").count(), 2);
        assert_eq!(BUILTIN_CONTENT_POLICY.matches("report at info").count(), 2);

        let c = Config::default();
        assert!(c.gate_fail_on.fails(Severity::Error));
        assert!(!c.gate_fail_on.fails(Severity::Warn));
        assert!(!c.gate_fail_on.fails(Severity::Info));
    }

    #[test]
    fn content_policy_file_is_appended_after_the_builtin_baseline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".postil")).unwrap();
        write(
            dir.path(),
            ".postil/content-policy.md",
            "Never mention unreleased pricing.",
        );
        let c = Config::load(dir.path(), None).unwrap();
        let policy = c.content_policy.as_deref().unwrap();
        assert!(policy.starts_with(BUILTIN_CONTENT_POLICY));
        assert!(
            policy.contains("--- REPO-SPECIFIC ADDITIONS ---\nNever mention unreleased pricing.")
        );
    }

    #[test]
    fn config_api_base_is_ignored_by_default() {
        // Repo-controlled model.apiBase must not redirect the inference
        // credential unless explicitly opted in. Driven through the inner
        // helper so the test is deterministic and touches no process env.
        let f: FileConfig =
            serde_yaml::from_str("model:\n  apiBase: https://untrusted.example/v1\n").unwrap();
        let mut c = Config::default();
        c.apply_file_inner(f, false, false).unwrap();
        assert_eq!(c.api_base, DEFAULT_API_BASE);
    }

    #[test]
    fn config_api_base_honored_when_opted_in() {
        let f: FileConfig =
            serde_yaml::from_str("model:\n  apiBase: https://trusted.local/v1\n").unwrap();
        let mut c = Config::default();
        c.apply_file_inner(f, true, false).unwrap();
        assert_eq!(c.api_base, "https://trusted.local/v1");
    }

    #[test]
    fn content_policy_explicit_false_wins_over_file_presence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".postil")).unwrap();
        write(dir.path(), ".postil/content-policy.md", "Some repo rule.");
        write(
            dir.path(),
            ".postil.yaml",
            "contentPolicy:\n  enabled: false\n",
        );
        let c = Config::load(dir.path(), None).unwrap();
        assert!(c.content_policy.is_none());
        assert!(c.content_policy_disabled);
    }

    #[test]
    fn content_policy_explicit_false_disables_the_default_baseline() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".postil.yaml",
            "contentPolicy:\n  enabled: false\n",
        );
        let c = Config::load(dir.path(), None).unwrap();
        assert!(c.content_policy.is_none());
        assert!(c.content_policy_disabled);
    }
}
