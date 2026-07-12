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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::envelope::{Kind, Severity};

pub const DEFAULT_MODEL: &str = "deepseek/deepseek-v4-pro";
pub const DEFAULT_CASCADE: [&str; 3] = [
    "google/gemini-3.1-flash-lite",
    "moonshotai/kimi-k2.7-code",
    "mistralai/mistral-large-2512",
];
pub const DEFAULT_SCORER_MODEL: &str = "anthropic/claude-haiku-4.5";
pub const DEFAULT_SCORER_FALLBACK: &str = "openai/gpt-5-mini";
pub const DEFAULT_API_BASE: &str = "https://openrouter.ai/api/v1";

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
    /// model output still blocks — that class is attacker-influenceable.
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
    pub api_base: String,
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
        Config {
            enabled: true,
            ignore: Vec::new(),
            severity_threshold: Severity::Info,
            min_confidence: 0.6,
            max_findings: 20,
            tone: "direct, specific, no praise, no filler".to_string(),
            focus: Vec::new(),
            on_clean: OnClean::Skip,
            gate_fail_on: GateLevel::Severity(Severity::Error),
            gate_on_error: OnError::Block,
            block_on_kinds: vec![Kind::HumanEscalation],
            model: DEFAULT_MODEL.to_string(),
            cascade: DEFAULT_CASCADE.iter().map(|m| (*m).to_string()).collect(),
            scorer: DEFAULT_SCORER_MODEL.to_string(),
            api_base: DEFAULT_API_BASE.to_string(),
            consensus: 1,
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
        cfg.apply_env();
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
        self.apply_file_inner(f, allow_config_api_base())
    }

    /// Core of [`apply_file`]. `allow_api_base` decides whether a
    /// repo-controlled `model.apiBase` is honored; the public wrapper derives it
    /// from the environment. Split out so tests can drive it deterministically
    /// without mutating global process environment.
    fn apply_file_inner(&mut self, f: FileConfig, allow_api_base: bool) -> Result<()> {
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
            if let Some(n) = m.name {
                self.model = n;
            }
            if let Some(c) = m.cascade {
                self.cascade = c;
            }
            if let Some(s) = m.scorer {
                self.scorer = s;
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
            if let Some(n) = m.consensus {
                anyhow::ensure!(n >= 1, "model.consensus must be >= 1");
                self.consensus = n;
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

    fn apply_env(&mut self) {
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
        if let Ok(s) = std::env::var("REVIEW_SCORER_MODEL")
            && !s.is_empty()
        {
            self.scorer = s;
        }
        if let Ok(b) = std::env::var("POSTIL_API_BASE")
            && !b.is_empty()
        {
            self.api_base = b;
        }
    }

    /// All models to try, in order, deduplicated.
    pub fn model_chain(&self) -> Vec<String> {
        let mut chain = vec![self.model.clone()];
        for m in &self.cascade {
            if !chain.contains(m) {
                chain.push(m.clone());
            }
        }
        chain
    }

    /// Scorer models to try, in order, deduplicated.
    pub fn scorer_chain(&self) -> Vec<String> {
        let mut chain = vec![self.scorer.clone()];
        let fallback = DEFAULT_SCORER_FALLBACK.to_string();
        if !chain.contains(&fallback) {
            chain.push(fallback);
        }
        chain
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

fn find_first(root: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().map(|n| root.join(n)).find(|p| p.is_file())
}

fn rel_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

pub const STARTER_CONFIG: &str = r#"# Postil review configuration. Docs: https://postil.dev/docs/config
# Every key is optional; unknown keys are rejected so typos fail loudly.

# ignore:
#   - "**/dist/**"
#   - "**/*.generated.*"

severityThreshold: info   # suppress findings below: info | warn | error
minConfidence: 0.6        # suppress findings the model is not confident about
maxFindings: 20

reviewer:
  tone: "direct, specific, no praise, no filler"
  # focus:
  #   - security
  #   - concurrency

review:
  onClean: skip           # skip = stay silent on clean PRs (default) | comment

gate:
  failOn: error           # the postil/gate check fails at/above: info | warn | error | never
  # blockOnKinds:           # kinds that block regardless of severity; humanEscalation also requires confidence >= 0.30
  #   - humanEscalation
  # onError: block          # block (default, fail closed) | advisory — gate outcome when
  #                         # the review itself errors (model outage). advisory keeps an
  #                         # outage from freezing merges; the review check goes neutral, not green.

model:
  name: deepseek/deepseek-v4-pro
  cascade:
    - google/gemini-3.1-flash-lite
    - moonshotai/kimi-k2.7-code
    - mistralai/mistral-large-2512
  scorer: anthropic/claude-haiku-4.5
  # apiBase: https://openrouter.ai/api/v1   # any OpenAI-compatible endpoint (Ollama, vLLM, Azure).
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

/// Built-in content-policy baseline, active whenever the dimension is on
/// (see [`Config::content_policy`]). Scoped to human-readable prose only:
/// comments, docstrings, Markdown, and PR title/body, never code logic,
/// identifiers, or structured data. Kept conservative and low-noise on
/// purpose — this augments, it does not replace, Postil's core "silence is
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
        DEFAULT_CASCADE.iter().map(|m| (*m).to_string()).collect()
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
    fn defaults_keep_primary_and_retry_roster_order() {
        let c = Config::default();
        assert_eq!(c.model, DEFAULT_MODEL);
        assert_eq!(c.cascade, default_cascade());
        assert_eq!(c.scorer, DEFAULT_SCORER_MODEL);
        assert_eq!(
            c.scorer_chain(),
            vec![DEFAULT_SCORER_MODEL, DEFAULT_SCORER_FALLBACK]
        );
        assert_eq!(
            c.model_chain(),
            vec![
                "deepseek/deepseek-v4-pro",
                "google/gemini-3.1-flash-lite",
                "moonshotai/kimi-k2.7-code",
                "mistralai/mistral-large-2512",
            ]
        );
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
        let f: FileConfig = serde_yaml::from_str(STARTER_CONFIG).unwrap();
        let mut c = Config::default();
        c.apply_file(f).unwrap();
        assert_eq!(c.max_findings, 20);
        assert_eq!(c.model, DEFAULT_MODEL);
        assert_eq!(c.cascade, default_cascade());
        assert_eq!(c.scorer, DEFAULT_SCORER_MODEL);
    }

    #[test]
    fn model_scorer_parses_from_postil_config() {
        let f: FileConfig = serde_yaml::from_str("model:\n  scorer: custom/scorer\n").unwrap();
        let mut c = Config::default();
        c.apply_file(f).unwrap();
        assert_eq!(c.scorer, "custom/scorer");
        assert_eq!(
            c.scorer_chain(),
            vec!["custom/scorer", DEFAULT_SCORER_FALLBACK]
        );
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
        c.apply_file_inner(f, false).unwrap();
        assert_eq!(c.api_base, DEFAULT_API_BASE);
    }

    #[test]
    fn config_api_base_honored_when_opted_in() {
        let f: FileConfig =
            serde_yaml::from_str("model:\n  apiBase: https://trusted.local/v1\n").unwrap();
        let mut c = Config::default();
        c.apply_file_inner(f, true).unwrap();
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
