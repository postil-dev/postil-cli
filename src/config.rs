//! Resolved review configuration.
//!
//! Precedence: CLI flags > environment > `.postil.{yaml,yml,json}` >
//! `.coderabbit.yaml` (translated) > defaults.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::envelope::Severity;

pub const DEFAULT_MODEL: &str = "deepseek/deepseek-v4-pro";
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
    pub model: String,
    pub cascade: Vec<String>,
    pub api_base: String,
    /// Run the first N models of [model + cascade] and keep agreeing findings.
    pub consensus: usize,
    /// Contents of `.postil/guardrails.md`, injected into the prompt as repo
    /// rules. Findings that violate one are emitted as `kind: guardrail`.
    pub guardrails: Option<String>,
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
            model: DEFAULT_MODEL.to_string(),
            cascade: Vec::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            consensus: 1,
            guardrails: None,
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
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelSection {
    pub name: Option<String>,
    pub cascade: Option<Vec<String>>,
    pub api_base: Option<String>,
    pub consensus: Option<usize>,
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
        }
        if let Some(m) = f.model {
            if let Some(n) = m.name {
                self.model = n;
            }
            if let Some(c) = m.cascade {
                self.cascade = c;
            }
            if let Some(b) = m.api_base {
                self.api_base = b;
            }
            if let Some(n) = m.consensus {
                anyhow::ensure!(n >= 1, "model.consensus must be >= 1");
                self.consensus = n;
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
  # onError: block          # block (default, fail closed) | advisory — gate outcome when
  #                         # the review itself errors (model outage). advisory keeps an
  #                         # outage from freezing merges; the review check goes neutral, not green.

model:
  name: deepseek/deepseek-v4-pro
  # cascade:
  #   - anthropic/claude-sonnet-4.6
  # apiBase: https://openrouter.ai/api/v1   # any OpenAI-compatible endpoint (Ollama, vLLM, Azure)
  # consensus: 1
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, content: &str) {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(content.as_bytes()).unwrap();
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
}
