//! Per-repo policy config. `.postil.yaml` is canonical; `.coderabbit.yaml` and
//! `.kodo.yaml` are read for zero-cost migration. Precedence is documented in
//! `precedence_order()`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::envelope::Severity;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct RepoConfig {
    /// Disable Postil entirely for this repo when false.
    pub enabled: Option<bool>,
    /// Glob excludes applied to finding paths.
    pub ignore: Vec<String>,
    /// Drop findings strictly below this severity.
    pub severity_threshold: Option<Severity>,
    /// Cap on inline findings posted to a PR.
    pub max_findings: Option<usize>,
    /// Optional reviewer-tone hints injected into the system prompt.
    pub reviewer: ReviewerHints,
    /// Merge-gate behaviour.
    pub review: ReviewBehavior,

    // Back-compat: older configs put these at the top level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_checks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_merge_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct ReviewerHints {
    pub tone: Option<ReviewerTone>,
    pub focus: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReviewerTone {
    Terse,
    #[default]
    Neutral,
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReviewBehavior {
    pub enabled: bool,
    pub on_clean: OnClean,
    pub auto_merge: bool,
    pub required_checks: Vec<String>,
    pub auto_merge_timeout_ms: u64,
}

impl Default for ReviewBehavior {
    fn default() -> Self {
        ReviewBehavior {
            enabled: true,
            on_clean: OnClean::Skip,
            auto_merge: false,
            required_checks: Vec::new(),
            auto_merge_timeout_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnClean {
    /// Silence-as-a-feature default: complete the check-run with no PR comment.
    #[default]
    Skip,
    /// Post an APPROVE review — needed only when branch protection requires an
    /// approving Postil review.
    Approve,
}

impl RepoConfig {
    /// Postil considers itself disabled when `enabled: false` is set explicitly.
    /// Default (None) means enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true) && self.review.enabled
    }

    pub fn merge_back_compat(mut self) -> Self {
        if let Some(rc) = self.required_checks.take()
            && self.review.required_checks.is_empty()
        {
            self.review.required_checks = rc;
        }
        if let Some(t) = self.auto_merge_timeout_ms.take()
            && self.review.auto_merge_timeout_ms == ReviewBehavior::default().auto_merge_timeout_ms
        {
            self.review.auto_merge_timeout_ms = t;
        }
        self
    }
}

/// Filenames Postil will look at in the working tree (or the PR head via the
/// contents API), in precedence order. The first non-empty parse wins; lower
/// items are silently ignored on conflict.
pub fn precedence_order() -> &'static [&'static str] {
    &[
        ".postil.yaml",
        ".postil.yml",
        ".postil.json",
        ".coderabbit.yaml",
        ".coderabbit.yml",
        ".kodo.yaml",
        ".kodo.yml",
    ]
}

/// Parse a `.postil.{yaml,yml,json}` document.
pub fn parse_postil(text: &str, filename: &str) -> anyhow::Result<RepoConfig> {
    let cfg: RepoConfig = if filename.ends_with(".json") {
        serde_json::from_str(text)?
    } else {
        serde_yaml::from_str(text)?
    };
    Ok(cfg.merge_back_compat())
}

/// Translate the subset of `.coderabbit.yaml` we honor: `reviews.path_filters`
/// (lines starting with `!` become `ignore` entries). Everything else is
/// dropped — Postil is opinionated.
pub fn translate_coderabbit(text: &str) -> anyhow::Result<RepoConfig> {
    #[derive(Deserialize)]
    struct CR {
        #[serde(default)]
        reviews: CRReviews,
    }
    #[derive(Deserialize, Default)]
    struct CRReviews {
        #[serde(default)]
        path_filters: Vec<String>,
    }
    let parsed: CR = serde_yaml::from_str(text)?;
    let ignore = parsed
        .reviews
        .path_filters
        .into_iter()
        .filter_map(|p| p.strip_prefix('!').map(str::to_string))
        .collect();
    Ok(RepoConfig {
        ignore,
        ..RepoConfig::default()
    })
}

/// Translate the subset of `.kodo.yaml` we honor: top-level `exclude`,
/// `severity`.
pub fn translate_kodo(text: &str) -> anyhow::Result<RepoConfig> {
    #[derive(Deserialize)]
    struct Kodo {
        #[serde(default)]
        exclude: Vec<String>,
        #[serde(default)]
        severity: Option<String>,
    }
    let parsed: Kodo = serde_yaml::from_str(text)?;
    let severity_threshold = parsed.severity.as_deref().and_then(Severity::parse);
    Ok(RepoConfig {
        ignore: parsed.exclude,
        severity_threshold,
        ..RepoConfig::default()
    })
}

/// Load the first matching config file from a local directory.
pub fn load_from_dir(dir: &Path) -> anyhow::Result<RepoConfig> {
    for name in precedence_order() {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        return load_from_text(&text, name);
    }
    Ok(RepoConfig::default())
}

pub fn load_from_text(text: &str, filename: &str) -> anyhow::Result<RepoConfig> {
    if filename.starts_with(".postil.") {
        parse_postil(text, filename)
    } else if filename.starts_with(".coderabbit.") {
        translate_coderabbit(text)
    } else if filename.starts_with(".kodo.") {
        translate_kodo(text)
    } else {
        Ok(RepoConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_enabled_with_skip_on_clean() {
        let c = RepoConfig::default();
        assert!(c.is_enabled());
        assert_eq!(c.review.on_clean, OnClean::Skip);
        assert_eq!(c.review.auto_merge_timeout_ms, 15_000);
    }

    #[test]
    fn explicit_disable() {
        let c = parse_postil("enabled: false\n", ".postil.yaml").unwrap();
        assert!(!c.is_enabled());
    }

    #[test]
    fn back_compat_required_checks_at_top_level() {
        let c = parse_postil(
            "requiredChecks: [Lint]\nautoMergeTimeoutMs: 42\n",
            ".postil.yaml",
        )
        .unwrap();
        assert_eq!(c.review.required_checks, vec!["Lint".to_string()]);
        assert_eq!(c.review.auto_merge_timeout_ms, 42);
    }

    #[test]
    fn coderabbit_path_filters_translate_to_ignore() {
        let cr = "reviews:\n  path_filters:\n    - '!dist/**'\n    - 'src/**'\n";
        let c = translate_coderabbit(cr).unwrap();
        assert_eq!(c.ignore, vec!["dist/**".to_string()]);
    }

    #[test]
    fn kodo_exclude_and_severity_translate() {
        let k = "exclude: ['vendor/**']\nseverity: warn\n";
        let c = translate_kodo(k).unwrap();
        assert_eq!(c.ignore, vec!["vendor/**".to_string()]);
        assert_eq!(c.severity_threshold, Some(Severity::Warn));
    }
}
