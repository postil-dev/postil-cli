//! Inference API-key resolution shared by CLI runtime checks.
//!
//! [`resolve_from_process_env`] resolves only the four explicit env vars, in
//! priority order. [`resolve_effective`] adds one more source below all
//! four: a stored `postil login` credential, used only when none of the env
//! vars is set. See `config.rs`'s module doc for the full precedence
//! statement.

use std::path::Path;

use anyhow::Result;

use crate::credentials::{self, Credentials};

pub(crate) const API_KEY_ENV_VARS: [&str; 4] = [
    "POSTIL_API_KEY",
    "OPENROUTER_API_KEY",
    "MODEL_API_KEY",
    "LLM_API_KEY",
];

pub(crate) fn names_text() -> String {
    API_KEY_ENV_VARS.join(", ")
}

pub(crate) fn credential_help() -> String {
    format!(
        "default model is {}; run `postil login` for hosted inference or set one of {}; see `postil models` for tested presets and override syntax",
        crate::config::default_model(),
        names_text()
    )
}

pub(crate) fn resolve_from_process_env() -> Option<String> {
    resolve_with(|name| std::env::var(name).ok())
}

pub(crate) fn resolve_with(mut lookup: impl FnMut(&str) -> Option<String>) -> Option<String> {
    API_KEY_ENV_VARS
        .iter()
        .find_map(|name| lookup(name).filter(|value| !value.trim().is_empty()))
}

/// Bearer key resolved for inference, falling back to a stored `postil
/// login` credential when none of the four explicit env vars is set.
/// `Ok(None)` means neither source has a key; callers turn that into their
/// own "set a key or run `postil login`" message. An expired stored
/// credential is reported here as an error, so the caller surfaces one
/// actionable instruction instead of a confusing upstream auth failure once
/// the request reaches the provider.
pub(crate) fn resolve_effective(credentials_path: &Path) -> Result<Option<String>> {
    resolve_effective_with(
        |name| std::env::var(name).ok(),
        || credentials::read(credentials_path),
    )
}

pub(crate) fn resolve_effective_with(
    env_lookup: impl FnMut(&str) -> Option<String>,
    credential_lookup: impl FnOnce() -> Result<Option<Credentials>>,
) -> Result<Option<String>> {
    if let Some(key) = resolve_with(env_lookup) {
        return Ok(Some(key));
    }
    let Some(credentials) = credential_lookup()? else {
        return Ok(None);
    };
    anyhow::ensure!(
        !credentials.is_expired(),
        "the stored postil login credential expired; run `postil login` again"
    );
    Ok(Some(credentials.token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resolve(pairs: &[(&str, &str)]) -> Option<String> {
        let values: HashMap<&str, &str> = pairs.iter().copied().collect();
        resolve_with(|name| values.get(name).map(|value| (*value).to_string()))
    }

    #[test]
    fn preserves_specific_key_precedence() {
        assert_eq!(
            resolve(&[
                ("OPENROUTER_API_KEY", "openrouter-key"),
                ("MODEL_API_KEY", "model-key"),
                ("LLM_API_KEY", "llm-key"),
            ]),
            Some("openrouter-key".to_string())
        );
        assert_eq!(
            resolve(&[
                ("POSTIL_API_KEY", "postil-key"),
                ("OPENROUTER_API_KEY", "openrouter-key"),
                ("MODEL_API_KEY", "model-key"),
            ]),
            Some("postil-key".to_string())
        );
    }

    #[test]
    fn empty_values_do_not_shadow_later_aliases() {
        assert_eq!(
            resolve(&[
                ("POSTIL_API_KEY", ""),
                ("OPENROUTER_API_KEY", " "),
                ("MODEL_API_KEY", ""),
                ("LLM_API_KEY", "llm-key"),
            ]),
            Some("llm-key".to_string())
        );
    }

    fn stored_credential(expires_at: &str) -> Credentials {
        Credentials {
            version: credentials::CREDENTIALS_VERSION,
            token: "pcli_stored-token-not-a-real-secret".to_string(),
            expires_at: expires_at.to_string(),
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
        }
    }

    fn resolve_effective(
        pairs: &[(&str, &str)],
        stored: Option<Credentials>,
    ) -> Result<Option<String>> {
        let values: HashMap<&str, &str> = pairs.iter().copied().collect();
        resolve_effective_with(
            |name| values.get(name).map(|value| (*value).to_string()),
            || Ok(stored),
        )
    }

    #[test]
    fn each_explicit_env_var_wins_over_a_stored_credential() {
        for name in API_KEY_ENV_VARS {
            let resolved = resolve_effective(
                &[(name, "explicit-key")],
                Some(stored_credential("2999-01-01T00:00:00.000Z")),
            )
            .unwrap();
            assert_eq!(
                resolved,
                Some("explicit-key".to_string()),
                "{name} did not take priority over a stored credential"
            );
        }
    }

    #[test]
    fn stored_credential_is_used_when_no_env_var_is_set() {
        let resolved =
            resolve_effective(&[], Some(stored_credential("2999-01-01T00:00:00.000Z"))).unwrap();
        assert_eq!(
            resolved,
            Some("pcli_stored-token-not-a-real-secret".to_string())
        );
    }

    #[test]
    fn absence_of_both_env_var_and_credential_resolves_to_none() {
        assert_eq!(resolve_effective(&[], None).unwrap(), None);
    }

    #[test]
    fn expired_stored_credential_yields_one_actionable_relogin_error() {
        let error = resolve_effective(&[], Some(stored_credential("2020-01-01T00:00:00.000Z")))
            .expect_err("expired credential must error, not silently resolve");
        let message = error.to_string();
        assert!(message.contains("postil login"));
        assert!(!message.contains("pcli_stored-token-not-a-real-secret"));
    }
}
