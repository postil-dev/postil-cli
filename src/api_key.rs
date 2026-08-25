//! Inference API-key resolution shared by CLI runtime checks.
//!
//! [`resolve_from_process_env`] resolves only the four explicit env vars, in
//! priority order. Stored-login resolution is invoked only when none of the
//! four is set. See `config.rs`'s module doc for the full precedence statement.

use std::future::Future;

use anyhow::Result;

#[cfg(test)]
use crate::credentials::Credentials;

pub(crate) const API_KEY_ENV_VARS: [&str; 4] = [
    "POSTIL_API_KEY",
    "OPENROUTER_API_KEY",
    "MODEL_API_KEY",
    "LLM_API_KEY",
];

pub(crate) fn names_text() -> String {
    API_KEY_ENV_VARS.join(", ")
}

pub(crate) fn resolve_from_process_env() -> Option<String> {
    resolve_with(|name| std::env::var(name).ok())
}

pub(crate) fn resolve_with(mut lookup: impl FnMut(&str) -> Option<String>) -> Option<String> {
    API_KEY_ENV_VARS
        .iter()
        .find_map(|name| lookup(name).filter(|value| !value.trim().is_empty()))
}

#[cfg(test)]
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

/// Resolves an explicit key without polling the stored-login future. This
/// keeps BYOK invocations independent of both the credential file and the
/// Postil authentication service.
pub(crate) async fn resolve_explicit_or_stored<F>(
    explicit: Option<String>,
    stored: F,
) -> Result<Option<String>>
where
    F: Future<Output = Result<Option<String>>>,
{
    match explicit {
        Some(key) => Ok(Some(key)),
        None => stored.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
            issuer: Some("https://postil.dev".to_string()),
            token: "pcli_stored-token-not-a-real-secret".to_string(),
            expires_at: expires_at.to_string(),
            refresh_token: None,
            refresh_expires_at: None,
            api_base: "https://postil.dev/api/inference/v1".to_string(),
            org: "runatlas-is".to_string(),
            model: "z-ai/glm-5.2".to_string(),
            pending_revocations: Vec::new(),
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

    #[tokio::test]
    async fn explicit_key_bypasses_stored_login_refresh() {
        let refreshed = Arc::new(AtomicBool::new(false));
        let invoked = refreshed.clone();
        let resolved = resolve_explicit_or_stored(Some("explicit-key".to_string()), async move {
            invoked.store(true, Ordering::SeqCst);
            Ok(Some("stored-key".to_string()))
        })
        .await
        .unwrap();
        assert_eq!(resolved.as_deref(), Some("explicit-key"));
        assert!(!refreshed.load(Ordering::SeqCst));
    }
}
