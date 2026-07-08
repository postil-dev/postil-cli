//! Inference API-key resolution shared by CLI runtime checks.

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
}
