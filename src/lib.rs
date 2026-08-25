//! Postil review engine. See README for the product doctrine.

pub(crate) mod adjudication;
pub(crate) mod api_key;
#[cfg(feature = "qualification-candidate")]
pub mod attribution;
pub(crate) mod brevity;
pub mod cli;
pub mod config;
pub(crate) mod credentials;
pub mod diff;
pub mod doctor;
pub(crate) mod durable_plan;
pub mod envelope;
pub mod filter;
pub mod forge;
pub mod hook;
pub mod llm;
pub mod local;
pub mod login;
pub(crate) mod machine_claim;
pub mod output;
pub mod plan;
pub(crate) mod progress;
pub mod prompt;
pub(crate) mod repository_search;
pub(crate) mod resolve;
pub mod review;
pub mod sarif;

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
