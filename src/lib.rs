//! Postil review engine. Library crate exposed so integration tests and external
//! consumers can call into the engine without spawning the binary.

pub mod cli;
pub mod config;
pub mod diff;
pub mod envelope;
pub mod filter;
pub mod github;
pub mod local;
pub mod openrouter;
pub mod output;
pub mod prompt;
pub mod repo_config;
pub mod review;
