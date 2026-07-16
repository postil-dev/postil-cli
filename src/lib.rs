//! Postil review engine. See README for the product doctrine.

pub(crate) mod api_key;
#[cfg(feature = "qualification-candidate")]
pub mod attribution;
pub mod cli;
pub mod config;
pub mod diff;
pub mod doctor;
pub mod envelope;
pub mod filter;
pub mod forge;
pub mod hook;
pub mod llm;
pub mod local;
pub mod output;
pub mod plan;
pub mod prompt;
pub mod respond;
pub mod review;
pub mod sarif;
