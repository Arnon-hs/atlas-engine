//! Capability-bounded filesystem access and domain models for Atlas Engine.
#![forbid(unsafe_code)]

mod classification;
mod git;
mod model;
mod parser;
mod secrets;
mod traversal;

pub use classification::{classify, content_hash, normalize_relative_path};
pub use model::*;
pub use parser::ParserRegistry;
pub use secrets::{detect_secrets, redact_secrets};
pub use traversal::Repository;

/// Current portable machine contract major/minor version.
pub const SCHEMA_VERSION: &str = "1.0";
/// Version of this engine, independent from machine contract versioning.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
