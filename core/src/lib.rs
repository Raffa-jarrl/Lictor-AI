//! lictor-core — the shared security check engine.
//!
//! Compiles to native (for Sentinel SDK, Guardian backend) and to WASM
//! (for the Shield browser extension). Public API is intentionally small:
//! each check returns a `Vec<Finding>`. The wrappers decide what to do with them.
//!
//! # Build targets
//!
//! ```bash
//! cargo build --release -p lictor-core
//! cargo build --release -p lictor-core --target wasm32-unknown-unknown \
//!     --no-default-features --features wasm
//! ```
//!
//! See `core/README.md` for details.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checks;
pub mod finding;

#[cfg(feature = "native")]
pub mod http;

pub use finding::{Category, Finding, Severity};

/// Library version, exposed for telemetry / report headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string used by the native HTTP client.
#[cfg(feature = "native")]
pub const USER_AGENT: &str = concat!(
    "Lictor-Core/",
    env!("CARGO_PKG_VERSION"),
    " (+https://lictor.ai)"
);

/// Run every static check against a URL, native side.
///
/// In the WASM/Shield build, the browser does the HTTP and feeds bytes
/// in via separate entry points — this function is native-only.
#[cfg(feature = "native")]
pub fn run_all_checks(_url: &str) -> Result<Vec<Finding>, Error> {
    // TODO(Phase 1): port audit.py check pipeline. Stub returns empty for now.
    Ok(Vec::new())
}

/// Top-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying HTTP failure (native only).
    #[cfg(feature = "native")]
    #[error("http error: {0}")]
    Http(String),

    /// URL could not be parsed.
    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    /// Other failure with context.
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    #[cfg(feature = "native")]
    #[test]
    fn user_agent_is_set() {
        assert!(USER_AGENT.starts_with("Lictor-Core/"));
    }
}
