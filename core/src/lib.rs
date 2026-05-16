//! lictor-core — the shared security check engine.
//!
//! Compiles to native (for Sentinel SDK, Guardian backend) and to WASM
//! (for the Shield browser extension). Public API is small: callers
//! provide a `Fetch` implementation and call `run_all_checks` (or one of
//! the `checks::*::run` functions). Findings come back as `Vec<Finding>`.
//!
//! # Build targets
//!
//! ```bash
//! cargo build --release -p lictor-core
//! cargo build --release -p lictor-core --target wasm32-unknown-unknown \
//!     --no-default-features --features wasm
//! ```
//!
//! # End-to-end native example
//!
//! ```bash
//! cargo run --example audit -- https://example.com -o report.md
//! ```
//!
//! See `core/README.md` for details.

#![forbid(unsafe_code)]

pub mod checks;
pub mod finding;
pub mod http;
pub mod report;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use finding::{Category, Finding, Severity};

/// Library version, exposed for telemetry / report headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string used by the native HTTP client.
pub const USER_AGENT: &str = concat!(
    "Lictor-Core/",
    env!("CARGO_PKG_VERSION"),
    " (+https://lictorai.com)"
);

/// Run all five URL-based static checks against `base_url`, using the
/// supplied `Fetch` implementation for HTTP. Returns the merged finding list.
///
/// This is the Shield path: audits a deployed site. For repository-based
/// audits (Studio, CI integrations) see [`run_repo_checks`].
///
/// Native callers will typically pass a `http::UreqFetch::new()`. WASM
/// callers will pass an implementation that wraps `window.fetch`.
pub fn run_all_checks<F: http::Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(checks::secrets::run(base_url, fetcher));
    findings.extend(checks::database::run(base_url, fetcher));
    findings.extend(checks::auth::run(base_url, fetcher));
    findings.extend(checks::cors::run(base_url, fetcher));
    findings.extend(checks::ai_agent::run(base_url, fetcher));
    findings
}

/// Run all source-file-based static checks against a project's source tree.
///
/// This is the Studio path: audits a local repository. `file_listing` is
/// a vector of `(relative_path, file_contents)` tuples — the caller is
/// responsible for walking the project and collecting source files (see
/// `studio/src-tauri/src/audit.rs::collect_source_files` for the canonical
/// implementation).
///
/// `declared_dependencies` are the names from `package.json` /
/// `Cargo.toml` / `requirements.txt` — used by the hallucinated-package
/// check to avoid false-positives on declared deps.
///
/// `fetcher` is used by checks that need to verify external state (e.g.,
/// `hallucinated_packages` queries the npm registry). Pass a no-op fetcher
/// for offline-only audits; those checks will skip cleanly.
pub fn run_repo_checks<F: http::Fetch>(
    file_listing: &[(String, String)],
    declared_dependencies: &std::collections::HashSet<String>,
    fetcher: &F,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Secrets — runs per-file analyze_text
    for (path, content) in file_listing {
        let source_label = match std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
        {
            Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") => "JS bundle",
            Some("py") => ".py file",
            Some("env") => ".env file",
            _ => "source file",
        };
        findings.extend(checks::secrets::analyze_text(content, path, source_label));
    }

    // Webhooks — file listing in, file listing scanned
    findings.extend(checks::webhooks::run(fetcher, file_listing));

    // Hallucinated packages — needs declared deps + npm registry
    findings.extend(checks::hallucinated_packages::run(
        fetcher,
        file_listing,
        declared_dependencies,
    ));

    findings
}

/// Top-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying HTTP failure (transport / DNS / TLS / timeout).
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
    use crate::http::MockFetch;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn user_agent_is_set() {
        assert!(USER_AGENT.starts_with("Lictor-Core/"));
    }

    #[test]
    fn run_all_checks_against_clean_html() {
        let fetcher =
            MockFetch::new().with_html("https://example.com/", "<html><body>Hello</body></html>");
        let findings = run_all_checks("https://example.com/", &fetcher);
        // We expect at least the two "no surface detected" info findings (auth + ai-agent).
        assert!(
            findings.iter().any(|f| f.severity == Severity::Info),
            "expected at least one info finding"
        );
        assert!(
            findings.iter().all(|f| f.severity != Severity::Critical),
            "expected no critical findings on clean HTML"
        );
    }
}
