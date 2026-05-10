//! Secrets exposure check.
//!
//! Detects:
//!   - API keys / JWTs / credentials in HTML/JS bundles
//!   - `/.env`, `/.git/config`, `wp-config.php` exposed at the URL root
//!
//! TODO(Phase 1): port from `audit.py::check_secrets`. Currently a stub.

use crate::finding::Finding;

/// Run the secrets-exposure check. Stub implementation.
pub fn run(_html_or_js: &str, _origin: &str) -> Vec<Finding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_empty() {
        assert!(run("", "https://example.com").is_empty());
    }
}
