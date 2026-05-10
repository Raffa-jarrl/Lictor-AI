//! Auth surface check.
//!
//! Detects: admin-flavored paths returning 200 instead of redirecting to login
//! (the classic vibe-coded SPA mistake — admin UI rendered client-side without
//! a server-side gate).
//!
//! TODO(Phase 1): port from `audit.py::check_auth`. Currently a stub.

use crate::finding::Finding;

/// Run the auth-surface check. Stub implementation.
pub fn run(_origin: &str) -> Vec<Finding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_empty() {
        assert!(run("https://example.com").is_empty());
    }
}
