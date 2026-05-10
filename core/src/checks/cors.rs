//! CORS posture check.
//!
//! Detects: `Access-Control-Allow-Origin: *` combined with `credentials: true`
//! — a classic developer-relaxed-CORS-without-understanding-it footgun.
//!
//! TODO(Phase 1): port from `audit.py::check_cors`. Currently a stub.

use crate::finding::Finding;

/// Run the CORS-posture check. Stub implementation.
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
