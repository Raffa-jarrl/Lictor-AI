//! AI agent surface check.
//!
//! Detects: presence of chat widgets / AI agents on the page. Flags the page
//! for a manual prompt-injection review (we don't try to prove injection
//! works — just point the user at the surface).
//!
//! TODO(Phase 1): port from `audit.py::check_ai_agent`. Currently a stub.

use crate::finding::Finding;

/// Run the AI-agent-surface check. Stub implementation.
pub fn run(_html: &str) -> Vec<Finding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_empty() {
        assert!(run("").is_empty());
    }
}
