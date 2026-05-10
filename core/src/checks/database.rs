//! Database exposure check.
//!
//! Detects:
//!   - Supabase REST endpoints with RLS disabled
//!   - Firebase Realtime DB with public read
//!   - `/api/users`, `/api/orders`, etc. returning data without auth
//!
//! TODO(Phase 1): port from `audit.py::check_database`. Currently a stub.

use crate::finding::Finding;

/// Run the database-exposure check. Stub implementation.
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
