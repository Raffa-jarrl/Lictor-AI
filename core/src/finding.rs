//! The `Finding` type — what every check returns.
//!
//! Designed to serialize cleanly to JSON for cross-language consumption
//! (Shield's TypeScript, Guardian's TypeScript, Sentinel's Python wrapper).

use serde::{Deserialize, Serialize};

/// Severity of a finding. Ordering: Critical > High > Medium > Low > Info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Active exposure that an attacker could exploit today.
    Critical,
    /// Significant misconfiguration that materially weakens the security posture.
    High,
    /// Defensible-in-depth issue. Worth fixing.
    Medium,
    /// Best-practice nudge. No active exposure.
    Low,
    /// Informational — context, not a vulnerability.
    Info,
}

/// What kind of check produced the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Secrets exposure (API keys, JWTs, .env, .git/config).
    Secrets,
    /// Database exposure (Supabase RLS, Firebase open, unauthenticated /api).
    Database,
    /// Authentication surface (admin paths returning 200).
    Auth,
    /// CORS posture (Allow-Origin: * with credentials).
    Cors,
    /// AI agent surface (chat widget / agent presence).
    AiAgent,
    /// Catch-all.
    General,
}

/// A single audit finding.
///
/// Designed to be small and JSON-friendly. Reports are produced by
/// pretty-printing a `Vec<Finding>` grouped by severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Severity level.
    pub severity: Severity,
    /// What kind of check produced this.
    pub category: Category,
    /// Short title (single line, < 80 chars).
    pub title: String,
    /// Longer detail — what was found and why it matters.
    pub detail: String,
    /// URL or file path where the evidence was observed.
    pub where_found: String,
    /// What to do about it.
    pub remediation: String,
}

impl Finding {
    /// Convenience constructor.
    pub fn new(severity: Severity, category: Category, title: impl Into<String>) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            detail: String::new(),
            where_found: String::new(),
            remediation: String::new(),
        }
    }

    /// Builder: set detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Builder: set where the evidence was observed.
    pub fn with_where(mut self, where_found: impl Into<String>) -> Self {
        self.where_found = where_found.into();
        self
    }

    /// Builder: set remediation guidance.
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn finding_builder() {
        let f = Finding::new(Severity::Critical, Category::Secrets, "Exposed key")
            .with_detail("OpenAI API key in main.js")
            .with_where("https://example.com/main.js")
            .with_remediation("Move to server-side proxy.");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, Category::Secrets);
        assert!(f.detail.contains("OpenAI"));
    }

    #[test]
    fn finding_round_trips_json() {
        let f = Finding::new(Severity::High, Category::Cors, "CORS too open");
        let s = serde_json::to_string(&f).unwrap();
        let g: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(g.title, "CORS too open");
    }
}
