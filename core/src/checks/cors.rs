//! CORS posture check.
//!
//! Two surfaces:
//!   - [`analyze_cors_headers`] — pure: classify a single response's CORS headers.
//!   - [`run`] — full pipeline using [`Fetch`].

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};

/// Common API paths probed for CORS.
pub const API_PATHS: &[&str] = &["/api/health", "/api/me", "/api/users", "/api/v1/me"];

/// Classification of a single CORS-headers response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorsClassification {
    /// `Allow-Origin: *` AND `Allow-Credentials: true` — High.
    StarWithCredentials,
    /// `Allow-Origin: *` alone — Info.
    StarOnly,
    /// Specific origin or no CORS headers — clean.
    Clean,
    /// Status outside 200..500 — skip.
    Skip,
}

/// Pure: classify a single response's CORS posture.
pub fn analyze_cors_headers(
    status: u16,
    allow_origin: &str,
    allow_credentials: &str,
) -> CorsClassification {
    if !(200..500).contains(&status) {
        return CorsClassification::Skip;
    }
    let aca = allow_origin.trim();
    let acc = allow_credentials.trim().to_lowercase();
    if aca == "*" && acc == "true" {
        CorsClassification::StarWithCredentials
    } else if aca == "*" {
        CorsClassification::StarOnly
    } else {
        CorsClassification::Clean
    }
}

/// Pure: build the "ACAO=* + ACAC=true" High finding.
pub fn finding_cors_misconfigured(path: &str, full_url: &str) -> Finding {
    Finding::new(
        Severity::High,
        Category::Cors,
        format!("CORS misconfiguration on {path}"),
    )
    .with_detail(
        "Endpoint sends `Access-Control-Allow-Origin: *` AND \
         `Access-Control-Allow-Credentials: true`. Browsers will reject this combination, \
         but it indicates a developer tried to relax CORS without understanding the model. \
         It's a strong signal that other endpoints may have a permissive `Origin` echo.",
    )
    .with_where(full_url)
    .with_remediation(
        "Reflect a SPECIFIC allowed origin (e.g. https://app.example.com), not `*`, \
         when credentials are involved. Maintain an allowlist of trusted origins.",
    )
}

/// Pure: build the "ACAO=* alone" Info finding.
pub fn finding_cors_origin_star(path: &str, full_url: &str) -> Finding {
    Finding::new(
        Severity::Info,
        Category::Cors,
        format!("CORS allows any origin on {path}"),
    )
    .with_detail(
        "`Access-Control-Allow-Origin: *` means any website can call this endpoint from a \
         browser. Fine if the response is genuinely public (rates, feature flags); \
         dangerous if it ever returns user-specific data.",
    )
    .with_where(full_url)
    .with_remediation(
        "Restrict CORS to your actual frontends if this endpoint can ever return private data.",
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Native pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Full pipeline.
pub fn run<F: Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();

    let parsed_base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };
    let origin = format!(
        "{}://{}",
        parsed_base.scheme(),
        parsed_base.host_str().unwrap_or("")
    );

    for path in API_PATHS {
        let full = format!("{origin}{path}");
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else {
            continue;
        };
        let aca = resp.header("access-control-allow-origin").unwrap_or("");
        let acc = resp
            .header("access-control-allow-credentials")
            .unwrap_or("");
        match analyze_cors_headers(resp.status, aca, acc) {
            CorsClassification::StarWithCredentials => {
                findings.push(finding_cors_misconfigured(path, &full));
            }
            CorsClassification::StarOnly => {
                findings.push(finding_cors_origin_star(path, &full));
            }
            CorsClassification::Clean | CorsClassification::Skip => {}
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{MockFetch, Response};

    #[test]
    fn classify_star_with_credentials() {
        assert_eq!(
            analyze_cors_headers(200, "*", "true"),
            CorsClassification::StarWithCredentials
        );
    }

    #[test]
    fn classify_star_only() {
        assert_eq!(
            analyze_cors_headers(200, "*", ""),
            CorsClassification::StarOnly
        );
    }

    #[test]
    fn classify_specific_origin_clean() {
        assert_eq!(
            analyze_cors_headers(200, "https://app.example.com", "true"),
            CorsClassification::Clean
        );
    }

    #[test]
    fn classify_500_skipped() {
        assert_eq!(
            analyze_cors_headers(500, "*", "true"),
            CorsClassification::Skip
        );
    }

    #[test]
    fn run_flags_misconfigured_endpoint() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("access-control-allow-origin".into(), "*".into());
        headers.insert("access-control-allow-credentials".into(), "true".into());
        let fetcher = MockFetch::new().with(
            Method::Get,
            "https://x.test/api/me",
            Response {
                status: 200,
                headers,
                body: b"{}".to_vec(),
            },
        );
        let findings = run("https://x.test/", &fetcher);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }
}
