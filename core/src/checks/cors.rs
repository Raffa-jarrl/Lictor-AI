//! CORS posture check.
//!
//! Mirrors `audit.py::check_cors`. Probes a small set of common API paths and
//! looks at their `Access-Control-Allow-Origin` / `-Credentials` headers.
//!
//! - `Allow-Origin: *` + `Allow-Credentials: true` → High (developer relaxed
//!   CORS without understanding it; browsers reject the combo, but it's a
//!   strong signal that other endpoints may be misconfigured too).
//! - `Allow-Origin: *` alone → Info (fine for genuinely public data; risky
//!   if the endpoint can ever return user-specific content).

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};

const API_PATHS: &[&str] = &["/api/health", "/api/me", "/api/users", "/api/v1/me"];

/// Run the CORS-posture check.
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
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else { continue };
        if !(200..500).contains(&resp.status) {
            continue;
        }

        let aca = resp
            .header("access-control-allow-origin")
            .unwrap_or("")
            .trim();
        let acc = resp
            .header("access-control-allow-credentials")
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if aca == "*" && acc == "true" {
            findings.push(
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
                .with_where(full)
                .with_remediation(
                    "Reflect a SPECIFIC allowed origin (e.g. https://app.example.com), not `*`, \
                     when credentials are involved. Maintain an allowlist of trusted origins.",
                ),
            );
        } else if aca == "*" {
            findings.push(
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
                .with_where(full)
                .with_remediation(
                    "Restrict CORS to your actual frontends if this endpoint can ever return private data.",
                ),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{MockFetch, Response};

    #[test]
    fn flags_origin_star_with_credentials() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        headers.insert("access-control-allow-credentials".to_string(), "true".to_string());
        let fetcher = MockFetch::new().with(
            Method::Get,
            "https://example.com/api/me",
            Response { status: 200, headers, body: b"{}".to_vec() },
        );
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.severity == Severity::High && f.title.contains("/api/me")),
            "expected high CORS finding, got: {findings:#?}"
        );
    }

    #[test]
    fn allows_origin_star_alone_is_info() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        let fetcher = MockFetch::new().with(
            Method::Get,
            "https://example.com/api/health",
            Response { status: 200, headers, body: b"{}".to_vec() },
        );
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Info && f.title.contains("/api/health")),
            "expected info CORS finding, got: {findings:#?}"
        );
    }

    #[test]
    fn specific_origin_is_clean() {
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "access-control-allow-origin".to_string(),
            "https://app.example.com".to_string(),
        );
        headers.insert("access-control-allow-credentials".to_string(), "true".to_string());
        let fetcher = MockFetch::new().with(
            Method::Get,
            "https://example.com/api/me",
            Response { status: 200, headers, body: b"{}".to_vec() },
        );
        let findings = run("https://example.com/", &fetcher);
        assert!(findings.is_empty(), "expected no findings, got: {findings:#?}");
    }
}
