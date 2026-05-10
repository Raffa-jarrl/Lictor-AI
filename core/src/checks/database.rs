//! Database / API exposure check.
//!
//! Two surfaces:
//!   - [`analyze_haystack`] / [`analyze_unauth_api_response`] — pure helpers
//!     that take already-fetched bytes. WASM-safe.
//!   - [`run`] — full pipeline using a [`Fetch`].

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};
use once_cell::sync::Lazy;
use regex::Regex;

static SUPABASE_URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)https://([a-z0-9]{20,})\.supabase\.co").unwrap());
static FIREBASE_DB_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)https://([a-z0-9\-]+)\.firebaseio\.com").unwrap());
static SCRIPT_SRC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap());

/// Common backend paths that vibe-coded apps often expose accidentally.
pub const API_PATHS: &[&str] = &[
    "/api/users",
    "/api/customers",
    "/api/orders",
    "/api/invoices",
    "/api/admin",
    "/api/v1/users",
    "/api/me",
];

/// Outcome of probing a Supabase project's REST schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupabaseProbeStatus {
    /// 200 + `definitions` keyword in body — RLS likely off.
    SchemaOpen,
    /// 401/403 — RLS appears active.
    AuthEnforced,
    /// Anything else — inconclusive.
    Inconclusive,
}

/// Pure: scan combined HTML+JS text, return all distinct Supabase project URLs found.
pub fn extract_supabase_hosts(haystack: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cap in SUPABASE_URL_RE.captures_iter(haystack) {
        let host = cap.get(0).unwrap().as_str().to_string();
        if seen.insert(host.clone()) {
            out.push(host);
        }
    }
    out
}

/// Pure: scan combined HTML+JS text, return all distinct Firebase RTDB URLs found.
pub fn extract_firebase_hosts(haystack: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cap in FIREBASE_DB_RE.captures_iter(haystack) {
        let host = cap.get(0).unwrap().as_str().to_string();
        if seen.insert(host.clone()) {
            out.push(host);
        }
    }
    out
}

/// Pure: extract first N script-src URLs (for callers that want to fetch and
/// pass JS bundle content back).
pub fn extract_script_srcs(html: &str, max: usize) -> Vec<String> {
    SCRIPT_SRC_RE
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .take(max)
        .collect()
}

/// Pure: classify a Supabase REST schema probe response.
pub fn classify_supabase_probe(status: u16, body: &[u8]) -> SupabaseProbeStatus {
    if status == 200 && body.windows(11).any(|w| w == b"definitions") {
        SupabaseProbeStatus::SchemaOpen
    } else if status == 401 || status == 403 {
        SupabaseProbeStatus::AuthEnforced
    } else {
        SupabaseProbeStatus::Inconclusive
    }
}

/// Pure: build a finding for an open Supabase REST schema (RLS likely off).
pub fn finding_supabase_schema_open(supabase_host: &str, rest_url: &str) -> Finding {
    Finding::new(
        Severity::Critical,
        Category::Database,
        "Supabase REST endpoint reachable without auth — RLS likely disabled",
    )
    .with_detail(format!(
        "Supabase project at {supabase_host} exposes its REST schema without authentication. \
         This typically means Row-Level Security (RLS) is disabled on at least some tables. \
         Anyone with this URL can read every row of those tables."
    ))
    .with_where(rest_url)
    .with_remediation(
        "Enable RLS on every table in your Supabase project. In the Supabase dashboard: \
         Authentication → Policies → toggle RLS on per table, then add policies that \
         restrict access to `auth.uid() = user_id` (or similar). The `anon` role should \
         see almost nothing without explicit policies.",
    )
}

/// Pure: build a finding for an auth-enforced Supabase project (informational).
pub fn finding_supabase_auth_enforced(supabase_host: &str, rest_url: &str, status: u16) -> Finding {
    Finding::new(
        Severity::Info,
        Category::Database,
        "Supabase project detected (RLS appears active)",
    )
    .with_detail(format!(
        "Project {supabase_host} returns {status} on REST schema probe — auth is being enforced. Good."
    ))
    .with_where(rest_url)
    .with_remediation(
        "No action needed. Spot-check that RLS policies cover ALL tables, not just user-data tables.",
    )
}

/// Pure: build a finding for a publicly-readable Firebase Realtime DB.
pub fn finding_firebase_open(firebase_host: &str, probe_url: &str) -> Finding {
    Finding::new(
        Severity::Critical,
        Category::Database,
        "Firebase Realtime Database publicly readable",
    )
    .with_detail(format!(
        "GET {probe_url} returned data without auth from project {firebase_host}. \
         Firebase rules allow read=true on at least part of the tree."
    ))
    .with_where(probe_url)
    .with_remediation(
        "Open the Firebase console → Realtime Database → Rules. Default-deny, then add \
         rules per path. `\".read\": \"auth != null\"` is the minimum baseline.",
    )
}

/// Pure: produce a finding for an unauthenticated `/api/*` endpoint that returns JSON.
/// Returns `None` if the response isn't JSON-shaped or has no body.
pub fn analyze_unauth_api_response(
    path: &str,
    full_url: &str,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Option<Finding> {
    if status != 200 {
        return None;
    }
    if !content_type.to_lowercase().contains("json") {
        return None;
    }
    if body.len() <= 30 {
        return None;
    }
    let count = approximate_record_count(body);
    Some(
        Finding::new(
            Severity::Critical,
            Category::Database,
            format!("Unauthenticated API endpoint returns data: {path}"),
        )
        .with_detail(format!(
            "GET {path} returned HTTP 200 with JSON containing approximately {count} record(s). \
             No auth header, no cookie. Anyone can read this."
        ))
        .with_where(full_url)
        .with_remediation(
            "Every API route should require a session/JWT/API-key. In Next.js: wrap handlers \
             in `withAuth`. In Express: middleware on the route. In Supabase: enable RLS. \
             Test by curl-ing the endpoint with no auth header — it should return 401.",
        ),
    )
}

fn approximate_record_count(body: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(body) else {
        return 1;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return 1;
    };
    match &v {
        serde_json::Value::Array(a) => a.len(),
        serde_json::Value::Object(o) => match o.get("data") {
            Some(serde_json::Value::Array(a)) => a.len(),
            _ => 1,
        },
        _ => 1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Native pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Full pipeline.
pub fn run<F: Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();

    let landing = match fetcher.fetch(base_url, Method::Get) {
        Ok(r) if (200..400).contains(&r.status) => r,
        _ => return findings,
    };
    let landing_text = landing.body_str().into_owned();

    let parsed_base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };

    // Build haystack: HTML + first 5 same-host JS bundles.
    let mut haystack = landing_text.clone();
    for src in extract_script_srcs(&landing_text, 5) {
        let Ok(full) = parsed_base.join(&src) else {
            continue;
        };
        if let Ok(resp) = fetcher.fetch(full.as_str(), Method::Get) {
            if resp.status == 200 && !resp.body.is_empty() {
                haystack.push('\n');
                haystack.push_str(&resp.body_str());
            }
        }
    }

    // Supabase probes.
    for sb_host in extract_supabase_hosts(&haystack) {
        let rest = format!("{sb_host}/rest/v1/");
        let Ok(resp) = fetcher.fetch(&rest, Method::Get) else {
            continue;
        };
        match classify_supabase_probe(resp.status, &resp.body) {
            SupabaseProbeStatus::SchemaOpen => {
                findings.push(finding_supabase_schema_open(&sb_host, &rest));
            }
            SupabaseProbeStatus::AuthEnforced => {
                findings.push(finding_supabase_auth_enforced(&sb_host, &rest, resp.status));
            }
            SupabaseProbeStatus::Inconclusive => {}
        }
    }

    // Firebase probes.
    for fb_host in extract_firebase_hosts(&haystack) {
        let probe = format!("{fb_host}/.json");
        let Ok(resp) = fetcher.fetch(&probe, Method::Get) else {
            continue;
        };
        if resp.status == 200 && resp.body.len() > 5 && resp.body != b"null" {
            findings.push(finding_firebase_open(&fb_host, &probe));
        }
    }

    // Common API paths.
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
        let ctype = resp.header("content-type").unwrap_or("");
        if let Some(f) = analyze_unauth_api_response(path, &full, resp.status, ctype, &resp.body) {
            findings.push(f);
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{MockFetch, Response};

    #[test]
    fn extract_supabase_dedupes() {
        let h = "x https://abcdefghijklmnopqrst.supabase.co/a y https://abcdefghijklmnopqrst.supabase.co/b";
        let hosts = extract_supabase_hosts(h);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn classify_supabase_open_when_definitions_present() {
        let body = br#"{"swagger":"2.0","definitions":{"users":{}}}"#;
        assert_eq!(
            classify_supabase_probe(200, body),
            SupabaseProbeStatus::SchemaOpen
        );
    }

    #[test]
    fn classify_supabase_auth_when_401() {
        assert_eq!(
            classify_supabase_probe(401, b""),
            SupabaseProbeStatus::AuthEnforced
        );
        assert_eq!(
            classify_supabase_probe(403, b""),
            SupabaseProbeStatus::AuthEnforced
        );
    }

    #[test]
    fn analyze_unauth_api_returns_none_when_not_json() {
        let f = analyze_unauth_api_response(
            "/api/users",
            "http://x/api/users",
            200,
            "text/html",
            b"<html></html>",
        );
        assert!(f.is_none());
    }

    #[test]
    fn analyze_unauth_api_counts_array_length() {
        let body = br#"[{"id":1,"name":"a"},{"id":2,"name":"b"},{"id":3,"name":"c"}]"#;
        let f = analyze_unauth_api_response(
            "/api/users",
            "http://x/api/users",
            200,
            "application/json",
            body,
        )
        .expect("expected finding");
        assert!(f.detail.contains("3 record"), "{}", f.detail);
    }

    #[test]
    fn analyze_unauth_api_returns_none_when_body_too_small() {
        // The 30-byte threshold blocks empty-stub JSON responses.
        let body = br#"{"ok":true}"#;
        let f = analyze_unauth_api_response(
            "/api/users",
            "http://x/api/users",
            200,
            "application/json",
            body,
        );
        assert!(f.is_none());
    }

    #[test]
    fn run_full_pipeline_detects_unauth_api() {
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", "<html></html>")
            .with(
                Method::Get,
                "https://example.com/api/users",
                Response {
                    status: 200,
                    headers: [("content-type".to_string(), "application/json".to_string())]
                        .into_iter()
                        .collect(),
                    body: br#"[{"id":1,"name":"a"},{"id":2,"name":"b"}]"#.to_vec(),
                },
            );
        let findings = run("https://example.com/", &fetcher);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("/api/users") && f.severity == Severity::Critical));
    }
}
