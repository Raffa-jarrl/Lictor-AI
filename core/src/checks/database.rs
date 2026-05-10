//! Database / API exposure check.
//!
//! Detects:
//!   - Supabase REST endpoints with RLS likely disabled
//!   - Firebase Realtime DB with public read
//!   - `/api/users`, `/api/orders`, etc. returning JSON without auth
//!
//! Mirrors `audit.py::check_db_exposure`.

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

const API_PATHS: &[&str] = &[
    "/api/users",
    "/api/customers",
    "/api/orders",
    "/api/invoices",
    "/api/admin",
    "/api/v1/users",
    "/api/me",
];

/// Run the database-exposure check.
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

    // Pull a few JS bundles too — embedded SaaS URLs are usually in JS, not HTML.
    let mut haystack = landing_text.clone();
    for src in SCRIPT_SRC_RE.captures_iter(&landing_text).take(5) {
        let Some(s) = src.get(1) else { continue };
        let full = match parsed_base.join(s.as_str()) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if let Ok(resp) = fetcher.fetch(full.as_str(), Method::Get) {
            if resp.status == 200 && !resp.body.is_empty() {
                haystack.push('\n');
                haystack.push_str(&resp.body_str());
            }
        }
    }

    // ── Supabase ──
    for cap in SUPABASE_URL_RE.captures_iter(&haystack) {
        let sb_host = cap.get(0).unwrap().as_str();
        let rest = format!("{sb_host}/rest/v1/");
        let Ok(resp) = fetcher.fetch(&rest, Method::Get) else { continue };
        // Supabase with RLS enabled returns 401/403; without RLS the schema definitions return 200.
        if resp.status == 200 && resp.body.windows(11).any(|w| w == b"definitions") {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::Database,
                    "Supabase REST endpoint reachable without auth — RLS likely disabled",
                )
                .with_detail(format!(
                    "Supabase project at {sb_host} exposes its REST schema without authentication. \
                     This typically means Row-Level Security (RLS) is disabled on at least some tables. \
                     Anyone with this URL can read every row of those tables."
                ))
                .with_where(rest)
                .with_remediation(
                    "Enable RLS on every table in your Supabase project. In the Supabase dashboard: \
                     Authentication → Policies → toggle RLS on per table, then add policies that \
                     restrict access to `auth.uid() = user_id` (or similar). The `anon` role should \
                     see almost nothing without explicit policies.",
                ),
            );
        } else if resp.status == 401 || resp.status == 403 {
            findings.push(
                Finding::new(
                    Severity::Info,
                    Category::Database,
                    "Supabase project detected (RLS appears active)",
                )
                .with_detail(format!(
                    "Project {sb_host} returns {} on REST schema probe — auth is being enforced. Good.",
                    resp.status
                ))
                .with_where(rest)
                .with_remediation(
                    "No action needed. Spot-check that RLS policies cover ALL tables, not just user-data tables.",
                ),
            );
        }
    }

    // ── Firebase ──
    for cap in FIREBASE_DB_RE.captures_iter(&haystack) {
        let fb_host = cap.get(0).unwrap().as_str();
        let probe = format!("{fb_host}/.json");
        let Ok(resp) = fetcher.fetch(&probe, Method::Get) else { continue };
        if resp.status == 200 && resp.body.len() > 5 && resp.body != b"null" {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::Database,
                    "Firebase Realtime Database publicly readable",
                )
                .with_detail(format!(
                    "GET {probe} returned data without auth. Firebase rules allow read=true on at least \
                     part of the tree."
                ))
                .with_where(probe)
                .with_remediation(
                    "Open the Firebase console → Realtime Database → Rules. Default-deny, then add \
                     rules per path. `\".read\": \"auth != null\"` is the minimum baseline.",
                ),
            );
        }
    }

    // ── Common public API endpoints ──
    let origin = format!(
        "{}://{}",
        parsed_base.scheme(),
        parsed_base.host_str().unwrap_or("")
    );
    for path in API_PATHS {
        let full = format!("{origin}{path}");
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else { continue };
        let ctype = resp.header("content-type").unwrap_or("").to_lowercase();
        if resp.status == 200 && ctype.contains("json") && resp.body.len() > 30 {
            let count = approximate_record_count(&resp.body);
            findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::Database,
                    format!("Unauthenticated API endpoint returns data: {path}"),
                )
                .with_detail(format!(
                    "GET {path} returned HTTP 200 with JSON containing approximately {count} record(s). \
                     No auth header, no cookie. Anyone can read this."
                ))
                .with_where(full)
                .with_remediation(
                    "Every API route should require a session/JWT/API-key. In Next.js: wrap handlers \
                     in `withAuth`. In Express: middleware on the route. In Supabase: enable RLS. \
                     Test by curl-ing the endpoint with no auth header — it should return 401.",
                ),
            );
        }
    }

    findings
}

/// Count records in a JSON response: top-level array length, or .data array length, else 1.
fn approximate_record_count(body: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(body) else { return 1 };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return 1 };
    match &v {
        serde_json::Value::Array(a) => a.len(),
        serde_json::Value::Object(o) => match o.get("data") {
            Some(serde_json::Value::Array(a)) => a.len(),
            _ => 1,
        },
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{MockFetch, Response};

    #[test]
    fn flags_unauthenticated_api_users() {
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", "<html></html>")
            .with(
                Method::Get,
                "https://example.com/api/users",
                Response {
                    status: 200,
                    headers: [("content-type".to_string(), "application/json".to_string())].into_iter().collect(),
                    body: br#"[{"id":1,"name":"a"},{"id":2,"name":"b"},{"id":3,"name":"c"}]"#.to_vec(),
                },
            );
        let findings = run("https://example.com/", &fetcher);
        let hit = findings
            .iter()
            .find(|f| f.title.contains("/api/users") && f.severity == Severity::Critical);
        assert!(hit.is_some(), "expected critical /api/users finding, got {findings:#?}");
        assert!(hit.unwrap().detail.contains("3 record"));
    }

    #[test]
    fn flags_supabase_rls_off() {
        let html = r#"<script>const u = "https://abcdefghijklmnopqrst.supabase.co/rest/v1"</script>"#;
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", html)
            .with(
                Method::Get,
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/",
                Response {
                    status: 200,
                    headers: Default::default(),
                    body: br#"{"swagger":"2.0","definitions":{"users":{}}}"#.to_vec(),
                },
            );
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.title.contains("Supabase") && f.severity == Severity::Critical),
            "expected supabase critical, got: {findings:#?}"
        );
    }

    #[test]
    fn ignores_authenticated_api() {
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", "<html></html>")
            .with_status(Method::Get, "https://example.com/api/users", 401);
        let findings = run("https://example.com/", &fetcher);
        assert!(findings.is_empty(), "expected no findings on 401, got: {findings:#?}");
    }
}
