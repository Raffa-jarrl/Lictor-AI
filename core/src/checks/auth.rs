//! Auth surface check.
//!
//! Mirrors `audit.py::check_auth`. Detects:
//!   - whether the page even has an auth surface (login link, password field)
//!   - admin-flavored paths returning 200 instead of redirecting to login
//!     (the classic vibe-coded SPA mistake — admin UI rendered client-side
//!     without a server-side gate)

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};
use once_cell::sync::Lazy;
use regex::Regex;

static LOGIN_LINK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)href=["'][^"']*(login|signin|sign-in|auth)["']"#).unwrap());

const ADMIN_PROBES: &[&str] = &["/admin", "/dashboard", "/account/admin", "/api/admin"];

/// Run the auth-surface check.
pub fn run<F: Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();

    let landing = match fetcher.fetch(base_url, Method::Get) {
        Ok(r) if (200..400).contains(&r.status) => r,
        _ => return findings,
    };
    let text_lower = landing.body_str().to_lowercase();

    let has_login_link = LOGIN_LINK_RE.is_match(&text_lower);
    let has_password_field =
        text_lower.contains(r#"type="password""#) || text_lower.contains("type='password'");

    if !has_login_link && !has_password_field {
        findings.push(
            Finding::new(
                Severity::Info,
                Category::Auth,
                "No login surface detected on landing page",
            )
            .with_detail(
                "Either this is a marketing-only page or the login is gated behind navigation. \
                 Auth audit is best run against the actual app URL, not the marketing site.",
            )
            .with_where(base_url)
            .with_remediation(
                "Re-run with the URL of your authenticated app (e.g. app.example.com or /dashboard).",
            ),
        );
        return findings;
    }

    let parsed_base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };
    let origin = format!(
        "{}://{}",
        parsed_base.scheme(),
        parsed_base.host_str().unwrap_or("")
    );

    for path in ADMIN_PROBES {
        let full = format!("{origin}{path}");
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else { continue };
        if resp.status == 200 {
            findings.push(
                Finding::new(
                    Severity::High,
                    Category::Auth,
                    format!("Admin-flavored path accessible without redirect: {path}"),
                )
                .with_detail(format!(
                    "GET {path} returned 200. If this page renders any admin content client-side \
                     (common with vibe-coded SPAs), the data is fetched and could be inspected. \
                     Real auth gates redirect to /login on the server."
                ))
                .with_where(full)
                .with_remediation(
                    "Server-render auth checks. In Next.js: use middleware.ts to redirect \
                     unauthenticated requests BEFORE the page is sent. Don't rely on client-side \
                     useEffect → router.push, that ships the page to anyone.",
                ),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockFetch;

    #[test]
    fn no_auth_surface_returns_info_only() {
        let fetcher = MockFetch::new().with_html("https://example.com/", "<html><body>marketing only</body></html>");
        let findings = run("https://example.com/", &fetcher);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn flags_admin_path_returning_200() {
        let html = r#"<a href="/login">Sign in</a>"#;
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", html)
            .with_status(Method::Get, "https://example.com/admin", 200);
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.title.contains("/admin") && f.severity == Severity::High),
            "expected high admin finding, got: {findings:#?}"
        );
    }

    #[test]
    fn admin_path_returning_302_is_clean() {
        let html = r#"<input type="password" />"#;
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", html)
            .with_status(Method::Get, "https://example.com/admin", 302)
            .with_status(Method::Get, "https://example.com/dashboard", 302)
            .with_status(Method::Get, "https://example.com/account/admin", 302)
            .with_status(Method::Get, "https://example.com/api/admin", 302);
        let findings = run("https://example.com/", &fetcher);
        assert!(findings.is_empty(), "expected no findings on proper redirects, got: {findings:#?}");
    }
}
