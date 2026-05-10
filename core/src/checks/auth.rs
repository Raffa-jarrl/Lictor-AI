//! Auth surface check.
//!
//! Two surfaces:
//!   - [`analyze_landing_html`] — pure: detect login surface signals.
//!   - [`finding_admin_path_open`] — pure: build a finding for an open admin path.
//!   - [`run`] — full pipeline using [`Fetch`].

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};
use once_cell::sync::Lazy;
use regex::Regex;

static LOGIN_LINK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)href=["'][^"']*(login|signin|sign-in|auth)["']"#).unwrap());

/// Admin-flavored paths probed when a login surface is present.
pub const ADMIN_PROBES: &[&str] = &["/admin", "/dashboard", "/account/admin", "/api/admin"];

/// Whether the landing page exposes a login surface (login link OR password field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginSurface {
    /// At least one signal: login link or `type=password` input.
    Present,
    /// Neither — likely a marketing-only page.
    Absent,
}

/// Pure: classify a landing page's auth surface.
pub fn analyze_landing_html(html: &str) -> LoginSurface {
    let lower = html.to_lowercase();
    let has_login_link = LOGIN_LINK_RE.is_match(&lower);
    let has_password_field =
        lower.contains(r#"type="password""#) || lower.contains("type='password'");
    if has_login_link || has_password_field {
        LoginSurface::Present
    } else {
        LoginSurface::Absent
    }
}

/// Pure: build the "no login surface" informational finding.
pub fn finding_no_login_surface(base_url: &str) -> Finding {
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
    )
}

/// Pure: build the "admin path open" High finding for a probed `path` that returned 200.
pub fn finding_admin_path_open(path: &str, full_url: &str) -> Finding {
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
    .with_where(full_url)
    .with_remediation(
        "Server-render auth checks. In Next.js: use middleware.ts to redirect \
         unauthenticated requests BEFORE the page is sent. Don't rely on client-side \
         useEffect → router.push, that ships the page to anyone.",
    )
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
    let html = landing.body_str();

    if matches!(analyze_landing_html(&html), LoginSurface::Absent) {
        findings.push(finding_no_login_surface(base_url));
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
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else {
            continue;
        };
        if resp.status == 200 {
            findings.push(finding_admin_path_open(path, &full));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockFetch;

    #[test]
    fn analyze_landing_detects_login_link() {
        assert_eq!(
            analyze_landing_html(r#"<a href="/login">Sign in</a>"#),
            LoginSurface::Present
        );
    }

    #[test]
    fn analyze_landing_detects_password_field() {
        assert_eq!(
            analyze_landing_html(r#"<input type="password" />"#),
            LoginSurface::Present
        );
    }

    #[test]
    fn analyze_landing_marketing_page_is_absent() {
        assert_eq!(
            analyze_landing_html("<html><body>welcome</body></html>"),
            LoginSurface::Absent
        );
    }

    #[test]
    fn run_flags_admin_open() {
        let fetcher = MockFetch::new()
            .with_html("https://x.test/", r#"<a href="/login">Sign in</a>"#)
            .with_status(Method::Get, "https://x.test/admin", 200);
        let findings = run("https://x.test/", &fetcher);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("/admin")));
    }
}
