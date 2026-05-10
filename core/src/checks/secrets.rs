//! Secrets exposure check.
//!
//! Detects:
//!   - API keys / JWTs / private-key blocks / connection strings in the
//!     landing-page HTML and the first 8 same-host JS bundles
//!   - `.env`, `.git/config`, `wp-config.php`, and similar sensitive files
//!     served at the URL root
//!
//! Patterns and severities are kept in lockstep with `audit.py::SECRET_PATTERNS`.
//! When you add a pattern in one, add it in the other.

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};
use once_cell::sync::Lazy;
use regex::Regex;

/// One row of the patterns table.
struct Pattern {
    re: Regex,
    label: &'static str,
    severity: Severity,
}

static SECRET_PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    let raw: &[(&str, &str, Severity)] = &[
        (r"AIza[A-Za-z0-9_\-]{35}",                                          "Google API key",                              Severity::High),
        (r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}",                             "Anthropic API key",                           Severity::Critical),
        (r"sk-[A-Za-z0-9]{20,}",                                             "OpenAI API key (or similar sk- token)",       Severity::Critical),
        (r"sk_live_[A-Za-z0-9]{24,}",                                        "Stripe live secret key",                      Severity::Critical),
        (r"sk_test_[A-Za-z0-9]{24,}",                                        "Stripe test secret key (still leaks logic)",  Severity::Medium),
        (r"pk_live_[A-Za-z0-9]{24,}",                                        "Stripe live publishable key (informational)", Severity::Info),
        (r"ghp_[A-Za-z0-9]{36}",                                             "GitHub personal access token",                Severity::Critical),
        (r"ghs_[A-Za-z0-9]{36}",                                             "GitHub server token",                         Severity::Critical),
        (r"xox[abp]-[A-Za-z0-9-]{10,}",                                      "Slack token",                                 Severity::High),
        (r"AKIA[0-9A-Z]{16}",                                                "AWS access key ID",                           Severity::High),
        (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",                    "Private key block",                           Severity::Critical),
        (r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",   "JWT token (verify intended)",                 Severity::Low),
        (r"mongodb(\+srv)?://[^\s\x22'<>]+",                                 "MongoDB connection string",                   Severity::Critical),
        (r"postgres(ql)?://[^\s\x22'<>]+",                                   "PostgreSQL connection string",                Severity::Critical),
        (r"redis://[^\s\x22'<>]+",                                           "Redis connection string",                     Severity::High),
    ];

    raw.iter()
        .map(|(re, label, sev)| Pattern {
            re: Regex::new(re).expect("hardcoded secret pattern must compile"),
            label,
            severity: *sev,
        })
        .collect()
});

/// Run the secrets check. Mirrors `audit.py::check_secrets`.
pub fn run<F: Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();

    let landing = match fetcher.fetch(base_url, Method::Get) {
        Ok(r) if (200..400).contains(&r.status) => r,
        Ok(r) => {
            findings.push(
                Finding::new(Severity::Info, Category::General, format!("Could not fetch {base_url}"))
                    .with_detail(format!(
                        "HTTP {} — site may be down, blocking the toolkit, or behind auth.",
                        r.status
                    ))
                    .with_where(base_url)
                    .with_remediation("Check the URL is correct and publicly reachable."),
            );
            return findings;
        }
        Err(e) => {
            findings.push(
                Finding::new(Severity::Info, Category::General, format!("Could not fetch {base_url}"))
                    .with_detail(format!("Transport error: {e}"))
                    .with_where(base_url)
                    .with_remediation("Check the URL is correct and publicly reachable."),
            );
            return findings;
        }
    };

    let landing_text = landing.body_str().into_owned();
    scan_text(&landing_text, base_url, "page HTML", &mut findings);

    // Scan first 8 same-host linked JS bundles.
    let parsed_base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };
    let base_host = parsed_base.host_str().unwrap_or("").to_lowercase();

    static SCRIPT_SRC_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap());

    let scripts: Vec<String> = SCRIPT_SRC_RE
        .captures_iter(&landing_text)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .take(8)
        .collect();

    for src in scripts {
        let full = match resolve_url(&parsed_base, &src) {
            Some(u) => u,
            None => continue,
        };
        let host = full.host_str().unwrap_or("").to_lowercase();
        if host != base_host {
            continue; // never poke a third-party bundle
        }
        let url_str = full.as_str().to_string();
        if let Ok(resp) = fetcher.fetch(&url_str, Method::Get) {
            if resp.status == 200 && !resp.body.is_empty() {
                let txt = resp.body_str().into_owned();
                scan_text(&txt, &url_str, "JS bundle", &mut findings);
            }
        }
    }

    // Common path leaks.
    let origin = format!("{}://{}", parsed_base.scheme(), parsed_base.host_str().unwrap_or(""));
    let probes = [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.git/config",
        "/wp-config.php",
        "/config.json",
    ];
    for path in probes {
        let full = format!("{origin}{path}");
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else { continue };
        if resp.status == 200 && resp.body.len() > 30 {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    Category::Secrets,
                    format!("Sensitive file publicly readable: {path}"),
                )
                .with_detail(format!(
                    "Returned HTTP 200 with {} bytes. Files like .env routinely contain database \
                     credentials, API keys, and webhook secrets. If this file has any real secrets, \
                     rotate them today.",
                    resp.body.len()
                ))
                .with_where(full)
                .with_remediation(
                    "Move secrets out of the served filesystem. For Vercel/Netlify, use the \
                     platform's environment-variable UI. Add `.env*` to `.gitignore` and verify \
                     the file is not in your build output (`dist/`, `out/`, `.next/standalone`).",
                ),
            );
        }
    }

    findings
}

fn scan_text(text: &str, where_found: &str, source_label: &str, findings: &mut Vec<Finding>) {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for pat in SECRET_PATTERNS.iter() {
        for m in pat.re.find_iter(text) {
            let value = m.as_str();
            let redacted = redact(value);
            let key = (pat.label.to_string(), redacted.clone());
            if !seen.insert(key) {
                continue;
            }
            findings.push(
                Finding::new(
                    pat.severity,
                    Category::Secrets,
                    format!("{} found in {}", pat.label, source_label),
                )
                .with_detail(format!(
                    "Pattern matched in publicly-served {}. Redacted form: `{}`. \
                     If this is a real key, rotate it. If it's intended to be public (e.g. Stripe \
                     publishable key), this finding is informational only.",
                    source_label, redacted
                ))
                .with_where(where_found)
                .with_remediation(
                    "Move the key server-side. Public-facing apps should NEVER contain server-secret \
                     keys (sk_live_, sk-, AIza for restricted-key services, etc.). Use a backend \
                     API as an intermediary.",
                ),
            );
        }
    }
}

fn redact(value: &str) -> String {
    if value.len() > 14 {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    } else {
        "<redacted>".to_string()
    }
}

fn resolve_url(base: &url::Url, src: &str) -> Option<url::Url> {
    if let Some(rest) = src.strip_prefix("//") {
        // Protocol-relative — inherit base's scheme.
        let scheme = base.scheme();
        return url::Url::parse(&format!("{scheme}://{rest}")).ok();
    }
    if let Ok(u) = url::Url::parse(src) {
        return Some(u);
    }
    base.join(src).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockFetch;

    #[test]
    fn detects_openai_key_in_landing_html() {
        let html = r#"<script>const k = "sk-ABCDEFGHIJabcdefghij1234567890"</script>"#;
        let fetcher = MockFetch::new().with_html("https://example.com/", html);
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.title.contains("OpenAI") && f.severity == Severity::Critical),
            "expected an OpenAI Critical finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_exposed_dotenv() {
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", "<html></html>")
            .with(
                Method::Get,
                "https://example.com/.env",
                crate::http::Response {
                    status: 200,
                    headers: Default::default(),
                    body: b"DATABASE_URL=postgres://user:pass@host/db\nAPI_KEY=secret_value_here_123\n".to_vec(),
                },
            );
        let findings = run("https://example.com/", &fetcher);
        assert!(
            findings.iter().any(|f| f.title.contains(".env") && f.severity == Severity::Critical),
            "expected an .env Critical finding, got: {findings:#?}"
        );
    }

    #[test]
    fn no_false_positive_on_clean_html() {
        let fetcher = MockFetch::new().with_html("https://example.com/", "<html><body>nothing</body></html>");
        let findings = run("https://example.com/", &fetcher);
        let crits: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        assert!(crits.is_empty(), "no criticals expected on clean HTML, got: {crits:#?}");
    }

    #[test]
    fn redact_short_value() {
        assert_eq!(redact("short"), "<redacted>");
    }

    #[test]
    fn redact_long_value() {
        assert_eq!(redact("sk-ABCDEFGHIJ1234567890"), "sk-ABC…7890");
    }
}
