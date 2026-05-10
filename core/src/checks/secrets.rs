//! Secrets exposure check.
//!
//! Two API surfaces:
//!
//!   1. [`analyze_text`] — pure: scan a string for secret patterns. WASM-safe,
//!      no I/O. Used by Shield (browser passes HTML, WASM scans).
//!   2. [`run`] — full pipeline: fetches the landing page + linked JS bundles
//!      + sensitive-file probes. Native-only (needs a [`Fetch`]).
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
        (r"AIza[A-Za-z0-9_\-]{35}", "Google API key", Severity::High),
        (
            r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}",
            "Anthropic API key",
            Severity::Critical,
        ),
        // Matches both legacy OpenAI keys (sk-AAAA...) and newer project keys
        // (sk-proj-AAAA...). The (?:proj-)? prefix is optional and non-capturing.
        (
            r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
            "OpenAI API key (or similar sk- token)",
            Severity::Critical,
        ),
        (
            r"sk_live_[A-Za-z0-9]{24,}",
            "Stripe live secret key",
            Severity::Critical,
        ),
        (
            r"sk_test_[A-Za-z0-9]{24,}",
            "Stripe test secret key (still leaks logic)",
            Severity::Medium,
        ),
        (
            r"pk_live_[A-Za-z0-9]{24,}",
            "Stripe live publishable key (informational)",
            Severity::Info,
        ),
        (
            r"ghp_[A-Za-z0-9]{36}",
            "GitHub personal access token",
            Severity::Critical,
        ),
        (
            r"ghs_[A-Za-z0-9]{36}",
            "GitHub server token",
            Severity::Critical,
        ),
        (r"xox[abp]-[A-Za-z0-9-]{10,}", "Slack token", Severity::High),
        (r"AKIA[0-9A-Z]{16}", "AWS access key ID", Severity::High),
        (
            r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
            "Private key block",
            Severity::Critical,
        ),
        (
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            "JWT token (verify intended)",
            Severity::Low,
        ),
        (
            r"mongodb(\+srv)?://[^\s\x22'<>]+",
            "MongoDB connection string",
            Severity::Critical,
        ),
        (
            r"postgres(ql)?://[^\s\x22'<>]+",
            "PostgreSQL connection string",
            Severity::Critical,
        ),
        (
            r"redis://[^\s\x22'<>]+",
            "Redis connection string",
            Severity::High,
        ),
    ];
    raw.iter()
        .map(|(re, label, sev)| Pattern {
            re: Regex::new(re).expect("hardcoded secret pattern must compile"),
            label,
            severity: *sev,
        })
        .collect()
});

static SCRIPT_SRC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap());

/// Pure: scan a single string for secret patterns. Returns one finding per
/// distinct (pattern, redacted-value) pair. No I/O. WASM-safe.
///
/// `where_found` is recorded on each finding (URL or path of origin).
/// `source_label` is the human-readable category ("page HTML", "JS bundle",
/// ".env file", etc.) — used in the finding title and detail.
pub fn analyze_text(text: &str, where_found: &str, source_label: &str) -> Vec<Finding> {
    use std::collections::HashSet;
    let mut findings = Vec::new();
    // Dedup by EXACT matched value — not by (label, redacted). Same secret
    // string commonly matches multiple patterns (e.g. an Anthropic key
    // `sk-ant-api03-...` also matches the broader OpenAI `sk-` pattern).
    // We want one finding per actual secret. Patterns are iterated in order,
    // so the more-specific label (listed first in SECRET_PATTERNS) wins.
    let mut seen: HashSet<String> = HashSet::new();

    for pat in SECRET_PATTERNS.iter() {
        for m in pat.re.find_iter(text) {
            let value = m.as_str();
            if !seen.insert(value.to_string()) {
                continue;
            }
            let redacted = redact(value);
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
    findings
}

/// Pure: produce a finding for an exposed sensitive file (`.env` etc.).
/// `path` is what was probed; `body_len` is the size of the response body.
pub fn finding_for_exposed_file(path: &str, full_url: &str, body_len: usize) -> Finding {
    Finding::new(
        Severity::Critical,
        Category::Secrets,
        format!("Sensitive file publicly readable: {path}"),
    )
    .with_detail(format!(
        "Returned HTTP 200 with {body_len} bytes. Files like .env routinely contain database \
         credentials, API keys, and webhook secrets. If this file has any real secrets, rotate them today."
    ))
    .with_where(full_url)
    .with_remediation(
        "Move secrets out of the served filesystem. For Vercel/Netlify, use the platform's \
         environment-variable UI. Add `.env*` to `.gitignore` and verify the file is not in your \
         build output (`dist/`, `out/`, `.next/standalone`).",
    )
}

/// Pure: extract `<script src="...">` URLs from HTML. Up to `max` of them.
pub fn extract_script_srcs(html: &str, max: usize) -> Vec<String> {
    SCRIPT_SRC_RE
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .take(max)
        .collect()
}

/// Sensitive-file paths probed at the URL root.
pub const SENSITIVE_FILE_PROBES: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/wp-config.php",
    "/config.json",
];

// ─────────────────────────────────────────────────────────────────────────────
// Native pipeline (uses Fetch)
// ─────────────────────────────────────────────────────────────────────────────

/// Full pipeline: fetch the landing page, scan it, scan first 8 same-host JS
/// bundles, probe sensitive paths. Native (or any environment with `Fetch`).
pub fn run<F: Fetch>(base_url: &str, fetcher: &F) -> Vec<Finding> {
    let mut findings = Vec::new();

    let landing = match fetcher.fetch(base_url, Method::Get) {
        Ok(r) if (200..400).contains(&r.status) => r,
        Ok(r) => {
            findings.push(unfetchable_finding(base_url, format!("HTTP {}", r.status)));
            return findings;
        }
        Err(e) => {
            findings.push(unfetchable_finding(
                base_url,
                format!("Transport error: {e}"),
            ));
            return findings;
        }
    };
    let landing_text = landing.body_str().into_owned();
    findings.extend(analyze_text(&landing_text, base_url, "page HTML"));

    let parsed_base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return findings,
    };
    let base_host = parsed_base.host_str().unwrap_or("").to_lowercase();

    for src in extract_script_srcs(&landing_text, 8) {
        let Some(full) = resolve_url(&parsed_base, &src) else {
            continue;
        };
        if full.host_str().unwrap_or("").to_lowercase() != base_host {
            continue;
        }
        let url_str = full.as_str().to_string();
        if let Ok(resp) = fetcher.fetch(&url_str, Method::Get) {
            if resp.status == 200 && !resp.body.is_empty() {
                findings.extend(analyze_text(&resp.body_str(), &url_str, "JS bundle"));
            }
        }
    }

    let origin = format!(
        "{}://{}",
        parsed_base.scheme(),
        parsed_base.host_str().unwrap_or("")
    );
    for path in SENSITIVE_FILE_PROBES {
        let full = format!("{origin}{path}");
        let Ok(resp) = fetcher.fetch(&full, Method::Get) else {
            continue;
        };
        if resp.status == 200 && resp.body.len() > 30 {
            findings.push(finding_for_exposed_file(path, &full, resp.body.len()));
        }
    }

    findings
}

fn unfetchable_finding(url: &str, detail: impl Into<String>) -> Finding {
    Finding::new(
        Severity::Info,
        Category::General,
        format!("Could not fetch {url}"),
    )
    .with_detail(detail.into())
    .with_where(url)
    .with_remediation("Check the URL is correct and publicly reachable.")
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
    use crate::http::{MockFetch, Response};

    #[test]
    fn analyze_text_finds_openai_key() {
        let html = r#"const k = "sk-ABCDEFGHIJabcdefghij1234567890""#;
        let findings = analyze_text(html, "https://x/", "page HTML");
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("OpenAI")));
    }

    #[test]
    fn analyze_text_finds_openai_proj_key() {
        // OpenAI shipped 'sk-proj-...' project keys in 2024+; the original
        // upstream pattern missed them. Don't regress.
        let html = r#"OPENAI_KEY = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGG""#;
        let findings = analyze_text(html, "https://x/", "page HTML");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("OpenAI")),
            "expected sk-proj- to match OpenAI pattern, got: {findings:#?}"
        );
    }

    #[test]
    fn analyze_text_dedupes_repeated_match() {
        let html = "sk-ABCDEFGHIJabcdefghij1234567890\nsk-ABCDEFGHIJabcdefghij1234567890\n";
        let findings = analyze_text(html, "https://x/", "page HTML");
        let openai_count = findings
            .iter()
            .filter(|f| f.title.contains("OpenAI"))
            .count();
        assert_eq!(
            openai_count, 1,
            "duplicate matches should fold to one finding"
        );
    }

    #[test]
    fn analyze_text_dedupes_anthropic_matched_by_openai_pattern() {
        // Real-world: an Anthropic key is also a valid match for the broader
        // OpenAI `sk-...` pattern. We want exactly ONE finding (Anthropic, the
        // more specific label that appears first in the patterns list).
        let html =
            r#"const k = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM""#;
        let findings = analyze_text(html, "https://x/", "page HTML");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert!(findings[0].title.contains("Anthropic"));
    }

    #[test]
    fn extract_script_srcs_caps_at_max() {
        let html = (0..20)
            .map(|i| format!(r#"<script src="/a{i}.js"></script>"#))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(extract_script_srcs(&html, 8).len(), 8);
    }

    #[test]
    fn run_full_pipeline_detects_dotenv() {
        let fetcher = MockFetch::new()
            .with_html("https://example.com/", "<html></html>")
            .with(
                Method::Get,
                "https://example.com/.env",
                Response {
                    status: 200,
                    headers: Default::default(),
                    body: b"DATABASE_URL=postgres://user:pass@host/db\nAPI_KEY=secret_value_here_123\n".to_vec(),
                },
            );
        let findings = run("https://example.com/", &fetcher);
        assert!(findings
            .iter()
            .any(|f| f.title.contains(".env") && f.severity == Severity::Critical));
    }

    #[test]
    fn redact_short_returns_placeholder() {
        assert_eq!(redact("short"), "<redacted>");
    }

    #[test]
    fn redact_long_keeps_head_and_tail() {
        assert_eq!(redact("sk-ABCDEFGHIJ1234567890"), "sk-ABC…7890");
    }
}
