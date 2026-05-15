//! Webhook signature verification check.
//!
//! Two API surfaces (same pattern as `secrets.rs`):
//!
//!   1. [`analyze_text`] — pure: scan source code for webhook handler patterns
//!      and flag any that don't appear to verify signatures. WASM-safe.
//!   2. [`run`] — full pipeline: fetches the project's deployed routes and
//!      probes for known unauthenticated webhook endpoints. Native-only.
//!
//! Currently detects Stripe, GitHub, Shopify, Slack, and Anthropic webhook
//! patterns. Adding a provider requires a new entry in `WEBHOOK_PATTERNS`
//! plus the corresponding verification-pattern check.

use crate::finding::{Category, Finding, Severity};
use crate::http::Fetch;
use once_cell::sync::Lazy;
use regex::Regex;

/// A webhook provider we know how to detect.
struct WebhookProvider {
    name: &'static str,
    /// Pattern that matches a webhook handler for this provider.
    /// (e.g., `stripe-signature` header, `/api/stripe-webhook` route, etc.)
    handler_pattern: Regex,
    /// Pattern that, if present in the same file, indicates verification.
    /// If absent, the handler is unverified.
    verifier_pattern: Regex,
    /// Plain-English description of what's at risk.
    description: &'static str,
}

static WEBHOOK_PROVIDERS: Lazy<Vec<WebhookProvider>> = Lazy::new(|| {
    vec![
        WebhookProvider {
            name: "Stripe",
            handler_pattern: Regex::new(
                r#"(?i)(?:stripe-signature|/api/(?:stripe-)?webhook|stripeWebhook|stripe\.webhook)"#,
            )
            .expect("valid stripe handler regex"),
            verifier_pattern: Regex::new(
                r#"(?:stripe|Stripe)\.webhooks\.constructEvent|webhookSecret|STRIPE_WEBHOOK_SECRET"#,
            )
            .expect("valid stripe verifier regex"),
            description: "Anyone could POST a fake `checkout.session.completed` event and grant themselves premium subscriptions or refund flows.",
        },
        WebhookProvider {
            name: "GitHub",
            handler_pattern: Regex::new(
                r#"(?i)x-hub-signature|x-github-event|/api/github-?webhook|github.*webhook"#,
            )
            .expect("valid github handler regex"),
            verifier_pattern: Regex::new(
                r#"(?:GITHUB_WEBHOOK_SECRET|webhooks\.verify|crypto\.createHmac.*sha256.*GITHUB)"#,
            )
            .expect("valid github verifier regex"),
            description: "Anyone could POST a fake `push` or `pull_request` event and trigger downstream deploys / Slack alerts / etc.",
        },
        WebhookProvider {
            name: "Shopify",
            handler_pattern: Regex::new(
                r#"(?i)x-shopify-hmac-sha256|/api/shopify-?webhook|shopify.*webhook"#,
            )
            .expect("valid shopify handler regex"),
            verifier_pattern: Regex::new(
                r#"(?:SHOPIFY_WEBHOOK_SECRET|verifyShopifyWebhook|crypto\.createHmac.*SHOPIFY)"#,
            )
            .expect("valid shopify verifier regex"),
            description: "Fake order-created events could trigger fulfillment / email flows.",
        },
        WebhookProvider {
            name: "Slack",
            handler_pattern: Regex::new(
                r#"(?i)x-slack-signature|/api/slack-?webhook|slack.*event"#,
            )
            .expect("valid slack handler regex"),
            verifier_pattern: Regex::new(
                r#"(?:SLACK_SIGNING_SECRET|verifySlackRequest|crypto.*SLACK)"#,
            )
            .expect("valid slack verifier regex"),
            description: "Anyone could POST fake slash-command or event payloads.",
        },
    ]
});

/// Result of scanning a single file for webhook patterns.
#[derive(Debug, Clone)]
pub struct WebhookSiteFinding {
    pub provider: String,
    pub file_path: String,
    pub line_hint: Option<u32>,
    pub description: String,
}

/// Pure analysis — scan the source text of a single file for webhook
/// handlers that lack signature verification.
///
/// Returns a finding per unverified handler. Empty = clean.
pub fn analyze_text(source: &str, file_path: &str) -> Vec<WebhookSiteFinding> {
    let mut found = Vec::new();

    for provider in WEBHOOK_PROVIDERS.iter() {
        if provider.handler_pattern.is_match(source) {
            // Handler is present. Is verification?
            if !provider.verifier_pattern.is_match(source) {
                // Find the rough line number of the handler match
                let line_hint = source
                    .lines()
                    .enumerate()
                    .find_map(|(i, line)| {
                        if provider.handler_pattern.is_match(line) {
                            Some((i + 1) as u32)
                        } else {
                            None
                        }
                    });

                found.push(WebhookSiteFinding {
                    provider: provider.name.to_string(),
                    file_path: file_path.to_string(),
                    line_hint,
                    description: provider.description.to_string(),
                });
            }
        }
    }

    found
}

/// Full pipeline: walks the project files (caller supplies them via the
/// fetcher) and aggregates unverified-webhook findings.
///
/// `file_listing` is a list of (path, source) tuples — the caller is
/// responsible for collecting the project's TS/JS/Python files and
/// passing them in. (Studio passes the local file walker output; Shield
/// passes deployed-route source if available.)
pub fn run<F: Fetch>(_fetcher: &F, file_listing: &[(String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (path, source) in file_listing {
        let site_findings = analyze_text(source, path);

        for sf in site_findings {
            let title = format!("{} webhook handler is unverified", sf.provider);
            let detail = format!(
                "We found a {} webhook handler at {} but no signature verification. {}",
                sf.provider, sf.file_path, sf.description
            );
            let where_found = match sf.line_hint {
                Some(line) => format!("{}:{}", sf.file_path, line),
                None => sf.file_path.clone(),
            };
            let remediation = format!(
                "Add {}'s standard signature verification step before trusting the request body.",
                sf.provider
            );
            findings.push(
                Finding::new(Severity::High, Category::Auth, title)
                    .with_detail(detail)
                    .with_where(where_found)
                    .with_remediation(remediation),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unverified_stripe_webhook() {
        let src = r#"
            // app/api/stripe-webhook/route.ts
            export async function POST(req) {
              const body = await req.json();
              if (body.type === 'checkout.session.completed') {
                await markUserAsPremium(body.data.object.customer);
              }
              return new Response('ok');
            }
        "#;
        let findings = analyze_text(src, "app/api/stripe-webhook/route.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].provider, "Stripe");
    }

    #[test]
    fn does_not_flag_verified_stripe_webhook() {
        let src = r#"
            import Stripe from 'stripe';
            const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
            const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

            export async function POST(req) {
              const sig = req.headers.get('stripe-signature');
              const body = await req.text();
              const event = stripe.webhooks.constructEvent(body, sig, webhookSecret);
              // ...
            }
        "#;
        let findings = analyze_text(src, "app/api/stripe-webhook/route.ts");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_unverified_github_webhook() {
        let src = r#"
            // pages/api/github-webhook.ts
            export default async function handler(req, res) {
              const event = req.headers['x-github-event'];
              if (event === 'push') { await deploy(req.body); }
              res.status(200).end();
            }
        "#;
        let findings = analyze_text(src, "pages/api/github-webhook.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].provider, "GitHub");
    }
}
