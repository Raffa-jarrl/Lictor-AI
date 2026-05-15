//! Check modules. Each one exposes a `run(...)` function returning `Vec<Finding>`.
//!
//! The original five seed checks were ported from `audit.py`. Two more
//! checks shipped 2026-05-15 to complete the 7 patterns the launch is
//! positioned around (see `~/Lictor/docs/launch/blog-7-patterns.md`):
//!
//!   - `webhooks` — flags unverified Stripe / GitHub / Shopify / Slack webhooks
//!   - `hallucinated_packages` — flags AI-generated imports that don't exist on npm
//!
//! New checks are added as sibling modules and registered in the
//! `run_all_checks` pipeline in `lib.rs`.

pub mod ai_agent;
pub mod auth;
pub mod cors;
pub mod database;
pub mod hallucinated_packages;
pub mod secrets;
pub mod webhooks;
