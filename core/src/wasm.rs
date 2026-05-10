//! WASM bindings for browser-side use (Lictor Shield).
//!
//! Exposes pure static-analysis entry points so the browser can:
//!   1. Do its own fetches (it has the `fetch` API + permissions)
//!   2. Pass response bodies / headers into WASM for pattern matching
//!   3. Get back a `Vec<Finding>` serialized as JS values
//!
//! Live HTTP probing is the browser's job. WASM stays pure.

#![cfg(feature = "wasm")]

use crate::checks::{ai_agent, auth, cors, database, secrets};
use crate::finding::Finding;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct WrappedFindings {
    findings: Vec<Finding>,
}

fn to_js(findings: Vec<Finding>) -> JsValue {
    serde_wasm_bindgen::to_value(&WrappedFindings { findings }).unwrap_or(JsValue::NULL)
}

/// Library version (for the Shield extension's About panel).
#[wasm_bindgen]
pub fn version() -> String {
    crate::VERSION.to_string()
}

/// Scan a text blob (page HTML, JS bundle body, .env file content) for
/// hardcoded secret patterns. Returns `{ findings: Finding[] }`.
#[wasm_bindgen]
pub fn analyze_secrets(text: &str, where_found: &str, source_label: &str) -> JsValue {
    to_js(secrets::analyze_text(text, where_found, source_label))
}

/// Build a Finding for a sensitive file (e.g. `.env`) that returned 200.
/// Returns `{ findings: Finding[] }` with one entry, for uniform JS handling.
#[wasm_bindgen]
pub fn analyze_exposed_file(path: &str, full_url: &str, body_len: usize) -> JsValue {
    to_js(vec![secrets::finding_for_exposed_file(
        path, full_url, body_len,
    )])
}

/// Extract Supabase project URLs from a haystack (HTML+JS combined).
#[wasm_bindgen]
pub fn extract_supabase_hosts(haystack: &str) -> Vec<JsValue> {
    database::extract_supabase_hosts(haystack)
        .into_iter()
        .map(JsValue::from)
        .collect()
}

/// Extract Firebase RTDB URLs from a haystack.
#[wasm_bindgen]
pub fn extract_firebase_hosts(haystack: &str) -> Vec<JsValue> {
    database::extract_firebase_hosts(haystack)
        .into_iter()
        .map(JsValue::from)
        .collect()
}

/// Classify a Supabase REST schema probe response. Returns one of
/// `"schema_open"` | `"auth_enforced"` | `"inconclusive"`.
#[wasm_bindgen]
pub fn classify_supabase_probe(status: u16, body: &[u8]) -> String {
    match database::classify_supabase_probe(status, body) {
        database::SupabaseProbeStatus::SchemaOpen => "schema_open".to_string(),
        database::SupabaseProbeStatus::AuthEnforced => "auth_enforced".to_string(),
        database::SupabaseProbeStatus::Inconclusive => "inconclusive".to_string(),
    }
}

/// Build a finding for an open Supabase REST schema.
#[wasm_bindgen]
pub fn finding_supabase_schema_open(supabase_host: &str, rest_url: &str) -> JsValue {
    to_js(vec![database::finding_supabase_schema_open(
        supabase_host,
        rest_url,
    )])
}

/// Build a finding for a Supabase project with RLS appearing active.
#[wasm_bindgen]
pub fn finding_supabase_auth_enforced(supabase_host: &str, rest_url: &str, status: u16) -> JsValue {
    to_js(vec![database::finding_supabase_auth_enforced(
        supabase_host,
        rest_url,
        status,
    )])
}

/// Build a finding for a publicly-readable Firebase RTDB.
#[wasm_bindgen]
pub fn finding_firebase_open(firebase_host: &str, probe_url: &str) -> JsValue {
    to_js(vec![database::finding_firebase_open(
        firebase_host,
        probe_url,
    )])
}

/// Analyze an unauthenticated API response. Empty array if not flag-worthy.
#[wasm_bindgen]
pub fn analyze_unauth_api(
    path: &str,
    full_url: &str,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> JsValue {
    let findings =
        database::analyze_unauth_api_response(path, full_url, status, content_type, body)
            .map(|f| vec![f])
            .unwrap_or_default();
    to_js(findings)
}

/// Classify a landing page's auth surface. Returns `"present"` | `"absent"`.
#[wasm_bindgen]
pub fn classify_login_surface(html: &str) -> String {
    match auth::analyze_landing_html(html) {
        auth::LoginSurface::Present => "present".to_string(),
        auth::LoginSurface::Absent => "absent".to_string(),
    }
}

/// Build the "no login surface" finding.
#[wasm_bindgen]
pub fn finding_no_login_surface(base_url: &str) -> JsValue {
    to_js(vec![auth::finding_no_login_surface(base_url)])
}

/// Build the "admin path open" finding for a probed path that returned 200.
#[wasm_bindgen]
pub fn finding_admin_path_open(path: &str, full_url: &str) -> JsValue {
    to_js(vec![auth::finding_admin_path_open(path, full_url)])
}

/// Classify a single endpoint's CORS posture. Returns one of
/// `"star_with_credentials"` | `"star_only"` | `"clean"` | `"skip"`.
#[wasm_bindgen]
pub fn classify_cors(status: u16, allow_origin: &str, allow_credentials: &str) -> String {
    use cors::CorsClassification::*;
    match cors::analyze_cors_headers(status, allow_origin, allow_credentials) {
        StarWithCredentials => "star_with_credentials".to_string(),
        StarOnly => "star_only".to_string(),
        Clean => "clean".to_string(),
        Skip => "skip".to_string(),
    }
}

/// Build the high-severity CORS misconfiguration finding.
#[wasm_bindgen]
pub fn finding_cors_misconfigured(path: &str, full_url: &str) -> JsValue {
    to_js(vec![cors::finding_cors_misconfigured(path, full_url)])
}

/// Build the info-level CORS-allows-any-origin finding.
#[wasm_bindgen]
pub fn finding_cors_origin_star(path: &str, full_url: &str) -> JsValue {
    to_js(vec![cors::finding_cors_origin_star(path, full_url)])
}

/// Detect AI-agent fingerprints in HTML and return the appropriate finding.
/// Returns `{ findings: Finding[] }` with exactly one entry (info if none, medium if any).
#[wasm_bindgen]
pub fn analyze_ai_agent(html: &str, base_url: &str) -> JsValue {
    let signals = ai_agent::detect_signals(html);
    let f = if signals.is_empty() {
        ai_agent::finding_no_agent(base_url)
    } else {
        ai_agent::finding_for_signals(&signals, base_url)
    };
    to_js(vec![f])
}

/// Constants the Shield content-script needs (so they live in one place).
#[wasm_bindgen]
pub fn sensitive_file_probes() -> Vec<JsValue> {
    secrets::SENSITIVE_FILE_PROBES
        .iter()
        .map(|s| JsValue::from(*s))
        .collect()
}

#[wasm_bindgen]
pub fn admin_probes() -> Vec<JsValue> {
    auth::ADMIN_PROBES
        .iter()
        .map(|s| JsValue::from(*s))
        .collect()
}

#[wasm_bindgen]
pub fn cors_api_paths() -> Vec<JsValue> {
    cors::API_PATHS.iter().map(|s| JsValue::from(*s)).collect()
}

#[wasm_bindgen]
pub fn database_api_paths() -> Vec<JsValue> {
    database::API_PATHS
        .iter()
        .map(|s| JsValue::from(*s))
        .collect()
}
