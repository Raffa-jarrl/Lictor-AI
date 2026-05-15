//! Tauri IPC commands — the typed bridge between the Solid frontend and the
//! Rust backend.
//!
//! Every `#[tauri::command]` function here must be registered in `main.rs`'s
//! `invoke_handler` macro, and the frontend wrapper in `src/lib/tauri.ts`
//! must match the signature.

use crate::audit::{self, AuditDocument, AuditError};
use std::path::PathBuf;

/// Returns the version string from Cargo.toml. Used by the frontend's
/// header version badge and (eventually) the auto-updater check.
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Runs an audit against the given project folder and returns an
/// AUDIT.json-shaped document.
///
/// v0.1.0-pre.0: stubbed. Returns a hand-crafted demo result so the frontend
/// can render against real data shape. Real wiring to `lictor-core` lands
/// in the Oct 1 milestone (see lictor-studio-mvp-spec.md §7).
#[tauri::command]
pub fn run_audit(path: String) -> Result<AuditDocument, String> {
    audit::stub_audit(PathBuf::from(path)).map_err(|e: AuditError| e.to_string())
}

/// Reads an AUDIT.json file from disk and validates it against the v0.1
/// schema. Returns the parsed document or a descriptive error.
///
/// v0.1.0-pre.0: stub. Real implementation lands Nov 15 milestone.
#[tauri::command]
pub fn import_audit_json(path: String) -> Result<AuditDocument, String> {
    audit::import_audit_json(PathBuf::from(path)).map_err(|e: AuditError| e.to_string())
}

/// Writes an AuditDocument to disk as AUDIT.json (pretty-printed, UTF-8).
/// Returns the path it wrote to.
///
/// v0.1.0-pre.0: stub.
#[tauri::command]
pub fn export_audit_json(doc: AuditDocument) -> Result<String, String> {
    audit::export_audit_json(doc).map_err(|e: AuditError| e.to_string())
}
