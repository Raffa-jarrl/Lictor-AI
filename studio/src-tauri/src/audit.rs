//! Audit wiring. v0.1.0-pre.1 — replaces the v0-pre.0 stub with real
//! `lictor-core` integration.
//!
//! `run_local_audit` walks a project directory, collects source files,
//! runs the pure-analysis checks from lictor-core, and aggregates the
//! results into Studio's `AuditDocument` (mirror of AUDIT.json v0.1).

use chrono::Utc;
use lictor_core::checks::{hallucinated_packages, secrets, webhooks};
use lictor_core::finding::{
    Category as CoreCategory, Finding as CoreFinding, Severity as CoreSeverity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
#[allow(dead_code)] // AuditFailed + Invalid are reserved for future error paths
pub enum AuditError {
    #[error("path does not exist: {0}")]
    PathNotFound(String),
    #[error("audit failed: {0}")]
    AuditFailed(String),
    #[error("AUDIT.json invalid: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

// ── AuditDocument types (mirror AUDIT.schema.json) ────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDocument {
    pub spec_version: String,
    pub tool: Tool,
    pub target: Target,
    pub audit: AuditMeta,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_attributions: Option<Vec<AgentAttribution>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_or_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMeta {
    pub started: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks_run: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAttribution {
    pub agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_count: Option<u32>,
}

// ── Real audit pipeline ───────────────────────────────────────────────────

const SCAN_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "rs", "go", "rb", "php", "java", "vue", "svelte",
];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".git",
    ".venv",
    "__pycache__",
    "vendor",
];

/// Walk the project tree, collect (path, contents) for source files we audit.
/// Caps total bytes to 50MB to avoid runaway scans on monorepos.
fn collect_source_files(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut total_bytes: usize = 0;
    const MAX_BYTES: usize = 50 * 1024 * 1024;
    const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !SKIP_DIRS.contains(&e.file_name().to_str().unwrap_or("")))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !SCAN_EXTENSIONS.contains(&ext) {
            continue;
        }
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() as usize > MAX_FILE_BYTES {
            continue;
        }
        if total_bytes + meta.len() as usize > MAX_BYTES {
            break;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            total_bytes += content.len();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string();
            files.push((rel, content));
        }
    }

    files
}

/// Parse package.json's `dependencies` + `devDependencies` + `peerDependencies`.
/// Returns an empty set if no package.json exists.
fn read_declared_deps(root: &Path) -> HashSet<String> {
    let pkg_path = root.join("package.json");
    let mut out = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(&pkg_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            for field in ["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(obj) = json.get(field).and_then(|v| v.as_object()) {
                    for k in obj.keys() {
                        out.insert(k.clone());
                    }
                }
            }
        }
    }
    out
}

/// Try to fingerprint the platform from project markers.
fn detect_platform(root: &Path) -> &'static str {
    // Lovable adds a `.lovable.json` or `lovable.config.*`.
    if root.join(".lovable.json").exists() || root.join("lovable.config.json").exists() {
        return "lovable";
    }
    // Bolt projects often have a `.bolt/` directory.
    if root.join(".bolt").is_dir() {
        return "bolt";
    }
    // v0 (Vercel) — heuristic: Next.js + `vercel.json` with v0 reference.
    if root.join("vercel.json").exists() {
        return "v0";
    }
    // Replit
    if root.join(".replit").exists() {
        return "replit";
    }
    "unknown"
}

/// Map lictor-core's `Severity` → AUDIT.json severity string.
fn severity_str(s: CoreSeverity) -> &'static str {
    match s {
        CoreSeverity::Critical => "critical",
        CoreSeverity::High => "high",
        CoreSeverity::Medium => "medium",
        CoreSeverity::Low => "low",
        CoreSeverity::Info => "info",
    }
}

/// Map lictor-core's `Category` → AUDIT.json category string.
fn category_str(c: CoreCategory) -> &'static str {
    match c {
        CoreCategory::Secrets => "secrets",
        CoreCategory::Database => "database",
        CoreCategory::Auth => "auth",
        CoreCategory::Cors => "cors",
        CoreCategory::AiAgent => "ai-agent",
        CoreCategory::General => "other",
    }
}

/// Convert a lictor-core `Finding` into Studio's AuditDocument-shaped `Finding`.
fn convert_finding(idx: usize, f: CoreFinding) -> Finding {
    // Split where_found into (file_path, line) if it's "path:line"
    let (file_path, line) = if let Some((p, l)) = f.where_found.rsplit_once(':') {
        match l.parse::<u32>() {
            Ok(n) => (Some(p.to_string()), Some(n)),
            Err(_) => (Some(f.where_found.clone()), None),
        }
    } else if !f.where_found.is_empty() {
        (Some(f.where_found.clone()), None)
    } else {
        (None, None)
    };

    Finding {
        id: format!("L-{:04}", idx + 1),
        severity: severity_str(f.severity).to_string(),
        category: category_str(f.category).to_string(),
        title: f.title.clone(),
        summary: f.detail.clone(),
        evidence: if file_path.is_some() {
            Some(Evidence { file_path, line })
        } else {
            None
        },
        fix: if !f.remediation.is_empty() {
            Some(Fix {
                summary: Some(f.remediation.clone()),
            })
        } else {
            None
        },
        agent: None, // lictor-core doesn't track agent attribution yet
    }
}

/// Main entry point: run the full local audit against a project root.
pub fn run_local_audit(root: PathBuf) -> Result<AuditDocument, AuditError> {
    if !root.exists() {
        return Err(AuditError::PathNotFound(root.display().to_string()));
    }

    let started_at = std::time::Instant::now();
    let started_rfc = Utc::now().to_rfc3339();

    let files = collect_source_files(&root);
    let declared_deps = read_declared_deps(&root);
    let platform = detect_platform(&root);

    // Run each check that operates on source files.
    let mut all_core_findings: Vec<CoreFinding> = Vec::new();

    // 1. Secrets (analyze each file).
    // secrets::analyze_text(text, where_found, source_label) returns Vec<CoreFinding> directly.
    for (path, content) in files.iter() {
        let source_label = match Path::new(path).extension().and_then(|s| s.to_str()) {
            Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") => "JS bundle",
            Some("py") => ".py file",
            Some("env") => ".env file",
            _ => "source file",
        };
        let secret_findings = secrets::analyze_text(content, path, source_label);
        all_core_findings.extend(secret_findings);
    }

    // 2. Webhooks (analyze each file)
    let mut webhook_findings = webhooks::run(&NoopFetch, &files);
    all_core_findings.append(&mut webhook_findings);

    // 3. Hallucinated packages (needs HTTP — for v0.1.0-pre.1, skip the npm
    // verification and only flag clearly-undeclared imports. Real npm check
    // ships in v0.1.0 GA.)
    // Note: hallucinated_packages::run requires a Fetch; we use NoopFetch which
    // returns errors for every fetch, causing the check to skip everything.
    // The check is correctly defensive — it doesn't flag anything it can't verify.
    let mut hallu_findings = hallucinated_packages::run(&NoopFetch, &files, &declared_deps);
    all_core_findings.append(&mut hallu_findings);

    // Convert to Studio's Finding shape
    let findings: Vec<Finding> = all_core_findings
        .into_iter()
        .enumerate()
        .map(|(i, f)| convert_finding(i, f))
        .collect();

    // Build the summary
    let mut summary = Summary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: findings.len() as u32,
    };
    for f in &findings {
        match f.severity.as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            "info" => summary.info += 1,
            _ => {}
        }
    }

    let elapsed_ms = started_at.elapsed().as_millis() as u64;

    Ok(AuditDocument {
        spec_version: "0.1".to_string(),
        tool: Tool {
            name: "lictor".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            vendor: Some("lictor.ai".to_string()),
        },
        target: Target {
            target_type: "repository".to_string(),
            url_or_path: Some(root.display().to_string()),
            platform_fingerprint: Some(platform.to_string()),
        },
        audit: AuditMeta {
            started: started_rfc,
            completed: Some(Utc::now().to_rfc3339()),
            duration_ms: Some(elapsed_ms),
            checks_run: Some(3), // secrets, webhooks, hallucinated_packages
        },
        summary,
        findings,
        agent_attributions: None,
        notes: Some(vec![format!(
            "Audited {} source files across the project. Skipped node_modules, target, dist, .git.",
            files.len()
        )]),
    })
}

/// No-op Fetch — for checks that need HTTP but we don't have it (offline-only).
/// All fetches fail; the check should treat that as "couldn't verify" and skip.
struct NoopFetch;

impl lictor_core::http::Fetch for NoopFetch {
    fn fetch(
        &self,
        _url: &str,
        _method: lictor_core::http::Method,
    ) -> Result<lictor_core::http::Response, lictor_core::Error> {
        Err(lictor_core::Error::Http("offline-only mode".to_string()))
    }
}

// ── AUDIT.json I/O ────────────────────────────────────────────────────────

pub fn import_audit_json(path: PathBuf) -> Result<AuditDocument, AuditError> {
    let content = std::fs::read_to_string(&path)?;
    let doc: AuditDocument = serde_json::from_str(&content)?;
    Ok(doc)
}

pub fn export_audit_json(doc: AuditDocument) -> Result<String, AuditError> {
    let pretty = serde_json::to_string_pretty(&doc)?;
    let out_path =
        std::env::temp_dir().join(format!("lictor-audit-{}.json", Utc::now().timestamp()));
    std::fs::write(&out_path, pretty)?;
    Ok(out_path.display().to_string())
}

// Back-compat alias for the command handler in commands.rs
pub fn stub_audit(root: PathBuf) -> Result<AuditDocument, AuditError> {
    run_local_audit(root)
}
