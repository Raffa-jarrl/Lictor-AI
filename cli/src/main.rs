//! lictor — terminal audit for AI-built apps.
//!
//! CLI sibling of Lictor Studio. Same engine (lictor-core), different
//! surface. Designed for: CI integration, scripting, headless servers,
//! and developers who prefer `lictor audit .` to launching a GUI.
//!
//! Outputs to stdout in 3 formats:
//!   - default       — colored human-readable (terminal)
//!   - --json        — AUDIT.json v0.1 (machine-readable, pipe-friendly)
//!   - --markdown    — full report (paste into a PR comment)

use chrono::Utc;
use clap::{Parser, Subcommand};
use lictor_core::checks::{hallucinated_packages, secrets, webhooks};
use lictor_core::finding::{Category, Finding, Severity};
use lictor_core::http::{Fetch, Method, Response};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "lictor")]
#[command(version)]
#[command(about = "Security audit for AI-built apps", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a security audit on a project directory
    Audit {
        /// Path to audit (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(long, default_value = "human")]
        format: OutputFormat,

        /// Exit with non-zero status if findings ≥ this severity exist
        /// (none | low | medium | high | critical). Default: none (always exit 0).
        #[arg(long, default_value = "none")]
        fail_on: FailOn,

        /// Skip the npm-registry verification step in the hallucinated-package
        /// check. Faster, but won't detect packages that don't exist on npm.
        #[arg(long)]
        offline: bool,
    },

    /// Print the version
    Version,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    /// Colored terminal output (default)
    Human,
    /// AUDIT.json v0.1 (machine-readable)
    Json,
    /// Full markdown report (pasteable)
    Markdown,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
enum FailOn {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    fn threshold(&self) -> Option<Severity> {
        match self {
            FailOn::None => None,
            FailOn::Low => Some(Severity::Low),
            FailOn::Medium => Some(Severity::Medium),
            FailOn::High => Some(Severity::High),
            FailOn::Critical => Some(Severity::Critical),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => {
            println!("lictor {}", env!("CARGO_PKG_VERSION"));
            println!("lictor-core {}", lictor_core::VERSION);
            ExitCode::SUCCESS
        }
        Commands::Audit {
            path,
            format,
            fail_on,
            offline,
        } => run_audit(&path, &format, &fail_on, offline),
    }
}

fn run_audit(path: &Path, format: &OutputFormat, fail_on: &FailOn, offline: bool) -> ExitCode {
    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::from(2);
    }

    let started = std::time::Instant::now();
    let started_rfc = Utc::now().to_rfc3339();

    // Collect source files
    let files = collect_source_files(path);
    let declared_deps = read_declared_deps(path);
    let platform = detect_platform(path);

    // Run checks
    let mut findings: Vec<Finding> = Vec::new();

    // 1. Secrets
    for (file_path, content) in &files {
        let source_label = source_label_for(file_path);
        findings.extend(secrets::analyze_text(content, file_path, source_label));
    }

    // 2. Webhooks
    let no_fetch = NoopFetch;
    findings.extend(webhooks::run(&no_fetch, &files));

    // 3. Hallucinated packages (skip when offline)
    if !offline {
        // TODO: wire UreqFetch here for real npm verification
        // For v0.1.0-pre.0 the offline flag is the default behavior; npm
        // verification ships in v0.1.0 GA.
        let _ = declared_deps; // silence unused warning until wired
    }
    findings.extend(hallucinated_packages::run(
        &no_fetch,
        &files,
        &declared_deps,
    ));

    let elapsed_ms = started.elapsed().as_millis() as u64;

    // Render output
    match format {
        OutputFormat::Human => render_human(&findings, &files, &platform, elapsed_ms),
        OutputFormat::Json => render_json(
            &findings,
            path,
            &platform,
            &started_rfc,
            elapsed_ms,
            files.len(),
        ),
        OutputFormat::Markdown => render_markdown(&findings, &platform, elapsed_ms, files.len()),
    }

    // Exit-code based on fail-on threshold
    if let Some(threshold) = fail_on.threshold() {
        let has_at_or_above = findings.iter().any(|f| f.severity >= threshold);
        if has_at_or_above {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

// ── File-walker (same logic as Studio's collect_source_files) ─────────────

const SCAN_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "rs", "go", "rb", "php", "html", "htm",
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

fn collect_source_files(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut total: usize = 0;
    const MAX_BYTES: usize = 50 * 1024 * 1024;
    const MAX_FILE: usize = 2 * 1024 * 1024;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !SKIP_DIRS.contains(&e.file_name().to_str().unwrap_or("")))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !SCAN_EXTENSIONS.contains(&ext) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(entry.path()) else {
            continue;
        };
        if meta.len() as usize > MAX_FILE {
            continue;
        }
        if total + meta.len() as usize > MAX_BYTES {
            break;
        }
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            total += content.len();
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            files.push((rel, content));
        }
    }
    files
}

fn read_declared_deps(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Ok(content) = std::fs::read_to_string(root.join("package.json")) {
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

fn detect_platform(root: &Path) -> String {
    if root.join(".lovable.json").exists() {
        "lovable".to_string()
    } else if root.join(".bolt").is_dir() {
        "bolt".to_string()
    } else if root.join("vercel.json").exists() {
        "v0".to_string()
    } else if root.join(".replit").exists() {
        "replit".to_string()
    } else {
        "unknown".to_string()
    }
}

fn source_label_for(file_path: &str) -> &'static str {
    match Path::new(file_path).extension().and_then(|s| s.to_str()) {
        Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") => "JS bundle",
        Some("py") => ".py file",
        Some("env") => ".env file",
        Some("html" | "htm") => "page HTML",
        _ => "source file",
    }
}

// ── Renderers ─────────────────────────────────────────────────────────────

fn render_human(findings: &[Finding], files: &[(String, String)], platform: &str, elapsed_ms: u64) {
    use anstyle::*;

    let red = Style::new().fg_color(Some(AnsiColor::Red.into())).bold();
    let orange = Style::new().fg_color(Some(AnsiColor::Yellow.into())).bold();
    let yellow = Style::new().fg_color(Some(AnsiColor::Yellow.into()));
    let blue = Style::new().fg_color(Some(AnsiColor::Blue.into()));
    let gray = Style::new().fg_color(Some(AnsiColor::BrightBlack.into()));
    let bold = Style::new().bold();

    println!();
    println!(
        "{bold}Lictor audit{bold:#} · {} files · platform: {} · {}ms",
        files.len(),
        platform,
        elapsed_ms,
        bold = bold,
    );
    println!("{gray}{}{gray:#}", "─".repeat(60), gray = gray);

    if findings.is_empty() {
        println!();
        println!("  ✓ Clean. No findings.");
        println!();
        return;
    }

    // Severity histogram
    let mut counts = [0u32; 5];
    for f in findings {
        let idx = match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        counts[idx] += 1;
    }

    println!();
    println!(
        "  {red}🔴 {}{red:#}  {orange}🟠 {}{orange:#}  {yellow}🟡 {}{yellow:#}  {blue}🔵 {}{blue:#}  {gray}⚪ {}{gray:#}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
        red = red,
        orange = orange,
        yellow = yellow,
        blue = blue,
        gray = gray,
    );
    println!();

    // List findings, severity-sorted
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    for (i, f) in sorted.iter().enumerate() {
        let (icon, style) = severity_marker(f.severity);
        let icon_styled = format!("{style}{icon}{style:#}", style = style);
        println!("  {} {bold}{}{bold:#}", icon_styled, f.title, bold = bold);
        if !f.where_found.is_empty() {
            println!("    {gray}{}{gray:#}", f.where_found, gray = gray);
        }
        // Wrap detail at 80 cols-ish
        for line in wrap_text(&f.detail, 72) {
            println!("    {}", line);
        }
        if !f.remediation.is_empty() {
            println!();
            println!("    {bold}Fix:{bold:#} {}", f.remediation, bold = bold);
        }
        if i + 1 < sorted.len() {
            println!();
        }
    }
    println!();
    println!("{gray}{}{gray:#}", "─".repeat(60), gray = gray,);
    println!(
        "  Run {bold}lictor audit . --format markdown{bold:#} for a paste-friendly report.",
        bold = bold,
    );
    println!(
        "  Run {bold}lictor audit . --format json{bold:#} for AUDIT.json output.",
        bold = bold,
    );
    println!();
}

fn severity_marker(s: Severity) -> (&'static str, anstyle::Style) {
    use anstyle::*;
    match s {
        Severity::Critical => (
            "🔴",
            Style::new().fg_color(Some(AnsiColor::Red.into())).bold(),
        ),
        Severity::High => (
            "🟠",
            Style::new().fg_color(Some(AnsiColor::Yellow.into())).bold(),
        ),
        Severity::Medium => ("🟡", Style::new().fg_color(Some(AnsiColor::Yellow.into()))),
        Severity::Low => ("🔵", Style::new().fg_color(Some(AnsiColor::Blue.into()))),
        Severity::Info => (
            "⚪",
            Style::new().fg_color(Some(AnsiColor::BrightBlack.into())),
        ),
    }
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

// ── JSON renderer (AUDIT.json v0.1 shape) ────────────────────────────────

#[derive(Serialize)]
struct AuditDocument<'a> {
    spec_version: &'static str,
    tool: ToolInfo<'a>,
    target: TargetInfo<'a>,
    audit: AuditMeta<'a>,
    summary: SummaryCounts,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct ToolInfo<'a> {
    name: &'static str,
    version: &'a str,
    vendor: &'static str,
}

#[derive(Serialize)]
struct TargetInfo<'a> {
    #[serde(rename = "type")]
    target_type: &'static str,
    url_or_path: String,
    platform_fingerprint: &'a str,
}

#[derive(Serialize)]
struct AuditMeta<'a> {
    started: &'a str,
    duration_ms: u64,
    checks_run: u32,
    file_count: u32,
}

#[derive(Serialize)]
struct SummaryCounts {
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
    total: u32,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    id: String,
    severity: &'static str,
    category: &'static str,
    title: &'a str,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'a str>,
}

fn render_json(
    findings: &[Finding],
    path: &Path,
    platform: &str,
    started: &str,
    elapsed_ms: u64,
    file_count: usize,
) {
    let mut counts = SummaryCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: findings.len() as u32,
    };
    for f in findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }

    let json_findings: Vec<JsonFinding> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let (file_path, _line) = split_where(&f.where_found);
            JsonFinding {
                id: format!("L-{:04}", i + 1),
                severity: severity_str(f.severity),
                category: category_str(f.category),
                title: &f.title,
                summary: &f.detail,
                file_path,
                fix: if f.remediation.is_empty() {
                    None
                } else {
                    Some(&f.remediation)
                },
            }
        })
        .collect();

    let doc = AuditDocument {
        spec_version: "0.1",
        tool: ToolInfo {
            name: "lictor",
            version: env!("CARGO_PKG_VERSION"),
            vendor: "lictor-ai.com",
        },
        target: TargetInfo {
            target_type: "repository",
            url_or_path: path.display().to_string(),
            platform_fingerprint: platform,
        },
        audit: AuditMeta {
            started,
            duration_ms: elapsed_ms,
            checks_run: 3,
            file_count: file_count as u32,
        },
        summary: counts,
        findings: json_findings,
    };

    match serde_json::to_string_pretty(&doc) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("error serializing JSON: {}", e),
    }
}

fn render_markdown(findings: &[Finding], platform: &str, elapsed_ms: u64, file_count: usize) {
    println!("# Lictor audit report\n");
    println!("- **Platform**: {}", platform);
    println!("- **Files audited**: {}", file_count);
    println!("- **Duration**: {} ms", elapsed_ms);
    println!("- **Findings**: {}\n", findings.len());

    if findings.is_empty() {
        println!("✅ Clean. No findings.\n");
        return;
    }

    // Severity histogram
    let mut counts = [0u32; 5];
    for f in findings {
        let idx = match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        counts[idx] += 1;
    }
    println!("## Summary\n");
    println!("| Severity | Count |");
    println!("|---|---|");
    println!("| 🔴 Critical | {} |", counts[0]);
    println!("| 🟠 High | {} |", counts[1]);
    println!("| 🟡 Medium | {} |", counts[2]);
    println!("| 🔵 Low | {} |", counts[3]);
    println!("| ⚪ Info | {} |\n", counts[4]);

    println!("## Findings\n");
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    for (i, f) in sorted.iter().enumerate() {
        println!(
            "### {}. {} {}\n",
            i + 1,
            severity_emoji(f.severity),
            f.title
        );
        if !f.where_found.is_empty() {
            println!("**Where**: `{}`\n", f.where_found);
        }
        println!("{}\n", f.detail);
        if !f.remediation.is_empty() {
            println!("**Fix**: {}\n", f.remediation);
        }
    }

    println!("---\n");
    println!(
        "Generated by [Lictor](https://lictor-ai.com) {}. Free, open source, Apache 2.0.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn severity_emoji(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 CRITICAL",
        Severity::High => "🟠 HIGH",
        Severity::Medium => "🟡 MEDIUM",
        Severity::Low => "🔵 LOW",
        Severity::Info => "⚪ INFO",
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn category_str(c: Category) -> &'static str {
    match c {
        Category::Secrets => "secrets",
        Category::Database => "database",
        Category::Auth => "auth",
        Category::Cors => "cors",
        Category::AiAgent => "ai-agent",
        Category::General => "other",
    }
}

fn split_where(where_found: &str) -> (Option<String>, Option<u32>) {
    if let Some((p, l)) = where_found.rsplit_once(':') {
        if let Ok(line) = l.parse::<u32>() {
            return (Some(p.to_string()), Some(line));
        }
    }
    if where_found.is_empty() {
        (None, None)
    } else {
        (Some(where_found.to_string()), None)
    }
}

// ── No-op Fetch (offline mode) ────────────────────────────────────────────

struct NoopFetch;

impl Fetch for NoopFetch {
    fn fetch(&self, _url: &str, _method: Method) -> Result<Response, lictor_core::Error> {
        Err(lictor_core::Error::Http("CLI offline mode".to_string()))
    }
}
