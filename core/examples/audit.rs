//! End-to-end native CLI: audit a URL, write a markdown report.
//!
//! Run from the workspace root:
//!
//! ```bash
//! cargo run --example audit -- https://your-vibe-coded-app.com
//! cargo run --example audit -- https://example.com -o my-report.md
//! ```
//!
//! Native-only (uses `ureq` for HTTP). The same checks compile to WASM via
//! the workspace's `wasm` feature for use inside Lictor Shield.

use lictor_core::http::UreqFetch;
use lictor_core::{report, run_all_checks};
use std::env;
use std::process::ExitCode;
use std::time::SystemTime;

fn print_usage() {
    eprintln!(
        "Lictor Core v{} — audit an AI-built site\n\n\
         USAGE:\n    \
             cargo run --example audit -- <URL> [-o OUTPUT.md]\n\n\
         EXAMPLE:\n    \
             cargo run --example audit -- https://example.com -o report.md\n\n\
         The audit is read-only and rate-limited to 1 req/sec/host.",
        lictor_core::VERSION
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::from(if args.is_empty() { 2 } else { 0 });
    }

    let mut url: Option<String> = None;
    let mut output = "audit-report.md".to_string();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-o" | "--output" => {
                let Some(v) = iter.next() else {
                    eprintln!("ERROR: --output requires a path");
                    return ExitCode::from(2);
                };
                output = v.clone();
            }
            s if s.starts_with("--") || s.starts_with("-") => {
                eprintln!("ERROR: unknown flag: {s}");
                print_usage();
                return ExitCode::from(2);
            }
            s => {
                if url.is_some() {
                    eprintln!("ERROR: only one URL allowed");
                    return ExitCode::from(2);
                }
                url = Some(s.to_string());
            }
        }
    }

    let mut target = match url {
        Some(u) => u,
        None => {
            print_usage();
            return ExitCode::from(2);
        }
    };
    if !target.starts_with("http://") && !target.starts_with("https://") {
        target = format!("https://{target}");
    }

    eprintln!("Lictor Core v{}", lictor_core::VERSION);
    eprintln!("Target: {target}");
    eprintln!("Output: {output}");
    eprintln!();

    let fetcher = UreqFetch::new();
    let findings = run_all_checks(&target, &fetcher);

    let now_iso = format_now();
    let md = report::render_markdown(&target, &findings, &now_iso);
    if let Err(e) = std::fs::write(&output, md) {
        eprintln!("ERROR: could not write {output}: {e}");
        return ExitCode::from(1);
    }

    eprintln!();
    eprintln!("✓ wrote {output} ({} finding(s))", findings.len());
    ExitCode::from(0)
}

/// Pre-formatted timestamp for the report header. Native-only stdlib — we
/// avoid pulling `chrono` to keep dependencies minimal.
fn format_now() -> String {
    let secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYY-MM-DD HH:MM in UTC. Hand-rolled to avoid pulling chrono into core.
    let (y, mo, d, h, mi) = unix_to_ymdhm_utc(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC")
}

/// Tiny pure-Rust UTC date breakdown. Good enough for report headers.
fn unix_to_ymdhm_utc(mut secs: u64) -> (u32, u32, u32, u32, u32) {
    let mi = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    let mut days = (secs / 86_400) as u64;
    secs %= 86_400;
    let _ = secs;

    let mut year: u32 = 1970;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months_norm = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let months_leap = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let months = if is_leap(year) { months_leap } else { months_norm };
    let mut month: u32 = 1;
    for &m in &months {
        if days < m as u64 {
            break;
        }
        days -= m as u64;
        month += 1;
    }
    (year, month, (days as u32) + 1, h, mi)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
