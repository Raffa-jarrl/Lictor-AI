//! Hallucinated-package check.
//!
//! AI coding assistants (Cursor, Claude Code, Copilot) sometimes generate
//! `import { X } from "package-name-that-does-not-exist"`. The package name
//! is plausible-shaped but doesn't exist on npm. Attackers have started
//! registering these hallucinated names to ship malware to anyone whose
//! AI assistant tries to install them.
//!
//! This check has two parts:
//!
//!   1. [`extract_imports`] — pure: scan source for `import` / `require` /
//!      `from ... import` statements. WASM-safe.
//!   2. [`run`] — full pipeline: for every import that's NOT a relative
//!      path AND NOT in `package.json` dependencies, query the npm
//!      registry to confirm existence. Native-only (needs HTTP).
//!
//! Strategy: false-positive aversion is critical. We only flag packages
//! that are (a) imported in source, (b) not listed in package.json's
//! dependencies, and (c) return 404 from the npm registry. All three
//! conditions must hold.

use crate::finding::{Category, Finding, Severity};
use crate::http::{Fetch, Method};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static IMPORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Matches imports of any shape: ES `import X from "pkg"`, bare `import "pkg"`,
    // CommonJS `require("pkg")` (anywhere — `const x = require(...)` works too),
    // dynamic `import("pkg")`, and Python `from pkg import X`.
    //
    // Group 1 captures the JS/TS specifier; group 2 captures the Python module.
    // Post-processing in `extract_imports` filters relative paths, node
    // built-ins, and trims subpaths (`pkg/sub` → `pkg`; `@scope/pkg/sub` →
    // `@scope/pkg`).
    Regex::new(
        r#"(?:(?:^|[\s=({,;])(?:import\s+[\w*{},\s]+\s+from\s+|import\s*\(?\s*|require\s*\(\s*)['"]([^'"]+)['"]|(?m)^\s*from\s+([\w\.]+)\s+import)"#,
    )
    .expect("valid import regex")
});

/// Extract all unique non-relative imports from a source file.
/// Filters out:
/// - Relative imports (`./foo`, `../bar`)
/// - Node built-ins (`fs`, `path`, etc.)
/// - Scoped packages where the scope alone is given (handled by callers)
pub fn extract_imports(source: &str) -> HashSet<String> {
    let mut imports = HashSet::new();

    for caps in IMPORT_REGEX.captures_iter(source) {
        // The regex has 2 alternation arms — TS/JS imports OR Python.
        let name = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());

        if let Some(name) = name {
            // Skip relative imports
            if name.starts_with('.') || name.starts_with('/') {
                continue;
            }
            // Skip node built-ins
            if is_node_builtin(name) {
                continue;
            }
            // For scoped packages (@scope/pkg), keep the full name
            // For unscoped, take only the top-level name (no subpaths)
            let pkg_name = if name.starts_with('@') {
                // @scope/pkg/subpath -> @scope/pkg
                name.splitn(3, '/').take(2).collect::<Vec<_>>().join("/")
            } else {
                // pkg/subpath -> pkg
                name.splitn(2, '/').next().unwrap_or(name).to_string()
            };

            imports.insert(pkg_name);
        }
    }

    imports
}

/// Returns true if the given name is a Node.js built-in module.
fn is_node_builtin(name: &str) -> bool {
    const BUILTINS: &[&str] = &[
        "assert",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dns",
        "events",
        "fs",
        "http",
        "https",
        "module",
        "net",
        "os",
        "path",
        "process",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "tls",
        "url",
        "util",
        "v8",
        "vm",
        "zlib",
        // Common Python built-ins / stdlib (Python sources too)
        "sys",
        "json",
        "datetime",
        "time",
        "re",
        "math",
        "random",
        "typing",
        "collections",
        "itertools",
        "functools",
    ];
    BUILTINS.contains(&name)
}

/// Query the npm registry for a package. Returns true if it exists,
/// false if 404, None if the registry was unreachable (don't flag in
/// that case — could be offline / firewall).
fn package_exists_on_npm<F: Fetch>(fetcher: &F, name: &str) -> Option<bool> {
    let url = format!("https://registry.npmjs.org/{}", urlencoding(name));
    match fetcher.fetch(&url, Method::Get) {
        Ok(resp) => {
            if resp.status == 200 {
                Some(true)
            } else if resp.status == 404 {
                Some(false)
            } else {
                // Other statuses (rate-limit, server error) — don't make
                // a determination
                None
            }
        }
        Err(_) => None,
    }
}

/// URL-encode a package name for the registry path.
/// (npm uses `%2F` for the `/` in scoped names.)
fn urlencoding(s: &str) -> String {
    s.replace('/', "%2F")
}

/// Full pipeline: scan all source files for imports, cross-reference
/// against package.json, query npm for any uncovered imports.
///
/// `file_listing` = (path, source) tuples
/// `declared_dependencies` = names from package.json's `dependencies` +
///                          `devDependencies` + `peerDependencies`
pub fn run<F: Fetch>(
    fetcher: &F,
    file_listing: &[(String, String)],
    declared_dependencies: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut all_imports: HashSet<String> = HashSet::new();

    // Collect every non-relative import across the project
    for (_, source) in file_listing {
        all_imports.extend(extract_imports(source));
    }

    // For each imported but undeclared package, check npm
    for pkg in all_imports.iter() {
        if declared_dependencies.contains(pkg) {
            continue;
        }

        match package_exists_on_npm(fetcher, pkg) {
            Some(false) => {
                // Hallucination confirmed: imported, undeclared, doesn't exist on npm
                let title = format!("Imported package '{}' does not exist on npm", pkg);
                let detail = format!(
                    "Your code imports '{}', but this package isn't listed in package.json AND \
                     doesn't exist on the npm registry. This is the canonical signature of an \
                     AI-hallucinated import. If an attacker registers this name, your next \
                     `npm install` will run their code.",
                    pkg
                );
                let remediation = format!(
                    "Either: (a) remove the import if the code doesn't need it, (b) find the \
                     correct existing package name your AI assistant meant, or (c) register \
                     '{}' yourself on npm if it's your own intended package.",
                    pkg
                );
                findings.push(
                    Finding::new(Severity::Critical, Category::Secrets, title)
                        .with_detail(detail)
                        .with_where(format!("imported from package: {}", pkg))
                        .with_remediation(remediation),
                );
            }
            Some(true) => {
                // Exists on npm but undeclared — that's a different category
                // of finding (potential supply-chain risk if the package
                // is added via a build step). Don't flag here; could be
                // flagged by a separate "undeclared dependency" check.
            }
            None => {
                // Couldn't determine — don't flag (avoid false positives
                // from registry outages)
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_js_imports() {
        let src = r#"
            import { useState } from "react";
            import Stripe from "stripe";
            import { wrap } from "@lictor/sentinel";
            import "./styles.css";
            const fs = require("fs");
            const mongoose = require("mongoose");
        "#;
        let imports = extract_imports(src);
        assert!(imports.contains("react"));
        assert!(imports.contains("stripe"));
        assert!(imports.contains("@lictor/sentinel"));
        assert!(imports.contains("mongoose"));
        // fs is a node builtin, should be filtered
        assert!(!imports.contains("fs"));
        // relative imports are filtered
        assert!(!imports.contains("./styles.css"));
    }

    #[test]
    fn extracts_python_imports() {
        let src = r#"
            import os
            from openai import OpenAI
            from langchain.agents import AgentExecutor
            import sys
        "#;
        let imports = extract_imports(src);
        assert!(imports.contains("openai"));
        // os, sys are stdlib, filtered
        assert!(!imports.contains("os"));
        assert!(!imports.contains("sys"));
    }

    #[test]
    fn scoped_packages_keep_full_name() {
        let src = r#"import { x } from "@anthropic-ai/sdk";"#;
        let imports = extract_imports(src);
        assert!(imports.contains("@anthropic-ai/sdk"));
        assert!(!imports.contains("@anthropic-ai"));
    }
}
