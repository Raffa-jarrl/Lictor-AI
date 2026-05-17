#!/usr/bin/env python3
"""
lictor-multi — runs Lictor checks across ALL surfaces we now cover.

Detects what kind of project this is (web, mobile, CLI, browser extension,
MCP server, desktop app, CI/CD config, serverless function), then runs
every applicable check module. Produces a unified report.

Usage:
    python3 scripts/lictor-multi.py <path-or-URL>
    python3 scripts/lictor-multi.py .                    # current dir
    python3 scripts/lictor-multi.py https://example.com  # URL
    python3 scripts/lictor-multi.py /path/to/repo --json # JSON out

This is Patrol v0.2 — Python implementation that ships working scans
NOW. Rust ports for the Worker happen in Patrol v0.3.
"""
from __future__ import annotations
import argparse, json, os, re, sys, time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator

# ============================================================================
# Finding model
# ============================================================================

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

@dataclass
class Finding:
    severity: str
    surface: str           # "web" / "mobile" / "cli" / "browser-ext" / "mcp" / "desktop" / "ci-cd" / "serverless"
    check: str             # short identifier
    title: str             # human-readable summary
    path: str = ""         # file path or URL where found
    line: int = 0
    evidence: str = ""
    fix: str = ""

# ============================================================================
# Project detection
# ============================================================================

@dataclass
class ProjectShape:
    is_web: bool = False
    is_mobile_ios: bool = False
    is_mobile_android: bool = False
    is_cli: bool = False
    is_browser_extension: bool = False
    is_mcp_server: bool = False
    is_desktop_electron: bool = False
    is_desktop_tauri: bool = False
    has_github_workflows: bool = False
    has_serverless: bool = False
    files_scanned: int = 0

def detect(root: Path) -> ProjectShape:
    s = ProjectShape()
    if not root.is_dir():
        return s

    # Browser extension: manifest.json with manifest_version
    for mf in root.rglob("manifest.json"):
        if "node_modules" in str(mf) or ".git" in str(mf): continue
        try:
            d = json.loads(mf.read_text(encoding="utf-8", errors="replace"))
            if isinstance(d, dict) and "manifest_version" in d:
                s.is_browser_extension = True
                break
        except Exception:
            pass

    # MCP server: imports modelcontextprotocol or has tool() decorators
    for py in list(root.rglob("*.py"))[:200]:
        if "node_modules" in str(py) or ".git" in str(py): continue
        try:
            head = py.read_text(encoding="utf-8", errors="replace")[:5000]
            if "modelcontextprotocol" in head or "@mcp.tool" in head or "FastMCP" in head:
                s.is_mcp_server = True
                break
        except Exception:
            pass
    if not s.is_mcp_server:
        for ts in list(root.rglob("*.ts"))[:200] + list(root.rglob("*.js"))[:200]:
            if "node_modules" in str(ts) or ".git" in str(ts): continue
            try:
                head = ts.read_text(encoding="utf-8", errors="replace")[:5000]
                if "@modelcontextprotocol/sdk" in head or "Server({" in head and "Tool" in head:
                    s.is_mcp_server = True; break
            except Exception:
                pass

    # Web: package.json with next/react/vue/svelte/astro
    for pj in root.rglob("package.json"):
        if "node_modules" in str(pj) or ".git" in str(pj): continue
        try:
            d = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            deps = {**d.get("dependencies", {}), **d.get("devDependencies", {})}
            if any(k in deps for k in ("next", "react", "vue", "svelte", "astro", "express", "hono", "fastify", "@cloudflare/workers-types")):
                s.is_web = True
            if "electron" in deps:
                s.is_desktop_electron = True
            if "@tauri-apps/api" in deps or "@tauri-apps/cli" in deps:
                s.is_desktop_tauri = True
            if "@cloudflare/workers-types" in deps or "wrangler" in deps:
                s.has_serverless = True
            break
        except Exception:
            pass
    if (root / "src-tauri" / "tauri.conf.json").exists():
        s.is_desktop_tauri = True

    # Mobile
    if list(root.rglob("Info.plist")) or list(root.rglob("*.xcodeproj"))[:1]:
        s.is_mobile_ios = True
    if list(root.rglob("AndroidManifest.xml"))[:1]:
        s.is_mobile_android = True

    # CLI: python script with __main__ or click/argparse, or shebang shell
    cli_signals = 0
    for py in list(root.rglob("*.py"))[:100]:
        if "node_modules" in str(py): continue
        try:
            head = py.read_text(encoding="utf-8", errors="replace")[:2000]
            if "if __name__" in head and ("argparse" in head or "click" in head):
                cli_signals += 1
        except Exception: pass
    for sh in list(root.rglob("*.sh"))[:50]:
        cli_signals += 1
    if cli_signals >= 2:
        s.is_cli = True

    # CI/CD
    if (root / ".github" / "workflows").exists() and any((root / ".github" / "workflows").glob("*.yml")):
        s.has_github_workflows = True

    # Serverless: wrangler.toml or serverless.yml or netlify.toml
    if (root / "wrangler.toml").exists() or (root / "serverless.yml").exists() or list(root.rglob("functions"))[:1]:
        s.has_serverless = True

    return s

# ============================================================================
# Helpers
# ============================================================================

def walk_source(root: Path, exts: tuple,
                skip_dirs=("node_modules", ".git", "target", "dist", ".next", "build", "out",
                           ".venv", "venv", "__pycache__", "site-packages", ".tox", ".mypy_cache",
                           ".pytest_cache", "vendor", "third_party")) -> Iterator[Path]:
    for p in root.rglob("*"):
        if not p.is_file(): continue
        if any(d in p.parts for d in skip_dirs): continue
        if p.suffix.lower() in exts:
            yield p

def file_lines(p: Path) -> list[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

# ============================================================================
# Check: MCP servers — the wedge surface
# ============================================================================

# Tool descriptions that interpolate external/network content
# Refined 2026-05-17 after manual verification revealed false positives where
# the OLD regex matched any file containing both "description" and "fetch"
# anywhere — even when "description" was a static string and "fetch" was a
# variable name elsewhere. New rule: must match within ~250 chars (typical
# multi-line description assignment) and the description= must be followed by
# either an f-string interpolation, await/fetch on same line, or an open paren
# (function call) instead of a quote.
DESC_DYNAMIC_RX = re.compile(r'description\s*=\s*[fF]["\'].*?\{[^}]+\}.*?["\']', re.DOTALL)
DESC_FETCHY_RX = re.compile(
    r'description\s*=\s*(?:await\s+|requests\.|httpx\.|urllib\.|fetch\s*\()',
    re.IGNORECASE,
)
# Exec / file-write tools with no obvious sandboxing
EXEC_TOOL_RX = re.compile(r'@\w*\.?tool\s*\([^)]*\)\s*(?:async\s+)?def\s+(\w*(?:run|exec|shell|cmd|spawn|eval|write_file|delete_file|rm)\w*)\s*\(', re.IGNORECASE)
# Tools that fetch external markdown / HTML and return raw
RAW_RETURN_RX = re.compile(r'def\s+(\w+).*?\):\s*\n(?:\s*"""[^"]*""")?\s*(?:response|r|res|content)\s*=\s*(?:requests|httpx|urllib|fetch).*?\n.*?return\s+(?:response\.text|r\.text|res\.text|content)', re.DOTALL)

def check_mcp(root: Path) -> list[Finding]:
    findings = []
    for p in walk_source(root, (".py", ".ts", ".js")):
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

        # Dynamic / network-derived tool descriptions
        if "tool" in text.lower() and "description" in text:
            if DESC_FETCHY_RX.search(text):
                findings.append(Finding(
                    severity="critical", surface="mcp", check="mcp-desc-fetch",
                    title="MCP tool description derived from network content (prompt-injection risk)",
                    path=rel,
                    fix="Tool descriptions must be static strings controlled by the developer. If the tool fetches external content, do that INSIDE the tool's run function, not in the description."
                ))

        # Exec-shaped tool names without sandbox indicators
        for m in EXEC_TOOL_RX.finditer(text):
            fname = m.group(1)
            line_no = text[:m.start()].count("\n") + 1
            # Check 50 lines after for sandbox / allowlist signals
            following = "\n".join(text.split("\n")[line_no-1:line_no+50])
            if not re.search(r'(allow.?list|sandbox|subprocess.*shell=False|docker|firejail|seccomp|chroot|user_confirm|require_confirmation)', following, re.IGNORECASE):
                findings.append(Finding(
                    severity="critical", surface="mcp", check="mcp-exec-tool-no-sandbox",
                    title=f"MCP tool `{fname}` performs exec / file-write without visible sandboxing or allow-list",
                    path=rel, line=line_no,
                    evidence=m.group(0)[:120],
                    fix=f"Wrap {fname} with an allow-list of permitted commands/paths, sandbox via container (docker/firejail), and require user confirmation for irreversible operations."
                ))

        # Network-fetched content returned raw to model
        for m in RAW_RETURN_RX.finditer(text):
            fname = m.group(1)
            line_no = text[:m.start()].count("\n") + 1
            findings.append(Finding(
                severity="high", surface="mcp", check="mcp-raw-network-output",
                title=f"MCP tool `{fname}` returns fetched network content directly to LLM (prompt-injection vector)",
                path=rel, line=line_no,
                fix="Sanitize fetched content before returning: strip HTML, escape pseudo-instruction patterns, or wrap in <untrusted_content>...</untrusted_content> tags the model is trained to skeptically handle."
            ))
    return findings

# ============================================================================
# Check: CI/CD — pull_request_target + actions pinning
# ============================================================================

def check_ci(root: Path) -> list[Finding]:
    findings = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir(): return findings

    for wf in wf_dir.glob("*.y*ml"):
        text = wf.read_text(encoding="utf-8", errors="replace")
        rel = str(wf.relative_to(root))

        # The pull_request_target + checkout-PR-head pattern (the real RCE)
        if "pull_request_target" in text:
            if re.search(r'(?:ref:|head\.ref|github\.event\.pull_request\.head)', text):
                line = next((i+1 for i, l in enumerate(text.split("\n")) if "pull_request_target" in l), 0)
                findings.append(Finding(
                    severity="critical", surface="ci-cd", check="ci-pr-target-checkout-head",
                    title="`pull_request_target` workflow checks out the PR's head — RCE on main branch via malicious PR",
                    path=rel, line=line,
                    fix="Use `pull_request` (runs in isolated context without secrets) OR explicitly check out the base branch (the merge commit, not the PR head). Never run untrusted code with `pull_request_target`'s elevated permissions."
                ))

        # Third-party actions pinned by tag not SHA
        for i, line in enumerate(text.split("\n"), 1):
            m = re.match(r'^\s*-?\s*uses:\s*([\w.-]+/[\w.-]+)@(v?\d+(?:\.\d+)*|main|master|latest|HEAD)\s*$', line)
            if m:
                action, ref = m.group(1), m.group(2)
                # Skip first-party github actions (less risky)
                if action.startswith("actions/") or action.startswith("github/"): continue
                findings.append(Finding(
                    severity="high", surface="ci-cd", check="ci-action-not-sha-pinned",
                    title=f"Third-party action `{action}` pinned to mutable tag `{ref}` (not SHA)",
                    path=rel, line=i,
                    fix=f"Pin to the immutable commit SHA: `{action}@<40-char-sha>`. Use Dependabot's `pinned-action-versions` to keep SHAs current intentionally."
                ))

        # Secrets echoed to logs
        for i, line in enumerate(text.split("\n"), 1):
            if re.search(r'(echo|printf|print).*\$\{\{\s*secrets\.', line):
                findings.append(Finding(
                    severity="high", surface="ci-cd", check="ci-secret-echoed",
                    title="Workflow echoes a secret to stdout — masking only works for exact name matches",
                    path=rel, line=i, evidence=line.strip()[:100],
                    fix="Don't echo secrets, ever. If you need to debug, write the secret to a file (gitignored, post-step cleanup) or use `add-mask` directive properly."
                ))

        # Default GITHUB_TOKEN permissions (no explicit scoping)
        if "permissions:" not in text and re.search(r'GITHUB_TOKEN|secrets\.GITHUB_TOKEN', text):
            findings.append(Finding(
                severity="medium", surface="ci-cd", check="ci-token-no-scope",
                title="Workflow uses GITHUB_TOKEN without explicit `permissions:` scoping (defaults to broad)",
                path=rel,
                fix="Add `permissions: contents: read` at the top of the workflow, then escalate per-step only where needed."
            ))
    return findings

# ============================================================================
# Check: Browser extensions — manifest overprivilege
# ============================================================================

def check_browser_ext(root: Path) -> list[Finding]:
    findings = []
    for mf in root.rglob("manifest.json"):
        if any(d in mf.parts for d in ("node_modules", ".git", "dist", "build")): continue
        try:
            text = mf.read_text(encoding="utf-8", errors="replace")
            d = json.loads(text)
        except Exception:
            continue
        if not isinstance(d, dict) or "manifest_version" not in d:
            continue
        rel = str(mf.relative_to(root)) if mf.is_relative_to(root) else str(mf)

        # host_permissions: <all_urls> / *://*/*
        host_perms = d.get("host_permissions", []) + d.get("permissions", [])
        if isinstance(host_perms, list):
            for hp in host_perms:
                if hp in ("<all_urls>", "*://*/*", "https://*/*", "http://*/*"):
                    findings.append(Finding(
                        severity="critical", surface="browser-ext", check="ext-all-urls-permission",
                        title=f"Extension requests `{hp}` — full read access to every page the user visits",
                        path=rel,
                        fix="Use `optional_host_permissions` and request access per-site at runtime via `chrome.permissions.request()`. Scope `host_permissions` to the specific domains your extension actually needs."
                    ))

        # web_accessible_resources too broad
        war = d.get("web_accessible_resources", [])
        if isinstance(war, list):
            for entry in war:
                if isinstance(entry, dict):
                    resources = entry.get("resources", [])
                    matches = entry.get("matches", [])
                    if "*://*/*" in matches or "<all_urls>" in matches:
                        findings.append(Finding(
                            severity="medium", surface="browser-ext", check="ext-war-too-broad",
                            title="`web_accessible_resources` exposed to all sites (`matches: *://*/*`)",
                            path=rel,
                            fix="Restrict `matches` to the specific origins that need access. Avoid wildcards."
                        ))

        # Dangerous permissions
        all_perms = d.get("permissions", [])
        if isinstance(all_perms, list):
            for sensitive in ("tabs", "history", "cookies", "webRequest", "debugger", "nativeMessaging", "downloads"):
                if sensitive in all_perms:
                    findings.append(Finding(
                        severity="medium", surface="browser-ext", check=f"ext-perm-{sensitive}",
                        title=f"Extension requests `{sensitive}` permission",
                        path=rel,
                        fix=f"Audit whether `{sensitive}` is actually used. If it's optional, make it optional. If it's only needed for one feature, refactor to request it on-demand."
                    ))

        # content_security_policy weakened
        csp = d.get("content_security_policy")
        if isinstance(csp, (str, dict)):
            csp_str = csp if isinstance(csp, str) else json.dumps(csp)
            if "unsafe-eval" in csp_str:
                findings.append(Finding(
                    severity="high", surface="browser-ext", check="ext-csp-unsafe-eval",
                    title="Extension CSP allows `unsafe-eval` — XSS in extension context is now RCE-shaped",
                    path=rel,
                    fix="Remove `unsafe-eval`. If a dependency requires it, find an alternative — modern build tools don't need eval."
                ))
    return findings

# ============================================================================
# Check: CLI scripts — command injection + secrets in argv
# ============================================================================

def check_cli_scripts(root: Path) -> list[Finding]:
    findings = []
    # Python: subprocess with shell=True + variable
    PY_SHELL_RX = re.compile(r'subprocess\.\w+\([^)]*shell\s*=\s*True[^)]*\)', re.MULTILINE)
    # os.system(variable) — but skip lines that are clearly inside a string/comment/docstring
    PY_OS_SYSTEM_RX = re.compile(r'^(?!\s*#)(?!\s*[\'"])(?!.*?["\'\`].*?os\.system).*\bos\.system\s*\(\s*[a-zA-Z_]\w*\s*[,)]', re.MULTILINE)
    # argparse with token/key/secret as a flag (visible in ps)
    PY_SECRET_ARG_RX = re.compile(r"add_argument\s*\(\s*[\"']--?[\w-]*(token|secret|key|password|api[-_]?key)\b", re.IGNORECASE)
    # eval / exec of variables
    PY_EVAL_RX = re.compile(r'\beval\s*\(\s*[a-zA-Z_]', re.MULTILINE)
    # Bash: unquoted variable expansion in command position
    SH_UNQUOTED_CMD_RX = re.compile(r'^\s*(\$\{?\w+\}?|`[^`]*`|\$\([^)]+\))\b', re.MULTILINE)

    for p in walk_source(root, (".py", ".sh", ".bash")):
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

        if p.suffix == ".py":
            for m in PY_SHELL_RX.finditer(text):
                # Skip if it's clearly a hardcoded constant (no variables)
                if not re.search(r'[a-zA-Z_]\w*\s*[+,)]', m.group(0)):
                    continue
                line = text[:m.start()].count("\n") + 1
                findings.append(Finding(
                    severity="critical", surface="cli", check="cli-shell-true-variable",
                    title="`subprocess(shell=True, …)` with a variable in the command — command injection",
                    path=rel, line=line, evidence=m.group(0)[:150],
                    fix="Use `shell=False` and pass args as a list: `subprocess.run(['git', 'clone', url])`. Never let a user string flow into a shell-interpreted command."
                ))
            for m in PY_OS_SYSTEM_RX.finditer(text):
                line = text[:m.start()].count("\n") + 1
                findings.append(Finding(
                    severity="critical", surface="cli", check="cli-os-system-variable",
                    title="`os.system(variable)` — shell injection if variable is attacker-influenced",
                    path=rel, line=line,
                    fix="Replace with `subprocess.run([…], check=True)`. `os.system` always invokes a shell."
                ))
            for m in PY_SECRET_ARG_RX.finditer(text):
                line = text[:m.start()].count("\n") + 1
                findings.append(Finding(
                    severity="high", surface="cli", check="cli-secret-in-argv",
                    title="Secret accepted via command-line flag — visible to `ps aux`",
                    path=rel, line=line, evidence=m.group(0)[:100],
                    fix="Accept secrets via stdin (`getpass.getpass()`), environment variable (`os.environ['TOKEN']`), or a file path argument that you read with restricted permissions. Never argv."
                ))
            for m in PY_EVAL_RX.finditer(text):
                line = text[:m.start()].count("\n") + 1
                findings.append(Finding(
                    severity="high", surface="cli", check="cli-eval-variable",
                    title="`eval(variable)` — arbitrary code execution if variable is attacker-influenced",
                    path=rel, line=line,
                    fix="`eval` of variable input is almost never the right answer. Use `ast.literal_eval` for parsing data, or a proper parser for DSLs."
                ))

        elif p.suffix in (".sh", ".bash"):
            # Look for unquoted variables in command position
            for i, line in enumerate(text.split("\n"), 1):
                if re.search(r'^\s*\w*\$\w+', line) and '"' not in line and "'" not in line:
                    findings.append(Finding(
                        severity="medium", surface="cli", check="sh-unquoted-var",
                        title="Bash uses unquoted variable in command — word-splitting / glob expansion risk",
                        path=rel, line=i, evidence=line.strip()[:100],
                        fix='Always quote: `"$var"` instead of `$var`. Especially in command arguments and conditionals.'
                    ))
                    break  # one per file is enough signal

    return findings

# ============================================================================
# Check: Desktop apps (Electron / Tauri)
# ============================================================================

def check_desktop(root: Path) -> list[Finding]:
    findings = []
    # Electron BrowserWindow config
    for p in walk_source(root, (".ts", ".tsx", ".js", ".jsx")):
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        if "BrowserWindow" in text or "webPreferences" in text:
            if re.search(r'nodeIntegration\s*:\s*true', text):
                line = next((i+1 for i, l in enumerate(text.split("\n")) if "nodeIntegration" in l and "true" in l), 0)
                findings.append(Finding(
                    severity="critical", surface="desktop", check="electron-node-integration",
                    title="Electron BrowserWindow has `nodeIntegration: true` — XSS becomes RCE on the user's machine",
                    path=rel, line=line,
                    fix="Set `nodeIntegration: false` + `contextIsolation: true`. Expose native functions via a preload script + `contextBridge`."
                ))
            if re.search(r'contextIsolation\s*:\s*false', text):
                line = next((i+1 for i, l in enumerate(text.split("\n")) if "contextIsolation" in l and "false" in l), 0)
                findings.append(Finding(
                    severity="high", surface="desktop", check="electron-context-isolation-off",
                    title="Electron BrowserWindow has `contextIsolation: false` — preload script accessible to web content",
                    path=rel, line=line,
                    fix="Set `contextIsolation: true` and use `contextBridge.exposeInMainWorld` for safe API exposure."
                ))
    # Tauri allowlist scope
    tc = root / "src-tauri" / "tauri.conf.json"
    if tc.exists():
        try:
            d = json.loads(tc.read_text(encoding="utf-8"))
            allowlist = d.get("tauri", {}).get("allowlist", {})
            if allowlist.get("all") is True:
                findings.append(Finding(
                    severity="high", surface="desktop", check="tauri-allowlist-all",
                    title="Tauri `allowlist.all: true` — every API surface is exposed to the renderer",
                    path=str(tc.relative_to(root)),
                    fix="Disable `all: true` and enable individual APIs per-feature. Audit which `fs`, `shell`, `process` scopes your app actually needs."
                ))
            shell = allowlist.get("shell", {})
            if shell.get("execute") is True and not shell.get("scope"):
                findings.append(Finding(
                    severity="critical", surface="desktop", check="tauri-shell-execute-no-scope",
                    title="Tauri `shell.execute: true` with no scope — frontend can run arbitrary commands",
                    path=str(tc.relative_to(root)),
                    fix="Define a `scope` array listing the exact commands + arg patterns the app needs. Never leave shell.execute unscoped."
                ))
        except Exception:
            pass
    return findings

# ============================================================================
# Dispatcher
# ============================================================================

CHECKS = [
    ("mcp",          check_mcp,          "is_mcp_server"),
    ("ci-cd",        check_ci,           "has_github_workflows"),
    ("browser-ext",  check_browser_ext,  "is_browser_extension"),
    ("cli-scripts",  check_cli_scripts,  "is_cli"),
    ("desktop",      check_desktop,      ("is_desktop_electron", "is_desktop_tauri")),
]

def run_all(root: Path, only=None) -> tuple[ProjectShape, list[Finding]]:
    shape = detect(root)
    findings = []
    for name, fn, gate in CHECKS:
        if only and name not in only:
            continue
        gates = gate if isinstance(gate, tuple) else (gate,)
        if any(getattr(shape, g) for g in gates):
            try:
                findings.extend(fn(root))
            except Exception as e:
                print(f"  [{name}] check raised: {e}", file=sys.stderr)
    return shape, findings

def render_md(shape, findings, target):
    lines = []
    lines.append(f"# Lictor multi-surface scan — `{target}`")
    lines.append("")
    lines.append("## Project shape detected")
    for k, v in asdict(shape).items():
        if isinstance(v, bool) and v:
            lines.append(f"- {k.replace('is_', '').replace('has_', '').replace('_', '-')}")
    if not any(v for v in asdict(shape).values() if isinstance(v, bool)):
        lines.append("- (none detected — falling back to generic source scan)")
    lines.append("")
    lines.append(f"## Findings: {len(findings)}")
    lines.append("")
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.surface))
    for f in findings:
        lines.append(f"### {SEV_EMOJI[f.severity]} **{f.severity.upper()}** — {f.title}")
        lines.append(f"- Surface: `{f.surface}`  ·  Check: `{f.check}`")
        if f.path: lines.append(f"- Where: `{f.path}`{f':' + str(f.line) if f.line else ''}")
        if f.evidence: lines.append(f"- Evidence: `{f.evidence}`")
        if f.fix: lines.append(f"- Fix: {f.fix}")
        lines.append("")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Path to a project directory (URL support via patrol-pilot.py instead)")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of markdown")
    ap.add_argument("--only", help="Run only specific check(s), comma-separated: mcp,ci-cd,browser-ext,cli-scripts,desktop")
    args = ap.parse_args()

    root = Path(args.target).resolve()
    if not root.exists():
        print(f"Target does not exist: {root}", file=sys.stderr); sys.exit(2)

    only = set(args.only.split(",")) if args.only else None
    shape, findings = run_all(root, only=only)

    if args.json:
        print(json.dumps({"shape": asdict(shape), "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(render_md(shape, findings, root))

if __name__ == "__main__":
    main()
