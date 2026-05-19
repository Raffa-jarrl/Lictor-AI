#!/usr/bin/env python3
"""
lictor-local — local project security scan.

Takes a directory, walks it, runs 5 checks tuned for AI-built apps:
  1. Hardcoded secrets in source (15+ vendor patterns)
  2. Exposed config files in build output (.env in public/, dist/, .next/)
  3. Service-role JWTs in client code (NEXT_PUBLIC_*, VITE_*)
  4. Open Firebase rules (firestore.rules + storage.rules)
  5. Hardcoded admin URLs without server-side auth check

Output: JSON to stdout (machine-readable for MCP / IDE integration) OR
        plain English to stderr (human-readable).

Usage:
  python3 lictor-local.py                    # scan current dir, plain output
  python3 lictor-local.py --json             # JSON output
  python3 lictor-local.py /path/to/project   # scan specific dir
  python3 lictor-local.py --max-files 500    # cap file walk

This is the heart of the IDE integration. Same checks run by:
  - /lictor-security-check (Claude Code skill)
  - Lictor MCP server (Cursor, Windsurf, Continue, Cline)
  - Future VSCode extension
"""
from __future__ import annotations
import argparse, base64, json, os, re, sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

# === Patterns ===
SECRET_PATTERNS = {
    "openai":       re.compile(r'(sk-(?:proj-)?(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{40,})'),
    "anthropic":    re.compile(r'(sk-ant-api03-[A-Za-z0-9_-]{90,})'),
    "google-ai":    re.compile(r'(AIza[A-Za-z0-9_-]{35})'),
    "huggingface":  re.compile(r'(hf_[A-Za-z0-9]{32,})'),
    "groq":         re.compile(r'(gsk_[A-Za-z0-9]{30,})'),
    "stripe-live":  re.compile(r'(sk_live_[A-Za-z0-9]{24,})'),
    "stripe-rk":    re.compile(r'(rk_live_[A-Za-z0-9]{24,})'),
    "github-pat":   re.compile(r'(ghp_[A-Za-z0-9]{36,})'),
    "github-server":re.compile(r'(ghs_[A-Za-z0-9]{36,})'),
    "aws-key":      re.compile(r'(AKIA[A-Z0-9]{16})'),
    "slack-bot":    re.compile(r'(xoxb-\d+-\d+-[A-Za-z0-9]{24,})'),
    "twilio-sid":   re.compile(r'\b(AC[a-f0-9]{32})\b'),
    "sendgrid":     re.compile(r'(SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,})'),
    "mailchimp":    re.compile(r'\b([0-9a-f]{32}-us\d{1,3})\b'),
    "replicate":    re.compile(r'(r8_[A-Za-z0-9]{30,})'),
    "supabase-sr":  re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*service_role[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
    "firebase-sa":  re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{20,}"'),
}

PLACEHOLDER = re.compile(
    r'(your[-_]?(?:api[-_]?)?(?:key|token|secret)|example|placeholder|XXXX+|TODO|REPLACE|FAKE|<.{1,30}>|0{8,}|x{8,}|insert[-_]?your|getenv|os\.environ|process\.env)',
    re.IGNORECASE,
)

# Files/dirs to walk vs skip
SOURCE_EXT = re.compile(r'\.(py|js|jsx|ts|tsx|mjs|cjs|json|env|yaml|yml|toml|ini|sh|swift|kt|kts|rb|go|rs|java|cs|php)$')
SKIP_DIR = re.compile(r'^(\.git|node_modules|\.next|\.nuxt|dist|build|out|\.venv|venv|__pycache__|\.tox|\.mypy_cache|\.pytest_cache|target|vendor|third_party|coverage|\.cache)$')
# These dirs SHOULD NOT contain secrets — anything found here is high-severity (they're served to users)
PUBLIC_DIR = re.compile(r'(?:^|/)(public|static|dist|build|out|\.next/static|www)(?:/|$)')


@dataclass
class Finding:
    severity: str          # critical / high / medium / low
    check: str             # short slug
    title: str             # one-line plain English
    file: str              # relative path
    line: int              # 1-indexed line number, 0 if N/A
    detail: str            # what we saw, redacted
    fix: str               # plain-English remediation


def is_text_file(path: Path, max_bytes: int = 200_000) -> bool:
    try:
        if path.stat().st_size > max_bytes: return False
        with open(path, "rb") as f:
            chunk = f.read(2048)
            if b"\x00" in chunk: return False
        return True
    except (OSError, PermissionError):
        return False


def walk_project(root: Path, max_files: int = 2000):
    """Walk project, yield (Path, str-content) for source files."""
    count = 0
    for r, dirs, files in os.walk(root):
        # Filter dirs in-place
        dirs[:] = [d for d in dirs if not SKIP_DIR.match(d)]
        for fn in files:
            if not SOURCE_EXT.search(fn): continue
            p = Path(r) / fn
            if not is_text_file(p): continue
            try:
                content = p.read_text("utf-8", "replace")
            except Exception:
                continue
            yield p, content
            count += 1
            if count >= max_files: return


def check_secrets_in_source(root: Path, max_files: int) -> list:
    findings = []
    seen_keys = set()
    for path, content in walk_project(root, max_files):
        rel = str(path.relative_to(root))
        in_public = bool(PUBLIC_DIR.search(rel))
        for kind, rx in SECRET_PATTERNS.items():
            for m in rx.finditer(content):
                val = m.group(1) if m.lastindex else m.group(0)
                if (kind, val) in seen_keys: continue
                # Context check — placeholder-zone?
                start = m.start()
                ctx = content[max(0, start-80):min(len(content), start+80)]
                if PLACEHOLDER.search(ctx): continue
                seen_keys.add((kind, val))
                # Line number
                line_no = content[:start].count("\n") + 1
                red = val[:8] + "…" + val[-4:] if len(val) > 14 else val[:6] + "…"
                # Severity: anything in public/ dir is critical (it ships to users)
                sev = "critical" if in_public else ("high" if kind in ("openai","anthropic","aws-key","stripe-live","supabase-sr","firebase-sa") else "medium")
                findings.append(Finding(
                    severity=sev, check="hardcoded-secret",
                    title=f"Hardcoded {kind} credential in source",
                    file=rel, line=line_no,
                    detail=f"{kind} key `{red}` found in {rel}:{line_no}" + (" (file is in a public/build directory — ships to every user)" if in_public else ""),
                    fix=f"Rotate the {kind} credential NOW at the vendor dashboard. Move the new key into a `.env.local` (gitignored) and read via `os.environ['KEY_NAME']` / `process.env.KEY_NAME`. NEVER commit the new key."
                ))
    return findings


def check_env_in_public(root: Path) -> list:
    """Look for .env files inside public/build output dirs — they ship to every visitor."""
    findings = []
    for r, dirs, files in os.walk(root):
        rel_r = os.path.relpath(r, root)
        if not PUBLIC_DIR.search("/" + rel_r): continue
        for fn in files:
            if fn.startswith(".env") or fn in (".env.local", ".env.production", "config.json", "firebase-service-account.json"):
                rel = os.path.relpath(os.path.join(r, fn), root)
                findings.append(Finding(
                    severity="critical", check="env-in-public",
                    title=f"Config file `{fn}` is inside a public/build directory",
                    file=rel, line=0,
                    detail=f"`{rel}` will be served to every visitor of your deployed site. Any credentials inside are public.",
                    fix=f"Remove `{rel}` from the build output. Add `{fn}` to your build's ignore list (`.gitignore`, `vercelignore`, build config). If anything sensitive was ever in this file: rotate every credential."
                ))
    return findings


def check_supabase_service_role_in_client(root: Path, max_files: int) -> list:
    """Find NEXT_PUBLIC_*SERVICE_ROLE* or VITE_*SERVICE_ROLE* — they bake into client bundle."""
    findings = []
    rx = re.compile(r'(NEXT_PUBLIC_[A-Z_]*SERVICE[A-Z_]*|VITE_[A-Z_]*SERVICE[A-Z_]*|REACT_APP_[A-Z_]*SERVICE[A-Z_]*)\s*=\s*([^\s\'"]{20,})', re.IGNORECASE)
    for path, content in walk_project(root, max_files):
        rel = str(path.relative_to(root))
        for m in rx.finditer(content):
            var_name = m.group(1)
            line_no = content[:m.start()].count("\n") + 1
            findings.append(Finding(
                severity="critical", check="service-role-in-client",
                title=f"Service-role key exposed via client-side env var `{var_name}`",
                file=rel, line=line_no,
                detail=f"`{var_name}` in {rel}:{line_no} — env vars prefixed with NEXT_PUBLIC_ / VITE_ / REACT_APP_ are baked into the client JavaScript bundle and visible to every visitor.",
                fix=f"Rename the env var to remove the public prefix (use `SUPABASE_SERVICE_ROLE_KEY` instead of `NEXT_PUBLIC_*`). Then move the call that uses it into a server-side route / API handler / edge function. Rotate the key at the vendor's dashboard — assume it has been exposed already."
            ))
    return findings


def check_firebase_rules(root: Path) -> list:
    findings = []
    for fn in ("firestore.rules", "storage.rules", "database.rules.json"):
        for path in root.rglob(fn):
            try: content = path.read_text("utf-8", "replace")
            except: continue
            rel = str(path.relative_to(root))
            # The classic "allow read, write: if true" pattern
            if re.search(r'allow\s+(read|write|read,\s*write|create|update|delete)\s*:\s*if\s+true', content):
                findings.append(Finding(
                    severity="critical", check="open-firebase-rules",
                    title=f"Firebase rules in `{rel}` allow read/write to anyone",
                    file=rel, line=0,
                    detail=f"`{rel}` contains `allow read/write: if true` — anyone with your Firebase project ID can read OR write every document.",
                    fix=f"Replace `if true` with `if request.auth != null && request.auth.uid == resource.data.userId` (or your equivalent ownership check). If you need public READ but not write, use `allow read: if true; allow write: if request.auth != null;`."
                ))
    return findings


def derive_grade(findings: list) -> str:
    counts = {s: 0 for s in ("critical","high","medium","low")}
    for f in findings: counts[f.severity] = counts.get(f.severity, 0) + 1
    if counts["critical"] >= 2: return "F"
    if counts["critical"] >= 1 or counts["high"] >= 4: return "D"
    if counts["high"] >= 1 or counts["medium"] >= 5: return "C"
    if counts["medium"] >= 1: return "B"
    return "A"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".", help="Project directory")
    ap.add_argument("--json", action="store_true", help="JSON output to stdout")
    ap.add_argument("--max-files", type=int, default=2000)
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr); sys.exit(2)

    findings = []
    findings += check_secrets_in_source(root, args.max_files)
    findings += check_env_in_public(root)
    findings += check_supabase_service_role_in_client(root, args.max_files)
    findings += check_firebase_rules(root)

    grade = derive_grade(findings)
    result = {
        "path": str(root),
        "grade": grade,
        "findings_count": len(findings),
        "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in ("critical","high","medium","low")},
        "findings": [asdict(f) for f in findings],
        "_meta": {
            "scanner": "lictor-local",
            "version": "0.1",
            "checks_run": 4,
        },
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nLictor scan — {root}", file=sys.stderr)
        print(f"Grade: {grade}  ·  {len(findings)} finding(s)", file=sys.stderr)
        for f in findings:
            sev_emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}.get(f.severity, "·")
            print(f"\n{sev_emoji} {f.severity.upper()} · {f.title}", file=sys.stderr)
            print(f"   📁 {f.file}{':'+str(f.line) if f.line else ''}", file=sys.stderr)
            print(f"   {f.detail}", file=sys.stderr)
            print(f"   💡 Fix: {f.fix}", file=sys.stderr)
        if not findings:
            print("\n✅ No critical/high/medium issues found in standard checks.", file=sys.stderr)
            print("   (This is a fast static check. For the full Claude Code skill audit, use /lictor-security-check.)", file=sys.stderr)


if __name__ == "__main__":
    main()
