#!/usr/bin/env python3
"""
patrol-github-secrets — GitHub Code Search for hardcoded secrets in F500 org public repos.

For each F500 program, infer the likely GitHub org name(s), then run code search
for high-signal secret patterns. Validates each hit by checking the file content
contains an actual live-looking credential (not test fixtures or examples).

Secret patterns:
  AWS:    AKIA[0-9A-Z]{16}                    (Access Key ID)
  GitHub: gh[pousr]_[A-Za-z0-9]{36,}          (PAT/OAuth/etc.)
  Slack:  xox[bpars]-[A-Za-z0-9-]{10,}        (Bot/User tokens)
  Stripe: sk_(live|test)_[A-Za-z0-9]{24,}     (API keys)
  Google: AIza[0-9A-Za-z\-_]{35}              (API keys)
  JWT:    eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+

FP gates (apply post-search):
  - Skip if file path contains "test", "example", "mock", "fixture", "sample"
  - Skip if path is README.md / docs/ (often documentation)
  - Skip if value matches known dummy patterns (AKIAIOSFODNN7EXAMPLE etc.)
  - For AWS keys: validate against well-formed regex + non-example prefix

Requires: `gh` CLI authenticated.

Usage:
  patrol-github-secrets.py --programs programs.json [--orgs org1,org2]
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

# Patterns: (name, regex, severity)
SECRET_PATTERNS = [
    ("aws_access_key",  re.compile(rb"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("github_pat",      re.compile(rb"ghp_[A-Za-z0-9]{36,}"), "CRITICAL"),
    ("github_server",   re.compile(rb"ghs_[A-Za-z0-9]{36,}"), "CRITICAL"),
    ("github_oauth",    re.compile(rb"gho_[A-Za-z0-9]{36,}"), "CRITICAL"),
    ("github_refresh",  re.compile(rb"ghr_[A-Za-z0-9]{36,}"), "CRITICAL"),
    ("slack_bot",       re.compile(rb"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}"), "CRITICAL"),
    ("slack_user",      re.compile(rb"xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{30,}"), "CRITICAL"),
    ("stripe_live",     re.compile(rb"sk_live_[A-Za-z0-9]{24,}"), "CRITICAL"),
    ("google_api",      re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "HIGH"),
    ("private_key",     re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("npmrc_token",     re.compile(rb"//[^/]+/:_authToken=[A-Za-z0-9_-]{20,}"), "CRITICAL"),
]

# Known example/dummy values — skip
KNOWN_DUMMIES = {
    b"AKIAIOSFODNN7EXAMPLE", b"AKIAI44QH8DHBEXAMPLE",
    b"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

# File-path FP gates
FP_PATH_KEYWORDS = ("test/", "tests/", "__tests__", "example", "/sample", "fixture",
                    "mock", "docs/", "documentation/", "/test_", ".test.", ".spec.",
                    "readme", "changelog", ".md", "/vendor/", "/node_modules/")


@dataclass
class GitHubSecret:
    org: str
    repo: str
    path: str
    pattern_name: str
    matched_value_prefix: str  # first 12 chars only (anti-leak: don't log full secret)
    html_url: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def gh_api(endpoint: str, paginate: bool = False, timeout: int = 30) -> list | dict:
    """Call gh api with optional pagination. Returns parsed JSON."""
    cmd = ["gh", "api", endpoint]
    if paginate: cmd.append("--paginate")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            print(f"[gh_api] {endpoint} -> error: {r.stderr[:200]}", file=sys.stderr)
            return [] if paginate else {}
        # Paginated results: gh emits one JSON object per page on separate lines? Actually emits concatenated
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            # Try parsing as concatenated JSON
            items = []
            for chunk in r.stdout.split("\n"):
                if chunk.strip().startswith("{"):
                    try:
                        items.append(json.loads(chunk))
                    except: pass
            return items
    except subprocess.TimeoutExpired:
        return [] if paginate else {}


def search_org(org: str, pattern_name: str, pattern_str: str, max_results: int = 30) -> list[dict]:
    """Use gh search to find files containing the pattern in this org."""
    # GitHub code search query format
    query = f"{pattern_str} org:{org}"
    try:
        r = subprocess.run(
            ["gh", "search", "code", query, "--limit", str(max_results), "--json", "repository,path,url,sha"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return []
        return json.loads(r.stdout) if r.stdout.strip() else []
    except Exception as e:
        return []


def fetch_file_content(html_url: str, max_bytes: int = 50000) -> bytes:
    """Convert GitHub HTML URL to raw URL and fetch."""
    # html_url: https://github.com/{org}/{repo}/blob/{ref}/{path}
    # raw_url:  https://raw.githubusercontent.com/{org}/{repo}/{ref}/{path}
    raw = html_url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    import urllib.request
    try:
        req = urllib.request.Request(raw, headers={"User-Agent": "Lictor-GHSecretValidator/0.1"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read(max_bytes)
    except Exception:
        return b""


def is_path_fp(path: str) -> bool:
    pl = path.lower()
    return any(kw in pl for kw in FP_PATH_KEYWORDS)


def validate_match(content: bytes, pattern_re) -> tuple[bool, bytes]:
    """Find first non-dummy match. Returns (is_real, matched_value)."""
    for m in pattern_re.finditer(content):
        val = m.group(0)
        if val in KNOWN_DUMMIES: continue
        # Heuristic: skip if surrounded by 'X' or 'x' characters (placeholder pattern)
        idx = m.start()
        before = content[max(0,idx-3):idx]
        after = content[m.end():m.end()+3]
        if b"xxx" in before.lower() or b"xxx" in after.lower(): continue
        return True, val
    return False, b""


def scan_org(org: str, max_per_pattern: int = 30) -> list[GitHubSecret]:
    findings = []
    for name, pattern_re, sev in SECRET_PATTERNS:
        # Translate compiled regex to search-friendly string
        # Use a short fragment that's likely to match (e.g. "AKIA" for AWS, "ghp_" for PAT)
        prefix_map = {
            "aws_access_key": "AKIA",
            "github_pat": "ghp_",
            "github_server": "ghs_",
            "github_oauth": "gho_",
            "github_refresh": "ghr_",
            "slack_bot": "xoxb-",
            "slack_user": "xoxp-",
            "stripe_live": "sk_live_",
            "google_api": "AIza",
            "private_key": "BEGIN PRIVATE KEY",
            "npmrc_token": "_authToken",
        }
        search_str = prefix_map.get(name, name)
        hits = search_org(org, name, search_str, max_results=max_per_pattern)
        for h in hits:
            try:
                repo = h.get("repository", {}).get("nameWithOwner", "?")
                path = h.get("path", "?")
                html_url = h.get("url", "?")
                if is_path_fp(path):
                    continue
                # Fetch + validate
                content = fetch_file_content(html_url)
                if not content: continue
                ok, val = validate_match(content, pattern_re)
                if not ok: continue
                findings.append(GitHubSecret(
                    org=org, repo=repo, path=path, pattern_name=name,
                    matched_value_prefix=val[:12].decode("utf-8", "replace"),
                    html_url=html_url, severity=sev,
                    notes=f"{name} matched in {repo}/{path}",
                ))
                # Stop after 1 per pattern per org (further hits are usually same value)
                break
            except Exception as e:
                continue
    return findings


def infer_orgs(program_name: str) -> list[str]:
    """Guess GitHub org name(s) from program name."""
    base = re.sub(r"[^a-z0-9]", "", program_name.lower())
    candidates = {base}
    # Add hyphen-separated variant
    candidates.add(re.sub(r"\s+", "-", program_name.lower()))
    # Strip common suffixes
    for suf in ("inc", "ltd", "llc", "corp", "vdp"):
        if base.endswith(suf):
            candidates.add(base[:-len(suf)])
    return [c for c in candidates if c and len(c) >= 3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--programs", help="Path to chaos programs.json")
    ap.add_argument("--orgs", help="Comma-separated org names (overrides --programs inference)")
    ap.add_argument("--max-per-pattern", type=int, default=20)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/github-secrets.jsonl")
    args = ap.parse_args()

    if args.orgs:
        orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    elif args.programs:
        progs = json.loads(Path(args.programs).read_text())
        orgs = []
        for p in progs:
            for c in infer_orgs(p.get("name", "")):
                if c not in orgs: orgs.append(c)
    else:
        ap.error("provide --orgs or --programs")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] github-secrets — scanning {len(orgs)} orgs × {len(SECRET_PATTERNS)} patterns")
    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_org, o, args.max_per_pattern): o for o in orgs}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=600)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = "🔴" if f.severity == "CRITICAL" else "🟠"
                if f.severity == "CRITICAL": n_crit += 1
                else: n_high += 1
                print(f"  [{i}/{len(orgs)}] {tag} {f.severity} {f.pattern_name} in {f.repo}/{f.path}")
            if i % 25 == 0:
                print(f"  [{i}/{len(orgs)}] crit={n_crit} high={n_high}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")


if __name__ == "__main__":
    main()
