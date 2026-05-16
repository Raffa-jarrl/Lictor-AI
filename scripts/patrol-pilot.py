#!/usr/bin/env python3
"""
Lictor Patrol — pilot scanner (manual, pre-Worker).

Targets: vibe-coded apps shared on GitHub in the last 7 days with a deployed
URL in the repo's `homepage` field.

For each deployed URL, runs lightweight HTTP probes for the same patterns
the real Worker will detect. Aggregates findings and produces a triage doc.

Usage:
    python3 scripts/patrol-pilot.py --since 7 --output docs/launch/patrol-pilot-2026-05-16.md

This is intentionally polite:
  - 1 scan per origin
  - 5-second timeout per request
  - 2-second sleep between hosts
  - Custom User-Agent identifying us
  - Stops at first JS bundle (≤ 500KB) — we don't slurp the whole site
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin
import urllib.request, urllib.error, ssl

UA = "Lictor-Patrol/0.1 (+https://lictor-ai.com/scan; friendly security scanner; raffa@lictor-ai.com)"
TIMEOUT = 8

# --- Severity-typed findings ---------------------------------------------------

SECRET_PATTERNS = [
    # (label, severity, regex, why-this-matters)
    ("Supabase service-role key in JS bundle",        "critical",
     re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}.*service_role', re.DOTALL),
     "Anyone who opens devtools has full database write access."),
    ("Stripe live secret key in JS bundle",            "critical",
     re.compile(r'sk_live_[A-Za-z0-9]{20,}'),
     "Anyone can charge or refund cards on your Stripe account."),
    ("OpenAI key in JS bundle",                        "critical",
     re.compile(r'sk-(proj-)?[A-Za-z0-9_-]{30,}'),
     "Your OpenAI quota can be drained in hours."),
    ("Anthropic key in JS bundle",                     "critical",
     re.compile(r'sk-ant-api\d{2}-[A-Za-z0-9_-]{30,}'),
     "Your Anthropic quota can be drained in hours."),
    ("GitHub Personal Access Token in JS bundle",      "critical",
     re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),
     "Read/write access to your GitHub repos."),
    ("AWS access key in JS bundle",                    "critical",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     "Spinning up crypto-miner EC2 boxes on your dime."),
    ("Generic .env contents leaked into bundle",       "high",
     re.compile(r'(NEXT_PUBLIC_|VITE_)?[A-Z_]*(SECRET|TOKEN|API_KEY|PASSWORD)\s*=\s*[A-Za-z0-9_/+=-]{16,}'),
     "Whatever this secret unlocks is now public."),
]

def http_get(url, max_bytes=500_000):
    """Polite GET. Returns (status, headers_dict, body_bytes_truncated) or None on fail."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read(max_bytes)
            headers = {k.lower(): v for k, v in r.headers.items()}
            return (r.status, headers, body)
    except urllib.error.HTTPError as e:
        return (e.code, dict(e.headers) if e.headers else {}, b"")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError) as e:
        return None

def has_header(headers, name, *contains):
    v = headers.get(name.lower(), "")
    if not contains: return bool(v)
    return any(c.lower() in v.lower() for c in contains)

@dataclass
class Finding:
    severity: str           # critical / high / medium / low / info
    check: str
    detail: str
    evidence: str = ""
    fix: str = ""

@dataclass
class ScanResult:
    repo: str               # e.g. owner/name
    repo_url: str
    deployed_url: str
    platform_hint: str
    grade: str = "?"
    findings: list[Finding] = field(default_factory=list)
    scan_error: str = ""

# --- Checks ------------------------------------------------------------------

def check_headers(homepage, status, headers) -> list[Finding]:
    f = []
    if status >= 400:
        f.append(Finding("info", "site-returns-non-2xx",
                         f"Homepage returned HTTP {status}", fix="Probably nothing to fix — but if you expected the site to load, investigate."))
        return f
    if not has_header(headers, "strict-transport-security"):
        f.append(Finding("low", "missing-hsts",
                         "No Strict-Transport-Security header",
                         fix="Add HSTS to your hosting platform's headers config."))
    if not has_header(headers, "content-security-policy"):
        f.append(Finding("medium", "missing-csp",
                         "No Content-Security-Policy header",
                         fix="Set a CSP — defense in depth against future XSS bugs."))
    if not has_header(headers, "x-frame-options") and not has_header(headers, "content-security-policy", "frame-ancestors"):
        f.append(Finding("low", "clickjackable",
                         "No X-Frame-Options or frame-ancestors CSP — site can be iframed by any other site",
                         fix="Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`."))
    return f

def check_exposed_files(homepage) -> list[Finding]:
    """Try the classic exposed-file gotchas at the site root."""
    f = []
    candidates = [
        (".env", "critical", "Your env file is publicly readable. Whatever secrets are in there are public."),
        (".env.local", "critical", "Your env file is publicly readable."),
        (".env.production", "critical", "Your production env file is publicly readable."),
        (".git/config", "high",     "Your .git directory is exposed. Attackers can reconstruct your full repo + commit history."),
        (".DS_Store", "low",        "macOS metadata file leaked — minor info disclosure."),
    ]
    for path, sev, why in candidates:
        url = urljoin(homepage, path)
        r = http_get(url, max_bytes=2048)
        if not r: continue
        status, headers, body = r
        if status == 200 and body:
            # Heuristic: real env files have KEY=VAL lines
            if path.startswith(".env") and b"=" in body and not b"<html" in body[:200].lower():
                f.append(Finding(sev, f"exposed-{path}",
                                 f"Found {path} at {url}",
                                 evidence=body[:200].decode('utf-8', 'replace').strip(),
                                 fix=f"Remove {path} from your deployed site or block at the hosting level. If it ever held secrets: rotate them now."))
            elif path == ".git/config" and b"[core]" in body:
                f.append(Finding(sev, "exposed-git",
                                 f".git directory exposed at {url}",
                                 fix="Block /.git/ at your hosting platform. Then check no secrets ever committed."))
            elif path == ".DS_Store" and body.startswith(b"\x00\x00\x00\x01Bud1"):
                f.append(Finding(sev, "exposed-ds-store",
                                 f".DS_Store served at {url}", fix="Add to .gitignore + remove from deploy."))
        time.sleep(0.5)  # polite
    return f

def check_js_bundle_secrets(homepage, html: bytes) -> list[Finding]:
    """Find JS bundle URLs in the HTML, fetch the first ≤500KB, regex for secrets."""
    f = []
    # Find <script src="..."> URLs
    script_srcs = re.findall(rb'<script[^>]+src=["\']([^"\']+)["\']', html, flags=re.I)[:8]
    bundle_text = ""
    bundle_url = None
    for src in script_srcs:
        src = src.decode("utf-8", "replace")
        url = urljoin(homepage, src)
        r = http_get(url, max_bytes=500_000)
        if not r: continue
        status, _, body = r
        if status != 200 or not body: continue
        try:
            t = body.decode("utf-8", "replace")
        except Exception:
            continue
        if len(t) > len(bundle_text):
            bundle_text = t
            bundle_url = url
        if len(bundle_text) > 200_000: break  # enough
    if not bundle_text: return f
    for label, sev, regex, why in SECRET_PATTERNS:
        m = regex.search(bundle_text)
        if m:
            redacted = m.group(0)[:18] + "…" + m.group(0)[-4:]
            f.append(Finding(sev, "secret-in-bundle",
                             label,
                             evidence=f"Found in {bundle_url}: {redacted}",
                             fix=f"Rotate that credential NOW. Then move it out of the client bundle — only server-side code should hold it. Why this matters: {why}"))
    return f

def derive_grade(findings) -> str:
    counts = {s: 0 for s in ("critical","high","medium","low","info")}
    for x in findings: counts[x.severity] = counts.get(x.severity,0)+1
    if counts["critical"] >= 2: return "F"
    if counts["critical"] >= 1 or counts["high"] >= 4: return "D"
    if counts["high"] >= 1 or counts["medium"] >= 5: return "C"
    if counts["medium"] >= 1: return "B"
    return "A"

# --- GitHub repo enumeration --------------------------------------------------

def gh_search_recent(since_days: int) -> list[dict]:
    """Use `gh api search/repositories` to find recent vibe-coder repos with deployed URLs."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")
    queries = [
        f'lovable created:>{since} fork:false',
        f'"bolt.new" OR "bolt-new" created:>{since} fork:false',
        f'"v0.dev" created:>{since} fork:false',
        f'cursor created:>{since} fork:false language:typescript',
    ]
    seen = set()
    results = []
    for q in queries:
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/repositories",
                 "-f", f"q={q}", "-f", "per_page=100", "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired):
            continue
        for it in items:
            key = it["full_name"]
            if key in seen: continue
            seen.add(key)
            results.append({
                "repo": key,
                "repo_url": it["html_url"],
                "homepage": (it.get("homepage") or "").strip(),
                "description": (it.get("description") or "").strip(),
                "platform_hint": platform_from(q, it),
                "stars": it.get("stargazers_count", 0),
                "created_at": it.get("created_at"),
            })
    return results

def platform_from(query, item):
    desc = (item.get("description") or "").lower()
    if "lovable" in query.lower() or "lovable" in desc: return "lovable"
    if "bolt" in query.lower() or "bolt" in desc: return "bolt"
    if "v0" in query.lower() or "v0.dev" in desc: return "v0"
    if "cursor" in query.lower(): return "cursor"
    return "?"

# --- Main --------------------------------------------------------------------

def scan_one(repo) -> ScanResult:
    r = ScanResult(repo=repo["repo"], repo_url=repo["repo_url"],
                   deployed_url=repo["homepage"], platform_hint=repo["platform_hint"])
    if not r.deployed_url:
        r.scan_error = "no homepage URL — would need git clone (skipped in this pilot)"
        return r
    # Normalize URL
    if not r.deployed_url.startswith(("http://", "https://")):
        r.deployed_url = "https://" + r.deployed_url
    home = http_get(r.deployed_url)
    if not home:
        r.scan_error = "homepage unreachable"
        return r
    status, headers, html = home
    r.findings.extend(check_headers(r.deployed_url, status, headers))
    if status == 200:
        r.findings.extend(check_exposed_files(r.deployed_url))
        r.findings.extend(check_js_bundle_secrets(r.deployed_url, html))
    r.grade = derive_grade(r.findings)
    return r

def render_report(results, output_path):
    from datetime import datetime
    actionable = [r for r in results if r.findings and r.grade in ("C","D","F")]
    actionable.sort(key=lambda r: (r.grade, -len([f for f in r.findings if f.severity == "critical"])))
    md = []
    md.append(f"# Lictor Patrol — pilot scan {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    md.append(f"**Scope:** repos created on GitHub in the last 7 days mentioning Lovable/Bolt/v0/Cursor with a published `homepage` URL.\n")
    md.append(f"**Total candidates discovered:** {len(results)}\n")
    md.append(f"**With deployed URLs (scannable):** {len([r for r in results if r.deployed_url])}\n")
    md.append(f"**Actually reachable + scanned:** {len([r for r in results if not r.scan_error and r.deployed_url])}\n")
    md.append(f"**Returned a grade ≤ C (worth contacting):** {len(actionable)}\n\n")
    md.append("---\n\n## Outreach queue\n\nApps below have findings serious enough that Bridge should draft a private outreach. Each one gets the standard 30-day private-disclosure window before public scorecard.\n\n")
    for i, r in enumerate(actionable, 1):
        md.append(f"### {i}. `{r.repo}` — grade **{r.grade}** · {r.platform_hint}\n")
        md.append(f"- Deployed: {r.deployed_url}\n- Repo: {r.repo_url}\n\n")
        md.append("**Findings:**\n")
        for f in sorted(r.findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity)):
            emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}[f.severity]
            md.append(f"- {emoji} **{f.severity.upper()}** — {f.detail}")
            if f.evidence: md.append(f"  - Evidence: `{f.evidence[:120]}`")
            if f.fix: md.append(f"  - Fix: {f.fix}")
            md.append("")
        md.append("")
    md.append("\n---\n\n## Full scan log (everything reachable)\n\n")
    md.append("| Repo | Platform | Grade | Findings | Deployed |\n|---|---|---|---|---|\n")
    for r in sorted(results, key=lambda x: x.grade if x.grade != "?" else "Z"):
        if r.scan_error or not r.deployed_url: continue
        md.append(f"| `{r.repo}` | {r.platform_hint} | **{r.grade}** | {len(r.findings)} | {r.deployed_url} |\n")
    md.append("\n## Repos skipped (no deployed URL)\n\n")
    skipped = [r for r in results if not r.deployed_url]
    md.append(f"{len(skipped)} repos had no `homepage` field. Patrol would clone these for code-only scans; out of scope for this URL-only pilot.\n")
    with open(output_path, "w") as f:
        f.write("\n".join(md))
    return len(actionable)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=int, default=7, help="Days back to search")
    ap.add_argument("--output", default="docs/launch/patrol-pilot-latest.md")
    ap.add_argument("--max", type=int, default=60, help="Cap on scans this run")
    args = ap.parse_args()

    print(f"[+] Searching GitHub for repos created in last {args.since} days...")
    repos = gh_search_recent(args.since)
    print(f"[+] Found {len(repos)} unique repos")
    with_url = [r for r in repos if r["homepage"]]
    print(f"[+] {len(with_url)} have deployed URLs — scanning up to {args.max}")
    to_scan = with_url[:args.max]
    results = []
    for i, r in enumerate(to_scan, 1):
        print(f"  [{i}/{len(to_scan)}] {r['repo']} -> {r['homepage']}", end="", flush=True)
        try:
            res = scan_one(r)
            results.append(res)
            print(f"  grade={res.grade}  findings={len(res.findings)}" + (f"  ERR={res.scan_error}" if res.scan_error else ""))
        except KeyboardInterrupt:
            print("\n[!] Aborted by user")
            break
        except Exception as e:
            print(f"  EXC={e}")
            results.append(ScanResult(repo=r["repo"], repo_url=r["repo_url"],
                                       deployed_url=r["homepage"], platform_hint=r["platform_hint"],
                                       scan_error=str(e)))
        time.sleep(2)  # 1 origin / 2 sec = polite
    # add the no-URL ones for the report's "skipped" count
    for r in repos:
        if not r["homepage"]:
            results.append(ScanResult(repo=r["repo"], repo_url=r["repo_url"],
                                       deployed_url="", platform_hint=r["platform_hint"],
                                       scan_error="no homepage"))
    n = render_report(results, args.output)
    print(f"\n[+] Wrote report to {args.output}")
    print(f"[+] {n} apps land in the outreach queue (grade ≤ C)")

if __name__ == "__main__":
    main()
