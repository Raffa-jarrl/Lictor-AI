#!/usr/bin/env python3
"""
patrol-npm-publish-leaks — scanner #19.

When devs publish to npm, they often forget to `.npmignore` files like
.env, config/local.json, etc. The published .tgz contains these even if
the GitHub repo has them gitignored.

Strategy:
  1. List packages from bounty-program orgs/scopes (@stripe, @shopify, etc.)
  2. For each package, fetch latest version metadata
  3. Download the .tgz, extract file list
  4. Look for .env, *.key, config/local.* etc. — pull contents
  5. Scan for secret patterns

Bounty leverage: vendor-published packages with secrets are clear bounty
material (companies pay because they published the leak themselves).
"""
from __future__ import annotations
import argparse, gzip, io, json, re, tarfile, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

UA = "Lictor-NpmLeakPatrol/0.1 (+https://lictor-ai.com)"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"npm-publish-leaks-{datetime.now().strftime('%Y-%m-%d')}-private.md"

# npm scopes for bounty-program companies
BOUNTY_SCOPES = [
    "@stripe", "@shopify", "@github", "@octokit", "@microsoft", "@azure",
    "@google-cloud", "@googleapis", "@discord", "@atlassian", "@hashicorp",
    "@elastic", "@mongodb", "@vercel", "@supabase", "@cloudflare", "@datadog",
    "@snyk", "@twilio", "@sendgrid", "@auth0", "@1password", "@anthropic-ai",
    "@openai", "@langchain", "@pinecone-database", "@netlify", "@sentry",
    "@posthog", "@plaid", "@notion", "@linear", "@calcom", "@trigger.dev",
    "@inngest", "@brex", "@figma", "@circleci", "@buildkite",
]

# Files we want to peek inside (high-leak risk)
RISKY_FILES = re.compile(
    r'(\.env(\.|$)|config/local|config/production|secrets\.|credentials\.|'
    r'\.aws/credentials|\.npmrc$|firebase-adminsdk|service-account|private\.key|'
    r'\.pem$|\.p12$|backup\.|\.bak$|\.tmp$|\.swp$)',
    re.I,
)

SECRET_PATTERNS = {
    "hf_token":      re.compile(r'\bhf_[A-Za-z0-9]{30,40}\b'),
    "openai_key":    re.compile(r'\bsk-[A-Za-z0-9_-]{40,}\b'),
    "anthropic_key": re.compile(r'\bsk-ant-api\d{2}-[A-Za-z0-9_-]{50,200}\b'),
    "aws_akid":      re.compile(r'\bAKIA[A-Z0-9]{16}\b'),
    "stripe_live":   re.compile(r'\bsk_live_[A-Za-z0-9]{24,99}\b'),
    "github_pat":    re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b'),
    "google_api":    re.compile(r'\bAIza[A-Za-z0-9_-]{35}\b'),
    "slack_token":   re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,200}\b'),
    "private_key":   re.compile(r'-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----'),
}
PLACEHOLDER_RX = re.compile(r'(example|placeholder|XXX|TODO|FAKE|your_|YOUR_|<[^>]{1,30}>|test_)', re.I)


def http_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


def list_scope_packages(scope, limit=50):
    """Get package names under a scope."""
    url = f"https://registry.npmjs.org/-/v1/search?text=scope:{scope.lstrip('@')}&size={limit}"
    body = http_get(url, 15)
    if not body: return []
    try:
        data = json.loads(body.decode())
        return [obj["package"]["name"] for obj in data.get("objects", [])]
    except Exception:
        return []


def get_latest_tarball(pkg_name):
    """Return the URL of the package's latest .tgz."""
    enc = pkg_name.replace("@", "%40").replace("/", "%2F")
    body = http_get(f"https://registry.npmjs.org/{enc}", 10)
    if not body: return None
    try:
        data = json.loads(body.decode())
        latest = data.get("dist-tags", {}).get("latest")
        if not latest: return None
        return data["versions"][latest]["dist"]["tarball"]
    except Exception:
        return None


def scan_tarball(tar_url, pkg_name, max_files=80):
    """Download tarball, extract risky files, scan content."""
    body = http_get(tar_url, 30)
    if not body: return []
    leaks = []
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
            files_checked = 0
            for member in tar:
                if not member.isfile(): continue
                if member.size > 1_000_000: continue  # skip huge files
                if not RISKY_FILES.search(member.name): continue
                files_checked += 1
                if files_checked > max_files: break
                try:
                    f = tar.extractfile(member)
                    if not f: continue
                    content = f.read().decode("utf-8", "replace")
                except Exception:
                    continue
                for pname, rx in SECRET_PATTERNS.items():
                    for m in rx.finditer(content):
                        ctx = content[max(0, m.start()-100):m.end()+150]
                        if PLACEHOLDER_RX.search(ctx): continue
                        leaks.append({
                            "package": pkg_name,
                            "file": member.name,
                            "pattern": pname,
                            "redacted": m.group(0)[:8] + "…" + m.group(0)[-4:] if len(m.group(0)) > 16 else m.group(0),
                            "tarball": tar_url,
                        })
    except Exception as e:
        pass
    return leaks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scopes", type=int, default=20)
    ap.add_argument("--pkgs-per-scope", type=int, default=25)
    args = ap.parse_args()

    print(f"[+] npm publish-leak patrol — {args.scopes} scopes × {args.pkgs_per_scope} packages each", flush=True)

    confirmed = []
    seen = set()
    for si, scope in enumerate(BOUNTY_SCOPES[:args.scopes], 1):
        pkgs = list_scope_packages(scope, args.pkgs_per_scope)
        print(f"  [{si}/{args.scopes}] {scope:<20} {len(pkgs)} packages", flush=True)
        for pkg in pkgs:
            if pkg in seen: continue
            seen.add(pkg)
            tar = get_latest_tarball(pkg)
            time.sleep(0.3)
            if not tar: continue
            leaks = scan_tarball(tar, pkg)
            if leaks:
                print(f"    🔴 {pkg}: {len(leaks)} leaks", flush=True)
                for l in leaks:
                    print(f"       {l['pattern']:<15} → {l['file']}  ({l['redacted']})", flush=True)
                confirmed.extend(leaks)
            time.sleep(0.4)
        time.sleep(1)

    print(f"\n[+] scan complete: {len(confirmed)} leaks across {len(seen)} npm packages", flush=True)

    if confirmed:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as f:
            f.write(f"# npm publish leaks — {datetime.now().strftime('%Y-%m-%d %H:%M')} (PRIVATE)\n\n")
            f.write(f"**Packages scanned:** {len(seen)}\n")
            f.write(f"**Leaks confirmed:** {len(confirmed)}\n\n")
            f.write("| Pattern | Package | File | Redacted |\n|---|---|---|---|\n")
            for l in confirmed:
                f.write(f"| **{l['pattern']}** | `{l['package']}` | `{l['file']}` | `{l['redacted']}` |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
