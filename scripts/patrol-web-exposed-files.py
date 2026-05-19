#!/usr/bin/env python3
"""
patrol-web-exposed-files — scanner #20.

Probes bounty-program subdomains for accidentally-exposed sensitive files
at the web layer (not source layer):
  - /.git/config
  - /.env
  - /.aws/credentials
  - /config.json, /backup.sql.gz
  - /server-status (Apache)
  - /actuator/env (Spring Boot)
  - /.svn/entries
  - /.DS_Store
  - /phpinfo.php

This is THE classic bounty pattern — a tier-1 H1 program pays $500-$5K
for an exposed .git/config on production. Different from source-code
scanning entirely.
"""
from __future__ import annotations
import argparse, json, re, ssl, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

UA = "Lictor-WebFilePatrol/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / ".lictor" / "web-exposed-ledger.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"web-exposed-{datetime.now().strftime('%Y-%m-%d')}-private.md"

# Top bounty programs — apex domains + key subdomains to probe
TARGETS = [
    # Mid-tier (less scanned)
    "sentry.io", "posthog.com", "plaid.com", "figma.com", "notion.so",
    "linear.app", "cal.com", "documenso.com", "trigger.dev", "inngest.com",
    "anthropic.com", "openai.com", "huggingface.co", "replicate.com",
    "buildkite.com", "circleci.com", "supabase.com", "vercel.com",
    "loom.com", "miro.com", "airtable.com", "retool.com",
    # Big tier
    "stripe.com", "shopify.com", "cloudflare.com", "discord.com",
    "github.com", "atlassian.com", "okta.com", "twilio.com",
    "uber.com", "airbnb.com", "spotify.com", "snap.com", "twitch.tv",
    "reddit.com", "coinbase.com", "robinhood.com", "etsy.com",
]

# Common dangerous subdomain prefixes to probe per apex
SUB_PREFIXES = ["", "api.", "admin.", "dev.", "staging.", "test.", "internal.",
                "beta.", "demo.", "old.", "legacy.", "dashboard.", "app."]

# Files to probe (each one is the "money shot")
PROBES = [
    {"path": "/.git/config",                "match": re.compile(r'\[core\]|repositoryformatversion', re.I), "severity": "HIGH",  "pay": 1000},
    {"path": "/.git/HEAD",                  "match": re.compile(r'^ref:\s*refs/heads/', re.M),               "severity": "HIGH",  "pay": 1000},
    {"path": "/.env",                       "match": re.compile(r'^[A-Z_]{3,40}\s*=\s*\S{3,}', re.M),       "severity": "CRIT",  "pay": 2500},
    {"path": "/.env.production",            "match": re.compile(r'^[A-Z_]{3,40}\s*=\s*\S{3,}', re.M),       "severity": "CRIT",  "pay": 3000},
    {"path": "/.env.local",                 "match": re.compile(r'^[A-Z_]{3,40}\s*=\s*\S{3,}', re.M),       "severity": "HIGH",  "pay": 1500},
    {"path": "/.aws/credentials",           "match": re.compile(r'\[default\]|aws_access_key_id', re.I),    "severity": "CRIT",  "pay": 5000},
    {"path": "/server-status",              "match": re.compile(r'Apache Server Status|Total accesses', re.I),"severity": "MED",   "pay": 250},
    {"path": "/actuator/env",               "match": re.compile(r'"propertySources"|"activeProfiles"', re.I),"severity": "HIGH",  "pay": 1500},
    {"path": "/actuator/heapdump",          "match": re.compile(r'^\x1f\x8b|JAVA PROFILE'),                  "severity": "HIGH",  "pay": 1500},
    {"path": "/.svn/entries",               "match": re.compile(r'^\d+\s', re.M),                            "severity": "MED",   "pay": 250},
    {"path": "/.DS_Store",                  "match": re.compile(rb'\x00\x00\x00\x01Bud1', re.DOTALL),       "severity": "INFO",  "pay": 100,  "binary": True},
    {"path": "/phpinfo.php",                "match": re.compile(r'<title>phpinfo|PHP Version', re.I),       "severity": "MED",   "pay": 500},
    {"path": "/config.json",                "match": re.compile(r'"(api_secret|secret_key|access_key|admin_password|aws_secret_access_key|stripe_secret|database_url|jwt_secret|private_key|service_account)"\s*:\s*"[^"]{16,}"', re.I), "severity": "HIGH", "pay": 1000},
    {"path": "/backup.sql",                 "match": re.compile(r'CREATE TABLE|INSERT INTO', re.I),         "severity": "CRIT",  "pay": 3000},
    {"path": "/database.sql",               "match": re.compile(r'CREATE TABLE|INSERT INTO', re.I),         "severity": "CRIT",  "pay": 3000},
    {"path": "/.npmrc",                     "match": re.compile(r'_authToken|registry='),                    "severity": "HIGH",  "pay": 1000},
    {"path": "/.htpasswd",                  "match": re.compile(r'^[a-z][a-z0-9._-]*:\$', re.M),            "severity": "HIGH",  "pay": 750},
]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Treat 3xx as terminal — do NOT follow. Redirects = FP for exposed-file probes."""
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

_OPENER = urllib.request.build_opener(NoRedirectHandler(),
    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))


def http_probe(url, timeout=8, binary=False):
    """Return (status, body_bytes_or_text). Does NOT follow redirects."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with _OPENER.open(req, timeout=timeout) as r:
            status = r.status
            # Reject 3xx (redirect = file doesn't exist where we asked)
            if 300 <= status < 400:
                return status, ""
            body = r.read(50000)
            return status, body if binary else body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def load_ledger():
    if not LEDGER.exists(): return set()
    seen = set()
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            try:
                d = json.loads(line)
                seen.add(f"{d['url']}|{d['path']}")
            except: pass
    return seen


def append_ledger(record):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(record) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-targets", type=int, default=40)
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] web-exposed-files patrol — {len(seen)} prior hits in ledger", flush=True)

    hits = []
    target_count = 0
    for apex in TARGETS[:args.max_targets]:
        for prefix in SUB_PREFIXES:
            host = f"{prefix}{apex}"
            for probe in PROBES:
                url = f"https://{host}{probe['path']}"
                key = f"{host}|{probe['path']}"
                if key in seen: continue
                target_count += 1
                is_binary = probe.get("binary", False)
                status, body = http_probe(url, binary=is_binary)
                time.sleep(0.2)
                if status != 200: continue
                if not body: continue
                # Match check (body can be bytes for binary patterns)
                m = probe["match"].search(body)
                if not m: continue
                rec = {
                    "url": host, "path": probe["path"], "severity": probe["severity"],
                    "pay": probe["pay"],
                    "snippet": (body[:200].decode("utf-8","replace") if is_binary else body[:200]).replace("\n"," "),
                    "found_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                append_ledger(rec)
                hits.append(rec)
                print(f"  🔴🔴 {probe['severity']:<4} ${probe['pay']:>4}  https://{host}{probe['path']}", flush=True)
        # Per-apex tick
        print(f"  [scanned {apex}]", flush=True)
        time.sleep(0.4)

    print(f"\n[+] scan complete: {len(hits)} exposed files across {target_count} probes")
    if hits:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as f:
            f.write(f"# Web-exposed files — {datetime.now().strftime('%Y-%m-%d %H:%M')} (PRIVATE)\n\n")
            f.write(f"**Probes:** {target_count}\n**Hits:** {len(hits)}\n")
            f.write(f"**Expected payout total:** ${sum(h['pay'] for h in hits):,}\n\n")
            f.write("| Severity | $ | URL | Snippet |\n|---|---|---|---|\n")
            for h in sorted(hits, key=lambda x: -x['pay']):
                f.write(f"| **{h['severity']}** | ${h['pay']:,} | https://{h['url']}{h['path']} | `{h['snippet'][:100]}` |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
