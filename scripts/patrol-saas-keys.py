#!/usr/bin/env python3
"""
patrol-saas-keys — hunt hardcoded SaaS API keys in public GitHub source.

Each vendor has a distinct prefix that's high-precision. GitHub auto-revokes
the obvious ones (Stripe, OpenAI, AWS) — but doesn't catch all of these.
And even when GitHub does scan, the keys often stay live long enough to be
abused before the maintainer rotates.

Vendors covered:
  - Mailchimp: <hex>-us<digits>      (~32 chars + DC suffix)
  - Twilio:    AC<32hex> account SID + auth_token
  - SendGrid:  SG.<43+chars>.<43+chars>
  - Algolia:   admin API key (32 hex chars near 'algolia')
  - Mapbox:    sk.<token>             (secret token, not public pk.)
  - Postmark:  <UUID>-<UUID>-<UUID>-<UUID>-<UUID> server token

For each match:
  1. Fetch file
  2. Verify pattern + context (skip obvious placeholders, test fixtures)
  3. Filter to fresh repos (last 365 days), skip archived
  4. Write outreach queue
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

VENDORS = [
    ("mailchimp",
     re.compile(r'\b([0-9a-f]{32}-us\d{1,3})\b'),
     [
         '"mailchimp" "us1" extension:py',
         '"mailchimp" "-us" extension:js',
         '"mailchimp" "-us" extension:ts',
         'MAILCHIMP_API_KEY extension:env',
         'MAILCHIMP_API_KEY extension:py',
     ]),
    ("sendgrid",
     re.compile(r'\b(SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,50})\b'),
     [
         '"SG." "sendgrid" extension:py',
         '"SG." "sendgrid" extension:js',
         '"SG." extension:env',
         'SENDGRID_API_KEY extension:env',
     ]),
    ("twilio-token",
     re.compile(r'\b(AC[a-f0-9]{32})\b.{0,100}?\b([a-f0-9]{32})\b', re.DOTALL),
     [
         '"twilio" "AC" extension:py',
         '"twilio" "auth_token" extension:js',
         'TWILIO_AUTH_TOKEN extension:env',
     ]),
    ("postmark",
     re.compile(r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b'),
     [
         '"postmark" "server_token" extension:py',
         '"postmark" "POSTMARK_API_TOKEN" extension:env',
         'POSTMARK_SERVER_TOKEN extension:env',
     ]),
    ("mapbox-secret",
     re.compile(r'\b(sk\.eyJ[A-Za-z0-9_-]{60,200}\.[A-Za-z0-9_-]{15,30})\b'),
     [
         '"mapbox" "sk.eyJ" extension:js',
         '"mapbox" "sk.eyJ" extension:py',
         'MAPBOX_SECRET_TOKEN extension:env',
     ]),
    ("algolia-admin",
     re.compile(r'algolia[^a-z]*admin[_-]?(?:api_?)?key[^a-z]*[\'"]([a-f0-9]{32})[\'"]', re.IGNORECASE),
     [
         '"algolia" "admin_api_key" extension:js',
         '"algolia" "admin_api_key" extension:py',
         'ALGOLIA_ADMIN_API_KEY extension:env',
     ]),
]

PLACEHOLDER_CTX = re.compile(
    r'(your|example|placeholder|REPLACE|XXX|TODO|getenv|process\.env|<.*>|test|demo|sample|fake|0{8,}|x{8,})',
    re.IGNORECASE,
)
SKIP_PATH_RX = re.compile(r'(\.example$|/tests?/|/__tests__/|/spec/|/fixtures?/|/docs?/|README|CHANGELOG)', re.IGNORECASE)


@dataclass
class Hit:
    vendor: str
    repo: str
    path: str
    url: str
    redacted: str
    stars: int = 0
    pushed_at: str = ""


def gh_code_search(query, max_pages=2):
    seen, results = set(), []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            results.append(it)
        time.sleep(2)
    return results


def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode().strip().replace("\n","")).decode("utf-8","replace")
    except Exception:
        return None


def gh_repo_meta(repo):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "--jq",
             '{stars: .stargazers_count, pushed_at: .pushed_at, archived: .archived}'],
            stderr=subprocess.DEVNULL, timeout=10)
        return json.loads(out)
    except Exception:
        return {}


def verify(item, vendor, rx, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    if SKIP_PATH_RX.search(path):
        return None
    content = gh_raw_file(repo, path)
    if not content: return None
    m = rx.search(content)
    if not m: return None
    val = m.group(1) if m.lastindex else m.group(0)
    start = m.start()
    ctx = content[max(0, start-80):min(len(content), start+80)]
    if PLACEHOLDER_CTX.search(ctx): return None
    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None
    pushed = meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days:
            return None
    except Exception:
        return None
    red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
    return Hit(vendor=vendor, repo=repo, path=path, url=item["html_url"],
               redacted=red, stars=meta.get("stars",0),
               pushed_at=meta.get("pushed_at","")[:10])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200, help="Total candidates to inspect across all vendors")
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--private", default=f"docs/launch/patrol-saas-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    seen_keys = set()
    raw_cands = []
    print(f"[+] querying {sum(len(q) for _,_,q in VENDORS)} search patterns across {len(VENDORS)} vendors...", flush=True)
    for vendor, rx, queries in VENDORS:
        for q in queries:
            items = gh_code_search(q, max_pages=1)
            for it in items:
                key = (it["repository"]["full_name"], it["path"], vendor)
                if key in seen_keys: continue
                seen_keys.add(key)
                raw_cands.append((vendor, rx, it))
                if len(raw_cands) >= args.max: break
            if len(raw_cands) >= args.max: break
        if len(raw_cands) >= args.max: break

    print(f"[+] {len(raw_cands)} candidates to verify...", flush=True)
    hits = []
    for i, (vendor, rx, item) in enumerate(raw_cands, 1):
        repo = item["repository"]["full_name"]
        path = item["path"]
        print(f"  [{i}/{len(raw_cands)}] {vendor} {repo}/{path}", end="", flush=True)
        try:
            h = verify(item, vendor, rx, args.max_age_days)
            if h:
                hits.append(h)
                print(f"  🔴 {h.vendor} {h.redacted}  ★{h.stars}", flush=True)
            else:
                print("  ⚪", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(1.0)

    md = [f"# Patrol — SaaS-key exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Candidates inspected:** {len(raw_cands)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Vendor | Repo | Path | ★ | Pushed | Redacted | File |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: (-x.stars, x.vendor)):
        md.append(f"| {h.vendor} | `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.redacted}` | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} confirmed SaaS-key exposures.")
    print(f"[+] Private: {args.private}")


if __name__ == "__main__":
    main()
