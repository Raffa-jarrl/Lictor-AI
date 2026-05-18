#!/usr/bin/env python3
"""
patrol-cloud-keys — 4 new vuln classes: Cloudflare / Twilio-SID / DataDog / Linear.

Why these 4 specifically:
- Cloudflare API tokens: 40-char base64-like, give full account access until revoked
- Twilio AccountSID: AC + 32 hex (paired with auth-token = SMS spend control)
- DataDog API keys: 32-hex DD keys, log/metric write access
- Linear API keys: lin_api_<64chars>, project / issue access

Each vendor's pattern is distinct enough for high-precision matching.
GitHub's auto-revocation covers some Stripe/OpenAI/AWS keys but rarely these.
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

VENDORS = [
    ("cloudflare",
     # Cloudflare API tokens are 40 chars, base64-like
     re.compile(r'(?:cloudflare|cf[\W_])[^a-z]{0,60}([A-Za-z0-9_-]{40})\b', re.IGNORECASE),
     [
         'cloudflare api_token extension:env',
         'CLOUDFLARE_API_TOKEN extension:env',
         '"cloudflare" "Bearer" extension:py',
         '"cloudflare" "Bearer" extension:js',
     ]),
    ("twilio-sid",
     re.compile(r'\b(AC[a-f0-9]{32})\b'),
     [
         'TWILIO_ACCOUNT_SID extension:env',
         '"twilio" "AC" extension:py',
         '"twilio" account_sid extension:js',
         '"twilio" account_sid extension:ts',
     ]),
    ("datadog-api",
     re.compile(r'(?:datadog|dd)[^a-z]{0,40}(?:api[_-]?key)[^a-z]{0,10}[\'"]([a-f0-9]{32})[\'"]', re.IGNORECASE),
     [
         'DATADOG_API_KEY extension:env',
         '"datadog" "api_key" extension:py',
         '"datadog" "api_key" extension:js',
         'DD_API_KEY extension:env',
     ]),
    ("linear-api",
     re.compile(r'(lin_api_[A-Za-z0-9]{40,})\b'),
     [
         '"lin_api_" extension:env',
         '"lin_api_" extension:py',
         '"lin_api_" extension:js',
         'LINEAR_API_KEY extension:env',
     ]),
]

PLACEHOLDER_CTX = re.compile(
    r'(your|example|placeholder|REPLACE|XXX|TODO|getenv|process\.env|os\.environ|<.*>|test|demo|sample|fake|0{8,}|x{8,})',
    re.IGNORECASE)
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


def gh_code_search(query, max_pages=1):
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
        return base64.b64decode(out.decode().strip().replace("\n", "")).decode("utf-8", "replace")
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
        pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days:
            return None
    except Exception:
        return None
    red = val[:8] + "…" + val[-4:] if len(val) > 14 else val
    return Hit(vendor=vendor, repo=repo, path=path, url=item["html_url"],
               redacted=red, stars=meta.get("stars", 0),
               pushed_at=meta.get("pushed_at", "")[:10])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=300, help="Total candidates to inspect")
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--private", default=f"docs/launch/patrol-cloudkeys-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    seen_keys = set()
    raw_cands = []
    print(f"[+] querying {sum(len(q) for _,_,q in VENDORS)} patterns across {len(VENDORS)} vendors...", flush=True)
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

    print(f"[+] {len(raw_cands)} candidates; verifying...", flush=True)
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
        time.sleep(0.8)

    md = [f"# Patrol — Cloud SaaS-key exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Candidates inspected:** {len(raw_cands)}",
          f"**Confirmed exposures:** {len(hits)}\n",
          "| Vendor | Repo | Path | ★ | Pushed | Redacted | File |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: (-x.stars, x.vendor)):
        md.append(f"| {h.vendor} | `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.redacted}` | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} confirmed cloud-key exposures.")
    print(f"[+] Private: {args.private}")


if __name__ == "__main__":
    main()
