#!/usr/bin/env python3
"""
patrol-sourcemap-leak — scanner #23.

Hunts production sites that ship JS sourceMaps (.map files), which expose
the entire pre-minified source code including internal API endpoints,
auth flows, hardcoded comments, and sometimes secrets that weren't
supposed to ship. Bounty programs typically pay $200-$1500 for confirmed
production source-map exposure.

Method:
  1. Fetch apex / common subdomains for each bounty target
  2. Look in HTML for <script src=...> URLs
  3. For each JS file, fetch and check for sourceMappingURL=
  4. Attempt to fetch the .map file
  5. If 200 + valid JSON map → confirmed leak
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SourceMapPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "sourcemap-ledger.jsonl"

SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
SOURCEMAP_RX = re.compile(rb'sourceMappingURL=([^\s\*]+\.map)', re.I)


@dataclass
class SourceMapLeak:
    site: str; js_url: str; map_url: str; payout: int
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=6, max_size=500000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(max_size)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


def check_one(site):
    """Returns list of SourceMapLeaks for this site."""
    url = f"https://{site}/"
    status, body = http_get(url)
    if status != 200 or not body: return []
    # Find script srcs
    js_urls = []
    for m in SRC_RX.finditer(body.decode("utf-8", "replace")[:200000]):
        src = m.group(1)
        if src.startswith("//"): js_url = f"https:{src}"
        elif src.startswith("/"): js_url = f"https://{site}{src}"
        elif src.startswith("http"): js_url = src
        else: js_url = f"https://{site}/{src}"
        # Only same-site JS (CDN-hosted is usually intentional)
        if site not in js_url and "cdn" not in js_url: continue
        js_urls.append(js_url)
        if len(js_urls) >= 5: break

    leaks = []
    for js_url in js_urls:
        status, js_body = http_get(js_url, max_size=200000)
        if status != 200 or not js_body: continue
        # Look for sourceMappingURL comment in the JS
        m = SOURCEMAP_RX.search(js_body[-2048:])  # usually at the end
        if not m: continue
        map_ref = m.group(1).decode("utf-8", "replace")
        # Resolve relative map URL
        if map_ref.startswith("http"): map_url = map_ref
        elif map_ref.startswith("/"): map_url = f"https://{site}{map_ref}"
        else: map_url = js_url.rsplit("/", 1)[0] + "/" + map_ref
        # Try fetching the map
        status, map_body = http_get(map_url, max_size=10000)
        if status != 200: continue
        try:
            data = json.loads(map_body)
            if "version" in data and "sources" in data:
                leaks.append(SourceMapLeak(site=site, js_url=js_url, map_url=map_url, payout=500))
        except: pass
    return leaks


def append_ledger(f):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fp:
        fp.write(json.dumps(asdict(f)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"))
    ap.add_argument("--max-domains", type=int, default=300)
    ap.add_argument("--workers", type=int, default=50)
    args = ap.parse_args()

    apexes = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines() if l.strip()][:args.max_domains]
    PREFIXES = ["", "app.", "dashboard."]
    sites = [f"{p}{a}" for a in apexes for p in PREFIXES]
    print(f"[+] sourcemap patrol — {len(sites)} sites to check", flush=True)

    hits = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, s): s for s in sites}
        for fut in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"  [{completed}/{len(sites)}] {len(hits)} sites with leaks", flush=True)
            try: result = fut.result(timeout=30)
            except: result = []
            for l in (result or []):
                print(f"  🔴🔴 SOURCEMAP-LEAK  https://{l.site}  → {l.map_url}", flush=True)
                append_ledger(l); hits.append(l)
    print(f"\n[+] scan complete: {len(hits)} sourcemap exposures found")


if __name__ == "__main__": main()
