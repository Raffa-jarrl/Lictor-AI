#!/usr/bin/env python3
"""
patrol-cache-poisoning — scanner #57.

Hunts web cache poisoning candidates. Pattern: an unkeyed header (X-Forwarded-Host,
X-Original-URL, etc.) influences the cached response body, allowing an attacker
to poison the cache for all subsequent requests.

Bounty range: $5K-$25K typical.

Method (ETHICAL — Lictor sends a benign poison payload to a unique CACHE-BUSTER URL):
  1. For each host: GET /?lictor-cb=<unique> with poison headers
  2. GET /?lictor-cb=<unique> again WITHOUT poison headers
  3. If the second response still contains the poison reflection → cache poisoning
  4. Use unique cache-buster param per probe — does NOT affect real-user caches.

Usage:
  patrol-cache-poisoning.py --hosts targets.txt --ledger cache-poisoning.jsonl
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-CachePatrol/0.1 (+https://lictor-ai.com)"
POISON_CANARY = "lictor-canary-poison-XYZ123"

UNKEYED_HEADERS_TO_TEST = [
    ("X-Forwarded-Host",   f"{POISON_CANARY}.example.com"),
    ("X-Host",             f"{POISON_CANARY}.example.com"),
    ("X-Forwarded-Server", f"{POISON_CANARY}.example.com"),
    ("X-HTTP-Host-Override", f"{POISON_CANARY}.example.com"),
    ("Forwarded",          f"host={POISON_CANARY}.example.com"),
    ("X-Original-URL",     f"/{POISON_CANARY}"),
    ("X-Rewrite-URL",      f"/{POISON_CANARY}"),
]

@dataclass
class CacheFinding:
    host: str
    path: str
    header_name: str
    poison_canary: str
    cached: bool
    snippet: str

def fetch(url: str, extra_headers: dict, timeout: int = 6):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **extra_headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(32768).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(32768).decode("utf-8", "replace")
        except: b = ""
        return e.code, dict(e.headers), b
    except Exception:
        return None, None, None

def check_host(host: str) -> list[CacheFinding]:
    out = []
    for hname, hval in UNKEYED_HEADERS_TO_TEST:
        unique_cb = f"{POISON_CANARY}-{hash(host + hname) & 0xffffff:06x}"
        url = f"https://{host}/?lictor-cb={unique_cb}"
        # Pass 1: poison
        time.sleep(0.4)
        s1, h1, b1 = fetch(url, {hname: hval})
        if not b1: continue
        if hval not in b1 and unique_cb not in b1: continue  # no reflection
        # Pass 2: clean request to same URL — does cache replay the poison?
        time.sleep(2)
        s2, h2, b2 = fetch(url, {})
        if not b2: continue
        cache_hit = (h2 or {}).get("X-Cache", "") + (h2 or {}).get("CF-Cache-Status", "")
        if hval in b2:
            idx = b2.find(hval)
            out.append(CacheFinding(
                host=host, path="/", header_name=hname,
                poison_canary=hval, cached=True,
                snippet=b2[max(0, idx-80):idx+120].replace("\n"," ")))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/cache-poisoning.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Cache-poisoning hunt across {len(hosts)} hosts × {len(UNKEYED_HEADERS_TO_TEST)} header tests")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                hits = fut.result()
            except Exception:
                continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n += 1
                print(f"  [{i}/{len(hosts)}] 🔴 {host}  CACHE-POISON via {f.header_name}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} cache-poisoning so far")
    print(f"\n[+] Done. {n} cache-poisoning candidates → {args.ledger}")

if __name__ == "__main__":
    main()
