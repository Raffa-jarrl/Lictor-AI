#!/usr/bin/env python3
"""
patrol-open-redirect — scanner #55.

Hunts open-redirect endpoints. Top-tier HackerOne pattern: an unvalidated
redirect parameter (?next=, ?url=, ?redirect=, ?return=) accepts an external
URL and 302s the browser to it. Used for phishing + chained into OAuth ATO.

Bounty range: $500-$5K alone; $5K-$25K if chains into OAuth account takeover.

Method (ETHICAL — Lictor never actually navigates):
  1. For each host: probe a curated list of redirect-prone endpoint shapes
     with `?<param>=https://attacker.example.com/lictor-canary`
  2. Inspect the response: a 30x with Location pointing to attacker host = vuln
  3. Log status + Location header.

Usage:
  patrol-open-redirect.py --hosts targets.txt --ledger open-redirect.jsonl
"""
from __future__ import annotations
import argparse, json, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-OpenRedirectPatrol/0.1 (+https://lictor-ai.com)"
ATTACKER_HOST = "https://attacker.example.com/lictor-canary-open-redirect"

REDIRECT_PATHS = [
    ("/login", ["next", "redirect", "url", "return", "returnTo", "redirect_uri"]),
    ("/signin", ["next", "redirect", "url", "return"]),
    ("/logout", ["next", "redirect", "url", "return"]),
    ("/auth", ["redirect_uri", "url"]),
    ("/oauth/callback", ["redirect_uri", "state"]),
    ("/redirect", ["url", "to", "target"]),
    ("/r", ["url", "target"]),
    ("/go", ["url", "to"]),
    ("/out", ["url"]),
    ("/exit", ["url"]),
    ("/track", ["url"]),
    ("/api/redirect", ["url"]),
    ("/api/v1/redirect", ["url"]),
    ("/api/logout", ["redirect"]),
]

@dataclass
class RedirectFinding:
    host: str
    path: str
    param: str
    full_url: str
    status: int
    location_header: str
    classification: str   # "open_redirect" / "filtered" / "no_redirect" / "error"

def probe(host: str, path: str, param: str, timeout: int = 6):
    qs = urllib.parse.urlencode({param: ATTACKER_HOST})
    url = f"https://{host}{path}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), url
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), url
    except Exception:
        return None, None, url

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

def classify(status: int | None, headers: dict | None) -> str:
    if status is None: return "error"
    if not headers: return "error"
    loc = headers.get("Location", "") or headers.get("location", "")
    if status in (301, 302, 303, 307, 308):
        if "attacker.example.com" in loc:
            return "open_redirect"
        return "filtered"
    return "no_redirect"

def check_host(host: str) -> list[RedirectFinding]:
    out = []
    for path, params in REDIRECT_PATHS:
        for p in params:
            time.sleep(0.2)
            status, headers, url = probe(host, path, p)
            cls = classify(status, headers)
            if cls == "open_redirect":
                out.append(RedirectFinding(
                    host=host, path=path, param=p, full_url=url,
                    status=status or 0,
                    location_header=(headers or {}).get("Location", "")[:200],
                    classification=cls))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/open-redirect.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Open-redirect hunt: {len(hosts)} hosts × {sum(len(p) for _,p in REDIRECT_PATHS)} combos")
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
                print(f"  [{i}/{len(hosts)}] 🔴 {host}{f.path}?{f.param}=  → {f.location_header[:60]}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} open-redirects so far")
    print(f"\n[+] Done. {n} open-redirects → {args.ledger}")

if __name__ == "__main__":
    main()
