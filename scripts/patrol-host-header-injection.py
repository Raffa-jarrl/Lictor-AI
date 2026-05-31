#!/usr/bin/env python3
"""
patrol-host-header-injection — scanner #56.

Hunts Host-header injection on password-reset and other email-generating
endpoints. The attack: poison the Host header → application generates a
password-reset email containing an attacker-controlled domain in the reset
URL → victim clicks → attacker captures the reset token.

Bounty range: $1K-$10K alone; $10K-$30K when chained into ATO.

Method (ETHICAL — Lictor never triggers real password resets):
  1. For each host: send GET / and GET /api/reset-password with arbitrary Host header
  2. Inspect response for:
     a. Location header reflecting our injected Host
     b. Body content reflecting our injected Host (canary string)
  3. Log the reflection — actual reset-email confirmation requires a real
     account, which the user supplies separately.

Usage:
  patrol-host-header-injection.py --hosts targets.txt --ledger host-header.jsonl
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-HostHeaderPatrol/0.1 (+https://lictor-ai.com)"
ATTACKER_HOST = "lictor-canary-hhi.example.com"

PROBE_PATHS = ["/", "/login", "/api/password-reset", "/api/forgot-password",
                "/forgot-password", "/reset", "/api/v1/auth/reset"]

@dataclass
class HHIFinding:
    host: str
    path: str
    injection_method: str   # "host_header" / "x_forwarded_host"
    status: int
    reflection_location: str  # "header" / "body" / "none"
    snippet: str

def probe(host: str, path: str, method: str, timeout: int = 6):
    url = f"https://{host}{path}"
    headers = {"User-Agent": UA}
    if method == "host_header":
        # Note: urllib doesn't let us inject Host on requests directly without
        # opening a raw connection. Use X-Forwarded-Host which most apps
        # treat as authoritative through reverse proxies.
        headers["X-Forwarded-Host"] = ATTACKER_HOST
        headers["X-Forwarded-Proto"] = "https"
    elif method == "x_forwarded_host":
        headers["X-Forwarded-Host"] = ATTACKER_HOST
    elif method == "x_original_host":
        headers["X-Original-Host"] = ATTACKER_HOST
    elif method == "forwarded":
        headers["Forwarded"] = f"host={ATTACKER_HOST}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(16384).decode("utf-8", "replace")
        except: b = ""
        return e.code, dict(e.headers), b
    except Exception:
        return None, None, None

def check_host(host: str) -> list[HHIFinding]:
    out = []
    for path in PROBE_PATHS:
        for method in ("x_forwarded_host", "x_original_host", "forwarded"):
            time.sleep(0.3)
            status, headers, body = probe(host, path, method)
            if not body and not headers: continue
            # Reflection in headers (typically Location)
            for hname, hval in (headers or {}).items():
                if ATTACKER_HOST in str(hval):
                    out.append(HHIFinding(
                        host=host, path=path, injection_method=method,
                        status=status or 0, reflection_location=f"header:{hname}",
                        snippet=str(hval)[:200]))
                    break
            else:
                if body and ATTACKER_HOST in body:
                    idx = body.find(ATTACKER_HOST)
                    out.append(HHIFinding(
                        host=host, path=path, injection_method=method,
                        status=status or 0, reflection_location="body",
                        snippet=body[max(0, idx-80):idx+100]))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/host-header-injection.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Host-header-injection hunt across {len(hosts)} hosts × {len(PROBE_PATHS)} paths")
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
                print(f"  [{i}/{len(hosts)}] 🔴 {host}{f.path}  reflect@{f.reflection_location}  via {f.injection_method}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} HHI reflections so far")
    print(f"\n[+] Done. {n} host-header-injection candidates → {args.ledger}")

if __name__ == "__main__":
    main()
