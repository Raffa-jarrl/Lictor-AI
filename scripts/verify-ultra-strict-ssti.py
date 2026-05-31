#!/usr/bin/env python3
"""
verify-ultra-strict-ssti — final pass to eliminate coincidence-based SSTI FPs.

Sends {{1337*1337}} → expects 1787569 (a 7-digit number unlikely to appear
coincidentally in any normal page content).

For each candidate that survived the 3-probe strict verifier:
  1. Send {{1337*1337}} via the same endpoint+param
  2. If "1787569" in response AND "{{1337*1337}}" NOT in response → REAL SSTI
  3. Otherwise → coincidence FP

Output: ssti-ultra-strict.jsonl with classification ∈ {confirmed_final, fp_coincidence}
"""
from __future__ import annotations
import argparse, json, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-UltraVerify/0.3 (+https://lictor-ai.com)"

PROBE = "{{1337*1337}}"
EXPECTED = "1787569"

@dataclass
class UltraVerdict:
    host: str
    endpoint: str
    param: str
    classification: str   # "confirmed_final" / "fp_coincidence" / "stale"
    notes: str = ""

def probe(host: str, ep: str, param: str, timeout: int = 8):
    qs = urllib.parse.urlencode({param: PROBE})
    url = f"https://{host}{ep}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.read(16384).decode("utf-8", "replace")
        except: return ""
    except Exception:
        return None

def verify(candidate: dict) -> UltraVerdict:
    host = candidate.get("host", "")
    orig = candidate.get("original", {}) or candidate
    ep = orig.get("endpoint", "")
    param = orig.get("param", "")
    body = probe(host, ep, param)
    if body is None:
        return UltraVerdict(host, ep, param, "stale", "unreachable")
    if EXPECTED in body and PROBE not in body:
        return UltraVerdict(host, ep, param, "confirmed_final",
                             f"1337*1337={EXPECTED} found in response — REAL SSTI confirmed via uncommon-number test")
    return UltraVerdict(host, ep, param, "fp_coincidence",
                         f"no {EXPECTED} in response — original 49+64+81 matches were coincidence")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp",
                     default="/Users/raffa/Lictor/v3/ledgers/ssti-strict-verified.jsonl")
    ap.add_argument("--out",
                     default="/Users/raffa/Lictor/v3/ledgers/ssti-ultra-strict.jsonl")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()

    candidates = []
    with open(args.inp) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                v = json.loads(line)
                if v.get("classification") == "confirmed_real":
                    candidates.append(v)
            except: pass

    # Dedupe by (host, endpoint, param) — multiple engine probes can hit same triple
    seen = set()
    unique = []
    for c in candidates:
        orig = c.get("original", {}) or c
        key = (c.get("host"), orig.get("endpoint"), orig.get("param"))
        if key in seen: continue
        seen.add(key)
        unique.append(c)
    print(f"[+] {len(candidates)} strict-verified → {len(unique)} unique (host,endpoint,param) tuples")

    n_real, n_fp = 0, 0
    with open(args.out, "w") as fout, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(verify, c): c for c in unique}
        for i, fut in enumerate(as_completed(futures), 1):
            try: v = fut.result()
            except Exception: continue
            fout.write(json.dumps(asdict(v)) + "\n"); fout.flush()
            if v.classification == "confirmed_final":
                n_real += 1
                print(f"  🔴 ULTRA-CONFIRMED: {v.host:35s} {v.endpoint:25s} param={v.param}")
            else:
                n_fp += 1
    print(f"\n[+] Done. {n_real} ULTRA-CONFIRMED (definitely real SSTI), {n_fp} eliminated as coincidence")
    print(f"[+] Output: {args.out}")

if __name__ == "__main__":
    main()
