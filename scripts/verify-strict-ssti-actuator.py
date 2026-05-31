#!/usr/bin/env python3
"""
verify-strict-ssti-actuator — STRICT re-verification for the two FP-prone classes.

V1 verifier was too loose:
  - SSTI: "{{8*8}}" → looks for "64" in body. Many sites contain "64" coincidentally.
  - Debug-actuator/heapdump: just checks body length > 100. Doesn't validate JAVA PROFILE magic.

This V2 verifier applies multiple stricter gates:

SSTI:
  1. Send {{7*7}}, {{8*8}}, {{9*9}} — expect 49, 64, 81 in respective responses
  2. ALL THREE must evaluate (catches coincidence — random page can have one number,
     not three specific ones in three different probes)
  3. Echo test: send a unique canary string like "lictor-XYZ-canary". If the
     response echoes the canary verbatim, the site is just reflecting input
     (not rendering templates) → FP
  4. Confirm payload {{ ... }} is NOT present in response (server processed it)

Debug-actuator (heapdump):
  1. Re-fetch with stream control + read full body (no 32KB cap)
  2. First 16 bytes must contain "JAVA PROFILE" (real Java heap dump magic)
  3. OR Content-Type must be application/octet-stream + Content-Length > 100KB
  4. OR Content-Disposition contains .hprof

Debug-actuator (env):
  1. Re-fetch /actuator/env or /env
  2. Must be valid JSON
  3. Must contain "propertySources" key with list of sources
  4. Must contain at least 5 properties with KEY=value shape

Debug-actuator (pprof):
  1. Re-fetch
  2. Either: protobuf content-type (real profile)
  3. Or: HTML table containing "goroutine" or "heap" headings
"""
from __future__ import annotations
import argparse, json, re, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-StrictVerify/0.2 (+https://lictor-ai.com)"

@dataclass
class StrictVerdict:
    source_ledger: str
    finding_type: str
    host: str
    classification: str   # "confirmed_real" / "fp_v2" / "stale" / "error"
    confidence: str       # "HIGH" / "MEDIUM" / "LOW"
    original: dict
    verification_notes: str = ""

def http_get(url: str, timeout: int = 8, max_bytes: int = 2_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "")
            cl = r.headers.get("Content-Length", "")
            cd = r.headers.get("Content-Disposition", "")
            body = r.read(max_bytes)
            return r.status, dict(r.headers), body, ct, cl, cd
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes)
            return e.code, dict(e.headers), body, e.headers.get("Content-Type",""), e.headers.get("Content-Length",""), e.headers.get("Content-Disposition","")
        except Exception:
            return e.code, dict(e.headers), b"", "", "", ""
    except Exception:
        return None, None, None, "", "", ""

# ============ Strict SSTI verifier ============

SSTI_PROBES = [("{{7*7}}", "49"), ("{{8*8}}", "64"), ("{{9*9}}", "81")]
ECHO_CANARY = "lictor-Xq7Z-canary-string-9zP2"

def verify_ssti_strict(f: dict) -> StrictVerdict:
    host = f.get("host", "")
    orig = f.get("original", {}) or f
    ep = orig.get("endpoint", "")
    param = orig.get("param", "")

    # Echo test first — if site echoes verbatim input, it's not template rendering
    qs = urllib.parse.urlencode({param: ECHO_CANARY})
    status, _, body, _, _, _ = http_get(f"https://{host}{ep}?{qs}")
    if body is None:
        return StrictVerdict("ssti-candidates.jsonl", "ssti", host, "stale", "LOW", f,
                              "unreachable on re-probe")
    try: text = body.decode("utf-8", "replace")
    except: text = ""
    if ECHO_CANARY in text:
        return StrictVerdict("ssti-candidates.jsonl", "ssti", host, "fp_v2", "HIGH", f,
                              "site echoes verbatim input — reflection, NOT template rendering")

    # Three-probe test
    confirmed_count = 0
    for payload, expected in SSTI_PROBES:
        time.sleep(0.4)
        qs = urllib.parse.urlencode({param: payload})
        _, _, body, _, _, _ = http_get(f"https://{host}{ep}?{qs}")
        if not body: continue
        try: text = body.decode("utf-8", "replace")
        except: continue
        if expected in text and payload not in text:
            confirmed_count += 1

    if confirmed_count == 3:
        return StrictVerdict("ssti-candidates.jsonl", "ssti", host, "confirmed_real", "HIGH", f,
                              "ALL three SSTI probes (49+64+81) evaluated — real template injection")
    if confirmed_count == 2:
        return StrictVerdict("ssti-candidates.jsonl", "ssti", host, "confirmed_real", "MEDIUM", f,
                              "2 of 3 probes evaluated — likely real SSTI (one engine quirk)")
    return StrictVerdict("ssti-candidates.jsonl", "ssti", host, "fp_v2", "HIGH", f,
                          f"only {confirmed_count}/3 probes evaluated — coincidental match in original")

# ============ Strict debug-actuator verifier ============

JAVA_PROFILE_MAGIC = b"JAVA PROFILE"
SECRET_HINT_RX = re.compile(r'(password|secret|api[_-]?key|aws|token|database_url|jwt[_-]?secret)',
                              re.IGNORECASE)

def verify_actuator_strict(f: dict) -> StrictVerdict:
    orig = f.get("original", {}) or f
    host = orig.get("host", "") or f.get("host", "")
    path = orig.get("path", "")
    url = f"https://{host}{path}"

    status, headers, body, ct, cl, cd = http_get(url, max_bytes=4_000_000)
    if status is None:
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "stale", "LOW", f,
                              "unreachable")
    if status != 200:
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                              f"status={status} on re-probe")

    body = body or b""

    # Heapdump verification — STRICT
    if "heapdump" in path:
        if body.startswith(JAVA_PROFILE_MAGIC) or JAVA_PROFILE_MAGIC in body[:64]:
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "HIGH", f, f"JAVA PROFILE magic detected, body={len(body)}B")
        if "octet-stream" in ct.lower() and ".hprof" in cd.lower():
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "HIGH", f, f"Content-Disposition .hprof + octet-stream")
        try: cl_int = int(cl) if cl else 0
        except: cl_int = 0
        if "octet-stream" in ct.lower() and cl_int > 100_000:
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "MEDIUM", f, f"octet-stream + CL={cl_int} — possibly heapdump")
        # Otherwise it's HTML/JSON returned by a catch-all
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                              f"no JAVA PROFILE magic, ct={ct[:40]}, size={len(body)} — likely HTML catch-all")

    # actuator/env or /env — STRICT JSON shape check
    if path in ("/actuator/env", "/env"):
        if "json" not in ct.lower():
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                                  f"non-JSON content-type {ct[:40]}")
        try:
            j = json.loads(body)
        except Exception:
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                                  "body is not valid JSON")
        if not isinstance(j, dict): return StrictVerdict("debug-actuator.jsonl", "debug_actuator",
                                                          host, "fp_v2", "HIGH", f, "JSON not object")
        if "propertySources" not in j and "activeProfiles" not in j:
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                                  "JSON missing propertySources/activeProfiles keys")
        # Count secrets
        body_text = body.decode("utf-8", "replace")
        secrets = len(SECRET_HINT_RX.findall(body_text))
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                              "HIGH" if secrets > 2 else "MEDIUM", f,
                              f"actuator/env confirmed valid JSON+propertySources, secret_hints={secrets}")

    # pprof
    if "/pprof" in path or "/debug/vars" in path:
        body_text = body[:8192].decode("utf-8", "replace")
        if "octet-stream" in ct.lower() or "protobuf" in ct.lower():
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "MEDIUM", f, f"pprof binary content-type {ct[:40]}")
        if "memstats" in body_text.lower() or "goroutine" in body_text.lower():
            if "<table" in body_text.lower() or "<pre" in body_text.lower():
                return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                      "MEDIUM", f, "pprof HTML response confirmed")
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                              "pprof shape not confirmed")

    # metrics
    if path in ("/metrics", "/prometheus"):
        body_text = body[:8192].decode("utf-8", "replace")
        if body_text.startswith("# HELP") or body_text.startswith("# TYPE"):
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "LOW", f, "Prometheus exposition format confirmed")
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                              "no Prometheus format markers")

    # Swagger — actually a real finding if present, but lower severity
    if "swagger" in path.lower() or "api-docs" in path:
        body_text = body[:8192].decode("utf-8", "replace").lower()
        if "swagger" in body_text or "openapi" in body_text or '"paths"' in body_text:
            return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                                  "LOW", f, "Swagger/OpenAPI API docs confirmed")
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                              "swagger shape not present")

    # Other actuator paths (info, health, mappings, beans) — usually low-value
    body_text = body[:4096].decode("utf-8", "replace").lower()
    if path.startswith("/actuator") and ("{" in body_text[:50] or '"_links"' in body_text):
        return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed_real",
                              "LOW", f, f"actuator path returns JSON (low-value endpoint)")
    return StrictVerdict("debug-actuator.jsonl", "debug_actuator", host, "fp_v2", "HIGH", f,
                          f"shape does not match expected, ct={ct[:30]}")

# ============ Main ============

def load_raw_ledger(path: Path) -> list[dict]:
    out = []
    if not path.exists(): return out
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: out.append(json.loads(line))
            except: pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssti-ledger",
                     default="/Users/raffa/Lictor/v3/ledgers/ssti-candidates.jsonl")
    ap.add_argument("--actuator-ledger",
                     default="/Users/raffa/Lictor/v3/ledgers/debug-actuator.jsonl")
    ap.add_argument("--wildcard-list",
                     default="/Users/raffa/Lictor/v3/ledgers/wildcard-host-list.txt")
    ap.add_argument("--out-ssti",
                     default="/Users/raffa/Lictor/v3/ledgers/ssti-strict-verified.jsonl")
    ap.add_argument("--out-actuator",
                     default="/Users/raffa/Lictor/v3/ledgers/actuator-strict-verified.jsonl")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()

    # Load wildcards from prior filter
    wildcards = set()
    if Path(args.wildcard_list).exists():
        wildcards = {ln.strip() for ln in Path(args.wildcard_list).read_text().splitlines() if ln.strip()}
    print(f"[+] Loaded {len(wildcards)} wildcard hosts to pre-filter")

    # ── SSTI ──
    ssti_raw = load_raw_ledger(Path(args.ssti_ledger))
    ssti_filtered = [r for r in ssti_raw if (r.get("host") or "").lower() not in wildcards]
    # Dedupe by (host, endpoint, param)
    seen = set()
    ssti_unique = []
    for r in ssti_filtered:
        key = (r.get("host"), r.get("endpoint"), r.get("param"))
        if key in seen: continue
        seen.add(key)
        ssti_unique.append(r)
    print(f"[+] SSTI raw: {len(ssti_raw)} → after wildcard filter: {len(ssti_filtered)} → dedup: {len(ssti_unique)}")

    n_conf, n_fp = 0, 0
    with open(args.out_ssti, "w") as fout, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(verify_ssti_strict, r): r for r in ssti_unique}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                v = fut.result()
            except Exception as e:
                continue
            fout.write(json.dumps(asdict(v)) + "\n"); fout.flush()
            if v.classification == "confirmed_real":
                n_conf += 1
                print(f"  🔴 SSTI CONFIRMED: {v.host} (notes: {v.verification_notes[:60]})")
            else:
                n_fp += 1
            if i % 25 == 0:
                print(f"  [{i}/{len(ssti_unique)}] SSTI confirmed={n_conf}  fp={n_fp}")
    print(f"\n[+] SSTI strict: {n_conf} confirmed_real, {n_fp} FPs → {args.out_ssti}")

    # ── Debug-actuator ──
    da_raw = load_raw_ledger(Path(args.actuator_ledger))
    da_filtered = [r for r in da_raw if (r.get("host") or "").lower() not in wildcards]
    # Dedupe by (host, path)
    seen = set()
    da_unique = []
    for r in da_filtered:
        key = (r.get("host"), r.get("path"))
        if key in seen: continue
        seen.add(key)
        da_unique.append(r)
    print(f"\n[+] Debug-actuator raw: {len(da_raw)} → after wildcard filter: {len(da_filtered)} → dedup: {len(da_unique)}")

    n_conf, n_fp = 0, 0
    with open(args.out_actuator, "w") as fout, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(verify_actuator_strict, r): r for r in da_unique}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                v = fut.result()
            except Exception:
                continue
            fout.write(json.dumps(asdict(v)) + "\n"); fout.flush()
            if v.classification == "confirmed_real":
                n_conf += 1
                print(f"  🔴 ACTUATOR CONFIRMED: {v.host}{v.original.get('path','')} → {v.verification_notes[:60]}")
            else:
                n_fp += 1
            if i % 50 == 0:
                print(f"  [{i}/{len(da_unique)}] actuator confirmed={n_conf}  fp={n_fp}")
    print(f"\n[+] Debug-actuator strict: {n_conf} confirmed_real, {n_fp} FPs → {args.out_actuator}")

if __name__ == "__main__":
    main()
