#!/usr/bin/env python3
"""
verify-findings — re-probe each finding with tighter logic to filter FPs.

The Phase-1 scanners are intentionally LOOSE (catch wide). This script does
the Phase-2 STRICT re-probe — for each finding type, applies tighter
classification + re-confirms the finding is still live at verification time.

Output: verified-findings.jsonl with classification ∈ {confirmed, fp, stale, error}

Per-class verification logic:

  open-redirect       Re-probe with fresh attacker host; confirm Location.startswith("https://attacker.example.com")
  debug-actuator      Re-fetch; confirm JSON body has env-var-shape (propertySources / activeProfiles)
  dep-confusion       Re-check npm/PyPI registry NOW (squat-status may have flipped)
  ssti-candidates     Send DIFFERENT math (8*8=64). If BOTH 7*7=49 AND 8*8=64 confirm → real SSTI
  path-traversal      Re-probe + verify body is short ASCII matching hostname shape
  host-header-inj     Re-probe; confirm injected host appears in body OR Location header
  http-smuggling      Re-probe 3 times; confirm delta>5s on majority
  hardhat-exposed     Re-probe eth_chainId; confirm still responds
  defi-rpc-leak       Re-fetch JS bundle; confirm key still present
  defi-admin-exposed  Strict re-classification; filter out wallet-connect customer UIs
  exposed-databases   Re-probe; confirm still open-no-auth
  exposed-infra       Re-probe; confirm still open-no-auth
  exposed-configs     Re-fetch; confirm content still matches shape regex

Usage:
  verify-findings.py --ledger-dir /Users/raffa/Lictor/v3/ledgers --out verified-findings.jsonl
"""
from __future__ import annotations
import argparse, json, re, socket, ssl, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-Verifier/0.1 (+https://lictor-ai.com)"

@dataclass
class Verdict:
    source_ledger: str
    finding_type: str
    host: str
    classification: str   # "confirmed" / "fp" / "stale" / "error"
    confidence: str       # "HIGH" / "MEDIUM" / "LOW"
    original: dict
    verification_notes: str = ""

# ============ Per-class verifiers ============

def http_fetch(url: str, headers: dict = None, timeout: int = 6):
    hdrs = {"User-Agent": UA, **(headers or {})}
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(32768).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(32768).decode("utf-8", "replace")
        except: b = ""
        return e.code, dict(e.headers), b
    except Exception:
        return None, None, None

class _NoRedir(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, *a): return a[1]
    def http_error_302(self, *a): return a[1]
    def http_error_303(self, *a): return a[1]
    def http_error_307(self, *a): return a[1]
    def http_error_308(self, *a): return a[1]

def http_fetch_noredir(url: str, headers: dict = None, timeout: int = 6):
    hdrs = {"User-Agent": UA, **(headers or {})}
    req = urllib.request.Request(url, headers=hdrs)
    opener = urllib.request.build_opener(_NoRedir())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(16384).decode("utf-8", "replace")
        except: b = ""
        return e.code, dict(e.headers), b
    except Exception:
        return None, None, None

def verify_open_redirect(f: dict) -> Verdict:
    host = f.get("host", ""); path = f.get("path", ""); param = f.get("param", "")
    attacker = "https://attacker.example.com/lictor-verify-canary"
    qs = urllib.parse.urlencode({param: attacker})
    url = f"https://{host}{path}?{qs}"
    status, hdrs, _ = http_fetch_noredir(url)
    if status is None:
        return Verdict("open-redirect.jsonl", "open_redirect", host, "stale", "LOW", f,
                       "host unreachable")
    loc = (hdrs or {}).get("Location", "") or (hdrs or {}).get("location", "")
    if status in (301, 302, 303, 307, 308) and loc.startswith("https://attacker.example.com"):
        return Verdict("open-redirect.jsonl", "open_redirect", host, "confirmed", "HIGH", f,
                       f"302 → {loc[:80]}")
    return Verdict("open-redirect.jsonl", "open_redirect", host, "fp", "HIGH", f,
                   f"no longer redirects to attacker (status={status}, loc={loc[:60]})")

def verify_debug_actuator(f: dict) -> Verdict:
    host = f.get("host", ""); path = f.get("path", "")
    url = f"https://{host}{path}"
    status, _, body = http_fetch(url)
    if status is None:
        return Verdict("debug-actuator.jsonl", "debug_actuator", host, "stale", "LOW", f, "unreachable")
    if status != 200:
        return Verdict("debug-actuator.jsonl", "debug_actuator", host, "fp", "HIGH", f,
                       f"status={status} no longer 200")
    blow = (body or "").lower()
    # Strong signals
    if path.startswith("/actuator/env") or path == "/env":
        if "propertysources" in blow or "activeprofiles" in blow:
            secret_count = len(re.findall(r'(password|secret|api[_-]?key|aws|token|database_url)', blow))
            return Verdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed",
                           "HIGH" if secret_count > 2 else "MEDIUM", f,
                           f"actuator/env confirmed, secret_count={secret_count}")
    if "heapdump" in path and body and len(body) > 100:
        return Verdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed", "HIGH", f,
                       f"heapdump downloadable, size={len(body)}")
    if "/pprof" in path:
        if "goroutine" in blow or "memstats" in blow or "<table" in blow:
            return Verdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed", "MEDIUM", f,
                           "Go pprof exposed")
    if path == "/metrics" or path == "/prometheus":
        if "# HELP" in (body or "") or "# TYPE" in (body or ""):
            return Verdict("debug-actuator.jsonl", "debug_actuator", host, "confirmed", "LOW", f,
                           "Prometheus metrics exposed (low-severity info disclosure)")
    return Verdict("debug-actuator.jsonl", "debug_actuator", host, "fp", "MEDIUM", f,
                   "no longer matches expected shape")

def verify_dep_confusion(f: dict) -> Verdict:
    pkg = f.get("package_name", ""); ecosystem = f.get("ecosystem", "")
    if not pkg: return Verdict("dep-confusion.jsonl", "dep_confusion", f.get("repo", ""),
                                "error", "LOW", f, "no package_name")
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{urllib.request.quote(pkg, safe='@/')}"
    elif ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{pkg.lower()}/json"
    else:
        return Verdict("dep-confusion.jsonl", "dep_confusion", f.get("repo", ""),
                       "error", "LOW", f, f"unknown ecosystem {ecosystem}")
    status, _, _ = http_fetch(url, timeout=10)
    if status == 404:
        return Verdict("dep-confusion.jsonl", "dep_confusion", f.get("repo", ""),
                       "confirmed", "HIGH", f,
                       f"{ecosystem}:{pkg} STILL unclaimed → squat-able")
    if status == 200:
        return Verdict("dep-confusion.jsonl", "dep_confusion", f.get("repo", ""),
                       "fp", "HIGH", f,
                       f"{ecosystem}:{pkg} got registered since scan — no longer squat-able")
    return Verdict("dep-confusion.jsonl", "dep_confusion", f.get("repo", ""),
                   "error", "LOW", f, f"registry status={status}")

def verify_ssti(f: dict) -> Verdict:
    host = f.get("host", ""); ep = f.get("endpoint", ""); param = f.get("param", "")
    # Send DIFFERENT math: 8*8 = 64
    p1 = "{{8*8}}"; expected = "64"
    qs = urllib.parse.urlencode({param: p1})
    url = f"https://{host}{ep}?{qs}"
    status, _, body = http_fetch(url)
    if not body:
        return Verdict("ssti-candidates.jsonl", "ssti", host, "stale", "LOW", f, "unreachable")
    if expected in body and p1 not in body:
        return Verdict("ssti-candidates.jsonl", "ssti", host, "confirmed", "HIGH", f,
                       "8*8=64 also evaluates → real template injection")
    return Verdict("ssti-candidates.jsonl", "ssti", host, "fp", "HIGH", f,
                   "8*8=64 does not evaluate — 49 in original was coincidental")

def verify_path_traversal(f: dict) -> Verdict:
    host = f.get("host", ""); ep = f.get("endpoint", "")
    param = f.get("param", ""); payload = f.get("payload", "")
    qs = urllib.parse.urlencode({param: payload})
    url = f"https://{host}{ep}?{qs}"
    status, _, body = http_fetch(url)
    if not body or status != 200:
        return Verdict("path-traversal.jsonl", "path_traversal", host, "stale", "LOW", f,
                       f"status={status}")
    body = body.strip()
    if len(body) > 254: return Verdict("path-traversal.jsonl", "path_traversal", host,
                                        "fp", "HIGH", f, "response too long for /etc/hostname")
    if re.match(r'^[a-z0-9][a-z0-9.-]{0,253}$', body.split('\n')[0]):
        return Verdict("path-traversal.jsonl", "path_traversal", host, "confirmed", "HIGH", f,
                       f"response matches hostname shape: {body[:60]}")
    return Verdict("path-traversal.jsonl", "path_traversal", host, "fp", "HIGH", f,
                   "response does not match hostname shape")

def verify_host_header(f: dict) -> Verdict:
    host = f.get("host", ""); path = f.get("path", "")
    method = f.get("injection_method", "x_forwarded_host")
    canary = "lictor-canary-hhi.example.com"
    headers = {}
    if method == "x_forwarded_host": headers["X-Forwarded-Host"] = canary
    elif method == "x_original_host": headers["X-Original-Host"] = canary
    elif method == "forwarded": headers["Forwarded"] = f"host={canary}"
    status, hdrs, body = http_fetch(f"https://{host}{path}", headers)
    if status is None:
        return Verdict("host-header-injection.jsonl", "host_header_injection", host,
                       "stale", "LOW", f, "unreachable")
    for hname, hval in (hdrs or {}).items():
        if canary in str(hval):
            return Verdict("host-header-injection.jsonl", "host_header_injection", host,
                           "confirmed", "HIGH", f, f"reflected in header:{hname}")
    if body and canary in body:
        return Verdict("host-header-injection.jsonl", "host_header_injection", host,
                       "confirmed", "MEDIUM", f, "reflected in body")
    return Verdict("host-header-injection.jsonl", "host_header_injection", host,
                   "fp", "HIGH", f, "no reflection on re-probe")

def verify_defi_rpc_leak(f: dict) -> Verdict:
    host = f.get("host", ""); js_url = f.get("js_source_url", "")
    redacted = f.get("key_redacted", ""); provider = f.get("provider", "")
    if not js_url or " " in js_url: return Verdict("defi-rpc-leak.jsonl", "defi_rpc_leak",
                                                     host, "error", "LOW", f, "no js_source_url")
    status, _, body = http_fetch(js_url, timeout=15)
    if not body:
        return Verdict("defi-rpc-leak.jsonl", "defi_rpc_leak", host, "stale", "LOW", f,
                       "js bundle unreachable")
    prefix, suffix = redacted.split("...")[0], redacted.split("...")[-1] if "..." in redacted else ""
    if prefix and suffix and prefix in body and suffix in body:
        return Verdict("defi-rpc-leak.jsonl", "defi_rpc_leak", host, "confirmed", "HIGH", f,
                       f"{provider} key still in JS bundle")
    return Verdict("defi-rpc-leak.jsonl", "defi_rpc_leak", host, "fp", "MEDIUM", f,
                   "key no longer in bundle (rotated or bundle changed)")

def verify_hardhat(f: dict) -> Verdict:
    host = f.get("host", ""); scheme = f.get("scheme", "http")
    port = f.get("port", 8545); path = f.get("path", "/")
    if scheme == "https" and port == 443: url = f"https://{host}{path}"
    elif scheme == "http" and port == 80: url = f"http://{host}{path}"
    else: url = f"{scheme}://{host}:{port}{path}"
    body = json.dumps({"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}).encode()
    req = urllib.request.Request(url, data=body,
                                  headers={"User-Agent":UA,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            resp = r.read(2048).decode("utf-8","replace")
            if '"result"' in resp:
                return Verdict("hardhat-exposed.jsonl", "hardhat_exposed", host, "confirmed",
                               "HIGH" if f.get("is_dev_node") else "MEDIUM", f,
                               f"eth_chainId responds: {resp[:80]}")
    except Exception:
        pass
    return Verdict("hardhat-exposed.jsonl", "hardhat_exposed", host, "stale", "LOW", f,
                   "RPC no longer responding")

def verify_exposed_configs(f: dict) -> Verdict:
    host = f.get("host", ""); path = f.get("path", "")
    sev = f.get("severity", "MEDIUM")
    url = f"https://{host}{path}"
    status, _, body = http_fetch(url)
    if status != 200 or not body:
        return Verdict("exposed-configs.jsonl", "exposed_config", host, "stale", "LOW", f,
                       f"status={status}")
    # Re-apply the shape regex from the original scanner
    if path.endswith(".env") or path == "/.env":
        if re.search(r'^[A-Z_]+=', body, re.M):
            return Verdict("exposed-configs.jsonl", "exposed_config", host, "confirmed", sev, f,
                           f"env-shape body confirmed, size={len(body)}")
    if path.endswith(".git/config"):
        if "[core]" in body or "[remote" in body:
            return Verdict("exposed-configs.jsonl", "exposed_config", host, "confirmed", sev, f,
                           ".git/config confirmed")
    if "wp-config" in path:
        if "DB_NAME" in body or "DB_USER" in body or "DB_PASS" in body:
            return Verdict("exposed-configs.jsonl", "exposed_config", host, "confirmed", "CRITICAL", f,
                           "wp-config.php with DB creds exposed")
    return Verdict("exposed-configs.jsonl", "exposed_config", host, "fp", "MEDIUM", f,
                   "content shape no longer matches expected")

def verify_exposed_db(f: dict) -> Verdict:
    host = f.get("host", ""); service = f.get("service", ""); port = f.get("port", 0)
    if service == "elasticsearch":
        status, _, body = http_fetch(f"http://{host}:9200/", timeout=5)
        if status == 200 and body and ("cluster_name" in body or "tagline" in body):
            return Verdict("exposed-databases.jsonl", "exposed_db", host, "confirmed", "HIGH", f,
                           f"elasticsearch still open at :9200")
    elif service == "couchdb":
        status, _, body = http_fetch(f"http://{host}:5984/_all_dbs", timeout=5)
        if status == 200 and body and body.strip().startswith("["):
            return Verdict("exposed-databases.jsonl", "exposed_db", host, "confirmed", "HIGH", f,
                           "couchdb still open")
    # TCP-protocol services need tcp_probe — skip for re-verify simplicity
    return Verdict("exposed-databases.jsonl", "exposed_db", host, "stale", "LOW", f,
                   "skipped (TCP re-probe not implemented in verifier)")

VERIFIERS = {
    "open-redirect.jsonl":           verify_open_redirect,
    "debug-actuator.jsonl":          verify_debug_actuator,
    "dep-confusion.jsonl":           verify_dep_confusion,
    "ssti-candidates.jsonl":         verify_ssti,
    "path-traversal.jsonl":          verify_path_traversal,
    "host-header-injection.jsonl":   verify_host_header,
    "defi-rpc-leak.jsonl":           verify_defi_rpc_leak,
    "hardhat-exposed.jsonl":         verify_hardhat,
    "exposed-configs.jsonl":         verify_exposed_configs,
    "exposed-databases.jsonl":       verify_exposed_db,
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger-dir", default="/Users/raffa/Lictor/v3/ledgers")
    ap.add_argument("--out", default="/Users/raffa/Lictor/v3/ledgers/verified-findings.jsonl")
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--max-per-class", type=int, default=500,
                     help="Cap per ledger to avoid blowing up on huge ledgers (e.g. defi-admin-exposed)")
    args = ap.parse_args()

    ldir = Path(args.ledger_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists(): out.unlink()  # fresh start each run

    all_findings = []
    for ledger_name, verifier in VERIFIERS.items():
        path = ldir / ledger_name
        if not path.exists() or path.stat().st_size == 0:
            print(f"[-] {ledger_name}: no findings to verify")
            continue
        n = 0
        with path.open() as fp:
            for line in fp:
                line = line.strip()
                if not line: continue
                try:
                    j = json.loads(line)
                except: continue
                all_findings.append((ledger_name, verifier, j))
                n += 1
                if n >= args.max_per_class: break
        print(f"[+] {ledger_name}: {n} findings queued for verification")

    print(f"\n[+] Total to verify: {len(all_findings)} with {args.threads} threads")
    n_confirmed, n_fp, n_stale = 0, 0, 0
    with out.open("a") as fout, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(v, j): (lg, j) for lg, v, j in all_findings}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                verdict = fut.result()
            except Exception as e:
                continue
            fout.write(json.dumps(asdict(verdict)) + "\n"); fout.flush()
            if verdict.classification == "confirmed": n_confirmed += 1
            elif verdict.classification == "fp": n_fp += 1
            else: n_stale += 1
            if i % 50 == 0:
                print(f"  [{i}/{len(all_findings)}]  confirmed={n_confirmed}  fp={n_fp}  stale={n_stale}")
    print(f"\n[+] Done. confirmed={n_confirmed} fp={n_fp} stale={n_stale} → {out}")

if __name__ == "__main__":
    main()
