#!/usr/bin/env python3
"""
patrol-debug-actuator — scanner #61.

Hunts exposed debug, profiler, actuator, and metrics endpoints that leak
secrets / internal state. The Spring Boot Actuator pattern is especially
lucrative — /actuator/env leaks every env var (incl. DB passwords / API keys).

Bounty range: $1K-$25K depending on what's exposed.

Targets per host:
  - Spring Boot Actuator: /actuator/env /actuator/heapdump /actuator/threaddump
    /actuator/loggers /actuator/configprops /actuator/health /actuator/info
    /actuator/mappings /actuator/beans /actuator/jolokia /actuator/httptrace
  - Go pprof: /debug/pprof/heap /debug/pprof/goroutine
  - Generic debug: /debug /debug/vars
  - Prometheus metrics: /metrics
  - Node.js: /debug-info
  - Django debug: /__debug__/

Method (ETHICAL — only fetch the endpoint, never modify state):
  1. GET each candidate path on each host
  2. Classify by response content (env-var-shape JSON vs deny)
  3. Flag responses that contain secret-shape values (KEY=, PASSWORD=, TOKEN=)

Usage:
  patrol-debug-actuator.py --hosts targets.txt --ledger debug-actuator.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-DebugActuatorPatrol/0.1 (+https://lictor-ai.com)"

ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/threaddump",
    "/actuator/loggers", "/actuator/configprops", "/actuator/health",
    "/actuator/info", "/actuator/mappings", "/actuator/beans",
    "/actuator/jolokia", "/actuator/httptrace", "/actuator/auditevents",
    "/env", "/heapdump", "/configprops", "/mappings", "/trace",  # boot 1.x
    "/debug/vars", "/debug/pprof/heap", "/debug/pprof/goroutine",
    "/debug/pprof/", "/debug/pprof", "/metrics", "/prometheus",
    "/__debug__/", "/debug-info", "/server-info", "/server-status",
    "/api/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs",
]

SECRET_PATTERN = re.compile(
    r'(password|secret|api[_-]?key|aws|access[_-]?key|token|private[_-]?key|'
    r'database_url|db_pass|stripe|jwt|mongodb://|postgres://|mysql://|redis://)',
    re.IGNORECASE)

@dataclass
class DebugFinding:
    host: str
    path: str
    status: int
    response_kind: str   # "actuator_env" / "actuator_health" / "pprof" /
                         # "prometheus" / "swagger" / "secrets_found" / "other"
    secret_count: int = 0
    snippet: str = ""

def probe(host: str, path: str, timeout: int = 6):
    url = f"https://{host}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(32768).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(32768).decode("utf-8", "replace")
        except: b = ""
        return e.code, b
    except Exception:
        return None, None

def classify(path: str, status: int | None, body: str | None) -> tuple[str, int]:
    if not body or status != 200: return ("not_exposed", 0)
    if path.startswith("/actuator/env") or path == "/env":
        if "propertySources" in body or "activeProfiles" in body:
            secrets = len(SECRET_PATTERN.findall(body))
            return ("actuator_env", secrets)
    if "heapdump" in path:
        return ("heapdump_exposed", 0)
    if "/pprof" in path or "/debug/vars" in path:
        if "/heap" in body or "/goroutine" in body or "memstats" in body:
            return ("pprof", 0)
    if "swagger" in path.lower() or "api-docs" in path:
        if "swagger" in body.lower() or "openapi" in body.lower() or '"paths"' in body:
            return ("swagger", 0)
    if path == "/metrics" or path == "/prometheus":
        if "# HELP" in body or "# TYPE" in body:
            return ("prometheus", 0)
    if path.startswith("/actuator/health") and ('"status"' in body):
        return ("actuator_health", 0)
    # Generic: any actuator response that leaks secrets
    if "/actuator" in path or "/debug" in path or "/server-" in path:
        secrets = len(SECRET_PATTERN.findall(body))
        if secrets > 0: return ("secrets_found", secrets)
        return ("other_debug_endpoint", 0)
    return ("not_exposed", 0)

def check_host(host: str) -> list[DebugFinding]:
    out = []
    for path in ACTUATOR_PATHS:
        time.sleep(0.2)
        status, body = probe(host, path)
        kind, secrets = classify(path, status, body)
        if kind == "not_exposed": continue
        snippet = (body or "")[:300].replace("\n", " ")
        out.append(DebugFinding(host=host, path=path, status=status or 0,
                                response_kind=kind, secret_count=secrets,
                                snippet=snippet))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/debug-actuator.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Debug/Actuator hunt: {len(hosts)} hosts × {len(ACTUATOR_PATHS)} paths")
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
                tag = "🔴" if f.response_kind in ("actuator_env", "secrets_found", "heapdump_exposed") else "🟡"
                print(f"  [{i}/{len(hosts)}] {tag} {host}{f.path} → {f.response_kind} secrets={f.secret_count}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} findings so far")
    print(f"\n[+] Done. {n} debug/actuator exposures → {args.ledger}")

if __name__ == "__main__":
    main()
