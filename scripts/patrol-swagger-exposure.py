#!/usr/bin/env python3
"""
patrol-swagger-exposure — scanner #26.

Hunts production servers exposing Swagger/OpenAPI documentation paths.
The spec file itself IS the proof — reveals every endpoint, parameter,
auth scheme, schema definition. Counts as INFO disclosure on most
bounty programs ($50-$300 typical).

Probed paths (most common):
  /swagger-ui.html, /swagger-ui/, /swagger.json, /swagger.yaml,
  /api-docs, /api/swagger, /v1/api-docs, /v2/api-docs, /v3/api-docs,
  /openapi.json, /openapi.yaml, /docs, /api/docs, /redoc,
  /api-explorer, /api-spec

Match patterns:
  - JSON with `swagger:`, `openapi:`, `paths:` keys
  - HTML containing "swagger-ui", "ReDoc", "openapi-explorer"
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SwaggerPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "swagger-ledger.jsonl"

# Paths sorted by likelihood-of-hit
PATHS_JSON = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api/swagger.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/spec.json", "/api/openapi.json", "/api/v1/openapi.json",
]
PATHS_HTML = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/docs", "/api/docs", "/api-docs/",
    "/redoc", "/api-explorer", "/explorer", "/api-spec",
]
PREFIXES = ["", "api.", "app.", "admin.", "internal.", "dev.", "staging.", "docs."]

JSON_SPEC_RX = re.compile(rb'"(swagger|openapi)"\s*:\s*"[0-9.]+"|"paths"\s*:\s*\{')
HTML_SPEC_RX = re.compile(rb'(swagger-ui|swaggerUi|SwaggerUIBundle|redoc|ReDoc|openapi-explorer)', re.I)


@dataclass
class SwaggerLeak:
    host: str; path: str; type: str  # "openapi-json" | "swagger-json" | "swagger-ui-html" | "redoc-html"
    spec_version: str  # "swagger 2.0", "openapi 3.0.1", etc.
    payout: int
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=6, max_size=50000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if 300 <= r.status < 400: return r.status, b""
            return r.status, r.read(max_size)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


def check_one(host_path):
    host, path = host_path
    is_json_path = path in PATHS_JSON
    url = f"https://{host}{path}"
    status, body = http_get(url)
    if status != 200 or not body: return None

    if is_json_path:
        # Validate it's actually a JSON spec
        if not JSON_SPEC_RX.search(body[:5000]): return None
        try:
            data = json.loads(body[:50000])
            ver = data.get("swagger") or data.get("openapi") or "?"
            spec_type = "openapi" if "openapi" in data else "swagger"
            return SwaggerLeak(
                host=host, path=path, type=f"{spec_type}-json",
                spec_version=f"{spec_type} {ver}", payout=200,
            )
        except Exception:
            return None
    else:
        # HTML — check for swagger-ui/redoc markers
        if not HTML_SPEC_RX.search(body[:50000]): return None
        kind = "swagger-ui-html" if b"swagger" in body.lower()[:5000] else "redoc-html"
        return SwaggerLeak(
            host=host, path=path, type=kind,
            spec_version="(html ui)", payout=150,
        )


def append_ledger(f):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fp:
        fp.write(json.dumps(asdict(f)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-paid.txt"))
    ap.add_argument("--max-domains", type=int, default=500)
    ap.add_argument("--workers", type=int, default=80)
    args = ap.parse_args()

    apexes = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines() if l.strip()][:args.max_domains]
    paths = PATHS_JSON + PATHS_HTML
    print(f"[+] swagger patrol — {len(apexes)} apex × {len(PREFIXES)} prefixes × {len(paths)} paths", flush=True)

    tasks = []
    for apex in apexes:
        for prefix in PREFIXES:
            host = f"{prefix}{apex}"
            for path in paths:
                tasks.append((host, path))
    print(f"[+] total probes: {len(tasks)}", flush=True)

    hits = []
    seen_hosts = set()  # one finding per host
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, t): t for t in tasks}
        for fut in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(tasks)}] {len(hits)} hits", flush=True)
            try: r = fut.result(timeout=10)
            except: r = None
            if r and r.host not in seen_hosts:
                seen_hosts.add(r.host)
                print(f"  🔴🔴 SWAGGER-EXPOSURE  https://{r.host}{r.path}  ({r.spec_version}, ${r.payout})", flush=True)
                append_ledger(r)
                hits.append(r)

    print(f"\n[+] scan complete: {len(hits)} swagger exposures")


if __name__ == "__main__": main()
