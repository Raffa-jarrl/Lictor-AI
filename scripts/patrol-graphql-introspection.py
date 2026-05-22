#!/usr/bin/env python3
"""
patrol-graphql-introspection — scanner #25.

Hunts production GraphQL endpoints with introspection enabled.
Bounty programs typically pay $100-$500 for this as INFO disclosure
(self-evident proof: the schema dump IS the artifact).

Method:
  1. For each bounty-program apex domain (+ common API prefixes)
  2. POST a tiny introspection query to /graphql, /api/graphql, /api/gql, etc.
  3. If response contains `__schema` with type definitions = INTROSPECTION ENABLED

Note: introspection enabled isn't ALWAYS a vuln (development APIs often
leave it on intentionally). But on production user-facing APIs at major
companies, it's considered INFO disclosure worth reporting.
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-GraphQLPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "graphql-introspection-ledger.jsonl"

# Tiny introspection query — just enough to confirm introspection is on
INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
}).encode()

PREFIXES = ["", "api.", "graphql.", "app.", "admin.", "internal.", "data.", "gateway."]
PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/api/gql", "/query", "/api/query"]


@dataclass
class GraphQLLeak:
    host: str; path: str; type_count: int; payout: int
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def probe(host, path, timeout=6):
    """POST introspection query. Return (status, body) or (0, b'')."""
    url = f"https://{host}{path}"
    try:
        req = urllib.request.Request(url, method="POST",
                                      data=INTROSPECTION_QUERY,
                                      headers={
                                          "User-Agent": UA,
                                          "Content-Type": "application/json",
                                          "Accept": "application/json",
                                      })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(20000)
    except urllib.error.HTTPError as e:
        try: body = e.read(5000)
        except: body = b""
        return e.code, body
    except Exception:
        return 0, b""


def check_one(host_path):
    host, path = host_path
    status, body = probe(host, path)
    if status != 200 or not body: return None
    # Look for valid introspection response: __schema in JSON with types[]
    try:
        data = json.loads(body)
        schema = data.get("data", {}).get("__schema")
        if not schema or not isinstance(schema, dict): return None
        types = schema.get("types")
        if not types or not isinstance(types, list): return None
        if len(types) < 3: return None  # require non-trivial schema
        # Confirmed introspection enabled
        return GraphQLLeak(
            host=host, path=path,
            type_count=len(types), payout=300,
            snippet=f"queryType={schema.get('queryType',{}).get('name','?')} types={len(types)}",
        )
    except Exception:
        return None


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
    print(f"[+] graphql-introspection patrol — {len(apexes)} apex × {len(PREFIXES)} prefixes × {len(PATHS)} paths", flush=True)

    tasks = []
    for apex in apexes:
        for prefix in PREFIXES:
            host = f"{prefix}{apex}"
            for path in PATHS:
                tasks.append((host, path))
    print(f"[+] total probes: {len(tasks)}", flush=True)

    hits = []
    seen_hosts = set()
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
                print(f"  🔴🔴 GRAPHQL-INTROSPECTION  https://{r.host}{r.path}  ({r.type_count} types, ${r.payout})", flush=True)
                append_ledger(r)
                hits.append(r)

    print(f"\n[+] scan complete: {len(hits)} GraphQL introspection exposures")


if __name__ == "__main__": main()
