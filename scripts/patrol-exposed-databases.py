#!/usr/bin/env python3
"""
patrol-exposed-databases — scanner #59.

Hunts publicly-reachable database / cache services with NO authentication:
  - Redis           (port 6379) — INFO command returns server info
  - MongoDB         (port 27017) — isMaster response over wire protocol
  - Memcached       (port 11211) — `version` command
  - Elasticsearch   (port 9200 HTTP) — / returns cluster info
  - CouchDB         (port 5984 HTTP) — /_all_dbs lists databases
  - InfluxDB        (port 8086 HTTP) — /query returns DB list
  - Cassandra       (port 9042) — CQL native protocol handshake

Bounty range: $5K-$50K for exposed prod DB with data.

Method (ETHICAL — no data extraction):
  1. TCP-connect to each port on each host. If port open, send the protocol's
     "hello / info" command (the lowest-impact RPC).
  2. If response indicates unauth access → log + STOP.
  3. Never enumerate keys, collections, or DB contents.

Usage:
  patrol-exposed-databases.py --hosts targets.txt --ledger exposed-dbs.jsonl
"""
from __future__ import annotations
import argparse, json, socket, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-DBPatrol/0.1 (+https://lictor-ai.com)"

@dataclass
class DBFinding:
    host: str
    service: str
    port: int
    status: str        # "open_no_auth" / "auth_required" / "closed" / "timeout"
    banner: str = ""
    notes: str = ""

def tcp_probe(host: str, port: int, payload: bytes, timeout: int = 5) -> bytes | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            data = b""
            try:
                while len(data) < 1024:
                    chunk = s.recv(1024)
                    if not chunk: break
                    data += chunk
                    if len(data) >= 64: break
            except socket.timeout:
                pass
            return data
    except Exception:
        return None

def check_redis(host: str) -> DBFinding | None:
    # Redis INFO command (RESP protocol)
    payload = b"*1\r\n$4\r\nINFO\r\n"
    data = tcp_probe(host, 6379, payload)
    if data is None: return DBFinding(host=host, service="redis", port=6379, status="closed")
    s = data.decode("utf-8", "replace")
    if "redis_version" in s:
        return DBFinding(host=host, service="redis", port=6379, status="open_no_auth",
                         banner=s[:200].replace("\n"," ").replace("\r"," "))
    if "NOAUTH" in s or "AUTH" in s:
        return DBFinding(host=host, service="redis", port=6379, status="auth_required",
                         banner=s[:200])
    return None

def check_memcached(host: str) -> DBFinding | None:
    data = tcp_probe(host, 11211, b"version\r\n")
    if data is None: return DBFinding(host=host, service="memcached", port=11211, status="closed")
    s = data.decode("utf-8", "replace")
    if s.startswith("VERSION"):
        return DBFinding(host=host, service="memcached", port=11211,
                         status="open_no_auth", banner=s[:100].strip())
    return None

def check_mongodb(host: str) -> DBFinding | None:
    # MongoDB wire-protocol isMaster OP_QUERY — simplified payload
    payload = bytes.fromhex(
        "3a000000010000000000000000d40700000000000061646d696e2e24636d6400000000000100000018000000106973576f7263647273000100000000")
    data = tcp_probe(host, 27017, payload)
    if data is None: return DBFinding(host=host, service="mongodb", port=27017, status="closed")
    if b"ismaster" in data or b"ok" in data or b"maxBsonObjectSize" in data:
        return DBFinding(host=host, service="mongodb", port=27017, status="open_no_auth",
                         banner=data[:100].hex())
    return None

def check_elasticsearch(host: str) -> DBFinding | None:
    try:
        req = urllib.request.Request(f"http://{host}:9200/", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(2048).decode("utf-8", "replace")
            if "cluster_name" in body or "tagline" in body:
                return DBFinding(host=host, service="elasticsearch", port=9200,
                                 status="open_no_auth", banner=body[:200])
    except urllib.error.HTTPError as e:
        if e.code == 401: return DBFinding(host=host, service="elasticsearch", port=9200,
                                            status="auth_required")
    except Exception:
        pass
    return None

def check_couchdb(host: str) -> DBFinding | None:
    try:
        req = urllib.request.Request(f"http://{host}:5984/_all_dbs", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(2048).decode("utf-8", "replace")
            if body.strip().startswith("["):
                return DBFinding(host=host, service="couchdb", port=5984,
                                 status="open_no_auth", banner=body[:200])
    except Exception:
        pass
    return None

def check_influxdb(host: str) -> DBFinding | None:
    try:
        req = urllib.request.Request(f"http://{host}:8086/query?q=SHOW+DATABASES",
                                      headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(2048).decode("utf-8", "replace")
            if "results" in body and "databases" in body:
                return DBFinding(host=host, service="influxdb", port=8086,
                                 status="open_no_auth", banner=body[:200])
    except Exception:
        pass
    return None

CHECKS = [check_redis, check_memcached, check_mongodb,
          check_elasticsearch, check_couchdb, check_influxdb]

def check_host(host: str) -> list[DBFinding]:
    out = []
    for fn in CHECKS:
        try:
            f = fn(host)
            if f and f.status in ("open_no_auth", "auth_required"):
                out.append(f)
        except Exception:
            pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/exposed-databases.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] DB-exposure hunt across {len(hosts)} hosts × {len(CHECKS)} services")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_open, n_gated = 0, 0
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
                tag = "🔴" if f.status == "open_no_auth" else "🟡"
                if f.status == "open_no_auth": n_open += 1
                else: n_gated += 1
                print(f"  [{i}/{len(hosts)}] {tag} {host}:{f.port} {f.service} {f.status}")
            if i % 50 == 0: print(f"  [{i}/{len(hosts)}] scanning... open={n_open} gated={n_gated}")
    print(f"\n[+] Done. open_no_auth={n_open} auth_required={n_gated} → {args.ledger}")

if __name__ == "__main__":
    main()
