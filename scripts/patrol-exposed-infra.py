#!/usr/bin/env python3
"""
patrol-exposed-infra — scanner #60.

Hunts publicly-reachable cluster/orchestration infrastructure with no auth:
  - Kubernetes API server   (port 6443, /api endpoint)
  - Docker daemon           (port 2375 HTTP, 2376 HTTPS) — /version
  - etcd                    (port 2379) — /version
  - Consul                  (port 8500) — /v1/agent/self
  - Nomad                   (port 4646) — /v1/agent/self
  - Spark Master            (port 8080 HTTP) — Spark UI
  - Hadoop NameNode UI      (port 9870 / 50070)
  - Jupyter notebook        (port 8888) — / requires no token = open

Bounty range: $5K-$50K for exposed orchestration. Kubernetes/Docker on prod
infra can be RCE-equivalent.

Method (ETHICAL — read-only info commands):
  1. HTTP/TCP probe each service's /version or /info endpoint.
  2. If the response reveals server metadata WITHOUT auth = unauth exposure.
  3. Do NOT list pods, containers, services, or KV data.

Usage:
  patrol-exposed-infra.py --hosts targets.txt --ledger exposed-infra.jsonl
"""
from __future__ import annotations
import argparse, json, socket, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-InfraPatrol/0.1 (+https://lictor-ai.com)"

@dataclass
class InfraFinding:
    host: str
    service: str
    port: int
    scheme: str
    path: str
    status: str   # "open_no_auth" / "auth_required" / "closed"
    banner: str = ""

def http_probe(host: str, port: int, path: str, scheme: str = "http", timeout: int = 5):
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(4096).decode("utf-8", "replace")
        except: b = ""
        return e.code, b
    except Exception:
        return None, None

def check_kubernetes(host: str) -> InfraFinding | None:
    for scheme, port in [("https", 6443), ("http", 8080), ("https", 8443)]:
        status, body = http_probe(host, port, "/api", scheme)
        if not body: continue
        if status == 401: return InfraFinding(host=host, service="kubernetes-api", port=port,
                                                scheme=scheme, path="/api", status="auth_required")
        if status == 200 and ("APIVersions" in body or "kind" in body):
            return InfraFinding(host=host, service="kubernetes-api", port=port,
                                scheme=scheme, path="/api", status="open_no_auth",
                                banner=body[:200])
    return None

def check_docker(host: str) -> InfraFinding | None:
    for scheme, port in [("http", 2375), ("https", 2376)]:
        status, body = http_probe(host, port, "/version", scheme)
        if status == 200 and body and ("Version" in body or "ApiVersion" in body):
            return InfraFinding(host=host, service="docker-daemon", port=port,
                                scheme=scheme, path="/version", status="open_no_auth",
                                banner=body[:200])
    return None

def check_etcd(host: str) -> InfraFinding | None:
    status, body = http_probe(host, 2379, "/version")
    if status == 200 and body and "etcdserver" in body:
        return InfraFinding(host=host, service="etcd", port=2379, scheme="http",
                            path="/version", status="open_no_auth", banner=body[:200])
    return None

def check_consul(host: str) -> InfraFinding | None:
    status, body = http_probe(host, 8500, "/v1/agent/self")
    if status == 200 and body and ("Config" in body or "NodeName" in body):
        return InfraFinding(host=host, service="consul", port=8500, scheme="http",
                            path="/v1/agent/self", status="open_no_auth", banner=body[:200])
    return None

def check_nomad(host: str) -> InfraFinding | None:
    status, body = http_probe(host, 4646, "/v1/agent/self")
    if status == 200 and body and "config" in body.lower():
        return InfraFinding(host=host, service="nomad", port=4646, scheme="http",
                            path="/v1/agent/self", status="open_no_auth", banner=body[:200])
    return None

def check_jupyter(host: str) -> InfraFinding | None:
    for port in (8888, 8889):
        status, body = http_probe(host, port, "/tree")
        if status == 200 and body and ("Jupyter" in body or "jupyter" in body):
            return InfraFinding(host=host, service="jupyter", port=port, scheme="http",
                                path="/tree", status="open_no_auth", banner=body[:200])
    return None

def check_spark(host: str) -> InfraFinding | None:
    status, body = http_probe(host, 8080, "/")
    if status == 200 and body and "Spark Master" in body:
        return InfraFinding(host=host, service="spark-master", port=8080, scheme="http",
                            path="/", status="open_no_auth", banner=body[:200])
    return None

def check_hadoop(host: str) -> InfraFinding | None:
    for port in (9870, 50070):
        status, body = http_probe(host, port, "/dfshealth.html")
        if status == 200 and body and "Hadoop" in body:
            return InfraFinding(host=host, service="hadoop-namenode", port=port, scheme="http",
                                path="/dfshealth.html", status="open_no_auth", banner=body[:200])
    return None

CHECKS = [check_kubernetes, check_docker, check_etcd, check_consul, check_nomad,
          check_jupyter, check_spark, check_hadoop]

def check_host(host: str) -> list[InfraFinding]:
    out = []
    for fn in CHECKS:
        try:
            f = fn(host)
            if f: out.append(f)
        except Exception:
            pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/exposed-infra.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Infra-exposure hunt across {len(hosts)} hosts × {len(CHECKS)} services")
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
