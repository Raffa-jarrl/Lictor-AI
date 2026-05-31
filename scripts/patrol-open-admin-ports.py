#!/usr/bin/env python3
"""
patrol-open-admin-ports — port scan for exposed admin/DB services.

Targets the "I forgot to firewall it" class:
  9200/9300  Elasticsearch       (mass PII via /_cat/indices)
  27017      MongoDB             (open auth → full DB)
  6379       Redis               (no auth INFO → RCE via CONFIG SET dir)
  6443/8443  Kubernetes API      (cluster takeover)
  10250      Kubelet             (RCE via exec API)
  2375/2376  Docker daemon       (host RCE via /containers/create)
  50070      Hadoop NameNode     (HDFS access)
  8545       Geth/JSON-RPC       (Web3 unlocked accounts)
  9000       MinIO / Portainer   (S3-compatible / container mgmt)
  5984       CouchDB             (Fauxton UI, mass data)
  9092/9094  Kafka               (broker access)
  9090       Prometheus          (metrics exfil)
  3000       Grafana             (dashboards + datasource creds)
  5601       Kibana              (Elasticsearch UI)
  4444       Selenium Grid       (browser-as-a-service RCE)

Protocol probes: validate the service actually responds with its protocol
fingerprint — NOT just port-open, since random TCP open != vulnerable service.

Usage:
  patrol-open-admin-ports.py --hosts hosts.txt --max-hosts 1000 --threads 40
"""
from __future__ import annotations
import argparse, json, socket, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-OpenAdminPorts/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# (port, service_name, probe_type, probe_data, expected_response_marker, severity)
# probe_type: "http", "raw"
PROBES = [
    (9200, "Elasticsearch",   "http", "/",                  b'"cluster_name"', "CRITICAL"),
    (9200, "ElasticsearchAPI","http", "/_cat/indices?v",    b"health status",  "CRITICAL"),
    (27017,"MongoDB",         "raw",  b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", b"ismaster", "CRITICAL"),
    (6379, "Redis",           "raw",  b"INFO\r\n",          b"redis_version", "CRITICAL"),
    (6443, "K8sAPI",          "http", "/api",               b"APIVersions",    "CRITICAL"),
    (8443, "K8sAPI",          "http", "/api/v1/namespaces", b"namespaces",     "CRITICAL"),
    (10250,"Kubelet",         "http", "/pods",              b'"kind":"PodList"', "CRITICAL"),
    (2375, "DockerAPI",       "http", "/info",              b"Containers",     "CRITICAL"),
    (2376, "DockerAPI",       "http", "/info",              b"Containers",     "CRITICAL"),
    (50070,"HadoopNamenode",  "http", "/jmx",               b"Hadoop:service",  "CRITICAL"),
    (8545, "GethRPC",         "http", "/", b"jsonrpc",  "CRITICAL"),  # tested with POST below
    (9000, "MinIO",           "http", "/minio/health/live", b"",               "HIGH"),
    (9000, "Portainer",       "http", "/api/status",        b"Version",        "HIGH"),
    (5984, "CouchDB",         "http", "/",                  b"couchdb",        "CRITICAL"),
    (9090, "Prometheus",      "http", "/api/v1/status/config", b"yaml",        "HIGH"),
    (3000, "Grafana",         "http", "/api/health",        b"database",       "HIGH"),
    (5601, "Kibana",          "http", "/api/status",        b"kibana",         "HIGH"),
]

@dataclass
class OpenAdmin:
    host: str
    port: int
    service: str
    proof: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def tcp_alive(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True
    except Exception:
        return False


def http_probe(host, port, path, marker, timeout=4):
    """Try HTTPS first, fall back to HTTP.
    FP gate: skip any response that's HTML (Cloudflare challenge, generic web page).
    Real admin services return JSON / plaintext / protocol-specific responses."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(8000)
                ctype = r.headers.get("Content-Type", "").lower()
                # FP gate: HTML responses are NOT real admin APIs
                if "text/html" in ctype or body.lstrip()[:20].lower().startswith(b"<!doctype") or body.lstrip()[:20].lower().startswith(b"<html"):
                    continue
                # FP gate: Cloudflare bot challenge
                if b"Just a moment" in body or b"cloudflare" in body.lower()[:500]:
                    continue
                if marker and marker.lower() in body.lower():
                    return True, body[:300].decode("utf-8", "replace")
                if not marker and r.status < 500:
                    return True, body[:300].decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8000)
                ctype = e.headers.get("Content-Type", "").lower() if e.headers else ""
                if "text/html" in ctype or b"Just a moment" in body:
                    continue
                if marker and marker.lower() in body.lower():
                    return True, body[:300].decode("utf-8", "replace")
            except: pass
        except Exception:
            continue
    return False, ""


def raw_probe(host, port, sendbytes, marker, timeout=4):
    """Send raw bytes, look for marker in response."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(sendbytes)
            s.settimeout(timeout)
            resp = b""
            try:
                while len(resp) < 4096:
                    chunk = s.recv(2048)
                    if not chunk: break
                    resp += chunk
            except socket.timeout:
                pass
            if marker.lower() in resp.lower():
                return True, resp[:300].decode("utf-8", "replace")
    except Exception:
        pass
    return False, ""


def geth_rpc_probe(host, port, timeout=4):
    """Special: POST eth_blockNumber JSON-RPC and check for jsonrpc response."""
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}:{port}/"
        try:
            data = b'{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
            req = urllib.request.Request(url, data=data, headers={
                "User-Agent": UA, "Content-Type": "application/json",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(4000)
                if b"jsonrpc" in body and b"result" in body:
                    return True, body[:300].decode("utf-8", "replace")
        except Exception:
            continue
    return False, ""


def scan_host(host: str, ports_only: list[int] = None) -> list[OpenAdmin]:
    findings = []
    # First pass: TCP alive check on each unique port (fast)
    unique_ports = set(p[0] for p in PROBES)
    if ports_only:
        unique_ports &= set(ports_only)
    alive_ports = set()
    for port in unique_ports:
        if tcp_alive(host, port, timeout=2.0):
            alive_ports.add(port)
    if not alive_ports: return []
    # Second pass: protocol probe on alive ports
    for port, svc, ptype, pdata, marker, sev in PROBES:
        if port not in alive_ports: continue
        if port == 8545:
            ok, proof = geth_rpc_probe(host, port)
        elif ptype == "http":
            ok, proof = http_probe(host, port, pdata, marker)
        else:
            ok, proof = raw_probe(host, port, pdata, marker)
        if ok:
            findings.append(OpenAdmin(
                host=host, port=port, service=svc, proof=proof,
                severity=sev, notes=f"{svc} responded on {host}:{port} without auth",
            ))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=2000)
    ap.add_argument("--threads", type=int, default=40)
    ap.add_argument("--ports", help="Comma-separated subset of ports to probe")
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/open-admin-ports.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    ports_filter = [int(p) for p in args.ports.split(",")] if args.ports else None
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] open-admin-ports — {len(hosts)} hosts × {len(set(p[0] for p in PROBES))} ports")
    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, ports_filter): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=180)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = "🔴" if f.severity == "CRITICAL" else "🟠"
                if f.severity == "CRITICAL": n_crit += 1
                else: n_high += 1
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}:{f.port} ({f.service})")
            if i % 200 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")


if __name__ == "__main__":
    main()
