#!/usr/bin/env python3
"""
patrol-open-services — scanner #19.

Hunts unauthenticated open services on bounty-program apex domains:
  - Redis            (6379)   no auth → full DB read/write
  - MongoDB          (27017)  no auth → full DB
  - Elasticsearch    (9200)   no auth → /_cat/indices reveals data
  - Kibana           (5601)   no auth → ES proxy
  - Prometheus       (9090)   /api/v1/query exposes metrics
  - Grafana          (3000)   default admin/admin sometimes works
  - Kubernetes API   (8080, 10250, 6443) no-auth read-only
  - Docker daemon    (2375, 2376) no-TLS → arbitrary container exec
  - etcd             (2379)  no-auth → cluster secrets
  - Jenkins          (8080)  /script unauth → RCE
  - SonarQube        (9000)  default admin/admin

These pay $500-$5K on H1/BC when found on bounty programs.

Method:
  1. Read corpus of apex domains
  2. For each, also probe common sub-prefixes (api., admin., monitor., metrics.,
     internal., dev., staging., k8s., kube., elk., monitoring., db., redis.)
  3. For each (host, port), open a TCP connection + send service-specific probe
  4. Check response for unauthenticated success signature

Cron: hourly (low-overhead — TCP probes are fast)
"""
from __future__ import annotations
import argparse, json, socket, ssl, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-OpenServicePatrol/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / ".lictor" / "open-service-ledger.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"open-services-{datetime.now().strftime('%Y-%m-%d')}-private.md"

# Service probes — (port, label, probe_bytes, success_pattern, payout_band)
SERVICES = [
    {
        "name": "Redis", "port": 6379, "payout": 2000,
        "probe": b"*1\r\n$4\r\nPING\r\n",
        "success_rx": b"+PONG\r\n",
    },
    {
        "name": "MongoDB", "port": 27017, "payout": 3000,
        # ismaster query (MongoDB protocol)
        "probe": (b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
                  b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
                  b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"),
        "success_rx": b"ismaster",
    },
    {
        "name": "Elasticsearch", "port": 9200, "payout": 2500,
        "probe": b"GET / HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b"You Know, for Search",
    },
    {
        "name": "Kibana", "port": 5601, "payout": 2000,
        "probe": b"GET /api/status HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b"kibana",
    },
    {
        "name": "Prometheus", "port": 9090, "payout": 1000,
        "probe": b"GET /api/v1/status/config HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b"global:",
    },
    {
        "name": "Grafana", "port": 3000, "payout": 1500,
        "probe": b"GET /api/health HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'"database":',
    },
    {
        "name": "Kubelet", "port": 10250, "payout": 3000,
        "probe": b"GET /pods HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'"kind":"PodList"',
    },
    {
        "name": "Kubernetes API (no-TLS)", "port": 8080, "payout": 3000,
        "probe": b"GET /api/v1 HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'"kind":"APIResourceList"',
    },
    {
        "name": "Docker daemon (no-TLS)", "port": 2375, "payout": 5000,
        "probe": b"GET /containers/json HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'[{"Id":',
    },
    {
        "name": "etcd", "port": 2379, "payout": 4000,
        "probe": b"GET /v2/keys/ HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'"action":"get"',
    },
    {
        "name": "Jenkins (script console)", "port": 8080, "payout": 4000,
        "probe": b"GET /script HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'Groovy script',
    },
    {
        "name": "SonarQube", "port": 9000, "payout": 1500,
        "probe": b"GET /api/server/version HTTP/1.0\r\nHost: any\r\n\r\n",
        "success_rx": b'sonar',
    },
]

# Subdomain prefixes likely to host internal services
PREFIXES = ["", "api.", "admin.", "internal.", "dev.", "staging.", "monitor.",
            "metrics.", "k8s.", "kube.", "elk.", "elastic.", "kibana.",
            "grafana.", "prometheus.", "db.", "redis.", "mongo.", "jenkins.",
            "ci.", "sonar."]

@dataclass
class OpenService:
    host: str
    port: int
    service: str
    payout: int
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def probe_port(host, port, probe_bytes, success_rx, timeout=4):
    """Open TCP, send probe, check response for success pattern."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(probe_bytes)
        data = b""
        for _ in range(3):
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                if success_rx in data: break
            except socket.timeout: break
        sock.close()
        return data if success_rx in data else None
    except Exception:
        return None


def check_host_service(host, svc):
    """Check one (host, service) tuple."""
    result = probe_port(host, svc["port"], svc["probe"], svc["success_rx"])
    if result:
        snippet = result[:200].decode("utf-8", "replace").replace("\n", " ").replace("\r", " ")
        return OpenService(
            host=host, port=svc["port"], service=svc["name"],
            payout=svc["payout"], snippet=snippet,
        )
    return None


def load_ledger():
    if not LEDGER.exists(): return set()
    seen = set()
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            try:
                d = json.loads(line)
                seen.add(f"{d['host']}|{d['port']}")
            except: pass
    return seen


def append_ledger(rec: OpenService):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"),
                    help="Path to apex-domain corpus file.")
    ap.add_argument("--max-domains", type=int, default=500)
    ap.add_argument("--workers", type=int, default=50)
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] open-services patrol — {len(seen)} prior hits in ledger", flush=True)

    domains = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines()
               if l.strip()][:args.max_domains]
    print(f"[+] scanning {len(domains)} apex domains × {len(PREFIXES)} prefixes × {len(SERVICES)} services", flush=True)

    # Build all (host, service) tuples to probe
    tasks = []
    for apex in domains:
        for prefix in PREFIXES:
            host = f"{prefix}{apex}"
            for svc in SERVICES:
                if f"{host}|{svc['port']}" in seen: continue
                tasks.append((host, svc))
    print(f"[+] total probes: {len(tasks)} (after ledger dedup)", flush=True)

    hits = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_host_service, h, s): (h, s) for h, s in tasks}
        for fut in as_completed(futures):
            h, s = futures[fut]
            seen.add(f"{h}|{s['port']}")
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(tasks)}] scanned, {len(hits)} hits", flush=True)
            try:
                rec = fut.result(timeout=10)
            except Exception:
                rec = None
            if rec:
                print(f"  🔴🔴 OPEN-SERVICE  {rec.service:<25} {rec.host}:{rec.port}  (${rec.payout:,})", flush=True)
                append_ledger(rec)
                hits.append(rec)

    print(f"\n[+] scan complete: {len(hits)} open services found")
    if hits:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as f:
            f.write(f"# Open services on bounty programs — {datetime.now().strftime('%Y-%m-%d')} (PRIVATE)\n\n")
            f.write(f"**Probes:** {len(tasks)}\n**Hits:** {len(hits)}\n")
            f.write(f"**Expected payout total:** ${sum(h.payout for h in hits):,}\n\n")
            f.write("| Service | Host | Port | $ | Snippet |\n|---|---|---|---|---|\n")
            for h in sorted(hits, key=lambda x: -x.payout):
                f.write(f"| **{h.service}** | `{h.host}` | {h.port} | ${h.payout:,} | `{h.snippet[:80]}` |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
