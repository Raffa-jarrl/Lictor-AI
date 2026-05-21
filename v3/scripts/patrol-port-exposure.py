#!/usr/bin/env python3
"""
Lictor v3 — port exposure scanner v2 (banner-grab only, NEVER auth)

REBUILT 2026-05-21 — added CDN pre-filter (skip cloudflare/fastly/
amazons3 hosts that reject everything but 443) and noise-port skip
(SSH banner-grab on every Linux server is low-value).

Detects exposed services on bounty-scope targets. Single TCP connect
per port, read first 256 bytes (banner), report. NEVER attempts
authentication, NEVER brute-forces credentials, NEVER sends exploits.

Hunts for:
  - RDP (3389) — Windows Remote Desktop exposed to the internet
  - VNC (5900/5901/5902) — Remote desktop, often default-passwordless
  - Telnet (23) — old IoT / camera / network device legacy
  - FTP (21) — anonymous-FTP misconfig
  - SNMP (161) — network device management (default 'public' string)
  - Elasticsearch (9200) — often unauthenticated databases
  - MongoDB (27017) — historically default-no-auth
  - Redis (6379) — often unauthenticated cache databases
  - Memcached (11211) — often unauthenticated
  - PostgreSQL (5432), MySQL (3306) — direct DB exposure
  - Docker API (2375 unencrypted, 2376 TLS)
  - Kubernetes API (6443, 10250 kubelet)
  - HikVision / Dahua camera API (8000, 37777)

Pre-filter: if the apex host is fronted by a major CDN (cloudflare /
fastly / amazons3 / akamai / vercel / netlify), skip ALL port scans —
those CDNs will reject any non-80/443 traffic anyway, so probing
wastes time.

Usage:
  python3 patrol-port-exposure.py --corpus PATH --max-domains N
  python3 patrol-port-exposure.py example.com   # single target

Output: ~/Lictor/v3/ledgers/port-exposure-candidates.jsonl
"""
from __future__ import annotations
import argparse, ipaddress, json, socket, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-PortExposure/0.3 (+https://lictor-ai.com)"


def _resolves_to_private(host: str) -> bool:
    """Resolve host. If it points at loopback/private/link-local/etc,
    skip — otherwise our TCP connects hit our own machine, not the
    target. This was a real FP class: baoliyun.com resolves to
    127.0.0.1 and the scan reported MY LOCAL VNC + PostgreSQL as 'open'
    on baoliyun.com."""
    try:
        ips = socket.getaddrinfo(host, None, socket.AF_INET)
    except Exception:
        return True  # can't resolve — skip
    for family, _, _, _, sockaddr in ips:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
    return False
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "port-exposure-candidates.jsonl"

CDN_SERVER_BLOCKLIST = {
    "cloudflare", "amazons3", "amazon s3", "cloudfront", "fastly",
    "akamai", "akamaighost", "vercel", "netlify", "github.com",
    "squarespace", "wix.com", "imperva", "sucuri", "incapsula",
    "ddos-guard", "qrator", "barracuda", "atlassianedge", "shopify",
    "esa", "istio-envoy",
}

# (port, service-name, severity, "what an attacker could do")
# Removed SSH (22) — too noisy, every Linux server exposes it at the
# apex; reports flood with low-impact "SSH banner reveals OpenSSH x.y".
PORTS_TO_PROBE = [
    (3389, "RDP",          "high",     "Brute-force / steal Windows credentials, lateral movement"),
    (5900, "VNC",          "high",     "Often passwordless or weak — full desktop access"),
    (5901, "VNC-alt",      "high",     "Same as 5900"),
    (5902, "VNC-alt2",     "high",     "Same as 5900"),
    (23,   "Telnet",       "critical", "Plaintext credentials, common on old IoT/cameras"),
    (21,   "FTP",          "medium",   "Plaintext credentials, anonymous-FTP misconfig common"),
    (161,  "SNMP",         "medium",   "Default 'public' community string leaks config"),
    (9200, "Elasticsearch","critical", "Often unauthenticated — full DB read access"),
    (27017,"MongoDB",      "critical", "Historically default-no-auth — full DB read/write"),
    (6379, "Redis",        "critical", "Often unauthenticated — config read, command injection"),
    (11211,"Memcached",    "high",     "Often unauthenticated — cache contents readable"),
    (5432, "PostgreSQL",   "high",     "Direct DB exposure"),
    (3306, "MySQL",        "high",     "Direct DB exposure"),
    (2375, "Docker-API",   "critical", "Unauthenticated Docker daemon — RCE"),
    (2376, "Docker-API-TLS","high",    "Docker daemon with TLS — still misconfig if exposed"),
    (6443, "K8s-API",      "high",     "Kubernetes control plane"),
    (10250,"K8s-kubelet",  "high",     "Kubelet API — node-level access"),
    (8000, "HTTP-camera",  "info",     "HikVision / camera default port"),
    (37777,"DVR-Dahua",    "high",     "Dahua DVR/NVR — often default-credential"),
]


def _is_cdn_apex(host: str) -> bool:
    """Quick HTTPS HEAD to decide if host is CDN-fronted. CDNs reject
    everything but 80/443, so port-scanning is wasted effort."""
    req = urllib.request.Request(f"https://{host}/", headers={"User-Agent": UA}, method="HEAD")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            headers = {k: v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
    except Exception:
        return False  # can't tell, fall through to port scanning

    if headers.get("CF-RAY") or headers.get("Cf-Ray"):
        return True
    server = (headers.get("Server", "") or "").lower()
    if any(cdn in server for cdn in CDN_SERVER_BLOCKLIST):
        return True
    powered = (headers.get("X-Powered-By", "") or "").lower()
    if "vercel" in powered or "next.js" in powered:
        return True
    return False


def _tcp_connect_and_banner(host: str, port: int, timeout: int = 4) -> dict | None:
    """Single TCP connect + banner grab. NEVER auths."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = b""
            try:
                banner = s.recv(256)
            except socket.timeout:
                # Some services don't send banner until we say hello — send a single newline
                try:
                    s.sendall(b"\r\n")
                    banner = s.recv(256)
                except Exception:
                    pass
            return {
                "host": host,
                "port": port,
                "open": True,
                "banner_first_256": banner.decode("utf-8", "replace")[:256] if banner else "",
                "banner_len": len(banner),
                "probed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def probe_one_host(host: str) -> list[dict]:
    """Probe all PORTS_TO_PROBE on a single host (after pre-filters)."""
    # CRITICAL: filter hosts that resolve to private/loopback IPs.
    # Without this, baoliyun.com (which resolves to 127.0.0.1) makes us
    # scan our own machine and report localhost VNC/Postgres as a "find".
    if _resolves_to_private(host):
        return []
    # CDN pre-filter — skip cloudflare/fastly/etc that reject everything but 443
    if _is_cdn_apex(host):
        return []

    findings = []
    for port, svc_name, severity, impact in PORTS_TO_PROBE:
        result = _tcp_connect_and_banner(host, port)
        if result is None:
            continue
        result["service_name"] = svc_name
        result["severity"] = severity
        result["impact_if_misconfigured"] = impact
        # Banner fingerprinting
        banner = result["banner_first_256"].lower()
        if "ssh-" in banner:
            result["fingerprint"] = "SSH"
        elif "redis" in banner or "noauth" in banner:
            result["fingerprint"] = "Redis"
        elif "mongodb" in banner:
            result["fingerprint"] = "MongoDB"
        elif "elasticsearch" in banner or '"name"' in banner:
            result["fingerprint"] = "Elasticsearch (or similar JSON-API service)"
        elif "memcached" in banner:
            result["fingerprint"] = "Memcached"
        elif "mysql" in banner or "\x00\x00\x00\x00\x0a" in banner:
            result["fingerprint"] = "MySQL"
        elif "vnc" in banner or "rfb" in banner:
            result["fingerprint"] = "VNC"
        elif "ftp" in banner:
            result["fingerprint"] = "FTP"
        elif "telnet" in banner or "login:" in banner:
            result["fingerprint"] = "Telnet"
        else:
            result["fingerprint"] = "unknown"
        findings.append(result)
        print(f"  🟡 PORT-OPEN  {host}:{port} ({svc_name}, {severity}, fp={result['fingerprint']})", flush=True)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="Single host to probe")
    ap.add_argument("--corpus", help="Path to apex-domain corpus file")
    ap.add_argument("--max-domains", type=int, default=200)
    ap.add_argument("--workers", type=int, default=30)
    args = ap.parse_args()

    if args.target:
        hosts = [args.target]
    elif args.corpus:
        p = Path(args.corpus).expanduser()
        if not p.exists():
            sys.exit(f"❌ Corpus file not found: {p}")
        hosts = [l.strip() for l in p.read_text().splitlines() if l.strip()][:args.max_domains]
    else:
        ap.print_help()
        sys.exit(1)

    print(f"[+] port-exposure v2 — {len(hosts)} hosts × {len(PORTS_TO_PROBE)} ports = {len(hosts) * len(PORTS_TO_PROBE):,} TCP connects max", flush=True)
    print(f"[+] CDN PRE-FILTER active — skipping cloudflare/fastly/amazons3 hosts (waste of time to probe)", flush=True)
    print(f"[+] BANNER-GRAB ONLY — NEVER attempts auth, NEVER brute-forces", flush=True)

    all_findings = []
    completed = 0
    cdn_skipped = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe_one_host, h): h for h in hosts}
        for fut in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"  [{completed}/{len(hosts)}] hosts probed, {len(all_findings)} open ports found", flush=True)
            try:
                hits = fut.result(timeout=300)
            except Exception:
                continue
            all_findings.extend(hits)

    print(f"\n[+] scan complete: {len(all_findings)} open ports across {len(set(f['host'] for f in all_findings))} hosts", flush=True)

    if all_findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in all_findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(all_findings)} entries to {LEDGER}", flush=True)


if __name__ == "__main__":
    main()
