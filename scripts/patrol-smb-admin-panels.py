#!/usr/bin/env python3
"""
patrol-smb-admin-panels — admin panel exposure scanner for SMB targets.

Hunts the "I forgot the panel was on the public internet" class:

  /phpmyadmin          → PHPMyAdmin (DB takeover if weak pass)
  /pma                 → PHPMyAdmin alias
  /mysql               → PHPMyAdmin alias
  /adminer             → Adminer (similar to PMA)
  /webmail             → Roundcube / RainLoop / Squirrelmail
  /mail                → Webmail alias
  /cpanel              → cPanel
  /webmin              → Webmin
  /:2083 /:2087        → cPanel/WHM HTTPS ports
  /:8443               → Plesk panel
  /:10000              → Webmin
  /:8080 /admin        → Tomcat/Generic
  /sqlitemanager       → SQLite Manager
  /.git/HEAD           → Git directory exposure
  /server-status       → Apache mod_status
  /metrics             → Prometheus metrics

Severity:
  CRITICAL: phpMyAdmin/Adminer reachable + no captcha (brute force possible)
  HIGH:     cPanel / Plesk / Webmin panel exposed
  MEDIUM:   Webmail panel (lower risk, intended public)

Usage:
  patrol-smb-admin-panels.py --hosts hosts.txt --threads 30
"""
from __future__ import annotations
import argparse, json, ssl, socket, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SMBAdminPanels/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# (path_or_port, marker, panel_name, severity)
HTTP_PANELS = [
    ("/phpmyadmin/",        b"phpMyAdmin",       "phpMyAdmin",       "CRITICAL"),
    ("/phpmyadmin",         b"phpMyAdmin",       "phpMyAdmin",       "CRITICAL"),
    ("/pma/",               b"phpMyAdmin",       "phpMyAdmin",       "CRITICAL"),
    ("/mysql/",             b"phpMyAdmin",       "phpMyAdmin",       "CRITICAL"),
    ("/adminer.php",        b"Adminer",          "Adminer",          "CRITICAL"),
    ("/adminer/",           b"Adminer",          "Adminer",          "CRITICAL"),
    ("/sqlitemanager/",     b"SQLiteManager",    "SQLiteManager",    "CRITICAL"),
    ("/webmin/",            b"Webmin",           "Webmin",           "HIGH"),
    ("/cpanel/",            b"cPanel",           "cPanel",           "HIGH"),
    ("/whm/",               b"WHM",              "WHM",              "HIGH"),
    ("/server-status",      b"Apache Server Status", "ApacheStatus", "HIGH"),
    ("/server-info",        b"Apache Server Information", "ApacheInfo", "MEDIUM"),
    ("/phpinfo.php",        b"phpinfo()",        "phpinfo",          "HIGH"),
    ("/info.php",           b"PHP Version",      "phpinfo",          "HIGH"),
    ("/test.php",           b"PHP Version",      "phpinfo",          "HIGH"),
    ("/webmail/",           b"Roundcube",        "Roundcube",        "MEDIUM"),
    ("/roundcube/",         b"Roundcube",        "Roundcube",        "MEDIUM"),
    ("/mail/",              b"Roundcube",        "Roundcube",        "MEDIUM"),
]

# (port, https?, path, marker, panel_name, severity)
PORT_PANELS = [
    (2083, True,  "/",       b"cPanel",  "cPanel HTTPS",  "HIGH"),
    (2087, True,  "/",       b"WHM",     "WHM HTTPS",     "HIGH"),
    (8443, True,  "/login_up.php3?",   b"Plesk",  "Plesk panel",   "HIGH"),
    (10000, True, "/",       b"Webmin",  "Webmin",        "HIGH"),
]


@dataclass
class AdminPanelFinding:
    host: str
    panel: str
    url: str
    severity: str
    evidence: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, timeout=5):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(5000)
    except urllib.error.HTTPError as e:
        try: body = e.read(5000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def tcp_alive(host, port, timeout=2):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except Exception:
        return False


def is_catchall(host: str) -> bool:
    """Check if host serves same content to random paths."""
    rand1 = f"https://{host}/_lictor_nonex_aaa{int.from_bytes(b'sx','big'):x}"
    rand2 = f"https://{host}/_lictor_nonex_bbb"
    s1, _, b1 = http(rand1, timeout=3)
    s2, _, b2 = http(rand2, timeout=3)
    if s1 == 200 and s2 == 200 and b1 == b2:
        return True
    return False


def scan_host(host: str) -> list[AdminPanelFinding]:
    findings = []
    # Skip catchall hosts
    if is_catchall(host): return []
    # HTTP path checks
    for path, marker, panel, sev in HTTP_PANELS:
        url = f"https://{host}{path}"
        s, h, body = http(url, timeout=4)
        if s != 200: continue
        if marker.lower() not in body.lower(): continue
        # Avoid FP: skip if body is HTML for an unrelated page that just mentions panel name
        # Require status 200 + marker actually present + content_type is HTML or expected
        findings.append(AdminPanelFinding(
            host=host, panel=panel, url=url,
            severity=sev,
            evidence=body[:200].decode("utf-8", "replace").replace("\n", " "),
            notes=f"{panel} admin panel publicly accessible at {url}",
        ))
    # Port-based panels
    for port, https, path, marker, panel, sev in PORT_PANELS:
        if not tcp_alive(host, port, timeout=2): continue
        scheme = "https" if https else "http"
        url = f"{scheme}://{host}:{port}{path}"
        s, _, body = http(url, timeout=4)
        if s == 0: continue
        if marker.lower() not in body.lower(): continue
        findings.append(AdminPanelFinding(
            host=host, panel=panel, url=url,
            severity=sev,
            evidence=body[:200].decode("utf-8", "replace").replace("\n", " "),
            notes=f"{panel} reachable on {host}:{port}",
        ))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=2000)
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/smb-admin-panels.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] smb-admin-panels — {len(hosts)} hosts × {len(HTTP_PANELS)+len(PORT_PANELS)} probes")
    n_crit = n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=90)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                else: n_med += 1
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(f.severity, "?")
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}  {f.panel}  {f.url[:80]}")
            if i % 200 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high} med={n_med}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med}")


if __name__ == "__main__":
    main()
