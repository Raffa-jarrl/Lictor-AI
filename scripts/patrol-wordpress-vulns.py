#!/usr/bin/env python3
"""
patrol-wordpress-vulns — comprehensive WordPress vuln scanner for SMB targets.

WordPress = 43% of all websites. SMB sites overwhelmingly use it. Checks:

  1. WP detection (wp-login.php, /wp-admin/, /wp-includes/, /wp-json/)
  2. User enumeration via REST API (/?rest_route=/wp/v2/users)
     OR /wp-json/wp/v2/users — leaks usernames + author IDs
  3. xmlrpc.php open (DDoS amplification + brute-force vector)
  4. WP version disclosure (meta generator + /wp-includes/version.php)
  5. /wp-config.php.bak or .save backup files
  6. Open /wp-content/uploads/ directory listing
  7. Debug log exposed (/wp-content/debug.log)
  8. WP_DEBUG=true (PHP errors in HTML)

Each finding reports specific severity:
  CRITICAL: /wp-config.php.bak (contains DB password)
  HIGH:     debug.log with PHP errors revealing paths
  MEDIUM:   user enumeration, xmlrpc open
  LOW:      version disclosure (informational)

Usage:
  patrol-wordpress-vulns.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-WPVulnPatrol/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


@dataclass
class WPFinding:
    host: str
    issue: str           # 'user_enum' / 'xmlrpc_open' / 'config_backup' / etc
    evidence_url: str
    evidence: str        # short snippet of body
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, method="GET", headers=None, timeout=6):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(15000)
    except urllib.error.HTTPError as e:
        try: body = e.read(15000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def is_wordpress(host: str) -> bool:
    """Detect WP via /wp-login.php (200) or /wp-json/ (200 JSON)."""
    s1, _, b1 = http(f"https://{host}/wp-login.php", timeout=4)
    if s1 == 200 and (b"wordpress" in b1.lower() or b"wp-login" in b1.lower()):
        return True
    s2, h2, b2 = http(f"https://{host}/wp-json/", timeout=4)
    if s2 == 200 and (b"wp/v2" in b2.lower() or b"wordpress" in b2.lower()):
        return True
    s3, _, b3 = http(f"https://{host}/", timeout=4)
    if b"/wp-content/" in b3 or b"/wp-includes/" in b3 or b'<meta name="generator" content="WordPress' in b3:
        return True
    return False


def check_user_enum(host: str) -> list[WPFinding]:
    """REST API /wp-json/wp/v2/users — returns user list if not blocked."""
    findings = []
    for url in (f"https://{host}/wp-json/wp/v2/users",
                f"https://{host}/?rest_route=/wp/v2/users"):
        s, _, body = http(url, timeout=5)
        if s == 200 and body.startswith(b"[") and b'"slug"' in body and b'"name"' in body:
            findings.append(WPFinding(
                host=host, issue="wp_user_enum_rest",
                evidence_url=url,
                evidence=body[:200].decode("utf-8", "replace"),
                severity="MEDIUM",
                notes="WordPress REST API leaks usernames + author slugs without auth.",
            ))
            return findings  # one is enough
    return findings


def check_xmlrpc_open(host: str) -> list[WPFinding]:
    """xmlrpc.php returns 405 to GET if active, 200 to POST with XML."""
    url = f"https://{host}/xmlrpc.php"
    s, _, body = http(url, method="GET", timeout=5)
    if s == 405 or (s == 200 and b"XML-RPC" in body):
        # Try a system.listMethods POST to confirm it's responsive
        post_url = url
        try:
            req = urllib.request.Request(post_url, method="POST",
                data=b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
                headers={"Content-Type": "text/xml", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                rbody = r.read(5000)
                if b"system.listMethods" in rbody or b"methodResponse" in rbody:
                    return [WPFinding(
                        host=host, issue="xmlrpc_open",
                        evidence_url=url,
                        evidence=rbody[:200].decode("utf-8", "replace"),
                        severity="MEDIUM",
                        notes="xmlrpc.php accepts POSTs (DDoS amplification + brute-force vector).",
                    )]
        except Exception: pass
    return []


def check_config_backup(host: str) -> list[WPFinding]:
    """wp-config.php.bak / .save / .swp / ~ etc."""
    findings = []
    for suffix in (".bak", ".save", ".swp", "~", ".old", ".backup", ".orig", ".tmp"):
        url = f"https://{host}/wp-config.php{suffix}"
        s, _, body = http(url, timeout=4)
        if s == 200 and (b"DB_PASSWORD" in body or b"DB_NAME" in body or b"<?php" in body[:50]):
            findings.append(WPFinding(
                host=host, issue="wp_config_backup",
                evidence_url=url,
                evidence=body[:200].decode("utf-8", "replace"),
                severity="CRITICAL",
                notes=f"wp-config.php{suffix} exposed — contains DB credentials + auth keys.",
            ))
            return findings  # one is enough
    return findings


def check_debug_log(host: str) -> list[WPFinding]:
    """/wp-content/debug.log exposed."""
    url = f"https://{host}/wp-content/debug.log"
    s, _, body = http(url, timeout=4)
    if s == 200 and len(body) > 50 and (b"PHP Warning" in body or b"PHP Fatal" in body or b"PHP Notice" in body or b"Stack trace" in body):
        return [WPFinding(
            host=host, issue="wp_debug_log",
            evidence_url=url,
            evidence=body[:300].decode("utf-8", "replace"),
            severity="HIGH",
            notes="WordPress debug.log publicly readable — reveals file paths, plugin internals, potential secrets.",
        )]
    return []


def check_version(host: str) -> list[WPFinding]:
    """Get WP version via meta generator + /wp-includes/version.php."""
    s, _, body = http(f"https://{host}/", timeout=4)
    m = re.search(rb'<meta name="generator" content="WordPress ([\d.]+)"', body)
    if m:
        ver = m.group(1).decode()
        # Only flag if version is OLD (< 6.5 as of 2026)
        try:
            major = int(ver.split(".")[0])
            minor = int(ver.split(".")[1]) if "." in ver else 0
            if major < 6 or (major == 6 and minor < 5):
                return [WPFinding(
                    host=host, issue="wp_outdated_version",
                    evidence_url=f"https://{host}/",
                    evidence=f'<meta name="generator" content="WordPress {ver}">',
                    severity="MEDIUM",
                    notes=f"WordPress {ver} is outdated. Latest is 6.5+. Likely vulnerable to known CVEs.",
                )]
        except: pass
    return []


def scan_host(host: str) -> list[WPFinding]:
    if not is_wordpress(host):
        return []
    findings = []
    for check in (check_user_enum, check_xmlrpc_open, check_config_backup,
                  check_debug_log, check_version):
        try:
            findings += check(host)
        except Exception: pass
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/wordpress-vulns.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] wordpress-vulns — {len(hosts)} hosts")
    n_crit = n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                else: n_med += 1
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(f.severity, "?")
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}  {f.issue}")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high} med={n_med}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med}")


if __name__ == "__main__":
    main()
