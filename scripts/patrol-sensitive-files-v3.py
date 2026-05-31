#!/usr/bin/env python3
"""
patrol-sensitive-files-v3 — HTTP probe for sensitive files at known paths.

Hunts the canonical "one file = total compromise" exposures:
  .env / .env.local / .env.production         (AWS keys, DB passwords)
  .git/config / .git/HEAD                     (private repo clone vector)
  config.json / credentials.json              (cloud SDK creds)
  database.yml / wp-config.php                (web app DB creds)
  .npmrc / .pypirc                            (private registry tokens)
  id_rsa / id_ed25519                         (SSH keys)
  .DS_Store                                   (directory listing)
  backup.sql / db.dump / dump.tar.gz          (data exfil)
  docker-compose.yml / .htpasswd              (config + creds)

FP gates:
  - 200 + SPA fallback (HTML index.html for all routes) -> skip
  - Content-Type text/html when expecting plain/binary -> skip
  - Must match expected content signature (e.g. .env must look like KEY=value lines)

Usage:
  patrol-sensitive-files-v3.py --hosts hosts.txt --max-hosts 500 --threads 30
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SensitiveFilesV3/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# (path, expected_marker_in_body, max_bytes_to_read)
PROBES = [
    ("/.env",                       rb"[A-Z_]+\s*=", 4000),
    ("/.env.local",                 rb"[A-Z_]+\s*=", 4000),
    ("/.env.production",            rb"[A-Z_]+\s*=", 4000),
    ("/.env.development",           rb"[A-Z_]+\s*=", 4000),
    ("/.git/config",                rb"\[core\]|\[remote", 2000),
    ("/.git/HEAD",                  rb"ref:\s+refs/heads/", 200),
    ("/config.json",                rb"\"[a-zA-Z_]+\":", 3000),
    ("/credentials.json",           rb"\"[a-zA-Z_]+\":|aws_access", 3000),
    ("/aws-credentials",            rb"aws_access_key_id|AKIA", 2000),
    ("/database.yml",               rb"adapter|password|username", 2000),
    ("/wp-config.php",              rb"DB_PASSWORD|DB_USER|wp-settings", 2000),
    ("/.npmrc",                     rb"_authToken|registry", 1500),
    ("/.pypirc",                    rb"\[pypi\]|username|password", 1500),
    ("/.htpasswd",                  rb":\$apr1\$|:\$2[ay]\$", 1500),
    ("/.DS_Store",                  rb"\x00\x00\x00\x01Bud1", 8),
    ("/docker-compose.yml",         rb"version:|services:", 2000),
    ("/docker-compose.yaml",        rb"version:|services:", 2000),
    ("/backup.sql",                 rb"CREATE TABLE|INSERT INTO|MySQL dump", 2000),
    ("/dump.sql",                   rb"CREATE TABLE|INSERT INTO", 2000),
    ("/db.sql",                     rb"CREATE TABLE|INSERT INTO", 2000),
    ("/dump.tar.gz",                rb"\x1f\x8b\x08", 4),
    ("/backup.tar.gz",              rb"\x1f\x8b\x08", 4),
    ("/.svn/entries",               rb"10\s*\n\s*dir|svn:", 1500),
    ("/server-status",              rb"Apache Server Status|Total accesses", 2000),
    ("/server-info",                rb"Apache Server Information", 2000),
    ("/phpinfo.php",                rb"PHP Version|phpinfo\(\)", 2000),
    ("/info.php",                   rb"PHP Version", 2000),
    ("/.well-known/security.txt",   rb"Contact:|Policy:", 1000),  # not sensitive but useful
]

@dataclass
class FileExposure:
    host: str
    path: str
    url: str
    status: int
    size: int
    content_type: str
    body_preview: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, max_bytes=4000, timeout=5):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes)
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, b"", dict(e.headers) if e.headers else {}
    except Exception:
        return 0, b"", {}


def is_spa_fallback(host: str) -> bool:
    """If a nonexistent path returns 200 with HTML/JS body, host serves SPA fallback for everything.
    Tightened: also detect <script>, sessionStorage, single-page-app markers, or large body
    where the same content is served for two distinct nonexistent paths."""
    url1 = f"https://{host}/_lictor_nonex_xyz_aaa"
    url2 = f"https://{host}/_lictor_nonex_xyz_bbb"
    s1, b1, h1 = http_get(url1, max_bytes=2000, timeout=3)
    if s1 == 200:
        ctype = h1.get("Content-Type", "").lower()
        b1_lower = b1[:1000].lower()
        # HTML/script-shaped response means SPA fallback
        if "text/html" in ctype: return True
        if b"<html" in b1_lower or b"<!doctype" in b1_lower: return True
        if b"<script" in b1_lower: return True  # naked JS = also SPA
        if b"sessionstorage" in b1_lower or b"localstorage" in b1_lower: return True
        # Two distinct nonexistent paths returning identical body = catchall
        s2, b2, _ = http_get(url2, max_bytes=2000, timeout=3)
        if s2 == 200 and b1 == b2:
            return True
    return False


def scan_host(host: str) -> list[FileExposure]:
    findings = []
    spa = is_spa_fallback(host)
    for path, marker_rx, max_bytes in PROBES:
        url = f"https://{host}{path}"
        status, body, headers = http_get(url, max_bytes=max_bytes, timeout=5)
        if status != 200 or not body:
            continue
        ctype = headers.get("Content-Type", "").lower()
        # FP gate: SPA fallback returning HTML for all paths
        if spa and ("text/html" in ctype or body[:200].lower().startswith(b"<")):
            continue
        # FP gate: even when SPA check missed, if body looks like HTML/JS NOT a config file, skip
        body_head = body[:200].lower()
        if (b"<script" in body_head or b"<html" in body_head or
            b"<!doctype" in body_head or b"sessionstorage" in body_head):
            continue
        if "text/html" in ctype and path not in ("/server-status", "/server-info", "/phpinfo.php", "/info.php"):
            continue
        # Must match expected marker
        if not re.search(marker_rx, body):
            continue
        # Severity
        if any(t in path for t in (".env", "credentials", ".git/config", "wp-config", "aws-credentials", ".npmrc")):
            sev = "CRITICAL"
        elif "security.txt" in path:
            sev = "INFO"   # this is a feature, not a vuln — useful for disclosure routing
        elif any(t in path for t in ("server-status", "server-info", "phpinfo", "info.php")):
            sev = "HIGH"
        elif any(t in path for t in ("backup", "dump", ".sql", ".tar.gz")):
            sev = "HIGH"
        else:
            sev = "MEDIUM"
        notes = f"Sensitive file exposed: {path}"
        findings.append(FileExposure(
            host=host, path=path, url=url, status=status, size=len(body),
            content_type=ctype[:80], body_preview=body[:120].decode("utf-8", "replace"),
            severity=sev, notes=notes,
        ))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=1000)
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/sensitive-files-v3.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] sensitive-files-v3 — {len(hosts)} hosts × {len(PROBES)} probes")
    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=120)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = "🔴" if f.severity == "CRITICAL" else "🟠"
                if f.severity == "CRITICAL": n_crit += 1
                else: n_high += 1
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}{f.path}")
            if i % 100 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")


if __name__ == "__main__":
    main()
