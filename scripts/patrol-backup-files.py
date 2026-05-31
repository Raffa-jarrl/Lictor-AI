#!/usr/bin/env python3
"""
patrol-backup-files — hunts publicly-served backup files.

The "we copied the prod DB to /backup.sql for migration and forgot to delete"
class. Often contains full DB dumps with PII, hashed passwords, internal
schema, API keys, etc. Real $500-5K class on SMBs (no bounty programs
typically, but can be paid CVD on larger targets).

Probes for common backup naming patterns:
  /backup.sql, /backup.sql.gz, /backup.tar.gz, /backup.zip
  /database.sql, /db.sql, /dump.sql, /db_backup.sql
  /site.tar.gz, /www.tar.gz, /htdocs.tar.gz, /public_html.tar.gz
  /<host>.sql, /<host>.tar.gz (date-stamped variations too)
  /backup/, /backups/, /db_backups/ (directory listing)
  /uploads/backup.sql (commonly-overlooked)

Content validation:
  .sql → "CREATE TABLE" / "INSERT INTO" / "MySQL dump"
  .tar.gz → gzip magic bytes (1f 8b 08)
  .zip → PK magic bytes
  Directory listing → "Index of /" / "Parent Directory"

Usage:
  patrol-backup-files.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-BackupFiles/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# (path, expected_magic_or_marker, severity, notes)
BACKUP_PROBES = [
    ("/backup.sql",         b"CREATE TABLE|INSERT INTO|MySQL dump",  "CRITICAL"),
    ("/database.sql",       b"CREATE TABLE|INSERT INTO|MySQL dump",  "CRITICAL"),
    ("/db.sql",             b"CREATE TABLE|INSERT INTO|MySQL dump",  "CRITICAL"),
    ("/dump.sql",           b"CREATE TABLE|INSERT INTO|MySQL dump",  "CRITICAL"),
    ("/db_backup.sql",      b"CREATE TABLE|INSERT INTO",             "CRITICAL"),
    ("/backup.sql.gz",      b"\x1f\x8b\x08",                          "CRITICAL"),
    ("/backup.tar.gz",      b"\x1f\x8b\x08",                          "CRITICAL"),
    ("/backup.zip",         b"PK\x03\x04",                            "CRITICAL"),
    ("/site.tar.gz",        b"\x1f\x8b\x08",                          "HIGH"),
    ("/www.tar.gz",         b"\x1f\x8b\x08",                          "HIGH"),
    ("/htdocs.tar.gz",      b"\x1f\x8b\x08",                          "HIGH"),
    ("/public_html.tar.gz", b"\x1f\x8b\x08",                          "HIGH"),
    ("/db.tar.gz",          b"\x1f\x8b\x08",                          "CRITICAL"),
    ("/mysqldump.sql",      b"MySQL dump|CREATE TABLE",                "CRITICAL"),
    ("/wordpress.sql",      b"CREATE TABLE.*wp_",                      "CRITICAL"),
    ("/backup/",            b"Index of|Parent Directory",              "HIGH"),
    ("/backups/",           b"Index of|Parent Directory",              "HIGH"),
    ("/db_backups/",        b"Index of|Parent Directory",              "HIGH"),
    ("/uploads/backup.sql", b"CREATE TABLE|INSERT INTO",               "CRITICAL"),
    ("/files/backup.sql",   b"CREATE TABLE|INSERT INTO",               "CRITICAL"),
    ("/admin/backup.sql",   b"CREATE TABLE|INSERT INTO",               "CRITICAL"),
    ("/.backup",            b"\x1f\x8b\x08|CREATE TABLE|PK",           "HIGH"),
]


@dataclass
class BackupFinding:
    host: str
    path: str
    url: str
    size: int
    severity: str
    content_class: str  # "sql", "tar.gz", "zip", "dir_listing"
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, max_bytes=4000, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes)
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(max_bytes)
        except: body = b""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return 0, b"", {}


def is_catchall(host: str) -> bool:
    """Two random paths returning same content = catchall."""
    s1, b1, _ = http(f"https://{host}/_lictor_xyz_aaa", timeout=4, max_bytes=1500)
    s2, b2, _ = http(f"https://{host}/_lictor_xyz_bbb", timeout=4, max_bytes=1500)
    if s1 == 200 and s2 == 200 and b1 == b2:
        return True
    return False


def classify_content(body: bytes) -> str:
    if body[:3] == b"\x1f\x8b\x08": return "gzip"
    if body[:4] == b"PK\x03\x04":   return "zip"
    if b"CREATE TABLE" in body or b"INSERT INTO" in body or b"MySQL dump" in body: return "sql"
    if b"Index of" in body[:500] or b"Parent Directory" in body[:500]: return "dir_listing"
    return "unknown"


def scan_host(host: str) -> list[BackupFinding]:
    if is_catchall(host): return []
    findings = []
    for path, marker_rx, sev in BACKUP_PROBES:
        url = f"https://{host}{path}"
        status, body, headers = http(url, max_bytes=4000, timeout=5)
        if status != 200 or not body or len(body) < 4: continue
        # FP gate: HTML content type for non-directory probes
        ctype = headers.get("Content-Type", "").lower()
        if path.endswith("/"):
            # Directory listing — accept text/html if marker matches
            pass
        elif "text/html" in ctype:
            continue  # backup files shouldn't be served as HTML
        # Marker match
        if not re.search(marker_rx, body): continue
        # Extra FP gate: skip if body is < 50 bytes (probably error page snippet)
        if len(body) < 50 and not path.endswith("/"): continue
        findings.append(BackupFinding(
            host=host, path=path, url=url,
            size=len(body), severity=sev,
            content_class=classify_content(body),
            notes=f"Backup file exposed at {path} ({classify_content(body)}, {len(body)} bytes sampled)",
        ))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/backup-files.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] backup-files — {len(hosts)} hosts × {len(BACKUP_PROBES)} probes")
    n_crit = n_high = 0
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
                else: n_high += 1
                tag = "🔴" if f.severity == "CRITICAL" else "🟠"
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}{f.path}  ({f.content_class}, {f.size} B)")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")


if __name__ == "__main__":
    main()
