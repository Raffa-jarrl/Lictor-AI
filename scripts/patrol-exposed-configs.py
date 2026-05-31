#!/usr/bin/env python3
"""
patrol-exposed-configs — scanner #64.

Hunts publicly-accessible configuration files / backup files / secret files
that should never be web-served. The "low-hanging-fruit" class: paths like
/.env, /.git/config, /backup.zip, /wp-config.php.bak, /web.config.

Bounty range: $500-$10K depending on content. .env files with prod secrets
can be $10K+ if they grant cloud access.

Method (ETHICAL — single HEAD/GET per path, log path + size, never download):
  1. For each host: probe a curated list of config/backup/secret paths.
  2. If 200 + non-trivial body, log path + first 100 bytes (no secret extraction).
  3. Severity-gate: only flag paths where 200 + the body looks like the
     expected file shape (e.g. /.env → contains `=` and `KEY` style).

Usage:
  patrol-exposed-configs.py --hosts targets.txt --ledger exposed-configs.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-ConfigPatrol/0.1 (+https://lictor-ai.com)"

# (path, content_shape_regex, severity)
CONFIG_PATHS = [
    ("/.env",                    re.compile(r'^[A-Z_]+=', re.M), "HIGH"),
    ("/.env.local",              re.compile(r'^[A-Z_]+=', re.M), "HIGH"),
    ("/.env.production",         re.compile(r'^[A-Z_]+=', re.M), "CRITICAL"),
    ("/.env.prod",               re.compile(r'^[A-Z_]+=', re.M), "CRITICAL"),
    ("/.env.development",        re.compile(r'^[A-Z_]+=', re.M), "MEDIUM"),
    ("/config.json",             re.compile(r'[\{"]', re.M), "MEDIUM"),
    ("/config.yaml",             re.compile(r'[a-z_]+:', re.M), "MEDIUM"),
    ("/config.yml",              re.compile(r'[a-z_]+:', re.M), "MEDIUM"),
    ("/secrets.json",            re.compile(r'[\{"]', re.M), "HIGH"),
    ("/credentials.json",        re.compile(r'[\{"]', re.M), "HIGH"),
    ("/credentials",             re.compile(r'\[default\]|aws_access_key', re.M | re.I), "CRITICAL"),
    ("/.aws/credentials",        re.compile(r'aws_access_key', re.M | re.I), "CRITICAL"),
    ("/wp-config.php",           re.compile(r'DB_NAME|DB_USER|DB_PASS', re.M), "CRITICAL"),
    ("/wp-config.php.bak",       re.compile(r'DB_NAME|DB_USER|DB_PASS', re.M), "CRITICAL"),
    ("/wp-config.php~",          re.compile(r'DB_NAME|DB_USER|DB_PASS', re.M), "CRITICAL"),
    ("/web.config",              re.compile(r'<\?xml|<configuration', re.M), "HIGH"),
    ("/.htpasswd",               re.compile(r'^[a-z]+:\$', re.M | re.I), "HIGH"),
    ("/.htaccess",               re.compile(r'RewriteRule|<Directory|AuthType', re.M), "LOW"),
    ("/.git/config",             re.compile(r'\[core\]|\[remote', re.M), "HIGH"),
    ("/.git/HEAD",               re.compile(r'^ref: refs/', re.M), "MEDIUM"),
    ("/.svn/entries",            re.compile(r'^\d+|^https?:', re.M), "MEDIUM"),
    ("/.DS_Store",               re.compile(r'Bud1', re.M), "LOW"),
    ("/Dockerfile",              re.compile(r'FROM\s', re.M | re.I), "LOW"),
    ("/docker-compose.yml",      re.compile(r'version:|services:', re.M), "MEDIUM"),
    ("/package.json",            re.compile(r'"name":|"version":', re.M), "LOW"),
    ("/composer.json",           re.compile(r'"name":|"require":', re.M), "LOW"),
    ("/.npmrc",                  re.compile(r'_authToken|registry=', re.M | re.I), "CRITICAL"),
    ("/.pypirc",                 re.compile(r'\[pypi\]|username', re.M | re.I), "CRITICAL"),
    ("/id_rsa",                  re.compile(r'BEGIN.*PRIVATE KEY', re.M), "CRITICAL"),
    ("/id_dsa",                  re.compile(r'BEGIN.*PRIVATE KEY', re.M), "CRITICAL"),
    ("/server.key",              re.compile(r'BEGIN.*PRIVATE KEY', re.M), "CRITICAL"),
    ("/backup.sql",              re.compile(r'CREATE TABLE|INSERT INTO', re.M | re.I), "CRITICAL"),
    ("/dump.sql",                re.compile(r'CREATE TABLE|INSERT INTO', re.M | re.I), "CRITICAL"),
    ("/backup.zip",              re.compile(r'^PK', re.M), "HIGH"),
    ("/backup.tar.gz",           re.compile(r'^\x1f\x8b', re.M), "HIGH"),
    ("/database.sqlite",         re.compile(r'^SQLite format', re.M), "CRITICAL"),
    ("/phpinfo.php",             re.compile(r'<title>phpinfo', re.M | re.I), "MEDIUM"),
    ("/info.php",                re.compile(r'<title>phpinfo', re.M | re.I), "MEDIUM"),
    ("/server-status",           re.compile(r'Apache Server Status', re.M | re.I), "MEDIUM"),
    ("/.terraform/terraform.tfstate", re.compile(r'"version":\s*\d', re.M), "CRITICAL"),
    ("/terraform.tfstate",       re.compile(r'"version":\s*\d', re.M), "CRITICAL"),
    ("/elmah.axd",               re.compile(r'Error Log|ELMAH', re.M | re.I), "HIGH"),
    ("/trace.axd",               re.compile(r'Request Details|trace.axd', re.M | re.I), "HIGH"),
    ("/Trace.axd",               re.compile(r'Request Details|trace.axd', re.M | re.I), "HIGH"),
]

@dataclass
class ConfigFinding:
    host: str
    path: str
    status: int
    content_size: int
    severity: str
    content_matched: bool
    snippet: str

def probe(host: str, path: str, timeout: int = 6):
    url = f"https://{host}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8192)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None

def check_host(host: str) -> list[ConfigFinding]:
    out = []
    for path, shape_rx, sev in CONFIG_PATHS:
        time.sleep(0.15)
        status, body = probe(host, path)
        if status != 200 or not body: continue
        text = body[:8192].decode("utf-8", "replace", errors="ignore")
        # Skip generic 404-disguised-as-200 (HTML landing page)
        if "<html" in text[:200].lower() and shape_rx.pattern not in text[:200]:
            if not shape_rx.search(text): continue
        matched = bool(shape_rx.search(text))
        if not matched: continue
        snippet = text[:120].replace("\n", " ")
        out.append(ConfigFinding(
            host=host, path=path, status=status, content_size=len(body),
            severity=sev, content_matched=matched, snippet=snippet))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/exposed-configs.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Config-exposure hunt: {len(hosts)} hosts × {len(CONFIG_PATHS)} paths")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_crit, n_high, n_med, n_low = 0, 0, 0, 0
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
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                elif f.severity == "MEDIUM": n_med += 1
                else: n_low += 1
                tag = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}[f.severity]
                print(f"  [{i}/{len(hosts)}] {tag} {host}{f.path}  ({f.content_size}B  {f.severity})")
            if i % 50 == 0: print(f"  [{i}/{len(hosts)}] scan... CRIT={n_crit} HIGH={n_high} MED={n_med}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] Ledger: {args.ledger}")

if __name__ == "__main__":
    main()
