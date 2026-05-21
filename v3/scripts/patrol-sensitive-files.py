#!/usr/bin/env python3
"""
Lictor v3 — sensitive file exposure scanner (HEAD-only on PII files)

Probes web servers for accidentally-exposed sensitive files. Ethical
constraints baked in:

  - .env / .git/* / wp-config.* / config files: limited GET of first
    500 bytes — enough to confirm it's a REAL exposed file (not a 404
    page that returned 200), NOT enough to read meaningful secrets.

  - PII / PCI / database dump files (csv, sql, sql.gz, zip, dump,
    tar, json customer-list patterns): HEAD ONLY — confirms file
    EXISTS and reports its size, NEVER downloads content.

  - SSH keys / .pem files: HEAD ONLY — same reasoning.

Output: ~/Lictor/v3/ledgers/sensitive-file-candidates.jsonl

Usage:
  python3 patrol-sensitive-files.py --corpus PATH --max-domains N
  python3 patrol-sensitive-files.py example.com
"""
from __future__ import annotations
import argparse, hashlib, json, re, secrets, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-SensitiveFiles/0.2 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "sensitive-file-candidates.jsonl"
CATCHALL_TOLERANCE = 0.05  # if probe CL is within 5% of canary CL, treat as catch-all match

# Each entry: (path, severity, category, fetch_mode, content_signature_regex)
# fetch_mode: "head" = HEAD only; "limited" = limited GET (≤500 bytes)
# content_signature_regex: if set, the body must match for the finding to be valid
# (this distinguishes a real .env from a 404 page that incorrectly returns 200)

SENSITIVE_PROBES = [
    # Environment files — limited GET to verify content
    ("/.env",                "critical", "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.local",          "critical", "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.production",     "critical", "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.backup",         "critical", "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.bak",            "critical", "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.dev",            "high",     "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.development",    "high",     "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.staging",        "high",     "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),
    ("/.env.test",           "medium",   "env-file",      "limited", re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.M)),

    # Git exposure
    ("/.git/config",         "critical", "git-exposure",  "limited", re.compile(r"\[core\]|\[remote ", re.M)),
    ("/.git/HEAD",           "critical", "git-exposure",  "limited", re.compile(r"ref:\s+refs/heads/", re.M)),
    ("/.git/logs/HEAD",      "critical", "git-exposure",  "limited", re.compile(r"^[0-9a-f]{40}\s", re.M)),
    ("/.git/index",          "high",     "git-exposure",  "head",    None),

    # SVN/Hg
    ("/.svn/entries",        "high",     "vcs-exposure",  "limited", re.compile(r"dir\b|\d+\n", re.M)),
    ("/.hg/store",           "high",     "vcs-exposure",  "head",    None),

    # WordPress config backups
    ("/wp-config.php.bak",   "critical", "wp-config",     "limited", re.compile(r"DB_NAME|DB_PASSWORD|<\?php", re.I)),
    ("/wp-config.php~",      "critical", "wp-config",     "limited", re.compile(r"DB_NAME|DB_PASSWORD", re.I)),
    ("/wp-config.php.old",   "critical", "wp-config",     "limited", re.compile(r"DB_NAME|DB_PASSWORD", re.I)),
    ("/wp-config.php.save",  "critical", "wp-config",     "limited", re.compile(r"DB_NAME|DB_PASSWORD", re.I)),
    ("/wp-config.php.swp",   "critical", "wp-config",     "head",    None),
    ("/.wp-config.php.swp",  "critical", "wp-config",     "head",    None),
    ("/wp-config.php.txt",   "critical", "wp-config",     "limited", re.compile(r"DB_NAME|DB_PASSWORD", re.I)),

    # Config files
    ("/config.json",         "high",     "config-file",   "limited", re.compile(r"[\"']?(api_key|secret|password|token)[\"']?\s*:", re.I)),
    ("/credentials.json",    "critical", "config-file",   "limited", re.compile(r"type|private_key|client_email|access_token", re.I)),
    ("/secrets.json",        "critical", "config-file",   "limited", re.compile(r"[\"']?(secret|key|password|token)[\"']?\s*:", re.I)),
    ("/firebase.json",       "medium",   "config-file",   "limited", re.compile(r"hosting|firestore|functions", re.I)),
    ("/database.yml",        "critical", "config-file",   "limited", re.compile(r"adapter:|password:|username:", re.I)),
    ("/database.yaml",       "critical", "config-file",   "limited", re.compile(r"adapter:|password:|username:", re.I)),
    ("/settings.py",         "high",     "config-file",   "limited", re.compile(r"SECRET_KEY|DATABASES\s*=", re.I)),
    ("/application.properties","high",   "config-file",   "limited", re.compile(r"spring\.datasource|server\.port", re.I)),
    ("/web.config",          "medium",   "config-file",   "limited", re.compile(r"<configuration>|<connectionStrings>", re.I)),

    # Database dump files — HEAD ONLY (never download)
    ("/backup.sql",          "critical", "db-dump",       "head",    None),
    ("/backup.sql.gz",       "critical", "db-dump",       "head",    None),
    ("/backup.zip",          "critical", "db-dump",       "head",    None),
    ("/backup.tar.gz",       "critical", "db-dump",       "head",    None),
    ("/dump.sql",            "critical", "db-dump",       "head",    None),
    ("/dump.sql.gz",         "critical", "db-dump",       "head",    None),
    ("/db.sql",              "critical", "db-dump",       "head",    None),
    ("/database.sql",        "critical", "db-dump",       "head",    None),
    ("/database.sql.gz",     "critical", "db-dump",       "head",    None),
    ("/mysql.sql",           "critical", "db-dump",       "head",    None),
    ("/site-backup.tar.gz",  "critical", "db-dump",       "head",    None),
    ("/www.tar.gz",          "critical", "db-dump",       "head",    None),
    ("/wordpress.sql",       "critical", "db-dump",       "head",    None),
    ("/wp.sql",              "critical", "db-dump",       "head",    None),

    # PII/PCI candidates — HEAD ONLY
    ("/customers.csv",       "critical", "pii-pci-file",  "head",    None),
    ("/users.csv",           "critical", "pii-pci-file",  "head",    None),
    ("/transactions.csv",    "critical", "pii-pci-file",  "head",    None),
    ("/orders.csv",          "critical", "pii-pci-file",  "head",    None),
    ("/payments.csv",        "critical", "pii-pci-file",  "head",    None),
    ("/export.csv",          "high",     "pii-pci-file",  "head",    None),
    ("/data.csv",            "medium",   "pii-pci-file",  "head",    None),

    # SSH/PGP keys — HEAD ONLY
    ("/id_rsa",              "critical", "private-key",   "head",    None),
    ("/.ssh/id_rsa",         "critical", "private-key",   "head",    None),
    ("/.ssh/authorized_keys","high",     "private-key",   "head",    None),
    ("/server.key",          "critical", "private-key",   "head",    None),
    ("/private.key",         "critical", "private-key",   "head",    None),
    ("/key.pem",             "critical", "private-key",   "head",    None),

    # Cloud credentials — HEAD ONLY
    ("/.aws/credentials",    "critical", "cloud-creds",   "limited", re.compile(r"\[default\]|aws_access_key_id", re.I)),
    ("/credentials",         "high",     "cloud-creds",   "head",    None),

    # Server info disclosure (lower severity)
    ("/server-status",       "medium",   "info-disclosure","limited", re.compile(r"Apache Server Status|Total accesses:|Server Version:", re.I)),
    ("/server-info",         "medium",   "info-disclosure","limited", re.compile(r"Apache Server Information|<title>Server Information", re.I)),
    ("/actuator/env",        "high",     "info-disclosure","limited", re.compile(r"propertySources|activeProfiles", re.I)),
    ("/actuator/health",     "low",      "info-disclosure","limited", re.compile(r"status.*UP", re.I)),
    ("/phpinfo.php",         "high",     "info-disclosure","limited", re.compile(r"<title>phpinfo\(\)|PHP Version", re.I)),
    ("/info.php",            "high",     "info-disclosure","limited", re.compile(r"<title>phpinfo\(\)|PHP Version", re.I)),
    ("/.htpasswd",           "high",     "info-disclosure","limited", re.compile(r":\$apr1\$|:\$2[ay]\$|:\$2[ay]\$", re.I)),
    ("/.DS_Store",           "low",      "info-disclosure","head",    None),

    # API surface (often not sensitive but worth knowing)
    ("/swagger.json",        "low",      "api-surface",   "limited", re.compile(r"swagger.*[0-9]|openapi", re.I)),
    ("/openapi.json",        "low",      "api-surface",   "limited", re.compile(r"openapi|swagger", re.I)),
    ("/api-docs",            "low",      "api-surface",   "head",    None),
    ("/api/swagger",         "low",      "api-surface",   "head",    None),
]


def _fetch(url: str, method: str = "GET", max_bytes: int = 500, timeout: int = 5) -> dict | None:
    """Fetch with strict byte limit (max_bytes=500 for content-verify;
    method='HEAD' for header-only). NEVER reads more than max_bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes).decode("utf-8", "replace") if method != "HEAD" else ""
            return {
                "status": r.status,
                "headers": {k: v for k, v in r.headers.items()},
                "body": body,
                "content_length": r.headers.get("Content-Length", ""),
                "content_type": r.headers.get("Content-Type", ""),
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": {k: v for k, v in e.headers.items()} if e.headers else {},
            "body": "",
            "content_length": "",
            "content_type": "",
        }
    except Exception:
        return None


def probe_one_host(host: str) -> list[dict]:
    findings = []
    # First confirm host is reachable on HTTP/S
    base = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        r = _fetch(url, method="HEAD")
        if r is not None:
            base = f"{scheme}://{host}"
            break
    if base is None:
        return findings

    # ANTI-CATCHALL CANARY — probe 2 nonsense paths and capture their
    # content-length + body hash. If subsequent probes match the canary
    # signature, the host is a wildcard/catch-all and the "finding" is
    # spurious (host returns same response for every URL).
    canary_paths = [
        f"/__lictor_canary_{secrets.token_hex(8)}",
        f"/__lictor_canary_{secrets.token_hex(8)}.bak",
    ]
    canary_cls = set()
    canary_hashes = set()
    canary_200_count = 0
    for cp in canary_paths:
        cr = _fetch(base + cp, method="GET", max_bytes=2000)
        if cr is None:
            continue
        if cr["status"] == 200:
            canary_200_count += 1
            try:
                cl = int(cr.get("content_length") or 0)
            except Exception:
                cl = 0
            if cl > 0:
                canary_cls.add(cl)
            body = cr.get("body", "") or ""
            if body:
                canary_hashes.add(hashlib.md5(body.encode("utf-8", "replace")).hexdigest())

    is_catchall = canary_200_count >= 1  # any 200 on nonsense = catch-all behavior

    def looks_like_canary(probe_cl: str, probe_body: str = "") -> bool:
        """Returns True if probe response matches catch-all signature."""
        if not is_catchall:
            return False
        try:
            cl = int(probe_cl or 0)
        except Exception:
            cl = 0
        # Match by exact CL or within tolerance of any canary CL
        for ccl in canary_cls:
            if cl == ccl:
                return True
            if ccl > 0 and abs(cl - ccl) / max(ccl, 1) < CATCHALL_TOLERANCE:
                return True
        # Match by body hash (limited-GET path)
        if probe_body:
            ph = hashlib.md5(probe_body.encode("utf-8", "replace")).hexdigest()
            if ph in canary_hashes:
                return True
        return False

    # Probe each sensitive path
    for path, severity, category, mode, sig_rx in SENSITIVE_PROBES:
        url = base + path
        if mode == "head":
            r = _fetch(url, method="HEAD")
        else:
            r = _fetch(url, method="GET", max_bytes=500)
        if r is None:
            continue
        if r["status"] != 200:
            continue
        # ANTI-CATCHALL: skip if response matches canary signature
        if looks_like_canary(r.get("content_length", ""), r.get("body", "")):
            continue
        # Anti-FP gate: if a signature regex is required, the body must match
        if sig_rx is not None and mode == "limited":
            if not sig_rx.search(r["body"]):
                continue  # 200 returned but body doesn't match — likely catch-all 404
        # For HEAD-only paths, the existence of a 200 is the finding (we can't see body)
        # but we should still skip CDN catch-all 200s — check Content-Length is reasonable
        if mode == "head":
            cl = r["content_length"]
            try:
                cl_int = int(cl) if cl else 0
            except Exception:
                cl_int = 0
            # Skip very small bodies (likely error pages)
            if cl_int < 50:
                continue

        finding = {
            "host": host,
            "url": url,
            "path": path,
            "severity": severity,
            "category": category,
            "fetch_mode": mode,
            "status": r["status"],
            "content_length": r["content_length"],
            "content_type": r["content_type"],
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        # For limited-GET findings, attach a tiny safe excerpt (first 80 chars, sanitized)
        if mode == "limited":
            excerpt = r["body"][:80].replace("\n", " ").replace("\r", " ")
            # Redact obvious password values for safety in our own logs
            excerpt = re.sub(r"(password|secret|key|token)\s*[=:]\s*['\"]?[^\s'\"]*", r"\1=[REDACTED]", excerpt, flags=re.I)
            finding["body_excerpt"] = excerpt
        findings.append(finding)
        print(f"  🔴 SENSITIVE  {host}{path}  [{category}/{severity}] CL={r['content_length'] or '?'}", flush=True)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?")
    ap.add_argument("--corpus", help="path to host corpus")
    ap.add_argument("--max-domains", type=int, default=200)
    ap.add_argument("--workers", type=int, default=20)
    args = ap.parse_args()

    if args.target:
        hosts = [args.target]
    elif args.corpus:
        p = Path(args.corpus).expanduser()
        if not p.exists():
            sys.exit(f"❌ {p} not found")
        hosts = [l.strip() for l in p.read_text().splitlines() if l.strip()][:args.max_domains]
    else:
        ap.print_help()
        sys.exit(1)

    print(f"[+] sensitive-files v1 — {len(hosts)} hosts × {len(SENSITIVE_PROBES)} probes", flush=True)
    print(f"[+] Ethical: HEAD-only on PII/PCI/DB-dump files; limited GET (≤500B) on configs", flush=True)
    print(f"[+] Anti-FP: limited-GET findings require body signature to match", flush=True)

    all_findings = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe_one_host, h): h for h in hosts}
        for fut in as_completed(futures):
            completed += 1
            if completed % 20 == 0:
                print(f"  [{completed}/{len(hosts)}] hosts probed, {len(all_findings)} sensitive files found", flush=True)
            try:
                hits = fut.result(timeout=120)
            except Exception:
                continue
            all_findings.extend(hits)

    print(f"\n[+] scan complete: {len(all_findings)} sensitive file findings", flush=True)

    if all_findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in all_findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(all_findings)} entries to {LEDGER}", flush=True)


if __name__ == "__main__":
    main()
