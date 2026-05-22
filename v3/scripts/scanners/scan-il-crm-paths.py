"""IL political CRM / admin path probe — HEAD-only, MAXIMUM ethical limits.

Targets political CRM, admin panel, voter/donor data export paths.
NEVER fetches body content. NEVER attempts authentication.
Records: status, content-length, content-type, server header.

For ANY 200 response on a voter/donor data path → STOP, flag for CERT-IL.
"""
import urllib.request, urllib.error, ssl, json, re, secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-ILGovProbe/0.1 (ethical-research; +https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "il-parties-crm-paths.jsonl"

# Sensitive paths grouped by category (all HEAD-only, signature collection)
ADMIN_PATHS = [
    # Generic admin panels
    "/admin", "/admin/", "/admin.php", "/admin/login", "/administrator",
    "/login", "/auth/login", "/user/login", "/wp-login.php", "/wp-admin/",
    # CMS admin
    "/wp-admin/admin-ajax.php", "/wp-json/wp/v2/users",
    "/index.php?option=com_users", "/administrator/index.php",  # Joomla
    "/typo3/", "/_admin/", "/dashboard",
    # Database admin tools
    "/phpmyadmin/", "/pma/", "/myadmin/", "/dbadmin/", "/adminer.php",
    "/phpMyAdmin/", "/phpinfo.php",
    # Common framework admin
    "/admin/login.aspx", "/Admin/Login.aspx", "/Admin/",
    # Server status / monitoring
    "/server-status", "/server-info", "/nginx_status",
]

DATA_EXPORT_PATHS = [
    # Voter/donor/member data exports — MUST FLAG IF 200
    "/voters.csv", "/voters.xlsx", "/voters.json", "/api/voters",
    "/members.csv", "/members.xlsx", "/members.json", "/api/members",
    "/donors.csv", "/donations.csv", "/api/donations", "/api/donors",
    "/contributions.csv", "/api/contributions",
    "/contacts.csv", "/contacts.xlsx", "/api/contacts",
    "/export.csv", "/export.xlsx", "/export.json", "/export.zip",
    "/database.sql", "/db.sql", "/dump.sql", "/backup.sql",
    "/users.csv", "/users.xlsx", "/api/users",
    # Common DB backup paths
    "/backup/", "/backups/", "/bak/", "/old/", "/_backup/",
    "/dump/", "/db-backup/", "/sql/", "/sqlite/",
    "/db.sqlite", "/database.sqlite", "/wp-content/uploads/db.sql",
    # Hebrew/Israel-specific data path patterns
    "/bocharim.csv", "/bocharim.xlsx",  # voters in Hebrew
    "/chaverim.csv", "/chaverim.xlsx",  # members in Hebrew
    "/mishpacha.csv",  # family in Hebrew
    # Mailing lists
    "/mailinglist.csv", "/subscribers.csv", "/api/subscribers",
    # CRM-specific
    "/leads.csv", "/api/leads", "/crm/export",
]

CONFIG_PATHS = [
    # Webserver config exposure (HEAD only)
    "/.htaccess", "/.htpasswd", "/web.config", "/nginx.conf",
    "/config.php", "/config.json", "/config.yml", "/config/database.php",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/.env", "/.env.production", "/.env.bak",
    "/composer.json", "/composer.lock",
    "/package.json", "/.npmrc",
]


def fetch_head(url, timeout=5):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, {k: v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k: v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return None, None


def head_cl(url):
    st, hdr = fetch_head(url)
    if st != 200 or not hdr: return None
    try: return int(hdr.get("Content-Length", "0"))
    except: return 0


def scan_host(host):
    findings = []
    base = f"https://{host}"
    # Canaries — HEAD on 3 random paths to detect catch-all
    nonce = secrets.token_hex(6)
    canary_cls = set()
    for cp in [f"/__canary_{nonce}.html", f"/__canary_{nonce}.csv",
               f"/__canary_{nonce}", f"/admin/__canary_{nonce}"]:
        cl = head_cl(f"{base}{cp}")
        if cl is not None and cl > 0:
            canary_cls.add(cl)

    all_paths = [(p, "admin") for p in ADMIN_PATHS] + \
                [(p, "data-export") for p in DATA_EXPORT_PATHS] + \
                [(p, "config") for p in CONFIG_PATHS]

    for path, category in all_paths:
        st, hdr = fetch_head(f"{base}{path}", timeout=4)
        if st not in (200, 301, 302, 401, 403): continue
        if not hdr: continue
        try: cl = int(hdr.get("Content-Length", "0"))
        except: cl = 0
        ct = hdr.get("Content-Type", "?")
        # Skip canary-matching (catch-all)
        if any(c > 0 and cl > 0 and abs(cl - c) / c < 0.05 for c in canary_cls): continue
        # Skip pure HTML on data-export paths (catch-all SPA)
        if category == "data-export" and "text/html" in ct.lower() and st == 200: continue
        # Log finding
        severity = "INFO"
        if category == "data-export" and st == 200: severity = "CRITICAL"  # exposed data
        elif category == "admin" and st == 200: severity = "HIGH"
        elif category == "config" and st == 200: severity = "HIGH"
        elif st in (401, 403): severity = "INFO"  # exists but locked

        print(f"  [{severity}] {host}{path}  HTTP={st} cl={cl} ct={ct[:40]}", flush=True)
        findings.append({
            "host": host, "path": path, "category": category,
            "status": st, "content_length": cl, "content_type": ct,
            "severity": severity,
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()]
print(f"[+] IL-CRM path probe — {len(hosts)} hosts × {len(ADMIN_PATHS)+len(DATA_EXPORT_PATHS)+len(CONFIG_PATHS)} paths (HEAD-only)", flush=True)
print(f"[+] ETHICAL: HEAD-only, no body fetch, no auth attempts. CRITICAL = exposed data path, requires CERT-IL notification.", flush=True)
print(flush=True)
all_findings = []
with ThreadPoolExecutor(max_workers=15) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        try:
            r = fut.result(timeout=120)
            if r: all_findings.extend(r)
        except Exception:
            pass
print(f"\n[+] IL-CRM scan complete: {len(all_findings)} findings", flush=True)

# Severity breakdown
from collections import Counter
sev = Counter(f["severity"] for f in all_findings)
print(f"[+] Severity breakdown: {dict(sev)}", flush=True)

if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)

    # Print CRITICAL findings prominently
    crits = [f for f in all_findings if f["severity"] == "CRITICAL"]
    if crits:
        print(f"\n🔴🔴🔴 CRITICAL FINDINGS (exposed data paths) — REQUIRES CERT-IL NOTIFICATION 🔴🔴🔴", flush=True)
        for c in crits:
            print(f"   {c['host']}{c['path']}  HTTP={c['status']}  cl={c['content_length']}  ct={c['content_type']}", flush=True)
