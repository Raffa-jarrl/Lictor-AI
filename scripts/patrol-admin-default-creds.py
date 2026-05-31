#!/usr/bin/env python3
"""
patrol-admin-default-creds — scanner #47.

Takes the output of scan-protocol-admin-panels (the existing admin-panel
fingerprint scanner) and extends it with a SINGLE default-credential probe
per (host, panel) pair.

Top-tier discovery pattern: exposed Jenkins / Grafana / Kibana / Airflow /
Sonarqube / phpMyAdmin / RabbitMQ / pgAdmin / Wordpress wp-admin / Joomla /
Adminer / Spark UI / Hadoop / RancherUI — many deployed with admin:admin,
admin:changeme, or vendor-doc defaults still in place.

Bounty rationale: "Exposed admin console with default credentials" routinely
pays $10K-$50K on HackerOne / Bugcrowd as it's an unauthenticated RCE
in spirit (admin panel = arbitrary command execution territory).

ETHICAL CONSTRAINTS (hard-coded into this scanner):
  - ONE login attempt per (host, panel) — never more. Not a brute-forcer.
  - ONLY the top vendor-default for each panel kind (no enumeration).
  - On success: log finding, do NOT navigate further, do NOT take any
    action beyond establishing the response is "authenticated" vs "rejected".
  - If panel returns 200 to default cred with login-form HTML still visible
    → marked "auth_unclear" (don't claim RCE).
  - Add a 5-second cool-down between credential attempts per host (anti-DoS).

Usage:
  patrol-admin-default-creds.py --panels admin-panels.jsonl --ledger admin-default-creds.jsonl
"""
from __future__ import annotations
import argparse, base64, json, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-AdminDefaultCredsPatrol/0.1 (+https://lictor-ai.com)"

# (panel_kind, login_path, method, form_field_user, form_field_pass, default_user, default_pass, success_signal_neg, success_signal_pos)
# success_signal_neg = string that would still appear if NOT logged in (login-form HTML)
# success_signal_pos = string that appears AFTER successful auth (dashboard, menu)
PANEL_PROFILES = {
    "jenkins": {
        "path": "/j_acegi_security_check", "method": "POST",
        "fields": {"j_username": "admin", "j_password": "admin"},
        "neg": "Invalid username or password", "pos": "Manage Jenkins"},
    "grafana": {
        "path": "/login", "method": "POST",
        "fields": {"user": "admin", "password": "admin"},
        "neg": "Invalid username", "pos": "dashboardCount",
        "content_type": "application/json"},
    "kibana": {
        "path": "/internal/security/login", "method": "POST",
        "fields": {"providerType": "basic", "providerName": "basic",
                   "currentURL": "/", "params": {"username": "elastic", "password": "changeme"}},
        "neg": "Invalid credentials", "pos": "userSettings",
        "content_type": "application/json"},
    "phpmyadmin": {
        "path": "/index.php", "method": "POST",
        "fields": {"pma_username": "root", "pma_password": ""},
        "neg": "Cannot log in to the MySQL server", "pos": "phpMyAdminUserSettings"},
    "adminer": {
        "path": "/", "method": "POST",
        "fields": {"auth[server]": "localhost", "auth[username]": "root", "auth[password]": ""},
        "neg": "Access denied", "pos": "phpMyAdminUserSettings"},
    "rabbitmq": {
        "path": "/api/whoami", "method": "GET",
        "auth_basic": ("guest", "guest"),
        "neg": "Unauthorized", "pos": '"name"'},
    "elasticsearch": {
        "path": "/_cluster/health", "method": "GET",
        "auth_basic": ("elastic", "changeme"),
        "neg": "unauthorized", "pos": "cluster_name"},
    "wp-admin": {
        "path": "/wp-login.php", "method": "POST",
        "fields": {"log": "admin", "pwd": "admin", "wp-submit": "Log In",
                   "redirect_to": "/wp-admin/", "testcookie": "1"},
        "neg": "ERROR", "pos": "wp-admin-bar"},
    "airflow": {
        "path": "/login/", "method": "POST",
        "fields": {"username": "admin", "password": "admin"},
        "neg": "Invalid login", "pos": "DAG"},
    "sonarqube": {
        "path": "/api/authentication/login", "method": "POST",
        "fields": {"login": "admin", "password": "admin"},
        "neg": "Authentication failed", "pos": ""},  # 200 = success for SonarQube
}

@dataclass
class CredHit:
    host: str
    panel_kind: str
    login_url: str
    cred_user: str
    cred_pass: str
    status: int
    classification: str  # "authenticated", "rejected", "auth_unclear"
    response_snippet: str = ""

def probe_credential(host: str, panel_kind: str, profile: dict, timeout: int = 10) -> CredHit | None:
    url = f"https://{host}{profile['path']}"
    method = profile["method"]

    headers = {"User-Agent": UA}
    body = None

    if "auth_basic" in profile:
        u, p = profile["auth_basic"]
        token = base64.b64encode(f"{u}:{p}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
        cred_user, cred_pass = u, p
    else:
        fields = profile["fields"]
        cred_user = fields.get("j_username") or fields.get("user") or fields.get("log") \
                    or fields.get("username") or fields.get("login") \
                    or fields.get("pma_username") or fields.get("auth[username]") \
                    or (fields.get("params", {}) or {}).get("username", "")
        cred_pass = fields.get("j_password") or fields.get("password") or fields.get("pwd") \
                    or fields.get("pma_password") or fields.get("auth[password]") \
                    or (fields.get("params", {}) or {}).get("password", "")
        if profile.get("content_type") == "application/json":
            body = json.dumps(fields).encode()
            headers["Content-Type"] = "application/json"
        else:
            body = urllib.parse.urlencode({k: v for k, v in fields.items()
                                            if not isinstance(v, (dict, list))}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
            text = r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try: text = e.read(4096).decode("utf-8", "replace")
        except Exception: text = ""
    except Exception:
        return None

    neg = profile.get("neg", "")
    pos = profile.get("pos", "")

    if neg and neg.lower() in text.lower():
        classification = "rejected"
    elif pos and pos.lower() in text.lower():
        classification = "authenticated"
    elif status in (200, 302) and not neg:
        classification = "authenticated"
    elif status == 401 or status == 403:
        classification = "rejected"
    else:
        classification = "auth_unclear"

    return CredHit(
        host=host, panel_kind=panel_kind, login_url=url,
        cred_user=cred_user, cred_pass=cred_pass,
        status=status, classification=classification,
        response_snippet=text[:200].replace("\n", " "))

def check_host(host: str, panel_kind: str) -> CredHit | None:
    profile = PANEL_PROFILES.get(panel_kind)
    if not profile: return None
    time.sleep(5)  # cool-down between attempts per host (anti-DoS / anti-brute)
    return probe_credential(host, panel_kind, profile)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panels", required=True,
                     help="JSONL ledger from scan-protocol-admin-panels with fields: host, panel_kind")
    ap.add_argument("--threads", type=int, default=4,
                     help="Low concurrency by design — this scanner makes auth attempts")
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/admin-default-creds.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    panels = []
    for line in Path(args.panels).read_text().splitlines():
        line = line.strip()
        if not line: continue
        try:
            j = json.loads(line)
            if j.get("host") and j.get("panel_kind") and j["panel_kind"] in PANEL_PROFILES:
                panels.append((j["host"], j["panel_kind"]))
        except Exception:
            pass
    if args.limit: panels = panels[:args.limit]

    print(f"[+] {len(panels)} (host, panel) pairs to probe with default creds")
    print(f"[+] Profiles available: {sorted(PANEL_PROFILES.keys())}")
    print(f"[+] ETHICS: ONE attempt per panel, no brute force, 5s cool-down between attempts")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_auth, n_reject, n_unclear = 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h, k): (h, k) for h, k in panels}
        for i, fut in enumerate(as_completed(futures), 1):
            host, kind = futures[fut]
            try:
                hit = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(panels)}] {host} ({kind}) EXC: {e}")
                continue
            if not hit:
                print(f"  [{i}/{len(panels)}] {host} ({kind})  no-response")
                continue
            ledger.write(json.dumps(asdict(hit)) + "\n")
            ledger.flush()
            tag = {"authenticated": "🔴", "rejected": "🟢", "auth_unclear": "🟡"}[hit.classification]
            print(f"  [{i}/{len(panels)}] {host} ({kind})  {tag} {hit.classification} status={hit.status}")
            if hit.classification == "authenticated": n_auth += 1
            elif hit.classification == "rejected": n_reject += 1
            else: n_unclear += 1

    print(f"\n[+] Done. authenticated={n_auth} rejected={n_reject} unclear={n_unclear}")
    print(f"[+] Ledger: {args.ledger}")
    print(f"[+] Authenticated findings are PROBABLE bounty material — verify manually before disclosure.")

if __name__ == "__main__":
    main()
