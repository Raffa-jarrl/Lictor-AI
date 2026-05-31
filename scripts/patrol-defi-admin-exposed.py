#!/usr/bin/env python3
"""
patrol-defi-admin-exposed — scanner #51 (Web3 pivot).

For each DeFi protocol domain, enumerate likely admin/governance/dev/staging
subdomains and check if they're publicly reachable without authentication.

Bounty rationale: DeFi protocols often expose admin panels (oracle config,
treasury management, governance dashboards) without auth in staging environments
that get accidentally pointed at production data. A single exposed admin panel
on a $100M+ TVL protocol → Immunefi-tier bounty ($5K-$100K+).

Top discovery patterns from past DeFi disclosures:
  - admin.{protocol}      governance configuration
  - dev.{protocol}        engineering tooling
  - staging.{protocol}    pre-prod environment with prod data
  - internal.{protocol}   internal-only tooling exposed
  - dashboard.{protocol}  treasury/ops dashboards
  - keeper.{protocol}     bot-management consoles
  - oracle.{protocol}     oracle-config admin

Method (ETHICAL — Lictor never authenticates):
  1. For each DeFi apex, generate candidate subdomains
  2. DNS-resolve each (skip NXDOMAIN)
  3. HTTP GET / on each
  4. Classify response:
     - 200 + non-login HTML → POTENTIAL exposed admin
     - 401/403 → properly gated (safe)
     - 200 + login form → properly gated (safe)
     - 5xx → server error, skip

Usage:
  patrol-defi-admin-exposed.py --hosts defi-hosts.txt --ledger defi-admin-exposed.jsonl
"""
from __future__ import annotations
import argparse, json, socket, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-DeFiAdminPatrol/0.1 (+https://lictor-ai.com)"

ADMIN_SUBDOMAINS = [
    "admin", "administrator", "console", "dashboard", "panel", "manage",
    "dev", "develop", "development", "staging", "stage", "test", "qa",
    "internal", "internals", "tools", "ops", "operations", "infra",
    "keeper", "keepers", "bot", "bots", "deployer", "deploy",
    "oracle", "oracles", "governance", "treasury", "vault-admin",
    "monitor", "monitoring", "metrics", "status",
    "private", "secret", "hidden", "secure",
    "support", "ticket", "tickets",
    "ci", "cd", "ci-cd", "jenkins", "grafana", "kibana",
    "rpc", "rpc-admin", "node", "node-admin", "validator-admin",
]

LOGIN_FORM_HINTS = [
    "<form", "type=\"password\"", "type='password'", "name=\"password\"",
    "name='password'", "name=\"login\"", "sign in", "log in", "login",
    "authenticate", "credentials", "username and password"
]

# Wallet-connect prompts on DeFi UIs are NOT proof of admin — exclude those
WALLET_CONNECT_HINTS = [
    "connect wallet", "metamask", "walletconnect", "rainbowkit",
    "web3-modal", "wallet-modal", "connect your wallet"
]

@dataclass
class AdminFinding:
    apex: str
    candidate_subdomain: str
    url: str
    status: int
    classification: str   # "exposed_potential", "auth_gated", "login_form",
                          # "wallet_connect", "nxdomain", "error", "unknown"
    title_or_first_h1: str = ""
    notes: str = ""

def resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None, timeout=4)
        return True
    except Exception:
        return False

def fetch(url: str, timeout: int = 7):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: body = e.read(16384).decode("utf-8", "replace")
        except Exception: body = ""
        return e.code, body
    except Exception:
        return None, None

def extract_title(html: str) -> str:
    import re
    m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
    if m: return m.group(1).strip()[:80]
    m = re.search(r'<h1[^>]*>([^<]+)</h1>', html, re.I)
    if m: return m.group(1).strip()[:80]
    return ""

def classify(status: int | None, body: str | None) -> str:
    if status is None: return "error"
    if status == 404: return "error"  # subdomain doesn't serve this path
    if status in (401, 403): return "auth_gated"
    if not body: return "unknown"
    blow = body.lower()
    if any(h in blow for h in WALLET_CONNECT_HINTS):
        # Wallet-connect prompts on DeFi UIs aren't an admin panel — they're customer UIs
        return "wallet_connect"
    if any(h in blow for h in LOGIN_FORM_HINTS):
        return "login_form"
    if status in (200, 302):
        return "exposed_potential"
    return "unknown"

def check_subdomain(apex: str, subdomain: str) -> AdminFinding | None:
    host = f"{subdomain}.{apex}"
    if not resolve(host):
        return AdminFinding(apex=apex, candidate_subdomain=subdomain, url=f"https://{host}/",
                             status=0, classification="nxdomain")
    # HTTPS first, fall back to HTTP if needed
    for scheme in ("https", "http"):
        status, body = fetch(f"{scheme}://{host}/")
        if status is not None:
            break
    cls = classify(status, body)
    if cls in ("nxdomain", "error"):
        return None  # skip noise
    return AdminFinding(
        apex=apex, candidate_subdomain=subdomain,
        url=f"{scheme}://{host}/", status=status or 0,
        classification=cls,
        title_or_first_h1=extract_title(body or ""),
        notes=(body or "")[:150].replace("\n", " "))

def check_apex(apex: str) -> list[AdminFinding]:
    hits = []
    for sub in ADMIN_SUBDOMAINS:
        time.sleep(0.4)
        try:
            f = check_subdomain(apex, sub)
            if f: hits.append(f)
        except Exception:
            pass
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/defi-admin-exposed.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    apexes = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    if args.limit: apexes = apexes[:args.limit]
    print(f"[+] DeFi admin-exposed hunt: {len(apexes)} apexes × {len(ADMIN_SUBDOMAINS)} subdomains")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_exposed, n_gated = 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_apex, a): a for a in apexes}
        for i, fut in enumerate(as_completed(futures), 1):
            apex = futures[fut]
            try:
                findings = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(apexes)}] {apex} EXC: {e}")
                continue
            exposed = [f for f in findings if f.classification == "exposed_potential"]
            for f in findings:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.classification == "exposed_potential": n_exposed += 1
                elif f.classification == "auth_gated": n_gated += 1
            if exposed:
                tags = [f"{f.candidate_subdomain}({f.title_or_first_h1[:30]})" for f in exposed[:3]]
                print(f"  [{i}/{len(apexes)}] 🔴 {apex} EXPOSED: {tags}")
            elif i % 20 == 0:
                print(f"  [{i}/{len(apexes)}] (no exposed admin found yet)")

    print(f"\n[+] Done. exposed_potential={n_exposed}  auth_gated={n_gated}")
    print(f"[+] Ledger: {args.ledger}")
    print(f"[+] 🔴 exposed_potential = manual review required → potential Immunefi-tier bug")

if __name__ == "__main__":
    main()
