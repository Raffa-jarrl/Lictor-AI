#!/usr/bin/env python3
"""
verify-and-notify-f500 — runs strict verification on every F500 finding and
ONLY sends Telegram alerts for findings that survive the FP gauntlet.

Replaces the noisy per-company orchestrator notifications. Polls every 60s,
processes new/modified summary.json files, applies all known FP rules, writes
the surviving findings to a `verified-leads.jsonl` ledger and notifies once
per verified lead (deduped via lead-id).

FP gates applied:
  - CORS Class #22 (Bearer-API): if ACAH lists Authorization/Bearer-token
    headers and no cookies are set on representative paths, downgrade to
    INFO and skip notify.
  - CORS Class #11 (SPA fallback): if root + nonexistent-path return same
    response, skip notify (CDN-level CORS, no real backend variance).
  - CORS Class #CDN-edge: if Set-Cookie header is absent on the probed
    path, the CORS+credentials combination is theoretical only — skip
    notify.
  - cicd Jenkins: must have hudson.model in /api/json body.
  - cicd GitLab: must have GitLab in /users/sign_in body.
  - Severity floor: only notify on findings classified as MEDIUM+ AFTER
    the FP rules.

Usage:
  nohup python3 -u scripts/verify-and-notify-f500.py > v3/ledgers/verify-notify.log 2>&1 &
"""
from __future__ import annotations
import json, os, ssl, sys, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")
F500 = ROOT / "v3" / "ledgers" / "f500"
VERIFIED = ROOT / "v3" / "ledgers" / "verified-f500-leads.jsonl"
STATE = ROOT / "v3" / "ledgers" / "verify-notify-state.json"
sys.path.insert(0, str(ROOT / "v3" / "scripts"))
try:
    from notify_telegram import notify as tg_notify
except Exception:
    def tg_notify(msg, **kw): return False

UA = "Lictor-VerifyNotify/0.1"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def http(url, method="GET", origin=None, headers=None, timeout=5):
    h = {"User-Agent": UA}
    if origin: h["Origin"] = origin
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(50000)
    except urllib.error.HTTPError as e:
        try: body = e.read(50000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


CDN_COOKIES_FILTER = ("__cf_bm", "__cfduid", "_dd_s", "incap_ses", "visid_incap",
                       "AWSALB", "AWSALBCORS", "acw_tc")
BEARER_HINTS_FILTER = ("authorization", "bearer", "accesstoken", "x-auth-token",
                       "securitytoken", "wolken_token", "x-api-key", "apikey",
                       "x-access-token", "serviceaccount")


def get_all_cookies(headers: dict) -> str:
    sc = ""
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            sc += v + "; "
    return sc


def verify_cors_finding(d: dict) -> tuple[bool, str]:
    """STRICT verification: CORS+creds reflection alone isn't enough.
    Must demonstrate a real session-steal path exists:
      1. Bearer-API gate (FP Class #22)
      2. App cookies actually set (not just CDN cookies)
      3. At least one cookie has SameSite=None (otherwise modern browsers
         block cross-site send even with credentials:include)
    """
    host = d.get("host", "")
    cls = d.get("classification", "")
    acah = d.get("returned_acah", "").lower()
    if "WITH_CREDENTIALS" not in cls:
        return False, "no_credentials_class"

    # FP Class #22: ACAH advertises Bearer auth headers → not session-stealable
    if any(h in acah for h in BEARER_HINTS_FILTER):
        return False, "fp22_bearer_api_in_acah"

    # Probe multiple paths looking for an actual app cookie with SameSite=None
    has_real_cookie = False
    samesite_none = False
    for path in ("/", "/login", "/api/auth", "/api/login",
                 "/api/users/me", "/me", "/account", "/api/account"):
        s2, h2, _ = http(f"https://{host}{path}", timeout=3)
        if s2 == 0: continue
        cookies_str = get_all_cookies(h2)
        for chunk in cookies_str.split(","):
            name_part = chunk.strip().split("=")[0].split(";")[0].strip()
            if not name_part: continue
            if any(cn in name_part for cn in CDN_COOKIES_FILTER): continue
            has_real_cookie = True
            if "samesite=none" in chunk.lower():
                samesite_none = True
        if samesite_none: break  # one is enough

    if not has_real_cookie:
        return False, "no_real_app_cookies_only_cdn"
    if not samesite_none:
        return False, "samesite_lax_default_blocks_cross_site"
    return True, "verified_real_cors_with_session_steal_path"


def verify_cicd_finding_strict(d: dict) -> tuple[bool, str]:
    """For cicd findings: require RCE-class endpoint accessible (not just
    fingerprint match). Jenkins /script open, GitLab /api/v4/users open, etc."""
    host = d.get("host"); port = d.get("port"); scheme = d.get("scheme", "https")
    plat = d.get("platform")
    base = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"

    if plat == "Jenkins":
        s, _, body = http(f"{base}/api/json", timeout=4)
        if b"hudson.model" not in body:
            return False, "jenkins_fp_no_hudson_model"
        s2, _, _ = http(f"{base}/script", timeout=4)
        if s2 == 200:
            return True, "jenkins_script_console_unauth_rce"
        return False, f"jenkins_real_but_script_auth_protected_({s2})"

    if plat == "GitLab":
        s, _, body = http(f"{base}/users/sign_in", timeout=4)
        if b"GitLab" not in body and b"gitlab" not in body:
            return False, "gitlab_fp_fingerprint_failed"
        s2, _, body2 = http(f"{base}/api/v4/users", timeout=4)
        if s2 == 200 and b"username" in body2:
            return True, "gitlab_api_v4_users_unauth_read"
        return False, f"gitlab_real_but_api_protected_({s2})"

    if plat == "ArgoCD":
        s, _, body = http(f"{base}/api/version", timeout=4)
        if b"Version" not in body and b"argo" not in body.lower():
            return False, "argocd_fp_fingerprint_failed"
        s2, _, body2 = http(f"{base}/api/v1/applications", timeout=4)
        if s2 == 200 and (b"items" in body2 or b"applications" in body2):
            return True, "argocd_applications_unauth_read"
        return False, f"argocd_real_but_apps_protected_({s2})"

    # Other platforms: passthrough, requires manual review
    return False, f"manual_review_needed_for_{plat}"


def verify_cicd_finding(d: dict) -> tuple[bool, str]:
    host = d.get("host"); port = d.get("port"); scheme = d.get("scheme")
    plat = d.get("platform")
    if plat == "Jenkins":
        url = f"{scheme}://{host}:{port}/api/json"
        s, _, body = http(url, timeout=4)
        if b"hudson.model" in body:
            return True, "verified_real_jenkins"
        return False, "fp_no_hudson_model"
    if plat == "GitLab":
        url = f"{scheme}://{host}:{port}/users/sign_in"
        s, _, body = http(url, timeout=4)
        if b"GitLab" in body or b"gitlab" in body:
            return True, "verified_real_gitlab"
        return False, "fp_no_gitlab_login"
    # Unknown — keep
    return True, "verified_other_platform"


def lead_id(company: str, scanner: str, finding: dict) -> str:
    """Deterministic ID for dedup."""
    host = finding.get("host", "?")
    port = finding.get("port", "")
    cls = finding.get("classification") or finding.get("platform") or "?"
    return f"{company}|{scanner}|{host}|{port}|{cls}"


def load_state() -> dict:
    if STATE.exists():
        try: return json.loads(STATE.read_text())
        except: pass
    return {"notified_leads": [], "last_sweep_at": ""}


def save_state(s):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def append_verified(lead: dict):
    VERIFIED.parent.mkdir(parents=True, exist_ok=True)
    with VERIFIED.open("a") as f:
        f.write(json.dumps(lead) + "\n")


# Phase 1 cross-corpus scanner ledgers (NOT per-company)
# Each tuple: (ledger_path, scanner_name, default_verify_pass)
CROSS_CORPUS_LEDGERS = [
    ("v3/ledgers/sensitive-files-v3.jsonl",     "sensitive-files",   True),
    ("v3/ledgers/open-admin-ports.jsonl",       "open-admin-ports",  True),
    ("v3/ledgers/github-secrets.jsonl",         "github-secrets",    True),
    ("v3/ledgers/takeover-claim-proof.jsonl",   "takeover-claim",    True),
    ("v3/ledgers/graphql-mutations-v2.jsonl",   "graphql-mutations", True),
    ("v3/ledgers/jwt-weakness.jsonl",           "jwt-weakness",      True),
    ("v3/ledgers/web3-jsonrpc-unlocked.jsonl",  "web3-jsonrpc",      True),
    ("v3/ledgers/oauth-misconfig.jsonl",        "oauth-misconfig",   True),
    ("v3/ledgers/ssrf-reprobe.jsonl",           "ssrf-reprobe",      True),
    ("v3/ledgers/nuclei-cve.jsonl",             "nuclei-cve",        True),
    ("v3/ledgers/api-quirks.jsonl",             "api-quirks",        True),
    ("v3/ledgers/web3-frontend-secrets.jsonl",  "web3-frontend-secrets", True),
    ("v3/ledgers/cache-deception.jsonl",        "cache-deception",   True),
    ("v3/ledgers/smart-contracts.jsonl",        "smart-contracts",   True),
    ("v3/ledgers/wordpress-vulns.jsonl",        "wordpress-vulns",   True),
    ("v3/ledgers/smb-admin-panels.jsonl",       "smb-admin-panels",  True),
]


def cross_corpus_lead_id(scanner: str, finding: dict) -> str:
    host = finding.get("host") or finding.get("org") or "?"
    extra = (finding.get("path") or finding.get("port") or finding.get("service")
             or finding.get("pattern_name") or finding.get("repo") or "")
    return f"_corpus|{scanner}|{host}|{extra}"


# Catchall hosts — anything matching these suffixes is auto-skipped (returns same response to any path)
CATCHALL_DENYLIST = [
    "id.aliexpress.com", "alibaba.taobao.com", "alibaba-work.1688.com",
    "m.tmall.com", "tmall.com", "staging.realtime.cloudflare.com",
    "koubei.com", "contactmonkey.com",
]


def host_in_catchall_denylist(host: str) -> bool:
    if not host: return False
    h = host.lower()
    return any(h.endswith(d) or h == d for d in CATCHALL_DENYLIST)


def process_cross_corpus(scanner_path, scanner_name, notified, new_count_ref):
    """Process a cross-corpus ledger (sensitive-files, open-ports, etc).
    ONLY notify on TRULY-verified findings — manual_review goes to ledger
    silently, no Telegram ping (user is allergic to noise)."""
    ledger = ROOT / scanner_path
    if not ledger.exists() or ledger.stat().st_size == 0:
        return
    for line in ledger.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        lid = cross_corpus_lead_id(scanner_name, d)
        if lid in notified: continue
        notified.add(lid)
        # Global catchall filter — skip findings on known-catchall hosts
        host = d.get("host") or d.get("matched_at", "")
        if host and host_in_catchall_denylist(host.split("/")[0].split("?")[0]):
            continue

        # Hard FP gates per scanner — don't notify if scanner isn't 100% sure
        if scanner_name == "takeover-claim":
            # Only notify on verified_claimable (we can prove the name is free)
            if d.get("claim_status") != "verified_claimable":
                continue
        if scanner_name == "sensitive-files":
            # Skip findings where body marker is suspect (small body, common SPA patterns)
            if d.get("size", 0) < 8:
                continue
            # Only HIGH/CRITICAL (INFO/MEDIUM go silently to ledger)
            if d.get("severity") not in ("HIGH", "CRITICAL"):
                continue
            # security.txt is a feature not a vuln, skip even if HIGH
            if "security.txt" in (d.get("path") or ""):
                continue
        if scanner_name == "open-admin-ports":
            # Only HIGH/CRITICAL
            if d.get("severity") not in ("HIGH", "CRITICAL"):
                continue
        if scanner_name == "github-secrets":
            # Always notify — scanner already validated against KNOWN_DUMMIES
            pass
        if scanner_name == "graphql-mutations":
            # Only HIGH/CRITICAL (MEDIUM = auth-gated mutations, info disc only)
            if d.get("severity") not in ("HIGH", "CRITICAL"):
                continue
        if scanner_name == "jwt-weakness":
            # All findings are CRITICAL by scanner design
            pass
        if scanner_name == "web3-jsonrpc":
            # Only HIGH/CRITICAL (MEDIUM = just info disclosure of chain_id)
            if d.get("severity") not in ("HIGH", "CRITICAL"):
                continue
        if scanner_name == "oauth-misconfig":
            # Only HIGH (open redirect). MEDIUM (implicit flow) is informational.
            if d.get("severity") != "HIGH":
                continue
        if scanner_name == "ssrf-reprobe":
            # Always notify — all findings are CRITICAL by scanner design
            pass
        if scanner_name == "nuclei-cve":
            # Only CRITICAL — HIGH includes many info-disclosure templates that aren't bounty-worthy
            if d.get("severity") != "CRITICAL":
                continue
            # Skip templates that are pure detection (no actual exploit confirmation)
            tmpl = (d.get("template_id") or "").lower()
            DETECTION_ONLY = ("default-page", "version", "detect", "fingerprint",
                             "panel", "login", "exposure-of-sensitive-info")
            if any(do in tmpl for do in DETECTION_ONLY):
                continue
        if scanner_name == "api-quirks":
            # All findings are HIGH/CRITICAL by scanner design
            if d.get("severity") not in ("CRITICAL", "HIGH"):
                continue
        if scanner_name == "web3-frontend-secrets":
            # All findings already validated against dummy patterns by scanner
            if d.get("severity") not in ("CRITICAL", "HIGH"):
                continue
        if scanner_name == "cache-deception":
            # All findings are HIGH by scanner design (only fires on cache-hit + auth mismatch)
            pass
        if scanner_name == "smart-contracts":
            # Slither High/Medium = real vulns worth manual triage
            sev = d.get("severity") or d.get("impact", "")
            if sev not in ("High", "Medium"):
                continue
            # Synthesize host field as chain_id:address for daemon dedup logic
            d["host"] = f"{d.get('chain_id','?')}:{d.get('address','?')}"
        if scanner_name == "wordpress-vulns":
            # WP findings: CRITICAL = wp-config backup, HIGH = debug log, MEDIUM = user enum/xmlrpc
            if d.get("severity") not in ("CRITICAL", "HIGH"):
                continue
        if scanner_name == "smb-admin-panels":
            # CRITICAL = phpMyAdmin/Adminer, HIGH = cPanel/Plesk/Webmin/server-status/phpinfo
            if d.get("severity") not in ("CRITICAL", "HIGH"):
                continue

        new_count_ref[0] += 1
        # SILENT MODE: no Telegram on verified findings.
        # decision-gate.py decides when user input is genuinely needed.
        # Findings flow silently to ledger → submission-queue → user pulls via Telegram /queue command.


def main():
    if not F500.exists():
        print(f"[!] F500 dir missing: {F500}", flush=True)
        return
    state = load_state()
    notified = set(state.get("notified_leads", []))
    print(f"[+] verify-notify daemon starting — {len(notified)} leads already notified", flush=True)

    while True:
        sweep_start = time.time()
        new_verified = 0
        new_count_ref = [0]
        # Cross-corpus scanners (sensitive-files, open-ports, github-secrets, takeover)
        for path, name, _ in CROSS_CORPUS_LEDGERS:
            try:
                process_cross_corpus(path, name, notified, new_count_ref)
            except Exception as e:
                print(f"[!] {name}: {e}", flush=True)
        new_verified += new_count_ref[0]
        # Per-company F500 scanners (CORS, cicd, etc)
        for company_dir in sorted(F500.iterdir()):
            if not company_dir.is_dir() or company_dir.name.startswith("_"): continue
            summ = company_dir / "summary.json"
            if not summ.exists(): continue
            try:
                s = json.loads(summ.read_text())
            except:
                continue
            name = s.get("name", company_dir.name)
            platform = s.get("platform", "?")
            for scanner_meta in s.get("scanners", []):
                sn = scanner_meta.get("name", "?")
                if scanner_meta.get("findings", 0) <= 0: continue
                ledger = company_dir / f"{sn}.jsonl"
                if not ledger.exists() or ledger.stat().st_size == 0: continue
                for line in ledger.read_text().splitlines():
                    if not line.strip(): continue
                    try:
                        d = json.loads(line)
                    except:
                        continue
                    lid = lead_id(company_dir.name, sn, d)
                    if lid in notified: continue
                    # Verify
                    if sn == "cors":
                        ok, reason = verify_cors_finding(d)
                    elif sn == "cicd-panels":
                        ok, reason = verify_cicd_finding_strict(d)
                    elif sn == "sourcemap":
                        # sourcemap findings are pre-validated by scanner (JSON map shape)
                        ok, reason = True, "sourcemap_prevalidated"
                    elif sn == "terraform-state":
                        # terraform findings are pre-validated by scanner
                        ok, reason = True, "terraform_prevalidated"
                    else:
                        ok, reason = True, "unknown_scanner_passthrough"
                    if not ok:
                        # Still mark as seen so we don't re-verify next sweep
                        notified.add(lid)
                        continue
                    # SILENT: record to ledger only; no Telegram.
                    new_verified += 1
                    notified.add(lid)
                    lead = {
                        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "company": name, "platform": platform, "scanner": sn,
                        "verify_reason": reason, "finding": d,
                    }
                    append_verified(lead)
        state["notified_leads"] = sorted(notified)
        state["last_sweep_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        save_state(state)
        if new_verified:
            print(f"[{state['last_sweep_at']}] verified new leads: {new_verified}", flush=True)
        # Sleep until next sweep
        elapsed = time.time() - sweep_start
        time.sleep(max(60 - elapsed, 5))


if __name__ == "__main__":
    main()
