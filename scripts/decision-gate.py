#!/usr/bin/env python3
"""
decision-gate — the ONLY thing that fires outbound Telegram pings.

Watches verified-leads + submission queue + scanner ledgers. Identifies
situations where USER INPUT IS GENUINELY NEEDED (not just status updates).
For each, generates a 3-option decision request via notify_decision().

Decision triggers (will fire Telegram, ONE per trigger, deduped via ID):

  TRIGGER_RCE_VERIFIED:
    - A Nuclei CRITICAL CVE template fires AND template has 'rce' tag
    - Options: 1) Submit immediately, 2) Verify with manual probe first, 3) Skip
  TRIGGER_SECRET_LEAK_LIVE:
    - github-secrets finding for an AKIA/ghp_/sk_live_ pattern
    - Options: 1) Notify the leaking org (responsible disclosure),
               2) Verify key is live first (NOT EXECUTED - need permission),
               3) Skip
  TRIGGER_TAKEOVER_VERIFIED_CLAIMABLE:
    - takeover-claim with claim_status=verified_claimable
    - Options: 1) Send disclosure to program owner,
               2) Verify claim-ability with a no-op claim attempt,
               3) Skip
  TRIGGER_NEW_BIG_QUEUE:
    - 5+ VERIFIED_REAL drafts accumulate in submission queue (not yet sent)
    - Options: 1) Show me digest now, 2) Batch-send all approved channels,
               3) Wait for 10+

Silent by default — only fires on triggers. User can pull state via /status
/queue /decisions /digest commands.
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")
VERIFIED = ROOT / "v3" / "ledgers" / "verified-f500-leads.jsonl"
QUEUE = ROOT / "v3" / "ledgers" / "submission-queue.jsonl"
NUCLEI = ROOT / "v3" / "ledgers" / "nuclei-cve.jsonl"
GH_SECRETS = ROOT / "v3" / "ledgers" / "github-secrets.jsonl"
TAKEOVER = ROOT / "v3" / "ledgers" / "takeover-claim-proof.jsonl"
DECISIONS = ROOT / "v3" / "ledgers" / "pending-decisions.jsonl"
STATE = ROOT / "v3" / "ledgers" / "decision-gate-state.json"

sys.path.insert(0, str(ROOT / "v3" / "scripts"))
try:
    from notify_telegram import notify_decision
except Exception:
    def notify_decision(*a, **kw): return False


def load_state():
    if STATE.exists():
        try: return json.loads(STATE.read_text())
        except: pass
    return {"fired_decision_ids": [], "last_check_at": ""}


def save_state(s):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def append_decision(d):
    DECISIONS.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS.open("a") as f:
        f.write(json.dumps(d) + "\n")


def fire_decision(decision_id: str, context: str, options: list[str], fired: set):
    if decision_id in fired: return False
    fired.add(decision_id)
    append_decision({
        "id": decision_id,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "context": context,
        "options": options,
        "status": "pending",
    })
    notify_decision(context, options, decision_id=decision_id)
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] FIRED: {decision_id}", flush=True)
    return True


# --- Trigger handlers ---

# Catchall denylist (synced with verify-and-notify-f500.py)
DG_CATCHALL_DENYLIST = [
    "id.aliexpress.com", "alibaba.taobao.com", "alibaba-work.1688.com",
    "m.tmall.com", "tmall.com", "staging.realtime.cloudflare.com",
    "koubei.com", "contactmonkey.com",
]


def host_catchall(host: str) -> bool:
    if not host: return False
    h = str(host).lower()
    # Pull pure host portion from URLs
    if "://" in h: h = h.split("://", 1)[1]
    h = h.split("/")[0].split("?")[0].split(":")[0]
    return any(h.endswith(d) or h == d for d in DG_CATCHALL_DENYLIST)


def check_nuclei_rce(fired: set):
    if not NUCLEI.exists() or NUCLEI.stat().st_size == 0: return
    for line in NUCLEI.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        if d.get("severity") != "CRITICAL": continue
        # Catchall filter
        if host_catchall(d.get("host", "")) or host_catchall(d.get("matched_at", "")):
            continue
        tags = (d.get("raw", {}).get("info", {}).get("tags") or "").lower()
        # Only RCE-class CVEs
        if not any(t in tags for t in ("rce", "command-injection", "code-execution", "deserialization", "ssti")):
            continue
        host = d.get("host", "?")
        tmpl = d.get("template_id", "?")
        decision_id = f"nuclei_rce|{tmpl}|{host}"
        context = (f"🔴 CRITICAL RCE: Nuclei template '{tmpl}' fired on {host}.\n"
                   f"Severity: CRITICAL  Type: {d.get('type','http')}\n"
                   f"Matched: {d.get('matched_at','?')[:100]}")
        fire_decision(decision_id, context, [
            "Submit disclosure draft to program (build draft + queue)",
            "Run safer manual probe first (curl reproduction only)",
            "Skip — looks like FP based on hostname",
        ], fired)


def check_github_secrets(fired: set):
    if not GH_SECRETS.exists() or GH_SECRETS.stat().st_size == 0: return
    for line in GH_SECRETS.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        if d.get("severity") != "CRITICAL": continue
        pattern = d.get("pattern_name", "?")
        repo = d.get("repo", "?")
        path = d.get("path", "?")
        decision_id = f"gh_secret|{pattern}|{repo}|{path}"
        context = (f"🔴 LIVE SECRET: {pattern} found in public GitHub repo.\n"
                   f"Repo: {repo}\n"
                   f"Path: {path}\n"
                   f"Prefix: {d.get('matched_value_prefix','?')}...")
        fire_decision(decision_id, context, [
            "Send responsible-disclosure email to org's security contact",
            "Verify key is live (requires API call — needs your approval)",
            "Skip — pattern matched but might be test fixture I missed",
        ], fired)


# Known-FP suppression for slither: (detector, contract_pattern_in_desc)
# weak-prng + _rpow/rpow = fixed-point math (Maker, Compound, etc.)
SLITHER_KNOWN_FP = [
    ("weak-prng", "_rpow"),
    ("weak-prng", "rpow"),
    ("weak-prng", "rmul"),
    ("weak-prng", "wmul"),
    ("weak-prng", "wpow"),
]


def is_slither_fp(d: dict) -> bool:
    detector = d.get("detector", "")
    desc = d.get("description", "").lower()
    for fp_det, fp_pattern in SLITHER_KNOWN_FP:
        if detector == fp_det and fp_pattern.lower() in desc:
            return True
    return False


def check_smart_contracts(fired: set):
    """Slither High-severity findings on bountied DeFi contracts."""
    SC = ROOT / "v3" / "ledgers" / "smart-contracts.jsonl"
    if not SC.exists() or SC.stat().st_size == 0: return
    for line in SC.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        sev = d.get("severity") or d.get("impact", "")
        if sev != "High": continue
        # FP filter
        if is_slither_fp(d): continue
        addr = d.get("address", "?")
        chain = d.get("chain_id", "?")
        detector = d.get("detector", "?")
        contract = d.get("contract_name", "?")
        decision_id = f"slither|{chain}|{addr}|{detector}|{contract}"
        context = (f"🔴 SLITHER HIGH: {detector} in {contract}\n"
                   f"Chain: {chain}  Address: {addr}\n"
                   f"Description: {d.get('description','?')[:200]}")
        fire_decision(decision_id, context, [
            "Submit immediately to Immunefi (this contract is on a bountied protocol)",
            "Run secondary check with foundry/manual review first",
            "Skip — slither known to FP on this pattern",
        ], fired)


def check_smb_panels(fired: set):
    """phpMyAdmin / Adminer / cPanel / Plesk / Webmin exposures."""
    SP = ROOT / "v3" / "ledgers" / "smb-admin-panels.jsonl"
    if not SP.exists() or SP.stat().st_size == 0: return
    for line in SP.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        if d.get("severity") != "CRITICAL": continue
        host = d.get("host", "?")
        if host_catchall(host): continue
        panel = d.get("panel", "?")
        decision_id = f"smb_panel|{panel}|{host}"
        context = (f"🔴 SMB PANEL EXPOSED: {panel} on {host}\n"
                   f"URL: {d.get('url','?')[:120]}\n"
                   f"Severity: CRITICAL (brute-force or default-creds risk)")
        fire_decision(decision_id, context, [
            "Send disclosure email to the org's security contact + WHOIS abuse address",
            "Verify reachable + capture for portfolio (no exploitation)",
            "Skip — likely intentional public access",
        ], fired)


def check_wp_config_backup(fired: set):
    """wp-config.php.bak / .save with DB credentials exposed."""
    WP = ROOT / "v3" / "ledgers" / "wordpress-vulns.jsonl"
    if not WP.exists() or WP.stat().st_size == 0: return
    for line in WP.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        if d.get("severity") != "CRITICAL": continue
        if d.get("issue") != "wp_config_backup": continue
        host = d.get("host", "?")
        if host_catchall(host): continue
        decision_id = f"wp_config|{host}"
        context = (f"🔴 wp-config BACKUP exposed: {host}\n"
                   f"URL: {d.get('evidence_url','?')}\n"
                   f"Contains DB credentials + WordPress auth keys.")
        fire_decision(decision_id, context, [
            "URGENT: Send disclosure (DB password is exposed right now)",
            "Verify content + queue draft for review first",
            "Skip — host looks like honeypot/test",
        ], fired)


def check_takeover(fired: set):
    if not TAKEOVER.exists() or TAKEOVER.stat().st_size == 0: return
    for line in TAKEOVER.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        if d.get("claim_status") != "verified_claimable": continue
        host = d.get("host", "?")
        service = d.get("service", "?")
        decision_id = f"takeover|{service}|{host}"
        context = (f"🔴 VERIFIED-CLAIMABLE takeover: {host}\n"
                   f"Service: {service}  Severity: {d.get('severity','?')}\n"
                   f"Evidence: {d.get('claim_evidence','?')[:120]}")
        fire_decision(decision_id, context, [
            "Build + send disclosure draft to program",
            "Attempt safe no-op claim to fully confirm (NEEDS your approval)",
            "Skip — domain looks like deliberate test/staging",
        ], fired)


def check_queue_size(fired: set):
    if not QUEUE.exists(): return
    items = [json.loads(l) for l in QUEUE.read_text().splitlines() if l.strip()]
    real = [i for i in items if i.get("status") == "VERIFIED_REAL"]
    n = len(real)
    # Fire when crossing thresholds (5, 10, 25)
    for threshold in (5, 10, 25):
        if n >= threshold:
            decision_id = f"queue_threshold|{threshold}"
            if decision_id in fired: continue
            top_str = ", ".join((r.get("company", "?") + "/" + r.get("scanner", "?")) for r in real[:3])
            context = (f"📋 SUBMISSION QUEUE: {n} VERIFIED_REAL drafts ready.\n"
                       f"Top: {top_str}")
            fire_decision(decision_id, context, [
                "Show me a digest now (one Telegram message)",
                "Batch-send all to channels (HackerOne/Bugcrowd/email) — careful",
                "Wait until queue hits next threshold",
            ], fired)


def main():
    print(f"[+] decision-gate starting at {datetime.now(timezone.utc).isoformat()}", flush=True)
    state = load_state()
    fired = set(state.get("fired_decision_ids", []))
    while True:
        try:
            check_nuclei_rce(fired)
            check_github_secrets(fired)
            check_takeover(fired)
            check_smart_contracts(fired)
            check_smb_panels(fired)
            check_wp_config_backup(fired)
            check_queue_size(fired)
        except Exception as e:
            print(f"[!] check error: {e}", flush=True)
        state["fired_decision_ids"] = sorted(fired)
        state["last_check_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        save_state(state)
        time.sleep(120)  # 2 min between checks (no rush, no noise)


if __name__ == "__main__":
    main()
