#!/usr/bin/env python3
"""
protection-gate — enforces the Lictor Submission Constitution as code.

Reads each finding before it becomes a draft. Applies rules 1–10 from
LICTOR-SUBMISSION-RULES.md. Findings that fail any gate are marked
BLOCKED with a reason. Findings that pass are marked APPROVED_FOR_DRAFT.

This sits BETWEEN verify-and-notify and submission-queue-builder so
nothing reaches the draft stage without passing the constitution.

Rule enforcement:
  R1 (human gate)          — n/a, this is automated; the human gate is the
                             actual send action which decision-gate already
                             routes through Telegram approval
  R2 (token redaction)     — for github-secrets findings, ensure ledger
                             entries only contain prefix, not full token
  R3 (PoC template)        — pass-through to submission-queue-builder,
                             which enforces the 6-section template
  R4 (AI fingerprint)      — pass-through, draft template avoids banned phrases
  R5 (FP gauntlet)         — already enforced by verify-and-notify daemon
  R6 (reputation tracker)  — read program-reputation.jsonl; block if
                             program has 2+ N/A closes in 30d
  R7 (disclosure ethics)   — block if finding contains evidence of
                             extracted data (e.g. body_preview > 500 chars
                             of user data)
  R8 (anonymization)       — n/a until public archive publish step
  R9 (drafts ledger)       — log every approval/block decision
  R10 (when in doubt)      — flag AMBIGUOUS findings for human review

Output ledger: v3/ledgers/protection-gate.jsonl
"""
from __future__ import annotations
import json, time, sys, os
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Canonical FP knowledge base (single source of truth — scripts/lictor_fp.py)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lictor_fp import classify_finding_fp

ROOT = Path("/Users/raffa/Lictor")
VERIFIED = ROOT / "v3" / "ledgers" / "verified-f500-leads.jsonl"
REPUTATION = ROOT / "v3" / "ledgers" / "program-reputation.jsonl"
GATE_OUT = ROOT / "v3" / "ledgers" / "protection-gate.jsonl"
STATE = ROOT / "v3" / "ledgers" / "protection-gate-state.json"
DISCLOSURES = ROOT / "v3" / "ledgers" / "disclosures-sent.jsonl"
# Human-verified takeover allowlist. Raffa adds hosts here AFTER personally
# confirming the takeover is exploitable today. Format: one host per line.
# Added 2026-05-27 per principle: "only if they are 100% sure valid security
# issue we are not here to make noise we here to solve the problem"
TAKEOVER_HUMAN_VERIFIED = ROOT / "v3" / "ledgers" / "takeover-human-verified.txt"

# Tier-1 takeover services (must match patrol-takeover-claim-proof.py).
# Other services auto-block in protection-gate even if they reach this stage.
TAKEOVER_TIER1 = {
    "AWS_S3", "GitHub_Pages", "Heroku", "Surge",
    "Webflow", "Cargo", "Azure_WebApp", "Netlify",
}

# Customer-resource subdomain patterns — finding where the SCAN TARGET HOST itself
# matches these is OUT OF SCOPE for the provider's bug-bounty program. The provider
# (DigitalOcean, AWS, Heroku, etc.) hosts CUSTOMER content under these subdomains,
# so any bug is the customer's fault, not the provider's. Submitting such findings
# wastes triager time and damages our reputation (Constitution Rule 6).
#
# Added 2026-05-27 after DigitalOcean N/A from @neho (Intigriti) explicitly cited
# "*.digitaloceanspaces.com — Customers' resources are hosted underneath this
# domain, so the entire domain should be considered out-of-scope."
#
# NOTE: This is for SCAN TARGETS. If a customer's own subdomain (e.g.
# victim.com) CNAMEs to one of these (e.g. abandoned-app.azurewebsites.net),
# that's still a valid takeover against victim.com — the protection-gate
# only blocks if the scan-target HOST itself matches.
# Platform-level soft-defers. After a triager closes N/N of our recent
# submissions on the same platform, route around them for a window. If a
# finding's platform matches a key here and today is before the date, BLOCK.
# After the date passes, the entry is ignored (set new dates as needed).
PLATFORM_SOFT_DEFER = {
    # 2026-05-28: lennaert closed 2/2 of our Intigriti submissions today
    # (coca-cola + wpengine). Pausing Intigriti submissions for 7 days so
    # his attention rotates and we don't burn the platform's trust.
    "intigriti": "2026-06-04T00:00:00+00:00",
}

CUSTOMER_RESOURCE_HOST_PATTERNS = [
    # AWS
    "s3.amazonaws.com", "s3-website", ".cloudfront.net",
    # Azure
    ".blob.core.windows.net",
    # DigitalOcean (today's trigger)
    ".digitaloceanspaces.com",
    # Google Cloud customer apps
    ".appspot.com", ".firebaseapp.com", ".web.app",
    # Heroku customer apps
    ".herokuapp.com",
    # Cloudflare customer
    ".workers.dev", ".pages.dev",
    # Vercel / Netlify customer apps
    ".vercel.app", ".netlify.app",
    # Other PaaS customer
    ".glitch.me", ".replit.app", ".repl.co",
    ".fly.dev", ".up.railway.app",
    ".azurewebsites.net",          # customer Azure WebApps
    ".onrender.com",
    ".pythonanywhere.com",
]


def load_state():
    if STATE.exists():
        try: return json.loads(STATE.read_text())
        except: pass
    return {"processed_keys": []}


def save_state(s):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def load_program_reputation() -> dict:
    """Build {program: {n_a, accepted, paid, last_close_reason, last_30d_n_a}}"""
    rep = {}
    if not REPUTATION.exists(): return rep
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    for line in REPUTATION.read_text().splitlines():
        if not line.strip(): continue
        try: d = json.loads(line)
        except: continue
        prog = d.get("program", "?")
        if prog not in rep:
            rep[prog] = {"n_a": 0, "accepted": 0, "paid": 0,
                         "n_a_30d": 0, "last_close_reason": ""}
        r = rep[prog]
        status = d.get("status", "")
        if status == "n_a":
            r["n_a"] += 1
            try:
                ts = datetime.fromisoformat(d.get("ts","").replace("Z","+00:00"))
                if ts >= cutoff:
                    r["n_a_30d"] += 1
            except: pass
        elif status == "accepted": r["accepted"] += 1
        elif status == "paid": r["paid"] += 1
        if d.get("close_reason"): r["last_close_reason"] = d["close_reason"]
    return rep


def evidence_contains_user_data(d: dict) -> bool:
    """Rule 7: block if body_preview shows extracted user PII."""
    finding = d.get("finding") or d
    preview = (finding.get("body_preview") or "")[:2000]
    proof = (finding.get("proof") or "")[:2000]
    blob = (preview + proof).lower()
    # Indicators of extracted personal data
    PII_RED_FLAGS = [
        "@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com",
        "credit_card", "ssn", "social_security",
        "passport", "national_id", "teudat_zehut",
    ]
    return any(flag in blob for flag in PII_RED_FLAGS)


def github_secret_full_token_check(d: dict) -> bool:
    """Rule 2: github-secrets entries must have prefix only, not full token."""
    if d.get("scanner") != "github-secrets": return True  # n/a
    finding = d.get("finding") or d
    prefix = finding.get("matched_value_prefix", "")
    # Prefix should be ≤ 14 chars per rule
    if len(prefix) > 16:
        return False  # token leaking via prefix field
    # Check the full record doesn't contain a longer token
    blob = json.dumps(d)
    import re
    SECRET_PATTERNS = [
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36,}",
        r"ghs_[A-Za-z0-9]{36,}",
        r"sk_live_[A-Za-z0-9]{20,}",
        r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}",
    ]
    for p in SECRET_PATTERNS:
        if re.search(p, blob):
            return False  # full token in record — protection violation
    return True


def reputation_gate(d: dict, rep: dict) -> tuple[bool, str]:
    """Rule 6: block if program has 2+ N/A in last 30d."""
    prog = d.get("company") or d.get("platform") or "?"
    pr = rep.get(prog, {})
    if pr.get("n_a_30d", 0) >= 2:
        return False, f"R6: program {prog} has {pr['n_a_30d']} N/A closes in last 30d — manual review required"
    return True, ""


def platform_defer_gate(d: dict) -> tuple[bool, str]:
    """Soft-defer a whole platform until the date in PLATFORM_SOFT_DEFER passes.
    Used when one triager closes multiple of our submissions in a short window
    and we need to let the queue rotate before resubmitting."""
    platform = (d.get("platform") or "").lower()
    if not platform: return True, ""
    until = PLATFORM_SOFT_DEFER.get(platform)
    if not until: return True, ""
    try:
        until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) < until_dt:
            return False, f"R6-platform-defer: platform '{platform}' soft-deferred until {until} (triager fatigue / recent N/As)"
    except: pass
    return True, ""


def customer_resource_gate(d: dict) -> tuple[bool, str]:
    """Cross-cutting block: if the scan target host is a customer-resource
    subdomain (shared-tenancy provider infra), the finding belongs to the
    customer, not the provider. Submitting it as a bug against the provider's
    program is scope abuse.
    Per principle: 'only if 100% sure valid security issue.'"""
    finding = d.get("finding") or d
    host = (finding.get("host") or "").lower()
    if not host: return True, ""
    for pat in CUSTOMER_RESOURCE_HOST_PATTERNS:
        if pat in host:
            return False, f"R7-customer-resource: host '{host}' is on shared customer-resource infra ('{pat}') — out of scope for the provider's program"
    return True, ""


def takeover_human_verified_set() -> set[str]:
    """Read the allowlist of hosts Raffa has personally confirmed takeoverable."""
    if not TAKEOVER_HUMAN_VERIFIED.exists(): return set()
    return {l.strip().lower() for l in TAKEOVER_HUMAN_VERIFIED.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")}


def takeover_100pct_gate(d: dict, verified_hosts: set[str]) -> tuple[bool, str]:
    """Takeover findings are now ABSOLUTE INTERNAL-ONLY.

    Why: between 2026-05-26 and 2026-05-28, Intigriti triagers closed 3/3 of
    our takeover submissions (here, coca-cola, wpengine) with the same core
    reason — "dangling CNAME without actual takeover demonstrated is out of
    scope." Constitution Rule 7 (HEAD-only, never claim) prevents us from
    meeting the active-claim-PoC bar that bounty programs now require.

    The scanner still runs (for internal research, cross-correlation with
    other scanners, future Lictor Studio DNS-hygiene product), but NO
    takeover finding ever reaches a submission queue. The human-verified
    allowlist mechanism is retired — there is no path to submission.
    """
    scanner = d.get("scanner", "")
    if scanner != "takeover-claim-proof": return True, ""  # n/a for other scanners
    return False, (
        "R7-takeover: ALL takeover-claim findings are INTERNAL-ONLY since 2026-05-28. "
        "Constitution Rule 7 (HEAD-only) + market signal (3/3 N/A from Intigriti in 2 weeks) "
        "make submission ethically and reputationally untenable. Use for internal research only."
    )


def apply_gates(d: dict, rep: dict, verified_hosts: set[str]) -> tuple[str, list[str]]:
    """Returns (verdict, reasons). verdict ∈ {APPROVED_FOR_DRAFT, BLOCKED, MANUAL_REVIEW}"""
    reasons = []

    # FP knowledge base (lictor_fp.py) — unified false-positive gate covering all
    # 19 documented FP classes. Runs first; a confirmed FP is a hard block.
    finding_view = dict(d)
    finding_view.update(d.get("finding") or {})
    finding_view.setdefault("scanner", d.get("scanner", ""))
    is_fp, fp_reason = classify_finding_fp(finding_view)
    if is_fp:
        reasons.append(f"FP_CLASS: {fp_reason}  [HARD BLOCK — lictor_fp]")

    # R2: secret protection
    if not github_secret_full_token_check(d):
        reasons.append("R2_VIOLATION: full secret/token in ledger record (must be prefix only)")

    # R7: PII / extracted-data check
    if evidence_contains_user_data(d):
        reasons.append("R7_VIOLATION: evidence contains user PII — disclosure ethics breach")

    # R6: reputation gate
    rep_ok, rep_reason = reputation_gate(d, rep)
    if not rep_ok:
        reasons.append(rep_reason)

    # R7-takeover: 100% human-verified requirement (codified 2026-05-27 per
    # principle "only if they are 100% sure valid security issue").
    tk_ok, tk_reason = takeover_100pct_gate(d, verified_hosts)
    if not tk_ok:
        reasons.append(tk_reason + "  [HARD BLOCK]")

    # R7-customer-resource: cross-cutting block for findings on shared
    # customer-resource infra (digitaloceanspaces.com, herokuapp.com, etc.).
    # Added 2026-05-27 after DigitalOcean N/A from neho (Intigriti).
    cr_ok, cr_reason = customer_resource_gate(d)
    if not cr_ok:
        reasons.append(cr_reason + "  [HARD BLOCK]")

    # R6-platform-defer: pause whole platforms when triager fatigue is real.
    # Added 2026-05-28 after lennaert closed 2/2 Intigriti submissions same day.
    pd_ok, pd_reason = platform_defer_gate(d)
    if not pd_ok:
        reasons.append(pd_reason + "  [HARD BLOCK]")

    # R10: ambiguous findings
    sev = (d.get("finding") or d).get("severity", "")
    if sev in ("LOW", "INFO"):
        reasons.append("R10: severity below MEDIUM — likely not bounty-worthy")

    # Verdict
    if any("VIOLATION" in r or "HARD BLOCK" in r for r in reasons):
        return "BLOCKED", reasons
    if reasons:
        return "MANUAL_REVIEW", reasons
    return "APPROVED_FOR_DRAFT", []


def lead_key(d: dict) -> str:
    f = d.get("finding") or d
    return f"{d.get('scanner','?')}|{d.get('company','?')}|{f.get('host', f.get('org','?'))}"


def main():
    print(f"[+] protection-gate starting", flush=True)
    state = load_state()
    processed = set(state.get("processed_keys", []))
    while True:
        if not VERIFIED.exists():
            time.sleep(60); continue
        rep = load_program_reputation()
        verified_hosts = takeover_human_verified_set()
        n_approved = n_blocked = n_review = 0
        for line in VERIFIED.read_text().splitlines():
            if not line.strip(): continue
            try: d = json.loads(line)
            except: continue
            key = lead_key(d)
            if key in processed: continue
            verdict, reasons = apply_gates(d, rep, verified_hosts)
            processed.add(key)
            with GATE_OUT.open("a") as f:
                f.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "key": key,
                    "verdict": verdict,
                    "reasons": reasons,
                    "scanner": d.get("scanner"),
                    "company": d.get("company"),
                    "host": (d.get("finding") or d).get("host","?"),
                }) + "\n")
            if verdict == "APPROVED_FOR_DRAFT": n_approved += 1
            elif verdict == "BLOCKED": n_blocked += 1
            else: n_review += 1
        state["processed_keys"] = sorted(processed)
        save_state(state)
        if n_approved or n_blocked or n_review:
            print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] approved={n_approved} blocked={n_blocked} manual_review={n_review}", flush=True)
        time.sleep(180)  # 3 min


if __name__ == "__main__":
    main()
