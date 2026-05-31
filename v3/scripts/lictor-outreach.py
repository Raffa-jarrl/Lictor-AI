#!/usr/bin/env python3
"""Lictor outreach-email generator — turns scan findings into personalized SMB CISO outreach.

For a target domain:
1. Mines all 16 Lictor ledgers for findings matching that domain
2. Picks the TOP 3 most impressive findings (by severity + brand impact)
3. Generates a personalized cold-outreach email body
4. Generates a personalized warm-intro email body (if introducer is provided)

Usage:
    lictor-outreach.py <domain> [--name "First Name"] [--company "Acme Corp"] [--from-intro "Mutual Friend"]

Output: prints both cold + warm email drafts ready to paste into Gmail.
"""
import sys, json, re
from pathlib import Path
from collections import defaultdict

LEDGER_DIR = Path.home() / "Lictor" / "v3" / "ledgers"

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}
# Categories ordered by "wow factor" for outreach (high-impact + visceral first)
CATEGORY_WOW = {
    "ransomware-exposure": 10,   # most visceral — "RDP exposed to internet"
    "git-exposure": 9,            # source code leak
    "wallet-file": 9,             # crypto wallet
    "cloud-blob": 8,              # public bucket
    "exposed-sourcemap": 7,       # reveals internal code
    "graphql-introspection-enabled": 6,
    "exposed-panel": 6,
    "tls-audit": 5,
    "email-auth": 4,
    "info-leak": 3,
}


def host_matches(host_field, target):
    if not host_field: return False
    h = host_field.lower().strip()
    t = target.lower().strip()
    return h == t or h.endswith("." + t) or t in h


def load_findings(target):
    findings = []
    if not LEDGER_DIR.exists(): return findings
    for ledger_file in LEDGER_DIR.glob("*.jsonl"):
        try:
            for line in ledger_file.read_text().splitlines():
                if not line.strip(): continue
                try: e = json.loads(line)
                except: continue
                host_field = e.get("host") or e.get("apex") or e.get("bucket") or e.get("repo")
                if not host_matches(host_field, target): continue
                e["_source_ledger"] = ledger_file.stem
                findings.append(e)
        except: continue
    return findings


def pick_top_findings(findings, limit=3):
    """Score each finding by severity × category-wow, return top N."""
    scored = []
    for f in findings:
        cat = f.get("type") or f.get("_source_ledger", "")
        canonical = next((k for k in CATEGORY_WOW if k in cat), cat)
        wow = CATEGORY_WOW.get(canonical, 1)
        # Severity: use nested findings max severity if applicable
        sev = (f.get("severity") or "low").lower()
        if "findings" in f and isinstance(f["findings"], list):
            max_sub = max((SEVERITY_RANK.get((s.get("severity") or "low").lower(), 1) for s in f["findings"]), default=1)
            sev_rank = max_sub
        else:
            sev_rank = SEVERITY_RANK.get(sev, 1)
        score = wow * sev_rank
        scored.append((score, f, canonical))
    scored.sort(key=lambda x: -x[0])
    return scored[:limit]


def render_finding_one_liner(f, cat):
    """Render a finding as a single short line for the email body."""
    host = f.get("host", "?")
    path = f.get("path", "")
    if cat == "ransomware-exposure":
        crit_findings = [sub for sub in f.get("findings", []) if (sub.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
        if crit_findings:
            issue = crit_findings[0].get("issue", "").split(" — ")[0]
            return f"{host} — {issue}"
        return f"{host} — risky service exposed externally"
    if cat == "exposed-sourcemap":
        url = f.get("url", "") or path
        # Extract just the .js.map filename if URL is long
        if url and "/" in url:
            display = ".../" + url.rsplit("/", 1)[-1]
        else:
            display = url or path
        return f"{host} → {display} (your frontend source code .js.map publicly downloadable)"
    if cat == "git-exposure":
        return f"{host}/.git/ — your full source repository is publicly readable"
    if cat == "email-auth":
        issues = [sub.get("issue", "") for sub in f.get("findings", []) if "missing" in sub.get("issue", "").lower() or "weak" in sub.get("issue", "").lower()]
        if issues:
            return f"{host} — {issues[0][:90]}"
        return f"{host} — email authentication gap"
    if cat == "tls-audit":
        issues = [sub for sub in f.get("findings", []) if (sub.get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM")]
        if issues:
            return f"{host}:443 — {issues[0].get('issue', '')[:90]}"
        return f"{host} — TLS posture issues"
    if cat == "graphql-introspection-enabled":
        tc = f.get("type_count", "?")
        return f"{host}{path} — GraphQL introspection enabled in production ({tc} schema types exposed)"
    if cat == "wallet-file":
        return f"{host}{path} — wallet/keystore file publicly accessible (size {f.get('content_length','?')} bytes)"
    if cat == "cloud-blob":
        return f"{host} — public cloud bucket listable without authentication"
    return f"{host}{path} — {cat}"


def render_cold_email(target, findings, name=None, company=None):
    top = pick_top_findings(findings, limit=3)
    company_name = company or target.split(".")[0].title()
    name_greeting = f"Hi {name}," if name else "Hi,"

    if not top:
        body = f"""{name_greeting}

I'm Raffa, founder of Lictor — open-source security scanner that's been
disclosing findings to companies in your industry this month.

I ran our scanner against {target}'s external perimeter and the good news:
no critical issues surfaced in this pass. That's rare — most domains we scan
have at least one HIGH-severity issue.

What I'm building: SMB-priced ($7K-15K/yr) version of what Tenable charges
$40K-$100K for. Continuous external scanning, plus disclosure-coordination
when we find an issue on a vendor of yours.

If continuous monitoring would be useful, I'd love a 20-minute call to walk
through what an ongoing program looks like for {company_name}.

— Raffa
   raffajarrl@gmail.com / https://lictor-ai.com/business
"""
    else:
        findings_text = "\n".join(f"  • {render_finding_one_liner(f, cat)}" for score, f, cat in top)
        # Severity tally
        sev_count = defaultdict(int)
        for f in findings:
            if "findings" in f and isinstance(f["findings"], list):
                for sub in f["findings"]:
                    sev_count[(sub.get("severity") or "info").upper()] += 1
            else:
                sev_count[(f.get("severity") or "info").upper()] += 1
        sev_summary = ", ".join(f"{n} {s}" for s, n in sev_count.items() if n > 0)

        body = f"""{name_greeting}

I'm Raffa, founder of Lictor — open-source security scanner that's been
disclosing findings to companies in your industry this month (90+ disclosures
in May including major bank, $7B DeFi protocol, and 5 GCS buckets with
regulated customer data).

Quick context: I ran our scanner against {target} this week. Top findings:

{findings_text}

({sev_summary} total)

Not pitching — this is yours to fix regardless. Want the full PDF report?
Reply "send it" and I'll email the 5-page breakdown with remediation guidance
mapped to SOC 2 / ISO 27001 / PCI-DSS controls.

What I'm building: SMB-priced version of what Tenable charges $40K-$100K for.
Continuous external scanning, plus we handle disclosure-coordination when we
find an issue on a vendor of yours.

Worth a 20-min call this week? I'll walk through these findings + what
ongoing monitoring looks like for {company_name}.

— Raffa
   raffajarrl@gmail.com / https://lictor-ai.com/business
   PS: Skip the call if you want — reply "send report" and I'll attach the PDF.
"""
    return body


def render_warm_email(target, findings, name=None, company=None, introducer=None):
    top = pick_top_findings(findings, limit=2)
    company_name = company or target.split(".")[0].title()
    name_greeting = f"Hi {name}," if name else "Hi,"
    intro_line = f"Thanks to {introducer} for the intro.\n\n" if introducer else ""

    if not top:
        findings_text = "Your perimeter looks clean in our initial scan — that's rare and means whoever's running your security is doing it well."
    else:
        findings_text = "Quick context — I ran our scanner against your perimeter:\n\n" + \
                       "\n".join(f"  • {render_finding_one_liner(f, cat)}" for score, f, cat in top) + \
                       "\n\n(Happy to send the full PDF report if useful.)"

    body = f"""{name_greeting}

{intro_line}I'm Raffa, founder of Lictor — the open-source security scanner
I've been running. 90+ disclosures in May including a $7B DeFi protocol, a
major bank, and 5 GCS buckets with regulated customer data.

{findings_text}

Building the SMB-priced version now (Lictor for Business — same engine, on
a schedule, with disclosure-coordination when we find issues on your vendors).
Looking for 10-15 design partners — Year 1 free in exchange for a quarterly
30-min feedback call.

Interest level on a 20-min call? I'll walk through findings + what ongoing
monitoring looks like for {company_name}. No sales deck — just your scan
results.

— Raffa
   https://lictor-ai.com/business
"""
    return body


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    target = sys.argv[1].strip().lower()
    # Parse kwargs
    kwargs = {}
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == "--name" and i+1 < len(sys.argv):
            kwargs["name"] = sys.argv[i+1]
        elif arg == "--company" and i+1 < len(sys.argv):
            kwargs["company"] = sys.argv[i+1]
        elif arg == "--from-intro" and i+1 < len(sys.argv):
            kwargs["introducer"] = sys.argv[i+1]

    findings = load_findings(target)
    print(f"# Lictor outreach email drafts for {target}")
    print(f"# Found {len(findings)} ledger entries matching target\n")

    print("=" * 72)
    print("COLD EMAIL VERSION")
    print("=" * 72)
    print(f"\nSubject: Quick question on {target}'s external attack surface\n")
    print(render_cold_email(target, findings, kwargs.get("name"), kwargs.get("company")))

    print("\n" + "=" * 72)
    print("WARM EMAIL VERSION (if you have a mutual intro)")
    print("=" * 72)
    print(f"\nSubject: Lictor security scan — quick findings for {kwargs.get('company') or target.split('.')[0].title()}\n")
    print(render_warm_email(target, findings, kwargs.get("name"), kwargs.get("company"), kwargs.get("introducer")))


if __name__ == "__main__":
    main()
