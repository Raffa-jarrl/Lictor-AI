#!/usr/bin/env python3
"""
bounty-matcher — match Lictor findings against bug-bounty programs.

For each disclosure we've sent (~/.lictor/disclosures.jsonl), determine:
  - Is the repo owned by a company with a bug-bounty program?
  - Which platform (HackerOne / Bugcrowd / Intigriti / direct VDP)?
  - Estimated payout range
  - Submission template

Three sources for program directories:
  1. HackerOne public directory (https://hackerone.com/opportunities/all)
  2. Bugcrowd public list (https://bugcrowd.com/programs)
  3. Static curated list of direct VDPs (Stripe, Anthropic, OpenAI, etc.)

Output: docs/launch/bounty-queue-YYYY-MM-DD.md ranked by expected payout.
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

LOG = Path.home() / ".lictor" / "disclosures.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"bounty-queue-{datetime.now().strftime('%Y-%m-%d')}.md"
UA = "Lictor-BountyMatcher/0.1 (+https://lictor-ai.com)"

# Curated direct-VDP list — companies that pay for vuln reports outside H1/BC
DIRECT_VDP = {
    "anthropic":   {"url": "https://anthropic.com/responsible-disclosure", "min": 100, "max": 25000, "channel": "direct"},
    "openai":      {"url": "https://bugcrowd.com/openai", "min": 200, "max": 20000, "channel": "bugcrowd"},
    "stripe":      {"url": "https://hackerone.com/stripe", "min": 500, "max": 100000, "channel": "hackerone"},
    "cloudflare":  {"url": "https://hackerone.com/cloudflare", "min": 100, "max": 30000, "channel": "hackerone"},
    "github":      {"url": "https://bounty.github.com", "min": 617, "max": 30000, "channel": "direct"},
    "google":      {"url": "https://bughunters.google.com", "min": 100, "max": 100000, "channel": "direct"},
    "supabase":    {"url": "https://supabase.com/.well-known/security.txt", "min": 100, "max": 5000, "channel": "direct"},
    "vercel":      {"url": "https://vercel.com/security", "min": 100, "max": 5000, "channel": "direct"},
    "netlify":     {"url": "https://www.netlify.com/security", "min": 0, "max": 0, "channel": "direct-vdp"},
    "hashicorp":   {"url": "https://hackerone.com/hashicorp", "min": 100, "max": 5000, "channel": "hackerone"},
    "twilio":      {"url": "https://bugcrowd.com/twilio", "min": 100, "max": 10000, "channel": "bugcrowd"},
    "sendgrid":    {"url": "https://sendgrid.com/.well-known/security.txt", "min": 0, "max": 5000, "channel": "direct"},
    "mailchimp":   {"url": "https://intercom.com/security", "min": 100, "max": 5000, "channel": "intigriti"},
    "ibm":         {"url": "https://hackerone.com/ibm", "min": 100, "max": 5000, "channel": "hackerone"},
    "microsoft":   {"url": "https://msrc.microsoft.com/", "min": 500, "max": 250000, "channel": "direct"},
    "shopify":     {"url": "https://hackerone.com/shopify", "min": 500, "max": 25000, "channel": "hackerone"},
    "discord":     {"url": "https://hackerone.com/discord", "min": 100, "max": 5000, "channel": "hackerone"},
    "atlassian":   {"url": "https://bugcrowd.com/atlassian", "min": 100, "max": 15000, "channel": "bugcrowd"},
    "snyk":        {"url": "https://snyk.io/policies/responsible-disclosure", "min": 0, "max": 5000, "channel": "direct"},
    "elastic":     {"url": "https://www.elastic.co/community/security", "min": 100, "max": 5000, "channel": "direct"},
    "mongodb":     {"url": "https://www.mongodb.com/security", "min": 100, "max": 5000, "channel": "direct"},
    "datadog":     {"url": "https://www.datadoghq.com/security", "min": 100, "max": 5000, "channel": "direct"},
    "1password":   {"url": "https://bugcrowd.com/agilebits", "min": 100, "max": 25000, "channel": "bugcrowd"},
}

# Heuristic: extract company name from repo owner
def owner_to_company(owner: str) -> str:
    """Normalize org names to bounty-program keys."""
    o = owner.lower()
    # Direct matches
    for key in DIRECT_VDP:
        if key in o:
            return key
    # Common aliases
    aliases = {
        "google-": "google", "googleapis": "google", "firebase": "google",
        "anthropics": "anthropic", "msft": "microsoft", "azure": "microsoft",
        "aws-": "amazon", "amazon-": "amazon",
        "stripe-": "stripe", "cloudflare-": "cloudflare",
    }
    for prefix, target in aliases.items():
        if o.startswith(prefix) or prefix.rstrip("-") == o:
            return target
    return ""


def load_findings():
    if not LOG.exists(): return []
    rows = []
    for line in LOG.read_text().splitlines():
        if not line.strip(): continue
        try:
            rows.append(json.loads(line))
        except: pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-fixed", action="store_true",
                    help="Include already-fixed findings (still bounty-eligible if reported within window)")
    args = ap.parse_args()

    rows = load_findings()
    print(f"[+] loaded {len(rows)} findings from log")

    matches = []
    for r in rows:
        repo = r.get("repo", "")
        if "/" not in repo: continue
        owner = repo.split("/")[0]
        company = owner_to_company(owner)
        if not company: continue
        vdp = DIRECT_VDP.get(company, {})
        # Skip already-fixed unless flag set
        if not args.include_fixed and r.get("fix_method"): continue
        matches.append({
            "repo": repo,
            "company": company,
            "class": r.get("class", ""),
            "issue_url": r.get("issue_url", ""),
            "channel": vdp.get("channel", "unknown"),
            "program_url": vdp.get("url", ""),
            "min_payout": vdp.get("min", 0),
            "max_payout": vdp.get("max", 0),
            "expected": (vdp.get("min", 0) + vdp.get("max", 0)) // 2,
            "fixed": bool(r.get("fix_method")),
        })

    matches.sort(key=lambda x: -x["expected"])

    md = [f"# Bounty queue — {datetime.now().strftime('%Y-%m-%d')}\n",
          f"**Findings scanned:** {len(rows)}",
          f"**Matched to bounty programs:** {len(matches)}",
          f"**Expected payout (sum of midpoints):** ${sum(m['expected'] for m in matches):,}\n",
          "## Submit-now queue (sorted by expected $)\n",
          "| Expected | Min–Max | Channel | Company | Class | Repo | Issue |",
          "|---|---|---|---|---|---|---|"]
    for m in matches:
        md.append(f"| **${m['expected']:,}** | ${m['min_payout']:,}–${m['max_payout']:,} | {m['channel']} | "
                  f"{m['company']} | {m['class']} | `{m['repo']}` | [link]({m['issue_url']}) |")

    if not matches:
        md.append("\n_No matches in this run. Most findings are in customer repos, not company-owned. "
                  "Bounty-eligible findings are ones where the LEAKING repo is owned by the company "
                  "that operates the leaked service (e.g., a Stripe-owned repo leaking a Stripe key)._\n")
        md.append("\n## Pivot: third-party leak channels\n")
        md.append("Most of our findings are 'customer X leaked vendor Y's key.' For those:\n")
        md.append("- **Stripe Secret Scanner Partnership** auto-revokes some; we don't get paid but the user benefits\n")
        md.append("- **Direct outreach to the LEAKING company** (not the vendor) is the bounty path — if customer X has their own bounty program, our finding qualifies under 'leaked credentials in source'\n")
        md.append("- Run `bounty-matcher.py --scan-customer-bounties` (TODO) to cross-ref repo owners against H1/BC public directory\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md))
    print(f"[+] wrote {OUT}")
    print(f"    {len(matches)} matches · expected ${sum(m['expected'] for m in matches):,}")


if __name__ == "__main__":
    main()
