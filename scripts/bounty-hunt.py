#!/usr/bin/env python3
"""
bounty-hunt — point our existing scanner toolkit at company-owned repos
that have bug-bounty programs. Findings IN their code = eligible for $$.

Quick-win strategy:
  - 10 small wins ($50-$500 each = $500-$5K) > 1 big win
  - Scan company-owned orgs for patterns we already detect
  - Output a queue ranked by likely payout + ease of submission

Companies + their bounty orgs (curated):
"""
from __future__ import annotations
import argparse, json, re, subprocess, time
from pathlib import Path
from datetime import datetime

OUT = Path.home() / "Lictor" / "docs" / "launch" / f"bounty-hunt-{datetime.now().strftime('%Y-%m-%d')}-private.md"

# Org → bounty program metadata
# Selected for: (a) public bounty program, (b) accepts repo-source findings,
# (c) decent payout for low/medium severity (which is what we typically find)
COMPANY_ORGS = {
    "github":          {"orgs": ["github", "octokit", "actions", "primer"],          "channel": "direct",     "min": 617,  "max": 30000},
    "microsoft":       {"orgs": ["microsoft", "Azure", "dotnet", "MicrosoftDocs"],   "channel": "direct",     "min": 500,  "max": 250000},
    "google":          {"orgs": ["google", "GoogleCloudPlatform", "googleapis"],     "channel": "direct",     "min": 100,  "max": 100000},
    "shopify":         {"orgs": ["Shopify"],                                          "channel": "hackerone",  "min": 500,  "max": 25000},
    "atlassian":       {"orgs": ["atlassian", "atlassian-labs"],                     "channel": "bugcrowd",   "min": 100,  "max": 15000},
    "discord":         {"orgs": ["discord"],                                          "channel": "hackerone",  "min": 100,  "max": 5000},
    "cloudflare":      {"orgs": ["cloudflare"],                                       "channel": "hackerone",  "min": 100,  "max": 30000},
    "snyk":            {"orgs": ["snyk", "snyk-labs"],                                "channel": "direct",     "min": 0,    "max": 5000},
    "hashicorp":       {"orgs": ["hashicorp"],                                        "channel": "hackerone",  "min": 100,  "max": 5000},
    "elastic":         {"orgs": ["elastic"],                                          "channel": "direct",     "min": 100,  "max": 5000},
    "mongodb":         {"orgs": ["mongodb"],                                          "channel": "direct",     "min": 100,  "max": 5000},
    "vercel":          {"orgs": ["vercel"],                                           "channel": "direct",     "min": 100,  "max": 5000},
    "supabase":        {"orgs": ["supabase"],                                         "channel": "direct",     "min": 100,  "max": 5000},
    "datadog":         {"orgs": ["DataDog"],                                          "channel": "direct",     "min": 100,  "max": 5000},
}

# Patterns we scan for (matches our existing patrol classes)
PATTERNS = {
    "prtarget":  ('"pull_request_target"',                                                "GitHub Actions RCE pattern", 200, 5000),
    "firebase":  ('"private_key_id" "service_account"',                                   "Firebase service-account JSON leak", 500, 10000),
    "db-creds":  ('"postgres://" OR "mysql://" OR "mongodb://" "@" extension:env',        "DB connection string with creds", 200, 3000),
    "aws":       ('"AKIA" "aws_secret_access_key"',                                       "AWS access-key + secret pair", 500, 5000),
    "stripe":    ('"sk_' + 'live_"',                                                      "Stripe LIVE secret key", 500, 10000),
}


def gh_search_in_org(org, query, max_results=10):
    """Code search within a single org."""
    try:
        out = subprocess.check_output(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={query} org:{org}", "-f", f"per_page={max_results}",
             "--jq", "[.items[] | {repo: .repository.full_name, path: .path, url: .html_url}]"],
            stderr=subprocess.DEVNULL, timeout=20)
        return json.loads(out)
    except Exception as e:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--companies", help="Comma-separated list (default: all)")
    ap.add_argument("--patterns", help="Comma-separated patterns (default: all)")
    args = ap.parse_args()

    companies = args.companies.split(",") if args.companies else list(COMPANY_ORGS.keys())
    patterns = args.patterns.split(",") if args.patterns else list(PATTERNS.keys())

    print(f"[+] hunting in {len(companies)} companies × {len(patterns)} patterns...", flush=True)
    print(f"    target: 10 quick wins (~$50-500 each)\n", flush=True)

    findings = []
    for company in companies:
        meta = COMPANY_ORGS[company]
        for org in meta["orgs"]:
            for pname in patterns:
                pat = PATTERNS[pname]
                literal, descr, pat_min, pat_max = pat
                print(f"  scan: {company}/{org} × {pname}", end="", flush=True)
                items = gh_search_in_org(org, literal, max_results=5)
                time.sleep(3)  # rate limit
                if items:
                    for it in items:
                        # Skip obvious noise paths + defense-code patterns we learned from manual triage
                        if re.search(r'(test|fixture|sample|example|docs?/|\.md$|README|CHANGELOG|'
                                     r'validation|validator|scanner|detector|semgrep|secrets?-?scanner|'
                                     r'\.go$|\.rs$|messages\.|event_types|backport|labeler\.yml)',
                                     it["path"], re.IGNORECASE):
                            continue
                        # Skip if path indicates it's library/SDK source defining the string as data
                        if re.search(r'/(types|schema|events|api)/', it["path"], re.IGNORECASE):
                            continue
                        # Expected payout = midpoint of pattern × company multiplier
                        cm = (meta["min"] + meta["max"]) // 2
                        pm = (pat_min + pat_max) // 2
                        expected = min(pm, cm)  # whichever is more conservative
                        findings.append({
                            "company": company, "org": org, "pattern": pname,
                            "repo": it["repo"], "path": it["path"], "url": it["url"],
                            "descr": descr, "expected": expected, "channel": meta["channel"],
                        })
                    print(f"  🔴 {len(items)} hit(s)", flush=True)
                else:
                    print(f"  ⚪", flush=True)

    findings.sort(key=lambda x: -x["expected"])

    md = [f"# Bounty hunt — {datetime.now().strftime('%Y-%m-%d')} (PRIVATE)\n",
          f"**Companies scanned:** {len(companies)} · **Patterns:** {len(patterns)}",
          f"**Findings (pre-verify):** {len(findings)}",
          f"**Expected payout (sum):** ${sum(f['expected'] for f in findings):,}\n",
          "## Submit queue — sorted by expected $\n",
          "_Each finding still needs manual verification before submission. Bounty programs reject false positives and may suspend reporters who submit too many low-quality reports._\n",
          "| Expected | Channel | Company | Pattern | Repo | File |",
          "|---|---|---|---|---|---|"]
    for f in findings:
        md.append(f"| **${f['expected']:,}** | {f['channel']} | {f['company']} | {f['pattern']} | "
                  f"`{f['repo']}` | [{f['path']}]({f['url']}) |")

    if not findings:
        md.append("\n_Clean. These orgs maintain their own credential hygiene._\n")
        md.append("\n**Next steps:**")
        md.append("- Try a larger company list (the orgs above are well-patched)")
        md.append("- Pivot to different patterns: SSRF, IDOR, broken auth in their hosted products")
        md.append("- Look at recent CVEs in their products for variants")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md))
    print(f"\n[+] wrote {OUT}")
    print(f"    {len(findings)} candidate findings · expected ${sum(f['expected'] for f in findings):,}")


if __name__ == "__main__":
    main()
