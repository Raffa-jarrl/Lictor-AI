#!/usr/bin/env python3
"""
morning-report — runs at 06:00 UTC. Generates the wake-up briefing.

Reads all 3 bounty-hunter ledgers (takeover, web-exposed, hf-leaks)
and produces:
  1. Total counts by scanner
  2. Top findings ranked by severity / $ value
  3. Ready-to-submit drafts for each (channel, target email, body)
  4. A simple "DO THESE TODAY" punch list

Output: docs/launch/morning-report-YYYY-MM-DD.md
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime, timezone, timedelta

LEDGERS = {
    "takeover":    Path.home() / ".lictor" / "subdomain-takeover-ledger.jsonl",
    "web-exposed": Path.home() / ".lictor" / "web-exposed-ledger.jsonl",
    "hf-leaks":    Path.home() / ".lictor" / "hf-leak-ledger.jsonl",
}
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"morning-report-{datetime.now().strftime('%Y-%m-%d')}.md"


def load(path):
    if not path.exists(): return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            try: rows.append(json.loads(line))
            except: pass
    return rows


def severity_score(entry, scanner):
    """Higher = more urgent. Used for ranking."""
    if scanner == "takeover":
        # All takeovers are high — but Vercel/Netlify takeover is cleanest to exploit
        return {"Vercel": 90, "Netlify": 85, "GitHub Pages": 80, "Heroku": 80,
                "AWS/S3": 95, "Fly.io": 75, "Render": 75}.get(entry.get("provider",""), 60)
    if scanner == "web-exposed":
        return {"CRIT": 95, "HIGH": 75, "MED": 50, "INFO": 20}.get(entry.get("severity",""), 40)
    if scanner == "hf-leaks":
        return {"hf_token": 60, "openai_key": 60, "anthropic_key": 70,
                "aws_akid": 90, "stripe_live": 95, "private_key": 80,
                "github_pat": 75, "slack_token": 65, "google_api": 60}.get(entry.get("pattern",""), 40)
    return 0


def render(scanner, e):
    """One-liner for a finding."""
    if scanner == "takeover":
        return f"{e.get('provider','?'):<14} {e.get('subdomain','?'):<50} → {e.get('cname','?')}"
    if scanner == "web-exposed":
        return f"{e.get('severity','?'):<5} ${e.get('pay',0):>5}  https://{e.get('url','?')}{e.get('path','?')}"
    if scanner == "hf-leaks":
        return f"{e.get('pattern','?'):<14} {e.get('space','?')[:50]}  {e.get('file','?')}  ({e.get('redacted','?')})"
    return str(e)


def submission_target(scanner, e):
    """Where to file this kind of finding."""
    if scanner == "takeover":
        company = e.get("company","").lower()
        return f"security@{company}.com  OR  GHSA at github.com/{company}-ai/{company}/security/advisories/new"
    if scanner == "web-exposed":
        host = e.get("url","")
        apex = ".".join(host.split(".")[-2:])
        return f"security@{apex}  OR  HackerOne/Bugcrowd"
    if scanner == "hf-leaks":
        return "Hugging Face: security@huggingface.co + notify repo owner via HF UI"
    return ""


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    md = [f"# Morning report — {today}\n",
          "## Lictor overnight bounty grind\n"]

    # Counts
    counts = {}
    findings = []
    for scanner, path in LEDGERS.items():
        rows = load(path)
        counts[scanner] = len(rows)
        for r in rows:
            findings.append((scanner, r, severity_score(r, scanner)))

    # Sort by severity desc
    findings.sort(key=lambda x: -x[2])

    md.append("## Totals (all-time ledger)\n")
    md.append(f"- 🌐 **Subdomain takeovers:** {counts['takeover']}")
    md.append(f"- 📂 **Web-exposed files:** {counts['web-exposed']}")
    md.append(f"- 🤗 **HF / npm leaks:** {counts['hf-leaks']}")
    md.append(f"- 🎯 **GRAND TOTAL:** {sum(counts.values())} findings\n")

    if not findings:
        md.append("\n_No findings yet. Cron continues every 30 min._\n")
        OUT.write_text("\n".join(md))
        print(f"[+] wrote {OUT} (no findings)")
        return

    # Submit queue — top 20 by severity
    md.append("## TOP-PRIORITY FINDINGS — submit these today\n")
    md.append("| # | Severity | Scanner | Finding | Submit to |")
    md.append("|---|---|---|---|---|")
    for i, (scanner, e, score) in enumerate(findings[:20], 1):
        md.append(f"| {i} | **{score}** | {scanner} | `{render(scanner, e)}` | {submission_target(scanner, e)} |")

    # Per-scanner detail
    for scanner in LEDGERS:
        section = [(s, e) for s, e, _ in findings if s == scanner]
        if not section: continue
        md.append(f"\n## All {scanner} findings ({len(section)})\n")
        for s, e in section:
            md.append(f"- {render(s, e)}")

    # Action plan
    md.append("\n---\n## Action plan today\n")
    md.append("1. Review top 5 above — pick highest-confidence ones")
    md.append("2. For each: verify is still live (re-fetch URL, re-check DNS)")
    md.append("3. Find the right disclosure channel (security.txt, security@, GHSA, H1/BC)")
    md.append("4. Submit via the channel — keep records in ~/.lictor/submissions/")
    md.append("5. Mark in ledger after submission (`bounty-hunter mark <id> submitted`)\n")

    OUT.write_text("\n".join(md))
    print(f"[+] wrote {OUT}")
    print(f"    {sum(counts.values())} total findings")
    print(f"    top finding score: {findings[0][2] if findings else 0}")


if __name__ == "__main__":
    main()
