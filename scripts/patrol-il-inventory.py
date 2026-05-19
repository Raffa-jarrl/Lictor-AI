#!/usr/bin/env python3
"""
patrol-il-inventory — scan IL projects from our existing GitHub inventory.

crt.sh times out on broad .co.il queries (too much CT data). Instead, we
scan the 380-repo IL inventory we already collected, focusing on the ~39
that have deployed homepages.

Uses lictor-il-priority for sector + IL boost ordering.
"""
from __future__ import annotations
import sys, time, importlib.util
from pathlib import Path
from datetime import datetime

HERE = Path(__file__).parent
INVENTORY = Path.home() / "Lictor" / "docs" / "launch" / "github-co-il-inventory.tsv"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"patrol-il-inventory-{datetime.now().strftime('%Y-%m-%d')}.md"

# Load pilot scanner
spec = importlib.util.spec_from_file_location("pilot", HERE / "patrol-pilot.py")
pilot = importlib.util.module_from_spec(spec); sys.modules["pilot"] = pilot
spec.loader.exec_module(pilot)

# Load IL priority module
spec2 = importlib.util.spec_from_file_location("ilp", HERE / "lictor-il-priority.py")
ilp = importlib.util.module_from_spec(spec2); sys.modules["ilp"] = ilp
spec2.loader.exec_module(ilp)


def load_inventory():
    rows = []
    if not INVENTORY.exists():
        print(f"!! missing {INVENTORY}", flush=True); return rows
    for line in INVENTORY.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 2: continue
        repo, url = parts[0], parts[1]
        stars = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        pushed = parts[3] if len(parts) > 3 else ""
        if url.startswith("http"):
            rows.append({"full_name": repo, "repo": repo,
                         "repo_url": f"https://github.com/{repo}",
                         "homepage": url, "platform_hint": "github-il",
                         "stargazers_count": stars, "pushed_at": pushed})
    return rows


def main():
    rows = load_inventory()
    print(f"[+] {len(rows)} IL repos with URLs in inventory", flush=True)

    # Score + sort by priority
    for r in rows:
        r["priority"] = ilp.disclosure_priority(r["full_name"], r["homepage"], r["stargazers_count"])
        r["il"] = ilp.is_il_target(r["full_name"], r["homepage"])
        r["sector"] = ilp.sector_score(r["full_name"], r["homepage"])
    rows.sort(key=lambda x: -x["priority"])

    print(f"[+] top 5 by priority:")
    for r in rows[:5]:
        print(f"  pri={r['priority']:>3}  sec={r['sector']:>2}  il={r['il']}  {r['full_name']}  {r['homepage']}")

    print(f"\n[+] scanning top {min(40, len(rows))}...", flush=True)
    results = []
    for i, r in enumerate(rows[:40], 1):
        print(f"  [{i}/{min(40,len(rows))}] {r['full_name'][:50]:<50}", end="", flush=True)
        try:
            sr = pilot.scan_one(r)
            results.append((r, sr))
            crits = sum(1 for f in sr.findings if f.severity in ("critical","high"))
            print(f"  grade={sr.grade}  crit/high={crits}", flush=True)
        except Exception as e:
            print(f"  EXC: {str(e)[:80]}", flush=True)
        time.sleep(1.2)

    # Write report
    md = [f"# IL inventory patrol — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n",
          f"**Inventory:** {len(rows)} IL repos with URLs · **Scanned:** {len(results)}",
          f"**Worth contacting (grade ≤ C):** {sum(1 for r,s in results if s.grade in ('C','D','F'))}\n",
          "| Pri | Repo | URL | Grade | Crit/High | Sector |",
          "|---|---|---|---|---|---|"]
    for r, s in sorted(results, key=lambda x: (x[1].grade, -x[0]["priority"])):
        crits = sum(1 for f in s.findings if f.severity in ("critical","high"))
        md.append(f"| {r['priority']} | `{r['full_name']}` | {r['homepage']} | **{s.grade}** | {crits} | {r['sector']} |")

    OUT.write_text("\n".join(md))
    print(f"\n[+] wrote {OUT}")


if __name__ == "__main__":
    main()
