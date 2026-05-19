#!/usr/bin/env python3
"""
disclose-priority — re-sort the disclosure queue so highest-impact targets fire first.

Today the cron + drain pick candidates by "most recently pushed". That treats
a 0-star student repo the same as a 5000-star CNCF project. Better: weight by

  impact_score = (star_score) + (sector_score) + (fork_score) - (age_penalty)

where:
  star_score    = log10(stars + 1) * 5    [0★ → 0, 100★ → 10, 5000★ → 19]
  sector_score  = 10 if banking/healthcare/government
                = 7  if infra/ai-feature
                = 3  if consumer
                = 0  otherwise
  fork_score    = log10(forks + 1) * 2
  age_penalty   = days_since_push / 30    [0 for fresh, 12 for 1yr old]

Run this BEFORE drain to re-order the private MDs. The cron + drain then
naturally pick the most impactful candidates first.

Usage:
  python3 scripts/disclose-priority.py            # report current ranking
  python3 scripts/disclose-priority.py --rewrite  # actually re-sort the MDs

Cron: 0 */6 * * *  (between scanner refresh and hourly cron)
"""
from __future__ import annotations
import argparse, json, math, re, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
LICTOR_DIR = Path.home() / "Lictor"
UA = "Lictor-Priority/0.1 (+https://lictorai.com)"

SECTOR_RX = {
    "banking-healthcare-gov": re.compile(r'\b(bank|finance|fintech|payment|wallet|health|hospital|medical|patient|gov|government|election|voting)\b', re.IGNORECASE),
    "infra-ai": re.compile(r'\b(cncf|kubernetes|k8s|terraform|ansible|operator|controller|cluster|llm|agent|rag|embedding|prompt)\b', re.IGNORECASE),
    "consumer": re.compile(r'\b(chat|social|messaging|dating|sharing|booking|delivery|ride|marketplace|user|customer)\b', re.IGNORECASE),
}


def gh_repo_meta(repo):
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}",
            headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:
        return None


def detect_sector(meta):
    if not meta: return None
    text = " ".join([
        meta.get("name", "") or "",
        meta.get("description", "") or "",
        " ".join(meta.get("topics", []) or []),
    ])
    for sector, rx in SECTOR_RX.items():
        if rx.search(text): return sector
    return None


def score_repo(repo):
    meta = gh_repo_meta(repo)
    if not meta: return 0, "no-meta"
    stars = meta.get("stargazers_count", 0)
    forks = meta.get("forks_count", 0)
    pushed = (meta.get("pushed_at", "") or "")[:10]
    sector = detect_sector(meta)

    star_score = math.log10(stars + 1) * 5
    fork_score = math.log10(forks + 1) * 2
    sector_score = {"banking-healthcare-gov": 10, "infra-ai": 7, "consumer": 3}.get(sector, 0)

    # Age penalty
    age_penalty = 0
    if pushed:
        try:
            d = datetime.fromisoformat(pushed)
            days = (datetime.now() - d).days
            age_penalty = days / 30
        except Exception:
            pass

    total = star_score + fork_score + sector_score - age_penalty
    breakdown = f"★{stars}={star_score:.1f} forks{forks}={fork_score:.1f} {sector or 'no-sector'}={sector_score} age={-age_penalty:.1f}"
    return total, breakdown


def parse_private_md(md_path):
    """Yield raw lines + extracted repo name (or None) for each line."""
    if not md_path.exists(): return
    for line in md_path.read_text().splitlines():
        m = re.match(r"\| `([^`]+)`", line)
        yield line, (m.group(1) if m else None)


def cmd_report():
    """Show current rank for top candidates in each private MD."""
    for md_glob in [
        "docs/launch/patrol-firebase-private.md",
        "docs/launch/patrol-db-creds-private.md",
        "docs/launch/patrol-prtarget-private-*.md",
        "docs/launch/patrol-saas-*-private.md",
        "docs/launch/patrol-cloudkeys-*-private.md",
    ]:
        for md in LICTOR_DIR.glob(md_glob):
            print(f"\n=== {md.name} ===")
            scored = []
            for line, repo in parse_private_md(md):
                if not repo: continue
                if repo in [s[2] for s in scored]: continue  # dedup
                total, breakdown = score_repo(repo)
                scored.append((total, breakdown, repo, line))
            scored.sort(key=lambda x: -x[0])
            for total, breakdown, repo, _ in scored[:10]:
                print(f"  {total:5.1f}  {repo:50s}  {breakdown}")


def cmd_rewrite():
    """Re-order private MD files by impact score."""
    for md_glob in [
        "docs/launch/patrol-firebase-private.md",
        "docs/launch/patrol-db-creds-private.md",
        "docs/launch/patrol-prtarget-private-*.md",
        "docs/launch/patrol-saas-*-private.md",
        "docs/launch/patrol-cloudkeys-*-private.md",
    ]:
        for md in LICTOR_DIR.glob(md_glob):
            text = md.read_text()
            lines = text.splitlines()
            # Find header + body
            header = []
            data_rows = []
            for i, line in enumerate(lines):
                m = re.match(r"\| `([^`]+)`", line)
                if m:
                    data_rows.append((line, m.group(1)))
                else:
                    header.append(line)
            if not data_rows: continue

            # Score each
            print(f"\n=== rewriting {md.name} ({len(data_rows)} rows) ===")
            scored = []
            seen_repos = set()
            for line, repo in data_rows:
                if repo in seen_repos: continue
                seen_repos.add(repo)
                total, _ = score_repo(repo)
                scored.append((total, line, repo))
            scored.sort(key=lambda x: -x[0])

            # Rewrite: header + sorted data rows
            new_text = "\n".join(header) + "\n" + "\n".join(s[1] for s in scored) + "\n"
            md.write_text(new_text)
            print(f"  wrote {len(scored)} rows, top: {scored[0][2] if scored else '?'} (score {scored[0][0]:.1f})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rewrite", action="store_true", help="Actually re-sort the MD files")
    args = ap.parse_args()
    if args.rewrite:
        cmd_rewrite()
    else:
        cmd_report()


if __name__ == "__main__":
    main()
