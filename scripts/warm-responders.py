#!/usr/bin/env python3
"""
warm-responders — scan our filed issues for positive replies, rank by warmth.

Reads ~/.lictor/disclosures.jsonl, fetches comments on each issue via gh,
classifies tone, emits a markdown punch list of people to thank +
suggested ask (star / share / both / nothing).
"""
from __future__ import annotations
import json, re, subprocess, sys, time
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

LOG = Path.home() / ".lictor" / "disclosures.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"warm-responders-{datetime.now().strftime('%Y-%m-%d')}.md"

WARM_RX = re.compile(r"\b(thank(s| you)|appreciate|grateful|good (catch|find|work)|nice (work|catch)|helpful|kind|fixed|patched|rotated|will (look|fix|patch|address)|on it|merged|resolved)\b", re.I)
COLD_RX = re.compile(r"\b(spam|slop|fuck|shit|annoying|low.?quality|chatgpt|ai.?generated|ai.?slop)\b", re.I)

def gh_issue_comments(repo, num):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/issues/{num}/comments",
             "--jq", "[.[] | {user: .user.login, body: .body, created_at: .created_at}]"],
            stderr=subprocess.DEVNULL, timeout=15)
        return json.loads(out)
    except Exception:
        return []

def gh_issue_state(repo, num):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/issues/{num}", "--jq", ".state"],
            stderr=subprocess.DEVNULL, timeout=10)
        return out.decode().strip().strip('"')
    except Exception:
        return "?"

def main():
    if not LOG.exists():
        print(f"no log at {LOG}", file=sys.stderr); sys.exit(1)
    rows = [json.loads(l) for l in LOG.read_text().splitlines() if l.strip()]
    # Dedupe by (repo, issue#)
    seen = {}
    for r in rows:
        url = r.get("issue_url") or r.get("url") or ""
        m = re.search(r"github\.com/([^/]+/[^/]+)/issues/(\d+)", url)
        if not m: continue
        seen[(m.group(1), m.group(2))] = r
    print(f"[+] {len(seen)} unique issues, scanning comments...", file=sys.stderr)

    warm, cold, neutral = [], [], []
    for i, ((repo, num), r) in enumerate(sorted(seen.items()), 1):
        if i % 10 == 0: print(f"  [{i}/{len(seen)}]", file=sys.stderr)
        comments = gh_issue_comments(repo, num)
        time.sleep(0.3)
        if not comments: continue
        # Take non-our comments
        ours = {"Raffa-jarrl", "lictor-bot", "lictor-ai"}
        others = [c for c in comments if c["user"] not in ours]
        if not others: continue
        for c in others:
            body = c["body"][:500]
            warmth = len(WARM_RX.findall(body)) - 2 * len(COLD_RX.findall(body))
            entry = {"repo": repo, "num": num, "user": c["user"],
                     "snippet": re.sub(r"\s+", " ", body)[:160],
                     "created": c["created_at"][:10], "warmth": warmth,
                     "url": f"https://github.com/{repo}/issues/{num}#issuecomment"}
            if warmth >= 1: warm.append(entry)
            elif warmth <= -1: cold.append(entry)
            else: neutral.append(entry)

    warm.sort(key=lambda x: -x["warmth"])
    md = [f"# Warm responders — {datetime.now().strftime('%Y-%m-%d')}\n",
          f"Scanned {len(seen)} disclosures. Warm: {len(warm)} · Neutral: {len(neutral)} · Cold: {len(cold)}\n",
          "## Warm (thank + ask for star/share)\n",
          "| User | Repo | Warmth | Snippet | Link |",
          "|---|---|---|---|---|"]
    for e in warm:
        md.append(f"| @{e['user']} | `{e['repo']}` | {e['warmth']} | {e['snippet']!r} | [#{e['num']}]({e['url']}) |")
    md.append("\n## Neutral (review manually)\n")
    md.append("| User | Repo | Snippet | Link |")
    md.append("|---|---|---|---|")
    for e in neutral:
        md.append(f"| @{e['user']} | `{e['repo']}` | {e['snippet']!r} | [#{e['num']}]({e['url']}) |")
    md.append("\n## Cold (do NOT contact)\n")
    md.append("| User | Repo | Snippet |")
    md.append("|---|---|---|")
    for e in cold:
        md.append(f"| @{e['user']} | `{e['repo']}` | {e['snippet']!r} |")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md))
    print(f"\n[+] wrote {OUT}")
    print(f"    warm: {len(warm)} | neutral: {len(neutral)} | cold: {len(cold)}")

if __name__ == "__main__":
    main()
