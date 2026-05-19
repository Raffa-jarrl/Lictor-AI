#!/usr/bin/env python3
"""
scan-il-npm-repos — scan the 199 npm-discovered IL repos for secrets.

For each IL repo (from expand-il-inventory.py output), run repo-scoped
GitHub code searches for:
  - Firebase service-account JSON (private_key_id)
  - Stripe LIVE keys (sk_live_)
  - DB connection strings with creds (postgres://user:pass@)
  - AWS access keys (AKIA)

Hits get flagged with IL priority boost (+15) and queued for disclosure
via the standard lictor-hourly rotation.
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

HERE = Path(__file__).parent
INVENTORY = Path.home() / "Lictor" / "docs" / "launch" / f"il-inventory-expanded-{datetime.now().strftime('%Y-%m-%d')}.tsv"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"scan-il-npm-{datetime.now().strftime('%Y-%m-%d')}-private.md"

# Reuse patterns from existing patrols
PATTERNS = {
    "firebase":  ('"private_key_id"',                    re.compile(r'"private_key_id":\s*"[a-f0-9]{40}"')),
    "stripe":    ('sk_' + 'live_',                       re.compile(r'\bsk_live_[A-Za-z0-9]{24,99}\b')),
    "db-creds":  ('postgres://',                         re.compile(r'(postgres|mysql|mongodb)(\+srv)?://[^:\s/]+:[^@\s]+@')),
    "aws":       ('AKIA',                                re.compile(r'\bAKIA[A-Z0-9]{16}\b')),
}

PLACEHOLDER_RX = re.compile(r'(example|sample|placeholder|REPLACE|XXX+|TODO|FAKE|your_|YOUR_|<.{1,30}>)', re.IGNORECASE)


def load_il_repos():
    if not INVENTORY.exists():
        print(f"!! missing {INVENTORY}", file=sys.stderr); return []
    repos = set()
    for line in INVENTORY.read_text().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 2: continue
        ident = parts[0]
        # Only keep github-format owner/name
        if "/" in ident and "." not in ident.split("/")[0]:
            repos.add(ident)
    return sorted(repos)


def gh_code_search_in_repo(repo, literal, timeout=15):
    try:
        out = subprocess.check_output(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={literal} repo:{repo}", "-f", "per_page=10",
             "--jq", "[.items[] | {path: .path, url: .html_url}]"],
            stderr=subprocess.DEVNULL, timeout=timeout)
        return json.loads(out)
    except Exception:
        return []


def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=12)
        return base64.b64decode(out.decode().strip().replace("\n", "")).decode("utf-8", "replace")
    except Exception:
        return None


def verify(repo, path, regex):
    content = gh_raw_file(repo, path)
    if not content: return None
    m = regex.search(content)
    if not m: return None
    # Context check
    start = m.start()
    ctx = content[max(0, start-100):min(len(content), start+200)]
    if PLACEHOLDER_RX.search(ctx): return None
    return m.group(0)[:60]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=199)
    args = ap.parse_args()

    repos = load_il_repos()[:args.max_repos]
    print(f"[+] scanning {len(repos)} IL repos for {len(PATTERNS)} secret classes...", flush=True)

    hits = []
    for i, repo in enumerate(repos, 1):
        print(f"  [{i}/{len(repos)}] {repo:<50}", end="", flush=True)
        repo_hits = []
        for class_name, (literal, regex) in PATTERNS.items():
            items = gh_code_search_in_repo(repo, literal)
            time.sleep(2.2)  # rate-limit
            for it in items:
                path = it["path"]
                # Skip obvious noise
                if re.search(r'(/tests?/|/__tests__/|/spec/|/fixtures?/|/docs?/|README|\.md$|node_modules|sample|dummy|fake|mock)', path, re.IGNORECASE):
                    continue
                redacted = verify(repo, path, regex)
                if redacted:
                    repo_hits.append({"class": class_name, "path": path, "url": it["url"],
                                       "redacted": redacted[:8] + "…" + redacted[-4:] if len(redacted) > 16 else redacted})
                    break  # one hit per class per repo
            time.sleep(0.5)
        if repo_hits:
            for h in repo_hits:
                h["repo"] = repo
                hits.append(h)
            classes = ",".join(h["class"] for h in repo_hits)
            print(f"  🔴 {classes}", flush=True)
        else:
            print("  ⚪", flush=True)

    # Write report
    md = [f"# IL npm-corpus scan — {datetime.now().strftime('%Y-%m-%d %H:%M')} (PRIVATE)\n",
          f"**IL repos scanned:** {len(repos)}",
          f"**Exposures found:** {len(hits)}",
          f"  by class: " + ", ".join(f"{c}={sum(1 for h in hits if h['class']==c)}" for c in PATTERNS) + "\n",
          "| Repo | Class | Path | Match | Link |",
          "|---|---|---|---|---|"]
    for h in hits:
        md.append(f"| `{h['repo']}` | {h['class']} | `{h['path']}` | `{h['redacted']}` | [link]({h['url']}) |")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md))
    print(f"\n[+] wrote {OUT}")
    print(f"    {len(hits)} exposures across {len(set(h['repo'] for h in hits))} unique IL repos")


if __name__ == "__main__":
    main()
