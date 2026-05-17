#!/usr/bin/env python3
"""
patrol-bot-tokens — hunt Discord / Slack bot tokens + webhook URLs.

GitHub's secret-scanning catches the well-known prefixes (xoxb-, etc.)
but not all token shapes, not all webhook URLs, and not all wrappers.

Detection:
  - Discord bot token: 24+ chars . 6 chars . 27+ chars (base64-url shape)
  - Discord webhook URL: https://discord(app)?.com/api/webhooks/<id>/<token>
  - Slack bot token: xoxb-<digits>-<digits>-<alnum>
  - Slack webhook URL: https://hooks.slack.com/services/<TEAM>/<APP>/<TOKEN>

For each candidate:
  1. Fetch file
  2. Verify the pattern + surrounding context (avoid false positives in tests/docs)
  3. Filter to fresh repos + skip archived
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DISCORD_BOT_TOKEN_RX = re.compile(r'[MNO][A-Za-z0-9_-]{22,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}')
DISCORD_WEBHOOK_RX = re.compile(r'https?://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,68}')
SLACK_BOT_TOKEN_RX = re.compile(r'xoxb-\d+-\d+-[A-Za-z0-9]{24,32}')
SLACK_WEBHOOK_RX = re.compile(r'https?://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}')
TELEGRAM_BOT_TOKEN_RX = re.compile(r'\b\d{8,11}:[A-Za-z0-9_-]{35}\b')

# Words/patterns suggesting documentation/test (not real)
PLACEHOLDER_CTX = re.compile(r'(YOUR_TOKEN|XXXXX|example|placeholder|REPLACE_ME|\.\.\.\.|test_token)', re.IGNORECASE)

@dataclass
class Hit:
    repo: str
    path: str
    url: str
    kind: str
    redacted: str
    stars: int = 0
    pushed_at: str = ""

def gh_code_search(query, max_pages=2):
    seen, results = set(), []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            results.append(it)
        time.sleep(2)
    return results

def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode("utf-8").strip().replace("\n", "")).decode("utf-8", "replace")
    except Exception:
        return None

def gh_repo_meta(repo):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}", "--jq",
             '{stars: .stargazers_count, pushed_at: .pushed_at, archived: .archived}'],
            stderr=subprocess.DEVNULL, timeout=10)
        return json.loads(out)
    except Exception:
        return {}

def context_around(text, start, window=80):
    return text[max(0, start - window):min(len(text), start + window)]

def verify(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    content = gh_raw_file(repo, path)
    if not content: return None

    hits = []
    for rx, kind in [(DISCORD_BOT_TOKEN_RX, "discord-bot-token"),
                      (DISCORD_WEBHOOK_RX, "discord-webhook"),
                      (SLACK_BOT_TOKEN_RX, "slack-bot-token"),
                      (SLACK_WEBHOOK_RX, "slack-webhook"),
                      (TELEGRAM_BOT_TOKEN_RX, "telegram-bot-token")]:
        for m in rx.finditer(content):
            ctx = context_around(content, m.start())
            if PLACEHOLDER_CTX.search(ctx): continue
            hits.append((kind, m.group(0)))
            break  # one per kind per file is enough signal
    if not hits: return None

    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None
    pushed = meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days:
            return None
    except Exception:
        return None

    kind, val = hits[0]
    return Hit(
        repo=repo, path=path, url=item["html_url"],
        kind=kind,
        redacted=val[:8] + "…" + val[-4:] if len(val) > 14 else val,
        stars=meta.get("stars", 0),
        pushed_at=meta.get("pushed_at", "")[:10],
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=100)
    ap.add_argument("--max-age-days", type=int, default=180)
    ap.add_argument("--private", default="docs/launch/patrol-bot-tokens-private.md")
    ap.add_argument("--public", default="docs/launch/patrol-bot-tokens-aggregate.md")
    args = ap.parse_args()

    queries = [
        '"https://hooks.slack.com/services/"',
        '"https://discord.com/api/webhooks/"',
        '"https://discordapp.com/api/webhooks/"',
        'xoxb-',
        'DISCORD_TOKEN extension:env',
        'TELEGRAM_BOT_TOKEN extension:py',
    ]
    seen, raw = set(), []
    print("[+] Discord/Slack/Telegram token + webhook hunt...")
    for q in queries:
        items = gh_code_search(q, max_pages=2)
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            raw.append(it)
            if len(raw) >= args.max: break
        if len(raw) >= args.max: break

    print(f"[+] {len(raw)} candidates; verifying...")
    hits = []
    for i, it in enumerate(raw, 1):
        repo = it["repository"]["full_name"]
        path = it["path"]
        print(f"  [{i}/{len(raw)}] {repo}/{path}", end="", flush=True)
        try:
            h = verify(it, args.max_age_days)
            if h:
                hits.append(h)
                print(f"  🔴 {h.kind} {h.redacted}  ★{h.stars}")
            else:
                print("  ⚪")
        except Exception as e:
            print(f"  EXC: {e}")
        time.sleep(1.2)

    md = ["# Patrol — Discord/Slack/Telegram bot-token exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Method:** Code search for token/webhook patterns, raw-file verify, placeholder filter.\n",
          f"## Confirmed bot tokens / webhooks in public source: {len(hits)}\n",
          "| Repo | Path | Stars | Kind | Token (redacted) | File |",
          "|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: -x.stars):
        md.append(f"| `{h.repo}` | `{h.path}` | {h.stars} | {h.kind} | `{h.redacted}` | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))

    pm = [f"# Patrol — bot token aggregate\n",
          f"**Run:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
          f"## Aggregate\n",
          f"- Candidates inspected: **{len(raw)}**",
          f"- Confirmed bot tokens/webhooks in public source: **{len(hits)}**"]
    Path(args.public).write_text("\n".join(pm))

    print(f"\n[+] Done. {len(hits)} confirmed bot token/webhook exposures.")

if __name__ == "__main__":
    main()
