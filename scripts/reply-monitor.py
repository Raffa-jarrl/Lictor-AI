#!/usr/bin/env python3
"""
reply-monitor — watches every issue I opened, alerts on new comments.

Runs via cron every 15 min. Polls /repos/{owner}/{name}/issues/{n}/comments
for each issue I authored. New comments (since last check) get logged + a
macOS notification fires + a daily digest is appended to ~/.lictor/replies/.

State at ~/.lictor/reply-monitor-state.json — tracks last-seen comment id per issue.
"""
from __future__ import annotations
import argparse, json, subprocess, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
STATE_FILE = Path.home() / ".lictor" / "reply-monitor-state.json"
LOG_FILE = Path.home() / ".lictor" / "replies.log"
DIGEST_DIR = Path.home() / ".lictor" / "replies"
DIGEST_DIR.mkdir(exist_ok=True)
STATE_FILE.parent.mkdir(exist_ok=True)


def log(msg):
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def http_json(url):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "lictor-reply-monitor/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        log(f"  http err: {url} → {e}")
        return None


def list_my_issues():
    """Pull all open + recently-updated issues I authored."""
    issues = []
    for page in range(1, 4):
        data = http_json(f"https://api.github.com/search/issues?q=author:Raffa-jarrl+sort:updated-desc&per_page=100&page={page}")
        if not data: break
        items = data.get("items", [])
        if not items: break
        for it in items:
            parts = it["repository_url"].split("/")
            issues.append({
                "repo": parts[-2] + "/" + parts[-1],
                "number": it["number"],
                "title": it["title"],
                "state": it["state"],
                "updated_at": it["updated_at"],
            })
        if len(items) < 100: break
    return issues


def notify_mac(title, message):
    """Pop a macOS banner. Best-effort, silent fail."""
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "{message}" with title "{title}"'
        ], timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-issues", type=int, default=200, help="Cap issues polled per run")
    ap.add_argument("--quiet", action="store_true", help="No macOS notification")
    args = ap.parse_args()

    log(f"=== reply-monitor start ===")
    state = {}
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())

    issues = list_my_issues()
    log(f"issues to poll: {len(issues)}")

    new_comments = []  # list of (repo, num, title, comment_dict)
    polled = 0
    for it in issues[:args.max_issues]:
        polled += 1
        # Skip closed issues if not updated recently (no new replies expected)
        key = f"{it['repo']}#{it['number']}"
        last_seen = state.get(key, 0)
        comments_url = f"https://api.github.com/repos/{it['repo']}/issues/{it['number']}/comments?per_page=20"
        comments = http_json(comments_url)
        if not comments: continue
        for c in comments:
            cid = c.get("id", 0)
            if cid <= last_seen: continue
            # Filter: skip my own comments (when I retract/follow-up)
            if c.get("user", {}).get("login") == "Raffa-jarrl": continue
            new_comments.append((it["repo"], it["number"], it["title"], c))
            state[key] = max(state.get(key, 0), cid)
        # Always update state even if no new comments — so we don't recheck old
        if comments and not state.get(key):
            state[key] = max((c.get("id", 0) for c in comments), default=0)
        time.sleep(0.15)  # be polite

    STATE_FILE.write_text(json.dumps(state, indent=2))

    if not new_comments:
        log(f"polled {polled}, no new comments")
        return

    log(f"🔔 {len(new_comments)} NEW comment(s) on Lictor disclosures:")
    today = datetime.now().strftime("%Y-%m-%d")
    digest_path = DIGEST_DIR / f"replies-{today}.md"
    with open(digest_path, "a") as df:
        for repo, num, title, c in new_comments:
            who = c.get("user", {}).get("login", "?")
            body_preview = (c.get("body", "") or "")[:300].replace("\n", " ")
            html_url = c.get("html_url", "")
            log(f"  • {repo}#{num} ← @{who}: {body_preview[:100]}")
            df.write(f"\n## {repo}#{num}\n")
            df.write(f"**from @{who}** at {c.get('created_at','?')}\n\n")
            df.write(f"> {body_preview}\n\n")
            df.write(f"Reply here: {html_url}\n")
            df.write(f"Original issue: https://github.com/{repo}/issues/{num}\n")
            df.write(f"---\n")

    if not args.quiet:
        notify_mac("🔔 Lictor replies",
                   f"{len(new_comments)} new reply(s) on disclosure issues. See ~/.lictor/replies/")
    log(f"digest → {digest_path}")


if __name__ == "__main__":
    main()
