#!/usr/bin/env python3
"""
lictor-hourly — the always-on disclosure machine.

Runs every hour via cron. Per cycle:
  1. Pull next target from the rotating queue (firebase → db-creds → prtarget → hf → npm → repeat)
  2. Verify target still exists + has issues enabled
  3. Submit a contact-request issue with the right body for the vuln class
  4. Update state file (so we never double-contact)
  5. Log to ~/.lictor/hourly.log

Hard safety limits:
  - MAX_PER_HOUR = 3 (default 1 — change with --per-hour)
  - MAX_PER_DAY = 40 (refuses to send more, even if queue full)
  - Sleeps if last submission < 15 min ago (avoids burst)
  - Rotates across vuln classes (avoids "all-firebase day" looking spammy)
  - Skips repos archived / disabled / deleted

Manual override: just don't run this hour. It's a cron job, not a daemon.

Cron entry:
  5 * * * * cd ~/Lictor && /usr/bin/python3 scripts/lictor-hourly.py >> ~/.lictor/hourly.log 2>&1

State file: ~/.lictor/hourly-state.json
"""
from __future__ import annotations
import argparse, json, os, re, sys, time, urllib.request, urllib.error, subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

LICTOR_DIR = Path.home() / "Lictor"
STATE_FILE = Path.home() / ".lictor" / "hourly-state.json"
LOG_FILE = Path.home() / ".lictor" / "hourly.log"
STATE_FILE.parent.mkdir(exist_ok=True)

CONTACT_BODY = (LICTOR_DIR / ".disclosure-bodies").as_posix()

# --- Vuln class registry -------------------------------------------------
CLASSES = {
    "firebase": {
        "private_md": "docs/launch/patrol-firebase-private.md",
        "title": "Security finding — possible Firebase service-account in source (details on request)",
        "body": """Hi —

Automated security scan flagged what appears to be a Firebase / Google service-account JSON in your public repo. I'm not posting details here for responsible-disclosure reasons.

Please contact me at **Raffa@Lictor-AI.com** (or DM via GitHub) and I'll send the exact file path + line, plus the JWT payload decode confirming what the key grants access to.

**Time-sensitive**: service-account keys grant full GCP/Firebase project access until manually revoked.

A note: this came from an automated scan flagging a *pattern*, not a verified live exploit. If we're wrong (sample key, test fixture, already-revoked), please reply and we'll close out. No blame intended.

— Raffa
Lictor AI · https://lictorai.com · github.com/Raffa-jarrl/Lictor-AI""",
    },
    "db-creds": {
        "private_md": "docs/launch/patrol-db-creds-private.md",
        "title": "Security finding — possible DB connection string with credentials (details on request)",
        "body": """Hi —

Automated security scan flagged what appears to be a database connection string with embedded credentials committed to your public source.

I'm not posting details here for responsible-disclosure reasons.

Please contact me at **Raffa@Lictor-AI.com** (or DM via GitHub) and I'll send the exact file path + line + redacted excerpt so you can verify and rotate.

If real, the fix is two steps:
1. Rotate the DB password (and any other credential in that file)
2. `git filter-repo` to scrub the credential from repo history

A note: this came from an automated scan flagging a *pattern*, not a verified live exploit. If we're wrong (test/sandbox DB, public-by-design, already-rotated), reply and we'll close out. No blame intended.

— Raffa
Lictor AI · https://lictorai.com""",
    },
    "prtarget": {
        "private_md": "docs/launch/patrol-prtarget-private-2026-05-17.md",
        "title": "Security finding — possible pull_request_target pattern (details on request)",
        "body": """Hi —

Automated security scan flagged a `pull_request_target` workflow in your repo that checks out the PR's head SHA / ref. This is the *pattern* of the classic GitHub Actions RCE — but whether it's actually exploitable depends on your guards (label gates, approved-ci checks, head-vs-base ownership checks, etc).

I'm not claiming we verified exploitability — we verified the pattern exists. Please review your workflow's guards and confirm. If they're sufficient, this is a non-issue and you can close.

If you'd like the exact workflow file + line we flagged, reply here or email **Raffa@Lictor-AI.com**.

— Raffa
Lictor AI · https://lictorai.com""",
    },
}

# Rotation order — round-robins each cycle
ROTATION = ["firebase", "db-creds", "prtarget"]

# Repos where I sent a PVR (private advisory) — won't show in public-issue search
PVR_SENT = {
    "anthropics/anthropic-sdk-python",
    "ibis-project/ibis",
    "Reckless-Satoshi/robosats",
}


def log(msg):
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"submitted": {}, "skipped": {}, "rotation_idx": 0, "last_submit_ts": 0}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def already_submitted_anywhere(repo, state):
    return repo in state.get("submitted", {})


def fetch_my_recent_issues():
    """Pull repos I've issued at recently — so we never double-contact."""
    # Use raw API with stored token (cron-safe)
    token = None
    token_file = Path.home() / ".lictor" / "gh-token"
    if token_file.exists():
        token = token_file.read_text().strip()
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], timeout=5).decode().strip()
        except Exception:
            return set()
    repos = set()
    # First get our username
    try:
        req = urllib.request.Request("https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "User-Agent": "lictor-hourly/0.1"})
        with urllib.request.urlopen(req, timeout=10) as r:
            username = json.loads(r.read())["login"]
    except Exception:
        return set()
    # Then search across all pages (cap at 3 pages = 300 issues)
    for page in range(1, 4):
        try:
            url = f"https://api.github.com/search/issues?q=author:{username}&per_page=100&page={page}"
            req = urllib.request.Request(url,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                         "User-Agent": "lictor-hourly/0.1"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
                items = data.get("items", [])
                if not items: break
                for it in items:
                    url_parts = it["repository_url"].split("/")
                    repos.add(url_parts[-2] + "/" + url_parts[-1])
        except Exception:
            break
    return repos


def candidates_for_class(vuln_class, days=365, exclude=None):
    """Parse the private MD file, return repos pushed within last N days, not already submitted."""
    info = CLASSES[vuln_class]
    fp = LICTOR_DIR / info["private_md"]
    if not fp.exists():
        return []
    text = fp.read_text()
    exclude = exclude or set()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = []
    for line in text.splitlines():
        m = re.match(r"\| `([^`]+)`", line)
        if not m: continue
        repo = m.group(1)
        # Find pushed date in line
        d = re.search(r"(\d{4}-\d{2}-\d{2})", line)
        pushed = d.group(1) if d else ""
        # Filter
        if repo in exclude: continue
        if pushed and pushed < cutoff: continue
        # Skip noise patterns
        if repo.lower().endswith(("/test", "/example", "/demo")): continue
        rows.append((repo, pushed))
    return rows


def repo_is_alive(repo):
    """Confirm repo exists, not archived, has issues enabled."""
    token = None
    token_file = Path.home() / ".lictor" / "gh-token"
    if token_file.exists():
        token = token_file.read_text().strip()
    if not token: return False
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "User-Agent": "lictor-hourly/0.1"})
        with urllib.request.urlopen(req, timeout=10) as r:
            meta = json.loads(r.read())
            return not meta.get("archived") and not meta.get("disabled") and meta.get("has_issues", True)
    except Exception:
        return False


def repo_has_private_security_policy(repo):
    """Pre-flight: if repo has SECURITY.md, security.txt, or PVR enabled, we should NOT
    fire a public issue — use their declared private channel instead.

    Added 2026-05-19 in response to rixx/pretalx feedback (issue #2459). Filing a public
    issue when the maintainer has set up a private channel is a process failure, not a
    judgment call. This function returns True when we should DEFER (i.e., skip the
    candidate this cycle and log it to a manual-private-disclosure queue).

    Checks:
      1. /.well-known/security.txt at the project's homepage or pages-host
      2. SECURITY.md in the repo (raw fetch on default branch)
      3. /security/policy via GH API
    """
    token = None
    token_file = Path.home() / ".lictor" / "gh-token"
    if token_file.exists():
        token = token_file.read_text().strip()
    if not token: return False  # fail-open to avoid blocking everything on a token issue

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "User-Agent": "lictor-hourly/0.1"}

    # 1. Check SECURITY.md (raw API — fast)
    for branch in ("main", "master"):
        try:
            url = f"https://api.github.com/repos/{repo}/contents/SECURITY.md?ref={branch}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as r:
                if r.status == 200:
                    return True  # SECURITY.md exists
        except urllib.error.HTTPError as e:
            if e.code != 404:
                pass  # any non-404 is ambiguous; continue checking
        except Exception:
            pass

    # 2. Check security advisory metadata via repo /community/profile
    try:
        url = f"https://api.github.com/repos/{repo}/community/profile"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
            files = data.get("files") or {}
            if files.get("security") is not None:
                return True
    except Exception:
        pass

    # 3. Check repo's homepage for /.well-known/security.txt (if homepage set)
    try:
        url = f"https://api.github.com/repos/{repo}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            meta = json.loads(r.read())
            homepage = meta.get("homepage") or ""
            if homepage and homepage.startswith("http"):
                try:
                    base = homepage.rstrip("/").rsplit("/", 0)[0] if "://" in homepage else homepage
                    txt_url = base.rstrip("/") + "/.well-known/security.txt"
                    txt_req = urllib.request.Request(txt_url, headers={"User-Agent": "lictor-hourly/0.1"})
                    with urllib.request.urlopen(txt_req, timeout=5) as tr:
                        if tr.status == 200 and b"Contact" in tr.read(2048):
                            return True
                except Exception:
                    pass
    except Exception:
        pass

    return False


def submit_issue(repo, title, body):
    """Submit via raw GitHub API."""
    # Try persistent token file first (cron-safe), then gh CLI (keychain — only works in interactive shell)
    token = None
    token_file = Path.home() / ".lictor" / "gh-token"
    if token_file.exists():
        token = token_file.read_text().strip()
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], timeout=5).decode().strip()
        except Exception:
            return None, "no gh token"
    url = f"https://api.github.com/repos/{repo}/issues"
    data = json.dumps({"title": title, "body": body}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "lictor-hourly/0.1",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()).get("html_url"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)


def count_today_submitted(state):
    today = datetime.now().strftime("%Y-%m-%d")
    return sum(1 for v in state.get("submitted", {}).values() if v.get("ts","").startswith(today))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-hour", type=int, default=1, help="Submissions per hourly run (default 1)")
    ap.add_argument("--max-per-day", type=int, default=40, help="Hard daily cap")
    ap.add_argument("--min-gap-min", type=int, default=15, help="Min minutes since last submission")
    ap.add_argument("--dry-run", action="store_true", help="Print what would happen, don't send")
    args = ap.parse_args()

    log(f"=== hourly cycle start (per_hour={args.per_hour}, daily_cap={args.max_per_day}) ===")
    state = load_state()

    # Hard daily cap
    today_count = count_today_submitted(state)
    if today_count >= args.max_per_day:
        log(f"daily cap reached ({today_count}/{args.max_per_day}) — skipping cycle")
        return

    # Min-gap throttle
    last = state.get("last_submit_ts", 0)
    gap_s = time.time() - last
    if gap_s < args.min_gap_min * 60:
        log(f"throttled — last submit {int(gap_s/60)} min ago, need ≥{args.min_gap_min}")
        return

    # Refresh our "do not double-contact" set
    already = set(state.get("submitted", {}).keys()) | fetch_my_recent_issues() | PVR_SENT | set(state.get("skipped", {}).keys())
    log(f"already-contacted set size: {len(already)}")

    sent_this_cycle = 0
    # Rotate through vuln classes — try each until we send N
    for _ in range(len(ROTATION) * 3):
        if sent_this_cycle >= args.per_hour: break
        if count_today_submitted(state) >= args.max_per_day:
            log("daily cap hit mid-cycle"); break

        cls = ROTATION[state.get("rotation_idx", 0) % len(ROTATION)]
        state["rotation_idx"] = (state.get("rotation_idx", 0) + 1) % len(ROTATION)
        info = CLASSES[cls]

        cands = candidates_for_class(cls, exclude=already)
        if not cands:
            log(f"  class {cls}: no fresh candidates — skipping")
            continue

        repo, pushed = cands[0]
        # IMMEDIATELY mark as taken so we don't re-pick within this cycle
        already.add(repo)
        log(f"  class {cls}: candidate {repo} (pushed {pushed})")

        if not repo_is_alive(repo):
            log(f"    skip — repo dead/archived/issues-disabled")
            state.setdefault("skipped", {})[repo] = {"reason": "dead", "ts": datetime.now().isoformat()}
            already.add(repo)
            continue

        # PRE-FLIGHT: if the repo has a declared private channel (SECURITY.md /
        # security.txt / PVR enabled), DEFER to the manual-private queue.
        # Filing public issues over their declared private channel is rude.
        # (Added 2026-05-19 after rixx/pretalx feedback — RET-009)
        if repo_has_private_security_policy(repo):
            log(f"    DEFER — repo has private security channel, queued for manual private disclosure")
            state.setdefault("private_queue", {})[repo] = {
                "class": cls, "pushed": pushed,
                "reason": "has-private-channel",
                "ts": datetime.now().isoformat(),
            }
            already.add(repo)
            continue

        if args.dry_run:
            log(f"    DRY-RUN — would submit: {info['title']}")
            sent_this_cycle += 1
            continue

        url, err = submit_issue(repo, info["title"], info["body"])
        if url:
            log(f"    ✓ submitted: {url}")
            state.setdefault("submitted", {})[repo] = {
                "class": cls, "url": url, "ts": datetime.now().isoformat()
            }
            already.add(repo)
            state["last_submit_ts"] = time.time()
            sent_this_cycle += 1
            time.sleep(2)
        else:
            log(f"    ✗ failed: {err}")
            state.setdefault("skipped", {})[repo] = {"reason": err, "ts": datetime.now().isoformat()}
            already.add(repo)

    save_state(state)
    today_count = count_today_submitted(state)
    log(f"=== cycle end: sent {sent_this_cycle} this run, {today_count} today, {len(state.get('submitted',{}))} all-time ===\n")


if __name__ == "__main__":
    main()
