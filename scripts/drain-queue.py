#!/usr/bin/env python3
"""
drain-queue — auto-submit ALL new candidates across ALL scanners.

Reads every patrol-*-private*.md file, builds the union of candidates,
filters out already-submitted repos, fires contact-requests up to --max.

Per vuln class it picks the right title + body template.
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
LICTOR_DIR = Path.home() / "Lictor"

# Repos where I sent a PVR (private advisory) — won't show in public-issue search
PVR_SENT = {
    "anthropics/anthropic-sdk-python",
    "ibis-project/ibis",
    "Reckless-Satoshi/robosats",
}

# Vuln class → (title, body file path, private-MD glob)
CLASSES = {
    "firebase": {
        "md_glob": "docs/launch/patrol-firebase-private.md",
        "title": "Security report — possible Firebase service-account exposure (please contact privately)",
        "body_path": "/tmp/contact-body.md",
    },
    "db-creds": {
        "md_glob": "docs/launch/patrol-db-creds-private.md",
        "title": "Security report — possible DB connection string with credentials (please contact privately)",
        "body_path": "/tmp/db-body.md",
    },
    "prtarget": {
        "md_glob": "docs/launch/patrol-prtarget-private-*.md",
        "title": "Security report — possible pull_request_target + checkout-head RCE (please contact privately)",
        "body_path": "/tmp/prtarget-body.md",
    },
    "saas-mailchimp": {
        "md_glob": "docs/launch/patrol-saas-*-private.md",
        "title": "Security report — possible Mailchimp API key in committed source (please contact privately)",
        "body_path": "/tmp/saas-mc-body.md",
        "vendor_filter": "mailchimp",
    },
    "saas-sendgrid": {
        "md_glob": "docs/launch/patrol-saas-*-private.md",
        "title": "Security report — possible SendGrid API key in committed source (please contact privately)",
        "body_path": "/tmp/saas-sg-body.md",
        "vendor_filter": "sendgrid",
    },
    "saas-twilio": {
        "md_glob": "docs/launch/patrol-saas-*-private.md",
        "title": "Security report — possible Twilio credentials in committed source (please contact privately)",
        "body_path": "/tmp/saas-tw-body.md",
        "vendor_filter": "twilio-token",
    },
}


def fetch_done():
    done = set()
    for page in range(1, 4):
        url = f"https://api.github.com/search/issues?q=author:Raffa-jarrl&per_page=100&page={page}"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "lictor-drain/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
                for it in data.get("items", []):
                    parts = it["repository_url"].split("/")
                    done.add(parts[-2] + "/" + parts[-1])
                if len(data.get("items", [])) < 100: break
        except Exception as e:
            print(f"warn: page {page} fetch failed: {e}")
            break
    return done


def extract_candidates(md_path, vendor_filter=None):
    """Yield (repo, pushed_date, stars) from a private MD file."""
    try:
        text = open(md_path).read()
    except FileNotFoundError:
        return
    for line in text.splitlines():
        # Match: | `repo` | ... | int | date |  (firebase/db format)
        m1 = re.match(r"\| `([^`]+)` \| `([^`]+)` \| (\d+) \| (\d{4}-\d{2}-\d{2})", line)
        if m1:
            yield m1.group(1), m1.group(4), int(m1.group(3))
            continue
        # prtarget format: | `repo` | stars | **HIGH** | `file` | date |
        m2 = re.match(r"\| `([^`]+)` \| (\d+) \| \*\*[A-Z]+\*\* \| `([^`]+)` \| (\d{4}-\d{2}-\d{2})", line)
        if m2:
            yield m2.group(1), m2.group(4), int(m2.group(2))
            continue
        # saas format: | vendor | `repo` | `path` | stars | date | redacted | link |
        m3 = re.match(r"\| ([a-z-]+) \| `([^`]+)` \| `([^`]+)` \| (\d+) \| (\d{4}-\d{2}-\d{2})", line)
        if m3:
            vend, repo, _, stars, pushed = m3.groups()
            if vendor_filter and vend != vendor_filter: continue
            yield repo, pushed, int(stars)


def submit(repo, title, body):
    url = f"https://api.github.com/repos/{repo}/issues"
    data = json.dumps({"title": title, "body": body}).encode()
    req = urllib.request.Request(url, data=data, method='POST', headers={
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'lictor-drain/0.1'})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read()).get('html_url', '?'), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, type(e).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=50, help="Total submissions in this drain")
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.max_age_days)).strftime('%Y-%m-%d')
    print(f"[drain] cutoff={cutoff}, max={args.max}, dry-run={args.dry_run}", flush=True)

    # Build done-set
    done = fetch_done() | PVR_SENT
    print(f"[drain] already-contacted set: {len(done)} (incl. {len(PVR_SENT)} PVRs)", flush=True)

    # Collect all candidates across all classes
    all_jobs = []  # (repo, title, body, source_class, pushed, stars)
    for cls_name, cfg in CLASSES.items():
        try:
            body = open(cfg["body_path"]).read()
        except FileNotFoundError:
            print(f"[drain] skip {cls_name}: body file missing ({cfg['body_path']})", flush=True)
            continue
        for md in LICTOR_DIR.glob(cfg["md_glob"]):
            for repo, pushed, stars in extract_candidates(md, cfg.get("vendor_filter")):
                if pushed < cutoff: continue
                if repo in done: continue
                all_jobs.append((repo, cfg["title"], body, cls_name, pushed, stars))

    # Dedup by repo (first vuln class wins for any single repo)
    seen = set(); unique = []
    for j in all_jobs:
        if j[0] in seen: continue
        seen.add(j[0]); unique.append(j)
    print(f"[drain] {len(unique)} unique fresh candidates across all classes", flush=True)

    # Sort: newest pushed first
    unique.sort(key=lambda j: j[4], reverse=True)

    # Take up to --max
    todo = unique[:args.max]
    print(f"[drain] will fire {len(todo)} this run\n", flush=True)

    if args.dry_run:
        for repo, title, body, cls_name, pushed, stars in todo:
            print(f"  DRY  [{cls_name:18s}] {pushed} ★{stars:4d} {repo}", flush=True)
        return

    ok = fail = 0
    by_class = {}
    for i, (repo, title, body, cls_name, pushed, stars) in enumerate(todo, 1):
        url, err = submit(repo, title, body)
        if url:
            ok += 1
            by_class[cls_name] = by_class.get(cls_name, 0) + 1
            print(f"  [{i:2d}/{len(todo)}] ✓ [{cls_name:18s}] {repo} → {url}", flush=True)
        else:
            fail += 1
            print(f"  [{i:2d}/{len(todo)}] ✗ [{cls_name:18s}] {repo} → {err}", flush=True)
        time.sleep(1.5)

    print(f"\n=== drain DONE ===")
    print(f"ok: {ok}  fail: {fail}")
    for cls, n in sorted(by_class.items(), key=lambda x: -x[1]):
        print(f"  {cls:20s} {n}")


if __name__ == "__main__":
    main()
