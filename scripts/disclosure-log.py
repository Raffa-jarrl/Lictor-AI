#!/usr/bin/env python3
"""
disclosure-log — maintain ~/.lictor/disclosures.jsonl, one row per disclosure.

Each row: {
  "repo": "owner/name",
  "class": "firebase" | "db-creds" | "prtarget" | "saas-mailchimp" | ...,
  "file_path": "src/firebase.json",            # what we flagged
  "marker": "private_key_id" | ...,             # the regex marker to re-check
  "issue_url": "https://github.com/.../issues/1",
  "issue_number": 1,
  "sent_at": "2026-05-18T12:34:56Z",
  "fixed_at": null,                             # set by recheck.py when confirmed-gone
  "fix_method": null,                           # "file-removed" | "marker-gone" | "issue-closed-by-maintainer"
}

The log is the ground truth. recheck.py reads it, re-runs the original check,
and marks `fixed_at` when the marker is no longer present.

Subcommands:
  init                  : create empty log if missing
  backfill              : populate log from past patrol-*-private.md + GitHub issues
  list [--unfixed]      : show all rows
  add <repo> <class>... : manually add a row
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path.home() / ".lictor" / "disclosures.jsonl"
LICTOR_DIR = Path.home() / "Lictor"
TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
UA = "Lictor-DisclosureLog/0.1 (+https://lictorai.com)"

# class → (private-md glob, marker pattern in file)
CLASS_MAP = {
    "firebase":         {"md_glob": "docs/launch/patrol-firebase-private.md",
                          "marker": "private_key_id"},
    "db-creds":         {"md_glob": "docs/launch/patrol-db-creds-private.md",
                          "marker": "postgres://|mongodb://|mongodb+srv://"},
    "prtarget":         {"md_glob": "docs/launch/patrol-prtarget-private-*.md",
                          "marker": "pull_request_target"},
    "saas-mailchimp":   {"md_glob": "docs/launch/patrol-saas-*-private.md",
                          "marker": r'\b[0-9a-f]{32}-us\d{1,3}\b',
                          "vendor": "mailchimp"},
    "saas-sendgrid":    {"md_glob": "docs/launch/patrol-saas-*-private.md",
                          "marker": r'SG\.[A-Za-z0-9_-]{20,}',
                          "vendor": "sendgrid"},
    "saas-twilio":      {"md_glob": "docs/launch/patrol-saas-*-private.md",
                          "marker": r'\bAC[a-f0-9]{32}\b',
                          "vendor": "twilio-token"},
    "cloud-cloudflare": {"md_glob": "docs/launch/patrol-cloudkeys-*-private.md",
                          "marker": r'[A-Za-z0-9_-]{40}',
                          "vendor": "cloudflare"},
    "cloud-twilio-sid": {"md_glob": "docs/launch/patrol-cloudkeys-*-private.md",
                          "marker": r'\bAC[a-f0-9]{32}\b',
                          "vendor": "twilio-sid"},
}


def gh_json(path):
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        return None


def all_my_issues():
    """Pull every issue I've authored (~200)."""
    out = []
    for page in range(1, 5):
        data = gh_json(f"/search/issues?q=author:Raffa-jarrl&per_page=100&page={page}")
        if not data: break
        items = data.get("items", [])
        if not items: break
        out.extend(items)
        if len(items) < 100: break
    return out


def parse_private_md(md_path, only_vendor=None):
    """Yield (repo, path, redacted_key) from a private MD file."""
    try:
        text = open(md_path).read()
    except FileNotFoundError:
        return
    for line in text.splitlines():
        # firebase/db: | `repo` | `path` | stars | date | email | link
        m = re.match(r"\| `([^`]+)` \| `([^`]+)` \| \d+", line)
        if m:
            yield m.group(1), m.group(2), None
            continue
        # prtarget: | `repo` | stars | severity | `path` | date
        m2 = re.match(r"\| `([^`]+)` \| \d+ \| \*\*[A-Z]+\*\* \| `([^`]+)`", line)
        if m2:
            yield m2.group(1), m2.group(2), None
            continue
        # saas/cloud: | vendor | `repo` | `path` | stars | date | redacted | link
        m3 = re.match(r"\| ([a-z-]+) \| `([^`]+)` \| `([^`]+)` \| \d+ \| \S+ \| `([^`]+)`", line)
        if m3:
            vend, repo, path, red = m3.groups()
            if only_vendor and vend != only_vendor: continue
            yield repo, path, red


def load_log():
    if not LOG_FILE.exists(): return []
    out = []
    for line in LOG_FILE.read_text().splitlines():
        if not line.strip(): continue
        try: out.append(json.loads(line))
        except: pass
    return out


def save_log(rows):
    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def add_row(rows, **kwargs):
    """Append unless already exists (matched by repo + class)."""
    for r in rows:
        if r["repo"] == kwargs["repo"] and r["class"] == kwargs["class"]:
            return False  # already logged
    rows.append(kwargs)
    return True


def cmd_init(args):
    LOG_FILE.parent.mkdir(exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("")
        print(f"created {LOG_FILE}")
    else:
        rows = load_log()
        print(f"exists with {len(rows)} rows")


def cmd_backfill(args):
    rows = load_log()
    print(f"current log: {len(rows)} rows", flush=True)

    # 1) Pull all my issues from GitHub
    print("fetching all my issues from GitHub...", flush=True)
    issues = all_my_issues()
    print(f"got {len(issues)} issues", flush=True)

    # 2) Match each issue to a class based on title pattern
    title_to_class = [
        ("Firebase service-account", "firebase"),
        ("DB connection string", "db-creds"),
        ("pull_request_target", "prtarget"),
        ("Mailchimp API key", "saas-mailchimp"),
        ("SendGrid API key", "saas-sendgrid"),
        ("Twilio credentials", "saas-twilio"),
        ("Twilio credentials in committed", "cloud-twilio-sid"),
    ]

    # 3) For each class, parse private MD to extract file_path for each repo
    paths_by_class_repo = {}
    for cls_name, cfg in CLASS_MAP.items():
        for md in LICTOR_DIR.glob(cfg["md_glob"]):
            for repo, path, red in parse_private_md(md, only_vendor=cfg.get("vendor")):
                key = (cls_name, repo)
                if key not in paths_by_class_repo:
                    paths_by_class_repo[key] = (path, red)

    # 4) For each issue, determine class + lookup file path + add row
    added = 0
    for it in issues:
        title = it.get("title", "")
        cls = None
        for substr, cname in title_to_class:
            if substr in title:
                cls = cname
                break
        if not cls: continue
        parts = it["repository_url"].split("/")
        repo = parts[-2] + "/" + parts[-1]
        path_info = paths_by_class_repo.get((cls, repo))
        file_path = path_info[0] if path_info else None
        redacted = path_info[1] if path_info else None
        marker = CLASS_MAP[cls]["marker"]
        if add_row(rows,
                   repo=repo, **{"class": cls},
                   file_path=file_path,
                   marker=marker,
                   redacted=redacted,
                   issue_url=it["html_url"],
                   issue_number=it["number"],
                   sent_at=it["created_at"],
                   state=it["state"],
                   state_reason=it.get("state_reason"),
                   fixed_at=None,
                   fix_method=None):
            added += 1

    save_log(rows)
    print(f"\nbackfill done: added {added} new rows, total {len(rows)}", flush=True)

    # Summary by class
    by_class = {}
    for r in rows:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    print("\nby class:")
    for c, n in sorted(by_class.items(), key=lambda x: -x[1]):
        print(f"  {c:20s} {n}")
    has_path = sum(1 for r in rows if r.get("file_path"))
    print(f"\nrows with file_path: {has_path}/{len(rows)}")


def cmd_list(args):
    rows = load_log()
    if args.unfixed:
        rows = [r for r in rows if not r.get("fixed_at")]
    for r in rows[:200]:
        cls = r.get("class", "?")
        repo = r.get("repo", "?")
        path = r.get("file_path") or "(no path)"
        status = "✅ fixed" if r.get("fixed_at") else "⏳ open"
        print(f"  [{status}] {cls:18s} {repo:50s} {path}")
    print(f"\ntotal: {len(rows)}")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("init")
    sp.add_parser("backfill")
    lc = sp.add_parser("list")
    lc.add_argument("--unfixed", action="store_true")
    args = ap.parse_args()
    {"init": cmd_init, "backfill": cmd_backfill, "list": cmd_list}[args.cmd](args)


if __name__ == "__main__":
    main()
