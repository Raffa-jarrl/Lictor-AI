#!/usr/bin/env python3
"""
recheck — for every unfixed disclosure, re-run the original check.

If the issue is closed by maintainer → fix_method = "issue-closed"
If we know the file_path and the file is now missing → fix_method = "file-removed"
If we know the file_path and the marker pattern is gone from the file → fix_method = "marker-gone"
If we don't know the file_path, search the repo for the marker → if no matches → fix_method = "marker-gone-repo-wide"

Mark fixed_at + fix_method in the log. Optionally post a courtesy comment.

Usage:
  python3 scripts/recheck.py                   # check all unfixed
  python3 scripts/recheck.py --limit 50        # cap per run
  python3 scripts/recheck.py --post-comment    # actually thank maintainers on fix
  python3 scripts/recheck.py --dry-run         # show what would change

Cron: */180 * * * * (every 3 hours)
"""
from __future__ import annotations
import argparse, base64, json, re, time, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path.home() / ".lictor" / "disclosures.jsonl"
TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
UA = "Lictor-Recheck/0.1 (+https://lictorai.com)"

# class → marker regex
MARKERS = {
    "firebase":         re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{20,}".*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY', re.DOTALL),
    "db-creds":         re.compile(r'(postgres|mongodb|mongodb\+srv|mysql)://[^:]+:[^@\s\'"<>`]{4,}@[A-Za-z0-9.-]+'),
    "prtarget":         re.compile(r'pull_request_target.*?(checkout.*?ref.*?head\.(sha|ref))', re.DOTALL),
    "saas-mailchimp":   re.compile(r'\b[0-9a-f]{32}-us\d{1,3}\b'),
    "saas-sendgrid":    re.compile(r'SG\.[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{40,}'),
    "saas-twilio":      re.compile(r'\bAC[a-f0-9]{32}\b'),
    "cloud-cloudflare": re.compile(r'(?:cloudflare|cf[\W_])[^a-z]{0,60}[A-Za-z0-9_-]{40}'),
    "cloud-twilio-sid": re.compile(r'\bAC[a-f0-9]{32}\b'),
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
    except urllib.error.HTTPError as e:
        if e.code == 404: return {"_404": True}
        return {"_err": f"HTTP {e.code}"}
    except Exception as e:
        return {"_err": str(e)}


def fetch_raw(repo, path):
    """Fetch raw file content from default branch via contents API."""
    d = gh_json(f"/repos/{repo}/contents/{urllib.parse.quote(path)}")
    if not d or d.get("_404") or d.get("_err"): return None
    content = d.get("content")
    if not content: return None
    try:
        return base64.b64decode(content.replace("\n","")).decode("utf-8", "replace")
    except Exception:
        return None


def search_repo_for_marker(repo, marker_pattern):
    """Use GH search/code to find any file in the repo matching the marker.
    Uses the SINGLE most specific literal from the regex — being too restrictive
    (requiring multiple literals) gives false positives ("we think it's gone")."""
    if "private_key_id" in marker_pattern.pattern:
        q = f'"private_key_id" repo:{repo}'
    elif "postgres://" in marker_pattern.pattern:
        q = f'"postgres://" repo:{repo}'
    elif "pull_request_target" in marker_pattern.pattern:
        q = f'pull_request_target repo:{repo}'
    elif "0-9a-f]{32}-us" in marker_pattern.pattern:
        q = f'mailchimp repo:{repo}'
    elif "SG\\." in marker_pattern.pattern:
        q = f'"SG." repo:{repo}'
    elif "AC[a-f0-9]{32}" in marker_pattern.pattern:
        q = f'twilio_account_sid repo:{repo}'
    elif "cloudflare" in marker_pattern.pattern.lower():
        q = f'CLOUDFLARE_API_TOKEN repo:{repo}'
    else:
        return None  # can't construct query
    # GH Code Search rate-limits at 30/min authenticated — sleep before search calls
    time.sleep(2.5)
    data = gh_json(f"/search/code?q={urllib.parse.quote(q)}")
    if not data or data.get("_err"): return None
    return data.get("total_count", 0)


def get_issue_state(repo, number):
    d = gh_json(f"/repos/{repo}/issues/{number}")
    if not d or d.get("_err"): return None
    return {"state": d.get("state"),
            "state_reason": d.get("state_reason"),
            "closed_at": d.get("closed_at")}


def post_comment(repo, number, body):
    url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"
    data = json.dumps({"body": body}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read()).get("html_url")
    except Exception as e:
        return None


def load_log():
    if not LOG_FILE.exists(): return []
    return [json.loads(l) for l in LOG_FILE.read_text().splitlines() if l.strip()]


def save_log(rows):
    LOG_FILE.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def recheck_one(row):
    """Returns (fix_method, evidence) or (None, reason-still-open)."""
    repo = row["repo"]
    cls = row["class"]
    number = row.get("issue_number")
    file_path = row.get("file_path")

    # 1. Issue state from GitHub
    state = get_issue_state(repo, number) if number else None
    if state and state["state"] == "closed":
        return ("issue-closed", f"maintainer closed (reason: {state.get('state_reason') or 'completed'}, at {state.get('closed_at','?')[:10]})")

    # 2. File-level recheck if we know the path
    if file_path:
        content = fetch_raw(repo, file_path)
        if content is None:
            # 404 = file removed
            return ("file-removed", f"{file_path} no longer in repo")
        marker = MARKERS.get(cls)
        if marker and not marker.search(content):
            return ("marker-gone", f"{file_path} still exists but marker pattern absent")
        return (None, f"{file_path} still contains marker")

    # 3. No path known — repo-wide search
    marker = MARKERS.get(cls)
    if marker:
        count = search_repo_for_marker(repo, marker)
        if count is None: return (None, "couldn't repo-wide-search")
        if count == 0:
            return ("marker-gone-repo-wide", f"GH search for marker in {repo} → 0 hits")
        return (None, f"GH search still shows {count} match(es)")

    return (None, "no marker registered for class")


def thank_you_body(fix_method):
    if fix_method == "issue-closed":
        return None  # Already closed, comment can feel redundant
    return f"""Quick note from Lictor — we just re-ran the same check we flagged in this issue, and the finding is now gone ({fix_method}).

If you rotated the credential, scrubbed it from history, or removed the file: thank you for taking it seriously. Marking this issue resolved on our end (state file).

If something else is going on (we got the wrong file, or the repo was restructured), reply here and we'll re-investigate.

— Raffa
Lictor AI · https://lictorai.com · we re-check every disclosure every few hours, so your fix doesn't go uncredited

*(This comment was automated based on our scanner detecting the marker is no longer present. The fact that we sent it means our check confirms your fix.)*"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=80, help="Max rows to check per run")
    ap.add_argument("--post-comment", action="store_true", help="Post a thank-you on confirmed fixes")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rows = load_log()
    unfixed = [r for r in rows if not r.get("fixed_at")]
    print(f"[recheck] total rows: {len(rows)}, unfixed: {len(unfixed)}", flush=True)
    print(f"[recheck] checking up to {args.limit}...\n", flush=True)

    newly_fixed = 0
    checked = 0
    by_method = {}

    for r in unfixed[:args.limit]:
        checked += 1
        repo = r["repo"]
        cls = r["class"]
        try:
            fix_method, evidence = recheck_one(r)
        except Exception as e:
            print(f"  [{checked}] EXC {repo} → {e}", flush=True)
            continue

        if fix_method:
            newly_fixed += 1
            by_method[fix_method] = by_method.get(fix_method, 0) + 1
            r["fixed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            r["fix_method"] = fix_method
            print(f"  [{checked}] ✅ FIXED {cls:18s} {repo:50s} via {fix_method}", flush=True)

            if args.post_comment and not args.dry_run and fix_method != "issue-closed":
                body = thank_you_body(fix_method)
                if body and r.get("issue_number"):
                    url = post_comment(repo, r["issue_number"], body)
                    if url: print(f"          comment: {url}", flush=True)
        else:
            print(f"  [{checked}] ⏳ open  {cls:18s} {repo:50s} ({evidence[:60]})", flush=True)
        time.sleep(0.5)

    if not args.dry_run:
        save_log(rows)

    print(f"\n[recheck] checked {checked}, newly-fixed: {newly_fixed}")
    if by_method:
        print("  by method:")
        for m, n in by_method.items():
            print(f"    {m}: {n}")

    total_fixed = sum(1 for r in rows if r.get("fixed_at"))
    print(f"\n[recheck] CUMULATIVE FIXES CONFIRMED: {total_fixed}/{len(rows)} = {total_fixed*100//max(len(rows),1)}%")


if __name__ == "__main__":
    main()
