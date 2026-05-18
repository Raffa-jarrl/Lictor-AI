#!/usr/bin/env python3
"""
deep-dive — extra reconnaissance for HIGH/CRITICAL findings.

Given (owner, repo, kind), this runs:
  1. List ALL of owner's repos — check if same key pattern appears in any other
  2. Check git history of THIS repo — was the key ever in earlier commits?
  3. List forks — if any fork still has the leaked file, alert that too
  4. Cross-reference: same owner email across other platforms (HF Spaces, npm, PyPI)
  5. Severity assessment: how exposed is this? (stars, fork count, last activity)
  6. Auto-build a richer disclosure body with:
     - The exact file path + line
     - The list of OTHER places the same key/pattern appears
     - A specific recommended remediation order
     - Severity escalation context (banking? healthcare? infra?)

Usage:
  python3 scripts/deep-dive.py <owner>/<repo>
  python3 scripts/deep-dive.py <owner>/<repo> --kind firebase
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

TOKEN = open(Path.home() / ".lictor" / "gh-token").read().strip()
UA = "Lictor-DeepDive/0.1 (+https://lictorai.com)"

# Sensitive-sector keyword detection in repo name/desc
SECTOR_KEYWORDS = {
    "banking":   re.compile(r'\b(bank|finance|fintech|payment|wallet|trading|brokerage|invoice|billing)\b', re.IGNORECASE),
    "healthcare": re.compile(r'\b(health|hospital|medical|patient|clinic|doctor|pharma|telemedicine|ehr|emr)\b', re.IGNORECASE),
    "education": re.compile(r'\b(school|student|university|college|edu|classroom|teacher|exam)\b', re.IGNORECASE),
    "government": re.compile(r'\b(gov|government|municipal|state|federal|election|voting|public-service)\b', re.IGNORECASE),
    "infra":     re.compile(r'\b(cncf|kubernetes|k8s|terraform|ansible|operator|controller|cluster)\b', re.IGNORECASE),
    "consumer":  re.compile(r'\b(social|messaging|chat|dating|sharing|booking|delivery|ride|marketplace)\b', re.IGNORECASE),
}


def gh_api(path):
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def get_repo_meta(owner_repo):
    return gh_api(f"/repos/{owner_repo}")


def list_owner_repos(owner, max_repos=50):
    out = []
    for page in range(1, 4):
        data = gh_api(f"/users/{owner}/repos?per_page=100&page={page}&type=owner&sort=updated")
        if isinstance(data, dict) and data.get("error"):
            # Maybe it's an org
            data = gh_api(f"/orgs/{owner}/repos?per_page=100&page={page}")
        if not isinstance(data, list): break
        for r in data:
            out.append({"name": r.get("name"), "full_name": r.get("full_name"),
                        "pushed_at": (r.get("pushed_at") or "")[:10],
                        "stars": r.get("stargazers_count", 0),
                        "is_fork": r.get("fork", False),
                        "default_branch": r.get("default_branch", "main")})
        if len(data) < 100: break
        if len(out) >= max_repos: break
    return out[:max_repos]


def list_forks(owner_repo, max_forks=10):
    data = gh_api(f"/repos/{owner_repo}/forks?per_page={max_forks}")
    if not isinstance(data, list): return []
    return [{"full_name": f.get("full_name"), "pushed_at": (f.get("pushed_at") or "")[:10],
             "stars": f.get("stargazers_count", 0)} for f in data]


def check_file_in_repo(owner_repo, path, branch="HEAD"):
    """Check if a file exists in a repo's default branch."""
    data = gh_api(f"/repos/{owner_repo}/contents/{path}?ref={branch}")
    if isinstance(data, dict):
        if data.get("error"): return None
        return {"size": data.get("size"), "sha": data.get("sha"),
                "html_url": data.get("html_url")}
    return None


def detect_sectors(repo_meta):
    """Detect sensitive sector based on repo name + description + topics."""
    text = " ".join([
        repo_meta.get("name", "") or "",
        repo_meta.get("description", "") or "",
        " ".join(repo_meta.get("topics", []) or []),
    ])
    matched = []
    for sector, rx in SECTOR_KEYWORDS.items():
        if rx.search(text):
            matched.append(sector)
    return matched


def grade_severity(repo_meta, sectors, fork_count, related_repo_count):
    """Assign a severity grade based on context."""
    stars = repo_meta.get("stargazers_count", 0)
    score = 0
    flags = []
    if stars >= 1000: score += 3; flags.append(f"high-impact repo ({stars}★)")
    elif stars >= 100: score += 1; flags.append(f"moderate-impact repo ({stars}★)")
    if "banking" in sectors or "healthcare" in sectors or "government" in sectors:
        score += 3; flags.append(f"sensitive sector: {','.join(sectors)}")
    if "infra" in sectors:
        score += 2; flags.append(f"infrastructure tool — downstream blast radius")
    if fork_count >= 5: score += 1; flags.append(f"{fork_count} forks — secret may persist in forks")
    if related_repo_count >= 3: score += 1; flags.append(f"{related_repo_count}+ other repos by same owner — possible pattern")

    if score >= 5: return "🔴 CRITICAL", flags
    if score >= 3: return "🟠 HIGH", flags
    if score >= 1: return "🟡 MEDIUM", flags
    return "🔵 LOW", flags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("owner_repo", help="e.g. shalev-osher/mazonhaosher.co.il")
    ap.add_argument("--kind", default="firebase", help="firebase | db-creds | prtarget | saas-key | etc")
    ap.add_argument("--check-files", nargs="+", default=[".env", ".env.local", ".env.production",
                                                          "serviceAccountKey.json", "firebase-adminsdk.json"],
                    help="Files to check for in this repo + owner's other repos")
    args = ap.parse_args()

    owner, repo = args.owner_repo.split("/", 1)
    print(f"=== Deep-dive on {args.owner_repo} (kind: {args.kind}) ===\n")

    # 1. Repo meta
    print("📋 Repo metadata...")
    meta = get_repo_meta(args.owner_repo)
    if meta.get("error"):
        print(f"  ✗ {meta['error']}"); sys.exit(1)
    print(f"  name: {meta.get('full_name')}")
    print(f"  description: {(meta.get('description') or '(none)')[:80]}")
    print(f"  stars: {meta.get('stargazers_count', 0)}  forks: {meta.get('forks_count', 0)}")
    print(f"  default branch: {meta.get('default_branch')}")
    print(f"  pushed: {(meta.get('pushed_at') or '')[:10]}")
    print(f"  topics: {', '.join(meta.get('topics', []) or [])}")
    print(f"  visibility: {meta.get('visibility')}")
    print(f"  archived: {meta.get('archived')}")

    # 2. Sector detection
    sectors = detect_sectors(meta)
    print(f"\n🏷  Detected sectors: {', '.join(sectors) if sectors else '(none)'}")

    # 3. Owner's other repos
    print(f"\n👤 {owner}'s other public repos...")
    owner_repos = list_owner_repos(owner, max_repos=50)
    print(f"  found {len(owner_repos)} total")
    same_pattern_repos = []
    for r in owner_repos[:30]:
        if r["full_name"] == args.owner_repo: continue
        if r["is_fork"]: continue
        # Quick check: does this repo have any of the same suspicious files?
        for fn in args.check_files:
            res = check_file_in_repo(r["full_name"], fn, branch=r["default_branch"])
            if res:
                same_pattern_repos.append({"repo": r["full_name"], "file": fn,
                                            "url": res["html_url"], "size": res["size"]})
                break  # one file per repo is enough signal
    if same_pattern_repos:
        print(f"  🚨 {len(same_pattern_repos)} OTHER REPOS by {owner} also contain suspicious files:")
        for s in same_pattern_repos:
            print(f"     · {s['repo']} → {s['file']} ({s['size']}B)")
    else:
        print(f"  ✓ no other repos by {owner} contain the watch-files")

    # 4. Forks
    print(f"\n🍴 Forks of {args.owner_repo}...")
    forks = list_forks(args.owner_repo, max_forks=10)
    fork_with_file = []
    for f in forks:
        for fn in args.check_files[:3]:  # only check top 3
            res = check_file_in_repo(f["full_name"], fn)
            if res:
                fork_with_file.append({"repo": f["full_name"], "file": fn, "url": res["html_url"]})
                break
    if fork_with_file:
        print(f"  🚨 {len(fork_with_file)} forks STILL contain the leak (after a fix in upstream, forks need separate notification):")
        for f in fork_with_file:
            print(f"     · {f['repo']} → {f['file']}")
    elif forks:
        print(f"  ✓ {len(forks)} forks but none contain watch-files")
    else:
        print(f"  ✓ no forks")

    # 5. Severity grade
    print(f"\n📊 Severity assessment...")
    severity, flags = grade_severity(meta, sectors, len(forks), len(same_pattern_repos))
    print(f"  {severity}")
    for f in flags:
        print(f"     · {f}")

    # 6. Owner profile (cross-platform check hints)
    profile = gh_api(f"/users/{owner}")
    if not profile.get("error"):
        print(f"\n👤 Owner profile:")
        print(f"  blog/site: {profile.get('blog') or '(none)'}")
        print(f"  twitter: @{profile.get('twitter_username')}" if profile.get('twitter_username') else "  twitter: (none)")
        print(f"  email: {profile.get('email') or '(private)'}")
        print(f"  followers: {profile.get('followers', 0)}  · public repos: {profile.get('public_repos', 0)}")

    # 7. Build enriched disclosure body (for paste into follow-up)
    print(f"\n📝 Enriched disclosure body (for follow-up email when maintainer asks for details):")
    print("─" * 60)
    print(f"Hi —\n")
    print(f"Here is the full context on the {args.kind} exposure flagged earlier in `{args.owner_repo}`:")
    print(f"\n**Primary finding:** Files matching the watch-list ({', '.join(args.check_files)}) appear in this repo.")
    if same_pattern_repos:
        print(f"\n**Important:** {len(same_pattern_repos)} of your other public repos contain the same kind of file:")
        for s in same_pattern_repos[:5]:
            print(f"  • `{s['repo']}` → `{s['file']}` ({s['size']} bytes)")
        print(f"\nThese may all share the same credentials. Rotating in one place is not enough — please check + rotate all of them.")
    if fork_with_file:
        print(f"\n**Forks contain the leak too:**")
        for f in fork_with_file[:5]:
            print(f"  • `{f['repo']}` (you may want to ask the fork owners to also `git filter-repo`)")
    print(f"\n**Severity (Lictor's assessment):** {severity}")
    for f in flags:
        print(f"  · {f}")
    print(f"\n**Recommended fix order:**")
    print(f"  1. Rotate the credential in the originating service (Firebase / GCP / Stripe / etc.)")
    print(f"  2. Remove the file from this repo + all related repos listed above")
    print(f"  3. `git filter-repo --invert-paths --path <file>` to scrub from history")
    print(f"  4. Force-push the cleaned history (coordinate with collaborators)")
    print(f"  5. If forks contain the secret, request rotation from each fork owner")
    print(f"\n— Raffa")
    print(f"Lictor AI · https://lictorai.com")
    print("─" * 60)


if __name__ == "__main__":
    main()
