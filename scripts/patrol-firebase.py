#!/usr/bin/env python3
"""
patrol-firebase — hunt committed Firebase service-account JSONs.

GitHub's secret-scanning catches OBVIOUS patterns (e.g., the `private_key`
field of a service account when committed in a known shape) but misses
many real-world cases where the JSON is:
  - Wrapped in code (e.g., `const sa = { ... }`)
  - Stored under unusual filenames (not `serviceAccountKey.json`)
  - Embedded in test fixtures, scripts, or config wrappers

Detection: the JSON has a fingerprint string `"private_key_id":` followed
within ~500 chars by `"-----BEGIN PRIVATE KEY-----"`. This combination
only appears in real Firebase / Google service-account credentials.

For each match:
  1. Fetch the file
  2. Verify the `private_key_id` + `private_key` co-presence
  3. Extract `client_email` if present (helps identify which project)
  4. Filter to repos pushed in the last N days + not archived
  5. Write outreach queue
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

SA_FINGERPRINT_RX = re.compile(
    r'"private_key_id"\s*:\s*"[a-f0-9]{20,}".*?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----',
    re.DOTALL,
)
CLIENT_EMAIL_RX = re.compile(r'"client_email"\s*:\s*"([^"]+)"')

@dataclass
class Hit:
    repo: str
    path: str
    url: str
    project_id: str = ""
    client_email: str = ""
    stars: int = 0
    pushed_at: str = ""

def gh_code_search(query, per_page=100, max_pages=3):
    seen, results = set(), []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", f"per_page={per_page}", "-f", f"page={page}",
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

PLACEHOLDER_EMAIL_RX = re.compile(r'(your-?app|your-?project|example|test-?project|myproject|placeholder|sample|demo|gitguardian|template|REPLACE|XXX|YOUR_)', re.IGNORECASE)
PLACEHOLDER_PROJECT_RX = re.compile(r'(your[-_]?project|example|test[-_]?project|myproject|placeholder|sample|demo)', re.IGNORECASE)

def verify(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    content = gh_raw_file(repo, path)
    if not content: return None
    if not SA_FINGERPRINT_RX.search(content): return None

    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None

    pushed = meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days:
            return None
    except Exception:
        return None

    email_m = CLIENT_EMAIL_RX.search(content)
    if email_m and PLACEHOLDER_EMAIL_RX.search(email_m.group(1)):
        return None  # placeholder example, not a real key
    # Also skip if path is README.md or docs/* (intentional documentation)
    if item["path"].lower().endswith("readme.md") or item["path"].lower().startswith("docs/"):
        return None
    return Hit(
        repo=repo, path=path, url=item["html_url"],
        client_email=email_m.group(1) if email_m else "",
        stars=meta.get("stars", 0),
        pushed_at=meta.get("pushed_at", "")[:10],
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=150)
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--private", default="docs/launch/patrol-firebase-private.md")
    ap.add_argument("--public", default="docs/launch/patrol-firebase-aggregate.md")
    args = ap.parse_args()

    queries = [
        '"private_key_id" "private_key" "type": "service_account"',
        '"private_key" "BEGIN PRIVATE KEY" extension:json',
        '"client_email" "private_key" extension:ts',
        '"client_email" "private_key" extension:py',
        # New query angles — different parts of GH index
        '"firebase-adminsdk" "private_key" extension:json',
        '"iam.gserviceaccount.com" "BEGIN PRIVATE KEY"',
        'filename:serviceAccountKey.json "private_key"',
        'filename:service-account.json "private_key"',
        '"GOOGLE_APPLICATION_CREDENTIALS" "BEGIN PRIVATE KEY"',
        '"firebase" "BEGIN PRIVATE KEY" extension:env',
    ]
    seen, raw = set(), []
    print(f"[+] Searching GitHub Code Search for Firebase service-account fingerprints...")
    for q in queries:
        items = gh_code_search(q, per_page=100, max_pages=2)
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
                print(f"  🔴 hit  email={h.client_email[:40]}  ★{h.stars}")
            else:
                print("  ⚪ no hit / filtered")
        except Exception as e:
            print(f"  EXC: {e}")
        time.sleep(1.2)

    # Reports
    md = ["# Patrol — Firebase service-account exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Method:** Code search for `private_key_id` + `private_key` co-presence, raw-file fetch, age + archived filter.\n",
          f"## Confirmed Firebase service-account JSONs in public source: {len(hits)}\n",
          "| Repo | Path | Stars | Pushed | client_email | File |",
          "|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: -x.stars):
        md.append(f"| `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.client_email[:40]}` | [link]({h.url}) |")
    md.append("\n## Outreach playbook\n")
    md.append("Each is a CRITICAL exposure. Service-account keys grant full project access until manually revoked. For each:")
    md.append("1. Try PVR: `https://github.com/<repo>/security/advisories/new`")
    md.append("2. Fallback to public contact-request issue if PVR off")
    md.append("3. The fix: rotate the SA key in Google Cloud Console, then git-history-rewrite to remove from repo history")
    Path(args.private).write_text("\n".join(md))

    pm = [f"# Patrol — Firebase exposure aggregate scan\n",
          f"**Run:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
          f"## Aggregate\n",
          f"- Candidates inspected: **{len(raw)}**",
          f"- Confirmed Firebase service-account JSONs in public source: **{len(hits)}**"]
    Path(args.public).write_text("\n".join(pm))

    print(f"\n[+] Done. {len(hits)} confirmed firebase exposures.")
    print(f"[+] Private: {args.private}")

if __name__ == "__main__":
    main()
