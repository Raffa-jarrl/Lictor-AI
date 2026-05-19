#!/usr/bin/env python3
"""
patrol-aws-keys — hunt AWS access keys in committed source.

AWS keys are uniquely valuable as a target because:
  - They appear in DIFFERENT files than firebase/db-creds (terraform .tf,
    k8s yaml, docker-compose.yml, .aws/credentials, awscli config)
  - GitHub auto-revokes some but slowly — keys live long enough to be abused
  - Real $$ at stake — anyone with AKIA+SECRET pair can spin up EC2/S3
  - Different search queries = ENTIRELY different result space from our
    existing 14 scanner classes

Verification chain:
  1. GitHub Code Search for AKIA prefix + context keywords
  2. Fetch raw file, regex confirm AKIA[A-Z0-9]{16}
  3. Look for matching SECRET in same file (40-char base64-ish near AKIA)
  4. Skip if placeholder/example/test_aws_key in context
  5. Skip if AKIA prefix is on a known sample-key list (AKIA000000000000EXAMPLE, etc)
  6. Filter: freshness + not archived
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

# AWS Access Key ID: AKIA + 16 uppercase alphanumeric
AKIA_RX = re.compile(r'\b(AKIA[A-Z0-9]{16})\b')
# AWS Secret Access Key: 40 chars, base64-ish (mixed case + digits + +/=)
SECRET_NEAR_AKIA = re.compile(r'\b([A-Za-z0-9+/=]{40})\b')

# Known sample keys from AWS docs / training material — skip entirely
KNOWN_SAMPLE = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "AKIA0000000000000000",
    "AKIAEXAMPLEKEY000000",
}

PLACEHOLDER_CTX = re.compile(
    r'(example|sample|placeholder|REPLACE|XXX|TODO|FAKE|YOUR_AWS|your_access_key|test_aws|<.{1,30}>|getenv|environ)',
    re.IGNORECASE,
)
SKIP_PATH_RX = re.compile(r'(\.example$|/tests?/|/__tests__/|/spec/|/fixtures?/|/docs?/|README|CHANGELOG)', re.IGNORECASE)


@dataclass
class Hit:
    repo: str
    path: str
    url: str
    akid: str
    has_secret: bool
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
            seen.add(key); results.append(it)
        time.sleep(2)
    return results


def gh_raw_file(repo, path):
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode().strip().replace("\n","")).decode("utf-8","replace")
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


def verify(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    if SKIP_PATH_RX.search(path): return None
    content = gh_raw_file(repo, path)
    if not content: return None
    m = AKIA_RX.search(content)
    if not m: return None
    akid = m.group(1)
    if akid in KNOWN_SAMPLE: return None

    # Context check around the AKIA
    start = m.start()
    ctx = content[max(0, start-100):min(len(content), start+200)]
    if PLACEHOLDER_CTX.search(ctx): return None

    # Look for a paired secret nearby (within ~500 chars)
    nearby = content[max(0, start-100):min(len(content), start+500)]
    has_secret = False
    for sm in SECRET_NEAR_AKIA.finditer(nearby):
        sec = sm.group(1)
        if sec == akid: continue  # the AKIA itself matched the {40} too short, but just in case
        if len(sec) == 40 and not PLACEHOLDER_CTX.search(nearby[max(0,sm.start()-40):min(len(nearby),sm.start()+40)]):
            has_secret = True; break

    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None
    pushed = meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days: return None
    except Exception:
        return None
    return Hit(repo=repo, path=path, url=item["html_url"],
               akid=akid[:8]+"…"+akid[-4:],
               has_secret=has_secret,
               stars=meta.get("stars",0),
               pushed_at=meta.get("pushed_at","")[:10])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--max-age-days", type=int, default=365)
    ap.add_argument("--private", default=f"docs/launch/patrol-aws-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    # 10 distinct queries targeting DIFFERENT file types where AWS keys hide
    queries = [
        'AKIA extension:tf',                           # terraform
        'AKIA extension:env',                          # .env files
        'AKIA extension:yml',                          # docker-compose, k8s, ansible
        'AKIA extension:yaml',
        '"aws_access_key_id" "aws_secret_access_key"', # .aws/credentials format
        'AKIA filename:.env',
        'AKIA filename:docker-compose.yml',
        'AKIA filename:credentials',
        'AKIA "aws_secret_access_key"',                # most-paired patterns
        '"AKIA" "secret_access_key" extension:py',
    ]

    seen, raw = set(), []
    print(f"[+] aws-keys patrol — {len(queries)} queries...", flush=True)
    for q in queries:
        items = gh_code_search(q, max_pages=1)
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key); raw.append(it)
            if len(raw) >= args.max: break
        if len(raw) >= args.max: break

    print(f"[+] {len(raw)} candidates; verifying...", flush=True)
    hits = []
    for i, it in enumerate(raw, 1):
        repo = it["repository"]["full_name"]
        path = it["path"]
        print(f"  [{i}/{len(raw)}] {repo}/{path[:40]}", end="", flush=True)
        try:
            h = verify(it, args.max_age_days)
            if h:
                hits.append(h)
                pair = "+SECRET" if h.has_secret else "AKIA-only"
                print(f"  🔴 {h.akid} {pair} ★{h.stars}", flush=True)
            else:
                print("  ⚪", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(0.8)

    md = [f"# Patrol — AWS access-key exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Candidates inspected:** {len(raw)}",
          f"**Confirmed exposures:** {len(hits)}",
          f"  (with paired secret: {sum(1 for h in hits if h.has_secret)})\n",
          "| Repo | Path | ★ | Pushed | AKIA (redacted) | Paired secret? | File |",
          "|---|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: (-x.stars, -int(x.has_secret))):
        md.append(f"| `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.akid}` | {'**YES**' if h.has_secret else 'no'} | [link]({h.url}) |")
    Path(args.private).write_text("\n".join(md))
    print(f"\n[+] Done. {len(hits)} AWS-key exposures ({sum(1 for h in hits if h.has_secret)} with paired secret).")


if __name__ == "__main__":
    main()
