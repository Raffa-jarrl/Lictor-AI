#!/usr/bin/env python3
"""
patrol-db-creds — hunt database connection strings with embedded passwords
in public source code.

Targets:
  - postgres://user:password@host/db   (and postgresql:// variants)
  - mongodb+srv://user:password@cluster.mongodb.net/db
  - mysql://user:password@host:port/db
  - redis://default:password@host:port

GitHub's secret-scanning catches the well-known cloud-vendor patterns but
misses self-hosted DBs with custom credentials. This catches the wider class.

False-positive filtering:
  - Skip if password is "password" / "your_password" / "${...}" template
  - Skip if host is localhost / 127.0.0.1 (clearly dev)
  - Require host to be a real domain pattern OR an IP that's not RFC1918
"""
from __future__ import annotations
import argparse, base64, ipaddress, json, re, subprocess, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

# Capture the whole connection string + parts
CONN_RX = re.compile(
    r'(postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis)://'
    r'([A-Za-z0-9_-]+)'                    # user
    r':([^@\s\'"<>`]{4,})'                  # password (>= 4 chars, not whitespace)
    r'@([A-Za-z0-9.-]+)'                    # host
    r'(?::\d{2,5})?'                        # optional port
    r'(/[A-Za-z0-9_-]*)?'                   # optional db path
)

PLACEHOLDER_PASSWORDS = {
    'password', 'your_password', 'your-password', 'YOUR_PASSWORD',
    'CHANGEME', 'changeme', 'CHANGE_ME', '<password>', '${PASSWORD}',
    '${DB_PASSWORD}', '${POSTGRES_PASSWORD}', '<<password>>',
}

def is_real_password(pw: str) -> bool:
    if pw in PLACEHOLDER_PASSWORDS: return False
    if pw.startswith('${') or pw.startswith('$(') or pw.startswith('<%'): return False
    if pw.startswith('<') and pw.endswith('>'): return False
    if 'env.' in pw or 'process.env' in pw: return False
    if all(c == pw[0] for c in pw): return False  # all same char
    return True

def is_real_host(host: str) -> bool:
    if host in ('localhost', '127.0.0.1', '0.0.0.0'): return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback: return False
    except ValueError:
        pass  # not an IP, treat as hostname → real
    return True

@dataclass
class Hit:
    repo: str
    path: str
    url: str
    scheme: str
    user: str
    host: str
    db: str
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

def verify(item, age_max_days):
    repo = item["repository"]["full_name"]
    path = item["path"]
    content = gh_raw_file(repo, path)
    if not content: return None

    matches = []
    for m in CONN_RX.finditer(content):
        scheme, user, pw, host, db = m.groups()
        db = db or ""
        if not is_real_password(pw): continue
        if not is_real_host(host): continue
        if user in ('user', 'username', 'admin'): continue  # generic placeholders
        matches.append((scheme, user, host, db))
    if not matches: return None

    meta = gh_repo_meta(repo)
    if meta.get("archived"): return None
    pushed = meta.get("pushed_at", "")
    try:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z","+00:00"))
        if (datetime.now(timezone.utc) - pushed_dt).days > age_max_days:
            return None
    except Exception:
        return None

    scheme, user, host, db = matches[0]  # report the first
    return Hit(
        repo=repo, path=path, url=item["html_url"],
        scheme=scheme, user=user, host=host, db=db,
        stars=meta.get("stars", 0),
        pushed_at=meta.get("pushed_at", "")[:10],
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=150)
    ap.add_argument("--max-age-days", type=int, default=180)
    ap.add_argument("--private", default="docs/launch/patrol-db-creds-private.md")
    ap.add_argument("--public", default="docs/launch/patrol-db-creds-aggregate.md")
    args = ap.parse_args()

    queries = [
        '"postgres://" extension:ts',
        '"postgresql://" extension:ts',
        '"mongodb+srv://" "@" extension:js',
        '"mongodb+srv://" "@" extension:ts',
        '"mysql://" "@" extension:env',
    ]
    seen, raw = set(), []
    print(f"[+] Searching GitHub Code Search for DB connection strings...")
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
                print(f"  🔴 {h.scheme}://{h.user}:***@{h.host}{h.db}  ★{h.stars}")
            else:
                print("  ⚪")
        except Exception as e:
            print(f"  EXC: {e}")
        time.sleep(1.2)

    md = ["# Patrol — DB connection-string exposure (PRIVATE)\n",
          f"**Scanned at:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
          f"**Method:** Code search for postgres/mongodb/mysql/redis URLs, raw-file verify, filter placeholders + private hosts.\n",
          f"## Confirmed real-host DB credentials in public source: {len(hits)}\n",
          "| Repo | Path | Stars | Pushed | scheme://user@host | File |",
          "|---|---|---|---|---|---|"]
    for h in sorted(hits, key=lambda x: -x.stars):
        md.append(f"| `{h.repo}` | `{h.path}` | {h.stars} | {h.pushed_at} | `{h.scheme}://{h.user}:***@{h.host}{h.db}` | [link]({h.url}) |")
    md.append("\n## Note\n")
    md.append("Many of these are likely test/sandbox DBs that the maintainer doesn't consider sensitive.")
    md.append("Verify before disclosing: open the host in a browser; if it's a production-shaped name (api.x.com, db.company.com), it's worth contacting.")
    md.append("If it's a generic Heroku/Render/Supabase-test host, lower priority.")
    Path(args.private).write_text("\n".join(md))

    pm = [f"# Patrol — DB connection-string aggregate scan\n",
          f"**Run:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
          f"## Aggregate\n",
          f"- Candidates inspected: **{len(raw)}**",
          f"- Confirmed real-host DB credentials: **{len(hits)}**"]
    Path(args.public).write_text("\n".join(pm))

    print(f"\n[+] Done. {len(hits)} confirmed DB credential exposures.")

if __name__ == "__main__":
    main()
