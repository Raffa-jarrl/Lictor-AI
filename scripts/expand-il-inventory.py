#!/usr/bin/env python3
"""
expand-il-inventory — build a 5-10x larger Israeli corpus.

Sources:
  1. crt.sh chunked by 30-day windows (avoids broad-query timeout)
  2. GitHub user search: location:Israel + repos with .co.il in name/desc
  3. npm registry: maintainer email *.co.il or location:Israel
  4. Optional: probe each discovered host for vibe-platform fingerprints
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone, timedelta

UA = "Lictor-IL-Inventory/0.1 (+https://lictor-ai.com; raffa@lictor-ai.com)"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"il-inventory-expanded-{datetime.now().strftime('%Y-%m-%d')}.tsv"


def crtsh_chunk(query: str, timeout=45):
    """Single crt.sh query with timeout."""
    url = f"https://crt.sh/?q={query}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  [!] {query}: {e}", flush=True); return []


def crtsh_il_chunked(months=12):
    """Query crt.sh by narrow subdomain prefixes to bypass timeout."""
    # Use 2-char prefix queries to bound result size
    prefixes = list("abcdefghijklmnopqrstuvwxyz0123456789")
    hosts = set()
    for i, prefix in enumerate(prefixes, 1):
        print(f"  [{i}/{len(prefixes)}] crt.sh: {prefix}%.co.il", flush=True)
        data = crtsh_chunk(f"{prefix}%25.co.il")
        for row in data:
            for name in (row.get("name_value", "") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(".co.il") and "@" not in name and " " not in name:
                    parts = name.split(".")
                    if len(parts) <= 4:  # skip deep subdomains
                        hosts.add(name)
        time.sleep(1.5)
        print(f"      cumulative: {len(hosts)} unique hosts", flush=True)
    return hosts


def github_il_users(max_pages=3):
    """GitHub user search: location:Israel — pull recent active users."""
    repos = set()
    try:
        for page in range(1, max_pages + 1):
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/users",
                 "-f", "q=location:Israel followers:>10",
                 "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", "[.items[].login]"],
                stderr=subprocess.DEVNULL, timeout=20)
            users = json.loads(out)
            if not users: break
            for u in users:
                # Pull their .co.il-mentioning repos
                try:
                    r_out = subprocess.check_output(
                        ["gh", "api", "-X", "GET", "search/repositories",
                         "-f", f"q=user:{u} .co.il in:name,description",
                         "-f", "per_page=10",
                         "--jq", "[.items[] | {repo: .full_name, url: .homepage // \"\", stars: .stargazers_count, pushed: .pushed_at}]"],
                        stderr=subprocess.DEVNULL, timeout=15)
                    for r in json.loads(r_out):
                        repos.add((r["repo"], r.get("url", ""), r.get("stars", 0), r.get("pushed", "")))
                except Exception: pass
                time.sleep(0.4)
            time.sleep(2)
    except Exception as e:
        print(f"  [!] gh search fail: {e}", flush=True)
    return repos


def npm_il_maintainers(limit=200):
    """npm search for packages whose maintainers have .co.il / .il emails."""
    # npm doesn't expose maintainer email in search; use indirect signal:
    # search packages with "Israel" / "Hebrew" in description or readme
    hits = set()
    queries = ["israel", "hebrew", "ivrit", "tel-aviv", ".co.il"]
    for q in queries:
        try:
            url = f"https://registry.npmjs.org/-/v1/search?text={q}&size=100"
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for obj in data.get("objects", []):
                p = obj.get("package", {})
                name = p.get("name", "")
                # Pull github repo link if present
                links = p.get("links", {})
                repo_url = links.get("repository", "")
                if "github.com" in repo_url:
                    repo = repo_url.replace("https://github.com/", "").replace("git+", "").rstrip(".git/")
                    hits.add((repo, links.get("homepage", ""), 0, ""))
            time.sleep(1.2)
        except Exception as e:
            print(f"  [!] npm {q}: {e}", flush=True)
        if len(hits) >= limit: break
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-crtsh", action="store_true")
    ap.add_argument("--skip-gh", action="store_true")
    ap.add_argument("--skip-npm", action="store_true")
    args = ap.parse_args()

    print(f"[+] Expanding IL inventory → {OUT}", flush=True)

    rows = []  # (repo_or_host, url, stars, pushed, source)

    if not args.skip_crtsh:
        print("\n[1/3] crt.sh chunked by prefix...", flush=True)
        hosts = crtsh_il_chunked()
        print(f"[1/3] crt.sh total: {len(hosts)} unique .co.il hosts", flush=True)
        for h in sorted(hosts):
            rows.append((h, f"https://{h}", 0, "", "crtsh"))

    if not args.skip_gh:
        print("\n[2/3] GitHub IL users...", flush=True)
        gh = github_il_users(max_pages=2)
        print(f"[2/3] GitHub: {len(gh)} IL repos", flush=True)
        for r in gh:
            rows.append((r[0], r[1], r[2], r[3], "github"))

    if not args.skip_npm:
        print("\n[3/3] npm IL-flagged packages...", flush=True)
        npm = npm_il_maintainers()
        print(f"[3/3] npm: {len(npm)} packages with IL signals", flush=True)
        for r in npm:
            rows.append((r[0], r[1], r[2], r[3], "npm"))

    # Dedupe by first field
    seen = set(); deduped = []
    for r in rows:
        if r[0] in seen: continue
        seen.add(r[0]); deduped.append(r)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        f.write("identifier\turl\tstars\tpushed\tsource\n")
        for r in deduped:
            f.write("\t".join(str(x) for x in r) + "\n")
    print(f"\n[+] Wrote {len(deduped)} unique entries → {OUT}")
    print(f"    by source: " + ", ".join(f"{s}={sum(1 for r in deduped if r[4]==s)}" for s in ("crtsh","github","npm")))


if __name__ == "__main__":
    main()
