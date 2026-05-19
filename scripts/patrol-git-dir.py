#!/usr/bin/env python3
"""
patrol-git-dir — scanner #24.

Hunts exposed .git/ directories. Different from /.git/config check —
this brute-forces additional .git/* paths that sometimes leak even when
/.git/config doesn't:
  - /.git/HEAD
  - /.git/index
  - /.git/packed-refs
  - /.git/logs/HEAD
  - /.git/description
  - /.git/info/refs

If ANY of these return 200 with the expected content, the .git directory
is dumpable — attacker can reconstruct entire git history including
secrets that were once committed. $500-$5K typical bounty.
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-GitDirPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "git-dir-ledger.jsonl"

PROBES = [
    ("/.git/HEAD", re.compile(rb"^ref:\s*refs/heads/", re.M)),
    ("/.git/index", re.compile(rb"^DIRC", re.M)),
    ("/.git/packed-refs", re.compile(rb"^# pack-refs with: peeled fully-peeled", re.M)),
    ("/.git/logs/HEAD", re.compile(rb"^[0-9a-f]{40} [0-9a-f]{40}", re.M)),
    ("/.git/description", re.compile(rb"Unnamed repository", re.I)),
    ("/.git/info/refs", re.compile(rb"^[0-9a-f]{40}\s", re.M)),
    ("/.git/config", re.compile(rb"\[core\]|repositoryformatversion", re.I)),
]
PREFIXES = ["", "www.", "api.", "app.", "admin.", "dev.", "staging.", "internal."]


@dataclass
class GitDirLeak:
    host: str; path: str; payout: int
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=5):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if 300 <= r.status < 400: return r.status, b""
            return r.status, r.read(8192)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


def check_one(host_probe):
    host, (path, success_rx) = host_probe
    url = f"https://{host}{path}"
    status, body = http_get(url)
    if status != 200 or not body: return None
    if success_rx.search(body):
        return GitDirLeak(host=host, path=path, payout=1500,
            snippet=body[:200].decode("utf-8", "replace").replace("\n"," "))
    return None


def append_ledger(f):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fp:
        fp.write(json.dumps(asdict(f)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"))
    ap.add_argument("--max-domains", type=int, default=300)
    ap.add_argument("--workers", type=int, default=80)
    args = ap.parse_args()

    apexes = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines() if l.strip()][:args.max_domains]
    print(f"[+] git-dir patrol — {len(apexes)} apex × {len(PREFIXES)} prefixes × {len(PROBES)} probes", flush=True)

    tasks = []
    for apex in apexes:
        for prefix in PREFIXES:
            host = f"{prefix}{apex}"
            for p in PROBES:
                tasks.append((host, p))
    print(f"[+] total probes: {len(tasks)}", flush=True)

    hits = []
    seen_hosts = set()  # one finding per host is enough
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, t): t for t in tasks}
        for fut in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(tasks)}] {len(hits)} hits", flush=True)
            try: r = fut.result(timeout=8)
            except: r = None
            if r and r.host not in seen_hosts:
                seen_hosts.add(r.host)
                print(f"  🔴🔴 GIT-DIR-LEAK  https://{r.host}{r.path}  (${r.payout})", flush=True)
                append_ledger(r); hits.append(r)
    print(f"\n[+] scan complete: {len(hits)} exposed .git/ directories")


if __name__ == "__main__": main()
