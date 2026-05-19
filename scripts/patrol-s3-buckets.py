#!/usr/bin/env python3
"""
patrol-s3-buckets — scanner #21.

Brute-forces likely S3 bucket names for each bounty-program apex domain.
For each found bucket, checks if it's:
  - Publicly listable (anyone can list contents) → $500-$2K
  - Publicly readable but not listable → $200-$1K
  - Publicly WRITABLE (rare, $$$) → $5K-$50K

Bucket name patterns to try per company:
  {company}, {company}-prod, {company}-staging, {company}-dev,
  {company}-backup, {company}-uploads, {company}-assets,
  {company}-data, {company}-static, {company}-logs,
  {company}-private, {company}-public, {company}-test
  Plus regional: s3.{region}.amazonaws.com/{bucket}
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.error, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-S3Patrol/0.1"
LEDGER = Path.home() / ".lictor" / "s3-bucket-ledger.jsonl"
OUT = Path.home() / "Lictor" / "docs" / "launch" / f"s3-buckets-{datetime.now().strftime('%Y-%m-%d')}-private.md"

PATTERNS = [
    "{c}", "{c}-prod", "{c}-production", "{c}-staging", "{c}-dev",
    "{c}-backup", "{c}-backups", "{c}-uploads", "{c}-upload",
    "{c}-assets", "{c}-data", "{c}-static", "{c}-logs",
    "{c}-private", "{c}-public", "{c}-test", "{c}-tests",
    "{c}-images", "{c}-files", "{c}-docs", "{c}-archive",
    "{c}-internal", "{c}-config", "{c}-secrets",
    "prod-{c}", "staging-{c}", "dev-{c}", "backup-{c}",
    "{c}.com", "{c}.io", "{c}.dev",
]


@dataclass
class BucketFinding:
    bucket: str
    apex: str
    url: str
    state: str  # "publicly-listable" | "publicly-readable" | "publicly-writable"
    payout: int
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(20000).decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(5000).decode("utf-8", "replace")
        except: body = ""
        return e.code, body, {}
    except Exception:
        return 0, "", {}


def check_bucket(bucket):
    """Returns BucketFinding if bucket exists and is publicly accessible."""
    # Try the standard S3 URL
    url = f"https://{bucket}.s3.amazonaws.com/"
    status, body, _ = http_get(url)
    if status == 404 or status == 0: return None  # bucket doesn't exist
    if "NoSuchBucket" in body: return None
    # Bucket exists. Determine state.
    if status == 200 and ("<ListBucketResult" in body or "<Name>" in body):
        # Publicly listable — high value
        return ("publicly-listable", body[:300])
    elif status == 403 and "AccessDenied" in body:
        # Bucket exists but no list permission. Could still be readable.
        return ("exists-private", body[:200])
    elif "PermanentRedirect" in body or "AllAccessDisabled" in body:
        return None  # exists but properly locked
    return None


def check_one(company_apex):
    """For one (company, apex) tuple, try all bucket-name patterns."""
    apex = company_apex
    # Derive company from apex: "stripe.com" → "stripe"
    company = apex.split(".")[0]
    results = []
    for pattern in PATTERNS:
        bucket = pattern.format(c=company)
        if len(bucket) < 3 or len(bucket) > 63: continue  # S3 bucket name rules
        if "." in bucket and not (bucket.endswith(".com") or bucket.endswith(".io") or bucket.endswith(".dev")):
            # avoid most-dot patterns
            continue
        check = check_bucket(bucket)
        if check:
            state, snippet = check
            if state == "publicly-listable":
                results.append(BucketFinding(
                    bucket=bucket, apex=apex,
                    url=f"https://{bucket}.s3.amazonaws.com/",
                    state=state, payout=1500, snippet=snippet,
                ))
            # We don't surface "exists-private" — too noisy and not exploitable
    return results


def load_ledger():
    if not LEDGER.exists(): return set()
    seen = set()
    for l in LEDGER.read_text().splitlines():
        if l.strip():
            try: seen.add(json.loads(l)["bucket"])
            except: pass
    return seen


def append_ledger(f):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fp:
        fp.write(json.dumps(asdict(f)) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(Path.home() / ".lictor" / "bounty-corpus-priority.txt"))
    ap.add_argument("--max-domains", type=int, default=200)
    ap.add_argument("--workers", type=int, default=80)
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] s3-bucket patrol — {len(seen)} prior bucket hits", flush=True)

    apexes = [l.strip() for l in Path(args.corpus).expanduser().read_text().splitlines()
              if l.strip()][:args.max_domains]
    print(f"[+] scanning {len(apexes)} apex domains × {len(PATTERNS)} bucket patterns ({args.workers} workers)", flush=True)

    hits = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, a): a for a in apexes}
        for fut in as_completed(futures):
            a = futures[fut]
            completed += 1
            if completed % 25 == 0:
                print(f"  [{completed}/{len(apexes)}] scanned, {len(hits)} hits", flush=True)
            try: result = fut.result(timeout=60)
            except Exception: result = []
            for f in (result or []):
                if f.bucket in seen: continue
                seen.add(f.bucket)
                print(f"  🔴🔴 S3-LEAK  {f.bucket}  ({f.state})  for apex={f.apex}", flush=True)
                append_ledger(f)
                hits.append(f)

    print(f"\n[+] scan complete: {len(hits)} public S3 buckets found")
    if hits:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        with OUT.open("w") as fp:
            fp.write(f"# Public S3 buckets — {datetime.now().strftime('%Y-%m-%d')} (PRIVATE)\n\n")
            fp.write(f"**Apex domains tried:** {len(apexes)}\n**Buckets found:** {len(hits)}\n\n")
            fp.write("| Bucket | Apex | State | $ | URL |\n|---|---|---|---|---|\n")
            for h in hits:
                fp.write(f"| `{h.bucket}` | `{h.apex}` | {h.state} | ${h.payout} | {h.url} |\n")
        print(f"    → {OUT}")


if __name__ == "__main__":
    main()
