#!/usr/bin/env python3
"""
patrol-cloud-blobs — scanner #27.

Brute-forces likely Azure Storage / GCP Cloud Storage / DigitalOcean
Spaces bucket names for each bounty-program apex. Same approach as S3
scanner but covers the THREE other major blob storage providers that
researchers often skip.

For each found public-listable bucket, returns the actual listing
(XML or JSON) as self-evident proof.

Providers:
  - Azure Storage: https://{name}.blob.core.windows.net/?comp=list
  - GCP Storage:   https://storage.googleapis.com/{name}?delimiter=
  - DO Spaces:     https://{name}.{region}.digitaloceanspaces.com/

Bounty payouts: $200-$2K for public-listable buckets with actual sensitive content.
"""
from __future__ import annotations
import argparse, json, re, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-CloudBlobPatrol/0.1"
LEDGER = Path.home() / ".lictor" / "cloud-blob-ledger.jsonl"

# Bucket name patterns to try per company
PATTERNS = [
    "{c}", "{c}-prod", "{c}-production", "{c}-staging", "{c}-dev",
    "{c}-backup", "{c}-backups", "{c}-uploads", "{c}-data",
    "{c}-assets", "{c}-static", "{c}-logs", "{c}-internal",
    "{c}-private", "{c}-public", "{c}-images", "{c}-files",
    "{c}-archive", "{c}-config", "{c}storage",
    "prod-{c}", "staging-{c}", "dev-{c}", "backup-{c}",
]

DO_REGIONS = ["nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1", "blr1"]

LISTING_SIGNS_XML = re.compile(rb'<EnumerationResults|<ListBucketResult|<Contents>|<Blob>')
LISTING_SIGNS_JSON = re.compile(rb'"items"\s*:\s*\[|"kind"\s*:\s*"storage')


@dataclass
class BlobFinding:
    provider: str        # "azure" | "gcp" | "digitalocean"
    bucket: str
    apex: str
    url: str
    state: str           # "publicly-listable"
    item_count: int      # approximate
    payout: int
    snippet: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, timeout=5):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8000)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


def check_azure(name):
    """Returns BlobFinding if publicly-listable, else None."""
    url = f"https://{name}.blob.core.windows.net/?comp=list&maxresults=10"
    status, body = http_get(url, timeout=5)
    if status != 200 or not body: return None
    if LISTING_SIGNS_XML.search(body):
        items = body.count(b"<Container>") or body.count(b"<Blob>")
        return ("publicly-listable", items, body[:300])
    return None


def check_gcp(name):
    url = f"https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=10"
    status, body = http_get(url, timeout=5)
    if status != 200 or not body: return None
    if LISTING_SIGNS_JSON.search(body):
        items = body.count(b'"id":') or body.count(b'"name":')
        return ("publicly-listable", items, body[:300])
    return None


def check_do(name):
    """DO Spaces — try a few common regions."""
    for region in DO_REGIONS[:3]:  # try top 3 regions for speed
        url = f"https://{name}.{region}.digitaloceanspaces.com/"
        status, body = http_get(url, timeout=5)
        if status != 200 or not body: continue
        if LISTING_SIGNS_XML.search(body):
            items = body.count(b"<Contents>") or body.count(b"<Key>")
            return (f"publicly-listable-{region}", items, body[:300])
    return None


PROVIDERS = [("azure", check_azure), ("gcp", check_gcp), ("digitalocean", check_do)]


def check_one(provider_name_pattern):
    provider, check_fn, name, apex = provider_name_pattern
    if len(name) < 3 or len(name) > 63: return None
    # Provider-specific naming validation
    if provider == "azure" and not re.match(r'^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$', name): return None
    if not re.match(r'^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$', name): return None
    try:
        result = check_fn(name)
    except Exception:
        return None
    if not result: return None
    state, items, snippet = result
    try:
        snippet_str = snippet.decode("utf-8", "replace").replace("\n"," ").replace("\r","")[:200]
    except: snippet_str = ""
    payout = 500 if items > 5 else 200
    return BlobFinding(
        provider=provider, bucket=name, apex=apex,
        url=f"({provider}) {name}",
        state=state, item_count=items, payout=payout,
        snippet=snippet_str,
    )


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
    print(f"[+] cloud-blob patrol — {len(apexes)} apex × {len(PATTERNS)} patterns × {len(PROVIDERS)} providers", flush=True)

    tasks = []
    for apex in apexes:
        company = apex.split(".")[0]
        for pattern in PATTERNS:
            name = pattern.format(c=company)
            for provider, fn in PROVIDERS:
                tasks.append((provider, fn, name, apex))
    print(f"[+] total probes: {len(tasks)}", flush=True)

    hits = []
    seen = set()
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_one, t): t for t in tasks}
        for fut in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(tasks)}] {len(hits)} hits", flush=True)
            try: r = fut.result(timeout=10)
            except: r = None
            if r:
                key = f"{r.provider}|{r.bucket}"
                if key in seen: continue
                seen.add(key)
                print(f"  🔴🔴 CLOUD-BLOB-{r.provider.upper()}  {r.bucket}  ({r.item_count} items) → {r.apex}  (${r.payout})", flush=True)
                append_ledger(r)
                hits.append(r)

    print(f"\n[+] scan complete: {len(hits)} cloud-blob exposures")


if __name__ == "__main__": main()
