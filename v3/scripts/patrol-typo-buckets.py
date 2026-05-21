#!/usr/bin/env python3
"""
Lictor v3 — typo-bucket scanner (the "atlassian-backup" class generator)

Tonight's mega-finding was gs://atlassian-backup — a publicly listable
~58GB GCS bucket of self-hosted Atlassian customer's database backups.
The bucket name had a TYPO ('atlassain' inside filenames) that's exactly
why it wasn't already known to the security community.

This scanner generates plausible typo'd bucket names for major
self-hosted enterprise software vendors and probes for them on AWS S3,
GCS, DigitalOcean Spaces, and Azure Blob Storage. The hypothesis:
self-hosters typo bucket names ALL THE TIME, and these typo'd buckets
escape standard "vendor-name brute" scanners.

Vendors covered (each gets 10-30 typo variants):
  - atlassian (atlassain, attlasian, atlsasian, attlassian, atlassion, ...)
  - gitlab (gitlb, gitlabs, gitlb, gtilab, ...)
  - jenkins (jenkns, jeenkins, jnkins, jenkinns, ...)
  - kubernetes (kubernets, kuberntes, kuberenetes, k8s, kubrnetes, ...)
  - elasticsearch (elastcsearch, elasticserch, esearch, ...)
  - postgres (postgress, postres, pgsql, postgress, ...)
  - mongodb (mongdb, monogo, mongbd, mngdb, mngo, ...)
  - splunk (spunk, splnk, splnkr, ...)
  - artifactory (artfactory, artifctory, artifacty, ...)
  - nexus (nxus, nexs, nexux, ...)
  - prometheus (prometeus, promethus, prometheous, ...)
  - grafana (grfana, grafna, grafanna, ...)

For each typo'd name, suffix with common backup/data patterns:
  -backup, -backups, -data, -db, -database, -dump, -snapshot,
  -prod, -production, -staging, -dev, -archive

Provider URL patterns probed:
  AWS S3:        https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1
  AWS S3 alt:    https://s3.amazonaws.com/{name}/?list-type=2&max-keys=1
  GCS:           https://storage.googleapis.com/{name}/?list-type=2&max-keys=1
  Azure Blob:    https://{name}.blob.core.windows.net/?restype=container&comp=list&maxresults=1
  DO Spaces:     https://{name}.nyc3.digitaloceanspaces.com/?list-type=2&max-keys=1
                 https://{name}.sfo3.digitaloceanspaces.com/?list-type=2&max-keys=1

Signal:
  - HTTP 200 + XML body with <ListBucketResult> AND any <Contents> → publicly listable
  - Look for branding hints in the first file Key (e.g. "atlassain_*", "_backup_")

Output to ledgers/typo-bucket-candidates.jsonl for Owl review.

Usage:
  python3 patrol-typo-buckets.py                    # all vendors, all suffixes, all providers
  python3 patrol-typo-buckets.py --vendor atlassian # one vendor only
  python3 patrol-typo-buckets.py --workers 30
"""
from __future__ import annotations
import argparse, json, re, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-TypoBucket/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "typo-bucket-candidates.jsonl"

# Vendor → list of typo variants (manually curated common misspellings)
VENDOR_TYPOS = {
    "atlassian": ["atlassain", "attlasian", "atlsasian", "attlassian", "atlassion", "atalssian", "atlasian", "altassian", "atlissian"],
    "gitlab":    ["gitlb", "gitlabs", "gtilab", "gtlab", "gilab", "gtilbab"],
    "jenkins":   ["jenkns", "jeenkins", "jnkins", "jenkinns", "jenkis", "jenins"],
    "kubernetes":["kubernets", "kuberntes", "kuberenetes", "kubrnetes", "kuberntes", "k8s"],
    "elasticsearch": ["elastcsearch", "elasticserch", "elastiserch", "elasticsearch", "esearch", "elasticseach"],
    "postgres":  ["postgress", "postres", "postgress", "postrges", "potgres"],
    "mongodb":   ["mongdb", "mongbd", "monogo", "monodb", "mongoo", "mngo"],
    "splunk":    ["spunk", "splnk", "splnkr", "splnks", "splnks", "splunks"],
    "artifactory":["artfactory", "artifctory", "artifacty", "artifactry", "artifctry"],
    "nexus":     ["nxus", "nexs", "nexux", "nexs", "nexuss"],
    "prometheus":["prometeus", "promethus", "prometheous", "prometeus", "promethes"],
    "grafana":   ["grfana", "grafna", "grafanna", "grafanaa", "grafan"],
    "jira":      ["jria", "jria", "jirra", "jiraa", "jirah"],
    "confluence":["conflunce", "confleunce", "confluence", "confulence", "conflueence", "conflug"],
    "bitbucket": ["bitbuket", "bitbukcet", "bitbuckt", "bitbckt"],
    "sonatype":  ["sontype", "sonatipe", "sonarype"],
    "redis":     ["reedis", "rdis", "redis"],
    "rabbitmq":  ["rbbitmq", "rabittmq", "rabbtmq"],
}

# Suffixes that strongly indicate data/backup buckets
SUFFIXES = ["-backup", "-backups", "-data", "-db", "-database", "-dump", "-snapshot",
            "-prod", "-production", "-staging", "-dev", "-archive", "-archives",
            "-storage", ""]

# Providers + URL templates
PROVIDERS = [
    ("aws-s3",          "https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1"),
    ("aws-s3-alt",      "https://s3.amazonaws.com/{name}/?list-type=2&max-keys=1"),
    ("gcs",             "https://storage.googleapis.com/{name}/?list-type=2&max-keys=1"),
    ("azure-blob",      "https://{name}.blob.core.windows.net/?restype=container&comp=list&maxresults=1"),
    ("do-spaces-nyc3",  "https://{name}.nyc3.digitaloceanspaces.com/?list-type=2&max-keys=1"),
    ("do-spaces-sfo3",  "https://{name}.sfo3.digitaloceanspaces.com/?list-type=2&max-keys=1"),
]


def _fetch(url: str, timeout: int = 5) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _check_bucket(provider: str, url_template: str, bucket_name: str) -> dict | None:
    """Probe one bucket. Return finding dict if publicly listable with at least 1 file."""
    url = url_template.format(name=bucket_name)
    status, body = _fetch(url)
    if status != 200:
        return None
    if "<ListBucketResult" not in body and "<EnumerationResults" not in body:
        return None  # not an S3/Azure listing response
    # Extract keys
    keys = re.findall(r'<(?:Key|Name)>([^<]+)</(?:Key|Name)>', body)
    # Filter out the bucket name itself (S3 includes the name as first <Name>)
    keys = [k for k in keys if k != bucket_name]
    if not keys:
        return None  # empty bucket, no signal value
    return {
        "provider": provider,
        "bucket": bucket_name,
        "url": url,
        "status": status,
        "sample_keys": keys[:5],
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _generate_names(vendors: list[str]) -> list[str]:
    """Generate (vendor-typo + suffix) combinations."""
    names = set()
    for vendor in vendors:
        if vendor not in VENDOR_TYPOS:
            print(f"  ⚠️  No typo dict for vendor '{vendor}', using as-is")
            for sfx in SUFFIXES:
                names.add(vendor + sfx)
            continue
        # Include the correct spelling + every typo
        all_variants = [vendor] + VENDOR_TYPOS[vendor]
        for variant in all_variants:
            for sfx in SUFFIXES:
                names.add(variant + sfx)
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", help="Only probe one vendor's typos (e.g. 'atlassian')")
    ap.add_argument("--workers", type=int, default=20)
    args = ap.parse_args()

    vendors = [args.vendor] if args.vendor else list(VENDOR_TYPOS.keys())
    names = _generate_names(vendors)
    print(f"[+] Generated {len(names)} candidate bucket names from {len(vendors)} vendors", flush=True)
    print(f"[+] Probing across {len(PROVIDERS)} providers = {len(names) * len(PROVIDERS)} total probes", flush=True)

    jobs = [(provider, tmpl, name) for (provider, tmpl) in PROVIDERS for name in names]
    findings = []
    completed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_check_bucket, p, t, n): (p, n) for p, t, n in jobs}
        for fut in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"  [{completed}/{len(jobs)}] checked, {len(findings)} hits so far", flush=True)
            try:
                result = fut.result(timeout=20)
            except Exception:
                continue
            if result:
                provider = result["provider"]
                bucket = result["bucket"]
                keys = result["sample_keys"]
                print(f"  🟡 BUCKET-HIT  {provider}://{bucket}  ({len(keys)} keys: {', '.join(k[:40] for k in keys[:2])})", flush=True)
                findings.append(result)

    print(f"\n[+] scan complete: {len(findings)} publicly-listable typo buckets found", flush=True)

    if findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(findings)} entries to {LEDGER}", flush=True)


if __name__ == "__main__":
    main()
