#!/usr/bin/env python3
"""validate-defi-buckets.py — Content triage for listable DeFi buckets.

ETHICAL CONSTRAINTS:
- GET the public bucket listing only (same data that scanner already found)
- Parse XML to identify file types, sizes, sensitive-keyword names
- NEVER download individual file contents
- NEVER attempt authentication
- HEAD-only on at most 1 most-interesting file per bucket (for Content-Type)
- All findings stay private; no public publication

OUTPUTS:
- Triage report: which buckets contain sensitive-looking content vs CDN noise
- Estimated Immunefi web/app bounty tier per finding
- Ledger: /Users/raffa/Lictor/v3/ledgers/defi-bucket-triage.jsonl
"""
import json
import sys
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

LEDGER = Path.home() / "Lictor/v3/ledgers/defi-bucket-triage.jsonl"
USER_AGENT = "LictorAI-EthicalScanner/0.1 (+https://lictor-ai.com/transparency)"
TIMEOUT = 15

# Targets — Immunefi-listed protocols with their web/app bounty ceiling
TARGETS = [
    # (vendor, url, immunefi_web_max_bounty, immunefi_url)
    ("safe",       "https://storage.googleapis.com/safe-storage/",        100_000, "https://immunefi.com/bounty/safe/"),
    ("safe",       "https://storage.googleapis.com/safe-assets/",         100_000, "https://immunefi.com/bounty/safe/"),
    ("gnosis",     "https://storage.googleapis.com/gnosis-data/",         100_000, "https://immunefi.com/bounty/safe/"),
    ("compound",   "https://compound.s3.amazonaws.com/",                  100_000, "https://immunefi.com/bounty/compound/"),
    ("compound",   "https://storage.googleapis.com/compound-public/",     100_000, "https://immunefi.com/bounty/compound/"),
    ("polygon",    "https://storage.googleapis.com/polygon/",             100_000, "https://immunefi.com/bounty/polygon/"),
    ("kyber",      "https://storage.googleapis.com/kyber-staging/",        50_000, "https://immunefi.com/bounty/kybernetwork/"),
    ("synthetix",  "https://synthetix-files.s3.amazonaws.com/",            50_000, "https://immunefi.com/bounty/synthetix/"),
    ("balancer",   "https://storage.googleapis.com/balancer-assets/",      50_000, "https://immunefi.com/bounty/balancer/"),
    ("curve",      "https://curve-public.s3.amazonaws.com/",               50_000, "https://immunefi.com/bounty/curvefinance/"),
    ("blast",      "https://blast.s3.amazonaws.com/",                      50_000, "https://immunefi.com/bounty/blast/"),
    ("maple",      "https://storage.googleapis.com/maple-production/",     25_000, "https://immunefi.com/bounty/maplefinance/"),
    ("maple",      "https://storage.googleapis.com/maple-assets/",         25_000, "https://immunefi.com/bounty/maplefinance/"),
    ("centrifuge", "https://centrifuge-dev.s3.amazonaws.com/",             25_000, "https://immunefi.com/bounty/centrifuge/"),
    ("lyra",       "https://lyra-public.nyc3.digitaloceanspaces.com/",     25_000, "https://immunefi.com/bounty/lyrafinance/"),
]

# Keywords in filenames that suggest sensitive content
SENSITIVE_KEYWORDS = [
    ".env", ".key", ".pem", ".pgp", ".p12", ".pfx", ".jks",
    "_key", "_secret", "_token", "_credentials", "_password",
    "config.json", "config.yaml", "config.yml",
    "backup", "dump", "export",
    ".sql", ".db", ".sqlite",
    "private", "internal",
    "deployer", "deploy.json", "deployments.json",
    "wallet", "mnemonic", "keystore",
    ".bak", ".backup",
    "secrets.", "credentials.",
    "service-account", "service_account",
    "production", "prod-", "-prod",  # often interesting in operational buckets
]

# Suffix → category for content classification
EXT_CATEGORY = {
    # CDN / asset junk (low value)
    "css": "cdn-asset", "js": "cdn-asset", "map": "sourcemap",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image",
    "svg": "image", "webp": "image", "ico": "image",
    "woff": "font", "woff2": "font", "ttf": "font", "otf": "font",
    "html": "html", "htm": "html",
    "mp4": "media", "webm": "media", "mp3": "media", "ogg": "media",
    "pdf": "pdf",
    "txt": "text",

    # Potentially interesting
    "json": "json-config",
    "yaml": "yaml-config", "yml": "yaml-config",
    "xml": "xml-config",
    "csv": "data", "tsv": "data",
    "sql": "DATABASE-DUMP",
    "db": "DATABASE-DUMP", "sqlite": "DATABASE-DUMP",

    # High-value (red flag)
    "env": "ENV-FILE",
    "key": "KEY-FILE",
    "pem": "CERT-OR-KEY",
    "p12": "CERT-OR-KEY",
    "pfx": "CERT-OR-KEY",
    "bak": "BACKUP",
    "backup": "BACKUP",
    "tar": "ARCHIVE", "gz": "ARCHIVE", "zip": "ARCHIVE", "tgz": "ARCHIVE",
    "log": "LOG-FILE",  # often operational
}


def fetch_listing(url):
    """GET the bucket listing XML. Returns (body, status, error)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read(), resp.status, None
    except urllib.error.HTTPError as e:
        return None, e.code, str(e)
    except Exception as e:
        return None, 0, str(e)


def parse_s3_xml(body):
    """Parse S3-compatible bucket listing XML.
    Returns list of {key, size, last_modified} for each file."""
    files = []
    try:
        # Strip XML namespace declarations (handle both single + double quotes,
        # GCS/S3/DO Spaces all use slightly different namespace formats)
        body_str = body.decode("utf-8", errors="replace")
        import re
        body_str = re.sub(r"\sxmlns=['\"][^'\"]+['\"]", "", body_str)
        body_str = re.sub(r"\sxmlns:\w+=['\"][^'\"]+['\"]", "", body_str)

        root = ET.fromstring(body_str)
        is_truncated = (root.findtext("IsTruncated", "false").lower() == "true")
        for content in root.findall("Contents"):
            key = content.findtext("Key", "")
            size = int(content.findtext("Size", "0") or 0)
            last_mod = content.findtext("LastModified", "")
            files.append({"key": key, "size": size, "last_modified": last_mod})
        return files, is_truncated
    except ET.ParseError as e:
        return [], False
    except Exception as e:
        return [], False


def classify_files(files):
    """Triage: identify sensitive content vs CDN noise."""
    sensitive_hits = []
    category_counts = Counter()
    total_size = 0
    largest_file = {"key": "", "size": 0}

    for f in files:
        key = f["key"]
        size = f["size"]
        total_size += size

        if size > largest_file["size"]:
            largest_file = f

        # Sensitive keyword check
        key_lower = key.lower()
        for kw in SENSITIVE_KEYWORDS:
            if kw in key_lower:
                sensitive_hits.append({
                    "key": key,
                    "size": size,
                    "keyword": kw,
                    "last_modified": f.get("last_modified", ""),
                })
                break

        # Category by extension
        ext = key.rsplit(".", 1)[-1].lower() if "." in key else "no-ext"
        category_counts[EXT_CATEGORY.get(ext, "other")] += 1

    return {
        "total_files": len(files),
        "total_size_bytes": total_size,
        "total_size_human": human_size(total_size),
        "category_counts": dict(category_counts.most_common()),
        "largest_file": {**largest_file, "size_human": human_size(largest_file["size"])},
        "sensitive_hits": sensitive_hits[:25],  # cap at 25
        "sensitive_hit_count": len(sensitive_hits),
    }


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def severity_assessment(triage, max_bounty):
    """Assess potential bounty value based on triage."""
    hits = triage["sensitive_hit_count"]
    cats = triage["category_counts"]

    # Red flags
    has_dump = any(cat in cats for cat in ["DATABASE-DUMP", "BACKUP", "ARCHIVE"])
    has_creds = any(cat in cats for cat in ["ENV-FILE", "KEY-FILE", "CERT-OR-KEY"])
    has_config = "json-config" in cats or "yaml-config" in cats
    has_logs = "LOG-FILE" in cats

    if has_dump or has_creds or hits >= 5:
        return "RED-FLAG", f"likely ${int(max_bounty * 0.5):,}-${max_bounty:,} bounty if validated"
    if has_logs or has_config or hits >= 1:
        return "INVESTIGATE", f"possible ${int(max_bounty * 0.1):,}-${int(max_bounty * 0.5):,} bounty if config has secrets"
    if cats.get("cdn-asset", 0) > 0.8 * triage["total_files"] and hits == 0:
        return "CDN-ONLY", "$0-$2,000 (likely intentional public CDN)"
    return "AMBIGUOUS", "$0-$5,000 (needs deeper triage)"


def main():
    print(f"[+] Validating {len(TARGETS)} listable DeFi buckets (GET-listing only, no downloads)")
    print(f"[+] Ledger: {LEDGER}")
    print()

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    results = []

    for i, (vendor, url, max_bounty, immunefi_url) in enumerate(TARGETS, 1):
        print(f"[{i:>2}/{len(TARGETS)}] {vendor:<12} → {url}")
        body, status, err = fetch_listing(url)

        if status != 200 or body is None:
            print(f"          [FAIL] status={status} err={err[:80] if err else ''}")
            entry = {
                "vendor": vendor, "url": url, "status": status,
                "max_bounty": max_bounty, "immunefi_url": immunefi_url,
                "error": err, "validated_at": datetime.now(timezone.utc).isoformat(),
            }
            results.append(entry)
            with open(LEDGER, "a") as f:
                f.write(json.dumps(entry) + "\n")
            continue

        files, truncated = parse_s3_xml(body)
        triage = classify_files(files)
        severity, est = severity_assessment(triage, max_bounty)

        entry = {
            "vendor": vendor,
            "url": url,
            "status": status,
            "max_bounty": max_bounty,
            "immunefi_url": immunefi_url,
            "severity": severity,
            "estimate": est,
            "triage": triage,
            "truncated": truncated,
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
        results.append(entry)

        with open(LEDGER, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Print summary
        print(f"          [OK]  {triage['total_files']:>5} files  |  {triage['total_size_human']:>10}  |  {severity}")
        print(f"          categories: {dict(list(triage['category_counts'].items())[:5])}")
        if triage["sensitive_hits"]:
            print(f"          🔥 {triage['sensitive_hit_count']} sensitive-keyword hits, top samples:")
            for h in triage["sensitive_hits"][:3]:
                print(f"             - {h['key'][:80]} ({human_size(h['size'])})")
        if truncated:
            print(f"          ⚠️  listing truncated (>1000 objects, only first page sampled)")
        print(f"          → {est}")
        print()

    # Final summary
    print("=" * 80)
    print("TRIAGE SUMMARY")
    print("=" * 80)
    by_severity = defaultdict(list)
    for r in results:
        if r.get("severity"):
            by_severity[r["severity"]].append(r)

    for sev in ["RED-FLAG", "INVESTIGATE", "AMBIGUOUS", "CDN-ONLY"]:
        if sev in by_severity:
            print(f"\n[{sev}] {len(by_severity[sev])} bucket(s)")
            for r in by_severity[sev]:
                print(f"  - {r['vendor']:<12} ${r['max_bounty']:,} max → {r['url']}")

    print(f"\n[+] Full ledger: {LEDGER}")
    print(f"[+] Done. {len(results)} buckets validated.")


if __name__ == "__main__":
    main()
