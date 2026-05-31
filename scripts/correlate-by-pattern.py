#!/usr/bin/env python3
"""
correlate-by-pattern — group verified findings by root-cause pattern.

Given verified findings across many hosts, identify clusters where the same
underlying issue affects multiple hosts. These often indicate:

  - A vendor whose default config exposes Spring Boot Actuator
    (all customers of vendor X are affected → bulk disclosure to vendor X)
  - A platform-level template / framework default
    (all Heroku apps with default config X expose Y)
  - A specific apex domain with many affected subdomains
    (rather than 20 individual disclosures, ONE disclosure to the parent org)

Output: clustered-findings.json — grouped findings ready for strategic disclosure.

Cluster keys we look for:
  - Same apex domain  (admin.foo.com, dashboard.foo.com → cluster on foo.com)
  - Same vendor stack (X-Powered-By, Server header pattern)
  - Same hosting     (Vercel / Netlify / Fastly / Heroku CDN cname)
  - Same finding+path  (e.g. /actuator/env across 50 hosts = Spring Boot vendor pattern)

Usage:
  correlate-by-pattern.py --verified verified-not-disclosed.jsonl --out clustered.json
"""
from __future__ import annotations
import argparse, json, re
from collections import defaultdict
from pathlib import Path

def apex_of(host: str) -> str:
    """Naive apex extractor — last 2 labels for common TLDs, last 3 for .co.uk/etc."""
    parts = host.lower().split(".")
    if len(parts) < 2: return host
    # Country-code 2nd-level: .co.uk, .com.au, .co.il, etc.
    second_levels = {("co","uk"), ("com","au"), ("co","il"), ("co","jp"),
                     ("co","nz"), ("com","br"), ("co","in"), ("com","mx")}
    if len(parts) >= 3 and (parts[-2], parts[-1]) in second_levels:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", default="/Users/raffa/Lictor/v3/ledgers/verified-not-disclosed.jsonl")
    ap.add_argument("--out", default="/Users/raffa/Lictor/v3/ledgers/clustered-findings.json")
    args = ap.parse_args()

    findings = []
    with open(args.verified) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: findings.append(json.loads(line))
            except: pass
    print(f"[+] Loaded {len(findings)} verified-not-disclosed findings")

    # Cluster 1: by apex domain
    by_apex: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        h = (f.get("host") or "").lower().replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        by_apex[apex_of(h)].append(f)

    # Cluster 2: by (finding_type, path) signature — indicates vendor/framework default
    by_signature: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        ft = f.get("finding_type", "")
        orig = f.get("original", {}) or {}
        # Pick a stable path/signature per finding type
        sig = orig.get("path") or orig.get("endpoint") or orig.get("ep") \
              or orig.get("manifest_path") or ""
        if sig: by_signature[f"{ft}::{sig}"].append(f)

    # Build output
    clusters = {
        "by_apex": {k: v for k, v in by_apex.items() if len(v) >= 2},  # only multi-finding apexes
        "by_signature": {k: v for k, v in by_signature.items() if len(v) >= 2},
        "singletons": [],  # findings that didn't cluster
    }

    # Track singletons (findings that are unique on both axes)
    clustered_hosts = set()
    for v in clusters["by_apex"].values():
        for f in v: clustered_hosts.add(id(f))
    for v in clusters["by_signature"].values():
        for f in v: clustered_hosts.add(id(f))
    clusters["singletons"] = [f for f in findings if id(f) not in clustered_hosts]

    # Summary
    print(f"\n=== CLUSTER SUMMARY ===")
    print(f"Apex-based clusters: {len(clusters['by_apex'])} (≥2 findings per apex)")
    for apex, fs in sorted(clusters["by_apex"].items(), key=lambda x: -len(x[1]))[:10]:
        types = sorted(set(f.get("finding_type","") for f in fs))
        print(f"  • {apex} — {len(fs)} findings ({', '.join(types[:4])})")
    print(f"\nSignature-based clusters: {len(clusters['by_signature'])} (vendor/framework defaults)")
    for sig, fs in sorted(clusters["by_signature"].items(), key=lambda x: -len(x[1]))[:10]:
        hosts = sorted(set(f.get("host","") for f in fs))[:3]
        print(f"  • {sig} — {len(fs)} hosts ({', '.join(hosts)}…)")
    print(f"\nSingletons (no cluster): {len(clusters['singletons'])}")

    # Write output as JSON (not JSONL — clusters are nested)
    Path(args.out).write_text(json.dumps(clusters, indent=2, default=str))
    print(f"\n[+] Written → {args.out}")
    print(f"[+] STRATEGY:")
    print(f"    Apex clusters (≥2 findings on same domain) → submit as ONE bulk disclosure to that org")
    print(f"    Signature clusters (same finding+path across hosts) → indicates vendor-default; alert vendor + each customer")
    print(f"    Singletons → individual per-host disclosure")

if __name__ == "__main__":
    main()
