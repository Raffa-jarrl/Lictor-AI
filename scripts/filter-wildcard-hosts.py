#!/usr/bin/env python3
"""
filter-wildcard-hosts — strip wildcard-catch-all hosts from verified findings.

A wildcard-catch-all host responds 200 with the same content for ANY path. These
hosts generate massive false-positive waves across multiple scanner classes
(SSTI matches "64", debug-actuator matches /actuator/heapdump, etc.) but none
of those findings are real vulnerabilities.

Detection heuristic:
  - A host with >= N findings across >= M distinct (finding_type, path) pairs
    is likely a wildcard catch-all.
  - Plus an explicit allowlist of confirmed wildcards from manual review.

Output:
  - verified-cleaned.jsonl    (findings after wildcard exclusion)
  - wildcard-excluded.jsonl   (excluded findings, for audit)
  - wildcard-host-list.txt    (the hosts we excluded)

Usage:
  filter-wildcard-hosts.py --in verified-not-disclosed.jsonl
"""
from __future__ import annotations
import argparse, json
from collections import defaultdict
from pathlib import Path

# Explicit wildcards confirmed via manual spot-check (extend as needed)
EXPLICIT_WILDCARDS = {
    "aquiris.studio",
    "elasticon.co", "elasticon.com",
    "elasticbeats.wtf", "elasticcloud.wtf",
    "elasticloud.wtf", "elasticsearch.wtf",
    "kibana.wtf", "logstash.wtf",
    "kibana.tech", "logstash.tech",
}

def detect_wildcards(findings: list[dict], min_findings: int = 5,
                      min_distinct_paths: int = 3) -> set[str]:
    """Heuristic: hosts with many findings across many distinct (type, path) signatures."""
    by_host_sigs: dict[str, set[tuple]] = defaultdict(set)
    by_host_total: dict[str, int] = defaultdict(int)
    for f in findings:
        h = (f.get("host") or "").lower().strip()
        if not h: continue
        ft = f.get("finding_type", "")
        orig = f.get("original", {}) or {}
        path_sig = orig.get("path") or orig.get("endpoint") or orig.get("ep") or ""
        by_host_sigs[h].add((ft, path_sig))
        by_host_total[h] += 1
    wildcards = set()
    for host, sigs in by_host_sigs.items():
        if len(sigs) >= min_distinct_paths and by_host_total[host] >= min_findings:
            wildcards.add(host)
    return wildcards

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp",
                     default="/Users/raffa/Lictor/v3/ledgers/verified-not-disclosed.jsonl")
    ap.add_argument("--out-clean",
                     default="/Users/raffa/Lictor/v3/ledgers/verified-cleaned.jsonl")
    ap.add_argument("--out-excluded",
                     default="/Users/raffa/Lictor/v3/ledgers/wildcard-excluded.jsonl")
    ap.add_argument("--out-host-list",
                     default="/Users/raffa/Lictor/v3/ledgers/wildcard-host-list.txt")
    ap.add_argument("--min-findings", type=int, default=5)
    ap.add_argument("--min-paths", type=int, default=3)
    args = ap.parse_args()

    findings = []
    with open(args.inp) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: findings.append(json.loads(line))
            except: pass
    print(f"[+] Loaded {len(findings)} findings from {args.inp}")

    # Detect wildcards
    detected = detect_wildcards(findings, args.min_findings, args.min_paths)
    all_wildcards = detected | EXPLICIT_WILDCARDS
    print(f"[+] Wildcard hosts: {len(detected)} heuristic + {len(EXPLICIT_WILDCARDS)} explicit "
          f"= {len(all_wildcards)} total")

    Path(args.out_host_list).write_text("\n".join(sorted(all_wildcards)) + "\n")
    print(f"[+] Wildcard host list → {args.out_host_list}")
    print(f"    Hosts excluded:")
    for h in sorted(all_wildcards):
        print(f"      • {h}")

    n_kept, n_excluded = 0, 0
    with open(args.out_clean, "w") as fout, open(args.out_excluded, "w") as fexc:
        for f in findings:
            h = (f.get("host") or "").lower().strip()
            if h in all_wildcards:
                fexc.write(json.dumps(f) + "\n")
                n_excluded += 1
            else:
                fout.write(json.dumps(f) + "\n")
                n_kept += 1

    print(f"\n[+] Kept:     {n_kept:5d} → {args.out_clean}")
    print(f"[+] Excluded: {n_excluded:5d} → {args.out_excluded}")

    # Re-tally by finding_type
    from collections import Counter
    kept = []
    with open(args.out_clean) as f:
        for line in f:
            try: kept.append(json.loads(line))
            except: pass
    print(f"\n=== POST-FILTER breakdown ===")
    tally = Counter((k.get("finding_type", "?"), k.get("confidence", "?")) for k in kept)
    for (ft, conf), n in sorted(tally.items(), key=lambda x: -x[1]):
        print(f"  {ft:25s} {conf:8s} {n:5d}")

if __name__ == "__main__":
    main()
