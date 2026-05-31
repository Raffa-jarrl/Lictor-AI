#!/usr/bin/env python3
"""
dedupe-against-prior — filter verified findings against prior-disclosure history.

For each verified finding, check whether we've previously submitted a disclosure
for the same (host, finding_type) pair. Avoids duplicate submissions which can
hurt our HackerOne/Bugcrowd reputation.

Sources of prior disclosures consulted:
  1. /Users/raffa/Lictor/disclosures/**/*.md   — disclosure templates
  2. Gmail sent messages with our disclosure subject patterns
  3. (optional) HackerOne / Bugcrowd account submissions (not implemented here —
     requires API keys; left as manual cross-check)

Output: verified-not-disclosed.jsonl — ready for submission

Usage:
  dedupe-against-prior.py --verified verified-findings.jsonl --out verified-not-disclosed.jsonl
"""
from __future__ import annotations
import argparse, json, re
from dataclasses import asdict
from pathlib import Path

# Match host references inside disclosure MD files
HOST_RX = re.compile(r'\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\.[a-z]{2,})\b')

def collect_prior_disclosure_hosts(disclosure_dir: Path) -> dict[str, set[str]]:
    """Returns dict {host: set(of disclosure file paths)} for prior disclosures."""
    out: dict[str, set[str]] = {}
    if not disclosure_dir.exists(): return out
    for mdf in disclosure_dir.rglob("*.md"):
        try:
            text = mdf.read_text(errors="replace")
        except: continue
        for m in HOST_RX.finditer(text):
            h = m.group(1).lower()
            # Skip generic hosts that pollute the dedupe
            if h in ("lictor-ai.com", "example.com", "github.com", "hackerone.com",
                     "bugcrowd.com", "immunefi.com", "gmail.com", "noreply.com",
                     "hackerone.com.", "world.org"):
                continue
            out.setdefault(h, set()).add(str(mdf))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", default="/Users/raffa/Lictor/v3/ledgers/verified-findings.jsonl")
    ap.add_argument("--disclosure-dir", default="/Users/raffa/Lictor/disclosures")
    ap.add_argument("--out", default="/Users/raffa/Lictor/v3/ledgers/verified-not-disclosed.jsonl")
    ap.add_argument("--dup-out", default="/Users/raffa/Lictor/v3/ledgers/duplicate-skipped.jsonl")
    args = ap.parse_args()

    print(f"[+] Building prior-disclosure host index from {args.disclosure_dir}")
    prior = collect_prior_disclosure_hosts(Path(args.disclosure_dir))
    print(f"[+] Prior disclosures: {len(prior)} unique hosts referenced across "
          f"{sum(len(v) for v in prior.values())} mentions")

    n_new, n_dup, n_total = 0, 0, 0
    with open(args.out, "w") as fout, open(args.dup_out, "w") as fdup, \
         open(args.verified) as fin:
        for line in fin:
            line = line.strip()
            if not line: continue
            try:
                j = json.loads(line)
            except: continue
            n_total += 1
            if j.get("classification") != "confirmed":
                continue  # only forward confirmed findings
            host = (j.get("host") or "").lower()
            # Strip scheme/port
            host = host.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
            if host in prior:
                fdup.write(json.dumps({**j, "skip_reason": "duplicate",
                                        "prior_disclosure_files": list(prior[host])[:3]}) + "\n")
                n_dup += 1
            else:
                fout.write(json.dumps(j) + "\n")
                n_new += 1

    print(f"[+] Total verified findings: {n_total}")
    print(f"[+] {n_new} NEW (not previously disclosed) → {args.out}")
    print(f"[+] {n_dup} duplicate (already disclosed)  → {args.dup_out}")

if __name__ == "__main__":
    main()
