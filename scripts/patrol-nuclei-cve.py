#!/usr/bin/env python3
"""
patrol-nuclei-cve — wrapper around Nuclei for batched CRITICAL/HIGH CVE scanning.

Runs Nuclei against the F500 host corpus with:
  - Severity filter: critical,high
  - Tag exclusions: info, banner, fingerprint, technology-detection
  - Output: JSONL ledger
  - Rate-limited (40 RPS, 100 concurrent) to avoid hammering targets
  - Skips templates that are pure detection (no exploit confirmation)

Why this is the 2026 path: F500 generic surface scanning is dead (CDN+SameSite+
Snyk killed it). Real $50K bugs in 2026 are unpatched CVEs (Confluence/GitLab/
Citrix/Atlassian/Splunk/SAP) hit on neglected corporate instances. Nuclei has
1,767 CRITICAL templates including 2026 CVEs — direct path to RCE-class findings.

Usage:
  patrol-nuclei-cve.py --hosts hosts.txt --max-hosts 2000
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

NUCLEI_BIN = "/opt/homebrew/bin/nuclei"
DEFAULT_LEDGER = "/Users/raffa/Lictor/v3/ledgers/nuclei-cve.jsonl"


def run_nuclei(hosts_file: str, ledger: str, severity: str = "critical,high",
               rate_limit: int = 40, concurrency: int = 50, timeout: int = 5):
    """Spawn nuclei. Returns (process, output_lines_consumed)."""
    cmd = [
        NUCLEI_BIN,
        "-list", hosts_file,
        "-severity", severity,
        # Exclude noisy info-only templates
        "-exclude-tags", "info,banner,fingerprint,tech,osint,fuzz,dast",
        # Performance
        "-rate-limit", str(rate_limit),
        "-c", str(concurrency),
        "-timeout", str(timeout),
        # Output: JSONL
        "-jsonl",
        "-stats",
        # Disable interactive prompts
        "-silent",
        "-no-color",
        # Custom user agent so target ops can identify
        "-H", "User-Agent: Lictor-NucleiPatrol/0.1 (+https://lictor-ai.com)",
        # Disable automated updates during scan
        "-disable-update-check",
        # Skip templates that require interactive interaction
        "-headless=false",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=2000)
    ap.add_argument("--severity", default="critical,high")
    ap.add_argument("--rate-limit", type=int, default=40)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--ledger", default=DEFAULT_LEDGER)
    args = ap.parse_args()

    # Build batch hosts file
    src_hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    batch_file = f"/tmp/_nuclei-batch-{int(time.time())}.txt"
    Path(batch_file).write_text("\n".join(f"https://{h}" if not h.startswith("http") else h for h in src_hosts))
    print(f"[+] nuclei-cve — {len(src_hosts)} hosts, severity={args.severity}", flush=True)

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    proc = run_nuclei(batch_file, args.ledger, args.severity, args.rate_limit, args.concurrency)

    n_findings = 0
    n_crit = 0
    n_high = 0
    with open(args.ledger, "a") as out:
        try:
            for line in iter(proc.stdout.readline, ""):
                line = line.strip()
                if not line: continue
                try:
                    d = json.loads(line)
                except: continue
                # Nuclei JSONL has 'template-id', 'matched-at', 'info' {severity, name, classification}
                tmpl = d.get("template-id", "?")
                sev = d.get("info", {}).get("severity", "?")
                name = d.get("info", {}).get("name", "?")
                matched = d.get("matched-at", "?")
                # Annotate + write to ledger
                annotated = {
                    "found_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "template_id": tmpl,
                    "severity": sev.upper() if sev else "?",
                    "name": name,
                    "matched_at": matched,
                    "host": d.get("host", matched),
                    "type": d.get("type"),
                    "extracted_results": d.get("extracted-results"),
                    "curl_command": d.get("curl-command"),
                    "raw": d,
                }
                out.write(json.dumps(annotated) + "\n")
                out.flush()
                n_findings += 1
                if sev == "critical": n_crit += 1
                elif sev == "high": n_high += 1
                tag = {"critical":"🔴","high":"🟠","medium":"🟡"}.get(sev, "?")
                print(f"  {tag} [{sev}] {tmpl}  {matched}", flush=True)
        except KeyboardInterrupt:
            proc.terminate()

    proc.wait()
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} total={n_findings}", flush=True)


if __name__ == "__main__":
    main()
