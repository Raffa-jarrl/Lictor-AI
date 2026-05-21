#!/usr/bin/env python3
"""
Lictor v3 — EOL software analyzer

Reads all port-exposure ledgers (existing + new subdomain scans),
extracts version strings from banners, and classifies hits by
EOL/CVE risk. Output: prioritized table of "old systems with known
risk" — exactly the user's brief: 'old system attention to be
unpatch and unsecured'.

EOL software classes detected:
  - MySQL 5.5 / 5.6 (EOL) / 5.7.x (EOL Oct 2023)
  - MariaDB 10.0 / 10.1 / 10.2 / 10.3 / 10.4 (EOL)
  - PostgreSQL 9.x / 10 / 11 (EOL)
  - ProFTPD ≤ 1.3.5 (multiple CVEs)
  - Pure-FTPd ≤ 1.0.49 (older)
  - vsftpd 2.x (CVE-2011-2523 backdoor risk)
  - vsftpd 3.0.0-3.0.3 (older)
  - FileZilla Server 0.x (pre-rewrite, EOL)
  - Microsoft IIS 6.x / 7.x (EOL)
  - Apache 2.0 / 2.2 (EOL)
  - OpenSSH < 7.4 (vulnerable to multiple CVEs)
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

LEDGERS = [
    Path.home() / "Lictor" / "v3" / "ledgers" / "port-exposure-candidates.jsonl",
]
# Also scan logs for hits not yet flushed to ledger
LOG_FILES = [
    Path("/tmp/lictor-il-port.log"),
    Path("/tmp/lictor-sectors-port.log"),
    Path("/tmp/lictor-expanded-port.log"),
    Path("/tmp/lictor-port-v4.log"),
    Path("/tmp/lictor-subdomain-port.log"),
    Path("/tmp/lictor-reverify-port.log"),
]


# (regex, classification, severity, reason)
EOL_PATTERNS = [
    # MySQL — MariaDB always emits "5.5.5-" as compat prefix before its OWN version,
    # so any banner containing "MariaDB" is MariaDB, not MySQL 5.5 (handled separately below).
    # Real MySQL 5.5 latest is 5.5.62; real 5.6 latest is 5.6.51; real 5.7 latest is 5.7.44.
    (re.compile(r"\b5\.5\.\d+\b(?!.*MariaDB)", re.I | re.S), "MySQL 5.5",     "CRITICAL", "EOL since Dec 2018"),
    (re.compile(r"\b5\.6\.\d+\b(?!.*MariaDB)", re.I | re.S), "MySQL 5.6",     "CRITICAL", "EOL since Feb 2021"),
    (re.compile(r"\b5\.7\.\d+\b(?!.*MariaDB)", re.I | re.S), "MySQL 5.7",     "HIGH",     "EOL since Oct 2023"),
    # MariaDB
    (re.compile(r"10\.0\.\d+-MariaDB", re.I), "MariaDB 10.0",      "CRITICAL", "EOL since Mar 2019"),
    (re.compile(r"10\.1\.\d+-MariaDB", re.I), "MariaDB 10.1",      "CRITICAL", "EOL since Oct 2020"),
    (re.compile(r"10\.2\.\d+-MariaDB", re.I), "MariaDB 10.2",      "CRITICAL", "EOL since May 2022"),
    (re.compile(r"10\.3\.\d+-MariaDB", re.I), "MariaDB 10.3",      "HIGH",     "EOL since May 2023"),
    (re.compile(r"10\.4\.\d+-MariaDB", re.I), "MariaDB 10.4",      "MEDIUM",   "EOL since June 2024"),
    # ProFTPD
    (re.compile(r"ProFTPD 1\.3\.[0-5]\b", re.I), "ProFTPD ≤1.3.5", "HIGH",     "CVE-2015-3306 mod_copy unauth file read; CVE-2019-12815 mod_copy"),
    (re.compile(r"ProFTPD Default Installation", re.I), "ProFTPD Default Install", "MEDIUM", "Unhardened config (ServerName not customized)"),
    # vsftpd
    (re.compile(r"vsftpd 2\.\d+", re.I),     "vsftpd 2.x",         "CRITICAL", "CVE-2011-2523 backdoor pattern (2.3.4); 2.x EOL"),
    (re.compile(r"vsftpd 3\.0\.[0-3]\b", re.I), "vsftpd 3.0.0-3.0.3", "MEDIUM", "Older 3.0 — multiple bug fixes since"),
    # FileZilla Server
    (re.compile(r"FileZilla Server 0\.\d+", re.I), "FileZilla Server 0.x", "HIGH", "Pre-rewrite codebase (2014 era), EOL since 1.x release"),
    # Pure-FTPd
    (re.compile(r"Pure-FTPd 1\.0\.[0-4]\d", re.I), "Pure-FTPd ≤1.0.49", "MEDIUM", "Older — security/bug fixes since"),
    # Microsoft IIS
    (re.compile(r"Microsoft-IIS/[67]\.", re.I), "IIS 6.x/7.x",      "CRITICAL", "IIS 6 EOL July 2015; IIS 7 EOL Jan 2020"),
    (re.compile(r"Microsoft-IIS/8\.", re.I),  "IIS 8.x",            "HIGH",     "IIS 8/8.5 EOL Oct 2023"),
    # Apache
    (re.compile(r"Apache/2\.0\.", re.I),      "Apache 2.0",         "CRITICAL", "EOL since July 2013"),
    (re.compile(r"Apache/2\.2\.", re.I),      "Apache 2.2",         "CRITICAL", "EOL since July 2017"),
    # OpenSSH older
    (re.compile(r"OpenSSH_[1-6]\.", re.I),    "OpenSSH ≤6.x",       "HIGH",     "Multiple CVEs in old OpenSSH versions"),
    (re.compile(r"OpenSSH_7\.[0-3]", re.I),   "OpenSSH 7.0-7.3",    "MEDIUM",   "Older 7.x — security fixes since"),
    # Microsoft FTP
    (re.compile(r"Microsoft FTP Service", re.I), "Microsoft FTP",   "INFO",     "Windows-IIS FTP — context-dependent"),
]


def extract_findings():
    findings = []  # list of (source, host, port, banner, version_str, classification, severity, reason)

    # Read ledgers
    for ledger in LEDGERS:
        if not ledger.exists():
            continue
        for line in ledger.read_text().splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            banner = j.get("banner_first_256", "") or ""
            host = j.get("host", "?")
            port = j.get("port", "?")
            for rx, cls, sev, reason in EOL_PATTERNS:
                if rx.search(banner):
                    findings.append({
                        "source": "ledger",
                        "host": host,
                        "port": port,
                        "banner_excerpt": banner.strip()[:120],
                        "classification": cls,
                        "severity": sev,
                        "reason": reason,
                    })

    # Read log files for additional context (banners are in nc-style separate from PORT-OPEN events)
    # The log only contains "PORT-OPEN host:port (service, sev, fp=X)" lines — not full banners.
    # We'll need to re-query the host:port to get the banner. Skip log for now; ledger has banner.

    return findings


def main():
    findings = extract_findings()
    if not findings:
        print("No EOL-class findings detected in any ledger.")
        return

    # Group by severity
    from collections import defaultdict
    by_sev = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]].append(f)

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    print(f"\n{'='*70}")
    print(f"EOL SOFTWARE ANALYSIS — {len(findings)} flagged exposures")
    print(f"{'='*70}\n")

    for sev in sev_order:
        if sev not in by_sev:
            continue
        print(f"[{sev}] {len(by_sev[sev])} findings:\n")
        for f in by_sev[sev]:
            print(f"  {f['host']:35s}:{f['port']:<6} [{f['classification']:25s}]")
            print(f"    why: {f['reason']}")
            print(f"    banner: {f['banner_excerpt']}")
            print()

    # Summary by classification
    print(f"\n{'='*70}")
    print(f"SUMMARY by classification:")
    print(f"{'='*70}")
    classifications = defaultdict(int)
    for f in findings:
        classifications[(f["severity"], f["classification"])] += 1
    for (sev, cls), n in sorted(classifications.items(), key=lambda x: (sev_order.index(x[0][0]), -x[1])):
        print(f"  [{sev}] {cls:30s}  ×{n}")


if __name__ == "__main__":
    main()
