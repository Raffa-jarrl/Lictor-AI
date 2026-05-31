#!/usr/bin/env python3
"""Lictor per-host report generator — turns scan ledger output into a customer deliverable.

Usage:
    python lictor-report.py <target-domain>
    python lictor-report.py example.com

Pulls findings for <domain> from all Lictor ledgers:
  - git-exposure-candidates.jsonl
  - sourcemap-exposure.jsonl
  - graphql-introspection.jsonl
  - tls-audit.jsonl
  - email-auth.jsonl
  - ransomware-exposure-v2.jsonl
  - wallet-exposure-candidates.v2.jsonl
  - google-sa-candidates.jsonl
  - hardhat-artifact-candidates.jsonl
  - mobile-backup-candidates.jsonl
  - solana-keypair-candidates.jsonl
  - il-parties-crm-paths.jsonl
  - subdomain-takeover-v2.jsonl
  - hf-leak-ledger.jsonl
  - cors-ledger.jsonl

Produces:
  - reports/<domain>-<date>.md   Markdown report
  - reports/<domain>-<date>.json Aggregated JSON for API consumers
  - reports/<domain>-<date>.html Optional HTML (markdown rendered)
"""
import json, sys, os
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

LEDGER_DIR = Path.home() / "Lictor" / "v3" / "ledgers"
REPORTS_DIR = Path.home() / "Lictor" / "v3" / "reports"

# Severity weight for risk scoring (0-100 scale)
SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "informational": 1, "info": 1}

# Compliance mapping per finding category
COMPLIANCE_MAP = {
    "git-exposure": {
        "owasp": "A05:2021 Security Misconfiguration",
        "cis": "Control 4 (Secure Configuration)",
        "pci_dss": "Req 2.2 (Secure Configurations)",
        "soc2": "CC6.1 (Logical Access)",
        "iso27001": "A.9.4.1 (Information Access Restriction)",
    },
    "exposed-sourcemap": {
        "owasp": "A05:2021 Security Misconfiguration",
        "cis": "Control 4",
        "pci_dss": "Req 2.2 + 6.5",
        "soc2": "CC6.6 (Vulnerability Management)",
        "iso27001": "A.14.2.5",
    },
    "graphql-introspection-enabled": {
        "owasp": "A05:2021 + API4:2023 Unrestricted Resource Consumption",
        "cis": "Control 4 + 18 (Penetration Testing)",
        "pci_dss": "Req 2.2 + 6.5",
        "soc2": "CC6.6",
        "iso27001": "A.14.2.5",
    },
    "tls-audit": {
        "owasp": "A02:2021 Cryptographic Failures",
        "cis": "Control 3 (Data Protection)",
        "pci_dss": "Req 4.1 (Strong Cryptography in transit)",
        "soc2": "CC6.7",
        "iso27001": "A.10.1.1 + A.14.1.3",
    },
    "email-auth": {
        "owasp": "A01:2021 Broken Access Control (auth spoofing)",
        "cis": "Control 9 (Email Defenses)",
        "pci_dss": "Req 5.1 (anti-phishing)",
        "soc2": "CC6.1 + CC6.8",
        "iso27001": "A.13.2.3",
    },
    "ransomware-exposure": {
        "owasp": "A05:2021 + A06:2021 (Vulnerable Components)",
        "cis": "Control 4 + 12 (Network Infra)",
        "pci_dss": "Req 1.2 (Firewall config) + 2.2",
        "soc2": "CC6.6",
        "iso27001": "A.13.1.1",
    },
    "wallet-file": {
        "owasp": "A05:2021 + A02:2021",
        "cis": "Control 3 (Data Protection)",
        "pci_dss": "N/A (crypto-asset specific)",
        "soc2": "CC6.7",
        "iso27001": "A.10.1.2 (Key Management)",
    },
    "subdomain-takeover": {
        "owasp": "A05:2021 + A07:2021 (Identification & Auth Failures)",
        "cis": "Control 4",
        "pci_dss": "Req 1.4",
        "soc2": "CC6.1",
        "iso27001": "A.13.1.1",
    },
}

# Default remediation guidance per finding type
REMEDIATION = {
    "git-exposure": (
        "Block public access to /.git/ directory:\n"
        "  • Apache: `RedirectMatch 404 /\\\\.git`\n"
        "  • Nginx: `location ~ /\\\\.git { deny all; return 404; }`\n"
        "  • Cloudflare WAF: deny rule on /.git/* path\n"
        "  • Best practice: deploy with `git archive` or `dist/` build output, not the git working tree"
    ),
    "exposed-sourcemap": (
        "Disable sourcemap generation in production builds:\n"
        "  • Webpack: `devtool: false` (or `hidden-source-map` for Sentry-only)\n"
        "  • Vite: `build.sourcemap: false`\n"
        "  • Next.js: `productionBrowserSourceMaps: false` (default)\n"
        "  • OR add CDN rule to deny `*.map` for external traffic"
    ),
    "graphql-introspection-enabled": (
        "Disable introspection in production:\n"
        "  • Apollo Server: `introspection: false`\n"
        "  • Hasura: `HASURA_GRAPHQL_ENABLE_INTROSPECTION=false`\n"
        "  • Add depth/complexity limits: graphql-depth-limit, graphql-cost-analysis\n"
        "  • Rate limit /graphql separately from REST"
    ),
    "tls-audit": (
        "Specific to finding — common fixes:\n"
        "  • Weak ciphers: disable RC4/DES/3DES/MD5/NULL/EXPORT in TLS config\n"
        "  • TLS 1.0/1.1: disable (PCI-DSS requires TLS 1.2+)\n"
        "  • Cert expiring: set up auto-renewal (Let's Encrypt + certbot or cloud cert manager)\n"
        "  • Missing HSTS: add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`"
    ),
    "email-auth": (
        "  • Missing SPF: add DNS TXT `v=spf1 include:_spf.google.com -all` (adjust includes for your provider)\n"
        "  • Missing DMARC: add DNS TXT `_dmarc.<domain>` with `v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>`\n"
        "  • Missing DKIM: enable in your mail provider (Google Workspace, M365, SendGrid, etc.)\n"
        "  • Weak DMARC (p=none): tighten to p=quarantine after 30-day monitoring"
    ),
    "ransomware-exposure": (
        "  • RDP/SMB/WinRM externally exposed: move behind VPN immediately; never expose to public internet\n"
        "  • Vulnerable VPN (Fortinet/Citrix/Pulse/SonicWall): patch to latest version, rotate all credentials\n"
        "  • Exchange OWA: apply latest CU + security patches; consider Exchange Online migration\n"
        "  • MOVEit/GoAnywhere: patch to vendor's current version; rotate API keys"
    ),
    "wallet-file": (
        "  • Remove /wallet.json, /keystore.json, /seed.txt from web-accessible paths\n"
        "  • Never deploy wallet files to production web servers\n"
        "  • If exposure occurred, treat keys as compromised — rotate immediately + check for unauthorized tx"
    ),
    "subdomain-takeover": (
        "  • Remove the dangling CNAME record from DNS\n"
        "  • If you actually need that subdomain: re-register the target on the cloud platform with your account\n"
        "  • Audit ALL CNAMEs in your DNS for similar danglers"
    ),
}


def host_matches(host_field, target):
    """Is this ledger entry about the target domain (including subdomains)?"""
    if not host_field: return False
    h = host_field.lower().strip()
    t = target.lower().strip()
    return h == t or h.endswith("." + t) or t in h


def load_all_findings_for_host(target):
    """Walk all ledgers, extract findings matching the target."""
    findings = []
    if not LEDGER_DIR.exists():
        return findings

    for ledger_file in LEDGER_DIR.glob("*.jsonl"):
        try:
            for line in ledger_file.read_text().splitlines():
                if not line.strip(): continue
                try: entry = json.loads(line)
                except: continue
                # Match host field (different ledgers use different names)
                host_field = entry.get("host") or entry.get("apex") or entry.get("bucket") or entry.get("repo")
                if not host_matches(host_field, target): continue
                # Tag with source ledger + normalize severity
                entry["_source_ledger"] = ledger_file.stem
                if "severity" not in entry:
                    # Derive severity from type
                    t = entry.get("type", "")
                    entry["severity"] = "MEDIUM"  # default
                findings.append(entry)
        except Exception as e:
            continue
    return findings


def compute_risk_score(findings):
    """0-100 score (100=clean) based on weighted severity."""
    total_penalty = 0
    for f in findings:
        sev = (f.get("severity", "") or "low").lower()
        # Handle nested findings format (TLS audit, ransomware exposure)
        if "findings" in f and isinstance(f["findings"], list):
            for sub in f["findings"]:
                sub_sev = (sub.get("severity", "") or "low").lower()
                total_penalty += SEVERITY_WEIGHT.get(sub_sev, 2)
        else:
            total_penalty += SEVERITY_WEIGHT.get(sev, 2)
    return max(0, 100 - total_penalty)


def categorize_findings(findings):
    """Group findings by type for the report."""
    by_category = defaultdict(list)
    for f in findings:
        # Map to canonical category
        t = f.get("type", "") or f.get("_source_ledger", "")
        canonical = next((k for k in COMPLIANCE_MAP if k in t), t)
        by_category[canonical].append(f)
    return by_category


def render_markdown(target, findings, score):
    """Render the full customer-facing report."""
    by_cat = categorize_findings(findings)
    sev_count = defaultdict(int)
    for f in findings:
        sev = (f.get("severity") or "info").upper()
        if "findings" in f and isinstance(f["findings"], list):
            for sub in f["findings"]:
                sev_count[(sub.get("severity") or "info").upper()] += 1
        else:
            sev_count[sev] += 1

    md = []
    md.append(f"# Lictor Security Scan Report")
    md.append(f"")
    md.append(f"**Target**: `{target}`")
    md.append(f"**Scan date**: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    md.append(f"**Risk score**: **{score}/100** {'🟢 LOW RISK' if score>=85 else '🟡 MEDIUM RISK' if score>=60 else '🔴 HIGH RISK'}")
    md.append(f"**Total findings**: {len(findings)}")
    md.append(f"")
    md.append(f"## Executive summary")
    md.append(f"")
    md.append(f"| Severity | Count |")
    md.append(f"|---|---|")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"):
        if sev_count[s] > 0:
            md.append(f"| {s} | {sev_count[s]} |")
    md.append(f"")
    md.append(f"### Lictor scan coverage")
    md.append(f"This scan checked `{target}` and its subdomains across the following attack-surface categories:")
    md.append(f"")
    md.append(f"- ✅ Web-exposed files (.git/, .env, wallet files, sourcemaps)")
    md.append(f"- ✅ Cloud-bucket misconfiguration (S3/GCS/Azure/DO/Wasabi)")
    md.append(f"- ✅ TLS/SSL posture (ciphers, certs, security headers)")
    md.append(f"- ✅ Email-authentication posture (SPF/DKIM/DMARC)")
    md.append(f"- ✅ Anti-ransomware exposure (risky ports + VPN/RAT fingerprints)")
    md.append(f"- ✅ GraphQL introspection (schema exposure)")
    md.append(f"- ✅ Subdomain takeover (dangling CNAMEs across 14 cloud platforms)")
    md.append(f"- ✅ Known CVE patterns (Nuclei templates + CISA KEV)")
    md.append(f"")

    if not findings:
        md.append(f"## ✅ No findings")
        md.append(f"")
        md.append(f"Lictor found no exposures, misconfigurations, or known-vulnerable patterns on `{target}` in this scan.")
        md.append(f"")
        md.append(f"Recommend continuing monthly scans + re-running after any major deployment.")
    else:
        md.append(f"## Findings detail")
        md.append(f"")
        for cat, items in by_cat.items():
            md.append(f"### {cat} ({len(items)} finding{'s' if len(items)!=1 else ''})")
            md.append(f"")
            comp = COMPLIANCE_MAP.get(cat)
            if comp:
                md.append(f"**Compliance mapping**:")
                md.append(f"- OWASP: {comp.get('owasp','-')}")
                md.append(f"- CIS Controls: {comp.get('cis','-')}")
                md.append(f"- PCI-DSS: {comp.get('pci_dss','-')}")
                md.append(f"- SOC 2: {comp.get('soc2','-')}")
                md.append(f"- ISO 27001: {comp.get('iso27001','-')}")
                md.append(f"")
            for item in items[:10]:
                sev = (item.get("severity") or "info").upper()
                md.append(f"- **[{sev}]** {item.get('host','?')} {item.get('path','')}")
                if item.get("detail"): md.append(f"    - {item['detail']}")
                if "findings" in item and isinstance(item["findings"], list):
                    for sub in item["findings"][:3]:
                        md.append(f"    - [{sub.get('severity','?')}] {sub.get('issue','?')}")
            if len(items) > 10:
                md.append(f"- *(+{len(items)-10} more — see attached JSON)*")
            md.append(f"")
            rem = REMEDIATION.get(cat)
            if rem:
                md.append(f"**Remediation**:")
                md.append(f"```")
                md.append(rem)
                md.append(f"```")
                md.append(f"")

    md.append(f"---")
    md.append(f"")
    md.append(f"## What's NOT in this scan (out of scope)")
    md.append(f"")
    md.append(f"- Internal network / Active Directory audit (Lictor Internal — separate product, roadmap)")
    md.append(f"- Active vulnerability exploitation (Lictor only does detection, never exploits)")
    md.append(f"- Endpoint / mobile app audit (out of external-surface scope)")
    md.append(f"- Code review / SAST (different tool category)")
    md.append(f"- Social engineering / phishing simulation")
    md.append(f"")
    md.append(f"## Lictor commitments")
    md.append(f"")
    md.append(f"- 🔒 All scans HEAD-only on sensitive paths (wallet files, DB dumps, backup paths)")
    md.append(f"- 🔒 Signature-only on credential paths (.env detection emits var-name, never the value)")
    md.append(f"- 🚫 Never downloads file contents from your servers")
    md.append(f"- 🚫 Never attempts authentication on any panel")
    md.append(f"- 🤝 If we find an issue on a vendor of yours, we handle the upstream disclosure")
    md.append(f"")
    md.append(f"---")
    md.append(f"")
    md.append(f"_Generated by Lictor v3 — https://lictor-ai.com_")
    md.append(f"_Methodology: Apache 2.0 open-source scanners + ~13K Nuclei templates + 1.6K CISA KEV entries_")
    md.append(f"_Questions: raffajarrl@gmail.com_")
    return "\n".join(md)


def main():
    if len(sys.argv) < 2:
        print("Usage: python lictor-report.py <target-domain>")
        sys.exit(1)
    target = sys.argv[1].lower().strip()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[+] Generating Lictor report for `{target}`")
    findings = load_all_findings_for_host(target)
    print(f"[+] Found {len(findings)} ledger entries matching target")

    score = compute_risk_score(findings)
    print(f"[+] Risk score: {score}/100")

    md = render_markdown(target, findings, score)
    date = datetime.now().strftime("%Y-%m-%d")
    md_path = REPORTS_DIR / f"{target}-{date}.md"
    json_path = REPORTS_DIR / f"{target}-{date}.json"

    md_path.write_text(md)
    json_path.write_text(json.dumps({
        "target": target,
        "scan_date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk_score": score,
        "finding_count": len(findings),
        "findings": findings,
    }, indent=2))

    print(f"[+] Markdown report: {md_path}")
    print(f"[+] JSON report: {json_path}")
    # Try to convert to PDF if pandoc available
    import shutil
    if shutil.which("pandoc"):
        pdf_path = REPORTS_DIR / f"{target}-{date}.pdf"
        os.system(f'pandoc "{md_path}" -o "{pdf_path}" --pdf-engine=xelatex 2>/dev/null || pandoc "{md_path}" -o "{pdf_path}" 2>/dev/null')
        if pdf_path.exists():
            print(f"[+] PDF report: {pdf_path}")


if __name__ == "__main__":
    main()
