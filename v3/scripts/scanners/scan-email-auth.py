"""SPF / DKIM / DMARC email-authentication posture scanner.

Per host, checks DNS for:
- SPF record (TXT v=spf1 ...) — anti-spoofing for outbound mail
- DKIM selectors (TXT <selector>._domainkey.<domain>) — signing posture
- DMARC record (TXT _dmarc.<domain>) — policy enforcement (none/quarantine/reject)
- MX records — does this domain even receive mail?

Output: per-host severity:
- CRITICAL: missing SPF (anyone can send mail claiming to be from this domain)
- HIGH: SPF too permissive (?all or +all instead of -all)
- HIGH: missing DMARC (no policy enforcement)
- MEDIUM: DMARC p=none (monitor-only, no actual rejection)
- LOW: missing DKIM selectors (or using only default 'default'/'google')
"""
import subprocess, json, sys, re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "email-auth.jsonl"

# Common DKIM selectors used by major providers
COMMON_DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2",
    "k1", "k2", "k3",  # Mailchimp
    "mte1", "mte2",   # MTE
    "everlytickey1", "everlytickey2",  # Everlytic
    "mandrill",
    "sendgrid",
    "amazonses",
    "fd", "fdkim",  # Freshdesk
    "20180409", "20210809",  # date-based common
    "s1", "s2",
    "mailerlite",
    "mxvault",
]


def dig_txt(name, timeout=4):
    """Return list of TXT record strings for <name>."""
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "TXT", name],
                          capture_output=True, text=True, timeout=timeout)
        # dig returns each TXT entry one per line, quoted
        out = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('"'):
                # Strip outer quotes, concatenate split chunks (TXT can be chunked)
                merged = "".join(c.strip('"') for c in re.findall(r'"[^"]*"', line))
                out.append(merged)
        return out
    except Exception:
        return []


def dig_mx(name, timeout=4):
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "MX", name],
                          capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def audit_domain(domain):
    findings = []
    # MX check
    mx = dig_mx(domain)
    if not mx:
        return None  # No mail handling, skip

    # SPF
    txt_records = dig_txt(domain)
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(("CRITICAL", "Missing SPF record — anyone can send mail claiming to be from this domain"))
    else:
        if spf.lower().endswith("+all"):
            findings.append(("CRITICAL", "SPF ends with +all (allow all senders) — equivalent to no SPF"))
        elif spf.lower().endswith("?all"):
            findings.append(("HIGH", "SPF ends with ?all (neutral) — receivers may still accept spoofed mail"))
        elif spf.lower().endswith("~all"):
            findings.append(("LOW", "SPF ends with ~all (softfail) — recipients may still accept; consider -all"))

    # DMARC
    dmarc_records = dig_txt(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_records if "v=DMARC1" in t), None)
    if not dmarc:
        findings.append(("HIGH", "Missing DMARC record (_dmarc.<domain>) — no policy enforcement on email auth failures"))
    else:
        # Parse p= policy
        m = re.search(r"p=(none|quarantine|reject)", dmarc, re.I)
        policy = m.group(1).lower() if m else "?"
        if policy == "none":
            findings.append(("MEDIUM", "DMARC p=none — monitor-only mode, spoofed mail still delivered"))
        elif policy == "quarantine":
            findings.append(("INFO", "DMARC p=quarantine — partial enforcement (spoofed → spam folder)"))
        # Subdomain policy
        sp_m = re.search(r"sp=(none|quarantine|reject)", dmarc, re.I)
        if not sp_m and policy:
            findings.append(("LOW", "DMARC missing 'sp=' (subdomain policy) — subdomains may inherit weaker default"))
        # Reporting
        if "rua=" not in dmarc and "ruf=" not in dmarc:
            findings.append(("INFO", "DMARC missing rua/ruf reporting addresses — no aggregate-report visibility"))

    # DKIM selectors — check common ones (HEAD-only, ~5 sec total)
    dkim_found = []
    for sel in COMMON_DKIM_SELECTORS[:8]:  # cap to 8 for speed
        records = dig_txt(f"{sel}._domainkey.{domain}", timeout=3)
        for r in records:
            if r.startswith("v=DKIM1") or "k=rsa" in r.lower():
                dkim_found.append(sel)
                break
    if not dkim_found:
        findings.append(("LOW", "No DKIM selectors found among common names — mail may be unsigned or use non-standard selectors"))

    if not findings:
        return None  # All-clean (rare but possible)

    return {
        "host": domain,
        "mx_count": len(mx),
        "spf": spf or "(none)",
        "dmarc": dmarc or "(none)",
        "dkim_selectors_found": dkim_found,
        "findings": [{"severity": s, "issue": i} for s, i in findings],
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
    # Strip subdomain prefixes; email auth is at apex level
    apex_hosts = set()
    for h in hosts:
        parts = h.split(".")
        # crude apex extraction (works for .com/.net etc.; for .co.il use 3 parts)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "net", "ac"):
            apex = ".".join(parts[-3:])
        else:
            apex = ".".join(parts[-2:])
        apex_hosts.add(apex)
    apex_list = sorted(apex_hosts)
    print(f"[+] Email-auth posture — {len(apex_list)} unique apex domains (from {len(hosts)} input)", flush=True)

    all_findings = []
    completed = 0
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(audit_domain, h): h for h in apex_list}
        for fut in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"  [{completed}/{len(apex_list)}] domains checked, {len(all_findings)} with email-auth issues", flush=True)
            try:
                r = fut.result(timeout=30)
                if r:
                    all_findings.append(r)
                    crit = [f for f in r["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
                    if crit:
                        print(f"  🔴 {r['host']}", flush=True)
                        for f in crit[:3]:
                            print(f"      [{f['severity']}] {f['issue'][:90]}", flush=True)
            except Exception: pass

    print(f"\n[+] Email-auth scan complete: {len(all_findings)} domains with issues", flush=True)
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for r in all_findings: f.write(json.dumps(r) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
