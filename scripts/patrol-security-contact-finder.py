#!/usr/bin/env python3
"""
patrol-security-contact-finder — find the right security contact for a target org.

Tries (in priority order):
  1. /.well-known/security.txt (RFC 9116)
  2. Common bug bounty platform pages (hackerone.com/<org>, bugcrowd.com/<org>, immunefi.com/bug-bounty/<org>)
  3. /security, /security.html, /bug-bounty paths on the org's main domain
  4. Common security@ / abuse@ / soc@ / cisco@ addresses (only if RFC 9116 doesn't exist)

Output: JSON to stdout (or JSONL ledger if --ledger).

Usage:
  patrol-security-contact-finder.py spotify.com
  patrol-security-contact-finder.py --batch domains.txt --ledger contacts.jsonl
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict

UA = "Lictor-ContactFinder/0.1 (+https://lictor-ai.com)"

@dataclass
class ContactReport:
    domain: str
    security_txt_url: str = ""
    security_txt_contact: list[str] = field(default_factory=list)
    security_txt_policy: str = ""
    security_txt_acknowledgements: str = ""
    hackerone_program: str = ""
    bugcrowd_program: str = ""
    immunefi_program: str = ""
    org_security_pages: list[str] = field(default_factory=list)
    plausible_email_addresses: list[str] = field(default_factory=list)
    recommended_channel: str = ""
    recommended_reason: str = ""

def http_head(url: str, timeout: int = 6) -> int | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def http_get(url: str, timeout: int = 6, max_bytes: int = 64 * 1024) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None

def parse_security_txt(text: str) -> dict:
    """Parse RFC 9116 security.txt format."""
    contacts = []
    policy = ""
    ack = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if ":" not in line: continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "contact":
            contacts.append(val)
        elif key == "policy":
            policy = val
        elif key == "acknowledgements" or key == "acknowledgments":
            ack = val
    return {"contacts": contacts, "policy": policy, "ack": ack}

def find_security_txt(domain: str) -> tuple[str, dict]:
    """Try /.well-known/security.txt and /security.txt."""
    for scheme in ("https", "http"):
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"{scheme}://{domain}{path}"
            text = http_get(url, timeout=5, max_bytes=16 * 1024)
            if text and "contact:" in text.lower():
                return url, parse_security_txt(text)
    return "", {}

def check_bounty_platforms(org_slug: str) -> dict:
    """Check if HackerOne / Bugcrowd / Immunefi has a program page for this org."""
    out = {}
    for name, url_tpl in [
        ("hackerone", f"https://hackerone.com/{org_slug}"),
        ("bugcrowd", f"https://bugcrowd.com/{org_slug}"),
        ("immunefi", f"https://immunefi.com/bug-bounty/{org_slug}/"),
    ]:
        status = http_head(url_tpl)
        if status == 200:
            out[name] = url_tpl
    return out

def find_org_security_page(domain: str) -> list[str]:
    """Look for /security or /bug-bounty pages on the org's main domain."""
    found = []
    for path in ("/security", "/security/", "/security.html",
                  "/bug-bounty", "/bug-bounty/", "/responsible-disclosure",
                  "/vulnerability-disclosure"):
        status = http_head(f"https://{domain}{path}")
        if status == 200:
            found.append(f"https://{domain}{path}")
    return found

def plausible_emails(domain: str) -> list[str]:
    """Most common patterns. Test each via SMTP would be ideal but Gmail blocks that
    for unauthenticated checks. So we list them; user can pick the right one based
    on org-known conventions."""
    return [
        f"security@{domain}",
        f"abuse@{domain}",
        f"soc@{domain}",
        f"infosec@{domain}",
        f"vulnerability@{domain}",
        f"whitehats@{domain}",  # Reddit-style
    ]

def find_contacts(domain: str) -> ContactReport:
    domain = domain.lower().strip()
    if domain.startswith("http"):
        domain = re.sub(r'^https?://', '', domain).split('/')[0]
    org_slug = domain.split('.')[0]  # naive

    rpt = ContactReport(domain=domain)

    # 1. security.txt
    url, parsed = find_security_txt(domain)
    if url:
        rpt.security_txt_url = url
        rpt.security_txt_contact = parsed.get("contacts", [])
        rpt.security_txt_policy = parsed.get("policy", "")
        rpt.security_txt_acknowledgements = parsed.get("ack", "")

    # 2. bug bounty platforms
    bp = check_bounty_platforms(org_slug)
    rpt.hackerone_program = bp.get("hackerone", "")
    rpt.bugcrowd_program = bp.get("bugcrowd", "")
    rpt.immunefi_program = bp.get("immunefi", "")

    # 3. org security page
    rpt.org_security_pages = find_org_security_page(domain)

    # 4. plausible emails (as fallback only)
    rpt.plausible_email_addresses = plausible_emails(domain)

    # Recommend
    if rpt.hackerone_program:
        rpt.recommended_channel = rpt.hackerone_program
        rpt.recommended_reason = "Active HackerOne program — best bounty + tracking"
    elif rpt.bugcrowd_program:
        rpt.recommended_channel = rpt.bugcrowd_program
        rpt.recommended_reason = "Active Bugcrowd program — bounty + tracking"
    elif rpt.immunefi_program:
        rpt.recommended_channel = rpt.immunefi_program
        rpt.recommended_reason = "Active Immunefi program (Web3) — bounty + tracking"
    elif rpt.security_txt_contact:
        rpt.recommended_channel = rpt.security_txt_contact[0]
        rpt.recommended_reason = "RFC 9116 security.txt confirmed contact"
    elif rpt.org_security_pages:
        rpt.recommended_channel = rpt.org_security_pages[0]
        rpt.recommended_reason = "Org-published security page — use form/contact on the page"
    else:
        rpt.recommended_channel = f"security@{domain}"
        rpt.recommended_reason = "FALLBACK ONLY — no security.txt, no public bug bounty program, no /security page. Email likely to bounce."

    return rpt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain", nargs="?")
    ap.add_argument("--batch", help="newline-delimited domains file")
    ap.add_argument("--ledger", default="")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()

    domains = []
    if args.batch:
        from pathlib import Path
        domains = [d.strip() for d in Path(args.batch).read_text().splitlines() if d.strip()]
    elif args.domain:
        domains = [args.domain]
    else:
        print("Usage: patrol-security-contact-finder.py <domain> | --batch <file>")
        sys.exit(1)

    results = []
    if len(domains) == 1:
        rpt = find_contacts(domains[0])
        results.append(rpt)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(find_contacts, d): d for d in domains}
            for fut in as_completed(futures):
                try: results.append(fut.result())
                except Exception as e:
                    print(f"  ERR {futures[fut]}: {e}")

    # Output
    if args.ledger:
        from pathlib import Path
        with Path(args.ledger).open("a") as f:
            for r in results:
                f.write(json.dumps(asdict(r)) + "\n")
        print(f"[+] {len(results)} contact reports → {args.ledger}")
    else:
        for r in results:
            print(json.dumps(asdict(r), indent=2))

if __name__ == "__main__":
    main()
