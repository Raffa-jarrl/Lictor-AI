#!/usr/bin/env python3
"""
find-contact — given a domain, find the security contact.

Tries in order:
  1. /.well-known/security.txt (RFC 9116 standard)
  2. /security.txt (legacy location)
  3. WHOIS (registrant email, if not GDPR-masked)
  4. DNS SOA RNAME (sysadmin email)
  5. /robots.txt comment (some sites stick emails there)
  6. /humans.txt
  7. About / Contact page scrape (regex for emails)

Output: best-guess contact + confidence level.
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.request, urllib.error, subprocess
from urllib.parse import urlparse

UA = "Lictor-ContactFinder/0.1 (+https://lictorai.com)"
TIMEOUT = 8
EMAIL_RX = re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
# Filter out junk emails (vendors + .il TLD registry boilerplate)
JUNK = re.compile(r'(sentry|cdn|googletagmanager|cloudflare|akamai|jsdelivr|unpkg|stripe|paypal|example|test\.com|isoc\.org\.il|tld-tech@|awsdns-|hostmaster@netvision|amazon\.com)\.?', re.IGNORECASE)
SECURITY_PRIORITIES = ['security@', 'abuse@', 'admin@', 'webmaster@', 'info@', 'contact@', 'support@', 'hello@']

def http_get(url, max_bytes=200_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None

def parse_security_txt(text):
    """Extract Contact: emails from security.txt."""
    contacts = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("contact:"):
            v = line.split(":", 1)[1].strip()
            if v.startswith("mailto:"): v = v[7:]
            if "@" in v: contacts.append(v)
    return contacts

def get_whois_email(domain):
    try:
        out = subprocess.check_output(["whois", domain], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", "replace")
        emails = EMAIL_RX.findall(out)
        # Filter junk
        good = [e for e in emails if not JUNK.search(e) and "redacted" not in e.lower() and "abuse@" not in e.lower()]
        return good[:3]
    except Exception:
        return []

def get_dns_soa(domain):
    try:
        out = subprocess.check_output(["dig", "+short", domain, "SOA"], stderr=subprocess.DEVNULL, timeout=5).decode()
        # SOA format: ns1.example.com hostmaster.example.com 12345 ...
        parts = out.strip().split()
        if len(parts) >= 2:
            rname = parts[1].rstrip(".")
            # RNAME is in DNS format: replace first . with @
            if "." in rname:
                local, _, dom = rname.partition(".")
                return [f"{local}@{dom}"]
    except Exception:
        pass
    return []

def scrape_page_emails(html):
    if not html: return []
    emails = EMAIL_RX.findall(html)
    return [e for e in emails if not JUNK.search(e)]

def best_email(candidates):
    """Pick the best email from a list, prioritizing security@ etc."""
    if not candidates: return None
    seen = []
    for c in candidates:
        c = c.lower().strip()
        if c not in seen: seen.append(c)
    for prefix in SECURITY_PRIORITIES:
        for c in seen:
            if c.startswith(prefix): return c
    return seen[0]

def find_contact(domain):
    """Run all checks, return dict."""
    result = {
        "domain": domain,
        "security_txt": [],
        "whois": [],
        "dns_soa": [],
        "scraped": [],
        "best": None,
        "confidence": "none",
    }
    # 1. security.txt
    for path in ("/.well-known/security.txt", "/security.txt"):
        for scheme in ("https", "http"):
            text = http_get(f"{scheme}://{domain}{path}")
            if text and "Contact:" in text:
                result["security_txt"] = parse_security_txt(text)
                break
        if result["security_txt"]: break
    # 2. WHOIS
    result["whois"] = get_whois_email(domain)
    # 3. DNS SOA
    result["dns_soa"] = get_dns_soa(domain)
    # 4. Scrape main + /contact + /about
    for path in ("/", "/contact", "/about", "/contact-us", "/about-us"):
        for scheme in ("https", "http"):
            text = http_get(f"{scheme}://{domain}{path}")
            if text:
                result["scraped"].extend(scrape_page_emails(text))
                break
    # Apply junk filter to everything
    for k in ("security_txt","whois","dns_soa","scraped"):
        result[k] = [e for e in result[k] if not JUNK.search(e)]

    # Compute best + confidence
    # Priority: security.txt > scraped (often the real org email) > DNS SOA > WHOIS (often registry boilerplate)
    if result["security_txt"]:
        result["best"] = best_email(result["security_txt"])
        result["confidence"] = "high"  # canonical channel
    elif result["scraped"]:
        # Prefer same-domain email when possible
        domain_emails = [e for e in result["scraped"] if domain in e.lower()]
        if domain_emails:
            result["best"] = best_email(domain_emails)
            result["confidence"] = "high" if any(result["best"].startswith(p) for p in SECURITY_PRIORITIES) else "medium"
        else:
            result["best"] = best_email(result["scraped"])
            result["confidence"] = "medium"
    elif result["dns_soa"]:
        result["best"] = result["dns_soa"][0]
        result["confidence"] = "low"
    elif result["whois"]:
        result["best"] = best_email(result["whois"])
        result["confidence"] = "low"
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+", help="Domain(s) to find contact for")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()
    for d in args.domains:
        r = find_contact(d)
        if args.json:
            print(json.dumps(r))
        else:
            print(f"\n=== {d} ===")
            print(f"  best: {r['best']}  ({r['confidence']})")
            if r['security_txt']: print(f"  security.txt: {r['security_txt']}")
            if r['whois']:        print(f"  whois:        {r['whois']}")
            if r['scraped']:      print(f"  scraped:      {r['scraped'][:3]}")
            if r['dns_soa']:      print(f"  dns soa:      {r['dns_soa']}")

if __name__ == "__main__":
    main()
