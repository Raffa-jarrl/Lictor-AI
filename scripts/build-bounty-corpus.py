#!/usr/bin/env python3
"""
build-bounty-corpus — pull all 4 bounty platforms from arkadiyt/bounty-targets-data
and produce a deduplicated list of apex domains for the takeover scanner.

Sources:
  - HackerOne: 456 programs
  - Bugcrowd: 218 programs
  - Intigriti: 127 programs
  - YesWeHack: 67 programs

Output: ~/.lictor/bounty-corpus.txt — one apex domain per line.
Also outputs ~/.lictor/bounty-corpus-paid.txt — only programs that PAY.
"""
import json, re, urllib.request
from pathlib import Path
from urllib.parse import urlparse

UA = "Lictor-CorpusBuilder/0.1"
SOURCES = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}
OUT_ALL  = Path.home() / ".lictor" / "bounty-corpus.txt"
OUT_PAID = Path.home() / ".lictor" / "bounty-corpus-paid.txt"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def extract_domain(asset_str):
    """Take an asset string like '*.example.com' or 'https://api.example.com/foo'
    and return the apex domain (example.com)."""
    if not asset_str: return None
    a = asset_str.strip().lower()
    # Skip non-domain assets (URLs to apps, source code, etc.)
    if any(skip in a for skip in ["github.com/", "play.google.com/", "apps.apple.com/", "itunes.apple.com"]):
        return None
    # Strip URL scheme
    if "://" in a: a = a.split("://", 1)[1]
    # Strip path
    a = a.split("/", 1)[0]
    # Strip port
    a = a.split(":", 1)[0]
    # Strip wildcard
    a = a.lstrip("*.")
    # Strip leading dots
    a = a.lstrip(".")
    # Validate: must contain a dot and TLD-ish chars
    if "." not in a: return None
    if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', a): return None
    # Reject TLD-only / "com.X" garbage (these come from miss-extracted wildcards like *.x.com.co)
    GARBAGE_PREFIXES = {"com", "net", "org", "co", "io", "ac", "gov"}
    if a.split(".")[0] in GARBAGE_PREFIXES and len(a.split(".")) == 2:
        return None  # e.g., "com.co", "com.cy" — not real domains
    # Reduce to apex (or keep one level if it's a country code like co.il, co.uk)
    parts = a.split(".")
    SECOND_LEVEL = {"co", "ac", "gov", "or", "ne", "edu"}
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        # e.g. site.co.uk -> site.co.uk (already apex)
        apex = ".".join(parts[-3:])
    else:
        apex = ".".join(parts[-2:])
    return apex


def get_assets_h1(prog):
    return [t.get("asset_identifier","") for t in prog.get("targets",{}).get("in_scope",[])
            if t.get("asset_type") in ("URL", "WILDCARD", "OTHER")]

def get_assets_bc(prog):
    return [t.get("target","") or t.get("uri","") for t in prog.get("targets",{}).get("in_scope",[])
            if t.get("type") in ("website", "api")]

def get_assets_intigriti(prog):
    return [t.get("endpoint","") for t in prog.get("targets",{}).get("in_scope",[])
            if str(t.get("type", "")).lower() in ("url", "wildcard", "website")]

def get_assets_ywh(prog):
    return [t.get("target","") for t in prog.get("targets",{}).get("in_scope",[])
            if t.get("type") in ("web-application", "api")]


PAID_CHECK = {
    "hackerone": lambda p: bool(p.get("offers_bounties")),
    "bugcrowd":  lambda p: (p.get("max_payout") or 0) > 0,
    "intigriti": lambda p: (((p.get("max_bounty") or {}).get("value") if isinstance(p.get("max_bounty"), dict) else p.get("max_bounty")) or 0) > 0,
    "yeswehack": lambda p: (p.get("max_bounty") or 0) > 0,
}
EXTRACTORS = {
    "hackerone": get_assets_h1,
    "bugcrowd":  get_assets_bc,
    "intigriti": get_assets_intigriti,
    "yeswehack": get_assets_ywh,
}


def main():
    all_domains = set()
    paid_domains = set()
    stats = {}

    for platform, url in SOURCES.items():
        try:
            data = fetch(url)
            print(f"[+] {platform}: {len(data)} programs", flush=True)
        except Exception as e:
            print(f"  [!] {platform} fetch fail: {e}", flush=True); continue

        plat_domains = set(); plat_paid = set()
        for prog in data:
            try:
                assets = EXTRACTORS[platform](prog)
                is_paid = PAID_CHECK[platform](prog)
            except Exception:
                continue
            for a in assets:
                apex = extract_domain(a)
                if apex:
                    all_domains.add(apex)
                    plat_domains.add(apex)
                    if is_paid:
                        paid_domains.add(apex)
                        plat_paid.add(apex)
        stats[platform] = (len(plat_domains), len(plat_paid))

    OUT_ALL.parent.mkdir(parents=True, exist_ok=True)
    OUT_ALL.write_text("\n".join(sorted(all_domains)) + "\n")
    OUT_PAID.write_text("\n".join(sorted(paid_domains)) + "\n")

    print(f"\n[+] Total unique apex domains: {len(all_domains)}")
    print(f"[+] Paid-program domains:      {len(paid_domains)}")
    print(f"\n  By platform (all / paid):")
    for plat, (a, p) in stats.items():
        print(f"    {plat:<12}  {a:>5}  {p:>5}")
    print(f"\n[+] Wrote {OUT_ALL}")
    print(f"[+] Wrote {OUT_PAID}")


if __name__ == "__main__":
    main()
