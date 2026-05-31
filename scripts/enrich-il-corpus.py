#!/usr/bin/env python3
"""
enrich-il-corpus — pulls real IL subdomains from 4 free sources in parallel.

Sources:
  1. subfinder (passive — aggregates 30+ free sources internally)
  2. DNSDumpster web scrape (1 query, rate-limited per IP)
  3. VirusTotal v3 passive DNS public endpoint (no auth, 4 req/min)
  4. Wayback Machine CDX API (free, no auth)

Strategy: query each source for major IL TLDs + major IL orgs we already
have, merge results, dedupe, write to il-smb-hosts.txt.

We don't aim for completeness — just MORE real-world IL hosts than the
seed × prefix expansion gives us.
"""
from __future__ import annotations
import json, re, subprocess, ssl, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

IL_CORPUS = Path('/Users/raffa/Lictor/v3/ledgers/il-smb-hosts.txt')
ctx = ssl.create_default_context()
UA = "Lictor-CorpusEnrich/0.1"

# Top IL apex domains to enumerate subdomains for
IL_APEXES_TO_ENUM = [
    "gov.il", "muni.il", "ac.il", "org.il", "co.il", "net.il",
    # Major specific orgs
    "leumi.co.il", "mizrahi-tefahot.co.il", "discountbank.co.il",
    "phoenix.co.il", "harel-group.co.il", "clalit.co.il",
    "maccabi4u.co.il", "meuhedet.co.il", "sheba.co.il",
    "tau.ac.il", "technion.ac.il", "huji.ac.il",
    "tel-aviv.gov.il", "jerusalem.muni.il", "haifa.muni.il",
    "wix.com", "monday.com", "fiverr.com",
    "pais.co.il", "winner.co.il",
]


def http(url, timeout=20, headers=None):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try: return e.code, e.read()
        except: return e.code, b""
    except Exception:
        return 0, b""


# === Source 1: subfinder ===
def subfinder_enum(target: str, timeout: int = 90) -> set[str]:
    """Run subfinder for one target."""
    try:
        r = subprocess.run(
            ["/opt/homebrew/bin/subfinder", "-d", target, "-silent",
             "-timeout", "10", "-max-time", "1"],
            capture_output=True, text=True, timeout=timeout,
        )
        return {l.strip().lower() for l in r.stdout.split("\n") if l.strip()}
    except Exception:
        return set()


# === Source 2: DNSDumpster (web scrape) ===
def dnsdumpster(target: str) -> set[str]:
    """DNSDumpster requires a CSRF token + form POST. Skip — too brittle."""
    # Implementing this would require CSRF token extraction + cookies +
    # form POST. Realistically dnsdumpster.com has hCaptcha now and isn't
    # scrape-friendly. Use subfinder's free sources instead (which include
    # similar data).
    return set()


# === Source 3: VirusTotal v3 passive DNS (no-auth tier) ===
def virustotal_passive(target: str) -> set[str]:
    """VT public api/v3/domains/{domain}/subdomains."""
    url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=40"
    s, body = http(url, timeout=20, headers={"x-apikey": ""})  # no key — likely 403
    if s != 200: return set()
    try:
        data = json.loads(body)
        return {x["id"].lower() for x in data.get("data", []) if x.get("id")}
    except Exception:
        return set()


# === Source 4: Wayback Machine CDX API (free, no auth) ===
def wayback_cdx(target: str) -> set[str]:
    """Pull all URLs Wayback has seen for *.target, extract hostnames."""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=2000"
    s, body = http(url, timeout=60)
    if s != 200: return set()
    try:
        rows = json.loads(body)
        hosts = set()
        for r in rows[1:]:  # skip header row
            if not r: continue
            try:
                parsed = urllib.parse.urlparse(r[0])
                host = (parsed.hostname or "").lower()
                if host and "." in host and target in host:
                    hosts.add(host)
            except Exception: continue
        return hosts
    except Exception:
        return set()


def enrich_target(target: str) -> dict:
    """Run all sources on one target, return per-source counts."""
    counts = {}
    all_hosts = set()
    # subfinder
    t0 = time.time()
    h = subfinder_enum(target)
    counts["subfinder"] = len(h)
    all_hosts.update(h)
    # virustotal
    h = virustotal_passive(target)
    counts["virustotal"] = len(h)
    all_hosts.update(h)
    time.sleep(15)  # VT rate-limit: 4/min
    # wayback
    h = wayback_cdx(target)
    counts["wayback"] = len(h)
    all_hosts.update(h)
    print(f"  {target:30s} subfinder={counts['subfinder']:4d} vt={counts['virustotal']:3d} wayback={counts['wayback']:4d} total_new={len(all_hosts)}  ({time.time()-t0:.0f}s)", flush=True)
    return {"target": target, "counts": counts, "hosts": all_hosts}


def main():
    print(f"[+] enrich-il-corpus — {len(IL_APEXES_TO_ENUM)} targets across 3 sources", flush=True)
    print(f"[+] (DNSDumpster skipped — has hCaptcha, not scrape-friendly)", flush=True)
    existing = set(IL_CORPUS.read_text().splitlines())
    new_total = set()

    # Single-threaded to be polite to free APIs
    for target in IL_APEXES_TO_ENUM:
        try:
            r = enrich_target(target)
            new_hosts = r["hosts"] - existing
            new_total.update(new_hosts)
        except Exception as e:
            print(f"  {target}: error {e}", flush=True)

    merged = existing | new_total
    IL_CORPUS.write_text("\n".join(sorted(merged)))
    print(f"\n[+] Done. IL corpus: {len(existing)} → {len(merged)} (+{len(new_total)})", flush=True)


if __name__ == "__main__":
    main()
