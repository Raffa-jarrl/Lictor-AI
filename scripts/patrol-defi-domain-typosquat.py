#!/usr/bin/env python3
"""
patrol-defi-domain-typosquat — scanner #68.

Hunts lookalike domains that imitate top DeFi protocols to phish + drain wallets.
The wallet-drainer-via-phishing class is responsible for an estimated $300M+/year
in stolen funds, per Chainalysis.

Strategy (passive, ethical):
  1. For each legitimate DeFi domain (uniswap.org, app.aave.com, etc.):
     - Generate typosquat candidates (DNStwist-style mutations)
     - DNS-resolve each candidate
     - For each resolving candidate:
       * Compare the rendered HTML/structure to the legit site
       * If high similarity AND not owned by the legitimate org → phishing candidate
       * Report to: the affected DeFi protocol + the registrar (for takedown)

Pays well in two ways:
  - Some DeFi protocols offer bug bounties for phishing-infrastructure finds
  - Drainer hunters / community reward services (e.g. SEAL 911, Web3 Antivirus)
    sometimes pay for verified phishing leads

Usage:
  patrol-defi-domain-typosquat.py --hosts defi-hosts.txt
"""
from __future__ import annotations
import argparse, json, socket, time, urllib.request, urllib.error, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-DeFiPhishPatrol/0.1 (+https://lictor-ai.com)"

# DNStwist-style mutations
def typo_mutations(domain: str) -> list[str]:
    """Generate typosquat domain candidates."""
    if "." not in domain: return []
    name, tld = domain.rsplit(".", 1)
    out = set()

    # Char swap (adjacent)
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        out.add(f"{swapped}.{tld}")

    # Char doubling
    for i, ch in enumerate(name):
        out.add(f"{name[:i+1]}{ch}{name[i+1:]}.{tld}")

    # Char dropping
    for i in range(len(name)):
        out.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # Common confusions
    for orig, sub in [("o", "0"), ("i", "1"), ("l", "1"), ("e", "3"),
                       ("a", "4"), ("s", "5"), ("g", "9"), ("rn", "m"), ("vv", "w")]:
        if orig in name:
            out.add(f"{name.replace(orig, sub, 1)}.{tld}")

    # Common TLDs swap
    for new_tld in ("com", "io", "xyz", "app", "net", "co", "fi", "finance", "org"):
        if new_tld != tld:
            out.add(f"{name}.{new_tld}")

    # Hyphens
    if "-" not in name and len(name) > 5:
        mid = len(name) // 2
        out.add(f"{name[:mid]}-{name[mid:]}.{tld}")

    # Remove the original
    out.discard(domain.lower())
    return sorted(out)

@dataclass
class PhishCandidate:
    legit_domain: str
    candidate_domain: str
    resolves: bool
    similarity_score: int = 0   # 0-100
    legit_hash_match: bool = False
    notes: str = ""
    severity: str = "INFO"

def resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return True
    except Exception:
        return False

def fetch_html_signature(host: str, timeout: int = 6) -> tuple[str, int]:
    """Return (md5-of-title-and-meta-section, byte-size) for similarity comparison."""
    url = f"https://{host}/"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(50_000).decode("utf-8", "replace")
            # Extract title + meta-section for signature
            import re
            title_m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
            title = title_m.group(1).strip() if title_m else ""
            metas = re.findall(r'<meta[^>]+>', body, re.I)
            sig = title + "\n" + "\n".join(sorted(metas[:10]))
            return hashlib.md5(sig.encode()).hexdigest(), len(body)
    except Exception:
        return "", 0

def check_legit_domain(legit: str, max_candidates: int = 25) -> list[PhishCandidate]:
    legit_hash, _ = fetch_html_signature(legit)
    if not legit_hash:
        # Can't establish baseline — skip
        return []
    candidates = typo_mutations(legit)[:max_candidates]
    findings = []
    for cand in candidates:
        time.sleep(0.3)
        if not resolves(cand):
            continue
        # Resolves → fetch and compare
        cand_hash, cand_size = fetch_html_signature(cand)
        if not cand_hash:
            findings.append(PhishCandidate(
                legit_domain=legit, candidate_domain=cand,
                resolves=True, severity="LOW",
                notes="DNS resolves but no HTTPS response"))
            continue
        sim = 100 if cand_hash == legit_hash else 0
        severity = "INFO"
        notes = ""
        if sim == 100:
            severity = "HIGH"
            notes = "Title + meta-tag signature IDENTICAL to legit site = likely a clone-phishing target"
        elif cand_size > 1000:
            # Resolves + returns content, but different
            severity = "MEDIUM"
            notes = "Resolves + returns content; might be parked/squatted/unrelated"
        findings.append(PhishCandidate(
            legit_domain=legit, candidate_domain=cand,
            resolves=True, similarity_score=sim,
            legit_hash_match=(sim == 100), severity=severity, notes=notes))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/defi-domain-typosquat.jsonl")
    ap.add_argument("--max-candidates", type=int, default=25)
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] DeFi domain-typosquat hunt: {len(hosts)} legit domains × ~{args.max_candidates} mutations each")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_hi, n_med, n_low = 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_legit_domain, h, args.max_candidates): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            legit = futures[fut]
            try:
                hits = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {legit} EXC: {e}")
                continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"⚪","INFO":"."}.get(f.severity,"?")
                print(f"  [{i}/{len(hosts)}] {tag} {legit} ← {f.candidate_domain}  {f.severity}  {f.notes[:60]}")
                if f.severity == "HIGH": n_hi += 1
                elif f.severity == "MEDIUM": n_med += 1
                else: n_low += 1
    print(f"\n[+] Done. HIGH={n_hi} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] 🔴 HIGH = signature-identical clone (likely phishing target) — disclose to legit org + registrar")

if __name__ == "__main__":
    main()
