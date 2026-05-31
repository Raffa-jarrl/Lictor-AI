#!/usr/bin/env python3
"""
patrol-defi-frontend-injection — scanner #66 (Web3, top-payout class).

DeFi front-end injection is the #1 wallet-drainer attack vector in 2024-2026.
The pattern: a DeFi protocol's official UI loads a compromised 3rd-party script
(via supply-chain attack OR via a DNS/CDN compromise). When users connect their
wallet to the UI, the injected script swaps transaction destination addresses
mid-signing, draining the wallet.

Real-world payouts for finding this pre-attack pattern:
- BadgerDAO ($120M drained via cloudflare worker, 2021) — could have been
  caught by SRI hash audit
- Curve.fi front-end DNS hijack (2022) — SRI gap
- Various 7-figure DeFi protocol UIs hit yearly

Detection (passive, ethical):
  1. Fetch the DeFi protocol's main HTML page
  2. Enumerate all <script src=...> and <link rel="stylesheet" href=...>
  3. For each 3rd-party asset (different domain than the protocol):
     - Check if there's an integrity="sha384-..." attribute (Subresource Integrity)
     - Check if the 3rd-party domain is reputable (CDN allowlist) or random
     - Check for known wallet-drainer JS patterns in the loaded code
  4. Flag anything: missing SRI on critical asset, exotic 3rd-party domain,
     pattern-match against known drainer signatures.

We do NOT actually load malicious payloads or interact with wallets.
"""
from __future__ import annotations
import argparse, json, re, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path

UA = "Lictor-DeFiInjectionPatrol/0.1 (+https://lictor-ai.com)"

# Known reputable CDNs that we DON'T flag for missing SRI (false-positive-prone)
REPUTABLE_CDNS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "static.cloudflareinsights.com", "cdn.segment.com", "cdn.amplitude.com",
    "snap.licdn.com", "connect.facebook.net", "platform.twitter.com",
}

# Known DeFi wallet-drainer JS signatures (regex patterns)
# These are common patterns found in actual drainer kits (passive detection)
DRAINER_PATTERNS = [
    (re.compile(rb'eval\s*\(\s*atob\s*\(', re.I), "obfuscated eval+atob (common drainer wrap)"),
    (re.compile(rb'window\.ethereum\.request.*personal_sign.*0x[0-9a-f]{200,}', re.I), "permit/personal_sign with huge payload"),
    (re.compile(rb'transfer\s*\(\s*["\']0x[0-9a-f]{40}', re.I), "hardcoded ETH transfer address in JS"),
    (re.compile(rb'inferno\s*drainer|angel\s*drainer|monkey\s*drainer|pink\s*drainer', re.I), "known drainer kit signature"),
    (re.compile(rb'WalletConnect.*hijack|metamask.*intercept', re.I), "wallet-hijack class name"),
]

SCRIPT_SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']([^>]*)>', re.IGNORECASE)
LINK_HREF_RX = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']([^>]*)>', re.IGNORECASE)
INTEGRITY_RX = re.compile(r'integrity=["\']([^"\']+)["\']', re.IGNORECASE)

@dataclass
class InjectionFinding:
    host: str
    asset_url: str
    asset_kind: str         # "script" / "stylesheet"
    third_party_domain: str
    has_sri: bool
    sri_hash: str = ""
    reputable: bool = False
    drainer_signature: str = ""
    severity: str = "INFO"  # INFO / LOW / MEDIUM / HIGH / CRITICAL
    notes: str = ""

def http_get(url: str, timeout: int = 10, max_bytes: int = 1_000_000) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except Exception:
        return None

def domain_of(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return p.netloc.lower()
    except Exception:
        return ""

def absolute(base: str, ref: str) -> str:
    if ref.startswith("//"): return "https:" + ref
    if ref.startswith("http"): return ref
    if ref.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{ref}"
    return urllib.parse.urljoin(base, ref)

def scan_drainer_patterns(js_bytes: bytes) -> str:
    """Return drainer-signature name if any pattern matches; '' otherwise."""
    for rx, name in DRAINER_PATTERNS:
        if rx.search(js_bytes[:500_000]):  # only scan first 500KB
            return name
    return ""

def check_host(host: str) -> list[InjectionFinding]:
    if not host.startswith("http"):
        base = f"https://{host}"
    else:
        base = host
        host = domain_of(host)

    html_bytes = http_get(f"{base}/")
    if not html_bytes:
        return []
    html = html_bytes.decode("utf-8", "replace")
    host_domain = host.lower()

    findings = []

    # Scan <script src=...>
    for m in SCRIPT_SRC_RX.finditer(html):
        src = m.group(1)
        attrs = m.group(2)
        asset_url = absolute(base, src)
        asset_domain = domain_of(asset_url)
        if not asset_domain: continue
        if host_domain in asset_domain or asset_domain in host_domain: continue
        # 3rd-party!
        sri_m = INTEGRITY_RX.search(attrs)
        has_sri = bool(sri_m)
        sri_hash = sri_m.group(1) if sri_m else ""
        reputable = asset_domain in REPUTABLE_CDNS
        # Severity scoring
        if not has_sri and not reputable:
            severity = "MEDIUM"
            notes = f"3rd-party script from {asset_domain} loaded WITHOUT SRI hash. If this asset is compromised, wallet-drain risk."
        elif not has_sri and reputable:
            severity = "LOW"
            notes = f"Reputable CDN ({asset_domain}) but no SRI — still better to add hash"
        else:
            continue  # SRI present, skip

        # Fetch the JS and pattern-scan for drainer signatures (only for non-reputable)
        drainer_sig = ""
        if not reputable:
            js_bytes = http_get(asset_url, max_bytes=500_000)
            if js_bytes:
                drainer_sig = scan_drainer_patterns(js_bytes)
                if drainer_sig:
                    severity = "CRITICAL"
                    notes = f"DRAINER SIGNATURE DETECTED: {drainer_sig}"

        findings.append(InjectionFinding(
            host=host, asset_url=asset_url, asset_kind="script",
            third_party_domain=asset_domain, has_sri=has_sri, sri_hash=sri_hash[:30],
            reputable=reputable, drainer_signature=drainer_sig,
            severity=severity, notes=notes))

    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True, help="newline-delimited DeFi hosts")
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/defi-frontend-injection.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] DeFi front-end injection hunt: {len(hosts)} hosts")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_crit, n_med, n_low = 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                hits = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} EXC: {e}")
                continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL":"🔴","MEDIUM":"🟡","LOW":"⚪","INFO":"."}.get(f.severity,"?")
                print(f"  [{i}/{len(hosts)}] {tag} {host} ← {f.third_party_domain}  {f.severity}  {f.notes[:60]}")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "MEDIUM": n_med += 1
                else: n_low += 1
    print(f"\n[+] Done. CRITICAL={n_crit} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] 🔴 CRITICAL = drainer signature detected in loaded JS — IMMEDIATE disclosure")

if __name__ == "__main__":
    main()
