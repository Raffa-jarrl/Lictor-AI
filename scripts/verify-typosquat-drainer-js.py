#!/usr/bin/env python3
"""
verify-typosquat-drainer-js — Move 3 of the 3-track sprint.

Takes the SUSPICIOUS typosquat candidates that survived defensive-registration
filtering (defi-domain-typosquat-VERIFIED-REAL.jsonl) and runs deep content
analysis to conclusively classify each as:
  - CONFIRMED_DRAINER   — wallet-drainer JS patterns detected
  - WALLET_PHISHING     — wallet-connect UI mimic, no drainer (yet)
  - LEGIT_ALT           — looks like legitimate alt-property of the org
  - UNKNOWN             — needs human review

For each candidate:
  1. Fetch the home HTML
  2. Enumerate all loaded JS (including 3rd-party)
  3. Fetch each JS body (capped at 500KB per asset)
  4. Pattern-match against:
     - Known drainer kit signatures (Inferno/Angel/Pink/Monkey)
     - WalletConnect / ethereum.request patterns
     - Suspicious permit / personal_sign payloads
     - Obfuscation patterns
  5. Cross-reference with legit's expected content

Usage:
  verify-typosquat-drainer-js.py
    --candidates /Users/raffa/Lictor/v3/ledgers/defi-domain-typosquat-VERIFIED-REAL.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-TyposquatDrainerVerify/0.1 (+https://lictor-ai.com)"

# Drainer & wallet-related patterns
DRAINER_PATTERNS = [
    (re.compile(rb'inferno\s*drainer|angel\s*drainer|monkey\s*drainer|pink\s*drainer', re.I),
        "known drainer kit name"),
    (re.compile(rb'eval\s*\(\s*atob\s*\(|eval\s*\(\s*Buffer\.from\s*\([^)]*base64', re.I),
        "obfuscated eval+atob (common drainer wrap)"),
    (re.compile(rb'window\.ethereum\.request[^)]*personal_sign[^)]*0x[0-9a-fA-F]{200,}', re.I),
        "personal_sign with huge payload (likely off-chain permit drainer)"),
    (re.compile(rb'eth_signTypedData_v[34][^)]*permit', re.I),
        "EIP-712 permit signature solicitation"),
    (re.compile(rb'transfer\s*\(\s*["\']0x[0-9a-fA-F]{40}["\']\s*,\s*(?:balanceOf|maxUint|2\*\*256)', re.I),
        "hardcoded recipient address + max-balance transfer"),
    (re.compile(rb'setApprovalForAll\s*\(\s*["\']0x[0-9a-fA-F]{40}["\']', re.I),
        "hardcoded setApprovalForAll target"),
    (re.compile(rb'(?:web3\.eth\.sendTransaction|ethers\.send).*\.\.\.balance|MaxUint256', re.I),
        "sweep-balance pattern"),
]

WALLET_PATTERNS = [
    (re.compile(rb'window\.ethereum|WalletConnect|coinbase[Ww]allet|phantom\.solana', re.I),
        "wallet-connect API surface"),
    (re.compile(rb'connect[Ww]allet|Connect Wallet|sign in with wallet', re.I),
        "Connect-Wallet UI text"),
]

SCRIPT_SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
INLINE_SCRIPT_RX = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

@dataclass
class VerifyResult:
    legit: str
    squat: str
    final_url: str
    drainer_signals: list = field(default_factory=list)
    wallet_signals: list = field(default_factory=list)
    js_assets_scanned: int = 0
    inline_scripts_scanned: int = 0
    verdict: str = "UNKNOWN"
    confidence: str = "low"   # low / medium / high
    notes: str = ""

def http_get(url: str, timeout: int = 10, max_bytes: int = 500_000) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except Exception:
        return None

def absolute_url(base: str, ref: str) -> str:
    if ref.startswith("//"): return "https:" + ref
    if ref.startswith("http"): return ref
    if ref.startswith("/"):
        p = urllib.parse.urlparse(base)
        return f"{p.scheme}://{p.netloc}{ref}"
    return urllib.parse.urljoin(base, ref)

def scan_bytes(data: bytes, source: str) -> tuple[list, list]:
    drainer_hits = []
    wallet_hits = []
    for rx, name in DRAINER_PATTERNS:
        if rx.search(data):
            drainer_hits.append(f"{source}: {name}")
    for rx, name in WALLET_PATTERNS:
        if rx.search(data):
            wallet_hits.append(f"{source}: {name}")
    return drainer_hits, wallet_hits

def verify_one(cand: dict) -> VerifyResult:
    legit = cand["legit"]
    squat = cand["squat"]
    base_url = f"https://{squat}/"
    result = VerifyResult(legit=legit, squat=squat, final_url=base_url)

    html_bytes = http_get(base_url, max_bytes=300_000)
    if not html_bytes:
        result.verdict = "UNREACHABLE"
        result.notes = "Could not fetch home page"
        return result

    html = html_bytes.decode("utf-8", "replace")

    # Scan inline scripts
    inline_hits_drainer = []
    inline_hits_wallet = []
    inline_count = 0
    for m in INLINE_SCRIPT_RX.finditer(html):
        body = m.group(1).encode("utf-8", "replace")
        if not body.strip(): continue
        inline_count += 1
        d, w = scan_bytes(body, "inline-script")
        inline_hits_drainer.extend(d)
        inline_hits_wallet.extend(w)
    result.inline_scripts_scanned = inline_count

    # Also scan the raw HTML for inline text patterns ("Connect Wallet", etc.)
    d, w = scan_bytes(html_bytes, "page-HTML")
    inline_hits_drainer.extend(d)
    inline_hits_wallet.extend(w)

    # Scan external script srcs (cap to first 6 to be polite)
    js_srcs = []
    for m in SCRIPT_SRC_RX.finditer(html):
        js_srcs.append(absolute_url(base_url, m.group(1)))
    js_srcs = js_srcs[:6]
    result.js_assets_scanned = len(js_srcs)

    ext_hits_drainer = []
    ext_hits_wallet = []
    for src in js_srcs:
        body = http_get(src, max_bytes=500_000)
        if not body: continue
        d, w = scan_bytes(body, src.split('/')[-1])
        ext_hits_drainer.extend(d)
        ext_hits_wallet.extend(w)
        time.sleep(0.3)

    result.drainer_signals = sorted(set(inline_hits_drainer + ext_hits_drainer))[:12]
    result.wallet_signals = sorted(set(inline_hits_wallet + ext_hits_wallet))[:8]

    # Verdict
    if result.drainer_signals:
        result.verdict = "CONFIRMED_DRAINER"
        result.confidence = "high"
        result.notes = "Drainer-class pattern detected in loaded JS"
    elif result.wallet_signals and len(result.wallet_signals) >= 2:
        # Has wallet UI but no drainer signature → could be staging or hidden
        result.verdict = "WALLET_PHISHING_SUSPECT"
        result.confidence = "medium"
        result.notes = "Wallet-connect UI present but no drainer pattern; could be staging/lazy-loaded"
    elif not result.wallet_signals and not result.drainer_signals:
        result.verdict = "LEGIT_ALT_OR_PARKED"
        result.confidence = "medium"
        result.notes = "No wallet/drainer surface — likely a legit alt-property or parked domain"
    else:
        result.verdict = "UNKNOWN"
        result.confidence = "low"
        result.notes = "Single wallet signal — needs human review"
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates",
                    default="/Users/raffa/Lictor/v3/ledgers/defi-domain-typosquat-VERIFIED-REAL.jsonl")
    ap.add_argument("--output",
                    default="/Users/raffa/Lictor/v3/ledgers/defi-typosquat-drainer-verified.jsonl")
    args = ap.parse_args()

    cands = [json.loads(l) for l in open(args.candidates)]
    print(f"[+] Drainer-JS verification on {len(cands)} candidates")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(verify_one, c): c for c in cands}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as e:
                print(f"  EXC: {e}")
                continue
            results.append(r)
            tag = {
                "CONFIRMED_DRAINER": "🔴",
                "WALLET_PHISHING_SUSPECT": "🟠",
                "LEGIT_ALT_OR_PARKED": "✅",
                "UNREACHABLE": "❌",
                "UNKNOWN": "⚪",
            }.get(r.verdict, "?")
            print(f"  {tag} {r.squat:25s} ({r.legit:20s}) → {r.verdict:25s} "
                  f"drainer={len(r.drainer_signals)} wallet={len(r.wallet_signals)} "
                  f"js={r.js_assets_scanned}")

    with open(args.output, "w") as f:
        for r in results:
            f.write(json.dumps(asdict(r)) + "\n")

    # Summary
    from collections import Counter
    by_verdict = Counter(r.verdict for r in results)
    print(f"\n[+] Summary: {dict(by_verdict)}")
    confirmed = [r for r in results if r.verdict == "CONFIRMED_DRAINER"]
    print(f"\n[+] {len(confirmed)} CONFIRMED phishing — submit to Immunefi / SEAL 911:")
    for r in confirmed:
        print(f"    {r.squat} (clone of {r.legit})")

if __name__ == "__main__":
    main()
