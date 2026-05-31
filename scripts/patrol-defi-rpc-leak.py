#!/usr/bin/env python3
"""
patrol-defi-rpc-leak — scanner #54 (Web3 pivot).

Hunts DeFi front-ends that hardcode RPC provider API keys (Alchemy, Infura,
QuickNode, Ankr, Moralis) in client-side JavaScript bundles.

Bounty rationale: a leaked RPC API key on a major DeFi protocol allows
unauthorized usage of that protocol's paid RPC tier, including:
  - Free queries against archive nodes (worth $/req)
  - DoS by exhausting the rate limit
  - Reading internal endpoints sometimes coupled to admin tier
  - Inference of protocol's bot infrastructure (which addresses they monitor)

Tier: $500-$10K typical (info disclosure with cost-impact). Higher if the
key has elevated tier (archive node, websocket, debug_traceTransaction).

Method (ETHICAL):
  1. For each DeFi host, fetch the homepage HTML.
  2. Extract <script src=...> URLs (main JS bundle + chunked Next.js).
  3. Fetch each JS file.
  4. Regex for embedded RPC API keys:
     - https://eth-mainnet.g.alchemy.com/v2/<KEY>
     - https://mainnet.infura.io/v3/<HEX32>
     - https://<HEX>.quiknode.pro/<HEX>/
     - https://rpc.ankr.com/eth/<KEY>
     - https://site1.moralis-nodes.com/eth/<KEY>
  5. Log + report. We DO NOT use the key.

Usage:
  patrol-defi-rpc-leak.py --hosts defi-hosts.txt --ledger defi-rpc-leak.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-DeFiRPCPatrol/0.1 (+https://lictor-ai.com)"

# RPC key patterns
RPC_KEY_PATTERNS = [
    # provider_name, regex, key_group_index
    ("alchemy",   re.compile(r'https?://[a-z-]+\.g\.alchemy\.com/v2/([A-Za-z0-9_-]{20,})'), 1),
    ("infura",    re.compile(r'https?://[a-z-]+\.infura\.io/v3/([a-f0-9]{32})'), 1),
    ("quicknode", re.compile(r'https?://[a-z0-9-]+\.quiknode\.pro/([a-f0-9]{32,})/?'), 1),
    ("ankr",      re.compile(r'https?://rpc\.ankr\.com/[a-z_]+/([A-Za-z0-9_-]{30,})'), 1),
    ("moralis",   re.compile(r'https?://[a-z0-9-]+\.moralis-nodes\.com/[a-z_]+/([A-Za-z0-9_-]{20,})'), 1),
    ("blast-api", re.compile(r'https?://[a-z-]+\.blastapi\.io/([a-f0-9-]{32,})'), 1),
    ("chainstack", re.compile(r'https?://[a-z0-9-]+\.p2pify\.com/([a-f0-9]{32})'), 1),
    ("pocket",    re.compile(r'https?://[a-z0-9-]+\.gateway\.pokt\.network/v1/lb/([a-f0-9]{20,})'), 1),
]

SCRIPT_SRC_RX = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
JS_INLINE_RX = re.compile(r'<script[^>]*>([^<]+)</script>', re.IGNORECASE | re.DOTALL)

@dataclass
class RPCLeak:
    host: str
    provider: str
    key_redacted: str
    found_in_url: str
    js_source_url: str
    notes: str = ""

def http_get(url: str, timeout: int = 12) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "")
            limit = 2_000_000 if ("javascript" in ct or "html" in ct) else 256_000
            return r.read(limit).decode("utf-8", "replace")
    except Exception:
        return None

def absolute(base: str, ref: str) -> str:
    if ref.startswith("//"): return "https:" + ref
    if ref.startswith("http"): return ref
    if ref.startswith("/"): return base + ref
    return base + "/" + ref

def scan_js(js_text: str, host: str, js_source_url: str) -> list[RPCLeak]:
    leaks = []
    for provider, rx, idx in RPC_KEY_PATTERNS:
        for m in rx.finditer(js_text):
            key = m.group(idx)
            if len(key) < 20: continue
            # Common false positives: placeholder
            if key.lower() in ("your_api_key_here", "your-api-key", "demo", "test"):
                continue
            leaks.append(RPCLeak(
                host=host, provider=provider,
                key_redacted=key[:6] + "..." + key[-4:],
                found_in_url=m.group(0)[:150],
                js_source_url=js_source_url,
                notes=f"matched in {js_source_url[-80:]}"))
            break  # one per provider per file is enough
    return leaks

def check_host(host: str) -> list[RPCLeak]:
    if not host.startswith("http"):
        host_url = f"https://{host}"
    else:
        host_url = host
        host = urllib.parse.urlparse(host).netloc

    # Step 1: fetch homepage
    html = http_get(host_url + "/")
    if not html: return []

    all_leaks = []
    # Inline scripts first
    for m in JS_INLINE_RX.finditer(html):
        all_leaks.extend(scan_js(m.group(1), host, host_url + "/ (inline)"))

    # Find script sources
    script_urls = []
    for m in SCRIPT_SRC_RX.finditer(html):
        try:
            script_urls.append(absolute(host_url, m.group(1)))
        except Exception:
            pass

    # Cap to 30 scripts per page to avoid hammering
    for js_url in script_urls[:30]:
        time.sleep(0.3)
        js_text = http_get(js_url)
        if not js_text: continue
        all_leaks.extend(scan_js(js_text, host, js_url))

    # Dedupe by (provider, key_redacted)
    seen = set()
    out = []
    for L in all_leaks:
        key = (L.provider, L.key_redacted)
        if key in seen: continue
        seen.add(key)
        out.append(L)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/defi-rpc-leak.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] DeFi RPC-key leak hunt across {len(hosts)} hosts")
    print(f"[+] Detects: Alchemy / Infura / QuickNode / Ankr / Moralis / Blast / Chainstack / Pokt")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_total = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                leaks = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} EXC: {e}")
                continue
            for L in leaks:
                ledger.write(json.dumps(asdict(L)) + "\n")
                ledger.flush()
                n_total += 1
                print(f"  [{i}/{len(hosts)}] {host}  🔴 {L.provider}  {L.key_redacted}  ({L.js_source_url[-60:]})")
            if not leaks and i % 15 == 0:
                print(f"  [{i}/{len(hosts)}] (no leaks yet)")

    print(f"\n[+] Done. {n_total} RPC-key leaks discovered → {args.ledger}")
    print(f"[+] Each leak = info-disclosure bounty; rotate-key recommendation goes to the protocol.")

if __name__ == "__main__":
    main()
