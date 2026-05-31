#!/usr/bin/env python3
"""
patrol-web3-frontend-secrets — hunts crypto/Web3 frontend secret leaks in JS bundles.

Common Web3 frontend bugs that pay $500-10K on Immunefi/HackerOne:
  1. Infura project ID + API secret in client-side JS (paid plans)
  2. Alchemy API key in JS (free tier limit abuse = service outage = bounty)
  3. Moralis API key (server-side scraping abuse)
  4. QuickNode endpoint URL with auth token in path
  5. WalletConnect project ID (less critical)
  6. Hardcoded private keys (rare but exists — usually testnet but sometimes mainnet)
  7. Stripe public_test_key in production (less critical)
  8. Sentry DSN with auth token (lets attacker read crash reports)
  9. Datadog client tokens (lets attacker write fake telemetry)

Algorithm:
  1. Fetch host root + a few common JS chunks (/static/js/*, /_next/static/*)
  2. Regex match each key pattern
  3. Validate non-test (skip "test_", placeholder strings, demo-only Alchemy IDs)

Usage:
  patrol-web3-frontend-secrets.py --hosts hosts.txt --threads 20
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-Web3FrontendSecrets/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# (pattern_name, regex, severity, validator_func_name)
PATTERNS = [
    # Infura project ID (32 hex chars after infura.io/v3/ or infura.io/ipfs/)
    ("infura_project_id", re.compile(rb'infura\.io/(?:v3|ipfs)/([a-f0-9]{32})'), "HIGH"),
    # Infura API secret (base64-ish, 44 chars, follows :secret pattern)
    ("infura_api_secret", re.compile(rb'[a-f0-9]{32}:[A-Za-z0-9+/]{44}'), "CRITICAL"),
    # Alchemy API key (after alchemy.com/v2/)
    ("alchemy_api_key", re.compile(rb'alchemy(?:api)?\.(?:com|io)/v2/([A-Za-z0-9_-]{20,})'), "HIGH"),
    # Moralis API key (long base64-ish, mentioned in API URL)
    ("moralis_api_key", re.compile(rb'(?:moralis|deep-index\.moralis\.io).{0,200}["\']eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']'), "HIGH"),
    # QuickNode auth URL
    ("quicknode_url", re.compile(rb'https?://[a-z0-9-]+\.[a-z0-9-]+\.quiknode\.pro/[a-f0-9]{32}'), "HIGH"),
    # Private key (raw hex, 64 chars after 0x)
    ("eth_private_key", re.compile(rb'(?:privateKey|PRIVATE_KEY|private_key)\s*[:=]\s*["\']0x?([a-fA-F0-9]{64})["\']'), "CRITICAL"),
    # Sentry DSN with auth token
    ("sentry_dsn", re.compile(rb'https://[a-f0-9]{20,40}@[a-z0-9.-]+\.ingest\.[a-z]+\.sentry\.io/\d+'), "HIGH"),
    # Datadog client token
    ("datadog_client_token", re.compile(rb'clientToken[\'"]?\s*:\s*[\'"](pub[a-f0-9]{32})[\'"]'), "MEDIUM"),
    # Standard AWS in JS
    ("aws_akia_in_js", re.compile(rb'AKIA[0-9A-Z]{16}'), "CRITICAL"),
    # Generic OPENAI key
    ("openai_in_js", re.compile(rb'sk-[A-Za-z0-9]{48}'), "CRITICAL"),
    # WalletConnect project ID (32 hex, lower severity)
    ("walletconnect_projid", re.compile(rb'projectId[\'"]?\s*:\s*[\'"]([a-f0-9]{32})[\'"]'), "MEDIUM"),
]

# Dummy / placeholder values to skip (regex matches that aren't real keys)
KNOWN_DUMMIES = {
    b"YOUR_API_KEY_HERE",
    b"AKIAIOSFODNN7EXAMPLE",
    b"00000000000000000000000000000000",
    b"11111111111111111111111111111111",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    b"ffffffffffffffffffffffffffffffff",
    b"demo",
    b"YOUR_INFURA_PROJECT_ID",
}

# JS file paths to probe
JS_PATHS = [
    "/", "/main.js", "/app.js", "/bundle.js", "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js", "/_next/static/chunks/framework.js",
]


@dataclass
class Web3Secret:
    host: str
    secret_class: str
    matched_in_url: str
    matched_value_prefix: str   # first 14 chars only — anti-leak
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http_get(url, max_bytes=2_000_000, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(max_bytes), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(max_bytes), dict(e.headers) if e.headers else {}
        except: return e.code, b"", {}
    except Exception:
        return 0, b"", {}


JS_SRC_RX = re.compile(rb'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)


def find_js_urls(host: str) -> list[str]:
    """Get list of JS URLs from the host's root page (max 5)."""
    status, body, _ = http_get(f"https://{host}/", max_bytes=300_000)
    if status != 200: return []
    urls = []
    for m in JS_SRC_RX.finditer(body[:200_000]):
        src = m.group(1).decode("utf-8", "replace")
        if src.startswith("//"): js_url = f"https:{src}"
        elif src.startswith("/"): js_url = f"https://{host}{src}"
        elif src.startswith("http"):
            # Only same-host or CDN-of-host
            if host not in src and "cdn" not in src.lower(): continue
            js_url = src
        else: js_url = f"https://{host}/{src}"
        urls.append(js_url)
        if len(urls) >= 5: break
    return urls


def is_dummy(value: bytes) -> bool:
    val = value.lower()
    return any(d in val for d in (b.lower() for b in KNOWN_DUMMIES))


def scan_host(host: str) -> list[Web3Secret]:
    findings = []
    seen_secrets = set()  # dedupe within host
    js_urls = find_js_urls(host)
    # Also include common static paths even if not in HTML
    js_urls = list(dict.fromkeys(js_urls + [f"https://{host}{p}" for p in JS_PATHS[1:]]))
    for js_url in js_urls[:8]:
        status, body, _ = http_get(js_url)
        if status != 200 or not body: continue
        for name, pattern, sev in PATTERNS:
            for m in pattern.finditer(body):
                val = m.group(1) if m.lastindex else m.group(0)
                if is_dummy(val): continue
                key = (name, val[:14])
                if key in seen_secrets: continue
                seen_secrets.add(key)
                findings.append(Web3Secret(
                    host=host, secret_class=name, matched_in_url=js_url,
                    matched_value_prefix=val[:14].decode("utf-8", "replace"),
                    severity=sev,
                    notes=f"{name} found in {js_url}",
                ))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/web3-frontend-secrets.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] web3-frontend-secrets — {len(hosts)} hosts × {len(PATTERNS)} patterns")
    n_crit = n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(f.severity, "?")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                else: n_med += 1
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}  {f.secret_class}  prefix={f.matched_value_prefix}")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high} med={n_med}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med}")


if __name__ == "__main__":
    main()
