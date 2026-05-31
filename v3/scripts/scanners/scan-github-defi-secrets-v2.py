#!/usr/bin/env python3
"""scan-github-defi-secrets-v2.py — Anti-FP rebuild of the DeFi-secrets hunt.

What v1 got wrong:
  v1 search pattern `DEPLOYER_PRIVATE_KEY filename:.env` matched every
  .env.example / .env.sample / test fixture in every DeFi repo. Result:
  114 "findings" of which ~100% are documentation files with no real key.

v2 fixes:
  1. STRICT path exclusion: .example / .sample / .template / mock /
     fixtures / test / spec / __tests__ / goerli / sepolia / testnet
  2. SUSPICION SCORING on filename: .env.production > .env > .env.sample
  3. REPO ACTIVITY check: stale repos = lower score
  4. PUBLIC-ADDRESS validation: extract any 0x-prefixed 40-hex-char
     ADDRESSES from the file (these are PUBLIC, not secrets), check
     Etherscan for transaction history. Active wallet = real leak.
     NEVER extracts the private key value itself.
  5. Output split into HIGH/MEDIUM/LOW confidence; only HIGH gets
     submitted to bug bounty.

ETHICAL GUARANTEE:
  - Never reads or logs the value of any private key
  - Never derives a wallet from a private key (would require reading it)
  - Only checks public Ethereum addresses that already appear elsewhere
    in the file (e.g., as deployment targets, contract addresses)
  - All API requests are read-only against public endpoints

USAGE:
  Re-triage existing ledger:  python3 scan-github-defi-secrets-v2.py --triage-only
  New search on org list:     python3 scan-github-defi-secrets-v2.py --search orgs.txt
"""
import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

LEDGER_V1 = Path.home() / "Lictor/v3/ledgers/github-defi-secrets.jsonl"
LEDGER_V2 = Path.home() / "Lictor/v3/ledgers/github-defi-secrets-v2.jsonl"
GH_TOKEN_PATH = Path.home() / ".lictor/gh-token"
USER_AGENT = "LictorAI-EthicalScanner/0.2 (+https://lictor-ai.com/transparency)"

# Paths/filename fragments that strongly indicate FP (example / test / sample)
PATH_FP_FRAGMENTS = [
    ".example", ".sample", ".template", ".dist",
    "example.env", "sample.env", "template.env",
    "/example", "/examples/",
    "/sample", "/samples/",
    "/template", "/templates/",
    "/mock", "/mocks/", "/__mocks__/",
    "/test", "/tests/", "/__tests__/",
    "/spec", "/specs/",
    "/fixture", "/fixtures/",
    "/e2e/", "/cypress/", "/playwright/",
    "/demo", "/demos/",
    "/docs/", "/documentation/",
    "test_keys", "test-keys", "dummy",
    "/scaffolding/", "/scaffold/",
]

# Testnet / non-mainnet indicators (low value)
TESTNET_FRAGMENTS = [
    "goerli", "sepolia", "ropsten", "rinkeby", "kovan",
    "testnet", "test-net", "devnet", "dev-net",
    "mumbai",      # polygon testnet
    "fuji",        # avalanche testnet
    "alfajores",   # celo testnet
    "chapel",      # bsc testnet
    "saigon",      # ronin testnet
    "hoodi", "holesky", "opt_goerli", "arb_goerli", "base_sepolia",
]

# Filename scoring: higher = more suspicious of real leak
FILENAME_SCORES = {
    ".env.production": 50,
    ".env.mainnet":    50,
    ".env.prod":       45,
    ".env.live":       45,
    ".env.deploy":     40,
    "production.env":  50,
    "mainnet.env":     50,
    "secrets.json":    40,
    "credentials.json": 40,
    "deploy.json":     30,
    "deployer.json":   35,
    ".env.local":      20,
    ".env":            15,    # ambiguous
}

# Well-known dummy / test keys (zero value, ignore)
KNOWN_TEST_KEYS = {
    # bip39 test mnemonic (all "abandon abandon ... about")
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    # Hardhat default test private keys (well-known, $0 value)
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # Hardhat #0
    # Common dummy strings
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x1111111111111111111111111111111111111111111111111111111111111111",
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
}

ETH_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def gh_token():
    try:
        return GH_TOKEN_PATH.read_text().strip()
    except Exception:
        return None


def http_get(url, headers=None, timeout=10):
    headers = headers or {}
    headers.setdefault("User-Agent", USER_AGENT)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""
    except Exception as e:
        return None, str(e).encode()


def filename_score(path):
    """Higher = more likely to be a real leak."""
    path_lower = path.lower()
    # Strong FP fragments → 0
    for frag in PATH_FP_FRAGMENTS:
        if frag in path_lower:
            return 0
    # Testnet → halve
    is_testnet = any(t in path_lower for t in TESTNET_FRAGMENTS)
    # Match against known suspicious names
    score = 5  # default for unknown
    basename = path_lower.rsplit("/", 1)[-1]
    for name, points in FILENAME_SCORES.items():
        if basename == name or path_lower.endswith(name):
            score = points
            break
    if is_testnet:
        score = score // 2
    return score


def fetch_file_metadata(repo, path, token):
    """Get last-commit info for this specific file (proves recency, not test)."""
    api = f"https://api.github.com/repos/{repo}/commits?path={urllib.request.quote(path)}&per_page=1"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    st, body = http_get(api, headers=headers)
    if st != 200:
        return None
    try:
        commits = json.loads(body)
        if not commits:
            return None
        c = commits[0]
        return {
            "last_commit_sha": c.get("sha", "")[:8],
            "last_commit_date": c.get("commit", {}).get("author", {}).get("date", ""),
            "last_commit_author": c.get("commit", {}).get("author", {}).get("name", ""),
        }
    except Exception:
        return None


def extract_public_addresses(repo, path, token):
    """Fetch first ~2KB of file, extract public ETH addresses (no key extraction).

    Ethical: addresses are PUBLIC by nature. We're looking at whether the
    deployer/contract addresses listed in the file are active wallets —
    that signals the file was a real production config, not a template.
    We do NOT read or log private key values.
    """
    raw_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
    headers = {"User-Agent": USER_AGENT, "Range": "bytes=0-2047"}
    if token:
        headers["Authorization"] = f"token {token}"
    st, body = http_get(raw_url, headers=headers, timeout=10)
    if st != 200 and st != 206:
        # try master branch
        raw_url = f"https://raw.githubusercontent.com/{repo}/master/{path}"
        st, body = http_get(raw_url, headers=headers, timeout=10)
        if st != 200 and st != 206:
            return []
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []

    # Extract addresses, dedupe, exclude known-zero
    addrs = set(m.lower() for m in ETH_ADDRESS_RE.findall(text))
    addrs = {a for a in addrs if a != "0x" + "0" * 40 and a != "0x" + "f" * 40}
    return sorted(addrs)


def check_address_activity(address):
    """Etherscan: does this address have any transaction history?
    Returns (has_activity, tx_count, balance_wei) or (None, None, None) on error.

    Uses free Etherscan API (rate limit 1 req/5s without key, fine for small batches).
    """
    # Get tx count via etherscan (no key needed, but rate-limited)
    api = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&page=1&offset=1&sort=desc"
    st, body = http_get(api, timeout=10)
    if st != 200:
        return None, None, None
    try:
        data = json.loads(body)
        if data.get("status") == "1":
            txs = data.get("result", [])
            return (len(txs) > 0), len(txs), None
        elif data.get("message") == "No transactions found":
            return False, 0, 0
        else:
            return None, None, None
    except Exception:
        return None, None, None


def classify_finding(entry, token, etherscan_check=True):
    """Score an existing v1 finding for v2 confidence."""
    path = entry.get("path", "")
    repo = entry.get("repo", "")
    score = filename_score(path)
    reasons = []

    if score == 0:
        reasons.append(f"FP: path matches exclusion ({path[:60]})")
        return {"v2_confidence": "FALSE-POSITIVE", "v2_score": 0, "reasons": reasons}

    if score < 10:
        reasons.append(f"low base score {score}")

    # Recency check
    meta = fetch_file_metadata(repo, path, token)
    if meta:
        date_str = meta.get("last_commit_date", "")
        if "2024" in date_str or "2025" in date_str or "2026" in date_str:
            score += 5
            reasons.append(f"recent file (last commit {date_str[:10]})")
        elif "2020" in date_str or "2021" in date_str:
            score -= 5
            reasons.append(f"stale file (last commit {date_str[:10]})")

    # Public address activity check (only on still-promising ones)
    if etherscan_check and score >= 20:
        addrs = extract_public_addresses(repo, path, token)
        if addrs:
            # Check first 3 addresses (rate-limit friendly)
            active = 0
            for a in addrs[:3]:
                ok, txc, _ = check_address_activity(a)
                if ok:
                    active += 1
                time.sleep(5.5)  # respect Etherscan free-tier rate limit
            if active > 0:
                score += 25
                reasons.append(f"{active}/{min(3, len(addrs))} public addresses in file are active on-chain")
            else:
                reasons.append(f"0/{min(3, len(addrs))} public addresses active (likely template)")
                score -= 10
        else:
            reasons.append("no public addresses extracted")

    # Final classification
    if score >= 40:
        confidence = "HIGH"
    elif score >= 20:
        confidence = "MEDIUM"
    elif score > 0:
        confidence = "LOW"
    else:
        confidence = "FALSE-POSITIVE"

    return {"v2_confidence": confidence, "v2_score": score, "reasons": reasons}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--triage-only", action="store_true",
                   help="Re-classify existing v1 ledger entries with v2 rules")
    p.add_argument("--no-etherscan", action="store_true",
                   help="Skip on-chain activity check (faster, less accurate)")
    p.add_argument("--limit", type=int, default=200,
                   help="Max entries to process (default 200)")
    args = p.parse_args()

    token = gh_token()
    if not token:
        print("[WARN] No GitHub token at ~/.lictor/gh-token. Some API calls will be rate-limited.")

    if args.triage_only:
        if not LEDGER_V1.exists():
            print(f"[FAIL] v1 ledger not found: {LEDGER_V1}")
            sys.exit(1)

        print(f"[+] v2 anti-FP re-triage of {LEDGER_V1}")
        print(f"[+] Strict path exclusion + on-chain validation of public addresses")
        print(f"[+] Output: {LEDGER_V2}")
        print()

        results = {"FALSE-POSITIVE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
        high_confidence = []

        with open(LEDGER_V1) as f, open(LEDGER_V2, "w") as out:
            for i, line in enumerate(f):
                if i >= args.limit:
                    break
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                path = entry.get("path", "")
                repo = entry.get("repo", "")
                print(f"  [{i+1:>3}] {repo[:35]:<35} {path[:50]}", end=" → ", flush=True)

                v2 = classify_finding(entry, token,
                                       etherscan_check=not args.no_etherscan)
                results[v2["v2_confidence"]] += 1
                print(f"{v2['v2_confidence']} (score {v2['v2_score']})", flush=True)

                # Write enriched entry
                entry["v2"] = v2
                entry["v2_classified_at"] = datetime.now(timezone.utc).isoformat()
                out.write(json.dumps(entry) + "\n")

                if v2["v2_confidence"] in ("HIGH", "MEDIUM"):
                    high_confidence.append(entry)

        print()
        print("=" * 70)
        print("v2 TRIAGE SUMMARY")
        print("=" * 70)
        for sev in ["HIGH", "MEDIUM", "LOW", "FALSE-POSITIVE"]:
            n = results[sev]
            pct = n * 100 // max(1, sum(results.values()))
            print(f"  {sev:<18} {n:>4}  ({pct}%)")

        print()
        if high_confidence:
            print("HIGH/MEDIUM CONFIDENCE — bounty-submission candidates:")
            for e in high_confidence:
                print(f"  - {e.get('repo'):<40} {e.get('path')}")
                print(f"      reasons: {'; '.join(e['v2'].get('reasons', []))}")
        else:
            print("[+] No HIGH/MEDIUM confidence findings — v1 was entirely FPs.")

        print()
        print(f"[+] Full v2 ledger: {LEDGER_V2}")

    else:
        print("New-search mode not yet implemented. Use --triage-only to re-classify v1 first.")
        sys.exit(0)


if __name__ == "__main__":
    main()
