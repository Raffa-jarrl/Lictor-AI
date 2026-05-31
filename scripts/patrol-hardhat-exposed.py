#!/usr/bin/env python3
"""
patrol-hardhat-exposed — scanner #53 (Web3 pivot).

Hunts publicly-reachable Hardhat / Foundry Anvil / Brownie / Ganache
developer JSON-RPC consoles. These accept arbitrary signed transactions
from unlocked dev accounts (often pre-funded with 10000 ETH on a forked
mainnet state).

Bounty rationale: an exposed dev RPC on a DeFi project's infrastructure
can let an attacker:
  - Drain the dev wallet (often holds real testnet funds reusable on mainnet
    if the same seed is used cross-chain)
  - Inspect deployment scripts and forked-mainnet state
  - In rare cases: trigger admin-only function calls on real mainnet
    contracts (if the dev console is connected to a forked mainnet with the
    same private key that owns the contract).

Tier: $5K-$100K per Immunefi disclosure for an exposed RPC on a major DeFi
infra org. Lower for staging/test RPC on smaller projects.

Method (ETHICAL):
  1. For each candidate host: probe known dev-RPC ports (8545, 8546, 9545)
     AND common paths on standard HTTPS (443) — /rpc, /api/rpc, /jsonrpc.
  2. Send the harmless eth_chainId JSON-RPC call.
  3. If response is valid JSON-RPC: it's a RPC endpoint.
  4. Send eth_accounts (lists unlocked accounts on the dev node — Hardhat
     auto-unlocks 20 by default).
  5. If non-empty accounts list: this is a DEV NODE (not a public node).
  6. Log + STOP. Do NOT send transactions, do NOT call eth_sendTransaction,
     do NOT call eth_sign.

Usage:
  patrol-hardhat-exposed.py --hosts defi-hosts.txt --ledger hardhat-exposed.jsonl
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-HardhatPatrol/0.1 (+https://lictor-ai.com)"

CANDIDATE_ENDPOINTS = [
    # (scheme, port, path)
    ("http",  8545, "/"),
    ("https", 8545, "/"),
    ("http",  8546, "/"),
    ("https", 8546, "/"),
    ("http",  9545, "/"),
    ("http",  9933, "/"),   # Substrate dev port
    ("https",  443, "/rpc"),
    ("https",  443, "/api/rpc"),
    ("https",  443, "/jsonrpc"),
    ("https",  443, "/json-rpc"),
    ("https",  443, "/eth"),
    ("https",  443, "/"),
    ("http",   80, "/rpc"),
]

CHAIN_ID_RPC = json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}).encode()
ACCOUNTS_RPC = json.dumps({"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 2}).encode()

@dataclass
class RPCFinding:
    host: str
    scheme: str
    port: int
    path: str
    is_jsonrpc: bool
    chain_id: str = ""
    unlocked_accounts_count: int = 0
    sample_address: str = ""
    is_dev_node: bool = False
    notes: str = ""

def post_jsonrpc(url: str, body: bytes, timeout: int = 6):
    req = urllib.request.Request(url, data=body,
                                  headers={"User-Agent": UA,
                                           "Content-Type": "application/json",
                                           "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(8192).decode("utf-8", "replace")
        except Exception: b = ""
        return e.code, b
    except Exception:
        return None, None

def parse_jsonrpc(body: str):
    if not body: return None
    try:
        j = json.loads(body)
        if isinstance(j, dict) and ("result" in j or "error" in j):
            return j
    except Exception:
        return None
    return None

def probe_endpoint(host: str, scheme: str, port: int, path: str) -> RPCFinding | None:
    if scheme == "https" and port == 443:
        url = f"https://{host}{path}"
    elif scheme == "http" and port == 80:
        url = f"http://{host}{path}"
    else:
        url = f"{scheme}://{host}:{port}{path}"

    # Test 1: eth_chainId — universal sanity check
    status, body = post_jsonrpc(url, CHAIN_ID_RPC)
    j = parse_jsonrpc(body or "")
    if not j: return None
    if "error" in j and "result" not in j:
        # Some RPC nodes restrict methods — note it but don't pursue
        return RPCFinding(host=host, scheme=scheme, port=port, path=path,
                          is_jsonrpc=True, notes="restricted_methods")

    chain_id = j.get("result", "")

    # Test 2: eth_accounts (ONLY if eth_chainId worked — saves rate)
    time.sleep(0.5)
    status2, body2 = post_jsonrpc(url, ACCOUNTS_RPC)
    j2 = parse_jsonrpc(body2 or "")
    accounts = []
    if j2 and "result" in j2 and isinstance(j2["result"], list):
        accounts = j2["result"]

    is_dev = len(accounts) > 0  # Public Ethereum nodes return [] for eth_accounts
    sample = accounts[0] if accounts else ""

    return RPCFinding(
        host=host, scheme=scheme, port=port, path=path,
        is_jsonrpc=True, chain_id=str(chain_id),
        unlocked_accounts_count=len(accounts),
        sample_address=sample,
        is_dev_node=is_dev,
        notes="DEV_NODE_DETECTED" if is_dev else "public_or_restricted")

def check_host(host: str) -> list[RPCFinding]:
    findings = []
    for scheme, port, path in CANDIDATE_ENDPOINTS:
        try:
            f = probe_endpoint(host, scheme, port, path)
            if f: findings.append(f)
        except Exception:
            pass
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/hardhat-exposed.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] Hardhat/Anvil/Brownie/Ganache exposure hunt across {len(hosts)} hosts")
    print(f"[+] ETHICS: only eth_chainId + eth_accounts. NEVER sends transactions or signatures.")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_dev, n_public = 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                findings = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} EXC: {e}")
                continue
            for f in findings:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.is_dev_node:
                    n_dev += 1
                    print(f"  [{i}/{len(hosts)}] {host}  🔴 DEV_NODE  "
                          f"chain={f.chain_id}  accounts={f.unlocked_accounts_count}  "
                          f"@{f.scheme}://{host}:{f.port}{f.path}")
                else:
                    n_public += 1
                    print(f"  [{i}/{len(hosts)}] {host}  🟡 public-RPC  chain={f.chain_id}  "
                          f"@{f.scheme}://{host}:{f.port}{f.path}")

    print(f"\n[+] Done. dev_nodes={n_dev} public_rpc={n_public}")
    print(f"[+] Ledger: {args.ledger}")
    print(f"[+] 🔴 dev_node findings = Immunefi-tier severity if on prod DeFi infra.")

if __name__ == "__main__":
    main()
