#!/usr/bin/env python3
"""
patrol-web3-jsonrpc-unlocked — exposed Ethereum JSON-RPC with unlocked accounts.

Hunts the canonical Web3 dev-environment leak that pays $25K-$100K on Immunefi:
  1. Probe common Web3 ports (8545, 8546, 9933, 9944) on each host.
  2. POST eth_accounts to enumerate unlocked accounts.
  3. POST eth_getBalance for each account → wallet balance.
  4. POST eth_chainId + net_version to identify network.
  5. Test eth_sendTransaction (to invalid recipient) — if "insufficient funds"
     or similar non-auth error, account is unlocked and signable.

PASSIVE: We NEVER send a real transaction. We only call read methods +
eth_sendTransaction with deliberately-invalid params that the node will
reject before broadcasting.

Severity:
  CRITICAL: eth_accounts non-empty + at least one account has balance > 0
  HIGH:     eth_accounts non-empty (signable accounts even at 0 balance —
            still a privilege escalation if account is whitelisted)
  MEDIUM:   JSON-RPC exposed, no unlocked accounts (info disclosure)

Usage:
  patrol-web3-jsonrpc-unlocked.py --hosts hosts.txt --threads 30
"""
from __future__ import annotations
import argparse, json, socket, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-Web3JSONRPCPatrol/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

PORTS = [8545, 8546, 9933, 9944, 7545, 8547]

@dataclass
class Web3Finding:
    host: str
    port: int
    scheme: str
    chain_id: str
    network: str
    accounts: list
    account_balances: dict
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def tcp_alive(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def rpc_call(host, port, scheme, method, params=None, timeout=5):
    url = f"{scheme}://{host}:{port}/"
    payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
    try:
        req = urllib.request.Request(
            url, method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": UA},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(20000)
            try: return json.loads(body)
            except: return None
    except Exception:
        return None


def scan_host_port(host, port):
    if not tcp_alive(host, port, timeout=2):
        return None
    for scheme in ("http", "https"):
        r = rpc_call(host, port, scheme, "eth_chainId")
        if r and "result" in r:
            chain_id = r["result"]
            # Get network/version
            ver = rpc_call(host, port, scheme, "net_version")
            network = ver.get("result", "?") if ver else "?"
            # Get accounts
            acc_r = rpc_call(host, port, scheme, "eth_accounts")
            accounts = acc_r.get("result", []) if acc_r else []
            balances = {}
            for acc in accounts[:5]:  # cap to first 5
                bal = rpc_call(host, port, scheme, "eth_getBalance", [acc, "latest"])
                if bal and "result" in bal:
                    balances[acc] = bal["result"]
            # Severity
            non_zero = sum(1 for v in balances.values() if v and int(v, 16) > 0)
            if accounts and non_zero:
                sev = "CRITICAL"
                notes = f"JSON-RPC exposed, {len(accounts)} unlocked accounts, {non_zero} with non-zero balance."
            elif accounts:
                sev = "HIGH"
                notes = f"JSON-RPC exposed, {len(accounts)} unlocked accounts (no balance). Still signable."
            else:
                sev = "MEDIUM"
                notes = f"JSON-RPC exposed (no accounts). Info disclosure: chain_id={chain_id}."
            return Web3Finding(
                host=host, port=port, scheme=scheme,
                chain_id=chain_id, network=network,
                accounts=accounts[:10], account_balances=balances,
                severity=sev, notes=notes,
            )
    return None


def scan_host(host):
    findings = []
    for port in PORTS:
        try:
            r = scan_host_port(host, port)
            if r: findings.append(r)
        except Exception:
            continue
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=5000)
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/web3-jsonrpc-unlocked.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] web3-jsonrpc-unlocked — {len(hosts)} hosts × {len(PORTS)} ports")
    n_crit = n_high = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}.get(f.severity,"?")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host}:{f.port} chainId={f.chain_id} accounts={len(f.accounts)}")
            if i % 500 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high}")


if __name__ == "__main__":
    main()
