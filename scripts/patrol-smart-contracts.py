#!/usr/bin/env python3
"""
patrol-smart-contracts — slither-powered static analysis on Immunefi DeFi contracts.

For each contract address in the target list:
  1. Fetch verified source from Sourcify (free, no API key)
  2. Save to /tmp/lictor-contracts/<chain>/<addr>/
  3. Run slither with --detect <high-impact-detectors>
  4. Parse JSON output, filter to High/Medium severity findings only
  5. Write to ledger

Slither detectors targeted (high bounty-value):
  - reentrancy-eth, reentrancy-no-eth (canonical $10K-1M class)
  - arbitrary-send-erc20, arbitrary-send-eth (funds-drain)
  - controlled-delegatecall (proxy hijack)
  - tx-origin (auth bypass)
  - suicidal (selfdestruct accessible)
  - unprotected-upgrade (admin function exposed)
  - uninitialized-state (storage collision)
  - weak-prng (manipulable RNG)
  - msg-value-loop (gas grief)

Usage:
  patrol-smart-contracts.py --contracts contracts.txt --threads 4
"""
from __future__ import annotations
import argparse, json, os, subprocess, urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SmartContracts/0.1"
ctx = ssl.create_default_context()
SLITHER_BIN = str(Path.home() / "Library" / "Python" / "3.9" / "bin" / "slither")
WORK_DIR = Path("/tmp/lictor-contracts")
WORK_DIR.mkdir(parents=True, exist_ok=True)

HIGH_VALUE_DETECTORS = [
    "reentrancy-eth", "reentrancy-no-eth", "reentrancy-unlimited-gas",
    "arbitrary-send-erc20", "arbitrary-send-erc20-permit",
    "arbitrary-send-eth",
    "controlled-delegatecall",
    "tx-origin",
    "suicidal",
    "unprotected-upgrade",
    "uninitialized-state", "uninitialized-storage",
    "weak-prng",
    "shadowing-state",
    "incorrect-shift",
    "msg-value-loop",
    "delegatecall-loop",
    "encode-packed-collision",
]

# Severity floor — slither uses High/Medium/Low/Informational/Optimization
ACCEPTED_SEVERITY = {"High", "Medium"}


@dataclass
class ContractFinding:
    chain_id: str
    address: str
    contract_name: str
    detector: str
    severity: str       # slither's: High/Medium/Low/Informational
    impact: str
    description: str
    sourcify_match: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def fetch_sourcify(chain_id: str, address: str) -> tuple[str, list[dict]] | None:
    """Returns (match_type, files) or None. Tries full_match first then any."""
    for match_kind in ("full_match", "any"):
        try:
            url = f"https://sourcify.dev/server/files/{match_kind}/{chain_id}/{address}"
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                d = json.loads(r.read())
                if d.get("status") in ("full", "perfect"):
                    return ("full", d.get("files", []))
                if d.get("status") == "partial":
                    return ("partial", d.get("files", []))
        except urllib.error.HTTPError as e:
            if e.code == 404: continue
            continue
        except Exception:
            continue
    return None


def write_contract_files(chain_id: str, address: str, files: list[dict]) -> Path | None:
    """Write all source files to a working dir. Returns dir path with .sol files."""
    out_dir = WORK_DIR / chain_id / address.lower()
    out_dir.mkdir(parents=True, exist_ok=True)
    has_sol = False
    for f in files:
        name = f.get("name", "unnamed")
        content = f.get("content", "")
        # Skip metadata
        if name.endswith(".json") and "metadata" in name.lower(): continue
        # Sanitize filename — keep only the basename + extension
        safe_name = name.replace("/", "_").replace("\\", "_")
        (out_dir / safe_name).write_text(content)
        if safe_name.endswith(".sol"):
            has_sol = True
    return out_dir if has_sol else None


def run_slither(contract_dir: Path, timeout: int = 120) -> dict | None:
    """Run slither, return parsed JSON or None on failure."""
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/Library/Python/3.9/bin:" + env.get("PATH", "")
    detectors = ",".join(HIGH_VALUE_DETECTORS)
    out_json = contract_dir / "slither-out.json"
    cmd = [SLITHER_BIN, ".",
           "--detect", detectors,
           "--json", str(out_json),
           "--solc-disable-warnings"]
    try:
        subprocess.run(cmd, cwd=str(contract_dir), env=env,
                       capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    if not out_json.exists(): return None
    try:
        return json.loads(out_json.read_text())
    except Exception:
        return None


def is_known_fp(check: str, description: str) -> bool:
    """Slither FP class suppression (added 2026-05-28 after SavingsDai noise).

    weak-prng on _rpow/_rmul/_wmul is a TRUE FALSE-POSITIVE — these are
    MakerDAO-style modular exponentiation helpers using `n % 2` for
    bit-checking, not random-number generation. Pattern repeats across
    every DSR-style protocol (sDAI, sUSDe, stETH, etc.).
    """
    if check == "weak-prng":
        # Filter on common modular-exp helper names
        for fn in ("_rpow", "._rpow", "rpow(", "_rmul", "._rmul", "rmul(",
                   "_wmul", "._wmul", "wmul(", "wpow(", "._wpow"):
            if fn in description:
                return True
    return False


def parse_slither(chain_id: str, address: str, source_match: str,
                  slither_result: dict) -> list[ContractFinding]:
    findings = []
    detectors = slither_result.get("results", {}).get("detectors", []) or []
    for det in detectors:
        severity = det.get("impact", "")  # slither uses "impact" field
        if severity not in ACCEPTED_SEVERITY: continue
        check = det.get("check", "?")
        description = det.get("description") or ""
        # Skip known-FP classes before processing
        if is_known_fp(check, description): continue
        # Get contract name from first element
        elements = det.get("elements", []) or []
        contract_name = "?"
        for e in elements:
            tc = e.get("type_specific_fields", {}).get("parent", {})
            if tc.get("type") == "contract":
                contract_name = tc.get("name", "?")
                break
        findings.append(ContractFinding(
            chain_id=chain_id, address=address.lower(),
            contract_name=contract_name, detector=check,
            severity=severity, impact=severity,
            description=description[:500].replace("\n", " "),
            sourcify_match=source_match,
        ))
    return findings


def analyze_one(entry: dict) -> list[ContractFinding]:
    """Entry: {chain_id, address, name}."""
    chain_id = str(entry.get("chain_id", "1"))
    address = entry.get("address", "").lower()
    if not address.startswith("0x") or len(address) != 42: return []
    # Fetch source
    result = fetch_sourcify(chain_id, address)
    if not result: return []
    match_type, files = result
    contract_dir = write_contract_files(chain_id, address, files)
    if not contract_dir: return []
    # Run slither
    slither_out = run_slither(contract_dir)
    if not slither_out: return []
    return parse_slither(chain_id, address, match_type, slither_out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts", required=True,
                    help="JSONL file: {chain_id, address, name}")
    ap.add_argument("--max-contracts", type=int, default=200)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/smart-contracts.jsonl")
    args = ap.parse_args()

    contracts = []
    for line in Path(args.contracts).read_text().splitlines():
        if not line.strip(): continue
        try: contracts.append(json.loads(line))
        except: continue
    contracts = contracts[:args.max_contracts]

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] smart-contracts — {len(contracts)} contracts × slither")
    n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(analyze_one, c): c for c in contracts}
        for i, fut in enumerate(as_completed(futures), 1):
            c = futures[fut]
            try: results = fut.result(timeout=180)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.severity == "High": n_high += 1
                else: n_med += 1
                tag = "🔴" if f.severity == "High" else "🟡"
                print(f"  [{i}/{len(contracts)}] {tag} {f.severity:6s} {f.detector:30s} {c.get('name','?')[:30]:30s}  {f.address[:10]}...")
            if i % 10 == 0:
                print(f"  [{i}/{len(contracts)}] high={n_high} med={n_med}")
    print(f"\n[+] Done. High={n_high} Medium={n_med}")


if __name__ == "__main__":
    main()
