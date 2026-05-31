#!/usr/bin/env python3
"""
wave-coordinator — iterative batch scanner across the full F500 corpus.

User asked for: "top 10 each time in intervals and then next 10 and again
again and again - we will scan the entire network if needed".

Implementation: for each scanner type, slice the unified F500 host corpus
into batches of N hosts. Run scanner on batch 1, wait for completion, run
on batch 2, etc., until full corpus is covered. Track per-scanner offset
in a state file so we resume cleanly across crashes.

Scanners coordinated:
  sensitive-files-v3       (5000-host batches)
  open-admin-ports         (2000-host batches — port scan is slower)
  takeover-claim-proof     (10000-host batches — fast, just DNS+HTTP)
  graphql-mutations-v2     (5000-host batches)

github-secrets uses a different corpus (program org names, not host list),
so it's NOT coordinated here — it runs end-to-end on the 1058 orgs.

Usage:
  nohup python3 -u scripts/wave-coordinator.py > v3/ledgers/wave-coord.log 2>&1 &
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
from dataclasses import dataclass

ROOT = Path("/Users/raffa/Lictor")
CORPUS = ROOT / "v3" / "ledgers" / "all-bounty-hosts.txt"
STATE = ROOT / "v3" / "ledgers" / "wave-coord-state.json"
LOGS = ROOT / "v3" / "ledgers"

# (script_path, batch_size, threads, ledger_filename, process_name_for_check)
WAVES = [
    {
        "name": "sensitive-files",
        "script": "scripts/patrol-sensitive-files-v3.py",
        "batch_size": 5000,
        "threads": 50,
        "ledger": "v3/ledgers/sensitive-files-v3.jsonl",
        "log": "v3/ledgers/sensitive-files-v3.log",
        "extra_args": [],
    },
    {
        "name": "open-admin-ports",
        "script": "scripts/patrol-open-admin-ports.py",
        "batch_size": 2000,
        "threads": 40,
        "ledger": "v3/ledgers/open-admin-ports.jsonl",
        "log": "v3/ledgers/open-admin-ports.log",
        "extra_args": [],
    },
    {
        "name": "takeover-claim",
        "script": "scripts/patrol-takeover-claim-proof.py",
        "batch_size": 10000,
        "threads": 30,
        "ledger": "v3/ledgers/takeover-claim-proof.jsonl",
        "log": "v3/ledgers/takeover-claim-proof.log",
        "extra_args": [],
    },
    {
        "name": "graphql-mutations",
        "script": "scripts/patrol-graphql-mutations-v2.py",
        "batch_size": 5000,
        "threads": 25,
        "ledger": "v3/ledgers/graphql-mutations-v2.jsonl",
        "log": "v3/ledgers/graphql-mutations-v2.log",
        "extra_args": [],
    },
    {
        "name": "jwt-weakness",
        "script": "scripts/patrol-jwt-weakness.py",
        "batch_size": 3000,
        "threads": 20,
        "ledger": "v3/ledgers/jwt-weakness.jsonl",
        "log": "v3/ledgers/jwt-weakness.log",
        "extra_args": [],
    },
    {
        "name": "web3-jsonrpc",
        "script": "scripts/patrol-web3-jsonrpc-unlocked.py",
        "batch_size": 5000,
        "threads": 30,
        "ledger": "v3/ledgers/web3-jsonrpc-unlocked.jsonl",
        "log": "v3/ledgers/web3-jsonrpc-unlocked.log",
        "extra_args": [],
    },
    {
        "name": "oauth-misconfig",
        "script": "scripts/patrol-oauth-misconfig.py",
        "batch_size": 3000,
        "threads": 25,
        "ledger": "v3/ledgers/oauth-misconfig.jsonl",
        "log": "v3/ledgers/oauth-misconfig.log",
        "extra_args": [],
    },
    {
        "name": "ssrf-reprobe",
        "script": "scripts/patrol-ssrf-reprobe.py",
        "batch_size": 3000,
        "threads": 25,
        "ledger": "v3/ledgers/ssrf-reprobe.jsonl",
        "log": "v3/ledgers/ssrf-reprobe.log",
        "extra_args": [],
    },
    {
        "name": "nuclei-cve",
        "script": "scripts/patrol-nuclei-cve.py",
        "batch_size": 1500,  # Nuclei is heavy — smaller batches
        "threads": 30,
        "ledger": "v3/ledgers/nuclei-cve.jsonl",
        "log": "v3/ledgers/nuclei-cve.log",
        "extra_args": ["--severity", "critical,high", "--rate-limit", "30",
                       "--concurrency", "30"],
    },
    {
        "name": "api-quirks",
        "script": "scripts/patrol-api-quirks.py",
        "batch_size": 3000,
        "threads": 20,
        "ledger": "v3/ledgers/api-quirks.jsonl",
        "log": "v3/ledgers/api-quirks.log",
        "extra_args": [],
    },
    {
        "name": "web3-frontend-secrets",
        "script": "scripts/patrol-web3-frontend-secrets.py",
        "batch_size": 3000,
        "threads": 20,
        "ledger": "v3/ledgers/web3-frontend-secrets.jsonl",
        "log": "v3/ledgers/web3-frontend-secrets.log",
        "extra_args": [],
    },
    {
        "name": "cache-deception",
        "script": "scripts/patrol-cache-deception.py",
        "batch_size": 3000,
        "threads": 25,
        "ledger": "v3/ledgers/cache-deception.jsonl",
        "log": "v3/ledgers/cache-deception.log",
        "extra_args": [],
    },
]


def load_state():
    if STATE.exists():
        try: return json.loads(STATE.read_text())
        except: pass
    return {"offsets": {}, "iterations": {}, "last_check_at": ""}


def save_state(s):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def total_hosts():
    if not CORPUS.exists(): return 0
    return sum(1 for l in CORPUS.read_text().splitlines() if l.strip())


def scanner_running(script_basename: str) -> bool:
    """Check if scanner process is currently running."""
    try:
        r = subprocess.run(["pgrep", "-f", script_basename], capture_output=True, text=True, timeout=3)
        return bool(r.stdout.strip())
    except Exception:
        return False


def make_batch_hosts_file(offset: int, size: int, dest: Path) -> int:
    """Write hosts[offset:offset+size] to dest. Return count written."""
    lines = [l.strip() for l in CORPUS.read_text().splitlines() if l.strip()]
    chunk = lines[offset:offset + size]
    dest.write_text("\n".join(chunk))
    return len(chunk)


def launch_scanner(wave, batch_hosts_path: Path):
    """Launch scanner in background. Returns PID."""
    cmd = [
        "/usr/bin/python3", "-u", str(ROOT / wave["script"]),
        "--hosts", str(batch_hosts_path),
        "--max-hosts", str(wave["batch_size"]),
        "--threads", str(wave["threads"]),
        "--ledger", str(ROOT / wave["ledger"]),
    ] + wave["extra_args"]
    logf = open(ROOT / wave["log"], "a")
    p = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, cwd=str(ROOT))
    return p.pid


MAX_CONCURRENT_SCANNERS = 7  # bumped to 7 — user request "higher efforts scanning today"

# Priority: lower number = scheduled first.
#
# REPRIORITIZED 2026-05-28 — bug-bounty market analysis after 3 N/A closes
# (Coca-Cola, WPEngine, DigitalOcean) showed takeover-claim findings have
# ~0 conversion rate in 2026 (programs require active takeover PoC which
# violates our Constitution Rule 7). Pivoting cycles to scanners whose
# output is CONCRETE EVIDENCE that triagers accept:
#   nuclei-cve, sensitive-files, web3-frontend-secrets, oauth-misconfig.
# Demoted: takeover-claim (priority 99 — runs last, only when nothing else
# is in queue). Eventually move to weekly cron, not daily wave.
SCANNER_PRIORITY = {
    # TIER 1 — high-conversion, concrete evidence (run first)
    "nuclei-cve":             1,   # 4041 templates × 1.5K, CRITICAL CVEs, undeniable PoC
    "sensitive-files":        2,   # .env / .git / wp-config.bak — hard artifact
    "web3-frontend-secrets":  3,   # live keys in JS bundles — pays on Immunefi-class
    "oauth-misconfig":        4,   # metadata probe, real auth issues
    "graphql-mutations":      5,   # introspection + mutation tests
    "jwt-weakness":           6,   # crafted JWT vs baseline
    # TIER 2 — secondary value, runs after Tier 1
    "cache-deception":        7,
    "ssrf-reprobe":           8,
    "api-quirks":             9,
    "open-admin-ports":      10,
    "web3-jsonrpc":          11,
    # TIER 3 — demoted, research-only output (protection-gate hard-blocks
    # submission anyway, so this just keeps the data flow alive)
    "takeover-claim":        99,   # demoted 2026-05-28 — market killed this class
}


def count_running_scanners() -> int:
    n = 0
    for wave in WAVES:
        if scanner_running(os.path.basename(wave["script"])):
            n += 1
    return n


def main():
    print(f"[+] wave-coordinator (ENDLESS, ROUND-ROBIN) starting — corpus has {total_hosts()} hosts, max-concurrent={MAX_CONCURRENT_SCANNERS}", flush=True)
    state = load_state()
    # Round-robin: sort WAVES by fewest iterations first so under-served scanners get priority
    while True:
        total = total_hosts()
        # Primary sort: priority (shortest scanners first per user request)
        # Secondary sort: fewest iterations (least-served scanner gets boost)
        sorted_waves = sorted(
            WAVES,
            key=lambda w: (SCANNER_PRIORITY.get(w["name"], 99),
                           state["iterations"].get(w["name"], 0))
        )
        for wave in sorted_waves:
            if count_running_scanners() >= MAX_CONCURRENT_SCANNERS:
                break
            name = wave["name"]
            offset = state["offsets"].get(name, 0)
            iters = state["iterations"].get(name, 0)
            script_basename = os.path.basename(wave["script"])
            if scanner_running(script_basename):
                continue
            if offset >= total:
                offset = 0
                state["offsets"][name] = 0
                print(f"[ENDLESS] {name} completed full corpus pass — wrapping to offset 0", flush=True)
            batch_path = LOGS / f"_wave-batch-{name}.txt"
            count = make_batch_hosts_file(offset, wave["batch_size"], batch_path)
            if count == 0:
                continue
            pid = launch_scanner(wave, batch_path)
            iters += 1
            new_offset = offset + count
            state["offsets"][name] = new_offset
            state["iterations"][name] = iters
            state["last_check_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save_state(state)
            print(f"[{state['last_check_at']}] {name} wave#{iters} launched PID={pid} hosts={count} offset={offset}-{new_offset}/{total}", flush=True)
        time.sleep(120)


if __name__ == "__main__":
    main()
