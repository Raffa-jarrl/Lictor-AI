#!/usr/bin/env python3
"""
auto-fp-cycle — runs deep-verify-all-now every 30 min on accumulated findings.

User asked: "we also need to run FP once we have findings".

This wraps deep-verify-all-now.py in a loop. Each cycle:
  1. Runs deep-verify-all-now (catchall + scanner-specific re-probe)
  2. Writes results to v3/ledgers/all-findings-verified.jsonl (overwrites)
  3. Sleeps 30 min
  4. Repeats

Honest answer about what verified-real means:
- For sensitive-files: file still serves expected content
- For takeover-claim: claim_status=verified_claimable
- For nuclei-cve: target still responds (NOT a full re-confirmation — manual review needed)
- For others: scanner-specific re-probe

This daemon doesn't fire Telegram. The decision-gate daemon does that
based on the same ledgers.
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")
LOG = ROOT / "v3" / "ledgers" / "auto-fp-cycle.log"
LAST_RUN = ROOT / "v3" / "ledgers" / "auto-fp-cycle-last-run.txt"


def run_verify_pass():
    """Run deep-verify-all-now as a subprocess. Returns elapsed seconds."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"\n[{ts}] === deep-verify-all-now pass starting ===", flush=True)
    t0 = time.time()
    try:
        r = subprocess.run(
            ["/usr/bin/nice", "-n", "10", "/usr/bin/python3", "-u",
             str(ROOT / "scripts" / "deep-verify-all-now.py")],
            capture_output=True, text=True, timeout=1800, cwd=str(ROOT)
        )
        elapsed = time.time() - t0
        # Capture summary from output
        out = r.stdout or ""
        # Pull summary lines
        in_summary = False
        for line in out.split("\n"):
            if "=== SUMMARY ===" in line or "Wrote " in line or "=== TRULY REAL" in line:
                in_summary = True
            if in_summary:
                print(f"  {line}", flush=True)
        print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] done in {elapsed:.0f}s", flush=True)
        LAST_RUN.write_text(json.dumps({
            "ts": ts, "elapsed_seconds": elapsed,
            "exit_code": r.returncode,
        }))
        return elapsed
    except subprocess.TimeoutExpired:
        print(f"[!] deep-verify-all-now timed out after 1800s", flush=True)
        return 1800
    except Exception as e:
        print(f"[!] deep-verify-all-now error: {e}", flush=True)
        return 0


def main():
    print(f"[+] auto-fp-cycle starting — verify pass every 30 min", flush=True)
    while True:
        run_verify_pass()
        # Sleep 30 min between passes
        time.sleep(1800)


if __name__ == "__main__":
    main()
