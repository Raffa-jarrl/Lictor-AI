#!/usr/bin/env python3
"""
lictor-discover-loop — never-sleep scanner cycler.

Runs forever as a background daemon. Cycles through every scanner with
varying parameters so we never re-query the same slice of GitHub Search.

Each cycle:
  1. Pick the next scanner (round-robin through ROTATION)
  2. Pick a parameter variation (different sort, time window, query subset)
  3. Run it, write to its private MD
  4. Sleep 5 min between cycles to be polite to GitHub API

The hourly cron + drain-queue stay capped at 50/day for SUBMISSIONS, but the
DISCOVERY pool grows constantly. So when drain runs, there's always fresh
candidates.

Architecture:
  Discovery (this script): ALWAYS RUNNING, builds candidate pool
  Submission (hourly cron + drain): RATE-LIMITED, consumes pool

Start:
  nohup python3 scripts/lictor-discover-loop.py > ~/.lictor/discover.log 2>&1 &
  echo $! > ~/.lictor/discover.pid

Stop:
  kill $(cat ~/.lictor/discover.pid)
"""
from __future__ import annotations
import argparse, json, os, signal, subprocess, sys, time
from datetime import datetime
from pathlib import Path

LICTOR_DIR = Path.home() / "Lictor"
STATE_FILE = Path.home() / ".lictor" / "discover-state.json"
LOG_FILE = Path.home() / ".lictor" / "discover.log"
STATE_FILE.parent.mkdir(exist_ok=True)


# Each entry: (scanner script, list of param-variation arg-arrays)
# We cycle through these → no repeat of same query within ROTATION-length time
ROTATION = [
    ("patrol-firebase.py", [
        ["--max", "300", "--max-age-days", "365"],
        ["--max", "400", "--max-age-days", "730"],
        ["--max", "500", "--max-age-days", "180"],
        ["--max", "600", "--max-age-days", "1095"],
    ]),
    ("patrol-db-creds.py", [
        ["--max", "200", "--max-age-days", "365"],
        ["--max", "300", "--max-age-days", "730"],
    ]),
    ("patrol-prtarget.py", [
        ["--max", "300"],
        ["--max", "500"],
    ]),
    ("patrol-saas-keys.py", [
        ["--max", "300", "--max-age-days", "365"],
        ["--max", "500", "--max-age-days", "730"],
    ]),
    ("patrol-cloud-keys.py", [
        ["--max", "300", "--max-age-days", "365"],
        ["--max", "500", "--max-age-days", "730"],
    ]),
    ("patrol-huggingface.py", [
        ["--max", "500", "--sort", "lastModified"],
        ["--max", "500", "--sort", "trendingScore"],
        ["--max", "300", "--sort", "likes"],
    ]),
    ("patrol-pypi.py", [
        ["--max", "200"],
        ["--max", "300"],
    ]),
]


def log(msg):
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def run_one_scan(scanner_script, args, timeout_s=1200):
    """Run a scanner with given args. Capture output, return (rc, hit_count_estimate)."""
    cmd = ["/usr/bin/python3", f"scripts/{scanner_script}"] + args
    log(f"  ▶ {scanner_script} {' '.join(args)}")
    start = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(LICTOR_DIR),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout_s, text=True,
                              env={**os.environ, "GH_TOKEN": open(Path.home()/".lictor"/"gh-token").read().strip()})
        elapsed = int(time.time() - start)
        # Parse "Done. N confirmed/verified" lines
        hits = 0
        for line in (proc.stdout or "").splitlines()[-20:]:
            for kw in ("confirmed", "verified"):
                if kw in line.lower() and "exposures" in line.lower():
                    import re
                    m = re.search(r"(\d+)\s+(?:confirmed|verified)", line)
                    if m: hits = int(m.group(1))
        log(f"    ✓ rc={proc.returncode} elapsed={elapsed}s hits~{hits}")
        return proc.returncode, hits
    except subprocess.TimeoutExpired:
        log(f"    ⏱ timeout after {timeout_s}s")
        return 124, 0
    except Exception as e:
        log(f"    ✗ {type(e).__name__}: {e}")
        return 1, 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sleep-between", type=int, default=300,
                    help="Seconds between scans (default 5 min)")
    ap.add_argument("--max-iterations", type=int, default=0,
                    help="Stop after N iterations (0 = forever)")
    ap.add_argument("--once", action="store_true", help="Run one full rotation cycle and exit")
    args = ap.parse_args()

    # Single-instance lock
    pid_file = Path.home() / ".lictor" / "discover.pid"
    if pid_file.exists():
        existing = pid_file.read_text().strip()
        if existing:
            try:
                os.kill(int(existing), 0)
                log(f"already running as pid {existing} — exiting")
                sys.exit(0)
            except (OSError, ValueError):
                pass  # stale pidfile
    pid_file.write_text(str(os.getpid()))

    def cleanup(*_):
        log("shutting down")
        if pid_file.exists(): pid_file.unlink()
        sys.exit(0)
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    state = load_state()
    state.setdefault("iteration", 0)
    state.setdefault("scanner_idx", 0)
    state.setdefault("variant_idx", {})

    log(f"=== lictor-discover-loop started (pid {os.getpid()}) ===")
    log(f"rotation: {len(ROTATION)} scanners, sleep={args.sleep_between}s between")

    iter_n = 0
    while True:
        scanner_script, variants = ROTATION[state["scanner_idx"] % len(ROTATION)]
        vidx = state["variant_idx"].get(scanner_script, 0) % len(variants)
        variant_args = variants[vidx]

        rc, hits = run_one_scan(scanner_script, variant_args)
        state["iteration"] += 1
        state["scanner_idx"] = (state["scanner_idx"] + 1) % len(ROTATION)
        state["variant_idx"][scanner_script] = (vidx + 1) % len(variants)
        state["last_scan"] = {"scanner": scanner_script, "args": variant_args,
                              "rc": rc, "hits": hits, "ts": datetime.now().isoformat()}
        save_state(state)

        iter_n += 1
        if args.once and state["scanner_idx"] == 0 and iter_n >= len(ROTATION):
            log("--once mode complete")
            break
        if args.max_iterations and iter_n >= args.max_iterations:
            log(f"--max-iterations {args.max_iterations} reached")
            break

        log(f"sleeping {args.sleep_between}s before next scan...")
        time.sleep(args.sleep_between)

    cleanup()


if __name__ == "__main__":
    main()
