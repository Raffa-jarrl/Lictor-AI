#!/usr/bin/env python3
"""
watchdog — keeps critical Lictor processes alive for the 12hr autonomous run.

Checks every 5 minutes:
  - wave-coordinator (auto-launches next batch when scanners finish)
  - verify-and-notify-f500 (gates findings → verified-leads ledger)
  - submission-queue-builder (drafts disclosures from verified leads)
  - telegram-bot-listener (user remote control)
  - orchestrate-f500-deep-scan (F500 sweep, only if still pending)

If any is dead, restarts it. Logs each restart to watchdog.log.

Usage:
  nohup python3 -u scripts/watchdog.py > v3/ledgers/watchdog.log 2>&1 &
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")

# (script_basename, restart_command_template, optional_skip_condition)
CRITICAL = [
    {
        "name": "wave-coordinator",
        "match": "wave-coordinator.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/wave-coordinator.py"],
        "log": "v3/ledgers/wave-coord.log",
    },
    {
        "name": "verify-and-notify-f500",
        "match": "verify-and-notify-f500.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/verify-and-notify-f500.py"],
        "log": "v3/ledgers/verify-notify.log",
    },
    {
        "name": "submission-queue-builder",
        "match": "submission-queue-builder.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/submission-queue-builder.py"],
        "log": "v3/ledgers/sq-builder.log",
    },
    {
        "name": "telegram-bot-listener",
        "match": "telegram-bot-listener.py",
        "cmd": ["/usr/bin/python3", "-u", "v3/scripts/telegram-bot-listener.py"],
        "log": "v3/ledgers/telegram-listener.log",
    },
    {
        "name": "decision-gate",
        "match": "decision-gate.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/decision-gate.py"],
        "log": "v3/ledgers/decision-gate.log",
    },
    {
        "name": "auto-fp-cycle",
        "match": "auto-fp-cycle.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/auto-fp-cycle.py"],
        "log": "v3/ledgers/auto-fp-cycle.log",
    },
    {
        "name": "protection-gate",
        "match": "protection-gate.py",
        "cmd": ["/usr/bin/python3", "-u", "scripts/protection-gate.py"],
        "log": "v3/ledgers/protection-gate.log",
    },
]


def is_running(match: str) -> bool:
    try:
        r = subprocess.run(["pgrep", "-f", match], capture_output=True, text=True, timeout=3)
        return bool(r.stdout.strip())
    except Exception:
        return False


def restart(svc: dict):
    logf = open(ROOT / svc["log"], "a")
    proc = subprocess.Popen(svc["cmd"], stdout=logf, stderr=subprocess.STDOUT, cwd=str(ROOT))
    return proc.pid


def main():
    print(f"[+] watchdog starting at {datetime.now(timezone.utc).isoformat()}", flush=True)
    restart_counts = {svc["name"]: 0 for svc in CRITICAL}
    last_digest_at = 0
    while True:
        now_ts = time.time()
        # Check each critical service
        for svc in CRITICAL:
            if not is_running(svc["match"]):
                pid = restart(svc)
                restart_counts[svc["name"]] += 1
                msg = f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] RESTARTED {svc['name']} (PID={pid}, restart #{restart_counts[svc['name']]})"
                print(msg, flush=True)
                # Notify Telegram on unexpected restarts (after first 2)
                if restart_counts[svc["name"]] > 1:
                    try:
                        sys.path.insert(0, str(ROOT / "v3" / "scripts"))
                        from notify_telegram import notify
                        notify(f"watchdog: restarted {svc['name']} (now restart #{restart_counts[svc['name']]})",
                               parse_mode="")
                    except Exception: pass
        # NO heartbeat — user is allergic to Telegram noise.
        # Use the Telegram bot's /status command to pull state on demand.
        time.sleep(300)  # 5 min between checks


def send_heartbeat():
    """2-hour digest: scan progress + verified queue size."""
    sys.path.insert(0, str(ROOT / "v3" / "scripts"))
    from notify_telegram import notify
    # Gather stats
    try:
        wave_state = json.loads((ROOT / "v3" / "ledgers" / "wave-coord-state.json").read_text())
        progress = []
        for name, off in wave_state.get("offsets", {}).items():
            it = wave_state.get("iterations", {}).get(name, 0)
            pct = min(100, int(off * 100 / 33426))
            progress.append(f"{name}={pct}% (wave#{it})")
    except: progress = ["wave state unavailable"]

    try:
        f500_state = json.loads((ROOT / "v3" / "ledgers" / "f500" / "_orchestrator-state.json").read_text())
        f500_done = len(f500_state.get("completed", []))
    except: f500_done = "?"

    try:
        q = (ROOT / "v3" / "ledgers" / "submission-queue.jsonl").read_text().splitlines()
        ready = sum(1 for l in q if l.strip() and json.loads(l).get("status") == "READY_FOR_REVIEW")
        stale = sum(1 for l in q if l.strip() and json.loads(l).get("status") == "STALE_AT_VERIFY")
    except: ready = stale = "?"

    msg = (f"HEARTBEAT (2hr): all systems running.\n"
           f"F500: {f500_done}/577\n"
           f"Wave progress:\n  " + "\n  ".join(progress) + "\n"
           f"Submission queue: {ready} ready, {stale} stale\n"
           f"Drafts: v3/ledgers/submissions/")
    notify(msg, parse_mode="")


if __name__ == "__main__":
    main()
