#!/usr/bin/env python3
"""
telegram-bot-listener — bidirectional Telegram control for Lictor.

Listens for commands from the configured chat_id (anti-spoof) and executes
whitelisted actions. Run as a background daemon.

Commands:
  /status                  — current scanners + recent findings
  /running                 — list active scan processes
  /findings [N]            — show recent findings (default 10)
  /f500                    — F500 orchestrator progress
  /scan <type> <target>    — launch a scan (sourcemap, takeover, cicd, terraform, cors)
  /kill <pid>              — kill a scan process
  /tail <log-name>         — tail last 20 lines of a log file
  /ledgers                 — list ledgers with finding counts
  /companies-with-findings — F500 companies that produced findings
  /help                    — this list

Security:
  - Only responds to the configured chat_id (no spoofing)
  - Whitelisted commands only (no arbitrary shell)
  - All commands logged to v3/ledgers/telegram-commands.jsonl
  - kill is restricted to processes owned by the user

Run:
  python3 telegram-bot-listener.py &  # background daemon
"""
from __future__ import annotations
import json, os, stat, sys, time, signal, subprocess, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/Users/raffa/Lictor")
SECRETS_DIR = Path.home() / ".lictor" / "secrets"
LEDGER_DIR = ROOT / "v3" / "ledgers"
OFFSET_FILE = LEDGER_DIR / "telegram-listener-offset.txt"
CMD_LOG = LEDGER_DIR / "telegram-commands.jsonl"
F500_DIR = LEDGER_DIR / "f500"
UA = "Lictor-TgListener/0.1 (+https://lictor-ai.com)"

def _load(name: str) -> str:
    path = SECRETS_DIR / name
    if not path.exists():
        sys.exit(f"missing {path}")
    perms = stat.S_IMODE(path.stat().st_mode)
    if perms & 0o077:
        sys.exit(f"{path} too permissive: {oct(perms)}")
    return path.read_text().strip()

TOKEN = _load("telegram.bot-token")
CHAT_ID = int(_load("telegram.chat-id"))

def api(method: str, payload: dict, timeout: int = 35) -> dict:
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json",
                                           "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": e.read().decode("utf-8", "replace")[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

def send(text: str, parse_mode: str = "Markdown") -> dict:
    text = text[:4000] + ("\n…truncated" if len(text) > 4000 else "")
    return api("sendMessage", {"chat_id": CHAT_ID, "text": text,
                               "parse_mode": parse_mode,
                               "disable_web_page_preview": True})

def log_cmd(chat_id: int, text: str, response: str):
    CMD_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(CMD_LOG, "a") as f:
        f.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "chat_id": chat_id, "command": text[:500],
            "response_preview": response[:300]
        }) + "\n")

# ========== Command handlers ==========

def cmd_help(*_) -> str:
    return ("*Available commands:*\n"
            "`/status` — overall status\n"
            "`/running` — list active scanner processes\n"
            "`/findings [N]` — show top N recent findings\n"
            "`/f500` — F500 orchestrator progress\n"
            "`/scan <type> <target>` — launch scan (types: sourcemap, takeover, cicd, terraform, cors)\n"
            "`/kill <pid>` — kill a scan process\n"
            "`/tail <log>` — tail last 20 lines of a log\n"
            "`/ledgers` — list ledgers + finding counts\n"
            "`/companies-with-findings` — F500 winners\n"
            "`/help` — this list")

def cmd_status(*_) -> str:
    try:
        r = subprocess.run(["/bin/ps", "aux"], capture_output=True, text=True, timeout=5)
        lines = [l for l in r.stdout.split("\n") if any(k in l for k in
                  ("patrol-", "verify-", "orchestrate-", "chaos", "dnsx", "nuclei"))
                 and "grep" not in l]
        proc_count = len(lines)
    except Exception:
        proc_count = "?"
    # Recent findings count
    try:
        ledger_count = sum(1 for f in LEDGER_DIR.glob("*.jsonl") if f.stat().st_size > 0)
    except Exception:
        ledger_count = "?"
    # F500 progress
    f500_done = 0
    try:
        state = json.loads((F500_DIR / "_orchestrator-state.json").read_text())
        f500_done = len(state.get("completed", []))
    except Exception: pass
    return (f"*Lictor status:*\n"
            f"Active scanners: `{proc_count}`\n"
            f"Ledgers with data: `{ledger_count}`\n"
            f"F500 progress: `{f500_done}/577`\n"
            f"Uptime: `{int(time.time() - START_TIME)}s`")

def cmd_running(*_) -> str:
    try:
        r = subprocess.run(["/bin/ps", "aux"], capture_output=True, text=True, timeout=5)
        lines = []
        for l in r.stdout.split("\n"):
            if any(k in l for k in ("patrol-", "verify-", "orchestrate-")) and "grep" not in l:
                parts = l.split()
                if len(parts) >= 11:
                    pid = parts[1]; elapsed = parts[9]
                    cmd = " ".join(parts[10:])[:80]
                    lines.append(f"`{pid}` ({elapsed}) {cmd}")
        if not lines: return "_no active scanners_"
        return "*Running:*\n" + "\n".join(lines[:15])
    except Exception as e:
        return f"err: {e}"

def cmd_findings(args) -> str:
    n = int(args[0]) if args and args[0].isdigit() else 10
    # Aggregate recent findings across F500 ledgers
    findings = []
    for ledger in F500_DIR.glob("*/[!_]*.jsonl"):
        try:
            company = ledger.parent.name
            scanner = ledger.stem
            for line in ledger.read_text().splitlines()[-5:]:
                try:
                    d = json.loads(line)
                    sev = d.get('severity', '?')
                    host = d.get('host') or d.get('source') or d.get('url', '?')
                    findings.append((ledger.stat().st_mtime, company, scanner, sev,
                                    str(host)[:50]))
                except: pass
        except: continue
    findings.sort(reverse=True)
    findings = findings[:n]
    if not findings: return "_no findings yet_"
    out = "*Recent findings:*\n"
    for _, company, scanner, sev, host in findings:
        out += f"`{sev}` {company}/{scanner}: {host}\n"
    return out

def cmd_f500(*_) -> str:
    try:
        state = json.loads((F500_DIR / "_orchestrator-state.json").read_text())
        completed = state.get("completed", [])
        failed = state.get("failed", [])
        # Count companies with findings
        winners = 0
        for comp_dir in F500_DIR.glob("*/"):
            if comp_dir.name.startswith("_"): continue
            try:
                summary = json.loads((comp_dir / "summary.json").read_text())
                if summary.get("total_findings", 0) > 0:
                    winners += 1
            except: pass
        return (f"*F500 sweep:*\n"
                f"Completed: `{len(completed)}/577`\n"
                f"Failed: `{len(failed)}`\n"
                f"Companies with findings: `{winners}`")
    except Exception as e:
        return f"f500 state read err: {e}"

def cmd_kill(args) -> str:
    if not args or not args[0].isdigit():
        return "usage: `/kill <pid>`"
    pid = int(args[0])
    # Safety: only allow killing Python/patrol/verify/orchestrate processes
    try:
        r = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "command="],
                          capture_output=True, text=True, timeout=3)
        cmd = r.stdout.strip()
        if not cmd:
            return f"PID {pid} not found"
        if not any(k in cmd for k in ("patrol-", "verify-", "orchestrate-", "python")):
            return f"refusing to kill non-scanner: {cmd[:80]}"
        os.kill(pid, signal.SIGTERM)
        return f"sent SIGTERM to {pid}"
    except ProcessLookupError:
        return f"PID {pid} not found"
    except Exception as e:
        return f"err: {e}"

def cmd_tail(args) -> str:
    if not args: return "usage: `/tail <log-name>`"
    log_name = args[0]
    # Search in v3/ledgers/ for matching log
    candidates = list(LEDGER_DIR.glob(f"*{log_name}*.log")) + list(F500_DIR.glob(f"*{log_name}*"))
    if not candidates: return f"no log matching `{log_name}`"
    log = candidates[0]
    try:
        lines = log.read_text().splitlines()[-20:]
        return f"*{log.name} (last 20):*\n```\n" + "\n".join(lines) + "\n```"
    except Exception as e:
        return f"err: {e}"

def cmd_ledgers(*_) -> str:
    out = []
    for f in sorted(LEDGER_DIR.glob("*.jsonl"), key=lambda p: -p.stat().st_size):
        size = f.stat().st_size
        if size == 0: continue
        try: count = sum(1 for _ in open(f))
        except: count = "?"
        out.append(f"`{count}` {f.name}")
    return "*Ledgers:*\n" + "\n".join(out[:20])

def cmd_companies_with_findings(*_) -> str:
    winners = []
    for comp_dir in F500_DIR.glob("*/"):
        if comp_dir.name.startswith("_"): continue
        try:
            summary = json.loads((comp_dir / "summary.json").read_text())
            total = summary.get("total_findings", 0)
            if total > 0:
                winners.append((total, comp_dir.name))
        except: pass
    winners.sort(reverse=True)
    if not winners: return "_no F500 companies with findings yet_"
    out = "*F500 winners:*\n"
    for total, name in winners[:20]:
        out += f"`{total}` {name}\n"
    return out

def cmd_scan(args) -> str:
    if len(args) < 2:
        return "usage: `/scan <type> <target>` — types: sourcemap|takeover|cicd|terraform|cors"
    scan_type = args[0].lower()
    target = args[1]
    # Write target to temp hosts file
    hosts_file = f"/tmp/lictor-tg-scan-{scan_type}-{int(time.time())}.txt"
    Path(hosts_file).write_text(target + "\n")
    cmd_map = {
        "sourcemap": ["scripts/patrol-sourcemap-leak.py", "--corpus", hosts_file, "--max-domains", "1", "--workers", "2"],
        "takeover": ["scripts/patrol-subdomain-takeover.py", "--corpus", hosts_file, "--max-domains", "1"],
        "cicd": ["scripts/patrol-cicd-admin-panels.py", "--hosts", hosts_file, "--max-hosts", "1", "--threads", "2"],
        "terraform": ["scripts/patrol-terraform-state-exposure.py", "--hosts", hosts_file, "--max-hosts", "1", "--threads", "2"],
        "cors": ["scripts/patrol-cors-credentials-reflected.py", "--hosts", hosts_file, "--max-hosts", "1", "--threads", "2"],
    }
    if scan_type not in cmd_map:
        return f"unknown type. choices: {','.join(cmd_map.keys())}"
    cmd = ["/usr/bin/python3"] + cmd_map[scan_type]
    try:
        # Launch in background, capture pid
        p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
        return f"launched `{scan_type}` on `{target}` → PID `{p.pid}`"
    except Exception as e:
        return f"err: {e}"

def cmd_queue(args) -> str:
    """Show submission queue summary."""
    try:
        from collections import Counter
        qf = Path('/Users/raffa/Lictor/v3/ledgers/submission-queue.jsonl')
        if not qf.exists(): return "queue empty"
        items = [json.loads(l) for l in qf.read_text().splitlines() if l.strip()]
        by_status = Counter(i.get('status') for i in items)
        lines = [f"*Submission queue ({len(items)} total):*"]
        for s, n in by_status.most_common():
            lines.append(f"  {n:3d}  {s}")
        # Show top 5 VERIFIED_REAL if any
        real = [i for i in items if i.get('status') == 'VERIFIED_REAL']
        if real:
            lines.append("\n*VERIFIED_REAL (submit-ready):*")
            for r in real[:5]:
                lines.append(f"  {r.get('severity','?')} {r.get('company','?')} {r.get('host','?')}")
        return "\n".join(lines)
    except Exception as e:
        return f"err: {e}"


def cmd_decisions(args) -> str:
    """Show pending decisions awaiting user input."""
    try:
        df = Path('/Users/raffa/Lictor/v3/ledgers/pending-decisions.jsonl')
        if not df.exists(): return "no pending decisions"
        items = [json.loads(l) for l in df.read_text().splitlines() if l.strip()]
        pending = [i for i in items if i.get('status') == 'pending']
        if not pending: return "no pending decisions"
        lines = [f"*Pending decisions ({len(pending)}):*"]
        for d in pending[:10]:
            lines.append(f"\n[{d.get('id','?')}] {d.get('context','?')[:200]}")
            for i, opt in enumerate(d.get('options', []), 1):
                lines.append(f"  {i}. {opt}")
        return "\n".join(lines)
    except Exception as e:
        return f"err: {e}"


def cmd_digest(args) -> str:
    """One-shot full digest of all relevant state."""
    parts = []
    parts.append(cmd_status())
    parts.append("")
    parts.append(cmd_queue([]))
    parts.append("")
    parts.append(cmd_decisions([]))
    return "\n".join(parts)


COMMANDS = {
    "/help": cmd_help, "/status": cmd_status, "/running": cmd_running,
    "/findings": cmd_findings, "/f500": cmd_f500, "/kill": cmd_kill,
    "/tail": cmd_tail, "/ledgers": cmd_ledgers,
    "/companies-with-findings": cmd_companies_with_findings,
    "/scan": cmd_scan,
    "/queue": cmd_queue, "/decisions": cmd_decisions, "/digest": cmd_digest,
}

def handle_message(msg: dict):
    chat_id = msg.get("chat", {}).get("id")
    if chat_id != CHAT_ID:
        return  # ignore non-authorized chats
    text = (msg.get("text") or "").strip()
    if not text: return
    # Parse command + args
    parts = text.split()
    cmd = parts[0].lower()
    args = parts[1:]
    handler = COMMANDS.get(cmd)
    if not handler:
        response = f"unknown command. use `/help`. got: `{cmd}`"
    else:
        try:
            response = handler(args)
        except Exception as e:
            response = f"command error: {e}"
    send(response)
    log_cmd(chat_id, text, response)

def get_updates(offset: int) -> list:
    """Long-polling for updates."""
    r = api("getUpdates", {"offset": offset, "timeout": 25}, timeout=35)
    if not r.get("ok"): return []
    return r.get("result", [])

def load_offset() -> int:
    try: return int(OFFSET_FILE.read_text().strip())
    except: return 0

def save_offset(offset: int):
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    OFFSET_FILE.write_text(str(offset))

START_TIME = time.time()

def main():
    print(f"[+] Telegram listener starting — chat_id={CHAT_ID}")
    send("🤖 *Lictor Telegram listener ONLINE*\n\nSend `/help` for available commands.")
    offset = load_offset()
    print(f"[+] starting offset: {offset}")
    while True:
        try:
            updates = get_updates(offset)
            for u in updates:
                offset = u["update_id"] + 1
                save_offset(offset)
                if "message" in u:
                    handle_message(u["message"])
        except Exception as e:
            print(f"[!] poll error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
