#!/usr/bin/env python3
"""
notify-telegram.py — minimal Telegram notify helper.

Usage:
  Importable:
    from notify_telegram import notify
    notify("🔴 Critical finding on X.com")

  CLI:
    python3 notify-telegram.py "🔴 Critical finding on X.com"
    python3 notify-telegram.py --from-stdin

Reads creds from ~/.lictor/secrets/telegram.{bot-token,chat-id}.
Silent on success. Returns non-zero on failure but does not raise.
"""
from __future__ import annotations
import json, os, stat, sys, urllib.request, urllib.error
from pathlib import Path

SECRETS_DIR = Path.home() / ".lictor" / "secrets"

def _load(name: str) -> str | None:
    path = SECRETS_DIR / name
    if not path.exists(): return None
    try:
        perms = stat.S_IMODE(path.stat().st_mode)
        if perms & 0o077: return None
        return path.read_text().strip()
    except Exception:
        return None

def notify(text: str, parse_mode: str = "Markdown", silent: bool = False) -> bool:
    """Send a Telegram message. Returns True on success, False on failure.
    Never raises — callers can fire-and-forget."""
    token = _load("telegram.bot-token")
    chat_id = _load("telegram.chat-id")
    if not token or not chat_id:
        if not silent: print("[notify] missing creds", file=sys.stderr)
        return False
    # Telegram message limit: 4096 chars
    text = text[:4000] + ("\n…(truncated)" if len(text) > 4000 else "")
    payload = {"chat_id": int(chat_id), "text": text, "parse_mode": parse_mode,
               "disable_web_page_preview": True}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json",
                                           "User-Agent": "Lictor-Notify/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
        return resp.get("ok", False)
    except Exception as e:
        if not silent: print(f"[notify] error: {e}", file=sys.stderr)
        return False


def notify_decision(context: str, options: list[str], decision_id: str = "",
                    silent: bool = False) -> bool:
    """Send a structured decision request. ONLY use when user input is genuinely needed.
    Format:
      DECISION NEEDED [id]
      context
      ---
      1. option A
      2. option B
      3. option C
      4. Other (reply with details)
    User replies "1" / "2" / "3" / "4 <detail>" on Telegram.
    """
    if len(options) != 3:
        if not silent: print("[notify_decision] must provide exactly 3 options", file=sys.stderr)
        return False
    decision_header = f"DECISION NEEDED" + (f" [{decision_id}]" if decision_id else "")
    body = "\n".join([
        decision_header,
        "",
        context,
        "",
        "Reply with the number:",
        f"  1. {options[0]}",
        f"  2. {options[1]}",
        f"  3. {options[2]}",
        f"  4. Other (reply '4 <details>')",
    ])
    return notify(body, parse_mode="", silent=silent)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("message", nargs="?", default=None)
    ap.add_argument("--from-stdin", action="store_true")
    ap.add_argument("--no-markdown", action="store_true")
    args = ap.parse_args()
    if args.from_stdin:
        text = sys.stdin.read()
    elif args.message:
        text = args.message
    else:
        ap.error("provide message or --from-stdin")
    ok = notify(text, parse_mode="" if args.no_markdown else "Markdown")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
