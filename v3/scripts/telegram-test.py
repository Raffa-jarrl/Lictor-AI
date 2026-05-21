#!/usr/bin/env python3
"""
Telegram bot connectivity test.

Reads ~/.lictor/secrets/telegram.bot-token + telegram.chat-id,
sends a test message. Confirms the setup works before deploying the Submitter.

Usage:
  python3 scripts/telegram-test.py
"""
from __future__ import annotations
import json, os, stat, sys, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

SECRETS_DIR = Path.home() / ".lictor" / "secrets"


def _load(name: str) -> str:
    path = SECRETS_DIR / name
    if not path.exists():
        sys.exit(f"❌ Token file missing: {path}\n   See ~/Lictor/v3/docs/TELEGRAM-SETUP.md for setup instructions.")
    perms = stat.S_IMODE(path.stat().st_mode)
    if perms & 0o077:
        sys.exit(f"❌ Token file {path} has too-permissive mode {oct(perms)}.\n   Run: chmod 600 {path}")
    return path.read_text().strip()


def main():
    print("[+] Loading Telegram credentials from ~/.lictor/secrets/...")
    try:
        token = _load("telegram.bot-token")
        chat_id = _load("telegram.chat-id")
    except SystemExit:
        raise
    except Exception as e:
        sys.exit(f"❌ Failed to load credentials: {e}")

    print(f"[+] Bot token loaded (length={len(token)})")
    print(f"[+] Chat ID loaded: {chat_id}")

    text = f"""🧪 *Lictor v3 Telegram test*

Time: `{datetime.now(timezone.utc).isoformat(timespec="seconds")}`
Setup: ✅ Working

If you see this message, the Submitter daemon will be able to send approval requests here.

Next step: deploy the Submitter as a launchd service. See `~/Lictor/v3/docs/SUBMIT-FLOW.md`."""

    payload = {
        "chat_id": int(chat_id),
        "text": text,
        "parse_mode": "Markdown",
    }
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Lictor-v3-telegram-test/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read())
        if resp.get("ok"):
            print("[+] ✅ Test message sent successfully!")
            print(f"    Message ID: {resp['result']['message_id']}")
            print(f"    Check your Telegram chat with the bot now.")
        else:
            sys.exit(f"❌ Telegram API returned: {resp}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        sys.exit(f"❌ Telegram API HTTP {e.code}: {body[:300]}")
    except Exception as e:
        sys.exit(f"❌ Request failed: {e}")


if __name__ == "__main__":
    main()
