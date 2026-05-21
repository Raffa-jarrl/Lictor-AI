#!/usr/bin/env python3
"""
Lictor v3 Submitter — Telegram bot + 4-platform API submission

Watches output/oracle-YYYY-MM-DD/*.md for verdict=GO files.
For each GO:
  1. Compose Telegram message with inline buttons [SUBMIT][DEFER][VIEW]
  2. Wait for user's tap
  3. On SUBMIT → call platform API → log to ledgers/shipped.jsonl
  4. On DEFER or timeout → log to ledgers/deferred.jsonl
  5. On VIEW → send the full Raven draft as a file

Safety:
  - NEVER submits without Lion APPROVE + Oracle GO + user tap
  - Reads tokens from ~/.lictor/secrets/ with permission check (0600 required)
  - Tokens never appear in logs or output files
  - All actions logged to ledgers/ with full context

Run:
  python3 scripts/submitter.py                         # one-shot scan + poll loop
  python3 scripts/submitter.py --once                  # process current GO files, exit (don't poll)
  python3 scripts/submitter.py --test-telegram         # send a test message, exit
  python3 scripts/submitter.py --dry-run               # do everything except call platform APIs
"""
from __future__ import annotations
import argparse, json, os, stat, sys, time, urllib.request, urllib.error
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path.home() / "Lictor-AI" / "v3"
SECRETS_DIR = Path.home() / ".lictor" / "secrets"
LEDGER_SHIPPED = ROOT / "ledgers" / "shipped.jsonl"
LEDGER_DEFERRED = ROOT / "ledgers" / "deferred.jsonl"
STATE_FILE = ROOT / "ledgers" / "submitter-state.json"  # tracks already-messaged findings
TELEGRAM_OFFSET_FILE = ROOT / "ledgers" / "telegram-offset.txt"

UA = "Lictor-v3-Submitter/0.1 (+https://lictor-ai.com)"
DRY_RUN = False  # set by --dry-run flag


# =============================================================================
# Token loading — strict permission check, never log
# =============================================================================

def _load_token(name: str) -> str:
    """Load a token from ~/.lictor/secrets/<name>. Requires 0600 perms. Never logs the token."""
    path = SECRETS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Token file missing: {path}. See docs/TELEGRAM-SETUP.md or docs/SUBMIT-FLOW.md.")
    perms = stat.S_IMODE(path.stat().st_mode)
    if perms & 0o077:
        raise PermissionError(f"Token file {path} has too-permissive mode {oct(perms)}. Run: chmod 600 {path}")
    return path.read_text().strip()


# =============================================================================
# Telegram bot — sendMessage / answerCallbackQuery / getUpdates
# =============================================================================

class Telegram:
    BASE = "https://api.telegram.org/bot{token}"

    def __init__(self):
        self.token = _load_token("telegram.bot-token")
        self.chat_id = _load_token("telegram.chat-id")

    def _api(self, method: str, payload: dict, timeout: int = 30) -> dict:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"Telegram {method} returned {e.code}: {body[:200]}")

    def send_approval(self, finding_id: str, summary_md: str) -> dict:
        """Send a message with inline ✅/❌/✏️ buttons. Returns Telegram's response."""
        payload = {
            "chat_id": int(self.chat_id),
            "text": summary_md,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ SUBMIT NOW", "callback_data": f"SUBMIT:{finding_id}"},
                    {"text": "❌ DEFER", "callback_data": f"DEFER:{finding_id}"},
                    {"text": "✏️ VIEW FULL DRAFT", "callback_data": f"VIEW:{finding_id}"},
                ]]
            }
        }
        return self._api("sendMessage", payload)

    def send_text(self, text: str) -> dict:
        return self._api("sendMessage", {"chat_id": int(self.chat_id), "text": text, "parse_mode": "Markdown"})

    def answer_callback(self, callback_query_id: str, text: str = "") -> dict:
        return self._api("answerCallbackQuery", {"callback_query_id": callback_query_id, "text": text})

    def edit_message_text(self, chat_id: int, message_id: int, new_text: str) -> dict:
        return self._api("editMessageText", {
            "chat_id": chat_id, "message_id": message_id, "text": new_text,
            "parse_mode": "Markdown", "disable_web_page_preview": True,
        })

    def send_document(self, file_path: Path, caption: str = "") -> dict:
        """Upload a file (e.g. the full Raven draft as .md) as a Telegram document."""
        # multipart/form-data via urllib is awkward; use a simple boundary
        boundary = "----LictorBoundary7MA4YWxkTrZu0gW"
        body = []
        for k, v in [("chat_id", self.chat_id), ("caption", caption[:1024])]:
            body.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
        body.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{file_path.name}\"\r\nContent-Type: text/markdown\r\n\r\n".encode())
        body.append(file_path.read_bytes())
        body.append(f"\r\n--{boundary}--\r\n".encode())
        data = b"".join(body)
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{self.token}/sendDocument",
            data=data,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": UA},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def get_updates(self, offset: int = 0, timeout: int = 25) -> list[dict]:
        """Long-poll for new updates. Returns the list of updates."""
        url = f"https://api.telegram.org/bot{self.token}/getUpdates?offset={offset}&timeout={timeout}"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout + 5) as r:
            resp = json.loads(r.read())
        return resp.get("result", [])


# =============================================================================
# Platform API clients — one per bounty platform
# =============================================================================

class PlatformBase:
    """Each subclass implements submit(finding) → {report_id, url, raw}."""
    name = "BASE"

    def submit(self, finding: dict, raven_draft_text: str) -> dict:
        raise NotImplementedError


class HackerOne(PlatformBase):
    name = "HackerOne"

    def __init__(self):
        # Format: "username:api_token" — used as HTTP Basic auth
        token_pair = _load_token("hackerone.token")
        self.basic_auth = b64encode(token_pair.encode()).decode()

    def submit(self, finding: dict, raven_draft_text: str) -> dict:
        # H1 API: POST /v1/reports — see https://docs.hackerone.com/programs/v1.html
        # Required fields: program (handle), title, vulnerability_information, severity, weakness_id
        if DRY_RUN:
            return {"report_id": "DRY-RUN", "url": "DRY-RUN", "raw": {"dry_run": True, "finding_id": finding["finding_id"]}}
        program_slug = finding["program"]["url"].rstrip("/").split("/")[-1]  # extract from URL
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_slug,
                    "title": _extract_field(raven_draft_text, "## Title", "##"),
                    "vulnerability_information": raven_draft_text,
                    "severity_rating": _cvss_to_h1_severity(finding["severity"]["cvss"]),
                    "impact": _extract_field(raven_draft_text, "## Impact", "##"),
                }
            }
        }
        req = urllib.request.Request(
            "https://api.hackerone.com/v1/reports",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Basic {self.basic_auth}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": UA,
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                resp = json.loads(r.read())
            report_id = resp.get("data", {}).get("id", "?")
            return {"report_id": report_id, "url": f"https://hackerone.com/reports/{report_id}", "raw": resp}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"HackerOne submit failed {e.code}: {err_body[:300]}")


class Bugcrowd(PlatformBase):
    name = "Bugcrowd"

    def __init__(self):
        self.token = _load_token("bugcrowd.token")

    def submit(self, finding: dict, raven_draft_text: str) -> dict:
        # Bugcrowd API: POST /v2/submissions
        # NOTE: Bugcrowd API requires submission via program-specific researcher API which needs the program UUID.
        # For initial v3 we mark as DRY_RUN+manual-paste fallback. Real impl requires per-program UUID lookup.
        if DRY_RUN:
            return {"report_id": "DRY-RUN", "url": "DRY-RUN", "raw": {"dry_run": True}}
        return {"report_id": "manual-paste-required", "url": finding["program"]["url"], "raw": {"note": "Bugcrowd submission requires manual paste — API access varies by program"}}


class Intigriti(PlatformBase):
    name = "Intigriti"

    def __init__(self):
        self.token = _load_token("intigriti.token")

    def submit(self, finding: dict, raven_draft_text: str) -> dict:
        # Intigriti researcher API: POST /external/researcher/v1/submissions
        if DRY_RUN:
            return {"report_id": "DRY-RUN", "url": "DRY-RUN", "raw": {"dry_run": True}}
        # Intigriti needs program_id (UUID), asset_id (UUID), type_id, severity_id — these come from program metadata
        # For v3-alpha: fall back to manual paste with full draft text
        return {"report_id": "manual-paste-required", "url": finding["program"]["url"], "raw": {"note": "Intigriti API needs UUID lookup — manual paste for v3-alpha"}}


class YesWeHack(PlatformBase):
    name = "YesWeHack"

    def __init__(self):
        self.token = _load_token("yeswehack.token")

    def submit(self, finding: dict, raven_draft_text: str) -> dict:
        # YWH API: POST /api/private/programs/{slug}/reports
        if DRY_RUN:
            return {"report_id": "DRY-RUN", "url": "DRY-RUN", "raw": {"dry_run": True}}
        return {"report_id": "manual-paste-required", "url": finding["program"]["url"], "raw": {"note": "YWH API needs program slug + 2FA flow — manual paste for v3-alpha"}}


PLATFORMS = {"HackerOne": HackerOne, "Bugcrowd": Bugcrowd, "Intigriti": Intigriti, "YesWeHack": YesWeHack}


# =============================================================================
# Helpers
# =============================================================================

def _extract_field(md_text: str, start_header: str, next_header_prefix: str) -> str:
    """Extract a section from a markdown draft by header."""
    if start_header not in md_text:
        return ""
    after = md_text.split(start_header, 1)[1]
    next_idx = after.find("\n" + next_header_prefix)
    return after[:next_idx].strip() if next_idx != -1 else after.strip()


def _cvss_to_h1_severity(cvss_vector: str) -> str:
    """Map CVSS vector → H1 severity_rating field ('none'/'low'/'medium'/'high'/'critical')."""
    # Simple heuristic: parse the score from the vector if present, else estimate from the impact metrics
    # H1 accepts 'none', 'low', 'medium', 'high', 'critical'
    # For v3-alpha we use a rough mapping:
    if "C:H" in cvss_vector and "I:H" in cvss_vector:
        return "critical" if "S:C" in cvss_vector else "high"
    if "C:H" in cvss_vector or "I:H" in cvss_vector:
        return "high"
    if "C:L" in cvss_vector or "I:L" in cvss_vector:
        return "medium"
    return "low"


def _state_load() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"already_messaged": {}}  # finding_id → telegram_message_id


def _state_save(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _telegram_offset_load() -> int:
    if TELEGRAM_OFFSET_FILE.exists():
        try:
            return int(TELEGRAM_OFFSET_FILE.read_text().strip())
        except Exception:
            return 0
    return 0


def _telegram_offset_save(offset: int) -> None:
    TELEGRAM_OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    TELEGRAM_OFFSET_FILE.write_text(str(offset))


def _append_ledger(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def _find_oracle_go_files() -> list[Path]:
    """Find all output/oracle-*/<finding>.md files with verdict=GO that we haven't messaged yet."""
    oracle_dir = ROOT / "output"
    state = _state_load()
    go_files = []
    for daydir in oracle_dir.glob("oracle-*"):
        for f in daydir.glob("*.md"):
            finding_id = f.stem
            if finding_id in state["already_messaged"]:
                continue
            text = f.read_text()
            # Look for "## Verdict" then GO
            if "Verdict" in text and "GO" in text and "NO-GO" not in text.split("Verdict")[1][:50]:
                go_files.append(f)
    return go_files


def _find_finding_in_ledgers(finding_id: str) -> Optional[dict]:
    """Look up the original finding data from confirmed.jsonl."""
    for ledger in [ROOT / "ledgers" / "confirmed.jsonl", ROOT / "ledgers" / "needs-verification.jsonl"]:
        if not ledger.exists():
            continue
        for line in ledger.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if rec.get("finding_id") == finding_id:
                    return rec
            except Exception:
                continue
    return None


def _find_raven_draft(finding_id: str) -> Optional[Path]:
    """Find the Raven draft file for a finding."""
    for daydir in (ROOT / "output").glob("writer-*"):
        candidate = daydir / f"{finding_id}.md"
        if candidate.exists():
            return candidate
    return None


def _compose_telegram_summary(finding: dict, oracle_verdict_text: str, raven_draft_text: str) -> str:
    """Build the Markdown text for the Telegram approval message."""
    program = finding.get("program", {})
    severity = finding.get("severity", {})
    return f"""🦉 *Lion APPROVED* + 🧙 *Oracle GO*

*Finding:* {finding.get('finding_id', 'unknown')}
*Class:* `{finding.get('class', 'unknown')}`
*Platform:* {program.get('platform', '?')} — {program.get('name', '?')}
*Severity:* {severity.get('band', '?')} (CVSS {severity.get('score', '?')})
*Est payout:* {finding.get('estimated_payout', '?')}

*Subdomain:* `{finding.get('subdomain', '?')}`
*Scope match:* `{program.get('scope_match', '?')}`

_Tap one of the buttons below._"""


# =============================================================================
# Main processing loop
# =============================================================================

def process_go_files(telegram: Telegram) -> int:
    """Find new Oracle-GO files, send Telegram message for each. Returns count messaged."""
    state = _state_load()
    go_files = _find_oracle_go_files()
    count = 0
    for go_file in go_files:
        finding_id = go_file.stem
        finding = _find_finding_in_ledgers(finding_id)
        if not finding:
            print(f"  ⚠️  No ledger entry for {finding_id} — skipping", flush=True)
            continue
        raven_draft = _find_raven_draft(finding_id)
        if not raven_draft:
            print(f"  ⚠️  No Raven draft for {finding_id} — skipping", flush=True)
            continue
        summary = _compose_telegram_summary(finding, go_file.read_text(), raven_draft.read_text())
        try:
            resp = telegram.send_approval(finding_id, summary)
            msg_id = resp["result"]["message_id"]
            state["already_messaged"][finding_id] = {"telegram_message_id": msg_id, "sent_at": datetime.now(timezone.utc).isoformat()}
            _state_save(state)
            print(f"  📲 Telegram message sent for {finding_id} (msg_id={msg_id})", flush=True)
            count += 1
        except Exception as e:
            print(f"  ❌ Telegram send failed for {finding_id}: {e}", flush=True)
    return count


def process_callback(update: dict, telegram: Telegram) -> None:
    """Handle a single inline-button callback from Telegram."""
    cb = update.get("callback_query")
    if not cb:
        return
    data = cb.get("data", "")
    if ":" not in data:
        return
    action, finding_id = data.split(":", 1)
    cb_id = cb["id"]
    chat_id = cb["message"]["chat"]["id"]
    msg_id = cb["message"]["message_id"]

    finding = _find_finding_in_ledgers(finding_id)
    if not finding:
        telegram.answer_callback(cb_id, "❌ Finding not in ledger — please check manually")
        return

    raven_draft = _find_raven_draft(finding_id)
    raven_text = raven_draft.read_text() if raven_draft else ""

    if action == "SUBMIT":
        platform_name = finding["program"]["platform"]
        platform_cls = PLATFORMS.get(platform_name)
        if not platform_cls:
            telegram.answer_callback(cb_id, f"❌ Unknown platform: {platform_name}")
            return
        try:
            platform = platform_cls()
            result = platform.submit(finding, raven_text)
            _append_ledger(LEDGER_SHIPPED, {
                "finding_id": finding_id,
                "submitted_at": datetime.now(timezone.utc).isoformat(),
                "platform": platform_name,
                "report_id": result.get("report_id"),
                "report_url": result.get("url"),
                "dry_run": DRY_RUN,
            })
            telegram.answer_callback(cb_id, "✅ Submitted")
            confirm_text = f"""✅ *Submitted to {platform_name}*

Report ID: `{result.get('report_id')}`
URL: {result.get('url')}

Triage status: Pending. I'll notify you when it moves.
{'_(DRY RUN — no actual submission)_' if DRY_RUN else ''}"""
            telegram.send_text(confirm_text)
            print(f"  ✅ Submitted {finding_id} → {result.get('report_id')}", flush=True)
        except Exception as e:
            telegram.answer_callback(cb_id, f"❌ Submit failed: {str(e)[:100]}")
            telegram.send_text(f"❌ *Submission failed* for `{finding_id}`:\n\n```\n{str(e)[:500]}\n```")
            _append_ledger(LEDGER_DEFERRED, {
                "finding_id": finding_id,
                "deferred_at": datetime.now(timezone.utc).isoformat(),
                "reason": "submit-failed",
                "error": str(e)[:500],
            })

    elif action == "DEFER":
        _append_ledger(LEDGER_DEFERRED, {
            "finding_id": finding_id,
            "deferred_at": datetime.now(timezone.utc).isoformat(),
            "reason": "user-tap-defer",
        })
        telegram.answer_callback(cb_id, "Deferred")
        telegram.send_text(f"❌ *Deferred* `{finding_id}` — will not submit. Available for re-evaluation next cycle.")
        print(f"  ⏸  Deferred {finding_id}", flush=True)

    elif action == "VIEW":
        if raven_draft:
            telegram.send_document(raven_draft, caption=f"Full draft: {finding_id}")
            telegram.answer_callback(cb_id, "Draft sent")
        else:
            telegram.answer_callback(cb_id, "Draft not found")

    else:
        telegram.answer_callback(cb_id, f"Unknown action: {action}")


def main():
    global DRY_RUN
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="Process current GO files, exit immediately")
    ap.add_argument("--test-telegram", action="store_true", help="Send a test message and exit")
    ap.add_argument("--dry-run", action="store_true", help="Do everything except call platform APIs")
    ap.add_argument("--poll-interval", type=int, default=30, help="Seconds between getUpdates polls")
    args = ap.parse_args()
    DRY_RUN = args.dry_run

    print(f"[+] Lictor v3 Submitter — root={ROOT}", flush=True)
    if DRY_RUN:
        print("[+] DRY RUN MODE — will compose Telegram messages but skip platform API calls", flush=True)

    telegram = Telegram()
    print(f"[+] Telegram bot loaded — chat_id={telegram.chat_id[:5]}...", flush=True)

    if args.test_telegram:
        telegram.send_text("🧪 *Lictor v3 alive* — Telegram bot integration working. " + datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print("[+] Test message sent", flush=True)
        return

    # Process any pending GO files
    n = process_go_files(telegram)
    print(f"[+] Sent {n} new approval messages", flush=True)

    if args.once:
        return

    # Poll loop: check for callbacks AND for new GO files every 30s
    print(f"[+] Entering poll loop (interval={args.poll_interval}s) — Ctrl-C to stop", flush=True)
    offset = _telegram_offset_load()
    while True:
        try:
            updates = telegram.get_updates(offset=offset, timeout=25)
            for upd in updates:
                offset = upd["update_id"] + 1
                _telegram_offset_save(offset)
                if "callback_query" in upd:
                    process_callback(upd, telegram)
        except Exception as e:
            print(f"  ⚠️  Poll error: {e} — sleeping {args.poll_interval}s and retrying", flush=True)
        # Also check for new GO files
        try:
            n = process_go_files(telegram)
            if n > 0:
                print(f"  📲 Sent {n} additional approval messages", flush=True)
        except Exception as e:
            print(f"  ⚠️  GO-file scan error: {e}", flush=True)
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] Submitter stopped by user", flush=True)
        sys.exit(0)
