#!/usr/bin/env python3
"""
update-submission-tracker — refresh /Users/raffa/Lictor/disclosures/SUBMISSION-TRACKER.md
with the current state of all email + platform disclosures.

Reads from local ledgers + outputs a refreshed MD with auto-generated sections.

Run daily via cron:
  30 7 * * *  /opt/homebrew/bin/python3 /Users/raffa/Lictor/scripts/update-submission-tracker.py

Future extension: integrate Gmail API for real-time inbox status; for now reads
the per-org disclosure MDs to enumerate the submission queue and overlays manual
status notes.
"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone

TRACKER = Path("/Users/raffa/Lictor/disclosures/SUBMISSION-TRACKER.md")
DISC_ROOT = Path("/Users/raffa/Lictor/disclosures")
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

AUTO_START = "<!-- AUTO-GENERATED START -->"
AUTO_END = "<!-- AUTO-GENERATED END -->"

def enumerate_disclosures():
    """Walk disclosure MD files + classify by date folder + finding-type."""
    out = []
    for d in sorted(DISC_ROOT.glob("2026-*/")):
        if not d.is_dir(): continue
        for f in sorted(d.glob("*.md")):
            if f.name.startswith("INDEX") or f.name.startswith("SUBMISSION-TRACKER"):
                continue
            out.append({
                "date": d.name.replace("2026-", "").replace("-submissions", ""),
                "category": d.name.split("-", 3)[-1] if "-" in d.name else "?",
                "file": f.name,
                "path": str(f),
                "size_kb": f.stat().st_size // 1024,
            })
    return out

def build_auto_section() -> str:
    discs = enumerate_disclosures()
    lines = [
        f"## 🤖 Auto-generated section",
        f"_Last updated: {NOW} — run via `update-submission-tracker.py`_\n",
        f"### Discovered disclosure MDs ({len(discs)} total)\n",
        "| Date | Category | File | Size |",
        "|------|----------|------|------|",
    ]
    for d in discs:
        lines.append(f"| {d['date']} | {d['category']} | `{d['file']}` | {d['size_kb']}KB |")
    return "\n".join(lines)

def main():
    if not TRACKER.exists():
        print(f"[!] Tracker not found: {TRACKER}")
        return
    text = TRACKER.read_text()
    auto = build_auto_section()

    if AUTO_START in text and AUTO_END in text:
        before = text.split(AUTO_START)[0]
        after = text.split(AUTO_END)[1]
        new_text = before + AUTO_START + "\n" + auto + "\n" + AUTO_END + after
    else:
        # First run — append auto section at the end
        new_text = text + "\n\n---\n\n" + AUTO_START + "\n" + auto + "\n" + AUTO_END + "\n"

    TRACKER.write_text(new_text)
    print(f"[+] Tracker updated: {TRACKER}")
    print(f"[+] Auto section: {len(auto)} chars")

if __name__ == "__main__":
    main()
