#!/usr/bin/env python3
"""Unify every Lictor surface onto the canonical AMBER accent (#E8A33D).

One-shot, idempotent migration of the standalone surfaces that carry their own
color literals (the CSS-linked pages already inherit static/tokens.css). Swaps
the legacy copper / gold / orange palette → amber, and cools the warning color
to gold so it never collides with the amber brand accent.

  python3 scripts/migrate-accent-to-amber.py            # dry-run (no writes)
  python3 scripts/migrate-accent-to-amber.py --apply     # write changes

NOTE: landing/style.css + landing/static/tokens.css and landing/business.html
are handled separately (structural changes), so they are NOT in this list.
"""
from __future__ import annotations
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FILES = [
    "landing/static/a11y.css",
    "landing/static/fx.css",
    "landing/static/shell.css",
    "landing/static/waitlist.js",
    "landing/static/fx.js",
    "landing/donate/donate.css",
    "landing/compliance/compliance.css",
    "landing/waitlist/waitlist.css",
    "landing/waitlist/index.html",
    "landing/scan-policy.html",
    "landing/scan/index.html",
    "landing/patterns/index.html",
    "landing/mission-control/index.html",
    "landing/isolation-os/index.html",
    "landing/index.html",
    "isolation/usb-os/includes/launcher.html",
    "shield/src/popup/popup.css",
    "scripts/internal-check.py",
]

# Hex literals (case-insensitive in, canonical uppercase out). \b guards against
# partial matches inside 8-digit hex.
HEX = {
    "#c4885a": "#E8A33D",  # copper accent      -> amber accent
    "#d89b6c": "#F2B85C",  # copper hover       -> amber hover
    "#b88f2e": "#F2B85C",  # gold-leftover hover-> amber hover
    "#7a4e2e": "#B97A28",  # bronze primary     -> deep amber
    "#9a6a40": "#C98A38",  # bronze primary-2   -> deep amber
    "#c9a23b": "#E8A33D",  # gold leaf          -> amber
    "#d68910": "#B8860B",  # warning orange     -> cooled gold
    "#ffb066": "#E8A33D",  # a11y/fx orange     -> amber
    "#ffc488": "#F2B85C",  # a11y/fx orange-hi  -> amber hover
}

# rgb()/rgba() copper(196,136,90) and gold(201,162,59) -> amber(232,163,61),
# tolerant of whitespace, preserving any alpha channel.
RGB_PAIRS = [(196, 136, 90), (201, 162, 59)]


def _rgb_sub(text: str) -> tuple[str, int]:
    n = 0
    for r, g, b in RGB_PAIRS:
        pat = re.compile(
            rf"rgba?\(\s*{r}\s*,\s*{g}\s*,\s*{b}\s*(,\s*[0-9.]+\s*)?\)", re.I
        )

        def repl(m):
            nonlocal n
            n += 1
            alpha = m.group(1)
            return f"rgba(232, 163, 61,{alpha.lstrip(',')})" if alpha else "rgb(232, 163, 61)"

        text = pat.sub(repl, text)
    return text, n


def migrate(text: str) -> tuple[str, int]:
    total = 0
    for old, new in HEX.items():
        pat = re.compile(re.escape(old) + r"\b", re.I)
        text, k = pat.subn(new, text)
        total += k
    text, k = _rgb_sub(text)
    total += k
    return text, total


def main() -> int:
    apply = "--apply" in sys.argv
    grand = 0
    print(f"=== migrate-accent-to-amber  [{'APPLY' if apply else 'DRY-RUN'}] ===")
    for rel in FILES:
        p = ROOT / rel
        if not p.exists():
            print(f"  !! MISSING  {rel}")
            continue
        src = p.read_text(encoding="utf-8")
        out, n = migrate(src)
        grand += n
        if n:
            print(f"  {'wrote' if apply else 'would change':>13}  {rel:<48} {n:>3} swap(s)")
            if apply:
                p.write_text(out, encoding="utf-8")
        else:
            print(f"  {'clean':>13}  {rel}")
    print(f"--- {grand} total replacement(s) across {len(FILES)} files ---")
    if not apply:
        print("    (dry-run — re-run with --apply to write)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
