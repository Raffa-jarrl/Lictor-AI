#!/usr/bin/env python3
"""
filter-optout — scrub a host list against the opt-out exclusion list.

Universal enforcement for scanners that don't import scan_ethics directly:
pipe any corpus through this first and it drops opted-out hosts.

    python3 scripts/filter-optout.py < hosts.txt > hosts.clean.txt
    python3 scripts/filter-optout.py hosts.txt        # in place-ish (stdout)
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_ethics import filter_hosts  # noqa: E402


def main() -> int:
    if len(sys.argv) > 1:
        src = Path(sys.argv[1]).read_text().splitlines()
    else:
        src = sys.stdin.read().splitlines()
    hosts = [h.strip() for h in src if h.strip() and not h.startswith("#")]
    for h in filter_hosts(hosts):
        print(h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
