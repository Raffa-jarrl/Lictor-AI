#!/usr/bin/env python3
"""
Beacon waitlist stats — daily Buttondown API pull.

Reads:
  BUTTONDOWN_API_KEY from ~/.lictor/secrets.env or env var

Writes:
  ~/Lictor/docs/business/diligence/waitlist-metrics/YYYY-MM-DD.json

Each snapshot has the shape Mission Control's /waitlist-metrics route expects:
  {
    captured_at: ISO timestamp,
    total_subscribers: int,
    confirmed_subscribers: int,
    unconfirmed_subscribers: int,
    by_platform: dict[str, int],
    by_source: dict[str, int],
    drip_email_stats: dict[str, float],
    net_new_today: int
  }

Designed to be idempotent — running twice in one day overwrites the same file.

Usage:
  python3 scripts/fetch-buttondown-stats.py              # today's snapshot
  python3 scripts/fetch-buttondown-stats.py --dry-run    # print, don't write
  python3 scripts/fetch-buttondown-stats.py --date 2026-06-15  # specific date

Set up cron (in genai.crontab, with Referer header):
  0 9 * * * /usr/bin/env python3 /Users/raffa/Lictor/scripts/fetch-buttondown-stats.py >> /tmp/buttondown-stats.log 2>&1
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOTS_DIR = REPO / "docs" / "business" / "diligence" / "waitlist-metrics"

# Buttondown API endpoints
BUTTONDOWN_BASE = "https://api.buttondown.com/v1"


def get_api_key() -> str | None:
    """Try env var first, then ~/.lictor/secrets.env."""
    key = os.environ.get("BUTTONDOWN_API_KEY", "")
    if key:
        return key
    secrets_file = pathlib.Path.home() / ".lictor" / "secrets.env"
    if secrets_file.exists():
        for line in secrets_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("export BUTTONDOWN_API_KEY=") or line.startswith(
                "BUTTONDOWN_API_KEY="
            ):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value:
                    return value
    return None


def fetch_paged(url: str, api_key: str) -> list[dict[str, Any]]:
    """Fetch a paginated Buttondown endpoint. Returns all items across all pages."""
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        req = urllib.request.Request(
            next_url,
            headers={
                "Authorization": f"Token {api_key}",
                "Accept": "application/json",
                "User-Agent": "Lictor-Beacon/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        items.extend(data.get("results", []))
        next_url = data.get("next")
    return items


def aggregate_subscribers(subs: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the summary metrics from a list of subscriber records."""
    by_platform: dict[str, int] = {}
    by_source: dict[str, int] = {}
    confirmed = 0
    unconfirmed = 0

    for s in subs:
        # Buttondown's status field: 'subscribed' (confirmed) vs 'unactivated' (pending)
        status = s.get("type", s.get("subscriber_type", ""))
        if status in ("regular", "subscribed", "premium"):
            confirmed += 1
        else:
            unconfirmed += 1

        # metadata fields (form fields with the `metadata__` prefix)
        meta = s.get("metadata", {}) or {}
        platform = (
            meta.get("platform")
            or meta.get("metadata__platform")
            or "unknown"
        )
        if platform:
            by_platform[platform] = by_platform.get(platform, 0) + 1

        # source — from UTM if present, else fallback to referrer
        source = meta.get("utm_source") or meta.get("source") or "direct"
        if source:
            by_source[source] = by_source.get(source, 0) + 1

    return {
        "confirmed_subscribers": confirmed,
        "unconfirmed_subscribers": unconfirmed,
        "total_subscribers": confirmed + unconfirmed,
        "by_platform": by_platform,
        "by_source": by_source,
    }


def compute_net_new(today_total: int, prev_snapshot: dict[str, Any] | None) -> int:
    if not prev_snapshot:
        return today_total
    prev_total = prev_snapshot.get("confirmed_subscribers", 0)
    return max(0, today_total - prev_total)


def load_previous_snapshot(target_date: dt.date) -> dict[str, Any] | None:
    if not SNAPSHOTS_DIR.exists():
        return None
    prev = None
    for f in sorted(SNAPSHOTS_DIR.glob("*.json")):
        try:
            file_date = dt.date.fromisoformat(f.stem)
        except ValueError:
            continue
        if file_date < target_date:
            try:
                prev = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
    return prev


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", help="YYYY-MM-DD (default: today)")
    parser.add_argument("--dry-run", action="store_true", help="print, don't write")
    args = parser.parse_args()

    api_key = get_api_key()
    if not api_key:
        print(
            "✗ BUTTONDOWN_API_KEY not set. Add it to ~/.lictor/secrets.env or "
            "export it. See docs/launch/beacon-campaign/dor-monday-morning-checklist.md "
            "Step 6 for setup."
        )
        sys.exit(1)

    target_date = (
        dt.date.fromisoformat(args.date) if args.date else dt.date.today()
    )

    print(f"Fetching Buttondown subscribers for {target_date.isoformat()}...")

    try:
        subs = fetch_paged(f"{BUTTONDOWN_BASE}/subscribers", api_key)
    except urllib.error.HTTPError as e:
        print(f"✗ Buttondown API error: {e.code} {e.reason}")
        if e.code == 401:
            print("  Token rejected. Check that BUTTONDOWN_API_KEY is current.")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"✗ Network error: {e.reason}")
        sys.exit(1)

    print(f"  fetched {len(subs)} subscribers")

    aggregated = aggregate_subscribers(subs)
    prev = load_previous_snapshot(target_date)
    net_new = compute_net_new(aggregated["confirmed_subscribers"], prev)

    snapshot = {
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "snapshot_date": target_date.isoformat(),
        **aggregated,
        "net_new_today": net_new,
        # drip_email_stats placeholder — Buttondown's email-stats API
        # surfaces per-email open/CTR; wire this in v0.2.
        "drip_email_stats": {},
    }

    if args.dry_run:
        print(json.dumps(snapshot, indent=2))
        return 0

    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SNAPSHOTS_DIR / f"{target_date.isoformat()}.json"
    out_path.write_text(json.dumps(snapshot, indent=2))
    print(f"✓ wrote {out_path}")
    print(
        f"  confirmed={aggregated['confirmed_subscribers']}  "
        f"unconfirmed={aggregated['unconfirmed_subscribers']}  "
        f"net_new={net_new}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
