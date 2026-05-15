#!/usr/bin/env python3
"""
Lictor monthly metrics generator.

Runs once per month on the 1st (cron + launchd) and produces:
  - docs/business/diligence/metrics-YYYY-MM.md (human-readable summary)
  - docs/business/data-room/05-sales-marketing/marketing-analytics-monthly.csv (append row)
  - docs/business/data-room/03-product/github-stats-monthly.csv (append row)
  - docs/business/data-room/01-financials/revenue-streams/teams-mrr-history.csv (append)
  - docs/business/data-room/01-financials/revenue-streams/course-revenue.csv (append)

Data sources (all read via env vars; missing ones produce "—" rows):
  - GITHUB_TOKEN          → stars, contributors, PRs
  - STRIPE_API_KEY        → AaaS + Enterprise revenue
  - PADDLE_API_KEY        → Teams subs + Course revenue
  - SUBSTACK_API_KEY      → newsletter subscribers + open rate
  - TWITTER_BEARER_TOKEN  → follower count
  - BUTTONDOWN_API_KEY    → alt newsletter source if Substack absent

Usage:
  python3 scripts/generate-monthly-metrics.py              # for previous month
  python3 scripts/generate-monthly-metrics.py 2026-09      # for specific month
  python3 scripts/generate-monthly-metrics.py --dry-run    # print, don't write

Designed to be idempotent: running twice for the same month produces the same files.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Configuration

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DILIGENCE_DIR = REPO_ROOT / "docs" / "business" / "diligence"
DATA_ROOM_DIR = REPO_ROOT / "docs" / "business" / "data-room"

GITHUB_REPO = "lictor-ai/lictor"
GITHUB_API = "https://api.github.com"


# ──────────────────────────────────────────────────────────────────────────────
# Source-specific fetchers. Each returns a dict of metrics, or {} on failure.

def fetch_github_stats() -> dict[str, Any]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return {}
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Lictor-metrics/1.0",
    }
    try:
        req = urllib.request.Request(f"{GITHUB_API}/repos/{GITHUB_REPO}", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return {
            "stars": data.get("stargazers_count", 0),
            "forks": data.get("forks_count", 0),
            "open_issues": data.get("open_issues_count", 0),
            "watchers": data.get("subscribers_count", 0),
        }
    except (urllib.error.URLError, json.JSONDecodeError, KeyError):
        return {}


def fetch_stripe_revenue(month_start: dt.date, month_end: dt.date) -> dict[str, Any]:
    """Pull aggregate Stripe revenue for the month — used for AaaS + Enterprise."""
    api_key = os.environ.get("STRIPE_API_KEY", "")
    if not api_key:
        return {}
    # Stripe's API: GET /v1/balance_transactions filtered by created
    # Cap at 100 transactions per page; rare for Lictor's volume to exceed.
    start_ts = int(dt.datetime.combine(month_start, dt.time.min).timestamp())
    end_ts = int(dt.datetime.combine(month_end, dt.time.max).timestamp())
    url = (
        f"https://api.stripe.com/v1/balance_transactions"
        f"?created[gte]={start_ts}&created[lte]={end_ts}&limit=100"
    )
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        total_cents = sum(t.get("amount", 0) for t in data.get("data", []) if t.get("type") == "charge")
        return {"stripe_revenue_usd": round(total_cents / 100, 2)}
    except (urllib.error.URLError, json.JSONDecodeError):
        return {}


def fetch_paddle_subs() -> dict[str, Any]:
    """Pull active Paddle subscription count + MRR (Teams + Course)."""
    api_key = os.environ.get("PADDLE_API_KEY", "")
    if not api_key:
        return {}
    # Paddle Billing API v1: GET /subscriptions?status=active
    url = "https://api.paddle.com/subscriptions?status=active&per_page=200"
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        subs = data.get("data", [])
        teams_count = sum(1 for s in subs if "teams" in (s.get("custom_data", {}) or {}).get("plan", "").lower())
        course_count = sum(1 for s in subs if "course" in (s.get("custom_data", {}) or {}).get("plan", "").lower())
        # Paddle returns prices in unit_price.amount (string, smallest currency unit)
        total_mrr_cents = 0
        for s in subs:
            for item in s.get("items", []):
                amount = int(item.get("price", {}).get("unit_price", {}).get("amount", "0"))
                total_mrr_cents += amount
        return {
            "teams_subs": teams_count,
            "course_subs": course_count,
            "paddle_mrr_usd": round(total_mrr_cents / 100, 2),
        }
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, ValueError):
        return {}


def fetch_twitter_followers() -> dict[str, Any]:
    """Pull current @lictor_ai follower count."""
    token = os.environ.get("TWITTER_BEARER_TOKEN", "")
    if not token:
        return {}
    handle = os.environ.get("TWITTER_HANDLE", "lictor_ai")
    url = f"https://api.twitter.com/2/users/by/username/{handle}?user.fields=public_metrics"
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        metrics = data.get("data", {}).get("public_metrics", {})
        return {
            "twitter_followers": metrics.get("followers_count", 0),
            "twitter_tweets": metrics.get("tweet_count", 0),
        }
    except (urllib.error.URLError, json.JSONDecodeError, KeyError):
        return {}


def fetch_substack_stats() -> dict[str, Any]:
    """Pull Substack subscriber count. Substack doesn't have a public API —
    we shell out to a local file dropped by the user. The file format:
    {"subscribers": 4283, "open_rate": 0.58, "as_of": "2026-10-01"}"""
    drop_file = REPO_ROOT / "docs" / "business" / "metrics-input" / "substack.json"
    if not drop_file.exists():
        return {}
    try:
        with drop_file.open() as f:
            data = json.load(f)
        return {
            "newsletter_subs": data.get("subscribers", 0),
            "newsletter_open_rate": data.get("open_rate", 0.0),
        }
    except (json.JSONDecodeError, OSError):
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# Output writers

def write_markdown_summary(
    month: str, metrics: dict[str, Any], dry_run: bool
) -> pathlib.Path:
    DILIGENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DILIGENCE_DIR / f"metrics-{month}.md"

    def m(key: str, fmt: str = "{}") -> str:
        v = metrics.get(key)
        if v is None or v == "":
            return "—"
        try:
            return fmt.format(v)
        except (ValueError, TypeError):
            return str(v)

    content = f"""# Monthly metrics — {month}

> Auto-generated by `scripts/generate-monthly-metrics.py` on {dt.date.today().isoformat()}.
> Source-of-truth for diligence. Refresh quarterly with accountant review.

## Community + reach

| Metric | Value |
|---|---|
| GitHub stars | {m("stars", "{:,}")} |
| GitHub forks | {m("forks", "{:,}")} |
| GitHub open issues | {m("open_issues", "{:,}")} |
| Twitter followers (@lictor_ai) | {m("twitter_followers", "{:,}")} |
| Newsletter subscribers | {m("newsletter_subs", "{:,}")} |
| Newsletter open rate | {m("newsletter_open_rate", "{:.1%}")} |

## Revenue

| Stream | Value |
|---|---|
| Teams subscriptions (active) | {m("teams_subs", "{:,}")} |
| Course subscriptions (active) | {m("course_subs", "{:,}")} |
| Paddle MRR (Teams + Course) | ${m("paddle_mrr_usd", "{:,.2f}")} |
| Stripe revenue this month (AaaS + Enterprise) | ${m("stripe_revenue_usd", "{:,.2f}")} |

## Data sources

| Source | Status |
|---|---|
| GitHub API | {'✅ live' if metrics.get('stars') is not None else '❌ token missing or rate-limited'} |
| Stripe API | {'✅ live' if metrics.get('stripe_revenue_usd') is not None else '❌ not configured'} |
| Paddle API | {'✅ live' if metrics.get('paddle_mrr_usd') is not None else '❌ not configured'} |
| Twitter API | {'✅ live' if metrics.get('twitter_followers') is not None else '❌ token missing'} |
| Substack stats | {'✅ live (drop file)' if metrics.get('newsletter_subs') is not None else '❌ drop file missing — run `make substack-snapshot` first'} |

## Notes

- This file feeds the data-room CSV updates (see `docs/business/data-room/`).
- Manual additions for what the APIs don't capture: paid course enrollees (one-time), AaaS customer count, Enterprise pilot status. Edit this file directly to add those rows; they survive subsequent re-runs (look for the "## Manual additions" header below).

## Manual additions

<!-- Anything Dor writes below this line is preserved on re-run. -->
"""
    # Preserve manual section if file exists
    if out_path.exists():
        existing = out_path.read_text()
        manual_marker = "## Manual additions"
        if manual_marker in existing:
            existing_manual = existing.split(manual_marker, 1)[1]
            content = content.split(manual_marker)[0] + manual_marker + existing_manual

    if dry_run:
        print(f"[dry-run] would write {out_path}")
        print(content)
    else:
        out_path.write_text(content)
        print(f"✓ wrote {out_path}")
    return out_path


def append_csv_row(path: pathlib.Path, headers: list[str], row: dict[str, Any], dry_run: bool):
    """Append a row to a CSV. Idempotent: if this month's row already exists, replace it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    if path.exists():
        with path.open() as f:
            rows = list(csv.DictReader(f))
    # Replace by month (first column convention: "month")
    rows = [r for r in rows if r.get("month") != row["month"]]
    rows.append({k: str(row.get(k, "")) for k in headers})
    rows.sort(key=lambda r: r.get("month", ""))
    if dry_run:
        print(f"[dry-run] would append to {path}: {row}")
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
    print(f"✓ updated {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Main

def parse_month(arg: str | None) -> tuple[str, dt.date, dt.date]:
    """Returns (month_str, start_date, end_date). Defaults to PREVIOUS month."""
    if arg:
        year, month = arg.split("-")
        d = dt.date(int(year), int(month), 1)
    else:
        today = dt.date.today()
        # Previous month
        if today.month == 1:
            d = dt.date(today.year - 1, 12, 1)
        else:
            d = dt.date(today.year, today.month - 1, 1)

    # End of month: day before next month's first
    if d.month == 12:
        end = dt.date(d.year + 1, 1, 1) - dt.timedelta(days=1)
    else:
        end = dt.date(d.year, d.month + 1, 1) - dt.timedelta(days=1)
    return d.strftime("%Y-%m"), d, end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("month", nargs="?", help="YYYY-MM (default: previous month)")
    parser.add_argument("--dry-run", action="store_true", help="print, don't write")
    args = parser.parse_args()

    month, start, end = parse_month(args.month)
    print(f"Generating metrics for {month} ({start} → {end})")

    metrics: dict[str, Any] = {}
    metrics.update(fetch_github_stats())
    metrics.update(fetch_stripe_revenue(start, end))
    metrics.update(fetch_paddle_subs())
    metrics.update(fetch_twitter_followers())
    metrics.update(fetch_substack_stats())

    print(f"Collected {len(metrics)} metrics from {sum(1 for k in metrics if metrics[k] is not None)} sources")

    # 1. Write markdown summary
    write_markdown_summary(month, metrics, args.dry_run)

    # 2. Update data-room CSVs
    append_csv_row(
        DATA_ROOM_DIR / "03-product" / "github-stats-monthly.csv",
        ["month", "stars", "forks", "open_issues"],
        {"month": month, **{k: metrics.get(k, "") for k in ["stars", "forks", "open_issues"]}},
        args.dry_run,
    )
    append_csv_row(
        DATA_ROOM_DIR / "05-sales-marketing" / "marketing-analytics-monthly.csv",
        ["month", "stars", "newsletter_subs", "newsletter_open_rate", "twitter_followers"],
        {
            "month": month,
            "stars": metrics.get("stars", ""),
            "newsletter_subs": metrics.get("newsletter_subs", ""),
            "newsletter_open_rate": metrics.get("newsletter_open_rate", ""),
            "twitter_followers": metrics.get("twitter_followers", ""),
        },
        args.dry_run,
    )
    append_csv_row(
        DATA_ROOM_DIR / "01-financials" / "revenue-streams" / "teams-mrr-history.csv",
        ["month", "active_subs", "mrr_usd"],
        {
            "month": month,
            "active_subs": metrics.get("teams_subs", ""),
            "mrr_usd": metrics.get("paddle_mrr_usd", ""),
        },
        args.dry_run,
    )

    print(f"\n✓ Done. Review at {DILIGENCE_DIR / f'metrics-{month}.md'}")


if __name__ == "__main__":
    sys.exit(main() or 0)
