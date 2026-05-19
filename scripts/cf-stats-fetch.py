#!/usr/bin/env python3
"""
cf-stats-fetch — pull Cloudflare web analytics + write a small JSON file the
site can fetch publicly.

Requires ~/.lictor/cf-config.json:
  {
    "token": "your-cloudflare-api-token-with-Analytics:Read",
    "zones": {
      "lictorai.com":  "zone-id-here",
      "lictor-ai.com": "zone-id-here"
    }
  }

Output: ~/Lictor/landing/static/cf-stats.json  (read by the /transparency page JS)
  {
    "fetched_at": "2026-05-19T12:00:00Z",
    "period_days": 7,
    "zones": {
      "lictorai.com": {
         "requests": 12345,
         "unique_visitors": 234,
         "page_views": 567,
         "top_referrers": [{"referer":"github.com","count":102},{"referer":"tiktok.com","count":89}],
         "top_pages":     [{"path":"/", "count":234}, {"path":"/scan","count":98}]
      },
      "lictor-ai.com": { ... }
    }
  }

Cron: 0 * * * *  (hourly)
"""
from __future__ import annotations
import argparse, json, sys, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

CONFIG_FILE = Path.home() / ".lictor" / "cf-config.json"
OUTPUT_FILE = Path.home() / "Lictor" / "landing" / "static" / "cf-stats.json"


def gql_query(token: str, query: str, variables: dict):
    """POST to Cloudflare GraphQL Analytics API."""
    data = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=data, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"errors": [{"message": f"HTTP {e.code}: {e.read()[:200].decode('utf-8','ignore')}"}]}
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


def fetch_zone(token: str, zone_id: str, days: int = 7):
    """Pull analytics for one zone over last N days."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    until = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Cloudflare Web Analytics (browser RUM-style) requires the rumPageloadEventsAdaptiveGroups dataset.
    # If account doesn't have Web Analytics enabled, fall back to httpRequests1dGroups.
    query = """
    query($zoneId: String!, $since: Time!, $until: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneId}) {
          totals: httpRequests1dGroups(
            limit: 1, filter: {date_geq: "%s", date_leq: "%s"}
          ) {
            sum { requests pageViews }
            uniq { uniques }
          }
          referers: httpRequestsAdaptiveGroups(
            limit: 10, filter: {datetime_geq: $since, datetime_leq: $until},
            orderBy: [count_DESC]
          ) {
            count
            dimensions { refererHost }
          }
          pages: httpRequestsAdaptiveGroups(
            limit: 10, filter: {datetime_geq: $since, datetime_leq: $until,
                                edgeResponseContentTypeName: "text/html"},
            orderBy: [count_DESC]
          ) {
            count
            dimensions { clientRequestPath }
          }
        }
      }
    }
    """ % (
        (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d"),
        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    )
    result = gql_query(token, query, {"zoneId": zone_id, "since": since, "until": until})
    if "errors" in result:
        return {"_error": result["errors"][0].get("message", "unknown")}
    try:
        z = result["data"]["viewer"]["zones"][0]
        totals = z["totals"][0]["sum"] if z["totals"] else {}
        uniq = z["totals"][0]["uniq"] if z["totals"] else {}
        return {
            "requests": totals.get("requests", 0),
            "page_views": totals.get("pageViews", 0),
            "unique_visitors": uniq.get("uniques", 0),
            "top_referrers": [
                {"referer": (r["dimensions"]["refererHost"] or "(direct)"), "count": r["count"]}
                for r in z.get("referers", [])
            ],
            "top_pages": [
                {"path": p["dimensions"]["clientRequestPath"], "count": p["count"]}
                for p in z.get("pages", [])
            ],
        }
    except Exception as e:
        return {"_error": f"parse error: {e}", "_raw": str(result)[:500]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--print", action="store_true", help="Also print JSON to stdout")
    args = ap.parse_args()

    if not CONFIG_FILE.exists():
        print(f"[cf-stats] no config at {CONFIG_FILE} — create it with token + zones, then re-run", file=sys.stderr)
        # Write an empty status file so the site shows a friendly placeholder
        OUTPUT_FILE.parent.mkdir(exist_ok=True, parents=True)
        OUTPUT_FILE.write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "_status": "not-configured",
            "_help": "drop a token in ~/.lictor/cf-config.json and re-run scripts/cf-stats-fetch.py",
        }, indent=2))
        sys.exit(1)

    cfg = json.loads(CONFIG_FILE.read_text())
    token = cfg["token"]
    zones = cfg.get("zones", {})

    result = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "period_days": args.days,
        "zones": {},
    }
    for name, zid in zones.items():
        print(f"[cf-stats] fetching {name} ({zid[:8]}…)...", file=sys.stderr)
        result["zones"][name] = fetch_zone(token, zid, args.days)

    OUTPUT_FILE.parent.mkdir(exist_ok=True, parents=True)
    OUTPUT_FILE.write_text(json.dumps(result, indent=2))
    print(f"[cf-stats] wrote {OUTPUT_FILE}", file=sys.stderr)
    if args.print:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
