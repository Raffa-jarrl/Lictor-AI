#!/usr/bin/env python3
"""
globe-aggregate — roll the globe-patrol zone ledger into a world heatmap.

Reads ~/.lictor/globe-zones.jsonl and writes output/globe-heatmap.json:
per-country warmth (hosts scanned, alive, warm, max/avg risk, signal mix) plus
a small list of the warmest hosts for map tooltips. The map view reads this.

Run standalone or let globe-patrol call it after each scan.
"""
from __future__ import annotations
import json, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
LEDGER = HOME / ".lictor" / "globe-zones.jsonl"
OUT = HOME / "Lictor" / "output" / "globe-heatmap.json"


def main() -> int:
    if not LEDGER.exists():
        print(f"no ledger at {LEDGER}", file=sys.stderr)
        return 1

    # latest record per host (re-scans overwrite), so warmth reflects current state
    latest: dict[str, dict] = {}
    for line in LEDGER.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        latest[r["host"]] = r

    zones: dict[str, dict] = defaultdict(lambda: {
        "scanned": 0, "alive": 0, "warm": 0, "catchall": 0,
        "risk_sum": 0, "max_risk": 0, "signals": defaultdict(int), "last": ""})
    warm_hosts = []

    for r in latest.values():
        cc = r.get("cc") or "ZZ"
        z = zones[cc]
        z["scanned"] += 1
        z["last"] = max(z["last"], r.get("ts", ""))
        if r.get("dead"):
            continue
        z["alive"] += 1
        if r.get("catchall"):
            z["catchall"] += 1
        risk = int(r.get("risk", 0))
        z["risk_sum"] += risk
        z["max_risk"] = max(z["max_risk"], risk)
        for s in r.get("signals", []):
            if not s.startswith("+") and s not in ("catch-all", "no-https"):
                z["signals"][s] += 1
        if risk >= 2:
            z["warm"] += 1
            warm_hosts.append({"host": r["host"], "cc": cc, "risk": risk,
                               "signals": [s for s in r.get("signals", []) if s != "catch-all"]})

    out_zones = {}
    for cc, z in zones.items():
        alive = z["alive"] or 1
        out_zones[cc] = {
            "scanned": z["scanned"], "alive": z["alive"], "warm": z["warm"],
            "catchall": z["catchall"], "max_risk": z["max_risk"],
            "avg_risk": round(z["risk_sum"] / alive, 2),
            # warmth 0..1: blend of warm density and peak severity → drives map colour
            "warmth": round(min(1.0, (z["warm"] / alive) * 0.7 + min(z["max_risk"], 15) / 15 * 0.3), 3),
            "signals": dict(sorted(z["signals"].items(), key=lambda x: -x[1])[:6]),
            "last": z["last"],
        }

    payload = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_scanned": sum(z["scanned"] for z in out_zones.values()),
        "total_warm": sum(z["warm"] for z in out_zones.values()),
        "countries": len(out_zones),
        "zones": dict(sorted(out_zones.items(), key=lambda x: -x[1]["warmth"])),
        "top_warm_hosts": sorted(warm_hosts, key=lambda x: -x["risk"])[:40],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2))
    print(f"[globe-aggregate] {payload['total_scanned']} hosts · {payload['countries']} zones · "
          f"{payload['total_warm']} warm → {OUT}")
    for cc, z in list(payload["zones"].items())[:8]:
        print(f"   {cc}: warmth={z['warmth']} warm={z['warm']}/{z['alive']} max_risk={z['max_risk']} {z['signals']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
