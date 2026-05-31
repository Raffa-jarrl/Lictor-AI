#!/usr/bin/env python3
"""
impact-stats — the public "blue numbers". AGGREGATE COUNTS ONLY, never names.

Reads every local findings ledger and emits the SCALE of what Lictor finds and
fixes on the open net — total sites examined, exposures surfaced, categories,
countries — with ZERO affected-party names, URLs, or paths. This is the public
impact story: big numbers, no victims.

BINDING RULE: the output (output/impact.json, IMPACT.md) must NEVER contain a
host, URL, repo, or party name. Hosts are counted via an in-memory set that is
never written. If you add a field here, it must be a number or a category label.

    python3 scripts/impact-stats.py
"""
from __future__ import annotations
import json, glob, re
from pathlib import Path
from collections import Counter

HOME = Path.home()
LICTOR = HOME / "Lictor"
SOURCES = [str(HOME / ".lictor" / "*.jsonl"), str(LICTOR / "v3" / "ledgers" / "*.jsonl")]
OUT_JSON = LICTOR / "output" / "impact.json"
OUT_MD = LICTOR / "IMPACT.md"

HOST_FIELDS = ("host", "url", "target", "domain", "repo", "homepage", "site", "hostname", "full_name")
CAT_FIELDS = ("check", "category", "type", "signal", "class", "kind", "rule", "template-id", "templateID", "finding")
SEV_FIELDS = ("severity", "sev", "risk_level")
# any of these truthy ⇒ the record is a positive finding, not just a scan observation
POS_FLAGS = ("confirmed", "verified", "vulnerable", "exposed", "found", "takeover", "claimable", "leak")


def first(d: dict, fields):
    for f in fields:
        v = d.get(f)
        if v:
            return v
    return None


def host_of(d: dict):
    h = first(d, HOST_FIELDS)
    if not h:
        return None
    h = re.sub(r"^[a-z]+://", "", str(h)).split("/")[0].split("?")[0].split(":")[0].strip().lower()
    return h or None


def is_finding(d: dict) -> bool:
    sev = str(first(d, SEV_FIELDS) or "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return True
    if str(d.get("classification", "")).lower() == "confirmed":
        return True
    for f in POS_FLAGS:
        if d.get(f) in (True, "true", 1):
            return True
    try:
        if int(d.get("risk", 0)) >= 2:
            return True
    except Exception:
        pass
    sigs = d.get("signals")
    if isinstance(sigs, list) and any(s not in ("catch-all", "no-https", "waf-catchall") and not str(s).startswith("+") for s in sigs):
        return True
    return False


AUTHORITATIVE = LICTOR / "v3" / "ledgers" / "all-findings-verified.jsonl"
REAL_VERDICTS = ("VERIFIED_REAL", "CONFIRMED", "VERIFIED", "TRUE_POSITIVE")
FP_VERDICTS = ("FP_CATCHALL", "FP_INFORMATIONAL", "STALE", "AMBIGUOUS", "FALSE_POSITIVE")


def main() -> int:
    records = 0
    files = 0
    hosts: set[str] = set()           # in-memory only — NEVER written
    countries: set[str] = set()

    # ── broad pass: distinct sites EXAMINED + countries, across every ledger ──
    for pattern in SOURCES:
        for fp in glob.glob(pattern):
            files += 1
            try:
                with open(fp, errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = json.loads(line)
                        except Exception:
                            continue
                        if not isinstance(d, dict):
                            continue
                        records += 1
                        h = host_of(d)
                        if h:
                            hosts.add(h)
                        cc = d.get("cc") or d.get("country") or d.get("countryCode")
                        if cc and str(cc) not in ("ZZ", ""):
                            countries.add(str(cc).upper()[:2])
            except Exception:
                pass

    # ── authoritative pass: VERIFIED findings only (verdict-gated, no double-count) ──
    by_cat: Counter = Counter()
    verdicts: Counter = Counter()
    finding_hosts: set[str] = set()
    verified_real = fp_filtered = raw_checked = 0
    if AUTHORITATIVE.exists():
        with open(AUTHORITATIVE, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                raw_checked += 1
                v = str(d.get("verdict", "")).upper()
                verdicts[v] += 1
                if any(r in v for r in REAL_VERDICTS):
                    verified_real += 1
                    by_cat[str(d.get("scanner", "other"))] += 1
                    h = host_of(d)
                    if h:
                        finding_hosts.add(h)
                elif v in FP_VERDICTS:
                    fp_filtered += 1

    fp_rate = round(fp_filtered / raw_checked * 100, 1) if raw_checked else 0.0

    payload = {
        "headline": {
            "sites_examined": len(hosts),
            "verified_exposures": verified_real,
            "sites_with_exposure": len(finding_hosts),
            "false_positives_filtered": fp_filtered,
            "countries_covered": len(countries),
            "risk_categories": len([c for c in by_cat if by_cat[c]]),
        },
        "by_category": dict(by_cat.most_common(20)),
        "validation": {
            "raw_flags_checked": raw_checked,
            "verified_real": verified_real,
            "false_positives_filtered": fp_filtered,
            "fp_rate_pct": fp_rate,
            "note": "Every raw flag is re-checked; only multi-signal-confirmed findings are counted.",
        },
        "methodology": {
            "ledgers_processed": files,
            "records_processed": records,
            "note": "Aggregate counts only. No host, URL, or party name is ever stored or published.",
        },
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2))

    h = payload["headline"]
    v = payload["validation"]
    md = f"""# Lictor — Impact

> The scale of what we find and responsibly disclose on the open net.
> **Aggregate numbers only — we never name an affected party.**

| | |
|---|---:|
| Sites examined | **{h['sites_examined']:,}** |
| Verified exposures | **{h['verified_exposures']:,}** |
| Sites with a real exposure | **{h['sites_with_exposure']:,}** |
| Countries covered | **{h['countries_covered']}** |
| False positives filtered out | **{h['false_positives_filtered']:,}** |

Every flag is independently re-checked before it counts — **{v['fp_rate_pct']}%** of
raw signals were rejected as false positives. Only multi-signal-confirmed
findings are in the numbers above.

### Verified exposures by category
""" + "\n".join(f"- **{n:,}** · {c}" for c, n in list(by_cat.most_common(10))) + f"""

---
_Generated from {records:,} scan records across {files} local ledgers. No names, URLs, or
paths appear in this file — by design. This is the only impact data that ever goes public._
"""
    OUT_MD.write_text(md)

    print(f"[impact-stats] {records:,} records / {files} ledgers")
    print(f"  sites examined:        {h['sites_examined']:,}")
    print(f"  VERIFIED exposures:    {h['verified_exposures']:,}")
    print(f"  sites w/ exposure:     {h['sites_with_exposure']:,}")
    print(f"  FPs filtered:          {h['false_positives_filtered']:,}  (fp rate {v['fp_rate_pct']}%)")
    print(f"  countries covered:     {h['countries_covered']}")
    print(f"  → {OUT_JSON}\n  → {OUT_MD}")
    print("  verified by category:", dict(by_cat.most_common(6)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
