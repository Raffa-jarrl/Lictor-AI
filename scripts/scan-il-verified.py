#!/usr/bin/env python3
"""
scan-il-verified — scan all IL sites with verifier-gating.

For each site:
  1. Run patrol-pilot.scan_one (raw flagging)
  2. For every actionable finding, run verify-finding (strict re-check)
  3. Only keep findings that pass verification

This kills WAF / SPA-fallback / bot-challenge false positives BEFORE they
ever land in the actionables file.
"""
from __future__ import annotations
import sys, importlib.util, time, json, argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "scripts")
# Load patrol-pilot
spec = importlib.util.spec_from_file_location("pilot", "scripts/patrol-pilot.py")
pilot = importlib.util.module_from_spec(spec); sys.modules["pilot"] = pilot
spec.loader.exec_module(pilot)
# Load verify-finding
spec2 = importlib.util.spec_from_file_location("verifier", "scripts/verify-finding.py")
verifier = importlib.util.module_from_spec(spec2); sys.modules["verifier"] = verifier
spec2.loader.exec_module(verifier)


def verify_findings(homepage, findings):
    """Re-check each finding via verifier. Return only those that pass."""
    survivors = []
    for f in findings:
        check = f.check or ""
        if check.startswith("exposed-.env"):
            verdict, _ = verifier.verify_exposed_env(homepage)
            if verdict == "confirmed":
                survivors.append(f)
        elif check == "admin-page-no-auth":
            verdict, _ = verifier.verify_admin_no_auth(homepage)
            if verdict == "confirmed":
                survivors.append(f)
        elif f.severity in ("critical", "high"):
            # For other critical/high findings (secret-in-bundle, JWT, firebase),
            # those come from regex on real JS bundle content — verifier doesn't have
            # a check for them. Keep as-is.
            survivors.append(f)
        # Drop everything else (low/info/medium that isn't admin)
    return survivors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="/tmp/il-discovery/scan-pool.txt")
    ap.add_argument("--output", default="/tmp/il-discovery/verified-findings.jsonl")
    ap.add_argument("--max", type=int, default=2000, help="Cap sites to scan")
    ap.add_argument("--sleep", type=float, default=0.8, help="Sleep between sites (be polite)")
    args = ap.parse_args()

    targets = []
    for line in open(args.pool):
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            targets.append((parts[0], parts[1]))
    targets = targets[:args.max]

    print(f"[scan-il-verified] starting on {len(targets)} sites @ {datetime.now()}", flush=True)
    print(f"[scan-il-verified] output → {args.output}", flush=True)

    clean = errored = raw_actionable = verified_actionable = 0
    start = time.time()
    fout = open(args.output, "w")

    for i, (rank, host) in enumerate(targets, 1):
        homepage = f"https://{host}/"
        try:
            r = pilot.scan_one({"repo": host, "repo_url": homepage,
                                "homepage": homepage, "platform_hint": "tranco-il",
                                "full_name": host, "stargazers_count": 0, "pushed_at": ""})
            # Raw flag count
            raw_flagged = [f for f in r.findings if f.severity in ("critical","high") or "admin" in (f.check or "") or "exposed" in (f.check or "")]
            if raw_flagged:
                raw_actionable += 1
                # Verify
                survivors = verify_findings(homepage, raw_flagged)
                if survivors:
                    verified_actionable += 1
                    findings_serial = [(f.severity, f.check, (f.detail or "")[:120]) for f in survivors]
                    fout.write(json.dumps({"rank": int(rank), "host": host, "grade": r.grade,
                                           "findings": findings_serial,
                                           "raw_count": len(raw_flagged),
                                           "verified_count": len(survivors)}) + "\n")
                    fout.flush()
                    summary = ";".join(f"{s}:{c}" for s,c,_ in findings_serial)
                    print(f"[{i}/{len(targets)}] #{rank} {host}  🔴 VERIFIED  {summary[:80]}", flush=True)
                else:
                    print(f"[{i}/{len(targets)}] #{rank} {host}  ⚪ {len(raw_flagged)} raw → 0 verified (false positives)", flush=True)
            else:
                clean += 1
                if i % 25 == 0:
                    elapsed = int(time.time()-start)
                    print(f"[{i}/{len(targets)}] progress — clean={clean} raw={raw_actionable} verified={verified_actionable} err={errored} ({elapsed//60}m{elapsed%60}s)", flush=True)
        except Exception as e:
            errored += 1
        time.sleep(args.sleep)

    fout.close()
    elapsed = int(time.time()-start)
    print(f"\n=== FINAL ===")
    print(f"scanned: {len(targets)}")
    print(f"clean: {clean}")
    print(f"raw-flagged (would-have-been-reported by old logic): {raw_actionable}")
    print(f"verified-confirmed (real findings): {verified_actionable}")
    print(f"false-positive rate: {((raw_actionable-verified_actionable)/max(raw_actionable,1)*100):.0f}%")
    print(f"errored: {errored}")
    print(f"elapsed: {elapsed//60}m{elapsed%60}s")
    print(f"output: {args.output}")


if __name__ == "__main__":
    main()
