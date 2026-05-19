#!/usr/bin/env python3
"""
scan-il-parallel — verified IL sweep with concurrent workers.

Same logic as scan-il-verified but uses ThreadPoolExecutor for ~10x speedup.
Each worker hits a different host so we don't hammer any single origin.
"""
from __future__ import annotations
import sys, importlib.util, time, json, argparse, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "scripts")
spec = importlib.util.spec_from_file_location("pilot", "scripts/patrol-pilot.py")
pilot = importlib.util.module_from_spec(spec); sys.modules["pilot"] = pilot
spec.loader.exec_module(pilot)
spec2 = importlib.util.spec_from_file_location("verifier", "scripts/verify-finding.py")
verifier = importlib.util.module_from_spec(spec2); sys.modules["verifier"] = verifier
spec2.loader.exec_module(verifier)


def verify_findings(homepage, findings):
    survivors = []
    for f in findings:
        check = f.check or ""
        if check.startswith("exposed-.env"):
            v, _ = verifier.verify_exposed_env(homepage)
            if v == "confirmed": survivors.append(f)
        elif check == "admin-page-no-auth":
            v, _ = verifier.verify_admin_no_auth(homepage)
            if v == "confirmed": survivors.append(f)
        elif f.severity in ("critical", "high"):
            survivors.append(f)
    return survivors


# Shared counters (locked)
LOCK = threading.Lock()
counts = {"clean": 0, "raw_act": 0, "verified": 0, "err": 0, "done": 0}
out_lock = threading.Lock()


def scan_one(rank, host, fout):
    homepage = f"https://{host}/"
    result = {"rank": int(rank), "host": host, "verified": []}
    try:
        r = pilot.scan_one({"repo": host, "repo_url": homepage,
                            "homepage": homepage, "platform_hint": "tranco-il",
                            "full_name": host, "stargazers_count": 0, "pushed_at": ""})
        raw_flagged = [f for f in r.findings
                       if f.severity in ("critical","high")
                       or "admin" in (f.check or "")
                       or "exposed" in (f.check or "")]
        with LOCK:
            counts["done"] += 1
            if not raw_flagged: counts["clean"] += 1
            else: counts["raw_act"] += 1
        if raw_flagged:
            survivors = verify_findings(homepage, raw_flagged)
            if survivors:
                with LOCK: counts["verified"] += 1
                findings_serial = [(f.severity, f.check, (f.detail or "")[:120]) for f in survivors]
                line = json.dumps({"rank": int(rank), "host": host, "grade": r.grade,
                                   "findings": findings_serial,
                                   "raw_count": len(raw_flagged),
                                   "verified_count": len(survivors)})
                with out_lock:
                    fout.write(line + "\n")
                    fout.flush()
                summary = ";".join(f"{s}:{c}" for s,c,_ in findings_serial)
                print(f"  🔴 VERIFIED #{rank} {host}  {summary[:80]}", flush=True)
    except Exception as e:
        with LOCK:
            counts["err"] += 1
            counts["done"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="/tmp/il-discovery/scan-pool.txt")
    ap.add_argument("--output", default="/tmp/il-discovery/verified-findings.jsonl")
    ap.add_argument("--max", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=10)
    args = ap.parse_args()

    targets = []
    for line in open(args.pool):
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            targets.append((parts[0], parts[1]))
    targets = targets[:args.max]
    total = len(targets)

    print(f"[parallel] starting on {total} sites with {args.workers} workers @ {datetime.now()}", flush=True)
    fout = open(args.output, "w")
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(scan_one, rank, host, fout) for rank, host in targets]
        # Periodic progress print
        last_print = 0
        while not all(f.done() for f in futures):
            time.sleep(15)
            with LOCK:
                done = counts["done"]; clean = counts["clean"]; raw = counts["raw_act"]
                ver = counts["verified"]; err = counts["err"]
            elapsed = int(time.time()-start)
            rate = done / max(elapsed,1)
            eta_s = (total - done) / max(rate, 0.1)
            print(f"  progress {done}/{total} ({rate:.1f}/s) clean={clean} raw={raw} verified={ver} err={err} elapsed={elapsed//60}m{elapsed%60}s eta={int(eta_s//60)}m{int(eta_s%60)}s", flush=True)

    fout.close()
    elapsed = int(time.time()-start)
    print(f"\n=== FINAL ===")
    print(f"scanned: {total}")
    print(f"clean: {counts['clean']}")
    print(f"raw-flagged: {counts['raw_act']}")
    print(f"verified-real: {counts['verified']}")
    print(f"false-positive rate: {(counts['raw_act']-counts['verified'])*100//max(counts['raw_act'],1)}%")
    print(f"errored: {counts['err']}")
    print(f"elapsed: {elapsed//60}m{elapsed%60}s")


if __name__ == "__main__":
    main()
