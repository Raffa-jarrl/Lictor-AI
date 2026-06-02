#!/bin/bash
# il-sector-gap-2h — rank Israel's sectors by EXPOSURE RATE to set scan priority.
#
# Takes a BALANCED sample from each .il sector (gov/health/muni/idf/ac/org/co),
# probes them with sensitive-files-v3 (gentle, single-lane, real hosts only —
# DNS-safe, no brute-force), then computes exposures-per-host-probed per sector.
# The sector with the highest rate is the "largest gap" — where to dig first.
#
# Draft-only. Writes a ranking to ~/.lictor/il-sector-gap-ranking.md
set -u
cd /Users/raffa/Lictor || exit 1
PY=/usr/bin/python3
SUBS="$HOME/.lictor/il-recon/il-passive-subs.txt"
WORK="$HOME/.lictor/il-recon/sector-gap"
LEDGER="v3/ledgers/il-sector-gap.jsonl"
RANK="$HOME/.lictor/il-sector-gap-ranking.md"
LOG=/tmp/il-sector-gap.log
CAP=1200
mkdir -p "$WORK"; : > "$LEDGER"

echo "[$(date +%H:%M)] sector-gap: building balanced per-sector samples (cap=$CAP)…" | tee "$LOG"
$PY - "$SUBS" "$WORK/union.txt" "$CAP" <<'PYEOF' | tee -a "$LOG"
import sys, collections
subs, out, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
sectors = [("gov",".gov.il"),("health",".health.gov.il"),("muni",".muni.il"),
           ("idf",".idf.il"),("ac",".ac.il"),("org",".org.il"),("co",".co.il")]
hosts = [h.strip() for h in open(subs, errors="ignore") if h.strip()]
buckets = collections.defaultdict(list)
for h in hosts:
    for name, suf in sectors:
        if h.endswith(suf):
            buckets[name].append(h); break
union = []
for name, _ in sectors:
    s = buckets[name][:cap]
    union += s
    print(f"  {name:7} {len(buckets[name]):>5} known -> sampling {len(s)}")
open(out, "w").write("\n".join(union) + "\n")
print(f"  UNION to probe: {len(union)}")
PYEOF

echo "[$(date +%H:%M)] probing balanced union (sensitive-files-v3, 8 threads, gentle)…" | tee -a "$LOG"
$PY scripts/patrol-sensitive-files-v3.py --hosts "$WORK/union.txt" --max-hosts 9000 --threads 8 --ledger "$LEDGER" >>"$LOG" 2>&1

echo "[$(date +%H:%M)] tallying exposure rate per sector…" | tee -a "$LOG"
$PY - "$WORK/union.txt" "$LEDGER" "$RANK" <<'PYEOF' | tee -a "$LOG"
import sys, json, collections
unionf, ledgerf, rankf = sys.argv[1], sys.argv[2], sys.argv[3]
sectors = [("gov",".gov.il"),("health",".health.gov.il"),("muni",".muni.il"),
           ("idf",".idf.il"),("ac",".ac.il"),("org",".org.il"),("co",".co.il")]
def sec(h):
    for n,s in sectors:
        if h.endswith(s): return n
    return "other"
probed = collections.Counter(sec(h.strip()) for h in open(unionf) if h.strip())
found_hosts = collections.defaultdict(set); sev = collections.defaultdict(collections.Counter)
for line in open(ledgerf, errors="ignore"):
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except: continue
    h=str(d.get("host","")); s=sec(h)
    found_hosts[s].add(h); sev[s][d.get("severity","?")]+=1
rows=[]
for n,_ in sectors:
    p=probed.get(n,0); f=len(found_hosts.get(n,set()))
    rate=(f/p*100) if p else 0
    crit=sev[n].get("CRITICAL",0)+sev[n].get("MEDIUM",0)
    rows.append((rate,n,p,f,crit,dict(sev[n])))
rows.sort(reverse=True)
with open(rankf,"w") as r:
    r.write("# Israel — Sector Exposure Ranking (where to dig first)\n\n")
    r.write("| Rank | Sector | Probed | Exposed hosts | Exposure rate | Crit+Med |\n")
    r.write("|---|---|---:|---:|---:|---:|\n")
    for i,(rate,n,p,f,crit,sv) in enumerate(rows,1):
        r.write(f"| {i} | .{n}.il | {p} | {f} | **{rate:.1f}%** | {crit} |\n")
    r.write("\n_DNS-safe balanced sample. Order above = recommended scan priority for the next days._\n")
print("\n  ===== SECTOR EXPOSURE RANKING (largest gap first) =====")
for i,(rate,n,p,f,crit,sv) in enumerate(rows,1):
    print(f"  {i}. .{n}.il  rate={rate:.1f}%  exposed={f}/{p}  crit+med={crit}  {sv}")
print(f"\n  -> priority order: {' > '.join('.'+n+'.il' for _,n,_,_,_,_ in rows)}")
PYEOF
echo "[$(date +%H:%M)] === SECTOR-GAP COMPLETE -> $RANK ===" | tee -a "$LOG"
