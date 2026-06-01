#!/bin/bash
# il-campaign-9h — a 9-hour, DNS-SAFE, Israel-focused scan campaign.
#
#   Phase 1: passive discovery via crt.sh certificate-transparency logs over the
#            expanded IL apex/ccTLD list (gov.il, muni.il, ac.il, health.gov.il,
#            idf.il, k12.il, org.il + known commercial apexes). ZERO DNS queries
#            to any target, NO brute-force → cannot trigger the ISP DNS alarm.
#   Phase 2: gentle, single-lane, HEAD-first probing of the discovered surface,
#            PUBLIC SECTOR FIRST, looping (500-host slices) until the 9h deadline.
#            Verifier-gated (zero-FP). Resolves only REAL hosts (no NXDOMAIN flood).
#
# Draft-only: writes local ledgers, sends nothing. Writes a report at the deadline.
set -u
cd /Users/raffa/Lictor || exit 1
PY=/usr/bin/python3
OUT="$HOME/.lictor/il-recon"
LOG=/tmp/il-campaign-9h.log
STATUS="$HOME/.lictor/il-campaign-status.txt"
REPORT="$HOME/.lictor/il-campaign-report.md"
VLEDGER="$HOME/.lictor/gentle-verified-$(date +%F).jsonl"
START=$(date +%s)
END=$((START + 32400))   # 9 hours

say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; echo "[$(date +%H:%M:%S)] $*" > "$STATUS"; }

say "=== IL 9h campaign START (DNS-safe) — ends ~$(date -r $END '+%a %H:%M') ==="

# ── Phase 1: passive crt.sh discovery (DNS-safe) ──
NAPX=$(wc -l <"$OUT/il-apex-expanded.txt" | tr -d ' ')
say "Phase 1: passive crt.sh discovery over $NAPX apex/ccTLD entries (CT logs only, no target DNS)…"
$PY scripts/passive-recon.py --apex "$OUT/il-apex-expanded.txt" --out "$OUT/il-passive-subs.txt" --sleep 4 >>"$LOG" 2>&1
NSUB=$(wc -l <"$OUT/il-passive-subs.txt" 2>/dev/null | tr -d ' ')
say "Phase 1 done: $NSUB IL hosts discovered passively."

# ── Prioritize: public sector first ──
$PY - "$OUT/il-passive-subs.txt" "$OUT/il-surface.txt" <<'PYEOF'
import sys
src, dst = sys.argv[1], sys.argv[2]
hosts = [h.strip() for h in open(src, errors="ignore") if h.strip() and not h.startswith("#")]
order = (".gov.il", ".health.gov.il", ".muni.il", ".idf.il", ".ac.il", ".org.il", ".co.il", ".net.il")
def rank(h):
    for i, suf in enumerate(order):
        if h.endswith(suf):
            return i
    return 99
open(dst, "w").write("\n".join(sorted(set(hosts), key=lambda h: (rank(h), h))) + "\n")
PYEOF
TOTAL=$(wc -l <"$OUT/il-surface.txt" | tr -d ' ')
say "Prioritized surface: $TOTAL IL hosts, public-sector first → il-surface.txt"

# ── Phase 2: gentle probe loop until the deadline (500-host slices, wrap when done) ──
OFFSET=0; ROUND=0
while [ "$(date +%s)" -lt "$END" ]; do
  ROUND=$((ROUND + 1))
  sed -n "$((OFFSET + 1)),$((OFFSET + 500))p" "$OUT/il-surface.txt" > /tmp/il-slice.txt
  if [ ! -s /tmp/il-slice.txt ]; then OFFSET=0; continue; fi
  REMAIN=$(((END - $(date +%s)) / 60))
  FOUND=$(wc -l <"$VLEDGER" 2>/dev/null | tr -d ' ' || echo 0)
  say "Phase 2 round $ROUND — hosts $((OFFSET+1))..$((OFFSET+500)) of $TOTAL · ${REMAIN}min left · verified-so-far=$FOUND"
  bash scripts/gentle-patrol.sh /tmp/il-slice.txt 500 >>"$LOG" 2>&1 || say "  (round $ROUND exit $?)"
  OFFSET=$((OFFSET + 500))
  [ "$OFFSET" -ge "$TOTAL" ] && OFFSET=0
  sleep 90
done

# ── Final report ──
say "=== Deadline reached after $ROUND rounds. Compiling report ==="
$PY scripts/impact-stats.py >>"$LOG" 2>&1 || true
$PY - "$VLEDGER" "$OUT/il-passive-subs.txt" "$REPORT" "$NAPX" "$ROUND" <<'PYEOF'
import sys, json, collections
vledger, subsf, reportf, napx, rounds = sys.argv[1:6]
ilsuf = (".il",)
def il(h): return str(h).endswith(".il")
subs = [h.strip() for h in open(subsf, errors="ignore") if h.strip()]
il_subs = [h for h in subs if il(h)]
findings = []
try:
    for line in open(vledger, errors="ignore"):
        line=line.strip()
        if not line: continue
        try: d=json.loads(line)
        except: continue
        findings.append(d)
except FileNotFoundError:
    pass
il_find = [f for f in findings if il(f.get("host",""))]
by_cat = collections.Counter()
for f in il_find:
    for fl in f.get("findings", []):
        # fl is [severity, check, detail] tuples from scan-il-verified
        try: by_cat[fl[1]] += 1
        except: pass
hosts_with = sorted({f.get("host","") for f in il_find})
def sector(h):
    for s in (".gov.il",".health.gov.il",".muni.il",".idf.il",".ac.il"):
        if h.endswith(s): return s
    return "other"
sec = collections.Counter(sector(h) for h in hosts_with)
with open(reportf,"w") as r:
    r.write("# Lictor — Israel 9-Hour Campaign Report\n\n")
    r.write(f"- Apex/ccTLD entries queried (passive): {napx}\n")
    r.write(f"- IL hosts discovered (crt.sh CT logs, zero target DNS): {len(il_subs):,}\n")
    r.write(f"- Probe rounds completed: {rounds}\n")
    r.write(f"- Verified findings (this campaign, IL): {len(il_find)}\n")
    r.write(f"- Distinct IL hosts with a verified finding: {len(hosts_with)}\n\n")
    r.write("## Findings by sector (verified IL hosts)\n")
    for s,c in sec.most_common():
        r.write(f"- {c} · {s}\n")
    r.write("\n## Findings by category (verified)\n")
    for c,n in by_cat.most_common(12):
        r.write(f"- {n} · {c}\n")
    r.write("\n_DNS-safe: discovery via certificate-transparency only; probing resolved only real hosts. No brute-force, no takeover. Draft-only — nothing was sent._\n")
print("report written")
PYEOF
say "=== CAMPAIGN COMPLETE → $REPORT ==="
