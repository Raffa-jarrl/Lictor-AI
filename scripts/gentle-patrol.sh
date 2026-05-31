#!/bin/bash
# gentle-patrol — the throttled, transparent, single-lane scan runner.
#
# This REPLACES wave-coordinator.py's swarm. Where that ran ~15 scanners in
# parallel at 20-50 threads each (the pattern that drew the ISP's attention),
# this runs scanners ONE AT A TIME, at low concurrency, with polite gaps —
# a steady hum instead of a flood. Every target list is opt-out-filtered
# first, and we identify ourselves on every request that supports a UA.
#
# Option 2 (throttled + transparent) of the sustainable plan. Pair it with
# passive-recon.py (Option 3) for discovery that never touches the targets.
#
#   bash scripts/gentle-patrol.sh [CORPUS] [MAXHOSTS]
#
# Draft-only — writes local ledgers, sends nothing. Ctrl-C safe.
set -u
cd /Users/raffa/Lictor || exit 1
PY=/usr/bin/python3
CORPUS="${1:-$HOME/.lictor/il-master.txt}"
MAX="${2:-800}"
export LICTOR_UA="Lictor-Patrol/1.0 (+https://lictorai.com/scan-policy; abuse@lictorai.com)"
LOG="/tmp/gentle-patrol-$(date +%F).log"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

[ -f "$CORPUS" ] || { echo "corpus not found: $CORPUS"; exit 1; }

# 1. opt-out filter + cap — the one universally-enforced control
CLEAN=/tmp/gentle-targets.txt
"$PY" scripts/filter-optout.py "$CORPUS" | head -n "$MAX" > "$CLEAN"
log "════════ gentle-patrol — single lane, throttled ════════"
log "corpus=$(basename "$CORPUS")  after opt-out+cap=$(wc -l <"$CLEAN"|tr -d ' ') hosts  max-threads=8"

# 2. scanners run SEQUENTIALLY (never in parallel), low concurrency, with sleeps.
#    Edit this list to taste; each runs to completion before the next starts.

log "── [1/3] validated web battery (verifier-gated, zero-FP) ──"
# build a rank<TAB>host pool from the clean list
awk '{print NR"\t"$0}' "$CLEAN" > /tmp/gentle-pool.txt
"$PY" scripts/scan-il-verified.py --pool /tmp/gentle-pool.txt \
  --output "$HOME/.lictor/gentle-verified-$(date +%F).jsonl" \
  --max "$MAX" --sleep 0.5 >>"$LOG" 2>&1 || log "  (verified scan exit $?)"
sleep 5

log "── [2/3] exposed sensitive files (HEAD-first, 8 threads) ──"
"$PY" scripts/patrol-sensitive-files-v3.py --hosts "$CLEAN" \
  --max-hosts "$MAX" --threads 8 \
  --ledger v3/ledgers/sensitive-files-v3.jsonl >>"$LOG" 2>&1 || log "  (sensitive-files exit $?)"
sleep 5

log "── [3/3] geo warm-map refresh (HEAD-only, slice 150) ──"
"$PY" scripts/globe-patrol.py --corpus "$CLEAN" --slice 150 >>"$LOG" 2>&1 || log "  (globe exit $?)"

log "════════ gentle-patrol done — one lane, polite, identifiable ════════"
log "review findings, then YOU click Submit on any disclosure. Nothing was sent."
