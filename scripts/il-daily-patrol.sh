#!/bin/bash
# il-daily-patrol — Israel first-priority daily VALIDATED scan.
#
# Israel is our first-priority zone. Once a day this:
#   1. refreshes the consolidated IL master (picks up newly-added IL hosts)
#   2. runs the verifier-gated scan — every raw flag is strictly re-checked,
#      only confirmed findings are written (zero-FP gate). Draft-only: it
#      writes a local ledger; it sends nothing. Raffa reviews + Submits.
#   3. refreshes the Globe geo warm-map for IL (HEAD-only, canary-guarded).
#
# Ethics: same discipline as every Lictor scanner — HEAD-only on sensitive
# surfaces, short timeouts, polite sleeps, no exploitation, aggregate-only on
# any public surface, never name an affected party publicly.
set -u
cd /Users/raffa/Lictor || exit 1
PY=/usr/bin/python3
DATE=$(date +%F)
LOG=/tmp/lictor-il-daily.log

echo "════════ il-daily-patrol $(date) ════════" >>"$LOG"

# 1. refresh consolidated master + scan pool
"$PY" scripts/build-il-master.py >>"$LOG" 2>&1

# 2. verifier-gated scan — only CONFIRMED findings survive to the ledger
"$PY" scripts/scan-il-verified.py \
  --pool /tmp/il-discovery/scan-pool.txt \
  --output "$HOME/.lictor/il-verified-$DATE.jsonl" \
  --max 5000 --sleep 0.3 >>"$LOG" 2>&1

# 3. geo warm-map refresh for the Globe (rolling, covers everything over time)
"$PY" scripts/globe-patrol.py \
  --corpus "$HOME/.lictor/il-master.txt" --corpus-cc IL --slice 5000 >>"$LOG" 2>&1

echo "════════ done $(date) ════════" >>"$LOG"
