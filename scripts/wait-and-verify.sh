#!/usr/bin/env bash
# wait-and-verify.sh
#
# Waits for all the Phase-1 scanners to complete, then runs the verification
# pipeline (verify-findings → dedupe-against-prior → correlate-by-pattern).
#
# Output: a ready-to-submit clean queue at:
#   /Users/raffa/Lictor/v3/ledgers/verified-not-disclosed.jsonl
#   /Users/raffa/Lictor/v3/ledgers/clustered-findings.json
#
# Usage:
#   nohup ./wait-and-verify.sh > /tmp/wait-and-verify.log 2>&1 &

set -u
SCRIPT_DIR=/Users/raffa/Lictor/scripts
LEDGER_DIR=/Users/raffa/Lictor/v3/ledgers
PID_DIR=/tmp/lictor-pids

# Scanners we care about for verification — the "phase 1" wave + new web-app
# scanners. We do NOT block on chaos-dnsx or dep-confusion (they run for many
# hours; verification can be re-run later when they finish).
WAIT_SCANNERS=(
  patrol-open-redirect
  patrol-host-header-injection
  patrol-cache-poisoning
  patrol-path-traversal
  patrol-exposed-databases
  patrol-exposed-infra
  patrol-debug-actuator
  patrol-ssti-candidates
  patrol-xxe-candidates
  patrol-exposed-configs
  patrol-http-smuggling
  patrol-graphql-mutations
  patrol-import-ssrf
  patrol-defi-admin-exposed
  patrol-hardhat-exposed
  patrol-defi-rpc-leak
)

echo "[$(date '+%H:%M:%S')] wait-and-verify started — watching ${#WAIT_SCANNERS[@]} scanner PIDs"

while true; do
  alive_count=0
  alive_names=()
  for name in "${WAIT_SCANNERS[@]}"; do
    pidfile="$PID_DIR/${name}.pid"
    if [ -f "$pidfile" ]; then
      pid=$(cat "$pidfile")
      if kill -0 "$pid" 2>/dev/null; then
        alive_count=$((alive_count+1))
        alive_names+=("$name")
      fi
    fi
  done
  if [ "$alive_count" -eq 0 ]; then
    echo "[$(date '+%H:%M:%S')] All ${#WAIT_SCANNERS[@]} scanners completed. Starting verification pipeline."
    break
  fi
  echo "[$(date '+%H:%M:%S')] $alive_count scanners still running: ${alive_names[*]}"
  sleep 120
done

echo ""
echo "================================================================"
echo "[$(date '+%H:%M:%S')] STEP 1 — verify-findings (FP re-probe)"
echo "================================================================"
python3 "$SCRIPT_DIR/verify-findings.py" \
  --ledger-dir "$LEDGER_DIR" \
  --out "$LEDGER_DIR/verified-findings.jsonl" \
  --threads 10 \
  --max-per-class 500

echo ""
echo "================================================================"
echo "[$(date '+%H:%M:%S')] STEP 2 — dedupe against prior disclosures"
echo "================================================================"
python3 "$SCRIPT_DIR/dedupe-against-prior.py" \
  --verified "$LEDGER_DIR/verified-findings.jsonl" \
  --disclosure-dir /Users/raffa/Lictor/disclosures \
  --out "$LEDGER_DIR/verified-not-disclosed.jsonl" \
  --dup-out "$LEDGER_DIR/duplicate-skipped.jsonl"

echo ""
echo "================================================================"
echo "[$(date '+%H:%M:%S')] STEP 3 — correlate by pattern (cross-site amplification)"
echo "================================================================"
python3 "$SCRIPT_DIR/correlate-by-pattern.py" \
  --verified "$LEDGER_DIR/verified-not-disclosed.jsonl" \
  --out "$LEDGER_DIR/clustered-findings.json"

echo ""
echo "================================================================"
echo "[$(date '+%H:%M:%S')] PIPELINE COMPLETE"
echo "================================================================"
echo ""
echo "Outputs:"
echo "  $LEDGER_DIR/verified-findings.jsonl          (all classifications)"
echo "  $LEDGER_DIR/verified-not-disclosed.jsonl     (confirmed + not previously disclosed)"
echo "  $LEDGER_DIR/duplicate-skipped.jsonl          (confirmed BUT previously disclosed)"
echo "  $LEDGER_DIR/clustered-findings.json          (grouped by apex + by signature)"
echo ""
echo "Next: review the clustered-findings to prioritize bulk-disclosure opportunities."
