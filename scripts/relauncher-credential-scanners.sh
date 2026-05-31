#!/usr/bin/env bash
# relauncher-credential-scanners.sh
#
# Waits for patrol-dependency-confusion (the current GH-rate-limit-hogging scan)
# to finish, then sequentially launches the credential-leak hunting suite to
# pick up any fresh leaks pushed to GitHub since the last scan.
#
# Order: bot-tokens → ai-saas-keys → aws-keys → firebase → cloud-keys → gitlab
# (sequential to respect GH search rate limit of 10 code-search req/min)
#
# Usage:
#   ./relauncher-credential-scanners.sh
#   nohup ./relauncher-credential-scanners.sh > /tmp/lictor-relauncher.log 2>&1 &

set -u

PID_DIR="/tmp/lictor-pids"
LEDGER_DIR="/Users/raffa/Lictor/v3/ledgers"
SCRIPT_DIR="/Users/raffa/Lictor/scripts"
LOG_DIR="/tmp"

mkdir -p "$PID_DIR" "$LEDGER_DIR"

DEP_PID_FILE="$PID_DIR/dep-confusion.pid"

echo "[$(date '+%H:%M:%S')] Relauncher starting — waiting for dep-confusion to finish"

if [ ! -f "$DEP_PID_FILE" ]; then
    echo "[$(date '+%H:%M:%S')] No dep-confusion PID file found — proceeding immediately"
else
    DEP_PID=$(cat "$DEP_PID_FILE")
    while kill -0 "$DEP_PID" 2>/dev/null; do
        echo "[$(date '+%H:%M:%S')] dep-confusion PID=$DEP_PID still running, waiting 60s..."
        sleep 60
    done
    echo "[$(date '+%H:%M:%S')] dep-confusion finished — relaunching credential suite"
fi

# Sequential launch — each scanner finishes before next starts, to stay under
# GitHub Code Search rate limit (10 req/min).

run_scanner() {
    local NAME="$1"
    local SCRIPT="$2"
    local LOG="$LOG_DIR/relauncher-${NAME}-$(date +%Y%m%d-%H%M).log"
    echo "[$(date '+%H:%M:%S')] === Launching $NAME ==="
    if [ ! -f "$SCRIPT" ]; then
        echo "[$(date '+%H:%M:%S')] $NAME — script not found at $SCRIPT, skipping"
        return
    fi
    python3 "$SCRIPT" "${@:3}" > "$LOG" 2>&1
    EXIT=$?
    echo "[$(date '+%H:%M:%S')] $NAME finished exit=$EXIT log=$LOG"
}

run_scanner "bot-tokens"      "$SCRIPT_DIR/patrol-bot-tokens.py"      \
            --max 200 --max-age-days 30

run_scanner "ai-saas-keys"    "$SCRIPT_DIR/patrol-ai-saas-keys.py"    \
            --max 200 --max-age-days 30

run_scanner "aws-keys"        "$SCRIPT_DIR/patrol-aws-keys.py"        \
            --max 200

run_scanner "firebase"        "$SCRIPT_DIR/patrol-firebase.py"        \
            --max 200

run_scanner "cloud-keys"      "$SCRIPT_DIR/patrol-cloud-keys.py"      \
            --max 200

run_scanner "gitlab"          "$SCRIPT_DIR/patrol-gitlab.py"          \
            --max 200

# Web3 credential hunt (the new scanner)
run_scanner "defi-deployer-keys" "$SCRIPT_DIR/patrol-defi-deployer-keys-github.py" \
            --orgs /Users/raffa/Lictor/v3/corpus/defi-orgs.txt --per-org-max 20

echo "[$(date '+%H:%M:%S')] === Relauncher complete — full credential sweep done ==="
echo "[$(date '+%H:%M:%S')] Check ledgers in $LEDGER_DIR"
