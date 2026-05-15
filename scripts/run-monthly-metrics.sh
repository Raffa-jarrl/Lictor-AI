#!/bin/bash
# Lictor monthly metrics — cron + launchd wrapper.
#
# Invoked on the 1st of every month at 06:00 IST by:
#   - launchd: ~/Library/LaunchAgents/ai.lictor.monthly-metrics.plist
#   - cron fallback (if launchd is broken)
#
# Logs to /tmp/lictor-monthly-metrics.log so failures are recoverable.

set -uo pipefail

REPO="$HOME/Lictor"
LOG="/tmp/lictor-monthly-metrics.log"

{
  echo "=== Lictor monthly metrics run at $(date) ==="

  # Load secrets from the standard location.
  # (Each line should be `export KEY=value`.)
  if [ -f "$HOME/.lictor/secrets.env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$HOME/.lictor/secrets.env"
    set +a
  fi

  cd "$REPO" || exit 1

  # Run the metrics generator for the previous month
  /usr/bin/env python3 scripts/generate-monthly-metrics.py

  RC=$?
  if [ $RC -ne 0 ]; then
    echo "✗ metrics generator exited with status $RC"
    # Optional: ping a webhook or Slack — for now just log
    exit $RC
  fi

  echo "✓ Monthly metrics complete"
} >> "$LOG" 2>&1
