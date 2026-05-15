#!/usr/bin/env bash
# Poll every 5 minutes until lictor-ai.com resolves. Then beep + notify.
# Usage: ./scripts/wait-for-dns.sh [domain]   (defaults to lictor-ai.com)

set -euo pipefail
DOMAIN="${1:-lictor-ai.com}"
INTERVAL=300   # 5 minutes

echo "[$(date +%H:%M:%S)] Watching $DOMAIN — polling every ${INTERVAL}s..."
echo "Ctrl-C to stop."

ATTEMPT=0
while true; do
  ATTEMPT=$((ATTEMPT + 1))
  RESULT=$(dig +short "$DOMAIN" @1.1.1.1 2>/dev/null | head -1 || true)

  if [[ -n "$RESULT" ]]; then
    echo "[$(date +%H:%M:%S)] ✅ $DOMAIN now resolves to: $RESULT"
    # macOS: beep + native notification
    if command -v osascript >/dev/null 2>&1; then
      osascript -e "display notification \"$DOMAIN is live — attach it to Pages now\" with title \"Lictor DNS ready\" sound name \"Glass\""
    fi
    echo -e "\a\a\a"
    echo ""
    echo "Next steps:"
    echo "  1. Cloudflare → lictor-ai-site → Custom domains → Add → $DOMAIN"
    echo "  2. Activate"
    echo "  3. Verify: curl -sI https://$DOMAIN | head -5"
    exit 0
  fi

  echo "[$(date +%H:%M:%S)] attempt $ATTEMPT — still no records for $DOMAIN, waiting..."
  sleep "$INTERVAL"
done
