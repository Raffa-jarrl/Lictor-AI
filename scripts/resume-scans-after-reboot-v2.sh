#!/bin/bash
# resume-scans-after-reboot-v2.sh
#
# Robust scan-resume script for after the new router arrives (2026-05-25).
# Improvements over v1:
#   - Validates network + tooling prerequisites before launching anything
#   - Uses consolidated chaos state (single deduped cname-results.txt + remaining-FOR-TOMORROW.txt)
#   - Tries multiple DNS resolvers, gracefully falls back if one is blocked
#   - Verifies dnsx + gh CLI are present and authed
#   - Each scan has its own PID file in /tmp/lictor-pids/ for easy management
#   - Includes admin-panels resume (171 hosts remaining), patrol-ai-saas-keys re-run,
#     tranco wrapper, AND optionally GitHub-based credential patrols
#   - Logs each phase to dated files for post-hoc debugging
#
# Usage (after new router connected + network confirmed):
#   bash ~/Lictor/scripts/resume-scans-after-reboot-v2.sh
#
# Add --skip-network-check to bypass the pre-flight (don't recommend).

set -u

SKIP_NETWORK=0
if [ "${1:-}" = "--skip-network-check" ]; then
  SKIP_NETWORK=1
fi

DATE=$(date +%Y-%m-%d-%H%M)
PID_DIR=/tmp/lictor-pids
mkdir -p $PID_DIR

echo "═══════════════════════════════════════════════════════════════"
echo " Resuming Lictor scan portfolio — $(date)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── PRE-FLIGHT: validate network + tooling ─────────────────────────
echo "[+] Pre-flight checks..."

# Tool presence
for tool in dnsx nuclei gh; do
  if ! command -v $tool > /dev/null 2>&1; then
    echo "  ✗ Missing tool: $tool — please install before resuming"
    exit 2
  fi
  echo "  ✓ $tool present"
done

# GitHub auth
if ! gh auth status > /dev/null 2>&1; then
  echo "  ✗ gh CLI not authenticated — run 'gh auth login' first"
  exit 3
fi
echo "  ✓ gh CLI authenticated"

# Network check (skippable)
if [ "$SKIP_NETWORK" = "0" ]; then
  echo "  [network] Testing GitHub + OpenAI + DNS..."
  GH_OK=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 https://api.github.com/zen 2>/dev/null)
  OPENAI_OK=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 https://api.openai.com/v1/models 2>/dev/null)
  DNS_TEST=$(dig +short +time=2 +tries=1 github.com @8.8.8.8 2>/dev/null | head -1)

  if [ "$GH_OK" != "200" ]; then
    echo "  ⚠ GitHub API: HTTP $GH_OK — credential patrols will fail until this works"
  else
    echo "  ✓ GitHub API: 200"
  fi
  if [ -z "$DNS_TEST" ]; then
    echo "  ✗ DNS to 8.8.8.8 not working — chaos pipeline WILL FAIL"
    echo "    Aborting. Fix network first or use --skip-network-check to force."
    exit 4
  else
    echo "  ✓ DNS resolution: $DNS_TEST"
  fi
fi
echo ""

# ─── REQUIRED FILES ─────────────────────────────────────────────────
echo "[+] Checking persisted artifacts..."
CNAME_OUT=/Users/raffa/.lictor/chaos-pipeline-2026-05-23/cname-results.txt
REMAINING=/Users/raffa/.lictor/chaos-pipeline-2026-05-23-resume/remaining-FOR-TOMORROW.txt
ADMIN_LEDGER=/Users/raffa/Lictor/v3/ledgers/protocol-admin-panels.jsonl
CHAOS_CORPUS=/Users/raffa/.lictor/chaos-bountied-hosts.txt
ADMIN_CORPUS=/Users/raffa/.lictor/bounty-corpus-priority.txt
TRANCO_CSV=/Users/raffa/.lictor/tranco-top1m.csv

for f in "$CNAME_OUT" "$REMAINING" "$ADMIN_LEDGER" "$CHAOS_CORPUS" "$ADMIN_CORPUS" "$TRANCO_CSV"; do
  if [ ! -f "$f" ]; then
    echo "  ✗ MISSING required: $f"
    exit 5
  fi
  echo "  ✓ $(ls -la $f | awk '{print $5}') bytes — $f"
done
echo ""

# ─── PROGRESS SUMMARY ───────────────────────────────────────────────
RESOLVED_COUNT=$(wc -l < "$CNAME_OUT" | tr -d ' ')
REMAINING_COUNT=$(wc -l < "$REMAINING" | tr -d ' ')
echo "[+] Chaos pipeline state:"
echo "    Resolved so far: $RESOLVED_COUNT CNAMEs"
echo "    Still to resolve: $REMAINING_COUNT subdomains"
echo "    Progress: $(echo "scale=2; $RESOLVED_COUNT * 100 / 36664740" | bc)%"
echo ""

# Compute admin-panels remaining from log
ADMIN_LOG=/Users/raffa/Lictor/logs/2026-05-23-pre-reboot/admin-panels-v2-rerun.log
if [ -f "$ADMIN_LOG" ]; then
  ADMIN_SCANNED=$(grep -oE "^\s+\[[0-9]+/507\] [a-zA-Z0-9.-]+" "$ADMIN_LOG" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')
  ADMIN_REMAINING_COUNT=$((507 - ADMIN_SCANNED))
  echo "[+] Admin-panels state:"
  echo "    Scanned: $ADMIN_SCANNED / 507"
  echo "    Remaining: $ADMIN_REMAINING_COUNT"
fi
echo ""

# ─── LAUNCH: chaos dnsx ─────────────────────────────────────────────
echo "[+] Launching chaos dnsx on $REMAINING_COUNT remaining subdomains..."
CHAOS_OUT=/Users/raffa/.lictor/chaos-pipeline-2026-05-23/cname-results-resumed-$DATE.txt
CHAOS_LOG=/tmp/chaos-dnsx-$DATE.log

nohup dnsx -l "$REMAINING" \
     -cname -resp -silent \
     -r 8.8.8.8,8.8.4.4,1.1.1.1 \
     -t 200 -rl 5000 -retry 1 \
     -o "$CHAOS_OUT" \
     > "$CHAOS_LOG" 2>&1 &
CHAOS_PID=$!
echo $CHAOS_PID > $PID_DIR/chaos-dnsx.pid
echo "    [OK] chaos dnsx: PID $CHAOS_PID (saved to $PID_DIR/chaos-dnsx.pid)"
echo "    Output: $CHAOS_OUT"
echo "    Log: $CHAOS_LOG"
echo ""

# ─── LAUNCH: admin-panels resume ────────────────────────────────────
ADMIN_RESUME_DIR=/Users/raffa/.lictor/admin-panels-resume
if [ -f "$ADMIN_RESUME_DIR/remaining.txt" ]; then
  echo "[+] Launching admin-panels on remaining hosts..."
  ADMIN_LOG_NEW=/tmp/admin-panels-$DATE.log
  cd /Users/raffa/Lictor/v3/scripts/scanners
  nohup python3 scan-protocol-admin-panels.py \
        --corpus "$ADMIN_RESUME_DIR/remaining.txt" \
        --limit 200 --delay 0.25 --paths full \
        > "$ADMIN_LOG_NEW" 2>&1 &
  ADMIN_PID=$!
  echo $ADMIN_PID > $PID_DIR/admin-panels.pid
  echo "    [OK] admin-panels: PID $ADMIN_PID"
  echo ""
fi

# ─── LAUNCH: patrol-ai-saas-keys (always re-run, fast) ─────────────
if [ "${GH_OK:-200}" = "200" ]; then
  echo "[+] Launching patrol-ai-saas-keys (32-vendor sweep)..."
  cd /Users/raffa/Lictor
  AI_LOG=/tmp/patrol-ai-saas-$DATE.log
  nohup python3 scripts/patrol-ai-saas-keys.py --max 1000 --max-age-days 730 \
    --private docs/launch/patrol-ai-saas-$DATE-private.md \
    > "$AI_LOG" 2>&1 &
  AI_PID=$!
  echo $AI_PID > $PID_DIR/patrol-ai-saas.pid
  echo "    [OK] patrol-ai-saas-keys: PID $AI_PID"
  echo ""
else
  echo "[~] Skipping patrol-ai-saas-keys — GitHub API not reachable"
  echo ""
fi

# ─── LAUNCH: tranco-after-chaos wrapper ─────────────────────────────
TRANCO_WRAPPER=/tmp/tranco-after-chaos-$DATE.sh
cat > "$TRANCO_WRAPPER" <<EOF
#!/bin/bash
echo "[\$(date)] [Tranco] Waiting for chaos dnsx (PID $CHAOS_PID) to finish..."
while ps -p $CHAOS_PID > /dev/null 2>&1; do sleep 60; done
echo "[\$(date)] [Tranco] Chaos done. Launching Tranco top-100K..."

OUT_DIR=/Users/raffa/.lictor/tranco-pipeline-\$(date +%Y-%m-%d)
mkdir -p "\$OUT_DIR"
head -100000 /Users/raffa/.lictor/tranco-top1m.csv | awk -F, '{print \$2}' > "\$OUT_DIR/tranco-top100k.txt"

dnsx -l "\$OUT_DIR/tranco-top100k.txt" -cname -resp -silent \\
     -r 8.8.8.8,8.8.4.4,1.1.1.1 -t 200 -rl 5000 -retry 1 \\
     -o "\$OUT_DIR/cname-results.txt"

PLATFORMS_REGEX="vercel-dns\\.com|herokudns\\.com|herokuapp\\.com|netlify\\.app|netlify\\.com|github\\.io|s3\\.amazonaws\\.com|cloudfront\\.net|azureedge\\.net|fastly\\.net|wpengine\\.com|surge\\.sh|bitbucket\\.io|readthedocs\\.io|ghost\\.io|webflow\\.io|statuspage\\.io|unbouncepages\\.com|gitlab\\.io"
grep -iE "\$PLATFORMS_REGEX" "\$OUT_DIR/cname-results.txt" > "\$OUT_DIR/cname-candidates.txt"
awk '{print \$1}' "\$OUT_DIR/cname-candidates.txt" | sort -u > "\$OUT_DIR/candidate-hosts.txt"

nuclei -l "\$OUT_DIR/candidate-hosts.txt" -tags takeover \\
       -severity medium,high,critical -silent \\
       -j -o "\$OUT_DIR/takeover-findings.jsonl"
echo "[\$(date)] [Tranco] Done."
EOF
chmod +x "$TRANCO_WRAPPER"
nohup "$TRANCO_WRAPPER" > /tmp/tranco-wrapper-$DATE.log 2>&1 &
TRANCO_PID=$!
echo $TRANCO_PID > $PID_DIR/tranco-wrapper.pid
echo "[+] Tranco-after-chaos wrapper: PID $TRANCO_PID"
echo ""

# ─── FINAL SUMMARY ───────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Resume complete!"
echo "═══════════════════════════════════════════════════════════════"
echo "PIDs:"
echo "  chaos dnsx:           $CHAOS_PID  ($PID_DIR/chaos-dnsx.pid)"
echo "  admin-panels:         ${ADMIN_PID:-skipped}"
echo "  patrol-ai-saas-keys:  ${AI_PID:-skipped}"
echo "  tranco-after-chaos:   $TRANCO_PID  ($PID_DIR/tranco-wrapper.pid)"
echo ""
echo "Logs: /tmp/*-$DATE.log"
echo "PID files: $PID_DIR/*.pid (for easy management)"
echo ""
echo "To check status: ps -p \$(cat $PID_DIR/chaos-dnsx.pid) ; tail /tmp/chaos-dnsx-$DATE.log"
echo "To kill all:    for f in $PID_DIR/*.pid; do kill \$(cat \$f); done"
echo ""
echo "Or just ask Claude: 'status?'"
