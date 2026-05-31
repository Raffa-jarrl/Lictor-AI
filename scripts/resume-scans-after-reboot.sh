#!/bin/bash
# resume-scans-after-reboot.sh
#
# Re-launches the 2026-05-23 scan portfolio from where it left off before the reboot.
#
# What this does:
#   1. Computes remaining work for chaos pipeline (subdomains not yet DNS-resolved)
#   2. Computes remaining work for admin-panels scan
#   3. Re-launches in background:
#        - chaos dnsx on REMAINING subdomains only
#        - admin-panels on REMAINING hosts only
#        - patrol-ai-saas-keys (full re-run, fast)
#        - tranco-after-chaos wrapper (auto-waits for chaos to finish)
#   4. Prints PIDs and log paths
#
# Usage (after reboot):
#   bash ~/Lictor/scripts/resume-scans-after-reboot.sh

set -u

echo "═══════════════════════════════════════════════════════════════"
echo " Resuming Lictor scan portfolio — $(date)"
echo "═══════════════════════════════════════════════════════════════"

# ─── Sanity check: are the persisted artifacts present? ───
CNAME_OUT=/Users/raffa/.lictor/chaos-pipeline-2026-05-23/cname-results.txt
ADMIN_LEDGER=/Users/raffa/Lictor/v3/ledgers/protocol-admin-panels.jsonl
ADMIN_LOG=/Users/raffa/Lictor/logs/2026-05-23-pre-reboot/admin-panels-v2-rerun.log
CHAOS_CORPUS=/Users/raffa/.lictor/chaos-bountied-hosts.txt
ADMIN_CORPUS=/Users/raffa/.lictor/bounty-corpus-priority.txt

for f in "$CNAME_OUT" "$ADMIN_LEDGER" "$ADMIN_LOG" "$CHAOS_CORPUS" "$ADMIN_CORPUS"; do
  if [ ! -f "$f" ]; then
    echo "MISSING required file: $f"
    exit 1
  fi
done
echo "[OK] All persisted artifacts present."
echo ""

# ─── Compute remaining work for CHAOS dnsx ───
echo "[+] Computing remaining chaos subdomains (this takes ~1-2 min on 36M)..."
RESUME_DIR=/Users/raffa/.lictor/chaos-pipeline-2026-05-23-resume
mkdir -p "$RESUME_DIR"

# Extract already-resolved hostnames (first column of cname-results.txt)
awk '{print $1}' "$CNAME_OUT" | sort -u > "$RESUME_DIR/resolved.txt"
RESOLVED=$(wc -l < "$RESUME_DIR/resolved.txt" | tr -d ' ')
echo "    Already resolved: $RESOLVED"

# Compute set difference: original corpus minus resolved
sort -u "$CHAOS_CORPUS" > "$RESUME_DIR/corpus-sorted.txt"
comm -23 "$RESUME_DIR/corpus-sorted.txt" "$RESUME_DIR/resolved.txt" > "$RESUME_DIR/remaining.txt"
REMAINING=$(wc -l < "$RESUME_DIR/remaining.txt" | tr -d ' ')
echo "    Remaining to resolve: $REMAINING"
echo ""

# ─── Compute remaining work for ADMIN-PANELS ───
echo "[+] Computing remaining admin-panels hosts..."
ADMIN_RESUME_DIR=/Users/raffa/.lictor/admin-panels-resume
mkdir -p "$ADMIN_RESUME_DIR"

# Extract scanned hosts from the saved log (look for "[N/507] HOSTNAME" lines)
grep -oE "^\s+\[[0-9]+/507\] [a-zA-Z0-9.-]+" "$ADMIN_LOG" \
  | awk '{print $2}' | sort -u > "$ADMIN_RESUME_DIR/scanned.txt"
SCANNED=$(wc -l < "$ADMIN_RESUME_DIR/scanned.txt" | tr -d ' ')
echo "    Already scanned: $SCANNED / 507"

sort -u "$ADMIN_CORPUS" > "$ADMIN_RESUME_DIR/corpus-sorted.txt"
comm -23 "$ADMIN_RESUME_DIR/corpus-sorted.txt" "$ADMIN_RESUME_DIR/scanned.txt" \
  > "$ADMIN_RESUME_DIR/remaining.txt"
ADMIN_REMAINING=$(wc -l < "$ADMIN_RESUME_DIR/remaining.txt" | tr -d ' ')
echo "    Remaining to scan: $ADMIN_REMAINING"
echo ""

# ─── Re-launch CHAOS dnsx on REMAINING only ───
if [ "$REMAINING" -gt 0 ]; then
  echo "[+] Launching chaos dnsx on $REMAINING remaining subdomains..."
  CHAOS_RESUMED_OUT=/Users/raffa/.lictor/chaos-pipeline-2026-05-23/cname-results-resumed.txt
  nohup dnsx -l "$RESUME_DIR/remaining.txt" \
       -cname -resp -silent \
       -t 200 -rl 5000 -retry 1 \
       -o "$CHAOS_RESUMED_OUT" \
       > /tmp/chaos-dnsx-resumed.log 2>&1 &
  CHAOS_PID=$!
  echo "    [OK] chaos dnsx (resume): PID $CHAOS_PID"
  echo "    Output: $CHAOS_RESUMED_OUT"
  echo "    Log:    /tmp/chaos-dnsx-resumed.log"
else
  echo "[+] Chaos dnsx already complete (0 remaining). Skipping."
fi
echo ""

# ─── Re-launch ADMIN-PANELS on REMAINING only ───
if [ "$ADMIN_REMAINING" -gt 0 ]; then
  echo "[+] Launching admin-panels on $ADMIN_REMAINING remaining hosts..."
  cd /Users/raffa/Lictor/v3/scripts/scanners
  nohup python3 scan-protocol-admin-panels.py \
        --corpus "$ADMIN_RESUME_DIR/remaining.txt" \
        --limit $ADMIN_REMAINING \
        --delay 0.25 \
        --paths full \
        > /tmp/admin-panels-resumed.log 2>&1 &
  ADMIN_PID=$!
  echo "    [OK] admin-panels (resume): PID $ADMIN_PID"
  echo "    Output: $ADMIN_LEDGER (will append)"
  echo "    Log:    /tmp/admin-panels-resumed.log"
else
  echo "[+] Admin-panels already complete (0 remaining). Skipping."
fi
echo ""

# ─── Re-launch patrol-ai-saas-keys (cheap re-run) ───
echo "[+] Re-launching patrol-ai-saas-keys (bug-fixed version)..."
cd /Users/raffa/Lictor
nohup python3 scripts/patrol-ai-saas-keys.py --max 800 --max-age-days 730 \
  --private docs/launch/patrol-ai-saas-2026-05-23-AFTER-REBOOT-private.md \
  > /tmp/patrol-ai-saas-resumed.log 2>&1 &
AI_PID=$!
echo "    [OK] patrol-ai-saas-keys: PID $AI_PID"
echo "    Log: /tmp/patrol-ai-saas-resumed.log"
echo ""

# ─── Re-launch tranco-after-chaos wrapper ───
# Update the wrapper to monitor the new chaos PID instead of the old one
if [ -n "${CHAOS_PID:-}" ]; then
  cat > /tmp/tranco-after-chaos-resumed.sh <<EOF
#!/bin/bash
echo "[\$(date)] [Tranco-resume] Waiting for chaos dnsx (PID $CHAOS_PID) to finish..."
while ps -p $CHAOS_PID > /dev/null 2>&1; do
  sleep 60
done
echo "[\$(date)] [Tranco-resume] Chaos done. Launching Tranco top-100K..."

OUT_DIR=/Users/raffa/.lictor/tranco-pipeline-\$(date +%Y-%m-%d)
mkdir -p "\$OUT_DIR"
head -100000 /Users/raffa/.lictor/tranco-top1m.csv | awk -F, '{print \$2}' > "\$OUT_DIR/tranco-top100k.txt"

dnsx -l "\$OUT_DIR/tranco-top100k.txt" -cname -resp -silent \
     -t 200 -rl 5000 -retry 1 -o "\$OUT_DIR/cname-results.txt"

PLATFORMS_REGEX="vercel-dns\.com|herokudns\.com|herokuapp\.com|netlify\.app|netlify\.com|github\.io|s3\.amazonaws\.com|cloudfront\.net|azureedge\.net|fastly\.net|wpengine\.com|surge\.sh|bitbucket\.io|readthedocs\.io|ghost\.io|webflow\.io|statuspage\.io|unbouncepages\.com|gitlab\.io"
grep -iE "\$PLATFORMS_REGEX" "\$OUT_DIR/cname-results.txt" > "\$OUT_DIR/cname-candidates.txt"
awk '{print \$1}' "\$OUT_DIR/cname-candidates.txt" | sort -u > "\$OUT_DIR/candidate-hosts.txt"

nuclei -l "\$OUT_DIR/candidate-hosts.txt" -tags takeover \
       -severity medium,high,critical -silent \
       -j -o "\$OUT_DIR/takeover-findings.jsonl"
echo "[\$(date)] [Tranco-resume] Done."
EOF
  chmod +x /tmp/tranco-after-chaos-resumed.sh
  nohup /tmp/tranco-after-chaos-resumed.sh > /tmp/tranco-after-chaos-resumed.log 2>&1 &
  TRANCO_PID=$!
  echo "[+] Tranco-after-chaos wrapper: PID $TRANCO_PID (waits for chaos)"
fi
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo " Resume complete. Active PIDs:"
echo "═══════════════════════════════════════════════════════════════"
echo "  chaos dnsx (resume):     ${CHAOS_PID:-not launched}"
echo "  admin-panels (resume):   ${ADMIN_PID:-not launched}"
echo "  patrol-ai-saas-keys:     $AI_PID"
echo "  tranco-after-chaos:      ${TRANCO_PID:-not launched}"
echo ""
echo "Monitor with: ps -p $CHAOS_PID,${ADMIN_PID:-1},$AI_PID,${TRANCO_PID:-1}"
echo "Or ask Claude: 'status?'"
