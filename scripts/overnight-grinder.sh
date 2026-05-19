#!/bin/bash
# overnight-grinder — runs the full bounty hunter fleet every 30 min through the night.
# Cron'd at */30 * * * *
# Each scanner is idempotent via its ledger — won't reprocess.

LOG=~/.lictor/overnight.log
mkdir -p ~/.lictor

ts() { date -u +"%Y-%m-%d %H:%M:%S UTC"; }

echo "" >> $LOG
echo "================================================================" >> $LOG
echo "[$(ts)] Overnight grinder tick" >> $LOG

# 1. Subdomain takeover scan (the highest-EV one)
echo "[$(ts)] Starting subdomain-takeover scan..." >> $LOG
python3 -u /Users/raffa/Lictor/scripts/patrol-subdomain-takeover.py \
  --max-domains 250 --max-subs-per-domain 200 \
  >> ~/.lictor/takeover.log 2>&1
echo "[$(ts)] Takeover scan done" >> $LOG

# 2. Web-exposed-files scan
echo "[$(ts)] Starting web-exposed-files scan..." >> $LOG
python3 -u /Users/raffa/Lictor/scripts/patrol-web-exposed-files.py \
  --max-targets 60 \
  >> ~/.lictor/web-exposed.log 2>&1
echo "[$(ts)] Web-exposed scan done" >> $LOG

# 3. HF leak scan (lightweight, just newest 50)
echo "[$(ts)] Starting HF leak scan..." >> $LOG
python3 -u /Users/raffa/Lictor/scripts/patrol-huggingface-leaks.py \
  --spaces 50 \
  >> ~/.lictor/hf-leaks.log 2>&1
echo "[$(ts)] HF leak scan done" >> $LOG

# 4. Summary tick
TAKEOVER_COUNT=$(wc -l < ~/.lictor/subdomain-takeover-ledger.jsonl 2>/dev/null || echo 0)
WEB_COUNT=$(wc -l < ~/.lictor/web-exposed-ledger.jsonl 2>/dev/null || echo 0)
HF_COUNT=$(wc -l < ~/.lictor/hf-leak-ledger.jsonl 2>/dev/null || echo 0)
echo "[$(ts)] Tick complete. Ledger totals: takeover=$TAKEOVER_COUNT web=$WEB_COUNT hf=$HF_COUNT" >> $LOG
