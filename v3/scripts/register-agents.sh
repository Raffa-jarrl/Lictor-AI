#!/usr/bin/env bash
#
# register-agents.sh — register all 7 Lictor v3 agents with the OpenClaw gateway.
#
# Run this ONCE after setting up the v3 project. Idempotent — safe to re-run.
#
# Prerequisites:
#   - openclaw CLI installed
#   - openclaw gateway running (openclaw gateway start)
#   - ollama running with mistral:7b, qwen2.5:14b, deepseek-r1:14b pulled
#   - anthropic provider configured (openclaw infer model auth login --provider anthropic)
#
set -euo pipefail

ROOT="$HOME/Lictor/v3"
cd "$ROOT" || { echo "❌ $ROOT not found"; exit 1; }

echo "[+] Registering Lictor v3 agents with OpenClaw gateway..."
echo "    Project root: $ROOT"
echo ""

# Function: register one agent
register_agent() {
  local id="$1"
  local name="$2"
  local model="$3"
  local workspace="$4"
  echo "  → Registering $name ($id) on model=$model workspace=$workspace"
  openclaw agents add \
    --id "$id" \
    --name "$name" \
    --model "$model" \
    --workspace "$workspace" \
    --idempotent 2>&1 | sed 's/^/      /' || echo "      (already registered or registration failed — see above)"
}

# The 7 agents (id, name, model, workspace)
register_agent "lictor-v3-planner"  "Orca"   "ollama/qwen2.5:14b"        "$ROOT/agents/planner"
register_agent "lictor-v3-scout"    "Hawk"   "ollama/mistral:7b"          "$ROOT/agents/scout"
register_agent "lictor-v3-prober"   "Otter"  "ollama/mistral:7b"          "$ROOT/agents/prober"
register_agent "lictor-v3-critic"   "Owl"    "ollama/deepseek-r1:14b"    "$ROOT/agents/critic"
register_agent "lictor-v3-writer"   "Raven"  "ollama/qwen2.5:14b"        "$ROOT/agents/writer"
register_agent "lictor-v3-reviewer" "Lion"   "anthropic/claude-sonnet-4-5" "$ROOT/agents/reviewer"
register_agent "lictor-v3-oracle"   "Oracle" "anthropic/claude-opus-4-1"  "$ROOT/agents/oracle"

echo ""
echo "[+] Verifying registration..."
openclaw agents list | grep "lictor-v3" || echo "  ⚠️  No lictor-v3 agents found — check openclaw config"

echo ""
echo "[+] Registering the Submitter as a background tool..."
openclaw tools add \
  --id "lictor-v3-submitter" \
  --type background-daemon \
  --script "$ROOT/scripts/submitter.py" \
  --idempotent 2>&1 | sed 's/^/    /' || true

echo ""
echo "[+] Done. Next steps:"
echo "    1. Set up Telegram bot:  $ROOT/docs/TELEGRAM-SETUP.md"
echo "    2. Test it:               python3 $ROOT/scripts/telegram-test.py"
echo "    3. Set platform tokens:   $ROOT/docs/SUBMIT-FLOW.md"
echo "    4. Start the Submitter:   python3 $ROOT/scripts/submitter.py --dry-run --once"
echo "    5. Trigger a daily run:   openclaw run lictor-v3-planner"
echo ""
echo "[+] v3 is registered. The cron in openclaw.config.json will fire at 06:00 IST daily."
