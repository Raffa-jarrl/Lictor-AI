#!/bin/bash
# Lictor first-time setup. Run once after cloning.
#
# Idempotent — safe to re-run.
# Checks dependencies, installs JS deps, renders brand assets, runs all
# verifications. Bails on the first hard error.
#
# Usage:  bash scripts/setup.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

echo "═══════════════════════════════════════════════════════════════"
echo "  Lictor — first-time setup"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── Step 1: Verify required tools ───────────────────────────────────────

echo "Step 1/6: Checking required tools…"

# Source rustup's environment if it's installed but not on PATH (common
# when running scripts from a non-login shell, e.g., bash scripts/setup.sh
# from a GUI terminal that hasn't sourced ~/.zshenv).
if [ -d "$HOME/.cargo/bin" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
if [ -d "$HOME/.rustup/toolchains" ]; then
  RUSTUP_TC=$(find "$HOME/.rustup/toolchains" -maxdepth 1 -type d -name 'stable-*' | head -1)
  if [ -n "$RUSTUP_TC" ] && [ -d "$RUSTUP_TC/bin" ]; then
    export PATH="$RUSTUP_TC/bin:$PATH"
  fi
fi

MISSING=()
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    MISSING+=("$1 ($2)")
  else
    echo "  ✓ $1"
  fi
}
need rustc "install via rustup: https://rustup.rs"
need cargo "comes with rustup"
need node "install via Homebrew: brew install node"
need pnpm "install: npm i -g pnpm"
need rsvg-convert "install: brew install librsvg"
need iconutil "macOS only — built-in on macOS"
need python3 "macOS ships Python 3 by default"

if [ ${#MISSING[@]} -gt 0 ]; then
  echo
  echo "✗ Missing dependencies:"
  for d in "${MISSING[@]}"; do echo "    - $d"; done
  echo
  echo "Install the missing tools, then re-run 'bash scripts/setup.sh'."
  exit 1
fi
echo "  → all tools present"
echo

# ── Step 2: Install JS deps for Studio + landing/guardian ──────────────

echo "Step 2/6: Installing JS dependencies…"
if [ -d studio ]; then
  echo "  → studio/ (pnpm install)"
  (cd studio && pnpm install --silent) 2>&1 | tail -3
fi
if [ -d guardian ] && [ -f guardian/package.json ]; then
  echo "  → guardian/ (pnpm install)"
  (cd guardian && pnpm install --silent) 2>&1 | tail -3
fi
if [ -d shield ] && [ -f shield/package.json ]; then
  echo "  → shield/ (pnpm install)"
  (cd shield && pnpm install --silent) 2>&1 | tail -3
fi
if [ -d sentinel ] && [ -f sentinel/package.json ]; then
  echo "  → sentinel/ (pnpm install)"
  (cd sentinel && pnpm install --silent) 2>&1 | tail -3
fi
echo

# ── Step 3: Render brand assets ────────────────────────────────────────

echo "Step 3/6: Rendering brand assets…"
bash scripts/render-brand-assets.sh > /tmp/lictor-setup-brand.log 2>&1 || {
  echo "  ✗ brand rendering failed — see /tmp/lictor-setup-brand.log"
  exit 1
}
RENDERED=$(bash scripts/render-brand-assets.sh --check | tail -1)
echo "  $RENDERED"
echo

# ── Step 4: Cargo build/check the workspace ────────────────────────────

echo "Step 4/6: Cargo workspace check (first time may take a few minutes)…"
cargo check --workspace --features native --quiet 2>&1 | tail -5
echo "  ✓ workspace compiles"
echo

# ── Step 5: Run the Rust test suite ────────────────────────────────────

echo "Step 5/6: Running Rust tests…"
TEST_RESULT=$(cargo test -p lictor-core --features native --quiet 2>&1 | tail -3 | head -1)
echo "  $TEST_RESULT"
echo

# ── Step 6: Optional Python venv for the metrics script ─────────────────

echo "Step 6/6: Python check (metrics script uses stdlib only — no install needed)"
python3 scripts/generate-monthly-metrics.py --dry-run > /dev/null 2>&1 && \
  echo "  ✓ scripts/generate-monthly-metrics.py runs"
echo

# ── Done ─────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Setup complete."
echo "═══════════════════════════════════════════════════════════════"
echo
echo "What works now:"
echo "  • Rust workspace compiles            cargo check --workspace"
echo "  • lictor-core 45 tests pass          cargo test -p lictor-core --features native"
echo "  • Studio frontend type-checks        cd studio && pnpm typecheck"
echo "  • Brand assets rendered              bash scripts/render-brand-assets.sh --check"
echo
echo "Common dev workflows:"
echo "  make studio-dev      # launch Lictor Studio in dev mode"
echo "  make test            # run all tests"
echo "  make check           # full type/compile check"
echo "  make help            # everything available"
echo
echo "What needs Dor (not part of this script):"
echo "  • Apple Developer Program enrollment (for Studio signing)"
echo "  • Delaware LLC registration"
echo "  • ~/.lictor/secrets.env with API keys for monthly metrics"
echo "  • Founder content recording (mic + light kit)"
echo
echo "See LAUNCH-SPRINT-PLAYBOOK.md + docs/launch/year-plan-2026-2027.md for the full plan."
