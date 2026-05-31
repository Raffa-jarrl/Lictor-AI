#!/usr/bin/env bash
# package-all.sh — build every shippable Lictor component into downloadable artifacts.
#
# Output: dist/release/  (gitignored)
#   lictor-<os>-<arch>(.tar.gz)          native CLI binary
#   lictor-shield-<ver>.zip              Chrome extension (load-unpacked / store zip)
#   lictor-<ver>.vsix                    VS Code extension
#   lictor-sentinel-<ver>.tgz            npm SDK tarball
#   lictor_sentinel-<ver>-*.whl + .tar.gz  Python SDK
#   lictor-airlock-<ver>.tgz             AI action-broker npm tarball
#   lictor-skills-<ver>.tar.gz           Claude Code skill suite
#
# Each step is best-effort: a failure is logged and the script continues, then a
# summary prints what built and what didn't. Nothing here PUBLISHES — it only
# produces local artifacts. Publishing to npm/PyPI/crates is a separate, gated
# step (see .github/workflows/release.yml) that needs registry tokens.
#
# Usage:  bash scripts/package-all.sh [--only cli,shield,vscode,sentinel,sentinel-py,airlock,skills]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/release"
mkdir -p "$OUT"

# pnpm if present, else npm (this repo's lockfiles are pnpm, but npm works for the
# per-package build/pack scripts, which are plain tsc/esbuild/node).
if command -v pnpm >/dev/null 2>&1; then PM=pnpm; else PM=npm; fi

ONLY=""
[[ "${1:-}" == "--only" ]] && ONLY="${2:-}"
want() { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }

declare -a OK=() FAIL=() SKIP=()
log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
good() { printf '  \033[32m✓ %s\033[0m\n' "$*"; OK+=("$1"); }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$*"; FAIL+=("$1"); }
skip() { printf '  \033[33m— %s (skipped: %s)\033[0m\n' "$1" "$2"; SKIP+=("$1"); }

run_pkg() { # run a package's npm/pnpm script: run_pkg <dir> <script>
  ( cd "$ROOT/$1" && "$PM" run "$2" ) ;
}

# ── CLI (Rust native binary) ───────────────────────────────────────────────
# Resolve cargo even when ~/.cargo/bin isn't on PATH (e.g. Homebrew rustup).
CARGO="$(command -v cargo || true)"
[[ -z "$CARGO" && -x "$HOME/.cargo/bin/cargo" ]] && CARGO="$HOME/.cargo/bin/cargo"
[[ -z "$CARGO" ]] && command -v rustup >/dev/null 2>&1 && CARGO="$(rustup which cargo 2>/dev/null || true)"
if want cli; then
  log "CLI — lictor (Rust)"
  if [[ -n "$CARGO" ]]; then
    if "$CARGO" build --release -p lictor-cli; then
      OS="$(uname -s | tr '[:upper:]' '[:lower:]')"; ARCH="$(uname -m)"
      BIN="$ROOT/target/release/lictor"
      if [[ -f "$BIN" ]]; then
        DEST="lictor-${OS}-${ARCH}"
        cp "$BIN" "$OUT/$DEST"
        ( cd "$OUT" && tar -czf "${DEST}.tar.gz" "$DEST" && rm -f "$DEST" )
        good "cli → ${DEST}.tar.gz"
      else
        bad "cli (binary not found at target/release/lictor)"
      fi
    else
      bad "cli (cargo build failed)"
    fi
  else
    skip "cli" "cargo not installed"
  fi
fi

# ── Shield (Chrome extension zip) ──────────────────────────────────────────
if want shield; then
  log "Shield — Chrome extension"
  if [[ -d "$ROOT/shield/wasm" ]] || [[ -f "$ROOT/shield/dist/wasm/lictor_core_bg.wasm" ]]; then
    if run_pkg shield package; then
      cp "$ROOT"/shield/lictor-shield-*.zip "$OUT"/ 2>/dev/null && good "shield → $(basename "$(ls -t "$ROOT"/shield/lictor-shield-*.zip | head -1)")" || bad "shield (zip not produced)"
    else
      bad "shield (package script failed)"
    fi
  else
    skip "shield" "WASM missing — run 'pnpm wasm' first (needs Rust + wasm-pack)"
  fi
fi

# ── VS Code extension (.vsix) ──────────────────────────────────────────────
if want vscode; then
  log "VS Code extension — .vsix"
  if [[ -f "$ROOT/vscode-extension/icon.png" ]]; then
    if run_pkg vscode-extension package; then
      cp "$ROOT"/vscode-extension/lictor-*.vsix "$OUT"/ 2>/dev/null && good "vscode → $(basename "$(ls -t "$ROOT"/vscode-extension/lictor-*.vsix | head -1)")" || bad "vscode (.vsix not produced)"
    else
      bad "vscode (package script failed)"
    fi
  else
    skip "vscode" "icon.png missing"
  fi
fi

# ── Sentinel (npm SDK tarball) ─────────────────────────────────────────────
if want sentinel; then
  log "Sentinel — npm SDK"
  if run_pkg sentinel build; then
    ( cd "$ROOT/sentinel" && "$PM" pack --pack-destination "$OUT" >/dev/null 2>&1 ) \
      && good "sentinel → $(basename "$(ls -t "$OUT"/lictor-sentinel-*.tgz | head -1)")" \
      || bad "sentinel (pack failed)"
  else
    bad "sentinel (build failed)"
  fi
fi

# ── Sentinel (Python SDK wheel + sdist) ────────────────────────────────────
if want sentinel-py; then
  log "Sentinel — Python SDK"
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import build' >/dev/null 2>&1; then
    ( cd "$ROOT/sentinel-py" && python3 -m build -o "$OUT" >/dev/null 2>&1 ) \
      && good "sentinel-py → $(basename "$(ls -t "$OUT"/lictor_sentinel-*.whl | head -1)")" \
      || bad "sentinel-py (build failed)"
  else
    skip "sentinel-py" "python3 -m build unavailable (pip install build)"
  fi
fi

# ── Airlock (npm action-broker tarball) ────────────────────────────────────
if want airlock; then
  log "Airlock — AI action broker"
  if [[ -d "$ROOT/airlock/node_modules" ]]; then
    if run_pkg airlock build; then
      ( cd "$ROOT/airlock" && "$PM" pack --pack-destination "$OUT" >/dev/null 2>&1 ) \
        && good "airlock → $(basename "$(ls -t "$OUT"/lictor-airlock-*.tgz | head -1)")" \
        || bad "airlock (pack failed)"
    else
      bad "airlock (build failed)"
    fi
  else
    skip "airlock" "deps missing — run 'npm --prefix airlock install' first"
  fi
fi

# ── Skills (Claude Code suite tarball) ─────────────────────────────────────
if want skills; then
  log "Skills — Claude Code suite"
  SVER="$(node -e "process.stdout.write(require('$ROOT/skills/plugin.json').version||'0.1.0')" 2>/dev/null || echo 0.1.0)"
  if ( cd "$ROOT/skills" && tar -czf "$OUT/lictor-skills-${SVER}.tar.gz" lictor-* plugin.json install.sh 2>/dev/null ); then
    good "skills → lictor-skills-${SVER}.tar.gz"
  else
    bad "skills (tar failed)"
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════"
echo "Artifacts in: $OUT"
ls -1sh "$OUT" 2>/dev/null | sed 's/^/  /'
echo "────────────────────────────────────────────"
printf 'built: %s   failed: %s   skipped: %s\n' "${#OK[@]}" "${#FAIL[@]}" "${#SKIP[@]}"
[[ ${#FAIL[@]} -gt 0 ]] && { printf 'failed → %s\n' "${FAIL[*]}"; exit 1; }
exit 0
