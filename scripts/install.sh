#!/usr/bin/env bash
# install.sh — install the `lictor` CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/Raffa-jarrl/Lictor-AI/main/scripts/install.sh | bash
#
# Strategy (in order):
#   1. Download a prebuilt binary for your OS/arch from the latest GitHub Release.
#   2. If no matching release asset exists yet, fall back to `cargo install` from
#      source (requires the Rust toolchain).
#   3. If neither works, print exact manual instructions.
#
# Installs to ${LICTOR_BIN_DIR:-$HOME/.local/bin}. Add that to your PATH if needed.
set -euo pipefail

REPO="Raffa-jarrl/Lictor-AI"
BIN_DIR="${LICTOR_BIN_DIR:-$HOME/.local/bin}"
TARGET="lictor"

say()  { printf '\033[1;36m▶\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64|aarch64) ARCH="aarch64" ;;
  x86_64|amd64)  ARCH="x86_64" ;;
esac
ASSET="lictor-${OS}-${ARCH}.tar.gz"

mkdir -p "$BIN_DIR"

install_from_release() {
  command -v curl >/dev/null 2>&1 || return 1
  say "Looking for a prebuilt binary ($ASSET) in the latest release…"
  local api url tmp
  api="https://api.github.com/repos/${REPO}/releases/latest"
  url="$(curl -fsSL "$api" 2>/dev/null \
    | grep -o "https://[^\"]*${ASSET}" | head -1 || true)"
  [[ -n "$url" ]] || { warn "No release asset named $ASSET yet."; return 1; }
  tmp="$(mktemp -d)"
  say "Downloading $url"
  curl -fsSL "$url" -o "$tmp/$ASSET" || { rm -rf "$tmp"; return 1; }
  tar -xzf "$tmp/$ASSET" -C "$tmp"
  install -m 0755 "$tmp/lictor-${OS}-${ARCH}" "$BIN_DIR/$TARGET" 2>/dev/null \
    || install -m 0755 "$tmp/$TARGET" "$BIN_DIR/$TARGET"
  rm -rf "$tmp"
  ok "Installed prebuilt binary → $BIN_DIR/$TARGET"
}

install_from_source() {
  command -v cargo >/dev/null 2>&1 || return 1
  say "No prebuilt binary — building from source with cargo…"
  if [[ -f "$(dirname "${BASH_SOURCE[0]}")/../Cargo.toml" ]]; then
    # Running from inside a clone.
    ( cd "$(dirname "${BASH_SOURCE[0]}")/.." && cargo install --path cli --root "${BIN_DIR%/bin}" --force )
  else
    # Piped install: clone shallow, then build.
    local tmp; tmp="$(mktemp -d)"
    git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/lictor" >/dev/null 2>&1 \
      || { rm -rf "$tmp"; return 1; }
    ( cd "$tmp/lictor" && cargo install --path cli --root "${BIN_DIR%/bin}" --force )
    rm -rf "$tmp"
  fi
  ok "Built and installed → $BIN_DIR/$TARGET"
}

if install_from_release || install_from_source; then
  echo
  ok "lictor installed."
  case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) warn "Add $BIN_DIR to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
  esac
  "$BIN_DIR/$TARGET" --version 2>/dev/null || true
  echo "Try:  lictor audit . --format human"
else
  cat >&2 <<EOF

Could not install automatically. Manual options:

  # From a clone (needs Rust — https://rustup.rs):
  git clone https://github.com/${REPO}.git && cd Lictor-AI
  cargo build --release -p lictor-cli
  cp target/release/lictor ${BIN_DIR}/

  # Or wait for the next tagged release, which ships prebuilt binaries.
EOF
  exit 1
fi
