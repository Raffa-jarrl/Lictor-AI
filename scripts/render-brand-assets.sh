#!/bin/bash
# Lictor brand-asset render pipeline.
#
# Generates every PNG / ICNS / ICO that ships with the product from the
# canonical SVG sources in `brand/`. Re-run any time the SVGs change.
#
# Outputs:
#   brand/icon-{16,32,48,128,256,512,1024}.png         — square mark, transparent
#   brand/profile-400.png                                — Twitter / LinkedIn avatar
#   brand/linkedin-banner.png                            — 1192×220 LinkedIn cover
#   landing/og/og-image.png                              — 1200×630 social card
#   landing/lictor-mark.svg, lictor-favicon.svg          — copied to web roots
#   studio/src-tauri/icons/*.png, *.icns, *.ico          — Tauri app icons
#   shield/icons/icon-{16,32,48,128}.png                 — Chrome extension icons
#
# Requirements: rsvg-convert (Homebrew: `brew install librsvg`),
#               iconutil (built-in on macOS), sips (built-in on macOS).
#
# Usage:
#   bash scripts/render-brand-assets.sh                  # render everything
#   bash scripts/render-brand-assets.sh --check          # verify all outputs exist
#   bash scripts/render-brand-assets.sh --clean          # remove generated files

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRAND="$REPO/brand"
MARK="$BRAND/lictor-mark.svg"
LOCKUP="$BRAND/lictor-lockup.svg"

# Sanity check — required tools
for tool in rsvg-convert iconutil sips; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "✗ Missing required tool: $tool"
    echo "  Install: brew install librsvg (rsvg-convert); iconutil + sips are built-in"
    exit 1
  fi
done

# Sanity check — source SVGs exist
for svg in "$MARK" "$LOCKUP"; do
  if [ ! -f "$svg" ]; then
    echo "✗ Missing source SVG: $svg"
    exit 1
  fi
done

ACTION="${1:-render}"

# ─── Helpers ──────────────────────────────────────────────────────────────

render_square() {
  local size="$1" out="$2"
  rsvg-convert -w "$size" -h "$size" "$MARK" -o "$out"
  printf "  %-50s %4sx%-4s\n" "${out#$REPO/}" "$size" "$size"
}

render_at() {
  local w="$1" h="$2" out="$3" src="${4:-$LOCKUP}"
  rsvg-convert -w "$w" -h "$h" "$src" -o "$out"
  printf "  %-50s %4sx%-4s\n" "${out#$REPO/}" "$w" "$h"
}

list_outputs() {
  echo "brand/icon-16.png"
  echo "brand/icon-32.png"
  echo "brand/icon-48.png"
  echo "brand/icon-128.png"
  echo "brand/icon-256.png"
  echo "brand/icon-512.png"
  echo "brand/icon-1024.png"
  echo "brand/profile-400.png"
  echo "brand/linkedin-banner.png"
  echo "landing/og/og-image.png"
  echo "landing/lictor-mark.svg"
  echo "landing/lictor-favicon.svg"
  echo "studio/src-tauri/icons/32x32.png"
  echo "studio/src-tauri/icons/128x128.png"
  echo "studio/src-tauri/icons/128x128@2x.png"
  echo "studio/src-tauri/icons/icon.icns"
  echo "studio/src-tauri/icons/icon.ico"
}

# ─── --check ──────────────────────────────────────────────────────────────

if [ "$ACTION" = "--check" ]; then
  MISSING=()
  while IFS= read -r f; do
    if [ ! -f "$REPO/$f" ]; then MISSING+=("$f"); fi
  done < <(list_outputs)
  if [ ${#MISSING[@]} -eq 0 ]; then
    echo "✓ All brand assets present ($(list_outputs | wc -l | tr -d ' ') files)"
    exit 0
  else
    echo "✗ Missing ${#MISSING[@]} files:"
    for f in "${MISSING[@]}"; do echo "    $f"; done
    exit 1
  fi
fi

# ─── --clean ──────────────────────────────────────────────────────────────

if [ "$ACTION" = "--clean" ]; then
  echo "Removing generated brand assets…"
  while IFS= read -r f; do
    if [ -f "$REPO/$f" ]; then rm "$REPO/$f"; echo "  removed $f"; fi
  done < <(list_outputs)
  exit 0
fi

# ─── render ───────────────────────────────────────────────────────────────

echo "Rendering brand assets from $MARK + $LOCKUP"
echo

# Mark — square icons (transparent background)
echo "Square mark icons:"
for size in 16 32 48 128 256 512 1024; do
  render_square "$size" "$BRAND/icon-${size}.png"
done

# Avatar — square 400×400 for Twitter / LinkedIn / GitHub profile
echo
echo "Profile avatars:"
render_square 400 "$BRAND/profile-400.png"

# LinkedIn cover banner — 1192×220
echo
echo "LinkedIn banner:"
render_at 1192 220 "$BRAND/linkedin-banner.png" "$LOCKUP"

# Social OG card — 1200×630
mkdir -p "$REPO/landing/og"
echo
echo "Social OG card:"
render_at 1200 630 "$REPO/landing/og/og-image.png" "$LOCKUP"

# Web-root copies (favicon + mark)
echo
echo "Web-root SVG copies:"
cp "$MARK" "$REPO/landing/lictor-mark.svg"
echo "  landing/lictor-mark.svg"
cp "$BRAND/lictor-favicon.svg" "$REPO/landing/lictor-favicon.svg"
echo "  landing/lictor-favicon.svg"

# Studio Tauri icons
mkdir -p "$REPO/studio/src-tauri/icons"
echo
echo "Studio (Tauri) icons:"
cp "$BRAND/icon-32.png" "$REPO/studio/src-tauri/icons/32x32.png"
echo "  studio/src-tauri/icons/32x32.png  (copied from icon-32.png)"
cp "$BRAND/icon-128.png" "$REPO/studio/src-tauri/icons/128x128.png"
echo "  studio/src-tauri/icons/128x128.png  (copied from icon-128.png)"
cp "$BRAND/icon-256.png" "$REPO/studio/src-tauri/icons/128x128@2x.png"
echo "  studio/src-tauri/icons/128x128@2x.png  (copied from icon-256.png)"

# macOS .icns — build an iconset then convert
ICONSET="$(mktemp -d)/lictor.iconset"
mkdir -p "$ICONSET"
for sz in 16 32 64 128 256 512 1024; do
  if [ -f "$BRAND/icon-${sz}.png" ]; then
    cp "$BRAND/icon-${sz}.png" "$ICONSET/icon_${sz}x${sz}.png"
  else
    rsvg-convert -w "$sz" -h "$sz" "$MARK" -o "$ICONSET/icon_${sz}x${sz}.png"
  fi
done
iconutil -c icns "$ICONSET" -o "$REPO/studio/src-tauri/icons/icon.icns"
echo "  studio/src-tauri/icons/icon.icns  (built from iconset)"

# Windows .ico (macOS doesn't natively build proper multi-res .ico — placeholder
# uses the 256 PNG renamed. Replace with a real .ico (e.g. via ImageMagick
# `convert` or an online tool) before shipping Windows builds in v0.2.)
cp "$BRAND/icon-256.png" "$REPO/studio/src-tauri/icons/icon.ico"
echo "  studio/src-tauri/icons/icon.ico   (placeholder — replace before Windows ship)"

# Shield Chrome extension icons (Manifest V3 expects 16, 32, 48, 128)
if [ -d "$REPO/shield" ]; then
  mkdir -p "$REPO/shield/icons"
  echo
  echo "Shield (Chrome extension) icons:"
  for sz in 16 32 48 128; do
    cp "$BRAND/icon-${sz}.png" "$REPO/shield/icons/icon-${sz}.png"
    echo "  shield/icons/icon-${sz}.png"
  done
else
  echo
  echo "  (skipping shield/icons — shield/ directory not present)"
fi

echo
echo "✓ Done. Run 'bash scripts/render-brand-assets.sh --check' to verify."
