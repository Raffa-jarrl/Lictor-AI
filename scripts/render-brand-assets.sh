#!/bin/bash
# Lictor brand-asset render pipeline.
#
# Canonical source of the mark is the amber Spartan-helmet badge:
#   brand/lictor-badge-master.png        (high-res, transparent)
# Text lockups are rendered separately (real Cormorant via Playwright) and live
# pre-rendered in brand/; this script consumes them:
#   brand/lictor-wordmark-horizontal.png   brand/lictor-og-card.png
#   brand/linkedin-banner.png              brand/lictor-wordmark-stacked.png
#   (regenerate those with scripts/render-lockups.py if the wordmark changes)
#
# Generates every PNG / ICO / ICNS / mark-SVG that ships across the suite —
# brand icons, social avatar, Studio (Tauri) icons, Shield (Chrome) icons,
# VS Code icon, and all landing favicons/marks — from that one badge.
#
# Usage:
#   bash scripts/render-brand-assets.sh            # render everything
#   bash scripts/render-brand-assets.sh --check    # verify all outputs exist
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRAND="$REPO/brand"
MASTER="$BRAND/lictor-badge-master.png"

for tool in python3 iconutil; do
  command -v "$tool" >/dev/null 2>&1 || { echo "✗ Missing required tool: $tool"; exit 1; }
done
[ -f "$MASTER" ] || { echo "✗ Missing canonical badge: $MASTER"; exit 1; }

list_outputs() {
  for s in 16 32 48 128 256 512 1024; do echo "brand/icon-${s}.png"; done
  echo brand/profile-400.png; echo brand/lictor-mark-mono.png; echo brand/lictor-mark-mono.svg
  echo brand/lictor-mark.svg; echo brand/lictor-favicon.svg; echo brand/lictor-lockup.svg
  echo studio/src-tauri/icons/32x32.png; echo studio/src-tauri/icons/128x128.png
  echo studio/src-tauri/icons/128x128@2x.png; echo studio/src-tauri/icons/icon.ico
  echo studio/src-tauri/icons/icon.icns
  for s in 16 32 48 128; do echo "shield/icons/icon-${s}.png"; echo "shield/dist/assets/icon-${s}.png"; done
  echo shield/dist/popup/mark.svg; echo vscode-extension/icon.png
  echo landing/static/lictor-mark.png; echo landing/lictor-mark-512.png
  echo landing/apple-touch-icon.png; echo landing/favicon-16.png; echo landing/favicon-32.png
  echo landing/favicon.ico; echo landing/lictor-mark.svg; echo landing/lictor-favicon.svg
  echo landing/static/lictor-logo.png; echo landing/og-image.png; echo landing/og/og-image.png
}

if [ "${1:-render}" = "--check" ]; then
  miss=0; while IFS= read -r f; do [ -f "$REPO/$f" ] || { echo "  ✗ $f"; miss=$((miss+1)); }; done < <(list_outputs)
  [ "$miss" -eq 0 ] && echo "✓ All brand assets present ($(list_outputs | wc -l | tr -d ' ') files)" || echo "✗ $miss missing"
  exit $([ "$miss" -eq 0 ] && echo 0 || echo 1)
fi

# Raster regeneration needs Pillow. If it's missing (e.g. a CI runner that only has
# rsvg/sips), the brand assets are already committed and correct — try to install
# Pillow, and if that isn't possible, skip regeneration rather than fail the build.
if ! python3 -c "import PIL" >/dev/null 2>&1; then
  python3 -m pip install --quiet Pillow >/dev/null 2>&1 \
    || python3 -m pip install --quiet --user Pillow >/dev/null 2>&1 \
    || python3 -m pip install --quiet --break-system-packages Pillow >/dev/null 2>&1 || true
fi
if ! python3 -c "import PIL" >/dev/null 2>&1; then
  echo "  Pillow unavailable — using the committed brand assets (skipping regeneration)."
  exit 0
fi

ICONSET="$(mktemp -d)/lictor.iconset"; mkdir -p "$ICONSET"
echo "Rendering brand assets from $MASTER …"
REPO="$REPO" MASTER="$MASTER" ICONSET="$ICONSET" python3 - <<'PY'
import os, base64, shutil
from PIL import Image, ImageChops
REPO=os.environ["REPO"]; BRAND=f"{REPO}/brand"; ICONSET=os.environ["ICONSET"]
badge=Image.open(os.environ["MASTER"]).convert("RGBA")
def P(*p): return os.path.join(REPO,*p)
def trans(size,pad=0.04):
    inner=int(size*(1-2*pad)); c=Image.new("RGBA",(size,size),(0,0,0,0))
    c.alpha_composite(badge.resize((inner,inner),Image.LANCZOS),((size-inner)//2,)*2); return c
def tile(size,pad=0.10):
    inner=int(size*(1-2*pad)); c=Image.new("RGBA",(size,size),(7,8,9,255))
    c.alpha_composite(badge.resize((inner,inner),Image.LANCZOS),((size-inner)//2,)*2); return c
def svg(path,png,vb):
    b=base64.b64encode(open(png,"rb").read()).decode()
    open(path,"w").write('<?xml version="1.0" encoding="UTF-8"?>\n'
      '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
      f'viewBox="0 0 {vb} {vb if vb!=1800 else 540}" width="{vb}" height="{vb if vb!=1800 else 540}" '
      f'role="img" aria-label="Lictor"><image href="data:image/png;base64,{b}" '
      f'xlink:href="data:image/png;base64,{b}" x="0" y="0" width="{vb}" height="{vb if vb!=1800 else 540}"/></svg>\n')
# brand square icons (charcoal) + avatar
for s in [16,32,48,128,256,512,1024]:
    img=tile(s, 0.08 if s>=128 else 0.04); (img.convert("RGB") if s>=512 else img).save(P("brand",f"icon-{s}.png"))
tile(400,0.12).convert("RGB").save(P("brand","profile-400.png"))
# studio Tauri
os.makedirs(P("studio","src-tauri","icons"),exist_ok=True)
tile(32).convert("RGB").save(P("studio","src-tauri","icons","32x32.png"))
tile(128).convert("RGB").save(P("studio","src-tauri","icons","128x128.png"))
tile(256).convert("RGB").save(P("studio","src-tauri","icons","128x128@2x.png"))
tile(256).save(P("studio","src-tauri","icons","icon.ico"),sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])
for nm,sz in [("16x16",16),("16x16@2x",32),("32x32",32),("32x32@2x",64),("128x128",128),
              ("128x128@2x",256),("256x256",256),("256x256@2x",512),("512x512",512),("512x512@2x",1024)]:
    tile(sz).convert("RGB").save(f"{ICONSET}/icon_{nm}.png")
# shield (transparent), source + dist
os.makedirs(P("shield","dist","assets"),exist_ok=True)
for s in [16,32,48,128]:
    img=trans(s,0.06 if s>=48 else 0.02); img.save(P("shield","icons",f"icon-{s}.png")); img.save(P("shield","dist","assets",f"icon-{s}.png"))
# vscode
tile(256).convert("RGB").save(P("vscode-extension","icon.png"))
# landing rasters
trans(512).save(P("landing","static","lictor-mark.png")); trans(512).save(P("landing","lictor-mark-512.png"))
ats=Image.new("RGBA",(180,180),(7,8,9,255)); ats.alpha_composite(trans(176,0.0),(2,2)); ats.convert("RGB").save(P("landing","apple-touch-icon.png"))
trans(32).save(P("landing","favicon-32.png")); trans(16).save(P("landing","favicon-16.png"))
trans(64).save(P("landing","favicon.ico"),sizes=[(16,16),(32,32),(48,48)])
# mark SVGs (256 embed) + slim favicon svg (96) + lockup svg (horizontal) + mono
trans(256).save("/tmp/_b256.png"); trans(96).save("/tmp/_b96.png")
for p in ["landing/lictor-mark.svg","brand/lictor-mark.svg","shield/dist/popup/mark.svg"]: svg(P(p),"/tmp/_b256.png",256)
for p in ["landing/lictor-favicon.svg","brand/lictor-favicon.svg"]: svg(P(p),"/tmp/_b96.png",96)
# mono: single-color amber engraving (alpha = luminance, gated to badge)
g=badge.convert("L"); a=badge.getchannel("A").point(lambda v:255 if v>8 else 0)
mono=Image.new("RGBA",badge.size,(232,163,61,0)); mono.putalpha(ImageChops.multiply(g,a)); mono.save(P("brand","lictor-mark-mono.png"))
mono.resize((256,256),Image.LANCZOS).save("/tmp/_mono256.png"); svg(P("brand","lictor-mark-mono.svg"),"/tmp/_mono256.png",256)
# lockups (pre-rendered by Playwright) — copy into web roots
shutil.copy(P("brand","lictor-wordmark-horizontal.png"),P("landing","static","lictor-logo.png"))
shutil.copy(P("brand","lictor-wordmark-horizontal.png"),P("brand","lictor-lockup.png"))
lk=base64.b64encode(open(P("brand","lictor-wordmark-horizontal.png"),"rb").read()).decode()
open(P("brand","lictor-lockup.svg"),"w").write('<?xml version="1.0" encoding="UTF-8"?>\n'
 '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1800 540" '
 f'width="1800" height="540" role="img" aria-label="Lictor AI"><image href="data:image/png;base64,{lk}" '
 f'xlink:href="data:image/png;base64,{lk}" x="0" y="0" width="1800" height="540"/></svg>\n')
os.makedirs(P("landing","og"),exist_ok=True)
shutil.copy(P("brand","lictor-og-card.png"),P("landing","og-image.png"))
shutil.copy(P("brand","lictor-og-card.png"),P("landing","og","og-image.png"))
print("  rasters + SVGs + lockups written")
PY
iconutil -c icns "$ICONSET" -o "$REPO/studio/src-tauri/icons/icon.icns"
echo "  studio/src-tauri/icons/icon.icns"
echo "✓ Done. Verify: bash scripts/render-brand-assets.sh --check"
