# Lictor — Brand Assets

Logo source files + pre-rendered raster exports.

## Files

| File | Use |
|---|---|
| `lictor-mark.svg` | Primary mark — Praetorian helmet with circuit-detail crest, full color |
| `lictor-mark-mono.svg` | Monochrome version (uses `currentColor`) — for embroidery, single-color print, dark backgrounds |
| `lictor-fasces.svg` | Secondary mark — bound rods + axe head. Use as alt favicon, separator/ornament |
| `lictor-favicon.svg` | Simplified mark, optimized for 16-32 px renders (no fine circuit detail) |
| `lictor-lockup.svg` | Mark + "Lictor AI" wordmark + tagline, horizontal lockup |
| `icon-{16,32,48,128,256,512}.png` | Pre-rendered PNG exports of the mark, used by Shield's manifest |
| `lictor-fasces.png` | PNG export of the fasces mark |
| `lictor-lockup.png` | PNG export of the lockup |
| `lictor-mark-mono.png` | PNG export of the mono mark |

## Re-render after editing

If you change any SVG, regenerate the PNGs:

```bash
brew install librsvg   # one-time

cd brand
rsvg-convert -w 16  -h 16  lictor-favicon.svg -o icon-16.png
rsvg-convert -w 32  -h 32  lictor-favicon.svg -o icon-32.png
rsvg-convert -w 48  -h 48  lictor-mark.svg    -o icon-48.png
rsvg-convert -w 128 -h 128 lictor-mark.svg    -o icon-128.png
rsvg-convert -w 256 -h 256 lictor-mark.svg    -o icon-256.png
rsvg-convert -w 512 -h 512 lictor-mark.svg    -o icon-512.png
rsvg-convert -w 1440       lictor-lockup.svg  -o lictor-lockup.png
rsvg-convert -w 256 -h 512 lictor-fasces.svg  -o lictor-fasces.png
rsvg-convert -w 256 -h 256 lictor-mark-mono.svg -o lictor-mark-mono.png
```

After regenerating, run `cd ../shield && pnpm build` to copy the new PNGs into the extension dist/.

## Color

Always pulled from the same palette. Don't sample from the rasters — use these:

| Role | Hex | Usage |
|---|---|---|
| Imperial Purple | `#3D2C5E` | Helmet body, primary brand surface |
| Gold Leaf       | `#C9A23B` | Crest, fasces cords, accents, "AI" wordmark |
| Charcoal        | `#0F1419` | Visor cutout, dark backgrounds, circuit traces |
| Bone            | `#F5F1E8` | Solder pads, light backgrounds |

## What this is NOT

These are first-pass marks generated programmatically. They're production-grade **structurally** (the SVG paths are clean, all colors come from the palette, all sizes render correctly), but they haven't had a designer's pass. Before a real Web Store submission or marketing launch, send the SVGs to a designer for a proper iteration. Tell them:

- Keep the Praetorian helmet metaphor
- Keep the imperial-purple + gold-leaf palette
- Improve the helmet silhouette (the curve from the skull to the cheek pieces wants more shape)
- Keep the circuit detail in the crest — it's the AI signature
- The mark MUST work at 16×16 — the favicon variant is a separate file for that reason

## License

Same as the rest of the repo: MIT for source, see `../LICENSE`.
