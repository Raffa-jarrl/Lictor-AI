<p align="center">
  <a href="https://lictor-ai.com"><img src="https://raw.githubusercontent.com/Raffa-jarrl/Lictor-AI/main/brand/lictor-badge-256.png" alt="Lictor AI" width="120"></a>
</p>

# Lictor Shield

> 🤖 **Part of the [Lictor AI security suite](../README.md)** — Lictor for AI. Shield guards the AI-built **app** in your browser.

> Chrome extension. Audits AI-built sites before you sign up. Alarms when AI accesses your data.

## What it does (target behaviour)

1. **Detects AI-built sites** on first visit (Next.js / Vite / Supabase / OpenAI / Anthropic SDK fingerprints in HTML + JS).
2. **Runs `lictor-core` (WASM)** against the site — same 5 checks as `audit.py`.
3. **Pops a verdict badge** on the toolbar: green (clean) / yellow (warnings) / red (critical findings).
4. **Alarms in real time** when a page tries to read sensitive surfaces (cookies, localStorage, form-field contents) and ship them to an AI endpoint.

## Status

**Phase 1 — done.** The extension builds, loads, and runs the full WASM-backed
audit end to end. MV3, minimum permissions, real PNG icons.

| Piece | Status |
|---|---|
| `manifest.json` | MV3, minimum permissions |
| `src/background.ts` | service worker — runs the WASM audit |
| `src/content.ts` | content script — detects AI-built sites |
| `src/popup/` | toolbar UI — live findings + severity badges |
| WASM bridge to `lictor-core` | wired (bundled in `dist/wasm/`) |
| Chrome Web Store listing | coming at launch (not live yet) |

## Install

### A. Download the zip (no toolchain needed)

1. Download `lictor-shield-<version>.zip` from the latest [GitHub Release](https://github.com/lictorai/lictor/releases).
2. Unzip it — you'll get a folder with `manifest.json` at its root.
3. Open `chrome://extensions`.
4. Toggle **Developer mode** (top-right) on.
5. Click **Load unpacked** and select the unzipped folder.

The Chrome Web Store listing is coming at launch; until then this is the install path.

### B. Build from source

Requires [Rust](https://rustup.rs/) + [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) (for the WASM step) and Node.

```bash
pnpm wasm                        # build lictor-core → shield/wasm/  (needs Rust + wasm-pack)
pnpm --filter @lictor/shield build   # produces shield/dist/
```

Then load `shield/dist/` via `chrome://extensions` → Developer mode → Load unpacked.

To produce the distributable zip yourself:

```bash
pnpm --filter @lictor/shield package  # builds dist/ then writes lictor-shield-<version>.zip
```

> Note: a fresh clone has no `shield/wasm/` (the `*.wasm` blob is gitignored), so
> run `pnpm wasm` once before the first build. `pnpm dev` runs an esbuild watch.

## Permissions philosophy

The store reviewer will scrutinize a security extension. Our defense:

- `<all_urls>` — required so we can audit any site the user visits. Justified to the reviewer in the description: "perform local security audits in WASM; no remote data collection."
- No `tabs.executeScript` — we use declarative content scripts only.
- No `storage` of user URLs by default — opt-in only, telemetry off by default.
- No `webRequest` modification — we observe, never intercept.

## Privacy contract (publicized)

- All audits run **locally** in WASM. No URL leaves your browser by default.
- Findings are **never** shipped to any backend without an explicit "share to lictor-ai.com" click.
- Source code is public. The `dist/` bundle published to the Web Store is reproducible from this repo.
