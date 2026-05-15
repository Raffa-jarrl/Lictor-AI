# Lictor Shield

> Chrome extension. Audits AI-built sites before you sign up. Alarms when AI accesses your data.

## What it does (target behaviour)

1. **Detects AI-built sites** on first visit (Next.js / Vite / Supabase / OpenAI / Anthropic SDK fingerprints in HTML + JS).
2. **Runs `lictor-core` (WASM)** against the site — same 5 checks as `audit.py`.
3. **Pops a verdict badge** on the toolbar: green (clean) / yellow (warnings) / red (critical findings).
4. **Alarms in real time** when a page tries to read sensitive surfaces (cookies, localStorage, form-field contents) and ship them to an AI endpoint.

## Status

Pre-alpha. Manifest scaffolded; content script + WASM bridge in progress (Phase 1).

| Piece | Status |
|---|---|
| `manifest.json` | scaffolded, MV3, minimum permissions |
| `src/background.ts` | service worker stub |
| `src/content.ts` | content script stub — detection logic |
| `src/popup/` | toolbar UI stub |
| WASM bridge to `lictor-core` | TODO |
| Chrome Web Store submission | TODO (after Phase 1 complete) |

## Build (once dependencies are wired)

```bash
pnpm install            # installs typescript, @types/chrome, vite
pnpm build              # produces dist/ ready to load unpacked in Chrome
pnpm dev                # watch mode
```

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
