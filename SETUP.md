# Lictor — Local Setup

One-time setup to build everything in this monorepo from a fresh machine.

## Required toolchain

| Tool | Why | Install |
|---|---|---|
| **Rust (stable)** | builds `core/` (native + WASM) | [rustup.rs](https://rustup.rs) |
| **wasm-pack** | bundles `core/` for Shield's browser load | `cargo install wasm-pack` |
| **Node 20+** | Shield's TS build, Sentinel SDK | [nodejs.org](https://nodejs.org) or `brew install node@20` |
| **pnpm 9+** | workspace package manager | `npm i -g pnpm` |

## First-time bootstrap

```bash
# 1. Install Rust (one-line install):
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add the WASM target:
rustup target add wasm32-unknown-unknown

# 3. Install wasm-pack:
cargo install wasm-pack

# 4. Install Node deps:
cd ~/Lictor && pnpm install
```

## Daily commands

```bash
# Build the core engine (native; runs all tests):
cargo build -p lictor-core
cargo test  -p lictor-core

# Build the WASM bundle for Shield:
pnpm wasm

# Build the Shield extension (loads dist/ unpacked into Chrome):
pnpm build:shield

# Develop Shield in watch mode:
pnpm --filter @lictor/shield dev
```

## Loading Shield into Chrome (development)

1. `pnpm build:shield`
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select `~/Lictor/shield/dist`
5. Pin the Lictor icon to the toolbar

## Phase 1 status

Phase 1 is **done**. The core engine + Shield extension are wired end-to-end:

- `core/` — 5 checks ported from upstream `audit.py`, 39 tests passing, native + WASM builds clean, clippy clean
- `shield/` — Chrome MV3 extension; content-script detects AI-built sites, background runs full WASM-backed audit, popup shows live findings with severity badges
- `examples/vulnerable-demo/` — fixture used to validate the engine catches the 6 expected findings against real HTTP

## Known gaps (deferred to later phases)

| Path | Status |
|---|---|
| `sentinel/` | One README. Code lands in Phase 2. |
| `guardian/` | One README. Code lands in Phase 3. |
| `shield/dist/assets/icon-*.png` | 1×1 transparent placeholders. Need designer pass on the Praetorian helmet mark before Web Store submission. |
| `wasm-opt` size pass | Disabled in Cargo.toml (bundled wasm-opt is older than rustc's bulk-memory output). 960 KB → ~280 KB once we wire a newer wasm-opt. |
