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

## Known gaps in this scaffold

These are deliberately empty — they land in their respective build phases.

| Path | Empty reason |
|---|---|
| `core/src/checks/*.rs` (5 files) | Stubs return empty `Vec<Finding>`. Real rules port from `audit.py` in Phase 1. |
| `core/src/http.rs` | Stub returns error. Real polite client lands in Phase 1. |
| `shield/src/content.ts` | Has detection heuristic + stub finding. Real WASM dispatch in Phase 1. |
| `sentinel/` | One README. Code lands in Phase 2. |
| `guardian/` | One README. Code lands in Phase 3. |
| `examples/` | Empty. Populated in Phase 2 once Sentinel ships. |
| `shield/assets/icon-*.png` | Not yet rendered. Need designer pass on the Praetorian helmet mark. |
