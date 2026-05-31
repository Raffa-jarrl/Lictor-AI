# Lictor Studio — desktop audit app

> 🤖 **Part of the [Lictor AI security suite](../README.md)** — Lictor for AI. Desktop audit app (Tauri).

> **Status:** v0.1.0-pre.0 — skeleton scaffold, builds but only stubs the audit
> **Ship target:** v0.1.0 — Dec 31, 2026 (macOS)
> **Spec:** `~/Lictor/docs/launch/lictor-studio-mvp-spec.md`

Native desktop app that runs Lictor's audit locally — no telemetry, no signup, no cloud round-trip. Built on Tauri 2.x (Rust + Solid + Tailwind).

## Quick start

Requires Rust 1.79+, Node 20+, and pnpm 9+.

```bash
# install dependencies
pnpm install

# dev mode (opens app window with hot-reload)
pnpm tauri dev

# release build (macOS .dmg)
pnpm tauri build
```

## Architecture

```
studio/
├── src-tauri/              Rust backend
│   ├── src/
│   │   ├── main.rs         Entry point + Tauri setup
│   │   ├── commands.rs     IPC handlers (audit, settings, AUDIT.json I/O)
│   │   ├── audit.rs        Wraps lictor-core::run_audit
│   │   └── settings.rs     Settings persistence
│   ├── Cargo.toml
│   ├── tauri.conf.json     Tauri config (signing, bundles, updater)
│   └── icons/              .icns, .ico, .png for the app
├── src/                    Solid frontend
│   ├── main.tsx            Entry
│   ├── App.tsx             Root component
│   ├── lib/
│   │   ├── tauri.ts        Typed Tauri command wrappers
│   │   └── audit-types.ts  TS types matching AUDIT.schema.json
│   ├── routes/             Audit / Findings / Detail / Settings
│   └── components/         SeverityBadge, FindingCard, etc.
├── public/                 Static assets
├── package.json
├── tsconfig.json
├── vite.config.ts
└── index.html
```

## Privacy posture

Studio sends ZERO data to lictorai.com or any third party. The only outbound network call is to check for app updates, and that's gated behind a user-toggleable setting. The whole pitch of Studio is "offline-by-design" — break this and the product loses its reason to exist.

## What's implemented in this skeleton

- ✅ Tauri 2.x project scaffold (Rust + Solid)
- ✅ One end-to-end IPC command (`get_app_version`) proves the bridge works
- ✅ Drop-zone UI stub for folder audit (no real audit yet)
- ✅ AUDIT.schema.json TypeScript types generated
- ✅ Tailwind + Lictor brand styling

## What's NOT implemented (build path forward)

- 🔲 Real audit (currently stubbed — wire to `lictor-core` crate)
- 🔲 Findings list view
- 🔲 Per-finding detail view + plain-English rendering
- 🔲 AUDIT.json import/export commands
- 🔲 Settings persistence
- 🔲 Auto-updater
- 🔲 Code signing + notarization (deferred to ship-week)

See `~/Lictor/docs/launch/lictor-studio-mvp-spec.md` for the full v0.1.0 scope + Sep-Dec milestone schedule.

## Build status

```bash
# verify the skeleton compiles
cargo check --manifest-path src-tauri/Cargo.toml

# verify the frontend type-checks
pnpm typecheck
```

Both should pass on a fresh clone.

## License

Apache 2.0. See `~/Lictor/LICENSE`.
