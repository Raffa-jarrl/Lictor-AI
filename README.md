# Lictor AI

> The bodyguard your AI didn't ship with.

[![CI](https://github.com/Raffa-jarrl/Lictor-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Raffa-jarrl/Lictor-AI/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![npm version](https://img.shields.io/npm/v/@lictor/sentinel.svg)](https://www.npmjs.com/package/@lictor/sentinel)
[![PyPI version](https://img.shields.io/pypi/v/lictor-sentinel.svg)](https://pypi.org/project/lictor-sentinel/)

Lictor is an open-source AI security suite. Four free things, all under one brand, designed for vibe-coders who don't have a CISO and don't want to talk to one:

- **[Lictor Shield](./shield)** — free Chrome extension. Watches AI-built sites you visit and warns you about leaked keys, open databases, and unguarded chat interfaces.
- **[Lictor Sentinel](./sentinel)** — free SDK (`npm install @lictor/sentinel` / `pip install lictor-sentinel`). Wraps your OpenAI/Anthropic SDK to block prompt injection and PII leaks in your live app.
- **[Lictor Guardian](./guardian)** — free hosted dashboard. Aggregates incidents across your apps. Audit log export for the day an enterprise customer asks "how do you secure AI?"
- **[Lictor Security Suite for Claude Code](./skills)** — four free Claude plugins. Type `/lictor-security-check` in any project to scan it for bugs before you ship. Plus `/lictor-explain` (translates jargon), `/lictor-fix-it` (applies fixes with your permission), `/lictor-rotate` (walks you through rotating a leaked key).

All four share **[Lictor Core](./core)** — a Rust crate that compiles to native and WASM, so the same checks run in your browser, your Node service, our cloud, and Claude Code.

## Status

| Component | What it is | Status |
|---|---|---|
| [`core/`](./core/) | Rust check engine, native + WASM | ✅ 39 tests, working CLI example, Apache 2.0 |
| [`shield/`](./shield/) | Chrome MV3 extension | ✅ WASM-backed audits, real popup verdict, loads unpacked |
| [`sentinel/`](./sentinel/) | TypeScript SDK (npm: `@lictor/sentinel`) | ✅ 159 tests, real `wrap()`, 3 checks (prompt-injection / pii-leak / secrets-in-input) |
| [`sentinel-py/`](./sentinel-py/) | Python SDK (PyPI: `lictor-sentinel`) | ✅ 11 tests, Python parity, zero runtime deps |
| [`guardian/`](./guardian/) | Hosted dashboard (Next.js + Postgres) | ✅ 12 integration tests, magic-link auth, incident timeline, audit log export, Slack webhook |
| [`skills/`](./skills/) | Claude Code plugin suite | ✅ 4 plugins (`/lictor-security-check`, `/lictor-explain`, `/lictor-fix-it`, `/lictor-rotate`) |
| [`landing/`](./landing/) | Marketing site (lictorai.com) | ✅ Single-page hero + `/compliance` subpage |

**Public launch target:** Tuesday October 6, 2026.

## Try the Claude Code plugins (60 seconds)

If you have Claude Code installed:

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/
```

Then in any Claude Code session, from your project's root directory:

```
/lictor-security-check
```

Claude reads your project, runs 7 checks, writes a `SECURITY-AUDIT.md`, and tells you in plain English what to fix.

## Try the native CLI

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI
cd lictor

# One-time setup
brew install rustup wasm-pack    # macOS
rustup default stable
rustup target add wasm32-unknown-unknown

# Audit any URL
cargo run --release --example audit -- https://your-app.com -o report.md
```

A self-contained vulnerable demo lives in [`examples/vulnerable-demo/`](./examples/vulnerable-demo/) — spin it up with `python3 -m http.server 8765` and audit it to verify the engine works on a known-bad target.

## Try the Chrome extension

```bash
cd shield
pnpm install
pnpm wasm     # builds lictor-core to WASM
pnpm build    # produces shield/dist/
```

In Chrome → `chrome://extensions` → Developer Mode → **Load unpacked** → select `shield/dist/`.

Visit any AI-built site (Vercel/Supabase/OpenAI/Anthropic fingerprints) and the toolbar badge reports findings.

## Why

The AI security market is dominated by enterprise-only point solutions. Every one of them assumes you can wait for procurement, sign a 6-figure contract, and integrate over 3 months. None of them does anything for the consumer staring at a vibe-coded SaaS asking "is this actually safe?"

Lictor flanks them. Free for individuals. Free for OSS. Paid for teams. Enterprise where the money is. One engine across all of them so every new check ships everywhere at once.

In a sentence: **safety infrastructure for the AI agent era.**

## License

Apache 2.0 for `core/`, `shield/`, `sentinel/`, `sentinel-py/`, and `skills/`. Guardian's hosted service code is published for transparency but licensed for hosted use through lictorai.com only (see [`guardian/LICENSE`](./guardian/LICENSE)).

See [`LICENSE`](./LICENSE) + [`NOTICE`](./NOTICE).

## Security

If you've found a vulnerability in Lictor itself, **don't open a public issue** — see [`SECURITY.md`](./SECURITY.md). False-negative reports (real bugs Lictor missed in your code) are the most valuable kind of report we get — use the [false-negative template](./.github/ISSUE_TEMPLATE/false-negative.md).

## Contributing

Not yet broadly open. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for what we DO want right now (bug reports, false-negative reports, pattern requests).

[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) applies.

## What's in this repo

```
.
├── core/             — Rust crate, the shared engine
├── shield/           — Chrome extension
├── sentinel/         — TypeScript SDK
├── sentinel-py/      — Python SDK
├── guardian/         — Next.js + Postgres dashboard
├── skills/           — Claude Code plugin suite (4 skills)
├── landing/          — Marketing site (HTML, deploys to lictorai.com)
├── brand/            — Logo SVG + rendered PNG icon variants
├── docs/             — Specs (sentinel-api, guardian-schema, wire-format)
│                        + compliance.md + BUG_BASH.md + launch/
└── examples/         — Vulnerable-by-design fixtures
```

## Built by

A 20-year cybersecurity engineer + Claude. Solo build, building in public.

If this saved you from a bad day: star the repo. That's how solo open-source projects get measured.
