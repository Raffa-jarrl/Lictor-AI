# Lictor AI

> The bodyguard your AI didn't ship with.

Lictor is an open-source AI security suite. Three products, one shared engine, plus a Claude Code skill for pre-release audits:

- **[Lictor Shield](./shield)** — free Chrome extension. Audits AI-built sites locally before you sign up; alarms when AI agents access your data.
- **[Lictor Sentinel](./sentinel)** — free SDK (npm + pip). Wraps OpenAI/Anthropic SDKs; blocks prompt injection, data exfiltration, and unsafe tool calls.
- **[Lictor Guardian](./guardian)** — hosted dashboard for teams. AI incident timeline, audit log export, Slack webhook, compliance evidence.
- **[Lictor Security Check](./skills/lictor-security-check)** — Claude Code skill. Run `/lictor-security-check` in your project before you deploy; get a markdown report with severity-ranked findings.

All three products share **[Lictor Core](./core)** — a Rust crate that compiles to native and WASM, so the same checks run in your browser, your Node service, and our cloud. The Claude skill is a markdown-only port of the same check catalog, designed for vibe-coders who haven't installed anything yet.

## Status

Pre-alpha. Building in public.

| Component | Status |
|---|---|
| `core/` | ✅ Phase 1 — 5 checks (secrets / database / auth / CORS / AI-agent), native + WASM, 39 tests, working CLI |
| `shield/` | ✅ Phase 1 — Chrome MV3 extension, WASM-backed audits, real popup verdict, loads unpacked into Chrome |
| `sentinel/` | placeholder (Phase 2) |
| `guardian/` | placeholder (Phase 3) |

## Try it (native CLI)

Audit any AI-built site from the terminal. The audit is read-only and rate-limited to 1 req/sec/host.

```bash
git clone https://github.com/lictor-ai/lictor.git
cd lictor

# One-time setup
brew install rustup wasm-pack    # macOS
rustup default stable
rustup target add wasm32-unknown-unknown

# Run
cargo run --release --example audit -- https://your-vibe-coded-app.com -o report.md
```

A self-contained vulnerable demo lives in [`examples/vulnerable-demo/`](./examples/vulnerable-demo/) — spin it up with `python3 -m http.server` and audit it to verify the engine works.

## Try it (Chrome extension)

```bash
cd shield
pnpm install
pnpm wasm        # builds lictor-core to WASM, copies into shield/wasm/
pnpm build       # produces shield/dist/
```

Then in Chrome → `chrome://extensions` → Developer Mode → Load unpacked → select `shield/dist/`.

Visit any AI-built site (Vercel/Supabase/OpenAI/Anthropic fingerprints) and the toolbar badge will report findings. A vulnerable demo to test against:

```bash
( cd examples/vulnerable-demo && python3 -m http.server 8765 )
# then in Chrome: open http://localhost:8765/
```

## Why

The AI security market is dominated by enterprise-only point solutions. Every one of them assumes you can wait for procurement, sign a 6-figure contract, and integrate over 3 months. None of them do anything for the consumer staring at a vibe-coded SaaS asking "is this actually safe?"

Lictor flanks them. Free for individuals. Free for OSS. Paid for teams. Enterprise where the money is. One engine across all of them so every new check ships everywhere at once.

## License

MIT for `core/`, `shield/`, `sentinel/`. Guardian's hosted service code lives in this repo for transparency but is not licensed for self-hosting — the value is in the hosted compliance + monitoring layer, not the code.

See [`LICENSE`](./LICENSE).

## Contributing

Not yet open for contributions — we're stabilizing the API surface. Watch the repo and we'll announce when contributing opens. Until then: ship a PR if you find a bug; expect a slow review.

## Built by

A 20-year cybersecurity engineer + Claude. Solo build. The course at [generationai.com](https://generationai.com) teaches developers to ship apps that pass Lictor's checks.
