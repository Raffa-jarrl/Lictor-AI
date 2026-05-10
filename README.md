# Lictor AI

> The bodyguard your AI didn't ship with.

Lictor is an open-source AI security suite. Three products, one shared engine:

- **[Lictor Shield](./shield)** — free Chrome extension. Audits AI-built sites before you sign up; alarms when AI accesses your data.
- **[Lictor Sentinel](./sentinel)** — free SDK (npm + pip). Wraps OpenAI/Anthropic SDKs; blocks prompt injection, data exfiltration, and unsafe tool calls.
- **[Lictor Guardian](./guardian)** — enterprise SaaS. Real-time AI security platform with SOC 2 / GDPR / EU AI Act reporting.

All three share **[Lictor Core](./core)** — a Rust crate that compiles to native and WASM, so the same checks run in your browser, your Node service, and our cloud.

## Status

Pre-alpha. Building in public. Star the repo to follow.

| Component | Status |
|---|---|
| `core/` | ✅ Phase 1 ported — 5 checks, 30 tests passing, working CLI example |
| `shield/` | manifest stubbed, content-script wired; WASM bridge to `core` is the next Phase 1 step |
| `sentinel/` | placeholder (Phase 2) |
| `guardian/` | placeholder (Phase 3) |

## Try it (native CLI)

```bash
cd ~/Lictor
cargo run --release --example audit -- https://your-vibe-coded-app.com -o report.md
```

Read-only. Rate-limited to 1 req/sec/host. Same checks as the upstream `audit.py`.

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
