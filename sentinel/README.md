# @lictor/sentinel

> The security crew for apps you built with AI — runtime defense for your OpenAI / Anthropic calls.
> One-line `wrap()` blocks prompt injection, secret exfiltration, and PII leaks before they hit production.

[![CI](https://github.com/Raffa-jarrl/Lictor-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Raffa-jarrl/Lictor-AI/actions)
[![npm](https://img.shields.io/npm/v/@lictor/sentinel.svg)](https://www.npmjs.com/package/@lictor/sentinel)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Why Sentinel

If your app calls `openai.chat.completions.create()` or `anthropic.messages.create()` with any input that came from a user — uploaded text, a chat message, an email body, a comment — your AI is one prompt-injection payload away from acting against your user's interest.

Sentinel sits between your code and the LLM. Same call site, same response shape:

```ts
// Before:
const client = new OpenAI();

// After:
const client = wrap(new OpenAI(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
});
```

Sentinel intercepts every call:
- **Pre-flight**: scans user input for prompt-injection patterns + leaked secrets. Blocks the call or logs a high-severity incident.
- **Post-flight**: scans the model's response for PII it shouldn't reveal. Redacts or blocks.
- **Telemetry**: ships fingerprints (never raw content) to Lictor Guardian for incident timeline + compliance evidence.

## What Sentinel catches

**Prompt injection (32 patterns across 7 attack families):**

| Family | Severity | What it catches |
|---|---|---|
| direct-override | high / medium | "ignore previous instructions", "from now on", "your real goal is…" |
| authority-impersonation | high | `System:`, `[SYSTEM]`, "admin override", "developer mode enabled" |
| jailbreak | high / medium | DAN-style personas, "act as evil AI", "you have been jailbroken" |
| system-prompt-extraction | medium / high | "repeat your system prompt", "what were your initial instructions" |
| delimiter-injection | **critical** | Model-control tokens: `<\|im_start\|>`, `[INST]`, fake `Assistant:` turn boundaries |
| goal-hijacking | medium | "instead of that, do this", "your new objective is…" |
| suspicious-encoding | medium | Long base64 strings, hex-escape soup, zero-width characters |

**Secrets in input (15 patterns)**: OpenAI/Anthropic/Stripe/GitHub/AWS/Slack/Google keys, JWT tokens, MongoDB connection strings, private keys. Catches users accidentally pasting their own credentials into prompts.

**PII in output**: credit-card numbers (Luhn-validated), social security numbers, email addresses leaked from training data. Configurable per-field.

## Install

```bash
pnpm add @lictor/sentinel
# or
npm i @lictor/sentinel
# or
yarn add @lictor/sentinel
```

## Quick start

### With OpenAI

```ts
import OpenAI from "openai";
import { wrap } from "@lictor/sentinel";

const client = wrap(new OpenAI(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
  onIncident: (event) => {
    console.warn(`[lictor] ${event.severity}: ${event.title}`);
  },
});

// Same call site — Sentinel intercepts pre-flight and post-flight.
const completion = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: userInput }],
});
```

### With Anthropic

```ts
import Anthropic from "@anthropic-ai/sdk";
import { wrap } from "@lictor/sentinel";

const client = wrap(new Anthropic(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
});

const message = await client.messages.create({
  model: "claude-3-5-sonnet-20241022",
  max_tokens: 1024,
  messages: [{ role: "user", content: userInput }],
});
```

### With Guardian (optional — for team-level monitoring)

```ts
const client = wrap(new OpenAI(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
  guardian: {
    endpoint: "https://app.lictor-ai.com/api/ingest",
    token: process.env.LICTOR_GUARDIAN_TOKEN!,
  },
});
```

Guardian gives you: per-incident timeline with severity / check / phase filters, audit-log export for SOC 2 / GDPR Article 32 / EU AI Act Article 12 evidence, Slack webhook for critical incidents. Free preview at app.lictor-ai.com.

## Privacy contract

Sentinel **never** ships raw user content to Guardian. The wire format includes only:
- Severity (`critical` / `high` / `medium` / `low` / `info`)
- Check ID (`prompt-injection` / `secrets-in-input` / `pii-leak`)
- 16-hex-char fingerprint (sha256 of the first 4 KB of content)
- Timestamp + request metadata

See [`docs/specs/wire-format.md`](https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/specs/wire-format.md) §4 for the privacy invariants.

Telemetry is opt-in: if `guardian` config is absent, no network calls are made. Sentinel works fully offline.

## Configuration

| Option | Type | Default | Purpose |
|---|---|---|---|
| `preflight` | `CheckId[]` | `["prompt-injection"]` | Checks to run on input before LLM call |
| `postflight` | `CheckId[]` | `[]` | Checks to run on output after LLM call |
| `mode` | `"block" \| "log" \| "redact"` | `"block"` | What to do on incident |
| `onIncident` | `(event) => void` | undefined | Hook fired on every incident |
| `guardian` | `{ endpoint, token }` | undefined | Telemetry destination (opt-in) |
| `fingerprintBytes` | `number` | `4096` | Size of fingerprinted prefix |

## Troubleshooting

**"Sentinel is blocking legitimate inputs."**
Switch to `mode: "log"` first. Sentinel will report incidents but not block. Review the captured incidents at app.lictor-ai.com/incidents (if Guardian is wired) or in the `onIncident` callback. Tune `preflight` to drop checks that are over-eager for your use case.

**"My streaming responses aren't intercepted."**
Post-flight checks on streaming responses ship in v0.2. For v0.1, post-flight only runs on the final completion message. Pre-flight is unaffected (input is always non-streaming).

**"Guardian telemetry isn't appearing in the dashboard."**
Confirm the token in `guardian.token` matches the project token in your Guardian project settings. Check `console.log` for `[lictor] outbound telemetry error` — common causes: firewall blocking outbound to `app.lictor-ai.com`, or token revocation.

**"I want to add a custom check."**
v0.1 ships with built-in checks only. Custom-check authoring ships in v0.2 (Q1 2027) as part of the Studio Pro tier. Until then, use `onIncident` to layer your own logic on top of the built-ins.

## How Sentinel fits in the Lictor suite

- **Lictor Skill Suite** — audit your project once with `/lictor-security-check`
- **Lictor Shield** — Chrome extension that audits any deployed AI-built site you visit
- **`@lictor/sentinel`** — *you are here* — runtime defense in your app
- **Lictor Guardian** — hosted dashboard for incidents + compliance evidence
- **Lictor Studio** — offline desktop audit for privacy-paranoid devs

Most teams shipping AI features want Sentinel + Guardian. Both are free for individuals.

## Develop

```bash
pnpm install
pnpm build
pnpm test
```

## License

[Apache-2.0](LICENSE). The Lictor commitment: this code stays free and open forever. Pro features for Studio + Guardian ship under BUSL with 4-year Apache-2.0 conversion (per Lictor's [legal structure memo](https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/launch/legal-structure-memo.md)).

## Links

- **Main repo**: [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI)
- **Documentation**: [lictor-ai.com/sentinel](https://lictor-ai.com/sentinel)
- **Python sibling**: [`lictor-sentinel` on PyPI](https://pypi.org/project/lictor-sentinel/)
- **Issues + feature requests**: [github.com/Raffa-jarrl/Lictor-AI/issues](https://github.com/Raffa-jarrl/Lictor-AI/issues)
- **Security disclosure**: security@lictor-ai.com

Built by a 20-year cybersecurity engineer. Tested across [12+ public teardowns](https://lictor-ai.com/teardowns) of real vibe-coded apps.
