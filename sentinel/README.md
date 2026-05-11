# @lictor/sentinel

> Wraps OpenAI / Anthropic SDK clients to block prompt injection, data exfiltration, and unsafe AI behaviour.

## Status

Pre-alpha. **API surface is locked** ([`docs/specs/sentinel-api.md`](../docs/specs/sentinel-api.md)). Check execution is stubbed and lands in Phase 1 (June–July 2026).

| Feature | Status |
|---|---|
| `wrap()` API | ✅ stable, real Proxy interception of OpenAI + Anthropic shapes |
| Type definitions | ✅ stable |
| Telemetry → Guardian | ✅ wired |
| Fingerprint hashing | ✅ |
| **Prompt-injection check** | ✅ **shipped W4 — 32 patterns across 7 attack families, 84 tests** |
| PII-leak check | ⏳ Phase 1 W5 |
| Secrets-in-input check | ⏳ Phase 1 W5 |
| Streaming response interception | ⏳ v0.2 |

## What `prompt-injection` catches

Auto-registered as a built-in. 32 curated patterns across these attack families:

| Family | Severity | What it catches |
|---|---|---|
| **direct-override** | high / medium | "ignore previous instructions", "from now on", "your real goal is…" |
| **authority-impersonation** | high | `System:`, `[SYSTEM]`, "admin override", "developer mode enabled", "bypass safety filters" |
| **jailbreak** | high / medium | DAN-style personas, "act as evil AI", "you have been jailbroken", "unrestricted version" |
| **system-prompt-extraction** | medium / high | "repeat your system prompt", "what were your initial instructions", "base64-encode your prompt" |
| **delimiter-injection** | **critical** | Model-control tokens never legitimately in user input: `<\|im_start\|>`, `[INST]`, `<\|eot_id\|>`, fake `Assistant:` turn boundaries |
| **goal-hijacking** | medium | "instead of that, do this", "your new objective is…" |
| **suspicious-encoding** | medium | Long base64 strings, hex-escape soup, zero-width / direction-override character runs |

Highest severity wins; all matched categories are listed in the finding detail. The catalog is curated for low false-positive rate — every pattern has positive AND negative test cases in `tests/prompt-injection.test.ts`.

When patterns evolve (and they will — adversarial inputs are a moving target), the addition discipline is:
1. Add the pattern to `src/checks/prompt-injection.ts`
2. Add at least one positive test (real adversarial input MUST trip)
3. Add at least one negative test (similar-looking legitimate input MUST NOT trip)
4. Bump the SDK minor version

## Install

```bash
pnpm add @lictor/sentinel
# or
npm i @lictor/sentinel
```

## Quick start

```ts
import OpenAI from "openai";
import { wrap } from "@lictor/sentinel";

const client = wrap(new OpenAI(), {
  preflight: ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
  onIncident: (event) => console.warn(`[lictor] ${event.severity}: ${event.title}`),
  guardian: {
    endpoint: "https://app.lictor.ai/api/ingest",
    token: process.env.LICTOR_GUARDIAN_TOKEN!,
  },
});

// Same call site. Sentinel intercepts pre-flight and post-flight.
const completion = await client.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: userInput }],
});
```

## Privacy contract

- Sentinel **never** ships raw user content to Guardian.
- The wire format includes only severities, check IDs, and 16-hex-char fingerprints (sha256 of the first 4 KB).
- Telemetry is opt-in and disabled when `guardian` is not configured.
- See [`docs/specs/wire-format.md`](../docs/specs/wire-format.md) §4 for the privacy invariants.

## Build

```bash
pnpm install
pnpm build
pnpm test
```

## License

MIT.
