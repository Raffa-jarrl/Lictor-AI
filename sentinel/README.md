# @lictor/sentinel

> Wraps OpenAI / Anthropic SDK clients to block prompt injection, data exfiltration, and unsafe AI behaviour.

## Status

Pre-alpha. **API surface is locked** ([`docs/specs/sentinel-api.md`](../docs/specs/sentinel-api.md)). Check execution is stubbed and lands in Phase 1 (June–July 2026).

| Feature | Status |
|---|---|
| `wrap()` API | ✅ stable, returns client unchanged at v0.1 |
| Type definitions | ✅ stable |
| Telemetry → Guardian | ✅ wired |
| Fingerprint hashing | ✅ |
| Prompt-injection check | ⏳ Phase 1 W4 |
| PII-leak check | ⏳ Phase 1 W5 |
| Secrets-in-input check | ⏳ Phase 1 W5 |
| Streaming response interception | ⏳ v0.2 |

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
