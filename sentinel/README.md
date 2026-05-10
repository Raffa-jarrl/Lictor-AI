# Lictor Sentinel

> Free SDK that wraps OpenAI / Anthropic clients. Blocks prompt injection, data exfiltration, and unsafe tool calls before they hit the model — and after the model responds.

## Status

Placeholder. Lands in **Phase 2** (weeks 5–8 of the build plan). Tracking in [docs/projects/lictor/STRATEGY.md](../../GenerationAI/docs/projects/lictor/STRATEGY.md) (private).

## Planned shape

Two language packages, one shared rule set (powered by `lictor-core`):

- **`@lictor/sentinel`** (npm, TypeScript) — wraps the OpenAI + Anthropic Node SDKs
- **`lictor-sentinel`** (PyPI, Python) — wraps `openai` + `anthropic` Python clients

Sketched API (subject to change — this is the *feel*, not the contract):

```ts
import OpenAI from 'openai';
import { wrap } from '@lictor/sentinel';

const client = wrap(new OpenAI(), {
  preflight:  ['prompt-injection', 'pii-in-input'],
  postflight: ['pii-leak', 'unsafe-tool-call'],
  onIncident: (event) => console.warn('[lictor]', event),
});

// Same call site — Sentinel checks transparently before/after.
const completion = await client.chat.completions.create({ /* ... */ });
```

## Design notes

- **Same call site.** No "rewrite your AI code with our SDK." We wrap the existing client; if Sentinel has nothing to flag, the call is a passthrough with ~1ms overhead.
- **Local-first.** Default checks run in-process. No network calls. No telemetry.
- **Optional Guardian link.** When `LICTOR_GUARDIAN_TOKEN` is set, incidents are forwarded to the hosted dashboard. Otherwise, on-device only.
- **Free + MIT.** No paid feature gating in the SDK itself — paid value lives in Guardian.

## Why this exists

Today, integrating "AI safety" into a real product means ad-hoc input filtering, post-hoc regex checks, and hoping you remembered the cases that matter. Sentinel ships the rule set + the wrapping pattern as one library. New rules ship via a version bump.

## License

MIT (planned).
