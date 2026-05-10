# Lictor Sentinel — API Specification

> **Status:** v0.1 contract. Locked W1 (May 2026). Changes here ripple through TS, Python, and Guardian's ingest endpoint — bump version + write a migration before changing.

The contract between developers and Sentinel. The `wrap()` function is the entire user-facing API. Everything else is implementation detail.

---

## 1. The `wrap()` function

### TypeScript

```ts
import OpenAI from "openai";
import { wrap, type SentinelConfig } from "@lictor/sentinel";

const client = wrap(new OpenAI(), {
  // Pre-flight checks (run on user input before sending to model)
  preflight: ["prompt-injection", "secrets-in-input"],

  // Post-flight checks (run on model output before returning to caller)
  postflight: ["pii-leak"],

  // What to do when a check trips
  onIncident: (event) => {
    console.warn(`[lictor] ${event.severity}: ${event.title}`);
  },

  // Optional: stream telemetry to Guardian for centralized monitoring
  guardian: {
    endpoint: "https://app.lictor.ai/api/ingest",
    token: process.env.LICTOR_GUARDIAN_TOKEN,
  },
});

// Same call site as the unwrapped client.
const completion = await client.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: userInput }],
});
```

### Python

```python
from openai import OpenAI
from lictor_sentinel import wrap

client = wrap(OpenAI(), config={
    "preflight": ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
    "on_incident": lambda event: print(f"[lictor] {event.severity}: {event.title}"),
    "guardian": {
        "endpoint": "https://app.lictor.ai/api/ingest",
        "token": os.getenv("LICTOR_GUARDIAN_TOKEN"),
    },
})

# Same call site.
completion = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}],
)
```

---

## 2. Configuration shape

```ts
interface SentinelConfig {
  /** Checks to run on user input before the model sees it. */
  preflight?: CheckId[];

  /** Checks to run on model output before returning to caller. */
  postflight?: CheckId[];

  /**
   * Action to take when a check trips. Default: "log" (no-op besides onIncident).
   * "block" throws a SentinelBlockedError. "redact" returns sanitized text.
   */
  onTrip?: "log" | "block" | "redact";

  /** Callback fired for every check trip, regardless of onTrip. */
  onIncident?: (event: IncidentEvent) => void;

  /** Optional Guardian integration. When set, every IncidentEvent is also POSTed. */
  guardian?: {
    endpoint: string;
    token: string;
    /** Default: 5000ms. Telemetry sends are best-effort, never block the user request. */
    timeoutMs?: number;
  };

  /** Override the underlying lictor-core check rules. Defaults to bundled rules. */
  rulesOverride?: Record<string, unknown>;
}

type CheckId =
  | "prompt-injection"      // Detects known injection patterns in input
  | "secrets-in-input"       // Catches API keys, JWTs, etc. in user input (data exfil setup)
  | "pii-leak"               // Catches emails, phones, SSNs in model output
  | "unsafe-tool-call";      // (v0.2) flags suspicious tool/function call patterns
```

---

## 3. The `IncidentEvent` shape

This is what `onIncident` receives and what gets POSTed to Guardian. Same shape, both surfaces.

```ts
interface IncidentEvent {
  /** ISO 8601 timestamp. */
  ts: string;

  /** Stable per-process ID; randomly generated at wrap() time. */
  agentId: string;

  /** Where the check tripped: 'preflight' (user input) or 'postflight' (model output). */
  phase: "preflight" | "postflight";

  /** Which check tripped. */
  checkId: CheckId;

  /** Severity from lictor-core. */
  severity: "critical" | "high" | "medium" | "low" | "info";

  /** Short human title, ≤80 chars. */
  title: string;

  /** Longer detail: what was found, why it matters. */
  detail: string;

  /** Reference: which model + which provider. */
  model: { provider: "openai" | "anthropic" | "other"; name: string };

  /**
   * Hashed fingerprint of the input/output that tripped (sha256 of first 4KB,
   * truncated to 16 hex chars). Allows correlating incidents without
   * shipping raw user content to Guardian. Never the full text.
   */
  fingerprint: string;

  /** What action was taken: 'logged' | 'blocked' | 'redacted'. */
  action: "logged" | "blocked" | "redacted";

  /** Sentinel SDK version that produced this event. */
  sentinelVersion: string;
}
```

**Privacy invariant:** Sentinel NEVER ships raw user content to Guardian. Only fingerprints, severities, and detection metadata. This is in the README, the consent flow, and the audit log.

---

## 4. Errors

```ts
class SentinelBlockedError extends Error {
  readonly incident: IncidentEvent;
  constructor(event: IncidentEvent);
}
```

Thrown when `onTrip: "block"` and a check trips. Callers catch it and decide how to surface to the end-user.

---

## 5. The hook lifecycle

For a single `client.chat.completions.create(args)` call:

```
1. wrap()'s proxy intercepts the call.
2. Run all preflight checks against args.messages[].content.
   For each trip:
     a. Build IncidentEvent (phase: 'preflight').
     b. Fire onIncident.
     c. POST to Guardian (best-effort, fire-and-forget).
     d. If onTrip='block', throw SentinelBlockedError. Stop here.
     e. If onTrip='redact', sanitize args before continuing.
3. Forward the call to the underlying SDK.
4. Receive the response.
5. Run all postflight checks against response output text.
   For each trip:
     a. Build IncidentEvent (phase: 'postflight').
     b. Fire onIncident.
     c. POST to Guardian (best-effort).
     d. If onTrip='block', throw SentinelBlockedError instead of returning.
     e. If onTrip='redact', return sanitized response.
6. Return response to caller.
```

**Performance contract:** preflight + postflight together add ≤5ms p95 to a Sentinel-wrapped call when no checks trip. (Bench tracked in `core/benches/`.)

---

## 6. Versioning

- Sentinel SDK version (semver) and `lictor-core` version are decoupled.
- Sentinel pins a `lictor-core` minor version range (`^0.1.0`).
- The `IncidentEvent` shape is part of the SDK's public contract — breaking changes require a major version bump.
- Every event includes `sentinelVersion` so Guardian can route by SDK version if needed.

---

## 7. What's deliberately NOT in v0.1

- Streaming response interception (deferred to v0.2)
- Custom user-defined check authoring (deferred to v0.3)
- Tool-call sandboxing / approval flow (deferred to v0.2)
- Multi-message conversation context tracking (deferred to v0.2)
- Anthropic streaming (`messages.stream()`) wrapping (deferred to v0.2)

If a v0.1 user asks for any of these, they go on the parking-lot list, not into the codebase.

---

## 8. References

- [`wire-format.md`](./wire-format.md) — what Sentinel POSTs to Guardian
- [`guardian-schema.md`](./guardian-schema.md) — what Guardian does with it
- [`../../core/src/finding.rs`](../../core/src/finding.rs) — the Rust Finding type that `IncidentEvent` mirrors
