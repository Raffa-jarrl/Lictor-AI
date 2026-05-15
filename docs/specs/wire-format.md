# Lictor Sentinel ↔ Guardian — Wire Format

> **Status:** v0.1 contract. Locked W1 (May 2026). Single source of truth for what Sentinel POSTs to Guardian's `/api/ingest` endpoint.

A breaking change here means an SDK major-version bump and a Guardian migration. Don't change casually.

---

## 1. The endpoint

```
POST https://app.lictor-ai.com/api/ingest
Content-Type: application/json
Authorization: Bearer <ingest_token>
```

The `ingest_token` is per-account, generated when the account is created, rotatable. Sentinel reads it from `process.env.LICTOR_GUARDIAN_TOKEN` (TS) or `os.environ['LICTOR_GUARDIAN_TOKEN']` (Python) by default.

---

## 2. The envelope

The wire format is an envelope wrapping one or more `IncidentEvent`s. Sentinel may batch (default: send immediately, but a future option may buffer up to 10 events or 1 second).

```json
{
  "envelope_version": "1",
  "sentinel_version": "0.1.0",
  "lictor_core_version": "0.1.0",
  "agent_id": "agent-7c4b3f81",
  "sent_at": "2026-10-06T14:23:45.123Z",
  "events": [
    {
      "ts": "2026-10-06T14:23:45.000Z",
      "phase": "preflight",
      "check_id": "prompt-injection",
      "severity": "high",
      "title": "Prompt injection pattern detected in user input",
      "detail": "Input contained the string \"ignore previous instructions\" in a structural location consistent with prompt injection.",
      "model": {
        "provider": "openai",
        "name": "gpt-4"
      },
      "fingerprint": "a3f2b8c1d4e5f6a7",
      "action": "blocked",
      "sentinel_version": "0.1.0"
    }
  ]
}
```

### Field-by-field

| Field | Required | Type | Notes |
|---|---|---|---|
| `envelope_version` | yes | `"1"` | String. Bump on breaking format changes. |
| `sentinel_version` | yes | semver string | Same as `events[].sentinel_version`. Hoisted to envelope for easy server-side filtering. |
| `lictor_core_version` | yes | semver string | The core version Sentinel is pinned to. |
| `agent_id` | yes | string | Stable per-process ID from `wrap()` time. Lets Guardian group events by app instance. |
| `sent_at` | yes | ISO 8601 timestamp | Wall-clock time the envelope was POSTed. |
| `events` | yes | `IncidentEvent[]` | 1–10 events per envelope. |

### Per-event fields

Match `IncidentEvent` from [`sentinel-api.md`](./sentinel-api.md) §3 exactly. Wire format is a JSON serialization of that type.

---

## 3. Server response

**Success (202 Accepted):**

```json
{
  "received": 1,
  "ingest_id": "ing_8b2c4d3e"
}
```

`202`, not `200` — events are accepted into the queue, processing is asynchronous. The `ingest_id` is for client-side debugging only; not surfaced in the dashboard.

**Auth failure (401 Unauthorized):**

```json
{
  "error": "invalid_token",
  "message": "ingest_token is invalid or revoked"
}
```

Sentinel logs the error via `onIncident` (with severity 'info') and continues — never blocks the user request because Guardian is down or misconfigured.

**Rate-limited (429 Too Many Requests):**

```json
{
  "error": "rate_limited",
  "retry_after_seconds": 60
}
```

Free preview tier: 1000 events/min per account. Pro: 10K/min. Team: 100K/min. Sentinel applies exponential backoff but never queues unbounded — drops events with `console.warn` after 3 failed retries.

**Validation error (400 Bad Request):**

```json
{
  "error": "validation",
  "field": "events[0].severity",
  "message": "must be one of: critical, high, medium, low, info"
}
```

This indicates Sentinel produced malformed output (a bug in our SDK). Sentinel logs and continues; the user request is unaffected.

---

## 4. Privacy invariants

These hold by construction. Anyone reviewing this doc should be able to verify them in the SDK source code:

1. **No raw user content** appears in any event field. The `fingerprint` is a sha256 hash of the first 4 KB of the relevant input/output, truncated to 16 hex chars. Reversing it requires a rainbow-table-scale corpus of plaintexts.
2. **No model output text** appears in any event field. Same fingerprint principle.
3. **No environment variable values** (besides `LICTOR_GUARDIAN_TOKEN` itself, which Sentinel never includes in any event payload) are read or shipped.
4. **No file system or process introspection** beyond what's needed to read the configured token.

If a future check needs richer context — say, *which* prompt-injection pattern matched — that context goes in `detail` as a structured but anonymized string ("pattern: 'ignore_previous_instructions' (rule #4)"), never the raw user text.

---

## 5. Backward compatibility

- The server accepts `envelope_version: "1"` indefinitely.
- New optional fields may be added in v1; clients ignore unknown fields, server ignores unrecognized fields not in the v1 schema.
- Removing a field, changing a field's type, or changing required→optional → bump to `envelope_version: "2"` and run both server-side handlers in parallel for at least one quarter.

---

## 6. References

- [`sentinel-api.md`](./sentinel-api.md) §3 — `IncidentEvent` shape (the authoritative type)
- [`guardian-schema.md`](./guardian-schema.md) — what these events become in Postgres
