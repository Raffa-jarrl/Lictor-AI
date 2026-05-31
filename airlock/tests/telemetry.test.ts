/**
 * telemetry.test.ts — Airlock → Guardian wire mapping.
 *
 * Airlock is the *action* boundary, but Guardian only speaks the shared incident
 * wire format (the one Sentinel sends). These tests pin that an AirlockEvent is
 * mapped onto that envelope EXACTLY as Guardian's zod schema requires, so the
 * built-in path works against an unmodified Guardian (no bridge):
 *
 *   - envelope keys are snake_case; event keys are camelCase (mirrors Sentinel)
 *   - channel → checkId, enforced → action (blocked|logged), fingerprint passes through
 *   - POST uses bearer auth + application/json
 *   - errors are swallowed (telemetry must never break the agent)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildEnvelope,
  mapAirlockEvent,
  shipToGuardian,
  setFetchForTests,
  type FetchLike,
} from "../src/telemetry.js";
import type { AirlockEvent } from "../src/index.js";
import { airlockVersion } from "../src/index.js";

function makeEvent(overrides: Partial<AirlockEvent> = {}): AirlockEvent {
  return {
    ts: "2026-05-29T12:00:00.000Z",
    agentId: "agent-test-1",
    channel: "shell",
    decision: "block",
    severity: "critical",
    ruleIds: ["destructive-command"],
    summary: "Tried to delete a directory tree",
    fingerprint: "0123456789abcdef",
    enforced: true,
    airlockVersion,
    ...overrides,
  };
}

test("mapAirlockEvent produces the camelCase incident wire shape Guardian expects", () => {
  const wire = mapAirlockEvent(makeEvent());
  assert.equal(wire.phase, "preflight");
  assert.equal(wire.checkId, "airlock-shell");
  assert.equal(wire.severity, "critical");
  assert.equal(wire.action, "blocked"); // enforced === true
  assert.equal(wire.fingerprint, "0123456789abcdef");
  assert.equal(wire.agentId, "agent-test-1");
  assert.equal(wire.sentinelVersion, airlockVersion);
  // model is the synthetic action-boundary "model".
  assert.deepEqual(wire.model, { provider: "other", name: "airlock-broker" });
  // title is the redacted summary; detail carries channel/decision/rule context.
  assert.equal(wire.title, "Tried to delete a directory tree");
  assert.match(wire.detail, /channel: shell/);
  assert.match(wire.detail, /destructive-command/);
  // fingerprint must satisfy Guardian's /^[0-9a-f]{16}$/.
  assert.match(wire.fingerprint, /^[0-9a-f]{16}$/);
});

test("channel maps to checkId; non-enforced decision maps to action: logged", () => {
  assert.equal(mapAirlockEvent(makeEvent({ channel: "mcp-tool" })).checkId, "airlock-mcp");
  assert.equal(mapAirlockEvent(makeEvent({ channel: "file-write" })).checkId, "airlock-file");
  assert.equal(mapAirlockEvent(makeEvent({ channel: "network" })).checkId, "airlock-network");

  // observe-mode block: classified block, but NOT enforced → logged, not blocked.
  const observed = mapAirlockEvent(makeEvent({ decision: "block", enforced: false }));
  assert.equal(observed.action, "logged");
});

test("title and detail are clamped to Guardian's length bounds (<=200 / <=2000)", () => {
  const longSummary = "x".repeat(5000);
  const wire = mapAirlockEvent(makeEvent({ summary: longSummary }));
  assert.ok(wire.title.length <= 200, "title must be <= 200 chars");
  assert.ok(wire.detail.length >= 1 && wire.detail.length <= 2000, "detail must be 1..2000 chars");
});

test("buildEnvelope wraps the event in the snake_case envelope Guardian validates", () => {
  const env = buildEnvelope(makeEvent());
  assert.equal(env.envelope_version, "1");
  assert.equal(env.sentinel_version, airlockVersion);
  assert.match(env.lictor_core_version, /^\d+\.\d+\.\d+/);
  assert.equal(env.agent_id, "agent-test-1");
  assert.match(env.sent_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(env.events.length, 1);
  assert.equal(env.events[0]!.checkId, "airlock-shell");
});

// Helper: capturing mock fetch.
interface MockCall {
  url: string;
  body: string;
  headers: Record<string, string>;
}

function makeMockFetch(
  responder: (call: MockCall) => { ok: boolean; status: number },
): { fetch: FetchLike; calls: MockCall[] } {
  const calls: MockCall[] = [];
  const fetch: FetchLike = async (url, init) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body = typeof init.body === "string" ? init.body : "";
    const call = { url, body, headers };
    calls.push(call);
    const r = responder(call);
    return { ok: r.ok, status: r.status, text: async () => "" };
  };
  return { fetch, calls };
}

test("shipToGuardian POSTs the envelope with bearer auth + JSON content type", async () => {
  const { fetch, calls } = makeMockFetch(() => ({ ok: true, status: 202 }));
  setFetchForTests(fetch);
  try {
    await shipToGuardian(makeEvent(), {
      endpoint: "http://localhost:3100/api/ingest",
      token: "lictor_test_token",
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "http://localhost:3100/api/ingest");
    assert.equal(calls[0]!.headers["Authorization"], "Bearer lictor_test_token");
    assert.equal(calls[0]!.headers["Content-Type"], "application/json");
    const body = JSON.parse(calls[0]!.body);
    assert.equal(body.envelope_version, "1");
    assert.equal(body.events[0].checkId, "airlock-shell");
    assert.equal(body.events[0].action, "blocked");
  } finally {
    setFetchForTests(null);
  }
});

test("shipToGuardian swallows errors — telemetry never breaks the agent", async () => {
  const fetch: FetchLike = async () => {
    throw new Error("ECONNREFUSED");
  };
  setFetchForTests(fetch);
  try {
    // Must resolve, not reject, even though fetch throws.
    await shipToGuardian(makeEvent(), {
      endpoint: "http://localhost:3100/api/ingest",
      token: "tok",
    });
  } finally {
    setFetchForTests(null);
  }
});
