/**
 * Smoke tests for the v0.1 wrap() API.
 *
 * v0.1 expectations:
 *   - wrap() compiles with a real OpenAI/Anthropic shape and returns a
 *     usable client.
 *   - Checks are stubbed (always pass), so wrap()'d calls behave identically
 *     to unwrapped calls.
 *   - Phase 1 will replace these tests with real check-trip integration tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { wrap, SentinelBlockedError, SENTINEL_VERSION } from "../src/index.js";
import type { IncidentEvent, SentinelConfig } from "../src/index.js";
import { buildEvent, emit } from "../src/wrap.js";
import { fingerprint } from "../src/fingerprint.js";

test("wrap returns the client unchanged at v0.1", () => {
  const fakeClient = { chat: { completions: { create: async () => ({}) } } };
  const wrapped = wrap(fakeClient, { preflight: ["prompt-injection"] });
  assert.equal(wrapped, fakeClient);
});

test("wrap accepts an empty config", () => {
  const c = {};
  const w = wrap(c);
  assert.equal(w, c);
});

test("SENTINEL_VERSION is set", () => {
  assert.match(SENTINEL_VERSION, /^\d+\.\d+\.\d+/);
});

test("fingerprint is 16 hex chars and stable for the same input", () => {
  const a = fingerprint("hello world");
  const b = fingerprint("hello world");
  const c = fingerprint("hello world!");
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("buildEvent fills agent + version + ts", () => {
  const e = buildEvent({
    phase: "preflight",
    checkId: "prompt-injection",
    severity: "high",
    title: "test",
    detail: "test detail",
    model: { provider: "openai", name: "gpt-4" },
    fingerprint: "0000000000000000",
    action: "logged",
  });
  assert.match(e.agentId, /^agent-[0-9a-f]+$/);
  assert.equal(e.sentinelVersion, SENTINEL_VERSION);
  assert.match(e.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test("emit() throws SentinelBlockedError when onTrip is 'block' and action is 'blocked'", () => {
  const event: IncidentEvent = buildEvent({
    phase: "preflight",
    checkId: "prompt-injection",
    severity: "high",
    title: "blocked input",
    detail: "test",
    model: { provider: "openai", name: "gpt-4" },
    fingerprint: "abcdef0123456789",
    action: "blocked",
  });
  const config: SentinelConfig = { onTrip: "block" };
  assert.throws(() => emit(event, config), SentinelBlockedError);
});

test("emit() does not throw when action is 'logged'", () => {
  const event: IncidentEvent = buildEvent({
    phase: "preflight",
    checkId: "prompt-injection",
    severity: "high",
    title: "logged",
    detail: "test",
    model: { provider: "openai", name: "gpt-4" },
    fingerprint: "abcdef0123456789",
    action: "logged",
  });
  let received: IncidentEvent | undefined;
  emit(event, { onTrip: "block", onIncident: (e) => { received = e; } });
  assert.equal(received?.title, "logged");
});

test("emit() invokes onIncident with the event", () => {
  const event: IncidentEvent = buildEvent({
    phase: "postflight",
    checkId: "pii-leak",
    severity: "medium",
    title: "test",
    detail: "test",
    model: { provider: "anthropic", name: "claude-3-sonnet" },
    fingerprint: "fedcba9876543210",
    action: "logged",
  });
  const calls: IncidentEvent[] = [];
  emit(event, { onIncident: (e) => calls.push(e) });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.checkId, "pii-leak");
});
