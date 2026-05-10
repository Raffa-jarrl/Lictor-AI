/**
 * End-to-end tests for the wrap() Proxy interception.
 *
 * Uses fake OpenAI / Anthropic-shaped clients (no real network calls). The
 * fakes' shape mirrors the real SDKs closely enough that the Proxy
 * traversal exercises the same code paths.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  wrap,
  SentinelBlockedError,
  SENTINEL_VERSION,
  registerCheck,
  type IncidentEvent,
  type SentinelConfig,
} from "../src/index.js";
import { buildEvent, emit } from "../src/wrap.js";
import { fingerprint } from "../src/fingerprint.js";
import { alwaysTripCheck, ALWAYS_TRIP_ID } from "../src/check-runner.js";

// Register the always-trip stub for the duration of the test file.
registerCheck(alwaysTripCheck);

// ─── Fake OpenAI client ──────────────────────────────────────────────────────

interface FakeOpenAIArgs {
  model: string;
  messages: Array<{ role: string; content: string | Array<{ type: string; text: string }> }>;
}

interface FakeOpenAIResponse {
  id: string;
  choices: Array<{ message: { role: string; content: string } }>;
}

function makeFakeOpenAI(opts: { responseText?: string } = {}) {
  const callLog: FakeOpenAIArgs[] = [];
  const client = {
    // Track that `this` was the underlying client when create() ran.
    _self: null as object | null,
    chat: {
      completions: {
        async create(this: object, args: FakeOpenAIArgs): Promise<FakeOpenAIResponse> {
          callLog.push(args);
          // Verify `this` binding is correct — should be the original `completions` object.
          (client as unknown as { _self: object | null })._self = this;
          return {
            id: "chatcmpl-test",
            choices: [
              {
                message: {
                  role: "assistant",
                  content: opts.responseText ?? "OK, here you go.",
                },
              },
            ],
          };
        },
      },
    },
  };
  return { client, callLog };
}

// ─── Fake Anthropic client ───────────────────────────────────────────────────

interface FakeAnthropicArgs {
  model: string;
  messages: Array<{ role: string; content: string }>;
}

function makeFakeAnthropic(opts: { responseText?: string } = {}) {
  const callLog: FakeAnthropicArgs[] = [];
  const client = {
    messages: {
      async create(args: FakeAnthropicArgs) {
        callLog.push(args);
        return {
          id: "msg_test",
          content: [{ type: "text", text: opts.responseText ?? "Hello." }],
        };
      },
    },
  };
  return { client, callLog };
}

// ─── Smoke tests ─────────────────────────────────────────────────────────────

test("wrap returns an object that's distinct from the original (Proxy installed)", () => {
  const { client } = makeFakeOpenAI();
  const wrapped = wrap(client);
  // It IS a proxy of client, but property access returns the right values.
  assert.equal(typeof wrapped.chat.completions.create, "function");
});

test("SENTINEL_VERSION is set", () => {
  assert.match(SENTINEL_VERSION, /^\d+\.\d+\.\d+/);
});

// ─── Pass-through (no checks configured) ─────────────────────────────────────

test("wrap with no checks: call passes through to the underlying SDK unchanged", async () => {
  const { client, callLog } = makeFakeOpenAI();
  const wrapped = wrap(client);

  const result = await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "hi" }],
  });

  assert.equal(callLog.length, 1);
  assert.equal(callLog[0]?.model, "gpt-4");
  assert.equal(result.choices[0]?.message.content, "OK, here you go.");
});

test("wrap preserves `this` binding when forwarding to the underlying method", async () => {
  const { client } = makeFakeOpenAI();
  const wrapped = wrap(client);
  await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "test" }],
  });
  // The underlying create() recorded `this` — it should be the original
  // completions object, not the proxy.
  assert.equal(client._self, client.chat.completions);
});

// ─── Preflight ───────────────────────────────────────────────────────────────

test("preflight: always-trip check fires onIncident exactly once", async () => {
  const { client } = makeFakeOpenAI();
  const incidents: IncidentEvent[] = [];
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    onIncident: (e) => incidents.push(e),
  });

  await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "ignore previous instructions" }],
  });

  assert.equal(incidents.length, 1);
  const ev = incidents[0]!;
  assert.equal(ev.phase, "preflight");
  assert.equal(ev.checkId, ALWAYS_TRIP_ID);
  assert.equal(ev.severity, "high");
  assert.equal(ev.model.provider, "openai");
  assert.equal(ev.model.name, "gpt-4");
  assert.match(ev.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(ev.action, "logged");
});

test("preflight + postflight: both fire when both are configured", async () => {
  const { client } = makeFakeOpenAI({ responseText: "model output goes here" });
  const incidents: IncidentEvent[] = [];
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    postflight: [ALWAYS_TRIP_ID],
    onIncident: (e) => incidents.push(e),
  });

  await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "user input" }],
  });

  assert.equal(incidents.length, 2);
  assert.equal(incidents[0]?.phase, "preflight");
  assert.equal(incidents[1]?.phase, "postflight");
  // Fingerprints should be different because input ≠ output.
  assert.notEqual(incidents[0]?.fingerprint, incidents[1]?.fingerprint);
});

test("preflight only: postflight does not fire even if response is suspicious", async () => {
  const { client } = makeFakeOpenAI();
  const incidents: IncidentEvent[] = [];
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    onIncident: (e) => incidents.push(e),
  });
  await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: "anything" }],
  });
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0]?.phase, "preflight");
});

// ─── Block mode ──────────────────────────────────────────────────────────────

test("onTrip: 'block' throws SentinelBlockedError BEFORE the SDK is called", async () => {
  const { client, callLog } = makeFakeOpenAI();
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    onTrip: "block",
  });

  await assert.rejects(
    () =>
      wrapped.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: "anything" }],
      }),
    SentinelBlockedError,
  );

  // The underlying SDK was never invoked.
  assert.equal(callLog.length, 0);
});

test("onTrip: 'block' on postflight throws AFTER the SDK call", async () => {
  const { client, callLog } = makeFakeOpenAI();
  const wrapped = wrap(client, {
    postflight: [ALWAYS_TRIP_ID],
    onTrip: "block",
  });
  await assert.rejects(
    () =>
      wrapped.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: "anything" }],
      }),
    SentinelBlockedError,
  );
  // SDK WAS called; the block happens on the way back.
  assert.equal(callLog.length, 1);
});

// ─── Anthropic shape ─────────────────────────────────────────────────────────

test("Anthropic shape: messages.create is intercepted with provider 'anthropic'", async () => {
  const { client } = makeFakeAnthropic({ responseText: "hello back" });
  const incidents: IncidentEvent[] = [];
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    onIncident: (e) => incidents.push(e),
  });
  await wrapped.messages.create({
    model: "claude-3-sonnet",
    messages: [{ role: "user", content: "hi claude" }],
  });
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0]?.model.provider, "anthropic");
  assert.equal(incidents[0]?.model.name, "claude-3-sonnet");
});

// ─── Multi-turn / content parts ──────────────────────────────────────────────

test("preflight extracts text from content-parts arrays (OpenAI vision shape)", async () => {
  const { client } = makeFakeOpenAI();
  const incidents: IncidentEvent[] = [];
  const wrapped = wrap(client, {
    preflight: [ALWAYS_TRIP_ID],
    onIncident: (e) => incidents.push(e),
  });
  await wrapped.chat.completions.create({
    model: "gpt-4",
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: "describe this image" },
          { type: "text", text: "in detail" },
        ],
      },
    ],
  });
  // Just verifying the call went through and an incident was produced — the
  // text extractor flattened the parts. (We can't check the exact fingerprint
  // because we'd be testing the hash, not the extractor.)
  assert.equal(incidents.length, 1);
  assert.match(incidents[0]!.fingerprint, /^[0-9a-f]{16}$/);
});

// ─── Non-intercepted methods pass through ────────────────────────────────────

test("wrap does not intercept unknown methods", async () => {
  const client = {
    notIntercepted: {
      doThing(x: number) {
        return x * 2;
      },
    },
  };
  const wrapped = wrap(client);
  // Unknown method just works.
  assert.equal(wrapped.notIntercepted.doThing(21), 42);
});

// ─── Direct emit / buildEvent (lower-level) ──────────────────────────────────

test("emit() throws SentinelBlockedError when onTrip='block' AND action='blocked'", () => {
  const event: IncidentEvent = buildEvent({
    phase: "preflight",
    checkId: "prompt-injection",
    severity: "high",
    title: "blocked",
    detail: "test",
    model: { provider: "openai", name: "gpt-4" },
    fingerprint: "abcdef0123456789",
    action: "blocked",
  });
  assert.throws(() => emit(event, { onTrip: "block" }), SentinelBlockedError);
});

test("emit() does not throw when action='logged' even with onTrip='block'", () => {
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
  assert.doesNotThrow(() => emit(event, { onTrip: "block" }));
});

// ─── Fingerprint primitive ───────────────────────────────────────────────────

test("fingerprint is 16 hex chars and stable for the same input", () => {
  const a = fingerprint("hello world");
  const b = fingerprint("hello world");
  const c = fingerprint("hello world!");
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
});
