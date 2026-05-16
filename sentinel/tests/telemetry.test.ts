/**
 * Telemetry tests — without a real Guardian. Uses setFetchForTests() to
 * inject a mock fetch and verify behaviour.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildEnvelope,
  sendToGuardian,
  setFetchForTests,
  pendingCount,
  type FetchLike,
} from "../src/telemetry.js";
import { buildEvent } from "../src/wrap.js";
import type { IncidentEvent } from "../src/index.js";

function makeEvent(): IncidentEvent {
  return buildEvent({
    phase: "preflight",
    checkId: "prompt-injection",
    severity: "high",
    title: "test event",
    detail: "test detail",
    model: { provider: "openai", name: "gpt-4" },
    fingerprint: "0123456789abcdef",
    action: "logged",
  });
}

// Helper: capturing mock fetch.
interface MockCall {
  url: string;
  body: string;
  headers: Record<string, string>;
}

function makeMockFetch(
  responder: (call: MockCall) => { ok: boolean; status: number; text?: string },
): { fetch: FetchLike; calls: MockCall[] } {
  const calls: MockCall[] = [];
  const fetch: FetchLike = async (url, init) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body = typeof init.body === "string" ? init.body : "";
    const call = { url, body, headers };
    calls.push(call);
    const r = responder(call);
    return {
      ok: r.ok,
      status: r.status,
      text: async () => r.text ?? "",
    };
  };
  return { fetch, calls };
}

test("buildEnvelope wraps the event correctly", () => {
  const ev = makeEvent();
  const env = buildEnvelope(ev);
  assert.equal(env.envelope_version, "1");
  assert.match(env.sentinel_version, /^\d+\.\d+\.\d+/);
  assert.equal(env.events.length, 1);
  assert.equal(env.events[0]!.title, "test event");
});

test("sendToGuardian POSTs with bearer auth + JSON content type", async () => {
  const { fetch, calls } = makeMockFetch(() => ({ ok: true, status: 202 }));
  setFetchForTests(fetch);
  try {
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "tok_test_abcdef",
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://app.lictorai.com/api/ingest");
    assert.equal(calls[0]!.headers["Authorization"], "Bearer tok_test_abcdef");
    assert.equal(calls[0]!.headers["Content-Type"], "application/json");
    const body = JSON.parse(calls[0]!.body);
    assert.equal(body.envelope_version, "1");
    assert.equal(body.events[0].title, "test event");
  } finally {
    setFetchForTests(null);
  }
});

test("sendToGuardian retries on 5xx until success", async () => {
  let calls = 0;
  const { fetch } = makeMockFetch(() => {
    calls++;
    if (calls < 3) return { ok: false, status: 502 };
    return { ok: true, status: 202 };
  });
  setFetchForTests(fetch);
  try {
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "tok",
      timeoutMs: 1000,
    });
    assert.equal(calls, 3, "expected 2 retries + 1 success");
  } finally {
    setFetchForTests(null);
  }
});

test("sendToGuardian does NOT retry on 4xx (permanent failure)", async () => {
  let calls = 0;
  const { fetch } = makeMockFetch(() => {
    calls++;
    return { ok: false, status: 401 };
  });
  setFetchForTests(fetch);
  try {
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "bad-token",
      timeoutMs: 1000,
    });
    assert.equal(calls, 1, "expected exactly one call for 4xx");
  } finally {
    setFetchForTests(null);
  }
});

test("sendToGuardian gives up after MAX_RETRIES + 1 attempts", async () => {
  let calls = 0;
  const { fetch } = makeMockFetch(() => {
    calls++;
    return { ok: false, status: 503 };
  });
  setFetchForTests(fetch);
  try {
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "tok",
      timeoutMs: 1000,
    });
    // MAX_RETRIES=3 → 4 total attempts (initial + 3 retries)
    assert.equal(calls, 4);
  } finally {
    setFetchForTests(null);
  }
});

test("sendToGuardian retries on network errors (thrown by fetch)", async () => {
  let calls = 0;
  const fetch: FetchLike = async () => {
    calls++;
    if (calls < 2) throw new Error("ECONNRESET");
    return { ok: true, status: 202, text: async () => "" };
  };
  setFetchForTests(fetch);
  try {
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "tok",
      timeoutMs: 1000,
    });
    assert.equal(calls, 2);
  } finally {
    setFetchForTests(null);
  }
});

test("sendToGuardian decrements pendingCount on completion", async () => {
  const { fetch } = makeMockFetch(() => ({ ok: true, status: 202 }));
  setFetchForTests(fetch);
  try {
    assert.equal(pendingCount(), 0);
    await sendToGuardian(makeEvent(), {
      endpoint: "https://app.lictorai.com/api/ingest",
      token: "tok",
    });
    assert.equal(pendingCount(), 0, "pendingCount should return to 0 after send");
  } finally {
    setFetchForTests(null);
  }
});
