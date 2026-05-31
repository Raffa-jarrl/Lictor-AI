/**
 * redact.test.ts — the audit trail must never become a new place secrets leak.
 *
 * Airlock writes a plain-English log of what the AI did. If the agent ran
 * `export STRIPE_KEY=sk_live_…`, the log must show that a key was set, NOT the
 * key itself. These tests pin that contract: recognizable secret shapes are
 * masked, the recognizable scheme prefix survives (so a human can tell WHAT
 * kind of secret it was), and the original value never appears in the output.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { redactSecrets, containsSecret } from "../src/index.js";

test("redactSecrets masks a Stripe live secret key but keeps its prefix", () => {
  // split so the literal secret-shape never appears in source (test value identical at runtime)
  const key = "sk_live_" + "51HxQabsuperSECRETvalue1234567890";
  const out = redactSecrets(`export STRIPE_KEY=${key}`);

  // The full secret value must be gone.
  assert.ok(!out.includes(key), "raw secret leaked into redacted output");
  // The recognizable scheme prefix survives so a human can identify the kind.
  assert.ok(out.includes("sk_live_"), "scheme prefix should be preserved");
  // A redaction marker is present.
  assert.match(out, /redacted/);
});

test("redactSecrets masks an OpenAI key, an AWS access key id, and a GitHub PAT", () => {
  const openai = "sk-" + "proj-abcdEFGH1234ijklMNOP5678qrstUVWX";
  const aws = "AKIA" + "IOSFODNN7EXAMPLE";
  const ghp = "ghp_" + "A".repeat(36);
  const out = redactSecrets(`key=${openai} aws=${aws} gh=${ghp}`);

  assert.ok(!out.includes(openai), "OpenAI key leaked");
  assert.ok(!out.includes(aws), "AWS access key id leaked");
  assert.ok(!out.includes(ghp), "GitHub PAT leaked");
});

test("redactSecrets masks a generic SECRET=value assignment it doesn't have a scheme for", () => {
  const out = redactSecrets("MY_DB_PASSWORD=hunter2horsebattery");
  assert.ok(!out.includes("hunter2horsebattery"), "generic secret value leaked");
  // Name + separator are kept; only the value is masked.
  assert.match(out, /MY_DB_PASSWORD=/);
});

test("redactSecrets is a no-op on text with no secrets", () => {
  const clean = "git status && npm run build";
  assert.equal(redactSecrets(clean), clean);
});

test("containsSecret detects a secret and is false on clean text", () => {
  assert.equal(containsSecret("token=sk_live_" + "51HxQabcdefghi1234567890"), true);
  assert.equal(containsSecret("ls -la /tmp"), false);
});
