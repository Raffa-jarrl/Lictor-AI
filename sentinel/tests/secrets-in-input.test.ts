/**
 * Tests for the secrets-in-input check.
 *
 * Mirrors lictor-core/src/checks/secrets.rs test coverage. Same patterns,
 * same dedup-by-exact-value, same severity ranking. If you add a pattern
 * to one, mirror it in the other and add tests on both sides.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  secretsInInputCheck,
  SECRET_PATTERNS,
} from "../src/checks/secrets-in-input.js";

function run(text: string) {
  return secretsInInputCheck.run(text, "preflight");
}

test("catalog has 15 patterns (mirrors lictor-core)", () => {
  assert.equal(SECRET_PATTERNS.length, 15);
});

test("empty input returns PASS", () => {
  assert.equal(run("").tripped, false);
});

test("clean text returns PASS", () => {
  const r = run("Can you help me debug this Python function?");
  assert.equal(r.tripped, false);
});

// ─── POSITIVE: each pattern trips on its target string ───────────────────────

const POSITIVES: Array<[string, string, "critical" | "high" | "medium" | "low" | "info"]> = [
  // Google API key
  ["My key is AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7", "Google", "high"],

  // Anthropic
  [
    "Auth: sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM",
    "Anthropic",
    "critical",
  ],

  // OpenAI legacy
  ["OPENAI_KEY=sk-ABCDEFGHIJabcdefghij1234567890", "OpenAI", "critical"],

  // OpenAI sk-proj-
  ["sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII is leaked", "OpenAI", "critical"],

  // Stripe live secret
  ["Stripe: sk_live_AAAABBBBCCCCDDDDEEEEFFFF", "Stripe live secret", "critical"],

  // Stripe test
  ["Test mode: sk_test_AAAABBBBCCCCDDDDEEEEFFFF", "Stripe test", "medium"],

  // Stripe publishable
  ["Public key: pk_live_AAAABBBBCCCCDDDDEEEEFFFF for the form", "Stripe live publishable", "info"],

  // GitHub PAT
  ["GH token: ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII", "GitHub personal", "critical"],

  // Slack
  ["Slack: xoxb-12345-abcdef-1234567890", "Slack", "high"],

  // AWS
  ["AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "AWS", "high"],

  // Private key
  [
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC...\n-----END RSA PRIVATE KEY-----",
    "Private key",
    "critical",
  ],

  // MongoDB
  [
    "Connection: mongodb+srv://admin:hunter2@cluster0.example.mongodb.net/db",
    "MongoDB",
    "critical",
  ],

  // Postgres
  ["DB: postgres://user:password@db.example.com:5432/prod", "PostgreSQL", "critical"],

  // Redis
  ["redis://default:password@redis.example.com:6379", "Redis", "high"],
];

for (const [input, expectedLabel, expectedSeverity] of POSITIVES) {
  test(`POSITIVE [${expectedLabel}]: ${input.slice(0, 50)}…`, () => {
    const r = run(input);
    assert.equal(r.tripped, true, `expected trip for: ${input}`);
    assert.ok(
      r.title.includes(expectedLabel) || r.detail.includes(expectedLabel),
      `expected ${expectedLabel} in result; got title "${r.title}", detail "${r.detail.slice(0, 200)}"`,
    );
    assert.equal(
      r.severity,
      expectedSeverity,
      `expected severity ${expectedSeverity}, got ${r.severity} for: ${input}`,
    );
  });
}

// ─── NEGATIVE: similar-looking inputs do NOT trip ────────────────────────────

const NEGATIVES: string[] = [
  "Please review my pull request.",
  "The variable name is api_key but the value is loaded from env.",
  "AIzaXXXX is too short to be a real key.", // 4 chars after AIza, real key needs 35
  "sk-XX is too short.",
  "AKIA12 is too short.",
  "ghp_short is too short.",
  "Use the OpenAI API to chat.", // mentions OpenAI but no key
  "Just regular text that talks about secrets and tokens.",
  "Postgres is a database engine.",
  "Use this URL: https://postgres.example.com/docs", // no creds, looks similar
];

for (const [i, input] of NEGATIVES.entries()) {
  test(`NEGATIVE [${i}]: ${input.slice(0, 60)}…`, () => {
    const r = run(input);
    assert.equal(
      r.tripped,
      false,
      `expected PASS, got trip "${r.title}" for: ${input}`,
    );
  });
}

// ─── Dedup behavior ──────────────────────────────────────────────────────────

test("same Anthropic key matched by OpenAI's broader pattern is reported once", () => {
  const r = run(
    "auth: sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM",
  );
  assert.equal(r.tripped, true);
  // Anthropic comes first in the pattern array; its label wins.
  assert.ok(r.title.includes("Anthropic"));
  assert.equal(r.severity, "critical");
  // Detail should only enumerate ONE match.
  const matchCount = (r.detail.match(/\[(?:critical|high|medium|low|info)\]/g) ?? []).length;
  assert.equal(matchCount, 1, `expected one match; got ${matchCount}: ${r.detail}`);
});

test("two distinct secrets produce two entries", () => {
  const r = run(
    "AWS=AKIAIOSFODNN7EXAMPLE and Stripe=sk_live_AAAABBBBCCCCDDDDEEEEFFFF",
  );
  assert.equal(r.tripped, true);
  const matchCount = (r.detail.match(/\[(?:critical|high|medium|low|info)\]/g) ?? []).length;
  assert.equal(matchCount, 2, `expected two matches; got ${matchCount}: ${r.detail}`);
  assert.equal(r.severity, "critical"); // max(high, critical)
});
