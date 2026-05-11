/**
 * Tests for the pii-leak check.
 *
 * POSITIVE — known PII strings that MUST trip the check.
 * NEGATIVE — similar-looking content that must NOT trip (no false positives).
 *
 * The Luhn check on credit-card matches is the most important false-positive
 * defense — random 16-digit numbers should not produce critical findings.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { piiLeakCheck, PII_PATTERNS } from "../src/checks/pii-leak.js";

function run(text: string) {
  return piiLeakCheck.run(text, "postflight");
}

test("PII catalog has expected categories", () => {
  const cats = new Set(PII_PATTERNS.map((p) => p.category));
  for (const expected of ["email", "phone", "ssn", "credit-card", "iban", "ip-address", "postal-address"]) {
    assert.ok(cats.has(expected as never), `missing category: ${expected}`);
  }
});

test("empty input returns PASS", () => {
  assert.equal(run("").tripped, false);
});

test("clean prose returns PASS", () => {
  const r = run(
    "Roman emperors ruled an empire that stretched from Britain to Mesopotamia. Their legacy influenced governance for centuries.",
  );
  assert.equal(r.tripped, false);
});

// ─── POSITIVE: real PII formats trip ─────────────────────────────────────────

const POSITIVES: Array<[string, string, "critical" | "high" | "medium" | "low"]> = [
  // Email
  ["The CEO's email is john.doe@example.com — please reach out.", "email", "medium"],
  ["Contact support at help+billing@acme.co.uk", "email", "medium"],

  // SSN (valid format, valid prefix)
  ["His SSN is 123-45-6789, please verify.", "ssn", "critical"],
  ["The record showed 234-56-7890 as the identifier.", "ssn", "critical"],

  // Credit card (Luhn-valid)
  // 4111-1111-1111-1111 is the universal Luhn-valid test card.
  ["Charge to 4111-1111-1111-1111 for $50.", "credit-card", "critical"],
  ["Mastercard 5500 0000 0000 0004 on file.", "credit-card", "critical"],

  // IBAN
  ["Wire to GB82WEST12345698765432 by Friday.", "iban", "critical"],
  ["German account: DE89370400440532013000", "iban", "critical"],

  // Phone (with required format)
  ["Call (555) 867-5309 if you have questions.", "phone", "medium"],
  ["My number is 555-867-5309.", "phone", "medium"],
  ["International: +1 555 867 5309", "phone", "medium"],

  // IP
  ["The server is at 192.168.1.100.", "ip-address", "low"],
  ["IPv6 route: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip-address", "low"],

  // Address
  ["Ship to 123 Main Street, Boston, MA 02101.", "postal-address", "medium"],
];

for (const [input, expectedCategory, expectedSeverity] of POSITIVES) {
  test(`POSITIVE [${expectedCategory}/${expectedSeverity}]: ${input.slice(0, 60)}…`, () => {
    const r = run(input);
    assert.equal(r.tripped, true, `expected trip for: ${input}`);
    assert.ok(
      r.title.includes(expectedCategory) || r.detail.includes(expectedCategory),
      `expected category ${expectedCategory} in result; got title: ${r.title}`,
    );
  });
}

// ─── NEGATIVE: similar-looking content does NOT trip ─────────────────────────

const NEGATIVES: string[] = [
  // Plain prose with no PII
  "The Roman Empire reached its peak in the 2nd century AD.",
  "Please summarize this article for me.",

  // 16-digit number that FAILS Luhn (so not a valid CC)
  "Order #1234567890123456 was shipped yesterday.", // 1234567890123456 — Luhn=10? actually let me think. We rely on the Luhn validator to filter this.

  // 10-digit number WITHOUT phone formatting (plain number)
  "The product ID is 5558675309 in our catalog.",

  // SSN-shaped but invalid prefix (000 or 666 or 9xx)
  "The test value was 000-12-3456 in the example.",
  "Sample placeholder: 666-12-3456",
  "Numeric token 999-12-3456 was generated.",

  // Generic "@" but not email shape
  "See @username for more info.",
  "The file path is foo/bar@1.2.3/index.",

  // Phone-shaped but in code/version contexts
  "Version 2.5.3-1234 released today.",
  "Run: cargo install --version 0.1.0",

  // Address-like but missing required parts (no state, no ZIP)
  "We met at 123 Main Street downtown.",

  // IBAN-shaped but too short (under 11 alphanumerics after 4 leading)
  "Reference code GB12ABC.",
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

// ─── Severity correctness ─────────────────────────────────────────────────────

test("SSN produces CRITICAL severity", () => {
  const r = run("My SSN is 123-45-6789.");
  assert.equal(r.tripped, true);
  assert.equal(r.severity, "critical");
});

test("Email alone produces MEDIUM severity", () => {
  const r = run("Reach out to alice@example.com");
  assert.equal(r.tripped, true);
  assert.equal(r.severity, "medium");
});

test("Multiple PII categories: severity = max", () => {
  const r = run("Email alice@example.com, SSN 123-45-6789, card 4111-1111-1111-1111.");
  assert.equal(r.tripped, true);
  assert.equal(r.severity, "critical");
});

// ─── Luhn defense ─────────────────────────────────────────────────────────────

test("Random 16-digit non-Luhn-valid number does NOT trip credit-card", () => {
  // 1234567890123456 — Luhn check fails (sum % 10 ≠ 0).
  const r = run("Track package 1234567890123456 in our system.");
  // It may match the wider pattern but Luhn rejects it, so no trip on credit-card.
  // Verify nothing critical fires from it.
  if (r.tripped) {
    assert.notEqual(r.severity, "critical", `unexpected critical for non-Luhn number: ${r.title}`);
  }
});

test("Test credit card 4111 1111 1111 1111 is detected (Luhn-valid)", () => {
  const r = run("Use 4111 1111 1111 1111 for testing.");
  assert.equal(r.tripped, true);
  assert.equal(r.severity, "critical");
});

// ─── Performance ──────────────────────────────────────────────────────────────

test("scans 100 KB of benign prose in under 500ms", () => {
  const big = "The Roman Empire and its emperors. ".repeat(3000);
  const t0 = Date.now();
  const r = run(big);
  const elapsed = Date.now() - t0;
  assert.equal(r.tripped, false);
  assert.ok(elapsed < 500, `pii-leak should be <500ms on 100KB benign text; was ${elapsed}ms`);
});
