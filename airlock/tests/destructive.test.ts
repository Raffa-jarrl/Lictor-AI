/**
 * destructive.test.ts — the #1 fear: "the AI will delete something I can't get
 * back." These tests pin the destructive-command rule: catastrophic +
 * irreversible shapes classify as block, and recoverable-but-surprising ones
 * warn. Precision is the product — a guard that screams at every `git reset`
 * gets turned off, so we also assert a routine command stays silent.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  evaluateAction,
  shellAction,
  toolAction,
  ALL_RULES,
  type RuleHit,
} from "../src/index.js";

function hitFor(text: string): { decision: string; severity: string; hits: RuleHit[] } {
  return evaluateAction(shellAction(text), ALL_RULES);
}

test("`rm -rf /` is classified destructive and blocked at critical severity", () => {
  const ev = hitFor("rm -rf /");
  assert.equal(ev.decision, "block");
  assert.equal(ev.severity, "critical");
  assert.ok(
    ev.hits.some((h) => h.ruleId === "destructive-command"),
    "expected a destructive-command hit",
  );
});

test("`rm -rf build/` (recursive force-delete of a named path) is blocked high", () => {
  const ev = hitFor("rm -rf build/");
  assert.equal(ev.decision, "block");
  // Not the catastrophic root/wildcard shape — high, not critical.
  assert.equal(ev.severity, "high");
  assert.ok(ev.hits.some((h) => h.title.includes("Recursive force-delete")));
});

test("`DROP TABLE users` is classified destructive and blocked at critical", () => {
  const ev = hitFor("psql -c 'DROP TABLE users'");
  assert.equal(ev.decision, "block");
  assert.equal(ev.severity, "critical");
  assert.ok(
    ev.hits.some((h) => h.ruleId === "destructive-command" && /DROP TABLE/i.test(h.title)),
  );
});

test("`git push --force` blocks, but `--force-with-lease` only warns", () => {
  const force = hitFor("git push --force origin main");
  assert.equal(force.decision, "block");

  const lease = hitFor("git push --force-with-lease origin main");
  assert.equal(lease.decision, "warn");
  // The guard must prevent the blanket force-push pattern from also firing.
  assert.ok(
    !lease.hits.some((h) => h.title.includes("Force-push (git push --force)")),
    "--force-with-lease should not trip the hard force-push rule",
  );
});

test("a routine command produces no hits (allow / info)", () => {
  const ev = hitFor("git status");
  assert.equal(ev.decision, "allow");
  assert.equal(ev.severity, "info");
  assert.equal(ev.hits.length, 0);
});

test("an MCP tool whose name implies destruction warns even with no shell command", () => {
  const ev = evaluateAction(toolAction("delete_database", { name: "analytics" }), ALL_RULES);
  assert.equal(ev.decision, "warn");
  assert.ok(ev.hits.some((h) => h.ruleId === "destructive-command"));
});
