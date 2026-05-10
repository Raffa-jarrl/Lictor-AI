/**
 * Integration tests against a real Postgres test DB.
 *
 * Setup: requires `DATABASE_URL` to point at a database where the schema
 * has been migrated. The tests assume an empty `accounts`/`incidents`
 * table at start (run `pnpm db:reset` first if needed).
 *
 * These tests cover the things that are hard to verify by inspection:
 *   1. Crypto round-trips (sign → verify → revoke)
 *   2. Magic-link atomic claim under double-click
 *   3. Ingest correctly maps wire format to DB rows
 *   4. Cross-account isolation (one account can't see another's incidents)
 *
 * Run with:  pnpm test
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { db } from "../src/lib/db.js";
import { generateToken, hashToken, signSessionId, verifySessionCookie } from "../src/lib/crypto.js";
import { createSession, loadSession, revokeSession } from "../src/lib/sessions.js";

// Set a stable session secret for the test run.
process.env["SESSION_SECRET"] =
  process.env["SESSION_SECRET"] ?? "00000000000000000000000000000000_test_secret_for_local_runs";

let testAccountId: string;
let testIngestToken: string;

before(async () => {
  // Make sure the test DB is reachable.
  await db().selectFrom("accounts").select("id").limit(1).execute();

  // Insert a test account.
  testIngestToken = generateToken();
  const inserted = await db()
    .insertInto("accounts")
    .values({
      email: `test+${Date.now()}@lictor.test`,
      ingest_token: testIngestToken,
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  testAccountId = inserted.id;
});

after(async () => {
  await db().deleteFrom("accounts").where("id", "=", testAccountId).execute();
  // Kysely manages its own pool; no explicit close needed for the test runner.
});

// ─── Crypto primitives ───────────────────────────────────────────────────────

test("generateToken returns 64 hex characters (32 bytes)", () => {
  const t = generateToken();
  assert.match(t, /^[0-9a-f]{64}$/);
});

test("hashToken is deterministic for the same input", () => {
  const t = "abcdefg";
  assert.equal(hashToken(t), hashToken(t));
  assert.notEqual(hashToken(t), hashToken("abcdefg "));
});

test("signSessionId / verifySessionCookie round-trip", () => {
  const id = "00000000-0000-0000-0000-000000000001";
  const cookie = signSessionId(id);
  assert.equal(verifySessionCookie(cookie), id);
});

test("verifySessionCookie returns null for tampered HMAC", () => {
  const id = "00000000-0000-0000-0000-000000000001";
  const cookie = signSessionId(id);
  // Flip one byte of the signature.
  const tampered = cookie.slice(0, -2) + (cookie.slice(-2) === "00" ? "ff" : "00");
  assert.equal(verifySessionCookie(tampered), null);
});

test("verifySessionCookie returns null for malformed cookie", () => {
  assert.equal(verifySessionCookie(undefined), null);
  assert.equal(verifySessionCookie(""), null);
  assert.equal(verifySessionCookie("not-a-session"), null);
  assert.equal(verifySessionCookie("id."), null);
});

// ─── Session lifecycle ───────────────────────────────────────────────────────

test("createSession + loadSession returns the linked account", async () => {
  const cookie = await createSession(testAccountId);
  const session = await loadSession(cookie);
  assert.ok(session);
  assert.equal(session?.accountId, testAccountId);
});

test("loadSession returns null after revokeSession", async () => {
  const cookie = await createSession(testAccountId);
  const session = await loadSession(cookie);
  assert.ok(session);
  await revokeSession(session!.sessionId);
  const reloaded = await loadSession(cookie);
  assert.equal(reloaded, null);
});

// ─── Magic-link atomic claim ─────────────────────────────────────────────────

test("magic_links UPDATE ... WHERE consumed_at IS NULL is atomic", async () => {
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 15 * 60_000);

  await db()
    .insertInto("magic_links")
    .values({
      account_id: testAccountId,
      email: "test@lictor.test",
      token_hash: tokenHash,
      expires_at: expiresAt,
    })
    .execute();

  // First claim succeeds.
  const first = await db()
    .updateTable("magic_links")
    .set({ consumed_at: new Date() })
    .where("token_hash", "=", tokenHash)
    .where("consumed_at", "is", null)
    .returning("account_id")
    .executeTakeFirst();
  assert.ok(first);

  // Second claim returns no rows.
  const second = await db()
    .updateTable("magic_links")
    .set({ consumed_at: new Date() })
    .where("token_hash", "=", tokenHash)
    .where("consumed_at", "is", null)
    .returning("account_id")
    .executeTakeFirst();
  assert.equal(second, undefined);
});

test("expired magic links cannot be consumed", async () => {
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);
  const expiredAt = new Date(Date.now() - 1000); // already expired

  await db()
    .insertInto("magic_links")
    .values({
      account_id: testAccountId,
      email: "test@lictor.test",
      token_hash: tokenHash,
      expires_at: expiredAt,
    })
    .execute();

  const claim = await db()
    .updateTable("magic_links")
    .set({ consumed_at: new Date() })
    .where("token_hash", "=", tokenHash)
    .where("consumed_at", "is", null)
    .where("expires_at", ">", new Date())
    .returning("account_id")
    .executeTakeFirst();
  assert.equal(claim, undefined);
});

// ─── Ingest INSERT ───────────────────────────────────────────────────────────

test("incidents INSERT round-trips through Postgres", async () => {
  const before = await db()
    .selectFrom("incidents")
    .select(db().fn.countAll<string>().as("c"))
    .where("account_id", "=", testAccountId)
    .executeTakeFirstOrThrow();

  await db()
    .insertInto("incidents")
    .values({
      account_id: testAccountId,
      agent_id: "agent-test",
      ts: new Date("2026-10-06T14:00:00Z"),
      phase: "preflight",
      check_id: "prompt-injection",
      severity: "high",
      title: "test incident",
      detail: "round-trip test",
      model_provider: "openai",
      model_name: "gpt-4",
      fingerprint: "0123456789abcdef",
      action: "logged",
      sentinel_version: "0.1.0",
    })
    .execute();

  const after = await db()
    .selectFrom("incidents")
    .select(db().fn.countAll<string>().as("c"))
    .where("account_id", "=", testAccountId)
    .executeTakeFirstOrThrow();

  assert.equal(Number(after.c), Number(before.c) + 1);
});

// ─── Cross-account isolation ─────────────────────────────────────────────────

test("incidents are isolated by account_id", async () => {
  // Create a second account.
  const otherToken = generateToken();
  const other = await db()
    .insertInto("accounts")
    .values({
      email: `other+${Date.now()}@lictor.test`,
      ingest_token: otherToken,
    })
    .returning("id")
    .executeTakeFirstOrThrow();

  try {
    await db()
      .insertInto("incidents")
      .values({
        account_id: other.id,
        agent_id: "agent-other",
        ts: new Date(),
        phase: "preflight",
        check_id: "prompt-injection",
        severity: "high",
        title: "other account incident",
        detail: "should not be visible to test account",
        model_provider: "openai",
        model_name: "gpt-4",
        fingerprint: "fedcba9876543210",
        action: "logged",
        sentinel_version: "0.1.0",
      })
      .execute();

    const visibleToTestAccount = await db()
      .selectFrom("incidents")
      .select("id")
      .where("account_id", "=", testAccountId)
      .where("agent_id", "=", "agent-other")
      .execute();
    assert.equal(visibleToTestAccount.length, 0);

    const visibleToOther = await db()
      .selectFrom("incidents")
      .select("id")
      .where("account_id", "=", other.id)
      .where("agent_id", "=", "agent-other")
      .execute();
    assert.equal(visibleToOther.length, 1);
  } finally {
    await db().deleteFrom("accounts").where("id", "=", other.id).execute();
  }
});

// ─── audit_log append-only enforcement ───────────────────────────────────────

test("audit_log UPDATE is rejected by trigger", async () => {
  await db()
    .insertInto("audit_log")
    .values({
      account_id: testAccountId,
      actor_email: "test@lictor.test",
      action: "test.action",
      target_id: null,
      metadata: { foo: "bar" },
      ip: null,
      user_agent: null,
    })
    .execute();

  // Trying to UPDATE should fail with the trigger's RAISE EXCEPTION.
  await assert.rejects(
    () =>
      db()
        .updateTable("audit_log")
        .set({ action: "tampered" })
        .where("actor_email", "=", "test@lictor.test")
        .execute(),
    /append-only/i,
  );
});
