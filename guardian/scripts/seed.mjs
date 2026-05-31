#!/usr/bin/env node
/**
 * Seed a friendly-tester account with realistic-looking incident data so
 * the W18 bug bash testers can poke at the dashboard without first
 * generating their own traffic.
 *
 * Usage:
 *   DATABASE_URL=... node scripts/seed.mjs --email tester@example.com
 *
 * Creates / upserts the account, generates ~60 incidents spread over the
 * last 7 days with realistic severity distribution + check_id mix.
 */

import { randomUUID } from "node:crypto";
import pg from "pg";

const { Client } = pg;

const args = process.argv.slice(2);
const emailArg = args[args.indexOf("--email") + 1];
const email = emailArg && emailArg !== "true" ? emailArg : "tester@lictor.test";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const client = new Client({ connectionString: url });
await client.connect();

// 1. Upsert account.
const ingestToken = `lictor_${randomUUID().replaceAll("-", "")}`;
const accountRes = await client.query(
  `INSERT INTO accounts (email, ingest_token)
   VALUES ($1, $2)
   ON CONFLICT (email) DO UPDATE SET updated_at = now()
   RETURNING id, ingest_token`,
  [email.toLowerCase(), ingestToken],
);
const accountId = accountRes.rows[0].id;
const finalToken = accountRes.rows[0].ingest_token;

// 2. Ensure stripe_customers row exists (preview tier).
await client.query(
  `INSERT INTO stripe_customers (account_id)
   VALUES ($1)
   ON CONFLICT (account_id) DO NOTHING`,
  [accountId],
);

// 3. Generate ~60 incidents spread over the last 7 days.
//    Mix of severities + check_ids that mirrors realistic traffic.

const severityWeights = [
  ["info", 0.30],
  ["low", 0.15],
  ["medium", 0.30],
  ["high", 0.20],
  ["critical", 0.05],
];

const checkScenarios = [
  // [check_id, phase, [title-templates]]
  ["prompt-injection", "preflight", [
    "Prompt injection — 1 pattern in 1 category (direct-override)",
    "Prompt injection — 2 patterns in 2 categories (direct-override, jailbreak)",
    "Prompt injection — 3 patterns in 3 categories (direct-override, authority-impersonation, jailbreak)",
    "Prompt injection — 1 pattern in 1 category (system-prompt-extraction)",
    "Prompt injection — 1 pattern in 1 category (delimiter-injection)",
  ]],
  ["pii-leak", "postflight", [
    "PII leak — 1 match in 1 category (email)",
    "PII leak — 2 matches in 2 categories (email, phone)",
    "PII leak — 1 match in 1 category (credit-card)",
    "PII leak — 3 matches in 2 categories (email, ip-address)",
    "PII leak — 1 match in 1 category (ssn)",
  ]],
  ["secrets-in-input", "preflight", [
    "Secret in input: OpenAI API key (or similar sk- token)",
    "Secret in input: GitHub personal access token",
    "Secret in input: AWS access key ID",
    "Secrets in input — 2 distinct credentials",
    "Secret in input: PostgreSQL connection string",
  ]],
];

const models = [
  ["openai", "gpt-4"],
  ["openai", "gpt-4o"],
  ["anthropic", "claude-3-sonnet"],
  ["anthropic", "claude-3-opus"],
];

function pickWeighted(weights) {
  const r = Math.random();
  let acc = 0;
  for (const [val, w] of weights) {
    acc += w;
    if (r < acc) return val;
  }
  return weights[weights.length - 1][0];
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomFingerprint() {
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < 16; i++) out += hex[Math.floor(Math.random() * 16)];
  return out;
}

const incidents = [];
const now = Date.now();
const sevenDays = 7 * 24 * 60 * 60 * 1000;

for (let i = 0; i < 60; i++) {
  const severity = pickWeighted(severityWeights);
  const [checkId, phase, titles] = pickRandom(checkScenarios);
  const title = pickRandom(titles);
  const [provider, name] = pickRandom(models);
  const tsOffset = Math.floor(Math.random() * sevenDays);
  const ts = new Date(now - tsOffset);
  const action = severity === "critical" ? "blocked" : Math.random() < 0.85 ? "logged" : "blocked";

  incidents.push({
    account_id: accountId,
    agent_id: `agent-seed-${(i % 4) + 1}`,
    ts,
    phase,
    check_id: checkId,
    severity,
    title,
    detail: `Seeded test incident for friendly-tester bug bash.\nCategory: ${checkId}\nGenerated at: ${new Date().toISOString()}\n\nThis is sample data — fingerprint below is random, not derived from real input.`,
    model_provider: provider,
    model_name: name,
    fingerprint: randomFingerprint(),
    action,
    sentinel_version: "0.1.0-alpha.0",
  });
}

// Bulk insert.
// NOTE: 13 columns per row — `sentinel_version` is NOT NULL in the schema, so
// it must be in both the column list and the flattened params. Omitting it
// crashes the whole seed with PG error 23502 (not-null violation).
const COLS = 13;
const valuesClauses = incidents
  .map(
    (_, i) =>
      "(" +
      Array.from({ length: COLS }, (_, j) => `$${i * COLS + j + 1}`).join(", ") +
      ")",
  )
  .join(", ");
const flat = incidents.flatMap((i) => [
  i.account_id, i.agent_id, i.ts, i.phase, i.check_id, i.severity,
  i.title, i.detail, i.model_provider, i.model_name, i.fingerprint, i.action,
  i.sentinel_version,
]);

await client.query(
  `INSERT INTO incidents
   (account_id, agent_id, ts, phase, check_id, severity, title, detail,
    model_provider, model_name, fingerprint, action, sentinel_version)
   VALUES ${valuesClauses}`,
  flat,
);

console.log(`✓ Seeded ${email}`);
console.log(`  Account ID: ${accountId}`);
console.log(`  Ingest token: ${finalToken}`);
console.log(`  Incidents: ${incidents.length} over the last 7 days`);
console.log("");
console.log("Sign in at http://localhost:3100/ and request a magic link for the email above.");

await client.end();
