#!/usr/bin/env node
/**
 * Migration runner. Applies SQL files in `migrations/` in order, tracking
 * applied migrations in a `_migrations` table.
 *
 * Usage:
 *   node scripts/migrate.mjs           # apply pending migrations
 *   node scripts/migrate.mjs --reset   # drop + recreate (DANGEROUS, dev only)
 */

import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Client } = pg;

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, "..", "migrations");

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const reset = process.argv.includes("--reset");

const client = new Client({ connectionString: url });
await client.connect();

if (reset) {
  if (!url.includes("localhost") && !url.includes("127.0.0.1")) {
    console.error("--reset is only allowed on localhost connections (safety guard)");
    process.exit(2);
  }
  console.warn("⚠  Dropping all tables (--reset on localhost only)");
  await client.query(`
    DROP TABLE IF EXISTS audit_log, incidents, sessions, magic_links, accounts, _migrations CASCADE;
  `);
}

await client.query(`
  CREATE TABLE IF NOT EXISTS _migrations (
    name        text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
  );
`);

const files = (await readdir(MIGRATIONS_DIR))
  .filter((f) => f.endsWith(".sql"))
  .sort();

const applied = new Set(
  (await client.query("SELECT name FROM _migrations")).rows.map((r) => r.name),
);

let count = 0;
for (const file of files) {
  if (applied.has(file)) continue;
  const sql = await readFile(join(MIGRATIONS_DIR, file), "utf8");
  console.log(`→ applying ${file}`);
  await client.query("BEGIN");
  try {
    await client.query(sql);
    await client.query("INSERT INTO _migrations (name) VALUES ($1)", [file]);
    await client.query("COMMIT");
    count++;
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(`✗ ${file} failed:`, e.message);
    process.exit(3);
  }
}

console.log(count === 0 ? "✓ no pending migrations" : `✓ applied ${count} migration(s)`);
await client.end();
