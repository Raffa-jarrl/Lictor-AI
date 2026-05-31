#!/usr/bin/env node
/**
 * airlock — the Lictor Airlock command-line interface.
 *
 *   airlock guard  [--enforce] -- <command>     classify one command (exit 2 = block)
 *   airlock run    [--enforce] -- <command...>  classify, then run it if allowed
 *   airlock watch  [--enforce]                  classify commands piped on stdin
 *   airlock report [--log <path>] [--limit N]   summarize the audit log
 *   airlock install-hook [--zsh]                print a shell hook to screen commands
 *   airlock version
 *
 * Global flags: --enforce (block, don't just warn), --json, --quiet,
 *               --no-audit, --log <path>.
 */

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { createAirlock } from "./broker.js";
import { shellAction } from "./actions.js";
import { explain, summarize } from "./audit/english.js";
import { defaultAuditPath } from "./audit/logger.js";
import { toExitCode, BASH_PREEXEC_HOOK, ZSH_PREEXEC_HOOK } from "./shell/index.js";
import { AirlockBlockedError, type AirlockConfig, type AirlockMode, type Verdict } from "./types.js";
import { airlockVersion } from "./version.js";
import { flushTelemetry } from "./telemetry.js";

interface Args {
  _: string[];
  rest: string[]; // args after `--`
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const _: string[] = [];
  const rest: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let afterDD = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (afterDD) {
      rest.push(a);
      continue;
    }
    if (a === "--") {
      afterDD = true;
      continue;
    }
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--") && needsValue(key)) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      _.push(a);
    }
  }
  return { _, rest, flags };
}

function needsValue(key: string): boolean {
  return (
    key === "log" ||
    key === "limit" ||
    key === "mode" ||
    key === "guardian-url" ||
    key === "guardian-token"
  );
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
  red: (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s: string) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  green: (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  dim: (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
};

function paint(decision: Verdict["decision"], s: string): string {
  if (decision === "block") return c.red(s);
  if (decision === "warn") return c.yellow(s);
  return c.green(s);
}

function configFrom(args: Args): AirlockConfig {
  const mode: AirlockMode = args.flags.enforce ? "enforce" : "observe";
  const cfg: AirlockConfig = { mode };
  if (args.flags["no-audit"]) cfg.auditLog = false;
  else if (typeof args.flags.log === "string") cfg.auditLog = args.flags.log;

  // Optional Guardian telemetry. Off unless BOTH a URL and a token are given.
  // Flags win over env vars (LICTOR_GUARDIAN_URL / LICTOR_GUARDIAN_TOKEN).
  const guardianUrl =
    (typeof args.flags["guardian-url"] === "string" ? args.flags["guardian-url"] : undefined) ??
    process.env.LICTOR_GUARDIAN_URL;
  const guardianToken =
    (typeof args.flags["guardian-token"] === "string" ? args.flags["guardian-token"] : undefined) ??
    process.env.LICTOR_GUARDIAN_TOKEN;
  if (guardianUrl && guardianToken) {
    cfg.guardian = { endpoint: guardianUrl, token: guardianToken };
  }
  return cfg;
}

function commandFrom(args: Args): string {
  // Prefer the part after `--`; fall back to positionals after the subcommand.
  if (args.rest.length > 0) return args.rest.join(" ");
  return args._.slice(1).join(" ");
}

// ── subcommands ───────────────────────────────────────────────────────────

async function cmdGuard(args: Args): Promise<number> {
  const command = commandFrom(args);
  if (!command) {
    process.stderr.write("usage: airlock guard [--enforce] -- <command>\n");
    return 64;
  }
  const airlock = createAirlock(configFrom(args));
  let verdict: Verdict;
  try {
    verdict = await airlock.broker(shellAction(command));
  } catch (err) {
    if (err instanceof AirlockBlockedError) verdict = err.verdict;
    else throw err;
  }
  if (args.flags.json) {
    process.stdout.write(`${JSON.stringify(verdict)}\n`);
  } else if (!args.flags.quiet || verdict.decision !== "allow") {
    process.stderr.write(`${paint(verdict.decision, explain(verdict))}\n`);
  }
  return toExitCode(verdict);
}

async function cmdRun(args: Args): Promise<number> {
  const command = commandFrom(args);
  if (!command) {
    process.stderr.write("usage: airlock run [--enforce] -- <command> [args...]\n");
    return 64;
  }
  const airlock = createAirlock(configFrom(args));
  let verdict: Verdict;
  let blocked = false;
  try {
    verdict = await airlock.broker(shellAction(command));
  } catch (err) {
    if (err instanceof AirlockBlockedError) {
      verdict = err.verdict;
      blocked = true;
    } else throw err;
  }

  if (verdict.decision !== "allow") {
    process.stderr.write(`${paint(verdict.decision, explain(verdict))}\n`);
  }
  if (blocked) {
    process.stderr.write(c.red("airlock: refusing to run a blocked command\n"));
    return toExitCode(verdict);
  }

  // Execute the command through the user's shell, inheriting stdio.
  return await new Promise<number>((resolve) => {
    const child = spawn(command, { shell: true, stdio: "inherit" });
    child.on("exit", (code) => resolve(code ?? 0));
    child.on("error", () => resolve(1));
  });
}

async function cmdWatch(args: Args): Promise<number> {
  const airlock = createAirlock(configFrom(args));
  const rl = createInterface({ input: process.stdin, terminal: false });
  process.stderr.write(c.dim("airlock: watching commands on stdin (one per line)…\n"));
  for await (const line of rl) {
    const command = line.trim();
    if (!command) continue;
    let verdict: Verdict;
    try {
      verdict = await airlock.broker(shellAction(command));
    } catch (err) {
      if (err instanceof AirlockBlockedError) verdict = err.verdict;
      else throw err;
    }
    process.stdout.write(`${paint(verdict.decision, summarize(verdict))}\n`);
  }
  return 0;
}

interface AuditLine {
  ts?: string;
  decision?: string;
  severity?: string;
  ruleIds?: string[];
  summary?: string;
  channel?: string;
  enforced?: boolean;
}

async function cmdReport(args: Args): Promise<number> {
  const path = typeof args.flags.log === "string" ? args.flags.log : defaultAuditPath();
  const limit = typeof args.flags.limit === "string" ? parseInt(args.flags.limit, 10) : 20;
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    process.stderr.write(`airlock: no audit log at ${path}\n`);
    process.stderr.write(c.dim("Run some commands through `airlock guard/run` first.\n"));
    return 0;
  }
  const lines = raw
    .split("\n")
    .filter(Boolean)
    .map((l) => safeParse(l))
    .filter((x): x is AuditLine => x !== null);

  const byDecision = { allow: 0, warn: 0, block: 0 } as Record<string, number>;
  const byRule = new Map<string, number>();
  for (const l of lines) {
    if (l.decision) byDecision[l.decision] = (byDecision[l.decision] ?? 0) + 1;
    for (const r of l.ruleIds ?? []) byRule.set(r, (byRule.get(r) ?? 0) + 1);
  }

  process.stdout.write(c.bold(`\nLictor Airlock — audit summary\n`));
  process.stdout.write(c.dim(`${path}\n\n`));
  process.stdout.write(`Total actions:  ${lines.length}\n`);
  process.stdout.write(
    `  ${c.green(`allow ${byDecision.allow ?? 0}`)}   ` +
      `${c.yellow(`warn ${byDecision.warn ?? 0}`)}   ` +
      `${c.red(`block ${byDecision.block ?? 0}`)}\n`,
  );

  if (byRule.size > 0) {
    process.stdout.write(`\nBy rule:\n`);
    for (const [rule, n] of [...byRule.entries()].sort((a, b) => b[1] - a[1])) {
      process.stdout.write(`  ${n.toString().padStart(4)}  ${rule}\n`);
    }
  }

  const flagged = lines.filter((l) => l.decision === "block" || l.decision === "warn").slice(-limit);
  if (flagged.length > 0) {
    process.stdout.write(`\nMost recent flagged actions (last ${flagged.length}):\n`);
    for (const l of flagged) {
      const dec = (l.decision ?? "allow") as Verdict["decision"];
      process.stdout.write(
        `  ${c.dim(l.ts ?? "")}  ${paint(dec, (l.summary ?? "").slice(0, 140))}\n`,
      );
    }
  }
  process.stdout.write("\n");
  return 0;
}

function cmdInstallHook(args: Args): number {
  const hook = args.flags.zsh ? ZSH_PREEXEC_HOOK : BASH_PREEXEC_HOOK;
  const rc = args.flags.zsh ? "~/.zshrc" : "~/.bashrc";
  process.stderr.write(c.dim(`# Append the block below to ${rc}, then reopen your shell.\n\n`));
  process.stdout.write(`${hook}\n`);
  return 0;
}

function cmdHelp(): number {
  process.stdout.write(
    `${c.bold("airlock")} — watch & contain what AI agents do (Lictor Airlock v${airlockVersion})\n\n` +
      `Usage:\n` +
      `  airlock guard  [--enforce] -- <command>      classify one command (exit 2 = block)\n` +
      `  airlock run    [--enforce] -- <command...>   classify, then run it if allowed\n` +
      `  airlock watch  [--enforce]                   classify commands piped on stdin\n` +
      `  airlock report [--log <path>] [--limit N]    summarize the audit log\n` +
      `  airlock install-hook [--zsh]                 print a shell hook\n` +
      `  airlock version\n\n` +
      `Flags:\n` +
      `  --enforce     block dangerous actions (default: observe — log only)\n` +
      `  --json        machine-readable verdict (guard)\n` +
      `  --quiet       only print non-allow verdicts (guard)\n` +
      `  --log <path>  audit log path (default ~/.lictor/airlock/audit.log)\n` +
      `  --no-audit    don't write to the audit log\n` +
      `  --guardian-url <url>      ship telemetry to a Guardian /api/ingest endpoint\n` +
      `  --guardian-token <token>  Guardian ingest token (Authorization: Bearer)\n\n` +
      `Telemetry is opt-in: set both --guardian-url and --guardian-token (or the\n` +
      `env vars LICTOR_GUARDIAN_URL / LICTOR_GUARDIAN_TOKEN). Only redacted\n` +
      `summaries + fingerprints are sent — never the raw command.\n\n` +
      `Observe first (breaks nothing), then flip to --enforce when you trust it.\n`,
  );
  return 0;
}

function safeParse(s: string): AuditLine | null {
  try {
    return JSON.parse(s) as AuditLine;
  } catch {
    return null;
  }
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const sub = args._[0];
  switch (sub) {
    case "guard":
      return cmdGuard(args);
    case "run":
      return cmdRun(args);
    case "watch":
      return cmdWatch(args);
    case "report":
      return cmdReport(args);
    case "install-hook":
      return cmdInstallHook(args);
    case "version":
    case "--version":
      process.stdout.write(`${airlockVersion}\n`);
      return 0;
    case undefined:
    case "help":
    case "--help":
      return cmdHelp();
    default:
      process.stderr.write(`airlock: unknown command '${sub}'\n\n`);
      cmdHelp();
      return 64;
  }
}

main()
  .then(async (code) => {
    // Flush any fire-and-forget Guardian telemetry before we tear down the
    // process. No-op when telemetry isn't configured / nothing is pending, and
    // it never throws (each send swallows its own errors).
    await flushTelemetry();
    process.exit(code);
  })
  .catch(async (err) => {
    process.stderr.write(`airlock: ${err instanceof Error ? err.message : String(err)}\n`);
    await flushTelemetry();
    process.exit(1);
  });
