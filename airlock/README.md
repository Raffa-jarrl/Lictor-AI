<p align="center">
  <a href="https://lictor-ai.com"><img src="https://raw.githubusercontent.com/Raffa-jarrl/Lictor-AI/main/brand/lictor-badge-256.png" alt="Lictor AI" width="120"></a>
</p>

# @lictor/airlock

> 🤖 **Part of the [Lictor AI security suite](../README.md)** — Lictor for AI. Airlock guards the **action** boundary — MCP tool-calls + shell, observe → enforce.

**Watch and contain what AI agents _do_.** A local broker that classifies every
shell command and MCP tool call an AI agent makes — in plain English — and can
stop the dangerous ones before they run.

Where [`@lictor/sentinel`](../sentinel) sits on the **prompt boundary** (what
goes into and out of the model), Airlock sits on the **action boundary**: the
shell commands the agent runs and the MCP tools it calls. Same philosophy, new
surface.

> "Don't let me be the person who let AI nuke prod."
> Airlock is the log that proves it didn't — and, when you're ready, the switch
> that stops it.

## Why this exists

When a small business says *"we're afraid of AI touching production,"* they mean
one of five things: it'll **destroy** something, **leak** data, reach **internal
systems**, pull in a **compromised** dependency, or *"I can't **prove** to my
auditor it was safe."*

Airlock answers all five from a single chokepoint, in two modes:

- **observe** (default) — classify and log every action in plain English. Blocks
  nothing, so it can't break a workflow and get uninstalled. This is the audit
  trail you show an auditor, a client, or your own boss.
- **enforce** — same classification, but now a `block` decision actually stops
  the action. You flip to it with **zero new config** once the observe-mode logs
  have shown you it's safe.

That's the whole thesis: one broker produces both the proof and the containment.

## Status

`0.1.0-alpha.0`. Not yet published to npm. **Build from source today** (see
[Develop](#develop)); the `npm i` / `npx` commands below are how it will install
at launch.

## Install

```bash
# at launch:
npm i -g @lictor/airlock      # the `airlock` CLI on your PATH
# or, no install:
npx @lictor/airlock guard -- "rm -rf build"
# or as a library:
npm i @lictor/airlock
```

Requires Node.js >= 20. Pure standard-library runtime — no required
dependencies. (MCP wrapping is SDK-agnostic; you do **not** need
`@modelcontextprotocol/sdk` installed to use Airlock.)

## CLI

```
airlock guard  [--enforce] -- <command>      classify one command (exit 2 = block)
airlock run    [--enforce] -- <command...>   classify, then run it if allowed
airlock watch  [--enforce]                   classify commands piped on stdin
airlock report [--log <path>] [--limit N]    summarize the audit log
airlock install-hook [--zsh]                 print a shell hook to screen commands
airlock version
```

**Flags:**

| Flag | Effect |
| --- | --- |
| `--enforce` | Block dangerous actions. Default is **observe** — log only. |
| `--json` | Machine-readable verdict (`guard`). |
| `--quiet` | Only print non-allow verdicts (`guard`). |
| `--log <path>` | Audit log path. Default: `~/.lictor/airlock/audit.log`. |
| `--no-audit` | Don't write to the audit log. |

Everything after `--` is treated as the command, so flags meant for the wrapped
command don't collide with Airlock's own.

### Examples

```bash
# Observe: see the verdict, the command still runs (exit 2 flags it for a hook).
airlock guard -- "rm -rf build"

# Enforce: classify, then run it only if it's allowed.
airlock run --enforce -- npm test

# Tail what the AI has been doing.
airlock report --limit 50

# Screen every interactive command in your shell (power-user opt-in):
airlock install-hook >> ~/.bashrc     # or: airlock install-hook --zsh >> ~/.zshrc
```

`guard`/`run` exit **2** on a `block` verdict and **0** otherwise, so shell
scripts and pre-exec hooks can stop a command on a non-zero exit.

## Library API

```ts
import { createAirlock } from "@lictor/airlock";

// Observe — breaks nothing, builds the audit trail.
const airlock = createAirlock({ mode: "observe" });
await airlock.guardShell("rm -rf build");          // logged, returns a Verdict

// When you trust the policy, flip one field:
const guard = createAirlock({ mode: "enforce" });
await guard.guardShell("rm -rf /");                // throws AirlockBlockedError
await guard.guardToolCall("delete_database", { name: "analytics" });
```

`createAirlock(config)` returns an `Airlock` with:

- `inspect(action)` — classify with **no side effects** (returns a `Verdict`).
- `broker(action)` — classify + log + (enforce) block. Throws
  `AirlockBlockedError` when it blocks.
- `guardShell(command, opts?)` — broker a raw shell command.
- `guardToolCall(tool, args?, opts?)` — broker an MCP tool call.

Key `AirlockConfig` fields: `mode` (`"observe"` | `"enforce"`), `rules` (subset
of the five rule ids), `auditLog` (path, or `false` to disable), `onVerdict`
(callback for every verdict, allow included), `allowlist` (regex strings that
force-allow), `prodMarkers` (strings that escalate a destructive/exfil hit to
critical/block), `redactSecrets` (default `true` — keep it), `warnAction`
(`"allow"` default, or `"block"` to stop on warnings too), and `guardian`
(optional off-box telemetry — redacted summary + fingerprint only, never the raw
command).

## MCP wrapping

The high-signal channel: an MCP tool call carries the tool name and structured
arguments, so the broker reasons about intent rather than guessing from a string.
Import from `@lictor/airlock/mcp` — no hard dependency on the MCP SDK.

```ts
import { guardCallToolHandler } from "@lictor/airlock/mcp";

// Drop-in around a standard MCP SDK CallTool handler:
server.setRequestHandler(
  CallToolRequestSchema,
  guardCallToolHandler(myHandler, { config: { mode: "enforce" } }),
);
```

```ts
import { guardToolDispatch } from "@lictor/airlock/mcp";

// Or wrap any generic (name, args) => result dispatcher:
const guarded = guardToolDispatch(myDispatch, { config: { mode: "observe" } });
```

In observe mode the call is logged and passed through unchanged. In enforce mode
a blocked call **never reaches the real tool** — the wrapper returns an MCP error
result the model can read (`"blocked by Airlock, here's why"`), so the agent
adapts instead of the server crashing.

## What it watches — the five policy categories

| Rule id | The fear | Examples it catches |
| --- | --- | --- |
| `destructive-command` | "it'll delete something I can't get back" | `rm -rf /`, `git push --force`, `DROP TABLE`, `TRUNCATE`, `DELETE`/`UPDATE` with no `WHERE`, `terraform destroy`, `kubectl delete`, `aws s3 rb`, fork bombs, `shutdown` |
| `data-exfiltration` | "it'll quietly ship my data somewhere" | `curl -d`/file uploads, `cat secret | curl`, `env | nc`, `scp`/`rsync` to a remote, uploads to paste/collaborator sites |
| `lateral-movement` | "it'll reach the rest of my network" | requests to LAN/private/link-local hosts, the cloud metadata endpoint (`169.254.169.254`), `ssh` to a LAN host, port scanners (`nmap`/`masscan`) |
| `supply-chain` | "it'll pull in something malicious and run it" | `curl … | bash`, `eval $(curl …)`, adding untrusted apt repos, registry installs, `npx` of a remote package |
| `secrets-access` | "it'll read my credentials" | reading `.env`, SSH keys, `~/.aws/credentials`, `.kube/config`, shell history, the OS keychain — and **blocks** when a credential read is piped to the network |

Each hit carries a plain-English `title`, a `reason` a non-technical owner can
read, and (where there's an obvious safer path) a `remediation`. Precision is the
product: catastrophic + irreversible → `block`; recoverable-but-surprising →
`warn`; routine work stays silent.

### Production escalation

Any `destructive-command` or `data-exfiltration` hit whose target matches a
**production marker** (`prod`/`production` by default, or your own
`prodMarkers`) is escalated to **critical / block** — the nightmare scenario gets
the hardest verdict.

## The enforce switch

Observation and enforcement come from the *same* classification. Observe today,
contain tomorrow:

```ts
createAirlock({ mode: "enforce" });   // library
```

```bash
airlock guard --enforce -- "<command>"   # CLI
```

In enforce mode a `block` throws `AirlockBlockedError` (library) / exits 2 (CLI)
/ returns an MCP error result (MCP) instead of running the action. Set
`warnAction: "block"` if you want enforce to stop on warnings too.

## Privacy

Airlock is local-first. The audit log lives on your machine at
`~/.lictor/airlock/audit.log` by default. Secrets are **redacted** before anything is
logged (an `sk_live_…` key is masked down to its scheme prefix). Shipping
anything off-box happens **only** if you supply a `guardian` config, and even
then it sends the privacy-safe event — a redacted summary plus a non-reversible
fingerprint — never the raw command.

## Develop

```bash
npm install        # dev deps only (typescript, tsx, @types/node)
npm run build      # tsc → dist/
npm test           # node --test via tsx
npm run typecheck  # tsc --noEmit
node dist/cli.js version
```

## How Airlock fits in the Lictor suite

Part of the [Lictor](../) AI-security line. **Sentinel** brokers the *prompt*
boundary; **Airlock** brokers the *action* boundary. They share an agent id and
fingerprint construction, so a single workstation running both reports correlated
telemetry to Guardian.

## License

Apache-2.0. See [LICENSE](./LICENSE).
