# Lictor — AI Security Audit for VS Code

> Free open-source security audit for apps built with AI. Catches the patterns Snyk and Semgrep miss in Lovable / Bolt / v0 / Cursor / Replit projects.
> One command. Plain English. No signup, no telemetry, no per-seat pricing.

## What it does

Right-click any file in Explorer → **Lictor: Audit this file**. Or open the Command Palette → **Lictor: Audit this workspace**.

Findings render:
- In the **Problems panel** (with severity-mapped error / warning / info levels)
- As **inline diagnostics** in the editor (hover tooltips with the plain-English fix)
- In the **Lictor sidebar** (grouped by severity, click to jump to the line)

Plus:
- **Import AUDIT.json** — paste in Snyk / Semgrep / Trivy / GitHub Security output and read it through Lictor's plain-English voice
- **Export findings** — save the current audit as AUDIT.json for CI artifacts or PR comments

## Prerequisites

The extension shells out to the `lictor` CLI binary. Install it once:

```bash
cargo install lictor-cli
```

Or download a prebuilt binary from https://lictor.ai/cli (when available).

In v0.2 we'll bundle the audit engine directly into the extension (WASM) so no CLI is needed.

## Configuration

| Setting | Default | What it does |
|---|---|---|
| `lictor.severityFilter` | `"low"` | Minimum severity to surface in the Problems panel. `"low"` shows everything except `info`. |
| `lictor.runOnSave` | `false` | Re-audit on every file save. Off by default — manual audits don't surprise you. |
| `lictor.skipDirs` | `["node_modules", "target", ...]` | Directories to skip during audits. |

## What Lictor catches

7 checks tuned for vibe-coder patterns:

1. **Secrets in client JS bundles** (Supabase service-role key, OpenAI keys, Stripe live keys, etc.)
2. **Missing Row-Level Security** on Supabase tables
3. **Hallucinated npm packages** (your AI imported something that doesn't exist on npm)
4. **Frontend-only auth checks** (the "admin gate" that ships to every visitor's browser)
5. **Unsigned webhooks** (Stripe, GitHub, Shopify, Slack)
6. **Cross-tenant data leakage** in Next.js cache
7. **AI endpoints with no rate limiting**

Same engine as `/lictor-security-check` (Claude Code skill), Lictor Studio (desktop), Lictor Shield (Chrome extension). Findings interop via the [AUDIT.json](https://github.com/lictor-ai/lictor/blob/main/docs/standards/AUDIT.json.md) standard.

## Privacy

Lictor runs **fully local**. No telemetry, no signup, no network calls (except the optional npm-registry lookup in the hallucinated-package check). Confirmed by Cargo + npm package audits.

## How Lictor fits in your workflow

| Surface | When you'd use it |
|---|---|
| **VS Code extension** (this) | While coding — see findings inline, fix them, audit before commit |
| **Claude Code skill** (`/lictor-security-check`) | While working inside Claude Code |
| **Lictor Studio** (desktop) | For a clean GUI audit outside any IDE |
| **Lictor CLI** (`lictor audit .`) | CI integration, headless servers, scripting |
| **Lictor Shield** (Chrome ext) | When you visit a deployed AI-built site and want to passively audit |
| **Sentinel SDK** (npm + PyPI) | Runtime defense in your app's OpenAI / Anthropic calls |
| **Lictor Guardian** (dashboard) | Team-level incident monitoring + compliance evidence |

All free, all open source, all Apache 2.0.

## Development

```bash
cd vscode-extension
pnpm install
pnpm watch       # auto-rebuild on src/ changes

# In VS Code: F5 to launch an Extension Development Host with this extension loaded
```

## License

Apache-2.0. See [LICENSE](../LICENSE).

## Status

**v0.1.0-pre.0** — preview. Ships to the VS Code Marketplace + Open VSX (for Cursor / Windsurf / Codium) on **December 22, 2026**.

See [vscode-extension-mvp-spec.md](../docs/launch/vscode-extension-mvp-spec.md) for the full v0.1 scope + Sep-Dec milestone schedule.
