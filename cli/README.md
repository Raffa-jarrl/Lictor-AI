# lictor (CLI)

> Terminal audit for AI-built apps. CLI sibling of [Lictor Studio](../studio/).
> Same engine. Different surface. For CI integration, scripts, headless servers, and developers who prefer a command over a GUI.

```bash
$ lictor audit .

Lictor audit · 47 files · platform: lovable · 234ms
────────────────────────────────────────────────────────────

  🔴 1  🟠 2  🟡 1  🔵 0  ⚪ 0

  🔴 Supabase service-role key found in JS bundle
    src/lib/db.ts:12
    Pattern matched in publicly-served JS bundle. Redacted form:
    `eyJ...`. If this is a real key, rotate it.

    Fix: Move to a server-only route, never bundle in client.

  🟠 Stripe webhook handler is unverified
    app/api/stripe-webhook/route.ts:8
    We found a Stripe webhook handler at
    app/api/stripe-webhook/route.ts but no signature verification.

    Fix: Add Stripe's standard signature verification step before
    trusting the request body.

  ...
```

## Install

### From crates.io (when published)

```bash
cargo install lictor-cli
```

### From the repo (today)

```bash
cd ~/Lictor
cargo install --path cli
```

## Usage

```bash
# Audit current directory, human-readable output
lictor audit .

# Audit a specific path
lictor audit ~/projects/my-lovable-app

# JSON output (AUDIT.json v0.1 spec — pipe-friendly)
lictor audit . --format json > audit.json

# Markdown output (paste-friendly for PR comments)
lictor audit . --format markdown >> security-review.md

# Fail the command if any HIGH-or-above findings exist
# (useful in CI)
lictor audit . --fail-on high

# Skip npm-registry verification (faster, but won't catch
# hallucinated package imports)
lictor audit . --offline
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or findings below `--fail-on` threshold) |
| `1` | Findings at-or-above `--fail-on` threshold |
| `2` | Bad invocation (e.g., path doesn't exist) |

## CI integration

### GitHub Actions

```yaml
- name: Install lictor
  run: cargo install lictor-cli

- name: Audit on every push
  run: lictor audit . --fail-on high --format json > audit.json

- name: Upload audit report
  uses: actions/upload-artifact@v4
  with:
    name: lictor-audit
    path: audit.json
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
lictor audit . --fail-on critical || exit 1
```

## What it checks

Same 7 checks as the rest of the Lictor suite:

1. **Secrets** in client-bundled files (15 patterns: OpenAI, Anthropic, Stripe, GitHub, AWS, Slack, Google, …)
2. **Database** exposure (Supabase RLS gaps, Firebase open, unauthenticated `/api`)
3. **Auth** surface (admin paths returning 200 to unauthenticated requests)
4. **CORS** posture (Allow-Origin: * with credentials)
5. **AI agent surface** (chat widgets, agent endpoints)
6. **Webhooks** unverified (Stripe / GitHub / Shopify / Slack signature verification)
7. **Hallucinated packages** (imports not in package.json AND not on npm — typical AI hallucination)

Platform-specific patterns are auto-detected from project markers (`.lovable.json` → Lovable, `.bolt/` → Bolt, `vercel.json` → v0, `.replit` → Replit).

## CLI vs Studio vs Claude Code skill — which do I want?

| Use case | Pick |
|---|---|
| One-off audit, terminal-native | **lictor-cli** (this) |
| Daily audit, GUI, offline, paid features | [Lictor Studio](../studio/) |
| Audit inside your AI coding workflow | [`/lictor-security-check` skill](../skills/lictor-security-check/) |
| Runtime defense in production code | [`@lictor/sentinel`](../sentinel/) (TS) or [`lictor-sentinel`](../sentinel-py/) (Python) |
| Browser-side audit of any deployed AI-built site | [Lictor Shield](../shield/) Chrome extension |
| Team-level monitoring + compliance evidence | [Lictor Guardian](../guardian/) dashboard |

All free, all open source, all Apache 2.0.

## Privacy

Lictor CLI runs **fully local**. No telemetry, no signup, no network calls (except the optional npm-registry lookup in the hallucinated-packages check, which `--offline` disables).

## Build

```bash
cd ~/Lictor
cargo build --release -p lictor-cli
./target/release/lictor audit .
```

## License

Apache-2.0. See [LICENSE](../LICENSE).
