<p align="center">
  <img src="brand/lictor-mark.svg" alt="Lictor AI" width="96">
</p>

# Lictor — open-source AI security tools

> Security checks for the apps you build with AI — right where you code.

**Free. Open source (Apache-2.0). Built for the founder or developer who shipped an app with Claude, Cursor, Copilot, or v0 and wants to know it's safe before real users show up.**

Most AI security tools are written for security teams and talk in CVSS scores. These don't. They run in the tools you already use, find the mistakes AI assistants tend to ship, and explain each one in plain English — what it is, what someone could do with it, and how to fix it.

---

## The tools

| Tool | What it is | Where it runs |
|---|---|---|
| **[`skills/`](./skills)** | Claude Code / Cursor skills — run `/lictor-security-check` on your project and get a plain-English security review | in your AI coding session |
| **[`ai-scan/`](./ai-scan)** | An AI-native static scanner — finds risks specific to LLM agents (tool authorization in prompts, prompt-injection sinks, sensitive data flowing back through the model) | CLI, Python |
| **[`sentinel/`](./sentinel)** · **[`sentinel-py/`](./sentinel-py)** | Runtime SDKs (npm / PyPI) — guard the prompt boundary against injection, PII leaks, and secrets-in-input | in your app |
| **[`shield/`](./shield)** | Chrome extension — checks an AI-built web app for the common exposure mistakes | your browser |
| **[`airlock/`](./airlock)** | An action broker for AI agents — observe, then gate, the MCP tool-calls and shell commands an agent can make | around your agent |
| **[`vscode-extension/`](./vscode-extension)** | The checks, in VS Code / Cursor | your editor |
| **[`studio/`](./studio)** | A desktop app for running the suite | macOS/Win/Linux |
| **[`core/`](./core)** · **[`cli/`](./cli)** | The shared engine (Rust → native + WASM) and the `lictor` CLI everything builds on | — |

## Quick start — run a security check with Claude

The fastest path: install the skills and ask Claude to check your project.

```bash
# in your project, with Claude Code:
#   /lictor-security-check
```

It walks your code, runs the checks, and writes a plain-English report you can act on tonight. See [`skills/`](./skills) for install.

Prefer the scanner directly?

```bash
# AI-native static scan of a Python AI app
python -m lictor_ai_scan path/to/your/app
```

## Why

If you built an app with AI and you don't have a security team, you're the security team. These tools are the friend-who-knows-security you don't have on staff — free, open, and built to be read (every check is an inspectable file, no black box).

## Contributing

Bug reports and **false-negative reports** (a real issue a check missed) are the most useful thing you can send. See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Found a vulnerability in Lictor itself? See [`SECURITY.md`](./SECURITY.md) — don't open a public issue.

## License

Apache-2.0 across the suite. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

## Built by

A 20-year security engineer + Claude. If it saved you a bad day, a star is how small open-source projects get measured.
