# Lictor AI

> The bodyguard your AI didn't ship with.

[![CI](https://github.com/Raffa-jarrl/Lictor-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Raffa-jarrl/Lictor-AI/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![npm version](https://img.shields.io/npm/v/@lictor/sentinel.svg)](https://www.npmjs.com/package/@lictor/sentinel)
[![PyPI version](https://img.shields.io/pypi/v/lictor-sentinel.svg)](https://pypi.org/project/lictor-sentinel/)
[![Latest scanner release](https://img.shields.io/github/v/release/Raffa-jarrl/Lictor-AI?label=patrol-scanner&color=brightgreen)](https://github.com/Raffa-jarrl/Lictor-AI/releases/latest)

> 🆕 **patrol-scanner v0.2 just shipped** — false-positive elimination across 5 providers (CloudFront, Azure CloudApp, GitHub Pages, Netlify, Heroku) with new `header_fp_blocklist` / `status_required` / `verifier` mechanism. 16 regression tests, 3 production FPs live-verified as filtered. [Release notes →](https://github.com/Raffa-jarrl/Lictor-AI/releases/tag/patrol-scanner-v0.2)

[![Watch the Lictor demo (3 min)](https://img.youtube.com/vi/RelXN5g1sac/maxresdefault.jpg)](https://youtu.be/RelXN5g1sac)

Lictor is an open-source AI security suite, organized as **three pillars on one shared engine** — easy to hold in your head:

### 🤖 Lictor for AI — *secure the AI you use*
Drops into every AI client you already use — **Claude Code, Cursor, Codex, Antigravity, Windsurf**, and the rest of the top-10 — and guards each boundary an AI agent can cross:
- **[Shield](./shield)** — Chrome extension: guards the AI-built **app** in your browser
- **[Sentinel](./sentinel)** — SDK (npm/pip): guards the **prompt** (injection + PII)
- **[Airlock](./airlock)** — action broker: guards the **action** (MCP tool-calls + shell; observe → enforce)
- **[Skills](./skills)** · **[VS Code / Cursor ext](./vscode-extension)** · **[Studio](./studio)** — guard your **dev loop** (`/lictor-security-check` and friends, in every client)

### 🏢 Lictor for Business — *secure the company* · *2026–27 roadmap*
The security an SMB needs but can't staff a team for:
- **[Domain Guard](./domain-guard)** — identities & Active Directory: stale passwords, over-privileged accounts, open shares
- **[Isolation](./isolation)** — the **red/black sandbox**: a pre-isolated machine to run & test AI agents *off* your real network, no env-build required
- **Audit & Rotate** — compliance evidence + guided key rotation (built on Guardian + the `lictor-rotate` skill)

### 🛰️ Lictor Patrol — *scan the world*
- **[v3 scanner](./v3)** + **Patrol** — 38-module external attack-surface recon; the engine behind *"we scanned 30,000 vibe-coded apps."* Apache 2.0, runs locally.

**Under all three sits the platform:** **[Lictor Core](./core)** (a Rust crate compiling to native + WASM, plus the AUDIT.json output standard), the **[`lictor` CLI](./cli)**, and **[Lictor Guardian](./guardian)** (the dashboard every product reports into — one audit trail, one place to prove you're secure). One engine, so every new check ships everywhere at once.

## May 2026 update — 276 disclosures sent, 13 false-positive classes catalogued

In the four weeks before public launch, Lictor's scanners produced:

- **276 verified disclosures** to affected organisations (184 via GitHub public process + 92 via direct-email CVD)
- **7,736 hosts scanned** across 12 countries / 5 industries (finance, healthcare, government, crypto, AI infrastructure)
- **38 scanner modules** with anti-FP rigor (HEAD-only canaries, vendor-fingerprint detection, content-quality validation, baseline-compare classifiers)
- **13 false-positive classes** discovered and filtered (see [`v3/docs/fp-catalog.md`](./v3/docs/fp-catalog.md))
- **0 victim names published** publicly — all disclosures routed privately under 60-day Coordinated Vulnerability Disclosure norms

The validated finding count after anti-FP filtering: 44 customer-app sourcemap exposures with revealed source code (down from 292 raw initial hits), 33 spoofable enterprise email domains, 11 publicly-listable cloud buckets, 14 EOL software stacks, 4 RDP/FTP/SMB services exposed direct-to-internet.

Full transparency at [lictorai.com/transparency](https://lictorai.com/transparency).

## Status

**🤖 Pillar 1 — Lictor for AI** *(shipped; the Oct 6 launch)*
| Component | What it is | Status |
|---|---|---|
| [`shield/`](./shield/) | Chrome MV3 extension | ✅ WASM-backed audits, real popup verdict, loads unpacked |
| [`sentinel/`](./sentinel/) | TypeScript SDK (npm: `@lictor/sentinel`) | ✅ 159 tests, real `wrap()`, 3 checks (prompt-injection / pii-leak / secrets-in-input) |
| [`sentinel-py/`](./sentinel-py/) | Python SDK (PyPI: `lictor-sentinel`) | ✅ 11 tests, Python parity, zero runtime deps |
| [`airlock/`](./airlock/) | AI action broker (npm: `@lictor/airlock`) | ✅ 23 tests, observe→enforce, MCP + shell, 5 policy rule families, Guardian telemetry |
| [`skills/`](./skills/) | Claude Code plugin suite | ✅ 4 plugins, one-line `install.sh`, portable to Cursor/Codex |
| [`vscode-extension/`](./vscode-extension/) | VS Code / Cursor extension | ✅ Packages to `.vsix`; Marketplace + Open VSX at launch |
| [`studio/`](./studio/) | Tauri desktop app | 🚧 Builds local `.dmg`/`.app`; signed release Q1 2027 |

**🏢 Pillar 2 — Lictor for Business** *(2026–27 roadmap)*
| Component | What it is | Status |
|---|---|---|
| [`domain-guard/`](./domain-guard/) | Identity & Active Directory posture | 🗺️ Spec'd — stale passwords, over-privileged accounts, open shares |
| [`isolation/`](./isolation/) | Red/black AI sandbox machine | 🗺️ Spec'd — run/test AI agents off the real network |
| Audit & Rotate | Compliance evidence + key rotation | ✅ Foundations exist (Guardian audit export + `lictor-rotate` skill); productizing |

**🛰️ Pillar 3 — Lictor Patrol** *(scanner shipped; autonomous Patrol building Q3)*
| Component | What it is | Status |
|---|---|---|
| [`v3/`](./v3/) | External attack-surface scanner battery | ✅ 38 scanner modules, anti-FP rigor (13 FP classes catalogued), 276 disclosures sent |
| [`disclosures/`](./disclosures/) | Coordinated Vulnerability Disclosure pipeline | ✅ Organised by tier (queue / courtesy-sourcemaps / bounty-eligible / verified-fp) |

**⚙️ The platform** *(shared by all three)*
| Component | What it is | Status |
|---|---|---|
| [`core/`](./core/) | Rust check engine, native + WASM + AUDIT.json standard | ✅ 45 tests, native + WASM builds, Apache 2.0 |
| [`cli/`](./cli/) | `lictor` terminal binary | ✅ `lictor audit . --format human/json/markdown` + `--fail-on` for CI |
| [`guardian/`](./guardian/) | Hosted dashboard — the one audit trail every product reports into | ✅ 12 integration tests, magic-link auth, audit-log export, Slack webhook, `docker compose up` |
| [`landing/`](./landing/) | Marketing site (lictorai.com) | ✅ Multi-page: hero, /business, /in-the-wild, /transparency, /scan, /patterns, /compliance |

**Public launch target:** Tuesday October 6, 2026.

## Download & install

Every component installs today. SDKs/extensions publish to their public registries at the **Oct 6, 2026** launch — until then, install from source or from the artifacts below. Build **all** downloadable artifacts at once with `make package` (→ `dist/release/`).

| Component | Install today | At launch (registry) |
|---|---|---|
| **CLI** (`lictor`) | `curl -fsSL https://raw.githubusercontent.com/Raffa-jarrl/Lictor-AI/main/scripts/install.sh \| bash` — grabs the release binary, or builds from source | `cargo install lictor-cli` / `brew install lictor` |
| **Skills** (Claude Code) | `git clone https://github.com/Raffa-jarrl/Lictor-AI && bash Lictor-AI/skills/install.sh` | — (always source) |
| **Sentinel** (npm) | `cd sentinel && pnpm install && pnpm build && npm pack` → `npm i ./lictor-sentinel-*.tgz` | `npm install @lictor/sentinel` |
| **Sentinel** (PyPI) | `pip install ./sentinel-py` (PEP 517 source install) | `pip install lictor-sentinel` |
| **Airlock** (npm) | `cd airlock && npm install && npm run build` → `node dist/cli.js --help` | `npm i -g @lictor/airlock` / `npx @lictor/airlock` |
| **Shield** (Chrome) | Download `lictor-shield-*.zip` from [Releases](https://github.com/Raffa-jarrl/Lictor-AI/releases) → unzip → `chrome://extensions` → Load unpacked | Chrome Web Store |
| **VS Code / Cursor** | Download `lictor-*.vsix` from [Releases](https://github.com/Raffa-jarrl/Lictor-AI/releases) → `code --install-extension lictor-*.vsix` | Marketplace + Open VSX |
| **Guardian** (self-host eval) | `cd guardian && docker compose up` → http://localhost:3100 | hosted at lictorai.com |
| **Studio** (desktop) | `make studio-build` → `.dmg`/`.app` (unsigned; right-click→Open) | signed `.dmg` Q1 2027 |

> **`make install`** installs the CLI + Claude Code skills locally in one step. **`make package`** builds every artifact above into `dist/release/`. Guardian's source is [source-available](./guardian/LICENSE) (run-it-yourself for dev/eval; not for hosting-as-a-service).

## Real-world impact

Lictor's scanners are designed to find real security issues in real codebases. Open-source maintainers across these projects have received Lictor-filed reports — many have closed them with fixes or explicit acknowledgements:

> **"thanks for flagging the trigger pattern. The above workflow was obsolete and due to be removed, and done by PR #126"**
> — [aws-neuron/aws-neuron-samples](https://github.com/aws-neuron/aws-neuron-samples) (Amazon AWS Neuron team)

Other projects that have actioned reports from Lictor's automated patrols:

- [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) — JOSE/JWT library (Go)
- [dbt-labs](https://github.com/dbt-labs) — analytics engineering platform
- [CrowdStrike](https://github.com/CrowdStrike) — security telemetry SDKs
- [ansible-lockdown/RHEL8-STIG](https://github.com/ansible-lockdown/RHEL8-STIG) — DISA STIG hardening (RHEL 8)
- [ansible-lockdown/RHEL9-CIS](https://github.com/ansible-lockdown/RHEL9-CIS) — CIS benchmark hardening (RHEL 9)
- [ansible-lockdown/Windows-2019-STIG](https://github.com/ansible-lockdown/Windows-2019-STIG) — DISA STIG hardening (Windows Server)
- [textfuel/lazyjira](https://github.com/textfuel/lazyjira) — terminal Jira client

All reports filed via Lictor's open-source scanners (`scripts/patrol-*.py`, Apache 2.0). The same patterns are running against your code if you `/lictor-security-check` your project today.

## Try the Claude Code plugins (60 seconds)

If you have Claude Code installed:

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/
```

Then in any Claude Code session, from your project's root directory:

```
/lictor-security-check
```

Claude reads your project, runs 7 checks, writes a `SECURITY-AUDIT.md`, and tells you in plain English what to fix.

## Try the native CLI

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI
cd lictor

# One-time setup
brew install rustup wasm-pack    # macOS
rustup default stable
rustup target add wasm32-unknown-unknown

# Audit any URL
cargo run --release --example audit -- https://your-app.com -o report.md
```

A self-contained vulnerable demo lives in [`examples/vulnerable-demo/`](./examples/vulnerable-demo/) — spin it up with `python3 -m http.server 8765` and audit it to verify the engine works on a known-bad target.

## Try the Chrome extension

```bash
cd shield
pnpm install
pnpm wasm     # builds lictor-core to WASM
pnpm build    # produces shield/dist/
```

In Chrome → `chrome://extensions` → Developer Mode → **Load unpacked** → select `shield/dist/`.

Visit any AI-built site (Vercel/Supabase/OpenAI/Anthropic fingerprints) and the toolbar badge reports findings.

## Why

The AI security market is dominated by enterprise-only point solutions. Every one of them assumes you can wait for procurement, sign a 6-figure contract, and integrate over 3 months. None of them does anything for the consumer staring at a vibe-coded SaaS asking "is this actually safe?"

Lictor flanks them. Free for individuals. Free for OSS. Paid for teams. Enterprise where the money is. One engine across all of them so every new check ships everywhere at once.

In a sentence: **safety infrastructure for the AI agent era.**

## License

Apache 2.0 for the whole suite — `core/`, `cli/`, `shield/`, `sentinel/`, `sentinel-py/`, `airlock/`, `skills/`, `vscode-extension/`, `studio/`, `v3/`, and the Business-pillar `domain-guard/` + `isolation/`. The one exception: **Guardian** — its hosted service code is published for transparency but licensed for hosted use through lictorai.com only (see [`guardian/LICENSE`](./guardian/LICENSE)).

See [`LICENSE`](./LICENSE) + [`NOTICE`](./NOTICE).

## Security

If you've found a vulnerability in Lictor itself, **don't open a public issue** — see [`SECURITY.md`](./SECURITY.md). False-negative reports (real bugs Lictor missed in your code) are the most valuable kind of report we get — use the [false-negative template](./.github/ISSUE_TEMPLATE/false-negative.md).

## Contributing

Not yet broadly open. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for what we DO want right now (bug reports, false-negative reports, pattern requests).

[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) applies.

## What's in this repo

```
.
│  ── 🤖 Pillar 1: Lictor for AI ──
├── shield/           — Chrome extension (guards the app)
├── sentinel/         — TypeScript SDK (guards the prompt)
├── sentinel-py/      — Python SDK
├── airlock/          — AI action broker (guards the action: MCP + shell)
├── skills/           — Claude Code plugin suite (4 skills) + Cursor adapter
├── vscode-extension/ — VS Code / Cursor extension
├── studio/           — Tauri desktop app
│  ── 🏢 Pillar 2: Lictor for Business (roadmap) ──
├── domain-guard/     — identity & Active Directory posture
├── isolation/        — red/black AI sandbox machine
│  ── 🛰️ Pillar 3: Lictor Patrol ──
├── v3/               — external attack-surface scanner battery
├── disclosures/      — coordinated vulnerability disclosure pipeline
│  ── ⚙️ Shared platform ──
├── core/             — Rust crate, the shared engine + AUDIT.json
├── cli/              — `lictor` terminal binary
├── guardian/         — Next.js + Postgres dashboard (the one audit trail)
├── landing/          — Marketing site (HTML, deploys to lictorai.com)
├── brand/            — Logo SVG + rendered PNG icon variants
├── docs/             — Specs (sentinel-api, guardian-schema, wire-format) + launch/
└── examples/         — Vulnerable-by-design fixtures
```

## Built by

A 20-year cybersecurity engineer + Claude. Solo build, building in public.

If this saved you from a bad day: star the repo. That's how solo open-source projects get measured.
