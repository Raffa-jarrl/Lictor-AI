# Lictor Studio — MVP scoping (v0.1.0)

> **Generated:** 2026-05-15
> **Target ship:** Q4 2026 (Dec 31, 2026 — v0.1.0 macOS)
> **v0.2 ship:** Q1 2027 (Mar 31, 2027 — v0.2.0 adds Windows + Pro tier)
> **Anti-Snyk Phase 3 differentiator:** Snyk's Evo is cloud-attached by design. Lictor Studio is offline-by-design. That asymmetry is the moat.

---

## 1. Product thesis

### What it is
A native desktop application (macOS first, Windows second) that runs the full Lictor audit locally — without ever opening a network socket. Bundles the Rust `lictor-core` engine, ships as a single signed binary, requires no Claude Code subscription, no cloud account, no API key, no telemetry.

### Why it exists
The Claude Code skill suite is the wedge — but it requires Claude Code, which costs $20+/mo and lives inside Anthropic's product. That gates Lictor for three real segments:

1. **Privacy-paranoid developers** — gov contractors, fintech, health, defense. Their codebases legally cannot send fingerprints to a cloud, even fingerprints. The Claude Code skill is off-limits.
2. **Cost-conscious indies** — $20/mo for Claude Code is a real expense. Many vibe-coders use Cursor (free tier) or Windsurf or plain VS Code with Copilot. They want Lictor, can't justify Claude Code.
3. **Air-gapped or offline-first builders** — train/plane developers, work-from-coffee-shop hackers with unreliable wifi, sovereign-cloud customers in jurisdictions that block external API traffic.

Studio reaches all three.

### Why it's also a strategic asset
Snyk's `agent-scan` requires `SNYK_TOKEN` and ships data to Snyk's API ([gap #2 in the Snyk analysis](./snyk-gap-analysis.md)). When Snyk Lite ships, Studio is Lictor's "we don't even need a network connection" answer. That's a category claim Snyk's architecture cannot make.

### Who it's for (v0.1.0)
- Solo founders building from Lovable / Bolt / v0 / Cursor / Replit / Windsurf
- Indie hackers who don't pay for Claude Code
- Anyone shipping AI-built apps on a Mac (macOS 13+ supported initially)
- Anyone working on a codebase they can't legally let leave their machine

Not for: enterprise CISOs (that's Lictor Enterprise, Q2 2027). Not for runtime monitoring (that's Sentinel SDK). Not for cloud-deployed-site auditing (that's Shield).

### Success criteria (Q1 2027)
- **10,000 downloads** of v0.1.x (cumulative, Dec 2026 – Mar 2027)
- **3,000 weekly active users** by Mar 31, 2027 (measured via anonymous build-id counts in CHANGELOG analytics — no identity tracking)
- **150 paying Pro subscribers** by Mar 31, 2027 ($79 one-time × 100 + $7/mo × 50 = $7,900 cumulative + $350/mo recurring)
- **4.5+ star rating** on whatever distribution mechanism we use (Product Hunt? GitHub stars? Our own landing-page reviews?)

---

## 2. MVP scope (v0.1.0)

### Ships in v0.1.0 — committed

- 7 security checks (parity with `/lictor-security-check` skill, same Rust core)
- Native UI for running an audit (file picker + drop zone for project folders)
- Findings list with severity icons (🔴🟠🟡🔵⚪), category filters, search
- Per-finding detail view: plain-English summary, file/line evidence with syntax highlighting, the fix runbook, rotated-secret runbook if applicable
- AUDIT.json import (load output from any conforming tool — Snyk, Semgrep, Trivy, GitHub Security)
- AUDIT.json export (save current findings to disk in the v0.1 spec)
- Settings panel: appearance (light/dark/auto), check toggles (enable/disable per-category), default audit path
- "Open in Claude Code" button per finding — opens the file + line in Claude Code if installed (uses `claude://file?path=...&line=...` URL scheme)
- macOS code signing + notarization (Gatekeeper-friendly install)
- Auto-update via Tauri's built-in updater
- Single signed `.dmg` download from `lictorai.com/studio`

### Explicitly OUT of v0.1.0 — defer to v0.2+

- **Local agent crew (Ollama-backed)** — the full 11-agent crew running on-device against a local LLM. Massive complexity surge (model bundling, inference performance, multi-agent orchestration). v0.2.
- **Windows + Linux builds** — Mac-only v0.1.0. The audience is heavily Mac-skewed (Lovable founders, Cursor users). v0.2 adds Windows; Linux defers to v0.3+.
- **Sentinel runtime monitoring tray app** — Studio v0.1 is audit-time only. Sentinel SDK already covers runtime. A tray companion is a separate product effort. v0.3.
- **Guardian sync** — Studio is offline-first by thesis. An opt-in "sync findings to my Guardian dashboard" is a v0.2 feature gated behind explicit consent.
- **Multi-language UI** — Studio v0.1 is English-only. Parrot agent (Q1 2027) generates locale files; Studio v0.2 picks them up.
- **Encrypted local audit history** — v0.1 keeps audit history in plaintext SQLite (still local-only). Pro tier in v0.2 adds AES-encrypted history.
- **Custom check authoring** — v0.1 ships the 7 built-in checks only. Custom-check SDK is a Pro feature in v0.2.
- **Team license keys** — single-user only in v0.1. Pro tier in v0.2 adds team licensing.

---

## 3. Tech choices

### Stack: Tauri 2.x + TypeScript frontend

**Why Tauri over Electron:**

| Dimension | Tauri 2.x | Electron |
|---|---|---|
| Binary size | ~10–25 MB | ~150+ MB |
| Memory at idle | ~80 MB | ~400 MB |
| Native integration | Excellent (Rust + system webview) | Decent |
| Rust core integration | First-class | Requires Node-Rust bridge |
| Security posture | Webview sandboxed by default | More attack surface |
| Cross-platform maturity | Production-ready in 2026 | Long-standing |

The deciding factor: **Lictor's check engine is already Rust** (in `lictor-core`). Tauri lets us call the engine directly via the JS-Rust bridge, no subprocess, no IPC overhead, no second packaging step. Electron would require either a Node-native binding or running `lictor-core` as a subprocess, both worse.

### Specific versions + libraries

- **Tauri 2.x** (latest stable as of Sep 2026) — frontend in webview, backend in Rust
- **Frontend framework:** Solid.js — small, fast, no virtual DOM overhead. Bundle target < 100KB JS.
- **Styling:** Tailwind 4 (matches the landing site's stack — designers move freely between the two)
- **State management:** Solid's built-in signals — no Redux / Zustand needed
- **Build tool:** Vite (Tauri default)
- **Test:** Vitest for frontend, `cargo test` for the Rust core
- **Code signing:** Apple Developer ID Application certificate (Mac); manual notarization in CI

### Architecture diagram

```
┌─────────────────────────────────────────────────────────┐
│                  Lictor Studio (Tauri app)               │
├─────────────────────────────────────────────────────────┤
│  Webview (Solid + Tailwind)        ← UI thread          │
│     ↑                                                    │
│     │ IPC (JSON over Tauri's bridge)                    │
│     ↓                                                    │
│  Tauri Core (Rust)                 ← business logic     │
│     ↓                                                    │
│  lictor-core (Rust crate)          ← shared with skills │
│     • 7 check engines                                   │
│     • AUDIT.json reader/writer                          │
│     • Platform fingerprinter (Lovable / Bolt / v0 / ...)│
└─────────────────────────────────────────────────────────┘

Network sockets opened: ZERO.
Files written outside app data dir: ZERO (unless user explicitly exports).
Telemetry: NONE.
```

### Telemetry — none, ever

This is non-negotiable. Studio's whole pitch is "offline-by-design." We do **not** ship Sentry, do **not** ship analytics SDKs, do **not** ping a "check for updates" endpoint on launch. The auto-updater pings `lictorai.com/studio/update.json` (Tauri's standard updater URL) but only when the user explicitly opens the "Check for updates" menu item or, on launch, the update preference setting is enabled.

This is documented in Settings → Privacy as "Lictor Studio sends zero data to lictorai.com or any third party. The only outbound network call is to check for app updates, and you control whether that happens."

---

## 4. File structure

Studio lives in a new top-level directory in the monorepo:

```
~/Lictor/studio/
├── Cargo.toml                      # Tauri+core dependencies
├── tauri.conf.json                 # Tauri config (signing, bundles)
├── src-tauri/                      # Rust side
│   ├── src/
│   │   ├── main.rs                 # Entry point
│   │   ├── commands.rs             # Tauri commands (IPC handlers)
│   │   ├── audit.rs                # Wraps lictor-core::run_audit
│   │   ├── audit_json.rs           # AUDIT.json import/export
│   │   ├── settings.rs             # Settings persistence
│   │   └── updater.rs              # Auto-update config
│   ├── icons/                      # macOS .icns, Windows .ico
│   ├── build.rs
│   └── tauri.conf.json
├── src/                            # Frontend (Solid + Tailwind)
│   ├── App.tsx
│   ├── routes/
│   │   ├── audit.tsx               # Run audit / drop-zone screen
│   │   ├── findings.tsx            # Findings list + filters
│   │   ├── detail.tsx              # Per-finding detail view
│   │   ├── settings.tsx            # Settings panel
│   │   └── about.tsx               # About + version + privacy notice
│   ├── components/
│   │   ├── SeverityBadge.tsx
│   │   ├── FindingCard.tsx
│   │   ├── CodeBlock.tsx           # Syntax-highlighted snippet
│   │   ├── DropZone.tsx
│   │   └── ...
│   ├── lib/
│   │   ├── tauri.ts                # Typed Tauri command wrappers
│   │   ├── audit-types.ts          # TS types matching AUDIT.schema.json
│   │   └── format.ts               # Plain-English formatters
│   ├── styles/
│   │   └── globals.css
│   └── main.tsx
├── public/
│   └── lictor-mark.svg
├── tests/
│   ├── e2e/                        # Playwright against the running app
│   └── unit/                       # Vitest
├── README.md
├── CHANGELOG.md
├── package.json
└── tsconfig.json
```

Shared with the rest of the Lictor monorepo:
- `~/Lictor/core/` — the `lictor-core` Rust crate (already exists)
- `~/Lictor/docs/standards/AUDIT.schema.json` — the schema Studio validates against
- `~/Lictor/brand/` — icons, colors, fonts

---

## 5. UX walkthrough

### First launch (Day 1, fresh install)

1. User downloads `Lictor.Studio.dmg` from `lictorai.com/studio` (~25 MB).
2. Opens DMG, drags to Applications. macOS Gatekeeper: passes (signed + notarized).
3. First launch shows a 3-screen onboarding:
   - **Screen 1:** "Lictor Studio audits your AI-built apps locally. Nothing leaves your machine." Button: "Continue."
   - **Screen 2:** "We don't collect any data. No telemetry. No accounts. No API keys. Ever." Button: "Continue."
   - **Screen 3:** "Drop a project folder below to run your first audit." Drop zone + Browse button.
4. User drops a Lovable project folder.
5. Audit starts. Progress bar shows: detected platform (`Lovable`), running checks (1/7 → 7/7), estimated time remaining.
6. ~30–60 seconds later, findings appear in the list view.
7. User clicks a 🔴 critical finding. Detail view opens:
   - Title in plain English
   - Severity + category badges
   - Evidence: file path + line + syntax-highlighted snippet
   - **What this means** (1–3 sentence summary)
   - **How to fix** (1-line summary + diff)
   - **Rotated secrets needed** (if applicable, with link to `/lictor-rotate` runbook)
   - Buttons: "Open in Claude Code", "Copy fix to clipboard", "Mark as resolved"

### Returning user flow

1. User opens Studio. Recent audits list shown (last 5 projects audited).
2. Click an item to re-audit, or drop a new folder.
3. Settings sidebar accessible via gear icon: appearance, check toggles, default audit path, auto-update preference.

### The "import other tool's output" flow

1. User has a `snyk-output.json` they ran earlier.
2. File → Import AUDIT.json (`Cmd+I`).
3. Studio renders Snyk's findings in Lictor's UI with the plain-English translations (the same logic from `/lictor-explain`).
4. User can now compare side-by-side: "Snyk found X, Lictor found Y, here's what each tool covered."

This is the anti-Snyk strategic asset: Studio becomes the *universal viewer* for any conforming security tool's output. Users start with Snyk + Studio. Some migrate to Lictor's own audit. The traffic flows the right direction.

### The "export findings" flow

1. After audit, File → Export findings (`Cmd+E`).
2. Choose format: AUDIT.json (default), Markdown report, plain-text summary.
3. Save to disk.
4. User shares the Markdown with a co-founder, or emails the AUDIT.json to an auditor.

---

## 6. AUDIT.json integration

Studio is the **reference consumer + reference emitter** of AUDIT.json v0.1.

**Studio MUST:**
- Validate every imported AUDIT.json against `/Users/raffa/Lictor/docs/standards/AUDIT.schema.json`
- Reject malformed input with a helpful error ("This file uses spec_version 0.2, Studio supports 0.1. Update Studio or use a v0.1 tool.")
- Emit AUDIT.json with `spec_version: "0.1"` and `tool.name: "lictor"` on every export
- Reconcile counts in `summary` with the actual `findings` array on emit
- Use `target.platform_fingerprint` to pick platform-specific rules during audit

**Studio MAY (v0.2+):**
- Support multiple `spec_version`s simultaneously
- Auto-migrate older AUDIT.json files to newer schema versions
- Merge findings from multiple AUDIT.json files (deduplicated by `fingerprint` field once standardized in v0.2)

---

## 7. Pricing + distribution model

### v0.1.0 — free, Apache 2.0

Studio v0.1.0 ships free. Apache 2.0. Source code in the monorepo (`~/Lictor/studio/`). Anyone can build it themselves; the precompiled `.dmg` is a convenience.

**Why free:**
- The audit logic is already free in the Claude Code skill. Charging for the desktop version creates a "OSS bait and switch" perception.
- The strategic value is *distribution*, not *revenue at v0.1*. Get 10,000 Macs running Studio first. Monetize the next layer.

### v0.2.0 — Studio Pro (paid tier launches Q1 2027)

A separate "Pro" build that includes everything in the free tier plus:

| Pro feature | Why people pay |
|---|---|
| Encrypted local audit history (AES-256 at rest) | Privacy-paranoid users want the audit trail itself protected |
| Custom check authoring (write your own checks in Rust or YAML) | Pro users have org-specific patterns they want to scan for |
| Team license keys (5 / 25 / unlimited tiers) | Small dev studios buy for their team |
| Priority support (24h email response SLA) | Enterprise-curious customers pay for SLAs |
| Advanced reporting (PDF export, custom branding) | Customers shipping audit reports to their own clients want this |

### Pricing (proposed for v0.2.0 ship)

- **Studio Free** — $0, forever
- **Studio Pro (individual)** — $79 one-time (lifetime license, free minor updates, $49 to upgrade to next major) OR $7/mo (cancel anytime, always latest version)
- **Studio Pro (team-5)** — $299 one-time or $25/mo, 5 named seats
- **Studio Pro (team-25)** — $999 one-time or $79/mo, 25 named seats
- **Studio Pro (unlimited)** — $2,999 one-time or $199/mo, unlimited seats in one org

### Distribution

- **Primary:** direct download from `lictorai.com/studio` (signed .dmg)
- **Secondary:** Homebrew cask (`brew install --cask lictor-studio`) — Q1 2027
- **Tertiary:** Mac App Store — investigated for v0.3+ (signing + review process adds friction; we control distribution better via direct download for v0.1–0.2)
- **Auto-update:** Tauri's built-in updater pulls from `lictorai.com/studio/update.json`. User can disable.

### Code signing requirements

- **macOS:** Apple Developer ID Application certificate ($99/yr) + notarization (free, automated in CI)
- **Windows (v0.2):** Code-signing certificate from Sectigo or similar ($300–500/yr) + SmartScreen reputation (builds over time)

---

## 8. Milestones to Q4 2026 ship

Working back from the Dec 31, 2026 v0.1.0 ship target:

| Week | Milestone | Gate to pass |
|---|---|---|
| **Sep 1, 2026** | Spec sign-off | This doc + Raffa's revisions merged |
| **Sep 15** | Tauri skeleton + first command | `cargo tauri dev` opens an empty window; one IPC call works |
| **Oct 1** | Audit pipeline wired | Drop folder → 7 checks run → findings returned as JSON to frontend |
| **Oct 15** | Full UI: audit + findings list | All findings render with severity icons, category filters work, search works |
| **Nov 1** | Detail view + Open in Claude Code | Per-finding detail page complete; `claude://` URL scheme tested |
| **Nov 15** | AUDIT.json import/export | Both flows working against the schema; tested against Snyk, Semgrep, Trivy output |
| **Dec 1** | Settings panel + auto-updater | All settings persisted; updater pings the right URL; rollback path tested |
| **Dec 15** | Code signing + notarization | Signed `.dmg` passes Gatekeeper on a fresh Mac without warnings |
| **Dec 22** | Landing page (`lictorai.com/studio`) + first paying tier infrastructure | Page live; Stripe Checkout wired for Pro v0.2 pre-orders (optional) |
| **Dec 31** | **v0.1.0 ships** | Public download live; first announcement post live |

Cushion: 2 working weeks built into the schedule for the inevitable signing/notarization/Tauri-update-system snags.

---

## 9. Open questions for Raffa

Decisions only Raffa can make:

1. **Tauri vs Electron — do you want to revisit?** The spec assumes Tauri. If you have Electron expertise on tap or want the bigger ecosystem, this is the time to decide. (Strong rec: stay Tauri. The 10x size + memory win + Rust-native bridge is decisive.)
2. **Mac-only v0.1 or also Windows?** The spec defers Windows to v0.2 (Q1 2027). If the audience research says Windows is bigger than I estimated, the priority flips. (Strong rec: Mac first. Indie vibe-coder population is heavily Mac.)
3. **Pricing for v0.2 Pro — confirm or revise?** $79 one-time / $7/mo for individual feels right for the indie audience. Team tiers ($299/$999/$2,999) are speculative. Worth running by 5 target users.
4. **Pro feature priority** — which Pro feature ships first matters. The spec orders them: encrypted history → custom checks → team licenses → priority support → advanced reporting. If you have signal that one is more demanded, reorder.
5. **Auto-update opt-in or opt-out?** The spec says opt-out (default to checking for updates, user can disable). Privacy-paranoid posture would argue opt-in. Tradeoff: opt-in means most users never update, security patches don't deploy. (Lean: opt-out, but make the disable obvious.)
6. **Mac App Store — pursue for v0.3 or never?** App Store gives distribution + trust but Apple takes 15-30% and has approval friction. Many privacy-focused apps stay off the App Store. (Lean: never, unless an investor or partner makes it strategic.)
7. **Should Studio call out to the local Claude Code skill if installed?** A "Run via Claude Code" button could offload the inference to Anthropic's product. Adds complexity but lets users with Claude Code get the agent-crew experience inside Studio. (Lean: ship without this in v0.1; add as a Settings toggle in v0.2.)

---

## 10. What needs to happen this week (May 18, 2026 onwards)

If you greenlight this spec:

- [ ] Apple Developer Program enrollment ($99/yr, ~24h activation)
- [ ] Decide individual vs team Apple ID (matters for signing key inheritance)
- [ ] Reserve the `lictorai.com/studio` route in the landing site
- [ ] Add `studio` to the Lictor monorepo CI matrix (Rust + Node both required)
- [ ] Start a `studio/CHANGELOG.md` with v0.1.0-pre.0 → v0.1.0 entries
- [ ] Mongoose the Tauri 2.x + macOS signing toolchain end-to-end on a throwaway app to verify the path works (avoid finding signing issues in Week 11 of build)

These are all <2h tasks. Do them in May so they don't compound risk in September.
