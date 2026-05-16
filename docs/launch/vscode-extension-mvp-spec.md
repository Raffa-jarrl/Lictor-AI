# Lictor VS Code extension — MVP scoping doc (v0.1.0)

> **Status:** Draft for Raffa review. Sign-off target: week of Sep 1, 2026.
> **Ship target:** Dec 31, 2026 (v0.1.0 live on VS Code Marketplace + Open VSX).
> **Owner:** TBD (contractor or Raffa). Spec author: Lyrebird. > **Cross-refs:** `ROADMAP.md` Q4 2026; `docs/launch/operation-triumph-expanded.md` Front 1+2.

---

## 1. Product thesis

Claude Code is one IDE; Cursor, Windsurf, and vanilla VS Code with Copilot are the rest of the market launch must reach. Snyk Studio already lives inside Cursor and Claude Code. If Lictor doesn't show up in the IDE the user is actually typing in, the brand never gets seen during the moment a security finding would matter.

The job-to-be-done: **a founder shipping from Lovable / Bolt / v0 opens their generated codebase in Cursor, and wants to know — before they push — whether the AI shipped something embarrassing.** Today they either run `/lictor-security-check` in a separate Claude Code window (context switch + skill must be installed globally) or wait until Shield catches it post-deploy. The extension closes the loop where the code already lives.

Target audience, priority order:
1. **Cursor users** — largest segment of the AI-builder market; Cursor is a VS Code fork that installs extensions via Open VSX.
2. **Vanilla VS Code + Copilot users** — the upmarket leak-through audience (Front 2 in the strategic plan).
3. **Windsurf users** — smaller but growing; Codeium IDE is also VS Code-derived.

Relationship to the Claude Code skills: **same engine, different surface.** The extension calls into `lictor-core` (the Rust crate already powering Shield via WASM) for the 7 static checks. It does not duplicate logic and does not require Claude Code installed. If Claude Code *is* installed alongside, a Code Action hands the finding off to `/lictor-fix-it`. The skills remain the agentic surface; the extension is the passive in-IDE eye.

**Success at Q1 2027** (90 days after v0.1.0 ships):
- 10,000 cumulative installs across VS Code Marketplace + Open VSX
- 2,500 WAU (heuristic: 25% retention from install)
- 500 Marketplace stars (Snyk's extension has ~600; achievable bar)
- ≥1 community-contributed check (validates the OSS posture)

---

## 2. MVP scope

**Ships in v0.1.0:**

- The 7 static checks from `/lictor-security-check`, running locally against the open workspace, no network calls.
- 4 commands in the Command Palette:
  - `Lictor: Audit current file` — runs the relevant subset of checks on the active editor's file
  - `Lictor: Audit entire project` — full sweep of the workspace
  - `Lictor: Explain this finding` — opens a webview with the plain-English breakdown, same voice as the skill
  - `Lictor: Import audit from file` — ingests an AUDIT.json from Snyk / Semgrep / Trivy / Lictor CLI and renders findings in the same UI
- Output surfaces:
  - **Problems panel** — every finding registered as a `Diagnostic` with the right severity (Critical/High → Error, Medium → Warning, Low → Information, Info → Hint)
  - **Inline diagnostics** — squigglies on the offending line, with hover tooltips containing the plain-English summary
  - **Sidebar view** — a custom `TreeView` in the activity bar grouping findings by severity, with a click-through to the file and a "Show details" action that opens the webview
  - **Status bar item** — `Lictor: 3 critical · 5 high` with a click to focus the sidebar
- AUDIT.json round-trip: import any conforming file, export the current findings to `./AUDIT.json` via `Lictor: Export current findings`.
- One-click "Open in Claude Code" Code Action on every finding — copies the finding to clipboard plus drops a hint to invoke `/lictor-fix-it`. (We do not directly orchestrate Claude Code; we make the handoff trivial.)
- Auto-detect Lovable / Bolt / v0 / Cursor / Replit project fingerprints from `package.json`, `.lovable.json`, `.bolt/*`, etc., and stamp the detected platform into emitted `AUDIT.json` (`target.platform_fingerprint`).

**Explicitly OUT of v0.1.0** (deferred):

- Auto-fix Code Actions (Claude Code owns agent surface; extension stays read-only, matching the skill).
- Multi-language UI (English only; ES/PT in v0.2 paired with Q4 landing translations; HE/JA in v0.3 per Q1 2027 plan).
- Background watch / audit-on-save (manual invocation only — avoids surprise CPU spikes).
- Telemetry of any kind. Permanent design choice; documented in README.
- Guardian dashboard sync (v0.2, opt-in — see §9).
- Auto-prompt on platform detect (v0.2 once we know if it annoys).
- Sentinel SDK install assistant (v0.2).
- Custom rule authoring (v0.3+; the Q1 2027 Skill Marketplace covers this).

Discipline: **v0.1.0 is the read-only-audit skill made native to the IDE.** No agent loop, no chat, no UI tricks beyond standard VS Code idioms. Anything beyond "show findings, explain findings, export findings" gets pushed.

---

## 3. Tech choices

**Language:** TypeScript. Non-negotiable. Target TS 5.4+, Node 20 (matches VS Code's bundled runtime as of May 2026). `@types/vscode` pinned to the engine target.

**Build:** esbuild. Single bundle to `dist/extension.js`, ~50ms cold builds, no webpack config debt. Shield already uses esbuild (`shield/build.mjs`); reuse the pattern verbatim.

**Test:** `@vscode/test-electron` + Mocha — the VS Code-blessed combo. Vitest is faster but the integration harness needs a real VS Code instance; `runTests` is what Marketplace pipelines expect. Pure-logic unit tests can run under Vitest in parallel.

**The engine: `lictor-core` via WASM, identical to Shield.** The Rust crate at `core/` already compiles to a `cdylib` with `wasm-bindgen`, already exports `analyze_secrets`, `analyze_ai_agent`, `classify_supabase_probe`, etc., and is already consumed by `shield/src/audit-engine.ts`. Reusing it gives us:

- Zero duplication of the 7 checks — no drift between Shield, Sentinel, extension
- ~870 KB WASM (per `shield/wasm/lictor_core_bg.wasm`) — fine for a one-time IDE install
- Native FS in the extension means we read files directly and pass strings to the analyzers; the `--target web` WASM build needs no Node shim

Explicitly rejected:
- **Node-native binding (NAPI):** would require per-platform binaries (macOS x64/arm64, Linux x64/arm64, Windows x64) and a more complex publishing pipeline. WASM is portable everywhere VS Code runs including Codespaces and code-server.
- **Subprocess to a Lictor CLI:** slow, requires PATH setup, breaks on Windows.
- **Pure-TS reimplementation of the checks:** drift risk + duplicated maintenance.

**Marketplace publishing:**
- **VS Code Marketplace** (Microsoft) via `vsce publish`. Publisher `lictor` (Raffa registers; free; Azure DevOps PAT).
- **Open VSX** (Eclipse) via `ovsx publish`. Required for Cursor / VSCodium / Gitpod / code-server. Same `.vsix`.

Both free. CI (GitHub Actions) builds on tag push `vscode-extension-v*`, runs tests, then `vsce publish` → `ovsx publish`.

**Telemetry: NONE.** No `@vscode/extension-telemetry`, no phone-home, no remote logging. Documented in README and `package.json`. Shield is local-only, Sentinel is local-only, extension is local-only — same posture, no exceptions. If Guardian sync ships in v0.2, it is **opt-in with a visible toggle**, never default.

---

## 4. File structure

Lives at `/Users/raffa/Lictor/vscode-extension/`:

```
vscode-extension/
├── package.json              # manifest + contributes block
├── tsconfig.json
├── build.mjs                 # esbuild script, mirrors shield/build.mjs
├── .vscodeignore             # excludes src/, tests/, node_modules/.cache
├── README.md                 # marketplace listing; doubles as in-IDE walkthrough
├── CHANGELOG.md              # required by marketplace for "What's New" tab
├── LICENSE                   # Apache-2.0 (matches monorepo)
├── icon.png                  # 128x128 marketplace icon (Lictor brand)
├── src/
│   ├── extension.ts          # activate() / deactivate() entry point
│   ├── commands/
│   │   ├── auditFile.ts
│   │   ├── auditProject.ts
│   │   ├── explainFinding.ts
│   │   ├── importAudit.ts
│   │   └── exportAudit.ts
│   ├── engine/
│   │   ├── runner.ts         # wraps lictor-core WASM, drives the 7 checks
│   │   └── platformDetect.ts # Lovable/Bolt/v0/Cursor/Replit fingerprinting
│   ├── ui/
│   │   ├── diagnostics.ts    # Problems-panel integration
│   │   ├── treeView.ts       # sidebar findings tree
│   │   ├── statusBar.ts      # status-bar item
│   │   └── findingWebview.ts # "Explain this finding" rich-detail webview
│   ├── audit/
│   │   ├── findingToDiagnostic.ts
│   │   ├── auditJson.ts      # AUDIT.json read/write + schema validation
│   │   └── voice.ts          # plain-English formatting helpers
│   └── types.ts              # shared types (Finding, Severity, etc — mirror shield/src/types.ts)
├── wasm/                     # checked-in build artifact from lictor-core
│   ├── lictor_core.js
│   ├── lictor_core_bg.wasm
│   └── lictor_core.d.ts
└── tests/
    ├── runTest.ts            # @vscode/test-electron entry
    ├── suite/
    │   ├── index.ts
    │   ├── audit.test.ts
    │   ├── auditJson.test.ts
    │   └── platformDetect.test.ts
    └── fixtures/             # known-vulnerable mini-projects (Lovable shape, Bolt shape, etc.)
```

The `contributes` block in `package.json` declares: 4 commands, 1 view container (`lictor`), 1 tree view (`lictorFindings`), 1 status-bar item, 4 configuration keys (auto-audit on save toggle [default false], severity threshold for status-bar display, export path for AUDIT.json, claude-code-handoff toggle [default true]).

---

## 5. User experience walkthrough

**Install:** user searches `lictor` in the Extensions tab (VS Code or Cursor). Top result: "Lictor — security audit for AI-built apps." One click installs. No signup, no API key, no consent dialog — nothing to consent to (zero telemetry, zero network calls without explicit user action).

**First launch:** on activation the extension does three things:
1. Registers the 4 commands + sidebar view + status-bar item
2. Reads `package.json` / `.lovable.json` / `.bolt/*` to detect the build platform
3. Sets status bar to "Lictor: ready" (gray; if platform detected, "Lictor: ready · Lovable detected")

It does **not** auto-run an audit and does **not** show a welcome walkthrough on first install. Walkthroughs land in v0.2 once we know what actually confuses people.

**First audit:** Cmd+Shift+P → "Lictor" → `Audit entire project`. Progress notification: "Lictor: scanning 247 files..." Completes in 3-15s (all 7 checks are regex/pattern-based; no AST in v0.1).

**Where findings appear:**
- **Problems panel** — every finding registered as a `Diagnostic` with `source: "lictor"`. The `message` is the plain-English title (*"Your `/api/users` endpoint gives out the customer list to anyone"*) — not the CWE ID.
- **Inline squigglies** on the offending line; hover tooltip shows plain-English summary + "Explain this finding" link.
- **Sidebar tree** grouped by severity: 🔴 Critical (2), 🟠 High (5), 🟡 Medium (8), 🔵 Low (12), ⚪ Info (3). Click jumps to file+line.
- **Status bar:** "Lictor: 2 critical · 5 high". Click focuses sidebar.

**Tooltip example (verbatim hover content):**

```
🔴 CRITICAL — Your /api/users endpoint gives out the customer list to anyone

Anyone who hits your-app.com/api/users gets your full user table. No
login check. The AI built the endpoint but didn't add the door lock.

📖 Explain this · 🔧 Open in Claude Code · 📤 Export AUDIT.json
```

Voice = `/lictor-security-check`. Same severity ladder, same glyphs, same diction.

**Fix workflow.** v0.1.0 is read-only. Two paths:
1. **"Open in Claude Code"** Code Action (lightbulb on the squiggly) — copies the finding to clipboard and opens Claude Code with a pre-filled prompt suggesting `/lictor-fix-it`. If Claude Code isn't installed, a toast offers a fallback: *"Copy this finding and ask your AI of choice."*
2. **"Explain this finding"** webview — full plain-English breakdown, code snippet, the "What can go wrong" story, the "How to fix tonight" steps. Voice = `/lictor-explain`. One-shot rendered, not conversational.

**Language:** v0.1.0 English only. ES/PT in v0.2 (Q1 2027, paired with landing translations). HE/JA in v0.3. The `findingToDiagnostic` layer ships with a translation hook from day one so we don't refactor.

---

## 6. AUDIT.json integration

The extension is an **AUDIT.json producer and consumer.** This is the anti-Snyk strategic asset: a Snyk user runs `Lictor: Import audit from file` against the JSON Snyk emitted, and gets every finding rendered in Lictor's plain-English UI with the same severity ladder, same explain-this webview, same handoff path. They didn't switch tools — they switched *translators*. That's the wedge.

**Producer:** `Lictor: Export current findings` writes `${workspace}/AUDIT.json`. Optional `lictor.autoExport` writes on every run (default off — see §9). Schema: `docs/standards/AUDIT.json.md` v0.1, with `tool.name = "lictor-vscode"`, `tool.version` from `package.json`, `target.platform_fingerprint` from auto-detection.

**Consumer:** `Lictor: Import audit from file` accepts any conforming `AUDIT.json` (spec v0.1+). Validates against the schema (shipped inline as `audit-schema.json`), maps `severity` to diagnostic levels, populates Problems panel + sidebar + status bar identically to a native run. Tool-of-origin (`tool.name`) shown in the sidebar header.

---

## 7. Milestones to Q4 2026 ship

Working back from Dec 31, 2026. Each milestone has a deliverable + a gate.

| Week of | Deliverable | Gate (must pass to proceed) |
|---|---|---|
| **Sep 1, 2026** | This spec, Raffa-reviewed and signed off | Raffa approves §9 open questions; any deltas merged into this doc |
| **Sep 15** | Skeleton extension: `package.json` + `extension.ts` + 4 command stubs registered | All 4 commands appear in Command Palette when extension is loaded in a fresh VS Code window; stubs show "not implemented" toast |
| **Oct 1** | `lictor-core` WASM wired in; 7 checks run against the open workspace via `Lictor: Audit entire project` | Audit completes against 5 known-vulnerable fixtures (one per platform: Lovable, Bolt, v0, Cursor, Replit) and finds ≥80% of the seeded vulns Shield also catches on the deployed version |
| **Oct 15** | Problems-panel + inline-diagnostics integration; status bar live | Every fixture's findings appear as `Diagnostic` entries with correct severity; squigglies render on correct line numbers; status bar shows accurate count |
| **Nov 1** | Sidebar tree view + "Explain this finding" webview | Webview renders the plain-English breakdown using the same voice template as `/lictor-explain`; sidebar groups by severity; click-through to file works |
| **Nov 15** | AUDIT.json import + export; Code Action for "Open in Claude Code" | Imports valid Snyk-emitted JSON (we use a sample from the Snyk docs); exports a schema-valid AUDIT.json; Claude Code handoff opens a new window with the finding prefilled |
| **Dec 1** | Cursor + Windsurf compatibility tested; fixes for any divergence | Install + run full audit on Cursor (latest) and Windsurf (latest); all 4 commands work; no console errors |
| **Dec 15** | Marketplace + Open VSX publishing pipeline; publisher account verified | `.vsix` builds in CI; `vsce publish --pre-release` succeeds against a staging publisher; Open VSX namespace claimed |
| **Dec 22** | Launch dress rehearsal — internal install on Raffa's machine + 3 design partners; bug-bash | Zero P0 bugs; CHANGELOG entry written; README polished for marketplace listing |
| **Dec 31** | **v0.1.0 LIVE** on VS Code Marketplace + Open VSX | Both listings searchable for `lictor`; install on a fresh machine works end-to-end |

The Dec 22 cushion is deliberate — Marketplace review can take 24-72h; we don't want to be debugging publisher verification on Dec 30.

If a milestone slips: shift the *gate*, not the date. v0.1.0 ships Dec 31 even if Cursor compatibility is rough (CHANGELOG flags known issues, v0.1.1 follows in early Jan). The strategic plan needs the Q4 2026 IDE-presence milestone hit.

---

## 8. Distribution + install flow

**Publishing requirements:**
- **VS Code Marketplace:** free publisher account, Microsoft Partner Center signup, Azure DevOps PAT for `vsce publish`. Publisher ID `lictor` (Raffa to claim). No code signing required.
- **Open VSX:** free namespace at open-vsx.org, GitHub OAuth login, `ovsx create-namespace lictor` then `ovsx publish`. No signing required.
- **Verified publisher badge:** domain verification at `lictorai.com` via DNS TXT record. Worth doing — visible trust signal on the listing.

**Discovery:**
- Marketplace search: `lictor` (primary), `vibe coder security`, `ai security audit`, `lovable security`, `bolt audit` (long-tail).
- `categories`: `Linters`, `Other`. Tags: `security`, `audit`, `ai`, `lovable`, `bolt`, `v0`, `cursor`.
- Cross-link from `lictorai.com` ("Install in VS Code / Cursor →") and every Claude Code skill README.
- Oct 6 launch teardown #1 includes "We built this — try it in your IDE" CTA.

**Install:** one click → extension loads → no signup, no API key, no consent dialog, no welcome popup. Fully functional on first open. Every friction point loses 5-15% of installs; we have none.

**Activation:** `onStartupFinished` only (no eager activation; zero perf cost when unused). README in the Marketplace listing doubles as a 60-second walkthrough.

**Updates:** Marketplace auto-updates by default. Patch (v0.1.x) for bugs; minor (v0.x.0) for features; v1.0.0 reserved for the first stable release after ~10k installs. CHANGELOG.md is the source of truth in builder dialect — no marketing voice.

---

## 9. Open questions for Raffa

1. **Guardian sync.** Opt-in push of findings to Guardian (workspace settings `lictor.guardian.endpoint` + `lictor.guardian.token`)? Recommend: **no in v0.1.0, yes in v0.2.** Keeps launch surface clean.

2. **AUDIT.json auto-export.** Default-on or explicit-only? Recommend **explicit only** — default-writes surprise users and create git noise. Trade-off: auto-export accelerates standard adoption.

3. **Auto-prompt on platform detection.** Notification when Lovable/Bolt detected, or silent? Recommend **silent in v0.1.0**, A/B in v0.2. Notifications annoy fast.

4. **Cursor / Windsurf pre-funding.** ~3 contractor days in Nov on explicit Cursor + Windsurf testing, or triage post-launch? Recommend **pre-fund.** Cursor is target audience #1; "doesn't work in Cursor" is the worst possible launch headline.

5. **Naming.** Three options: `Lictor` (brand-pure), `Lictor Security` (SEO-friendly), `Lictor for Cuttlefish Coders` (audience-targeted but locks out upmarket leak-through). Recommend **`Lictor Security`**.

6. **Check contributions.** Accept TS PRs against the extension, or route all check authoring through `lictor-core` (Rust, harder)? Recommend **route through `lictor-core`** — single source of truth across Shield / Sentinel / extension.

7. **Pre-release channel.** Ship `v0.1.0-rc.1` to Marketplace as `--pre-release` in Dec 15-22 for design partner install? Recommend **yes** — real pipeline test without polluting stable.

---

## Appendix — non-goals for v0.1.0 (one-line each, for clarity)

- No chat interface (Claude Code owns that).
- No fix-application (read-only, by design — `/lictor-fix-it` owns that).
- No AST parsing (regex + string matching only — same as `lictor-core` ships today).
- No background audit (manual invocation only).
- No remote scanning (the workspace is the unit of audit).
- No PII collection.
- No update notifications inside the IDE (Marketplace handles it).
- No "Lictor Premium" upsell anywhere in the UI.
