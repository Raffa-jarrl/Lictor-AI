# Lictor public roadmap

> **Snyk's roadmap is closed. Lictor's is here.**
> Updated: 2026-05-15 (Patrol added as Q3 headline; soft launch Aug 15)

## 🎯 The bet — if Lictor wins, this is true in 18 months

1. Every Lovable / Bolt / v0 / Cursor founder knows their **Lictor score** before they ship
2. **AUDIT.json** is the universal output format across Semgrep, Aikido, Snyk, and us
3. `lictor.ai/scan/<url>` is the answer to "is my AI-built app safe?" the way SSL Labs is the answer to "is my cert configured right?"
4. The **Lictor Patrol** dataset is the largest public corpus of AI-app security postures, cited in every "state of AI security" report from 2027 on
5. The **11-agent crew** is the reference architecture for OSS security projects

If those are true, the rest is detail. Everything below is a step toward one of those five.

## 🚀 The headline — Lictor Patrol

**[Full spec →](docs/launch/lictor-scan-and-patrol-v0.1.md)** · **[Soft-launch draft →](docs/launch/lictor-patrol-announcement.md)**

Patrol is an autonomous engine that scans every new public vibe-coder app in the last 7-30 days, finds the critical bugs, and contacts the founders privately under the name **Lictor AI** — with the specific finding, the 5-minute fix, and the free tool sitting next to it. The 30-day silent run produces a single launch story on **Aug 15**: *"We scanned 30,000 vibe-coded apps. Here's what we found."*

By Oct 6 (the official launch), Lictor is already a known thing because the investigation was already published. The rest of the suite is the natural next chapter.

This is the move. Everything in Q3 below serves it.

---

---

## ✅ Done — May 2026 foundation

Pre-Year-1 work shipped before public launch:

- [x] **Repo public** at github.com/Raffa-jarrl/Lictor-AI (May 15)
- [x] **9 CI jobs green** — every push validates core, studio, sentinel, sentinel-py, guardian, shield, landing, cli, setup.sh
- [x] `/lictor-security-check` Claude Code skill — 7 checks tuned for Lovable / Bolt / v0 / Cursor / Replit
- [x] `/lictor-explain` Claude Code skill — universal translator across Snyk, Semgrep, Trivy, npm audit, GitHub Security, Aikido outputs (plain English)
- [x] `/lictor-fix-it` Claude Code skill — drafts the fix + diff
- [x] `/lictor-rotate` Claude Code skill — 10 provider-specific key-rotation runbooks
- [x] `lictor-core` Rust crate — 7 checks (secrets / database / auth / cors / ai-agent / webhooks / hallucinated_packages), 45 tests
- [x] `lictor-cli` terminal binary — `lictor audit . --format human/json/markdown` + `--fail-on critical` for CI
- [x] `lictor-studio` Tauri skeleton — Rust compiles + TS typechecks + icons rendered (ships Dec 31)
- [x] Shield Chrome extension — WASM + 5 URL-based checks
- [x] Sentinel npm + PyPI alpha — runtime defense, READMEs launch-ready, LICENSE files in place
- [x] Guardian dashboard — Next.js + Postgres, integration tests in CI
- [x] AUDIT.json v0.1 spec + JSON Schema (CC0 community standard)
- [x] `landing/` repositioned — vibe-coder-vertical wedge; Beacon waitlist page; `.well-known/security.txt`
- [x] All OSS hygiene files: README, LICENSE, CHANGELOG, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, FUNDING, Dependabot, 6 issue templates, PR template
- [x] Brand asset render pipeline — 17 auto-generated outputs from 2 SVG sources
- [x] Monthly metrics generator (Python) + cron + launchd plist
- [x] 11-agent crew operational — sleep-resistant cron + 4 launchd jobs
- [x] Probe agent extended for weekly competitive-watch on 6 competitors
- [x] Mission Control: competitive-watch + year-1-metrics + waitlist-metrics dashboards
- [x] ~80 strategic + tactical docs in `docs/launch/` — year plan, anti-Snyk playbook, M&A strategy, teardown engine, Beacon campaign, acquirer deck, press kit, 5 polished launch teardown drafts, Sep 22 disclosure emails
- [x] **VS Code extension skeleton** (`vscode-extension/`) — manifest, diagnostics provider, sidebar tree view, 5 commands, README; TS compiles clean (ships v0.1 in Q4 2026)
- [x] **4 new specialist agent SOULs** — Translator (🌐 locale rendering), Reel (🎬 video scripts), Booth (🎙️ podcast/CFP scouting), Bridge (🤝 GitHub triage); bring-online dates staggered Oct 2026–Jan 2027
- [x] **AUDIT.json v0.2 adoption outreach** — 5 personalized email drafts (Semgrep, VibeEval, Symbioticsec, Aikido, Snyk) at `docs/launch/audit-json-adoption-outreach.md`
- [x] **Waitlist landing translated** to Spanish (LATAM) and Portuguese (BR) at `landing/translations/{es,pt-BR}/waitlist.html`
- [x] **Course removed from Lictor scope** — separate consulting business, no longer a revenue line. Three dedicated docs deleted; planning docs (year-plan, operation-triumph, acquirer-deck, m-and-a, etc.) annotated with course-removed headers. Revenue model: Teams + AaaS + Enterprise.
- [x] **Repo URL canonicalized** to `github.com/Raffa-jarrl/Lictor-AI` across 55 files (READMEs, landing, translations, CI, agent SOULs, monthly-metrics script). The `lictor-ai/lictor` org never existed.
- [x] **Marketing performance-report template** (`docs/launch/performance-report-template.md`) — 3-cadence scaffold (daily / weekly / monthly transparency / QBR), 3 north-star metrics (WAI, AaaS MRR-eq, GH stars), data-source → agent → frequency mapping, 10-item setup checklist
- [x] **Design system v0.1** — audit (8.5/10, 4 drift points fixed), canonical reference at `docs/design-system/README.md` (tokens + components inventory + 5 rules), first formal component spec (SeverityBadge, 5 levels) at `docs/design-system/components/severity-badge.md`. Tokens extended in `landing/style.css`: spacing scale, radius scale, motion, severity tints, accent derivatives. Extracted `landing/waitlist/waitlist.css` (was inline; ES + PT-BR translations were referencing a missing file).

## 🚀 Now — Q3 2026 (Jun–Sep) — *Patrol & soft launch*

| Week | Item | Outcome target | Kill | Owner |
|---|---|---|---|---|
| **Jun 1 (W22)** | Patrol architecture live — source enumerators (6/10), cron, dedup, queue, Scan engine deployed as Cloudflare Worker | First 100 URLs scanned end-to-end | Engine fails on >30% of URLs | dev (C-3PO) + Conductor |
| **Jun 8 (W23)** | **PILOT SCAN — last 7 days cohort** | 500-1,000 apps scanned, 50+ private outreaches sent | <100 apps scanned | Bridge drafts; Dor reviews; Mirror watches voice |
| **Jun 15 (W24)** | Disclosure state machine + opt-out flow + scorecard page + OG-image renderer | 30-day timer running on every D/F finding | Any private finding leaks before window | dev + Quill |
| **Jun 22 (W25)** | Audit corpus (KV append-only) + `lictor.ai/in-the-wild` internal-only aggregate dashboard | First aggregate stats published internally | Corpus stores any URL or PII | dev + Conductor |
| **Jun 29 (W26)** | Patrol expands to last-30-days cohort + 4 remaining sources (YC, Cursor, npm, Twitter/X) | 4,000-6,000 apps scanned cumulative | <1,500 | Probe (extends from competitive-watch) |
| **Jul 6 (W27)** | **`lictor.ai/scan/<url>` PUBLIC** — paste-a-URL form + embeddable badge | 100 user-initiated scans in week 1 | <10 | dev + Quill (launch copy) |
| **Jul 13 (W28)** | Bridge auto-sends low-risk outreach (B/C); Dor still reviews D/F | First weekly leaderboard published (Lovable only) | Voice issues caught in Mirror review | Bridge + Mirror |
| **Jul 20 - Aug 14** | **SILENT RUN — 30 days, collecting data** | ~30,000 apps scanned cumulative; voice + outreach refined | <10,000 scanned by Aug 14 | All agents in production mode |
| **Aug 15 (W34)** | **🚨 SOFT LAUNCH** — publish the 30-day finding report (HN + Twitter + press + blog) | HN front page top 5 by noon; 5,000+ scans in week 1; 1,500+ stars added | Off HN front page by noon; <500 scans | Dor on the bullhorn; Bridge handles inbound; full crew on call |
| **Aug 16 - Oct 5** | Compound on the soft-launch attention | Weekly Patrol report becomes the content engine. Booth pivots to Lovable / Bolt / v0 platform-integration outreach | <2x weekly scan growth | Quill + Reel weekly content; Booth on integrations |
| **Sep 28-30** | First quarterly retrospective (calendar-blocked) | Honest review of soft-launch numbers + Patrol corpus state | — | Dor + Mirror |
| **Oct 6 (W41)** | **🎯 HARD LAUNCH** — full suite (Studio, CLI, SDK, Guardian, Shield, skill suite, VS Code) | "The next chapter" — not a debut. Patrol already established the brand. | Soft launch failed (then we delay hard launch) | Whole crew |

**Other Q3 items running in parallel:**

- [ ] **Beacon waitlist** — Target 1,000 signups by Oct 5, kill <250 by Jul 31 ([spec](docs/launch/beacon-campaign/README.md))
- [ ] **Landing site live at `lictor.ai`** via Cloudflare Pages (May 22)
- [ ] **Buttondown waitlist live** + 5-email drip sequence (May 25)
- [ ] **Sentinel 0.1.0 GA** on npm + PyPI — alpha → GA (Jul 1)
- [ ] **First 5 design partners signed** — Beacon-sourced + direct outreach (by Sep 1)

**Cuts from prior Q3 plan** (to make room for Patrol):
- ❌ 5 founder videos → cut to 2 (Reel agent takes the cadence Nov 1 anyway)
- ❌ "Weekly teardown engine by Sep 1" → replaced by Patrol (teardowns become Patrol byproducts when high-profile apps score F)
- ❌ "Sep 22 disclosure emails to 5 teardown targets" → made redundant by Patrol's own continuous responsible-disclosure flow

## 🛠 Next — Q4 2026 (Oct–Dec) — *compound the Patrol wedge*

Q4 is about turning Patrol's August-soft-launched credibility into installs, paid customers, and platform integrations.

- [ ] **Lictor for Teams paid tier** — $19/mo flat, unlimited seats. Outcome target: 100 paid teams by Dec 31, kill <20 by Nov 30
- [ ] **VS Code extension v0.1.0** — Marketplace + Open VSX, by W+12 (~Dec 22). Outcome: 500 installs by Jan 31, kill <50
- [ ] **CLI telemetry endpoint** (`metrics.lictor.ai/ping`, Cloudflare Worker, opt-in) — prerequisite for Tier-1 WAI metric. **Ship in W+2 (~Oct 20).**
- [ ] **First monthly transparency report** at `lictor.ai/transparency` — Nov 1 publish (backfilled to May 2026 so the public archive starts before Patrol)
- [ ] **Browser-extension scoring on every tab** — extend Shield with the Lictor Score badge. By W+8 (~Dec 1).
- [ ] **Lovable / Bolt / v0 integration outreach** (the AUDIT.json adoption play, now compelling because we have Patrol's receipts). Goal: 1 of 3 integrated by Q1 2027.
- [ ] **Bridge agent online Oct 13** for community triage (Patrol intake hits Bridge first)
- [ ] **Reel agent online Nov 1** for video script production
- [ ] **Translator agent online Dec 1** for ES + PT-BR
- [ ] **10 weekly Patrol findings reports published Oct 6 → Dec 15** (auto-generated by Patrol; reviewed by Mirror; published as the weekly newsletter)
- [ ] **1 cornerstone essay** — "What 30,000 vibe-coded apps taught us" (drafted from Patrol corpus). Sep 22, evergreen.
- [ ] **Lictor Studio v0.1** — deferred to Q1 2027 (was Dec 31; a local desktop is a worse magnet than Patrol's public reach. Studio still ships, just later.)

## 🔭 Later — Q1 2027 (Jan–Mar)

Subject to Q4 learnings.

- [ ] **First Lovable / Bolt / v0 native integration** — `lictor.ai/scan` linked in their publish flow. The AUDIT.json adoption play, fully landed.
- [ ] **Lictor Studio v0.1** — macOS .dmg, signed + notarized (deferred from Q4)
- [ ] **Audit-as-a-Service productized** — first 5 VC firms enrolled, AaaS MRR-eq ≥$15k
- [ ] **Lictor Skill Marketplace** — community-authored agents
- [ ] **Hebrew + Japanese landing translations**
- [ ] **Talk at AI Engineer Summit** (March 2027)
- [ ] **Booth agent online Jan 15** for podcast booking + CFP scouting
- [ ] **First conference CFP acceptance**
- [ ] **Patrol corpus paper** — peer-reviewed v0 draft of "The Vibe-Coder Security Landscape: 100,000 Apps Scanned"

## 🌅 Eventually — Q2 2027 (Apr–Jun)

Three bets, not seven items. Each defines what Lictor is in Year 2 if it happens.

- [ ] **Lictor Foundation incorporated** — governance for the OSS core, making the Apache-2.0-forever commitment legally binding. The thing that makes Lictor un-acquirable by Snyk for the wrong reasons.
- [ ] **AUDIT.json v1.0 — adopted by ≥3 of {Snyk, Semgrep, Aikido, VibeEval, Veracode}** — the standard wins, Lictor wins by being the standard's home.
- [ ] **First Enterprise pilot** — on-prem deploy with custom agents, $25-75k/year. The point isn't the revenue; it's the proof that Lictor scales up, not just down.

---

## How to influence this roadmap

- **Found a vibe-coder security pattern we're missing?** Open an issue with the `pattern-request` label. Include a public repo URL showing the pattern in the wild.
- **Want a feature that's not here?** Open an issue with `feature-request`. The 5 most-upvoted feature requests every quarter get prioritized.
- **Hate something on this list?** Open a `concerns` issue. We respond to all of them, publicly.
- **Read a Lictor finding that sounded too jargony?** File a `voice-bug` — voice is the product.
- **Want to contribute code?** See `CONTRIBUTING.md`. We accept PRs for: new checks, language support, IDE integrations, translations.

The roadmap shifts toward what gets the loudest community signal — within the bounds of the strategic plan (`docs/launch/year-plan-2026-2027.md`). Nothing is decided in private.

---

## ⚠️ Trip-wires — conditions that flip this roadmap

These are the conditions under which the current plan is wrong and we change it publicly.

| Condition | Triggers by | Response |
|---|---|---|
| **Snyk ships a free vibe-coder tier** | Sep 1 2026 | Pull soft launch forward to Jul 15. Reframe Patrol report around the comparison. |
| **Beacon waitlist <250 signups by Jul 31** | Jul 31 | Messaging is wrong — pause content, run 10 customer-dev calls, reposition by Aug 15 |
| **Patrol pilot scans <100 apps** | Jun 14 | Engine isn't ready — extend pilot, post-mortem with Mirror, don't expand |
| **Patrol founder-response rate <3%** | Jul 1 | Outreach voice is wrong — rewrite with Mirror + re-pilot |
| **Soft launch off HN front page by noon** | Aug 15 | Methodology wasn't compelling — post-mortem before Oct 6; consider delaying hard launch |
| **Lovable / Bolt / v0 block our scraping** | any time | Pivot to API partnership offer (give them the scoring service in exchange for app-index API). Already aligned with AUDIT.json adoption play. |
| **Credible legal complaint about Patrol** | any time | Pause Patrol immediately; respond publicly within 48h; update legal-structure-memo with Patrol-specific addendum |
| **Sentinel npm installs <100/wk by Dec 1** | Dec 1 | Runtime SDK isn't the right wedge — deprioritize Sentinel investment, double down on Patrol + Studio instead |

## 🚫 What Lictor will refuse to ever do

These constraints ARE the positioning. Putting them on the public roadmap is binding.

- **Never ship default-on telemetry.** Opt-in only, ever. The CLI ping endpoint is `--telemetry on` by user choice.
- **Never charge per-seat for the OSS core.** Teams is $19/mo flat for unlimited seats. Forever.
- **Never require an account to install or run.** The CLI works offline. The skill suite works offline. Scan works without signup.
- **Never sell a SOC 2 module / compliance certification automation.** Use Vanta / Drata. We're a security audit tool, not a compliance theater tool.
- **Never gate features the OSS user actually needs behind the paid tier.** Paid is for teams, hosted dashboard, premium support — never for "the check that finds the bug."
- **Never publish an individual scorecard without consent or the disclosure window having expired.** Patrol's 30/90-day rules are non-overridable.
- **Never name a specific affected app in a press release or aggregate report.** Aggregate counts only, ever.

If we ever break one of these, the [`docs/lictor/wrong.md`](docs/lictor/wrong.md) log records it publicly and explains why. (That log will exist by Aug 15.)

## What's NOT on the roadmap (deliberate non-goals)

- **Compliance certification automation** (SOC 2 / ISO 27001 audit prep). Use Vanta / Drata / Secureframe.
- **Pen-testing-as-a-service.** Use HackerOne / Bugcrowd / Synack.
- **Production runtime IDS / IPS.** Use Cloudflare / Datadog / Sentry. Sentinel handles AI-specific runtime; everything else is downstream.
- **Multi-cloud posture management.** Use Wiz / Orca / Lacework.
- **Generic SAST for non-AI codebases.** Use Semgrep / Snyk Code. Lictor is specifically tuned for AI-built and AI-integrating apps.

We say no to these because saying yes makes Lictor worse at the thing it's actually good at.

---

## How to read the labels

| Label | Meaning |
|---|---|
| `pattern-request` | Add this attack pattern to our check engine |
| `feature-request` | Add this capability to one of the products |
| `bug` | Something is broken |
| `false-positive` | Lictor flagged something safe |
| `false-negative` | Lictor missed something dangerous |
| `voice-bug` | A finding sounded too compliance-y / too jargony |
| `concerns` | You disagree with our direction |
| `good-first-issue` | New contributor friendly |
| `help-wanted` | We'd love a PR for this |
| `roadmap-q3-2026` etc. | Tagged by target quarter |

The most-valuable issue types are `false-negative` and `voice-bug` — both make Lictor genuinely better.

---

## Recent changes log

| Date | Change |
|---|---|
| 2026-05-15 | Initial roadmap published with repo flip; ✅ Done section added with foundation work; Beacon waitlist campaign added to Now; lictor-cli + AUDIT.json moved to Done (originally Q4); CI green status surfaced |
| 2026-05-15 (pm) | **Course removed from project scope** (separate consulting biz — was a mistake to fold in). Revenue model now Teams + AaaS + Enterprise. **Repo URL canonicalized** to Raffa-jarrl/Lictor-AI (the lictor-ai org never existed; 55 files updated). **VS Code extension skeleton, 4 specialist agents, ES + PT-BR translations, AUDIT.json outreach drafts, marketing perf-report template, design system v0.1** all moved to Done. Q4 Spanish/Portuguese translation item removed (already shipped). New Q4 items: **CLI telemetry endpoint** (prerequisite for Tier-1 WAI metric) + **first monthly transparency report** published. |
| 2026-05-16 | **Major restructure: Lictor Patrol added as Q3 headline.** Patrol is the autonomous scanner that finds bugs in every new vibe-coder app on the public internet (last 7-30 days), contacts founders privately, builds the audit-corpus moat. Soft launch Aug 15 with the 30-day finding report. Hard launch Oct 6 becomes "the next chapter," not the debut. Top of roadmap rewritten around the 5 outcome states ("if Lictor wins, this is true"). Added **trip-wires** (8 conditions that flip the plan) and **refuse-to-build** commitments (7 binding constraints). Q3 weekly milestones replace the Jun-Sep bucket. **Cut:** 5 founder videos → 2; weekly teardown engine (replaced by Patrol byproducts); 3 cornerstone blog posts → 1; Sep 22 disclosure emails (Patrol's continuous flow replaces); Studio v0.1 deferred from Q4 to Q1 2027. Q2 2027 trimmed from 7 directional items to 3 bets. |

Future roadmap changes get logged here, with reason. Reading this section over time tells you what the project is actually responding to.
