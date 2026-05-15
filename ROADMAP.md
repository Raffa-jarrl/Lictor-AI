# Lictor public roadmap

> **Snyk's roadmap is closed. Lictor's is here.**
> Open issues, vote with 👍, propose new items. Lictor goes where the community pushes hardest.
> Updated: 2026-05-15 (after the foundation-shipped roadmap update)

This is the *intended* roadmap. It's not a contract. Anything past Q4 2026 will shift as we learn from real usage. Everything before launch (Oct 6, 2026) is committed.

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
- [x] ~80 strategic + tactical docs in `docs/launch/` — year plan, anti-Snyk playbook, M&A strategy, teardown engine, Beacon campaign, course curriculum, acquirer deck, press kit, 5 polished launch teardown drafts, Sep 22 disclosure emails
- [x] **VS Code extension skeleton** (`vscode-extension/`) — manifest, diagnostics provider, sidebar tree view, 5 commands, README; TS compiles clean (ships v0.1 in Q4 2026)
- [x] **4 new specialist agent SOULs** — Translator (🌐 locale rendering), Reel (🎬 video scripts), Booth (🎙️ podcast/CFP scouting), Bridge (🤝 GitHub triage); bring-online dates staggered Oct 2026–Jan 2027
- [x] **AUDIT.json v0.2 adoption outreach** — 5 personalized email drafts (Semgrep, VibeEval, Symbioticsec, Aikido, Snyk) at `docs/launch/audit-json-adoption-outreach.md`
- [x] **Waitlist landing translated** to Spanish (LATAM) and Portuguese (BR) at `landing/translations/{es,pt-BR}/waitlist.html`

## 🚀 Now — Q3 2026 (Jun–Sep)

Pre-launch validation + execution. All items here are committed.

- [ ] **Beacon — pre-launch waitlist campaign** (May 18 → Oct 5)
  - Target: 1,000 confirmed signups by Oct 5 · Stretch: 5,000 · Kill: <250 by Jul 31
  - See `docs/launch/beacon-campaign/README.md` for full spec
- [ ] Landing site live at `lictor.ai` via Cloudflare Pages
- [ ] Buttondown waitlist account live + 5-email drip sequence loaded
- [ ] First 5 founder videos recorded + published (one per week starting Jun 1)
- [ ] Sentinel 0.1.0 GA on npm + PyPI (alpha → GA)
- [ ] First 5 design partners signed (Beacon-sourced + direct outreach)
- [ ] Weekly teardown engine operational by Sep 1
- [ ] Sep 22: disclosure emails to 5 teardown targets (drafts ready in repo)
- [ ] First quarterly retrospective scheduled (Sep 28–30, calendar-blocked)
- [ ] **Oct 6 launch: Teardown #1 (Pitchtank) published**

## 🛠 Next — Q4 2026 (Oct–Dec)

Committed if Q3 ships clean.

- [ ] 12 weekly teardowns published Oct 6 → Dec 22 (scaffolds + 5 polished drafts in repo)
- [ ] Lictor for Teams paid tier — $19/mo flat, unlimited seats — Dec 15
- [ ] VS Code extension v0.1.0 — Marketplace + Open VSX, Dec 22
- [ ] Lictor Studio v0.1.0 — macOS .dmg, signed + notarized, Dec 31
- [ ] Spanish + Portuguese landing-page translations
- [ ] AUDIT.json adoption push (Snyk / Aikido / VibeEval / Semgrep outreach)
- [ ] 3 cornerstone blog posts published (drafts in repo: 7-patterns, why-I-built, when-competitor-ships-free)
- [ ] Self-teardown writeup published (Aug 25 — Lictor audits Lictor)
- [ ] First major-media placement (The Register / TechCrunch / Verge pitching)
- [ ] Bridge agent comes online (Oct 13) for community triage
- [ ] Reel agent comes online (Nov 1) for video script production
- [ ] Translator agent comes online (Dec 1) for ES + PT-BR

## 🔭 Later — Q1 2027 (Jan–Mar)

Subject to Q4 learnings.

- [ ] Lictor Skill Marketplace — community-authored agents
- [ ] First Lictor + {Lovable / Bolt / v0} platform integration
- [ ] Hebrew + Japanese landing translations
- [ ] Lictor Studio v0.2 — Mac + Windows + Pro tier ($79 one-time or $7/mo)
- [ ] Audit-as-a-Service productized — first 5 VC firms enrolled
- [ ] GenerationAI course relaunch — "Ship Secure AI Apps in 30 Days" ($99)
- [ ] Talk at AI Engineer Summit (March 2027)
- [ ] Booth agent comes online (Jan 15) for podcast booking + CFP scouting
- [ ] First conference CFP acceptance

## 🌅 Eventually — Q2 2027 (Apr–Jun)

Direction, not commitment.

- [ ] Lictor Enterprise — on-prem deploy, custom agents, premium support
- [ ] Public bug bounty program ($5k pool)
- [ ] Lictor Foundation incorporated (governance for OSS code)
- [ ] Lictor book / definitive guide
- [ ] Talk submitted to Black Hat USA / DEF CON 2027
- [ ] First dev advocate (or community manager) hire
- [ ] First "informational" acquirer conversation (no commitment — optionality only)

---

## How to influence this roadmap

- **Found a vibe-coder security pattern we're missing?** Open an issue with the `pattern-request` label. Include a public repo URL showing the pattern in the wild.
- **Want a feature that's not here?** Open an issue with `feature-request`. The 5 most-upvoted feature requests every quarter get prioritized.
- **Hate something on this list?** Open a `concerns` issue. We respond to all of them, publicly.
- **Read a Lictor finding that sounded too jargony?** File a `voice-bug` — voice is the product.
- **Want to contribute code?** See `CONTRIBUTING.md`. We accept PRs for: new checks, language support, IDE integrations, translations.

The roadmap shifts toward what gets the loudest community signal — within the bounds of the strategic plan (`docs/launch/year-plan-2026-2027.md`). Nothing is decided in private.

---

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

Future roadmap changes get logged here, with reason. Reading this section over time tells you what the project is actually responding to.
