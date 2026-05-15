# Lictor public roadmap

> **Snyk's roadmap is closed. Lictor's is here.**
> Open issues, vote with 👍, propose new items. Lictor goes where the community pushes hardest.
> Updated: 2026-05-15

This is the *intended* roadmap. It's not a contract. Anything past Q4 2026 will shift as we learn from real usage. Everything before launch (Oct 6, 2026) is committed.

---

## 🚀 Now — Q3 2026 (Jul–Sep)

The launch quarter. All items here are committed.

- [ ] Public repo flip (currently private)
- [ ] Landing site live at `lictor.ai` (Cloudflare Pages)
- [x] `/lictor-security-check` Claude Code skill — 7 checks tuned for Lovable / Bolt / v0 / Cursor / Replit
- [x] `/lictor-explain` Claude Code skill — plain-English translator for any security tool output
- [x] `/lictor-fix-it` Claude Code skill — drafts the fix + diff
- [x] `/lictor-rotate` Claude Code skill — provider-specific key-rotation runbooks
- [x] Shield Chrome extension — local-only audit of any AI-built site
- [x] Sentinel npm + PyPI SDK — runtime defense for OpenAI / Anthropic clients
- [x] Guardian dashboard — incident timeline + compliance evidence export
- [ ] Sentinel 0.1.0 GA on npm + PyPI (graduate from alpha)
- [ ] 5 design partners running Lictor in their own projects
- [ ] Weekly teardown engine operational — see `docs/launch/teardown-engine.md`
- [ ] **Oct 6 launch: Teardown #1 published**

## 🛠 Next — Q4 2026 (Oct–Dec)

Committed if Q3 ships clean.

- [ ] 12 weekly teardowns published by Dec 31
- [ ] Lictor for Teams paid tier — $19/mo flat-rate, unlimited seats
- [ ] VS Code extension (Sentinel integration + skill triggers in the IDE)
- [ ] First Lictor Studio desktop app build (offline-only audit)
- [ ] Spanish + Portuguese landing-page translations
- [ ] `AUDIT.json` v0.1 community standard published — invite Snyk / Aikido / VibeEval / Semgrep to co-sign
- [ ] First major-media placement (The Register / TechCrunch / Verge)
- [ ] 3 cornerstone blog posts:
  - [ ] "What [Snyk Lite | Aikido Free | GitHub AI Security] means for indie founders"
  - [ ] "The 7 patterns we catch that the others miss"
  - [ ] "Audit your audit — translating any security report into human"

## 🔭 Later — Q1 2027 (Jan–Mar)

Subject to Q4 learnings.

- [ ] Lictor Skill Marketplace — community-authored agents
- [ ] First Lictor + {Lovable | Bolt | v0} platform integration
- [ ] Hebrew + Japanese translations
- [ ] Lictor Studio v1 (Mac + Windows)
- [ ] Audit-as-a-Service productized — first 5 VC firms enrolled
- [ ] GenerationAI course relaunch — "Ship secure AI apps in 30 days"
- [ ] Talk at AI Engineer Summit (March 2027)
- [ ] 4 new specialist agents — see `docs/launch/new-agents-spec.md`

## 🌅 Eventually — Q2 2027 (Apr–Jun)

Direction, not commitment.

- [ ] Lictor Enterprise — on-prem deploy, custom agents, premium support
- [ ] Public bug bounty program ($5k pool)
- [ ] Lictor Foundation incorporated (501(c)(3) or equivalent)
- [ ] Lictor book / definitive guide
- [ ] Talk submitted to Black Hat USA / DEF CON 2027
- [ ] First dev advocate hire

---

## How to influence this roadmap

- **Found a vibe-coder security pattern we're missing?** Open an issue with the `pattern-request` label. Include a public repo URL showing the pattern in the wild.
- **Want a feature that's not here?** Open an issue with `feature-request`. The 5 most upvoted feature requests every quarter get prioritized.
- **Hate something on this list?** Open a `concerns` issue. We respond to all of them, publicly.
- **Want to contribute code?** See `CONTRIBUTING.md`. We accept PRs for: new checks, language support, IDE integrations, translations.

The roadmap shifts toward what gets the loudest community signal — within the bounds of the strategic plan (`docs/launch/operation-triumph-expanded.md`). Nothing is decided in private.

---

## What's NOT on the roadmap (deliberate non-goals)

- **Compliance certification automation** (SOC 2 / ISO 27001 audit prep). Use Vanta / Drata / Secureframe — they're great at this. Lictor is a security tool, not a compliance vendor.
- **Pen-testing-as-a-service.** Use HackerOne / Bugcrowd / Synack. Lictor finds bugs in your code; humans find bugs in your business logic.
- **Production runtime IDS / IPS.** Use Cloudflare / Datadog / Sentry. Sentinel handles AI-specific runtime; everything else is downstream.
- **Multi-cloud posture management.** Use Wiz / Orca / Lacework. Lictor scans repos and AI calls, not cloud accounts.
- **Generic SAST for non-AI codebases.** Use Semgrep / Snyk Code. Lictor is specifically tuned for AI-built and AI-integrating apps.

We say no to these because saying yes makes Lictor worse at the thing it's actually good at.

---

## How to read the labels

| Label | Meaning |
|---|---|
| `pattern-request` | Add this attack pattern to our check engine |
| `feature-request` | Add this capability to one of the 4 products |
| `bug` | Something is broken |
| `false-positive` | Lictor flagged something safe |
| `false-negative` | Lictor missed something dangerous |
| `concerns` | You disagree with our direction |
| `voice-bug` | A finding sounded too compliance-y / too jargony |
| `good-first-issue` | New contributor friendly |
| `help-wanted` | We'd love a PR for this |
| `roadmap-q3-2026` etc. | Tagged by target quarter |

The most valuable issue types are `false-negative` and `voice-bug` — both make Lictor genuinely better.
