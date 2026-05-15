# Operation Triumph EXPANDED — 12-month plan to category-defining

> **Generated:** 2026-05-15
> **Author of record:** Dor + agent crew (Conductor as project lead)
> **Time horizon:** May 2026 → May 2027 (12 months)
> **Scope:** From "we exist publicly" (Oct 6, 2026 launch) to "Lictor is the brand vibe-coders + AI builders trust to ship safely."
> **Posture:** The 90-day anti-Snyk playbook scaled to a full year, across 5 strategic fronts, 4 quarters, with a real revenue trajectory and a clear definition of category-defining.

---

## The bigger thesis

Lictor is not "an open-source security tool for vibe-coders." That framing was correct for May 2026; it's too small for May 2027.

**The bigger thesis:** *Every AI-built app needs a crew of AI agents auditing it — and Lictor is the brand that defines what that crew looks like, how it speaks, and what it costs.*

By May 2027 the goal is:
- **Category ownership.** When a developer Googles "audit my Lovable app" — Lictor is the first non-paid result.
- **Distribution density.** 10,000 weekly active users of `/lictor-security-check` inside Claude Code. 50,000 GitHub stars on the monorepo.
- **Content gravity.** A weekly teardown archive of 50+ published audits, indexed by every security search.
- **Revenue legitimacy.** $25–50k MRR across Teams ($19/mo flat-rate), Course ($99 once), and Audit-as-a-Service ($2-10k per VC-portfolio sweep). Not VC-scale, but enough to fund a community + a dev advocate hire.
- **Voice authority.** Dor is on at least one major security podcast and one industry-conference stage. Quill's voice is recognized as "that plain-English security writer who makes the others sound like lawyers."

This is not "win the OSS popularity contest." This is **become the public-facing brand of a category that didn't exist 18 months ago**, before incumbents wake up and crush the category with money.

---

## The 5 strategic fronts (not just anti-Snyk)

The 90-day playbook was framed against Snyk specifically. The 12-month plan operates on 5 fronts in parallel:

### Front 1 — Vibe-coder vertical (the wedge)
- **Audience:** solo founders shipping from Lovable / Bolt / v0 / Cursor / Replit
- **Surface:** `/lictor-security-check` Claude Code skill + Shield browser extension
- **Channel:** indie-hacker Twitter, Lovable Discord, vibe-coder Reddit (r/SaaS, r/indiehackers)
- **Q4 2026 goal:** 5,000 weekly active skill users; 3 viral teardowns on Hacker News
- **Q2 2027 goal:** 25,000 weekly active; recognized partnership with at least one platform (Lovable / Bolt / v0)

### Front 2 — AI-engineer-curious devs (the upmarket leak-through)
- **Audience:** software engineers at small startups (3–30 person teams) using Claude Code / Cursor / Devin daily
- **Surface:** Sentinel SDK (runtime defense) + Guardian dashboard (team-level monitoring)
- **Channel:** dev Twitter, Lobste.rs, /r/programming, Pragmatic Engineer newsletter, AI Engineer Summit
- **Q4 2026 goal:** Sentinel installed in 500 production codebases (measured by fingerprint telemetry)
- **Q2 2027 goal:** 5,000 production Sentinel installs; 50 paying Guardian teams

### Front 3 — Dev studios + AI agencies (the multiplier)
- **Audience:** small agencies (2–15 people) shipping AI features for clients on retainer
- **Surface:** Lictor Audit-as-a-Service — agency hires Lictor to audit their client portfolio quarterly
- **Channel:** direct outreach, agency-leadership Slack groups, the IndieHackers founder list
- **Q4 2026 goal:** 5 agencies running quarterly Lictor audits as part of their delivery
- **Q2 2027 goal:** 30 agencies; published case studies from 5

### Front 4 — Education + course (the moat)
- **Audience:** developers learning AI dev, bootcamp students, university comp-sci instructors
- **Surface:** GenerationAI course (Dor's existing project) — "Ship secure AI apps" curriculum, $99 per seat
- **Channel:** Twitter threads → newsletter → course funnel, university outreach, bootcamp partnerships
- **Q4 2026 goal:** 100 paid course enrollments
- **Q2 2027 goal:** 500 enrollments; course added to 3 bootcamp curricula; a "Lictor Certified Auditor" badge program

### Front 5 — Enterprise leak-through (the surprise upside)
- **Audience:** F500 CISOs and AppSec engineers who personally use vibe-coder tools on weekends
- **Surface:** Lictor enterprise edition (Q1 2027) — on-prem deploy, custom agents, premium support
- **Channel:** organic only at first — wait for CISOs to find Lictor through their own builds, then introduce a "talk to us" path
- **Q4 2026 goal:** 10 unsolicited enterprise inquiries logged (no proactive outreach)
- **Q2 2027 goal:** 3 enterprise pilots; one signed contract at $50k+/yr

**Why 5 fronts and not 1:** vibe-coder market is the wedge but it caps at modest revenue. Real growth comes from leak-through into the adjacent markets the OSS strategy *naturally* opens up. A solo founder using Lictor today is a startup engineer using Sentinel in 2027 is a F500 AppSec lead piloting Enterprise in 2028. Plan for the leak-through *now* by building infrastructure for all 5 from launch.

---

## The 4 quarters

### Q3 2026 (Jul–Sep) — Foundation
> *"By Sep 30 we are a public brand with a working content engine and 100 actual users."*

**Build:**
- ✅ Lictor monorepo public on GitHub (done — pending visibility flip)
- ✅ Landing site repositioned to vibe-coder vertical (done 2026-05-15)
- ✅ The 4 strategic docs in `docs/launch/` (done 2026-05-15)
- 🔲 `/lictor-explain` skill that translates Snyk + Semgrep + Trivy + GH Security output to plain English (ships this session)
- 🔲 Weekly teardown engine — agents wired to produce one teardown per week starting Sep 1
- 🔲 Public roadmap on GitHub Projects, community-votable
- 🔲 First 5 GenerationAI agents reach 24/7 production uptime (heartbeat infra fixed 2026-05-14)
- 🔲 Dor's founder-on-camera channel: pilot 3 videos by Aug 1, weekly cadence by Sep 1

**Ship:**
- 🔲 Sep 22: send responsible-disclosure emails to 5 teardown targets
- 🔲 Sep 25: Sentinel `@lictor/sentinel@0.1.0` and `lictor-sentinel==0.1.0` GA on npm + PyPI (not alpha)
- 🔲 Sep 27: Domains live (`lictor.ai` resolves, OG image working)
- 🔲 Oct 4: launch dress rehearsal — full content drop tested internally
- 🔲 Oct 6: LAUNCH. Teardown #1 (Pitchtank) goes live across all surfaces.

**Audience:**
- 🔲 5 design partners running Lictor in their own projects by Sep 1
- 🔲 100 GitHub stars by Oct 6
- 🔲 500 GitHub stars by Oct 13 (one viral teardown)

### Q4 2026 (Oct–Dec) — Velocity
> *"By Dec 31 we have a 12-week archive of public teardowns and the indie-hacker community thinks of Lictor without prompting."*

**Build:**
- 🔲 12 published teardowns by Dec 31 (weekly cadence from Oct 6)
- 🔲 IDE plugin for VS Code (Sentinel SDK integration + skill triggers)
- 🔲 Lictor for Teams paid tier live ($19/mo flat-rate — see anti-Snyk playbook Phase 3)
- 🔲 `AUDIT.json` standard proposal published — invite Snyk/Aikido/VibeEval to co-sign
- 🔲 First Lictor Studio desktop app build (offline-only audit, anti-Snyk Phase 3 differentiator)
- 🔲 Spanish + Portuguese landing page translations (LATAM is the highest-growth vibe-coder region)

**Ship:**
- 🔲 Weekly teardown every Tuesday
- 🔲 3 cornerstone blog posts: "What Snyk's free tier means for indie founders" (when relevant), "The 7 patterns we catch that the other tools miss", "Audit your audit — a Lictor skill for translating any security report"
- 🔲 First conference talk submitted to AI Engineer Summit (March 2027 slot)
- 🔲 First major media placement: pitch The Register or TechCrunch on a teardown finding

**Audience:**
- 🔲 5,000 weekly active skill users
- 🔲 5,000 GitHub stars
- 🔲 50 paying Teams subscribers ($950 MRR)
- 🔲 5 indie hackers publicly using Lictor as part of their stack (visible on their landing pages or in their tweets)

### Q1 2027 (Jan–Mar) — Scale
> *"By Mar 31 we have a community contributing content, a course generating revenue, and at least one platform partnership."*

**Build:**
- 🔲 Lictor Skill Marketplace — community-contributed agents (e.g., user writes "WordPress audit agent," ships to registry, others install)
- 🔲 "Lictor Certified Auditor" badge program for course graduates
- 🔲 First Lictor + Lovable / Bolt / v0 integration (which platform first depends on Q4 conversations)
- 🔲 Hebrew + Japanese landing-page translations (Dor's home market + the second-fastest-growing AI-builder language)
- 🔲 Lictor Studio v1 ships (Mac + Windows)
- 🔲 Audit-as-a-Service productized — first 5 VC firms enrolled to audit their portfolios

**Ship:**
- 🔲 Continued weekly teardown — now 24 published total
- 🔲 GenerationAI course relaunch with Lictor integration — "Ship secure AI apps in 30 days"
- 🔲 Lictor at AI Engineer Summit (March 2027) — Dor on stage, agent crew demo
- 🔲 First sponsored content (paid placement in IndieHackers newsletter, $5k spend)

**Audience:**
- 🔲 15,000 weekly active skill users
- 🔲 15,000 GitHub stars
- 🔲 200 paying Teams subscribers ($3,800 MRR)
- 🔲 100 course enrollments ($9,900 cumulative)
- 🔲 5 Audit-as-a-Service customers ($10–25k cumulative revenue)
- 🔲 **First quarter with positive monthly cash flow** (modest, but symbolic)

### Q2 2027 (Apr–Jun) — Dominate / Define
> *"By Jun 30 Lictor is the answer when anyone asks 'how do you secure an AI-built app?'"*

**Build:**
- 🔲 Enterprise edition launched (on-prem, custom agents, premium support — $50–100k/yr)
- 🔲 Agent crew expanded from 11 → 15 (4 new specialists — see below)
- 🔲 Public bug bounty program — Lictor audits Lictor, with a $5k pool
- 🔲 Open governance model — Lictor Foundation incorporated as a 501(c)(3) or equivalent so the community OSS commitment is structurally protected from acquisition pressure
- 🔲 First Lictor book / definitive guide — long-form publication on shipping secure AI apps

**Ship:**
- 🔲 Continued weekly teardown — now 36+ published total
- 🔲 Black Hat USA / DEF CON 2027 submission (or RSAC 2027 acceptance for the security stage)
- 🔲 First Lictor-employed (or contracted) dev advocate hire
- 🔲 Press cycle: at least 2 major publications cover Lictor's first-year arc

**Audience:**
- 🔲 25,000 weekly active skill users
- 🔲 50,000 GitHub stars
- 🔲 500 paying Teams subscribers ($9,500 MRR)
- 🔲 500 course enrollments ($49,500 cumulative)
- 🔲 30 Audit-as-a-Service customers + 3 Enterprise pilots
- 🔲 **$25–50k MRR target** across all revenue streams

---

## The new specialist agents (Q1 2027 hires)

The current crew of 11 is designed for content + audit + brand. The bigger ambition needs 4 more specialists:

1. **🌐 Translator (linguistic specialist)**
 - **Job:** Render every Lictor public artifact in Hebrew, Spanish, Portuguese, Japanese. Maintain cultural fit per language (Hebrew is Dor's native — has authentic voice; LATAM needs Portuguese-vs-Spanish distinction; Japan needs formality calibration).
 - **Cadence:** Translates one piece per day.
 - **Model:** Claude Sonnet (translation quality matters).

2. **🎬 Reel (video-script writer + YouTube/TikTok plan)**
 - **Job:** Generate weekly scripts for Dor's talking-head videos. Pull from that week's teardown + Trends' viral-format intel + Pulse's hooks. Format for 60s shorts, 8-12 min long-form, and TikTok-native.
 - **Cadence:** 3 scripts per week (1 long, 2 short).
 - **Model:** Claude Sonnet.

3. **🎙️ Booth (podcast booker + conference scout)**
 - **Job:** Identify weekly opportunities — podcasts that booked similar guests, conferences with open CFPs, newsletters that take guest posts. Draft cold outreach. Maintain a public "Dor will speak about X" list.
 - **Cadence:** 5 outreach drafts per week + weekly conference CFP digest.
 - **Model:** Claude Haiku (this is volume + recall work, not creative).

4. **🤝 Bridge (community manager + GitHub triage)**
 - **Job:** Triage incoming GitHub issues, label them, draft initial responses, escalate non-trivial ones to Dor or dev. Welcome new contributors. Maintain the public roadmap. Run the weekly "Lictor user spotlight" thread.
 - **Cadence:** Continuous (every 4h heartbeat).
 - **Model:** Claude Sonnet for triage + drafting, escalates flagged issues to a Dor inbox.

**Estimated agent cost:** 4 new agents × ~$3/day Claude API spend ≈ $360/mo additional inference cost. Within Q1 2027 revenue assumptions.

---

## Revenue trajectory (modest but real)

| Quarter | Teams ($19/mo) | Course ($99) | Audit-as-Service | Enterprise | **Total MRR** |
|---|---|---|---|---|---|
| Q4 2026 | 50 subs = $950 | 30 enrollees one-time = $2,970 prior 90d | 0 | 0 | **$950 MRR** |
| Q1 2027 | 200 subs = $3,800 | +70 = $6,930 prior 90d | 5 customers @ avg $4k = $20k over 90d | 0 | **$3,800 + $7k/mo audit avg ≈ $10–11k MRR** |
| Q2 2027 | 500 subs = $9,500 | +400 = $39,600 prior 90d | 30 customers, mix monthly + one-off ≈ $25k/mo | 3 pilots ≈ $5k/mo each = $15k | **$25–50k MRR target** |

The math is intentionally conservative. The point isn't to project a unicorn-shaped revenue curve — the point is to *prove the OSS-led business model works at sustainable scale*. $25–50k MRR by Q2 2027 funds:
- Dor full-time on Lictor (~$10k/mo runway)
- 1 dev advocate or community manager (~$8k/mo)
- Agent crew infra (~$1.5k/mo)
- Marketing experiments + sponsorships (~$3k/mo)
- A real runway buffer (~$5k/mo)

Anything above that is acceleration. Anything below means the bet is still right but the pacing slows.

---

## Risk map — what could kill this

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Snyk ships free vibe-coder tier in Q3 2026 | 35% | High | The anti-Snyk-free-tier playbook IS the mitigation. Already written. |
| Lovable / Bolt build first-party security so well third-party tools feel redundant | 30% | High | Compete on multi-platform breadth (Lictor audits all 5+ platforms) + Claude Code distribution. Lovable can't ship in Cursor. |
| GitHub Advanced Security adds "AI-built code security" as a free feature | 25% | Medium-High | Lictor's plain-English + multi-agent transparency moat. GH won't ship plain English at developer-team scale. |
| Anthropic / OpenAI ship native code-audit features in Claude / GPT | 20% | Critical | Different playbook entirely — pivot to *workflow orchestrator* layer above native audit. Plan B doc to write Q4 2026. |
| Major teardown legal blowback (founder sues) | 10% | Critical | Disclosure rails in teardown-engine.md. Legal review on every teardown ≥ Risk-3. |
| Dor burnout (solo founder is the bottleneck) | 40% | Critical | The agent crew offloads. Hire dev advocate Q1 2027. Founder content cadence capped at sustainable level. |
| Open-source community turns against Lictor (perceived as commercial bait-and-switch) | 15% | High | Lictor Foundation (501(c)(3)) in Q2 2027 makes the OSS commitment structural. Public licensing pledge: core never gets EE-only features. |
| OpenClaw / OpenAI / Anthropic API costs explode | 25% | Medium | Push to lightweight local models where possible (Ollama). Budget cap per agent per day. |

---

## What category-defining looks like (the 12-month definition of done)

By May 2027, "category-defining" means **all 7 of these are true simultaneously**:

1. ☐ Google search "how to audit Lovable app" returns Lictor in top 3 organic results
2. ☐ At least 1 major publication (The Register / TechCrunch / Wired / Verge) has run a Lictor-led teardown as a news story
3. ☐ At least 2 of {Lovable, Bolt, v0, Cursor, Replit} have linked to Lictor from their own docs
4. ☐ Dor has spoken at one Tier-1 security or AI conference (Black Hat / DEF CON / RSAC / AI Engineer Summit)
5. ☐ Snyk or Aikido has publicly referenced Lictor in marketing copy or comparison docs (= they've validated the category)
6. ☐ At least 5,000 stars on the GitHub repo and 10,000 WAU on the Claude Code skill
7. ☐ $25k+ MRR across the revenue streams, with at least one Enterprise pilot signed

If ≥ 5 of these are true: category-defining. If 3–4: strong second player (still good outcome). If ≤ 2: the bet needs a serious rethink.

---

## What needs to happen NEXT (this week)

The 12-month plan is a sketch, not a sermon. The work is the work. This week's specific commits:

1. **Ship `/lictor-explain` Snyk-translator skill** (this session) — strategic asset for when Snyk Lite drops
2. **Configure Probe to monitor 6 competitors weekly** (this session) — early warning system
3. **Stand up the public roadmap repo** (this session) — anti-Snyk Phase 2 move
4. **Write `AUDIT.json` standard proposal** (this session) — Phase 3 standards-ownership
5. **Wire the teardown engine into the agent crew** (this session via the agent I spawned)
6. **Specify the 4 new agents** (this session)
7. **Have the user review the plan and confirm or adjust the targets** (after this session)
8. **Begin recording founder content** (Dor — week of May 18, 2026)
9. **Send responsible-disclosure emails to teardown targets** (Sep 22 — calendar reminder needed)

The plan is the map. The agents and the engine are the vehicle. The next 12 months are the road.
