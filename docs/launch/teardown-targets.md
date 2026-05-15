# Launch teardown targets — Oct 6 2026

> **Generated:** 2026-05-15
> **Purpose:** Ranked candidate apps for the Oct 6 launch teardown demo. *"Lictor's 11 AI agents audited [APP] in 12 minutes. Here's what they found."*
> **Selection criteria** — each must have at least 3 of: public user base, public attention, solo/tiny-team founder (punches up), plausibly real platform-typical gaps, not in any Lictor partnership, not so big it looks like a hit job.

---

## TL;DR

3 strong candidates, 2 acceptable-but-riskier, 1 wildcard. Most viral household-name vibe-coded apps have already been breached publicly (Cluely, Moltbook, the Khan teardown, EnrichLead) — the story is told. Sweet spot: **public founder + mid-tier traction (10K–100K users) + platform-typical gaps not yet audited.**

Of all indie launches, ~11% leak credentials in their frontend (SupaExplorer Jan 2026 report). Finding insecure apps isn't the constraint. Finding apps that **punch up enough to be newsworthy + don't punch down hard enough to look like bullying + aren't already a smoking crater** — that's the constraint.

---

## The 5 — ordered safest-first

### #1 — Pitchtank (`pitchtank.io`) — **Risk 1 / RECOMMENDED LAUNCH PICK**

| | |
|---|---|
| **Platform** | Lovable (featured on madewithlovable.com) |
| **What it does** | Community voting on startup ideas, 70/30 revenue splits, builds the top-voted idea monthly |
| **Founder** | Public solo indie, listed on madewithlovable |
| **Traction** | Modest but real — public on Product Hunt, growing |

**Why it's the launch pick:**
- Holds user accounts + payment splits = real money flowing = real stakes
- Solo + Lovable + Supabase = near-certain platform-typical RLS gaps
- The "we build the winning idea" mechanic means *founders upload their ideas* — a leak would be embarrassing in a self-evident, screenshots-itself way
- Punches up just enough (legit running business, not a toy demo) but won't sue
- No existing Lictor relationship

**Predicted findings:**
- Missing / misconfigured RLS on votes / ideas / users tables → attacker reads every submitted idea
- Supabase anon key in JS bundle
- No rate limit on voting endpoint (= ballot-stuffing)

**Why this lands well for launch:** founder almost certainly responds publicly and *gratefully* (free PR for him). The teardown reads as *"indie founder gets free security audit from Lictor's AI agents"* rather than *"Lictor humiliates a real company."* That's exactly the frame Lictor needs to seed.

---

### #2 — Tymora (`tymora.ai`) — **Risk 2 / strongest narrative fit**

| | |
|---|---|
| **Platform** | Lovable |
| **What it does** | AI "executive assistant" — reads email, calendar, texts, calls, social comments |
| **Founder** | Public-facing on X |
| **Traction** | Visible on Lovable's showcase, real OAuth-scoped data access |

**Why:**
- Reads Gmail + Calendar + SMS = dream attack surface for a teardown demo
- If they followed Lovable's default Supabase pattern, OAuth refresh tokens almost certainly sit in a table without RLS — that's the cleanest possible headline (*"Lictor's agents pulled OAuth refresh tokens for X users' inboxes in under 12 minutes"*)
- Same "AI agent era" frame as Lictor — the symmetry writes itself: *"AI agents doing real-world actions need real-world security"*

**Predicted findings:** OAuth refresh tokens in Supabase without RLS; Google API keys / SMS provider keys hardcoded in client; no audit log of agent actions (the exact thing Sentinel solves).

**Risk note:** if findings are critical you're publishing a roadmap for exploiting users' Gmail. **Hard requirement: 7–10 day responsible disclosure window before publishing.**

---

### #3 — FindMeMail (`findmemail.io`) — **Risk 2.5 / unbeatable headline**

| | |
|---|---|
| **Platform** | Lovable |
| **What it does** | B2B verified email lookup — "15K+ verified emails, 31K+ companies" |
| **Founder** | Witarist IT Services Pvt. Ltd. (small Indian software studio) |
| **Traction** | Paying customers (one-time $200 lifetime deal) |

**Why:**
- It's a database OF EMAILS — the irony of leaking an emails-database is irresistible launch copy: *"We audited a leaked-email-finder for leaked emails. Reader, we found them."*
- Paying customers = they care, will respond
- Lovable-built + holds PII = textbook RLS-gap setup
- Tiny team in India = punches up (markets itself as serious), doesn't punch down

**Predicted findings:** entire email database queryable via anon-key from browser; Stripe webhook unauthenticated; email-validity-check endpoint un-rate-limited.

**Risk note:** foreign jurisdiction = slower disclosure response. Plan for 14-day window.

---

### #4 — AgentSwarms (`agentswarms.fyi`) — **Risk 3 / biggest narrative bonus if it lands well**

| | |
|---|---|
| **Platform** | Lovable |
| **What it does** | Visual in-browser sandbox for building / testing / orchestrating multi-agent AI swarms; 40+ lessons, 30+ live agents, runs SQL / sends emails / calls webhooks |
| **Founder** | Public on X (@AgentSwarmsAI) |

**Why:**
- Live multi-agent execution with user-supplied API keys + real SQL + real emails = densest possible attack surface
- This IS the AI-agent-era platform Lictor's launch is positioned against — auditing AgentSwarms is the proof-of-concept for *"your AI agent platform needs Sentinel"*
- Likely co-promotional: educator personas usually engage with security teaching moments

**Predicted findings:** user-supplied OpenAI / Anthropic API keys in plaintext in Supabase without RLS (the apocalyptic finding); agent execution sandbox escape via prompt injection in lesson content; unsigned webhook URLs.

**Risk note:** this teaches agentic AI, so security failures look more embarrassing for them. If you find what's predicted, you've handed every reader a way to drain users' API keys. **Hard requirement: 14-day disclosure window minimum.**

**Upside:** if the founder ends up on the launch stage as a *"we worked with the founder to fix it"* co-promotion, that's a 10x multiplier on the teardown's reach.

---

### #5 — Anything (`anything.so`, Dhruv Amin & Marcus Lowe) — **Risk 4 / biggest single-shot payoff**

| | |
|---|---|
| **Platform** | Anything is itself a vibe-coding platform (not built on Lovable — it IS the platform); users ship to App Store |
| **Founder** | Public, ex-Google, on X; $11M raise at $100M valuation |
| **Traction** | Thousands of apps published; pulled by Apple March 30, 2026 |

**Why:**
- Already in the spotlight (Apple controversy = press paying attention)
- VC-backed but small enough that founders engage personally on Twitter
- Their pitch is *"non-technical people publish apps"* — security audit of a shipped app is the perfect *"this is why we exist"* demo for Lictor
- You don't audit Anything itself — you audit *one of the thousands of apps shipped through it,* picking the highest-profile one

**Predicted findings:** hardcoded API keys in shipped app bundle (App Store binaries get extracted); no certificate pinning = MitM-able; no Keychain storage for user secrets in default template.

**Risk note:** VC-backed founders have legal capacity. Sharp. If findings are misrepresented, they will push back publicly. **Only do this with airtight findings + 21+ day responsible disclosure + Patrick-McKenzie-quality legal review.**

**Tactical use:** **do not lead with this on Oct 6.** Reserve as launch-week-2 follow-up after the audience has accepted the Pitchtank-style teardown frame.

---

## 3 to explicitly AVOID

| App | Why avoid |
|---|---|
| **Cluely** | Already breached mid-2025 (83K records). Story is told. Roy Lee fights publicly; his audience is *anti-establishment* tech — teardown frames as "boomers attacking the kid." Net negative. |
| **Anything by Pieter Levels** (e.g. fly.pieter.com) | Pieter is the patron saint of vibe coding, 700K followers, universally beloved by your target audience. Teardown = every indie hacker hates Lictor by Oct 7. Hard no. |
| **Wave AI (Josh Mohrer)** | $4M ARR, SOC-2 audited, Vanta Trust Center, founder is ex-Uber NYC GM with deep network + lawyers. Wrong tier — too professional + too well-connected. |

Bonus avoid: **Moltbook** — already torn apart by Wiz, acquired by Meta March 2026. Dead story.

---

## Wildcard — YC W26 cohort

Documented: **25% of YC Winter 2025 was 95%+ AI-generated code** (kolega.dev). One YC founder publicly bragged about Cursor → days later had hardcoded API keys + a $14K OpenAI bill from a stranger draining them.

**Wildcard play:** pick **one YC W26 launch company** that publicly bragged on its launch tweet about being "fully vibe-coded" or "AI-built end-to-end." YC companies are:
- Bigger story (every tech reporter has YC on Google Alerts)
- More punchable-up (institutional backing, not solo indie)
- More likely to respond well (YC trains founders to handle bad PR maturely)

**Headline writes itself:** *"YC just funded $500K for this AI-built SaaS. Lictor's 11 agents found 7 critical vulnerabilities in 12 minutes. Here's the audit."*

**Risk:** 5. Biggest payoff, biggest blowup potential. Hard requirements:
- Specific company with documented "fully vibe-coded" public claims you can quote back
- 21-day disclosure window with explicit "publishing Oct 6" deadline
- Legal review on the writeup before publishing

**Strong recommendation: don't put the wildcard in the Oct 6 launch itself.** Use #1 (Pitchtank) for launch. Reserve the YC wildcard for Oct 13–20 as a "second-week amplification" — by then the launch narrative is established, you've earned the right to swing harder, and you've seen how the indie-hacker audience reacted to the first teardown.

---

## Recommended sequencing

| Date | Action |
|---|---|
| **Sep 22** | Send responsible disclosure emails to all 5 targets with explicit *"we plan to publish on Oct 6"* notice. Anyone who fixes everything in 14 days gets a *"fixed cleanly, here's how"* credit story instead of a teardown. |
| **Oct 6 (launch)** | Lead with **Pitchtank** (risk 1, narrative-perfect, almost-certain-positive founder response) |
| **Oct 6 alternate** | If Pitchtank fixes everything before Oct 6 (unlikely but possible), pivot to **Tymora** — second-safest, strongest "AI agent era" narrative match |
| **Oct 13–20** | Teardown #2 with **AgentSwarms** or **Anything** — depending on which engaged best with disclosure |
| **Week 3+** | Wildcard YC company if you've picked one and given proper disclosure runway |

---

## Sources

- [Lovable Vulnerability Explained: 170+ Apps Exposed (Superblocks)](https://www.superblocks.com/blog/lovable-vulnerabilities)
- [The Register: AI-built app on Lovable exposed 18K users](https://www.theregister.com/2026/02/27/lovable_app_vulnerabilities/)
- [Wiz: Hacking Moltbook — 1.5M API keys exposed](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- [Made with Lovable — featured apps directory](https://madewithlovable.com/)
- [SupaExplorer Cybersecurity Insight Report Jan 2026](https://supaexplorer.com/cybersecurity-insight-report-january-2026)
- [Kolega: YC Celebrated Building a Generation of Insecure Startups](https://kolega.dev/blog/y-combinator-just-celebrated-building-a-generation-of-insecure-startups/)
- [TechCrunch: Anything raises $11M at $100M valuation](https://techcrunch.com/2025/09/29/vibe-coding-startup-anything-nabs-a-100m-valuation-after-hitting-2m-arr-in-its-first-two-weeks/)
- [MacRumors: Apple pulls Anything from App Store](https://www.macrumors.com/2026/03/30/apple-pulls-vibe-coding-app/)
- [Hacker News: Vibe-coded Lovable-hosted app littered with basic flaws](https://news.ycombinator.com/item?id=47182659)
