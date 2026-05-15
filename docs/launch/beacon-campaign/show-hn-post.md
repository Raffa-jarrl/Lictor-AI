# Show HN — DO NOT POST UNTIL WEEK 10 (Wed July 23, 2026)

> HN punishes empty-waitlist posts. Wait until: (1) the repo is public (target June 1), (2) waitlist has 500+ confirmed signups, (3) at least one polished teardown is live on lictor.ai/blog or as a public gist.

---

## Why Week 10

The Show HN moment is **the single highest-value channel slot in the entire Beacon campaign**. One front-page hit on HN ≈ 1,000–5,000 waitlist signups in 24 hours. But HN also has a brutal feedback loop: posts that hit the front page with no substance get downvoted into oblivion fast, and HN remembers — you only get one good shot per project per ~6 months.

By Week 10 (mid-July):
- Repo has been public for ~6 weeks (HN can verify the code is real)
- 250–500 signups on the waitlist (proof of demand, not vapor)
- ~5 founder videos in the world (Dor has a face HN can put to the project)
- The self-teardown is published (HN can verify methodology)
- Multiple weekly teaser threads have circulated (the audience exists already)

Posting earlier wastes the shot. Posting later misses the launch-prep window.

---

## Submission timing

**Wed July 23, 2026, 09:10 AM PT.** Empirically the highest-engagement window for Show HN submissions. Submit, wait 4 minutes, then upvote ≤2 times from accounts in your circle for the initial momentum. Do NOT solicit upvotes from your audience — HN's anti-manipulation detection will flag the post if signal patterns look orchestrated.

---

## The post

**Title:** Show HN: Lictor — free open-source AI security audit for vibe-coded apps

(60 chars exactly. HN's optimal title length. Includes "free" and "open-source" — both keywords HN's audience filters for.)

**URL:** Leave blank. Use a text post instead. Text posts on Show HN drive comments faster than link posts; comments compound visibility.

**Text:**

```
Hey HN — I'm Dor, a 20-year cybersecurity engineer building Lictor in the open.

Quick what + why:

What: Lictor is a free open-source security audit for apps built with AI (Lovable, Bolt, v0, Cursor, Replit, Claude Code). 11 AI agents walk your project, find what's broken, and explain the fix in plain English. Apache 2.0. Runs locally inside Claude Code. No signup, no telemetry, no per-seat pricing.

Why: ~40-62% of AI-generated code ships with security vulnerabilities. Existing security tools (Snyk, Veracode, Checkmarx) were built for codebases people wrote by hand and cost $25/dev/mo minimum. None of that helps the 8M people shipping AI-built apps from Lovable on Saturday.

The 7 checks:
1. Service-role keys in client JS bundles (the canonical Lovable bug)
2. Missing Row-Level Security on Supabase tables
3. Hallucinated npm packages (typical AI mistake)
4. Frontend-only auth checks
5. Unsigned Stripe / GitHub / Shopify webhooks
6. Cross-tenant cache leakage in Next.js
7. AI endpoints with no rate limiting

Repo: https://github.com/lictor-ai/lictor (Apache 2.0)
Waitlist (ships October 6): https://lictor.ai/waitlist
First teardown — Lictor audited Lictor's own codebase: https://lictor.ai/blog/we-audited-lictor-with-lictor

What I'd love feedback on:

1. The check engine is a Rust crate (lictor-core) that compiles to native + WASM. Native runs in Claude Code skills + CLI; WASM runs in the Chrome extension. The architecture: shared analyzer crate, multiple frontends. Curious if anyone has been down this path with security tools and has war stories.

2. The "11 agents" structure: each agent is a markdown file (SOUL.md) you can read and fork. The architecture surfaces which agent flagged what, with confidence scores. Transparency vs noise tradeoff — would love takes from anyone who's tried this kind of agent-orchestration in production tools.

3. The voice problem: every Lictor finding is translated into plain English, never compliance dialect. We have a forbidden-word list (leverage, robust, paradigm, etc.) enforced at the writer-agent level + a "voice-bug" issue label so users can report when a finding sounded too jargony. Curious if anyone has run a "voice is the product" discipline elsewhere — what worked, what didn't.

4. The acquisition-readiness vs OSS-purity tension. We're committing to a Lictor Foundation (Q2 2027) that governs the OSS core, with commercial features under BUSL with 4-year Apache conversion. Open to feedback from anyone who's structured an OSS-led business this way.

Building this solo + an 11-agent AI crew that handles content, triage, weekly reviews, competitive scans. The full plan + month-by-month execution is public: github.com/lictor-ai/lictor/blob/main/docs/launch/year-plan-2026-2027.md

Happy to answer questions on architecture, security philosophy, business model, agent design — anything.
```

---

## Why this post will land

- **Lead with what + why in 2 paragraphs.** HN attention spans are short.
- **Concrete checks listed.** No mystery; HN respects specificity.
- **3 working URLs.** The repo verifies the project is real. The waitlist verifies demand. The teardown verifies methodology.
- **Asking 4 specific technical questions.** Comments-driven posts beat link posts on Show HN. Each question prompts replies.
- **Founder credibility front-loaded** ("20-year cybersecurity engineer") but not in the headline — HN dislikes status flexing.
- **No marketing speak.** Word-checked: zero forbidden words.
- **Sufficient depth for engineers to engage.** Rust crate architecture, agent-orchestration tradeoffs, voice discipline, business model.

---

## How to handle the comments

Engagement during the first 3 hours of the post is the entire game. Block 11 AM PT to 2 PM PT on Wednesday July 23. Respond to every comment. Specifically:

**If the top comment is a critique:**
Don't get defensive. Acknowledge the critique on its merits. Counter-argue only if the critique has a factual error. Example: *"That's fair — the agent-as-markdown-file architecture is a tradeoff. Trades latency (can't compile prompts to deterministic logic) for transparency (any user can read why a finding triggered). For a security tool, I'd take transparency every time."*

**If someone says "this is just Snyk-lite":**
Generous response. *"Honest take: there's overlap (both are security audits) but a structural difference. Snyk is cloud-attached with a 5-seat minimum; Lictor is local-only with no minimum. Snyk speaks compliance dialect; Lictor speaks plain English. Both are deliberate — different audience, different shape. I expect most teams shipping AI features will use both."*

**If someone asks "why not just contribute this to Snyk":**
Same answer as the Reddit FAQ.

**If someone asks "are you really going to keep this free forever":**
Link to the Foundation commitment in CONTRIBUTING.md. *"The Lictor Foundation incorporating Q2 2027 governs the OSS code. Commercial features ship from Lictor LLC under BUSL with 4-year Apache conversion. The structural separation is the commitment. If the Foundation gets dissolved, that's a public-record event the community can rally against."*

**If someone asks "what's the business model":**
Honest. *"Teams tier ($19/mo flat, unlimited seats) for small teams who want shared findings + faster support. Audit-as-a-Service for VC firms auditing portfolio companies. Enterprise pilots later. Target: $25–50k MRR by May 2027. Self-funded; no VC. Burn ~$50k over 12 months."*

**If someone asks how the agents really work technically:**
Deeper engineering response. *"The agents are Claude/Sonnet-level LLMs invoked with structured system prompts. The 'SOUL.md' files are version-controlled system-prompt definitions. The audit isn't pure-LLM though — the actual check logic is in lictor-core (Rust) and ships to WASM for browser surfaces. The agents are responsible for prioritization, scoring, and the plain-English writing — not the detection itself. Detection is deterministic; analysis is LLM-assisted. Tradeoff: deterministic where reliability matters, LLM where voice matters."*

---

## What to do after the post

**If the post hits #1 on Show HN:** clear your calendar for 24h. Reply to every comment. Sleep is optional. The post WILL get scraped onto Twitter / other sites, and you'll get a wave of inbound DMs / emails — be ready to triage.

**If the post hits #1 on the main HN front page** (rare, but possible if it gets >300 points): you've broken into the second-order audience (HN users who don't filter for "Show"). This is the moment to capitalize — pin the post on Dor's personal Twitter, share it in the LinkedIn company page, send a one-time email to the existing waitlist saying "we hit the HN front page; here's the link, here's the conversation, here's how to weigh in."

**If the post lands in #20-50 on Show HN:** still good. The Show HN section has its own loyal audience. Won't drive 5,000 signups but 200-500 is realistic.

**If the post sits below #50 within an hour:** the post didn't catch. Don't try to revive it. Don't post a different version tomorrow. Wait 6+ months before another Show HN attempt for Lictor. Use what you learned in the comments to inform the actual Oct 6 launch post.

---

## What NOT to do

- **Don't email your waitlist asking them to upvote.** HN explicitly bans this and detects it.
- **Don't post in HN's other sections (Ask HN, etc.) on the same day.** Looks orchestrated.
- **Don't argue with critics in long threads.** Make your point once, acknowledge theirs, move on.
- **Don't apologize for the post being a Show HN.** This isn't a forum where Show HN is a second-class citizen.
- **Don't link to the Beacon waitlist as the primary CTA.** HN's audience prefers the repo URL — link to GitHub, link to the teardown, link to the audit-our-own-audit post. The waitlist is fine as one of three URLs.
- **Don't post the same content cross-channel within 48h.** Twitter + LinkedIn within 1h of HN is fine. Reddit on the same day will get flagged.

---

## The metrics that matter

| Metric | Floor | Target | Stretch |
|---|---|---|---|
| Position on Show HN at peak | Top 30 | Top 10 | #1 |
| Comments | 30 | 80 | 200+ |
| Upvotes (Show HN section) | 60 | 150 | 400+ |
| Front-page placement | No | No | Yes |
| Waitlist signups attributed to HN | 100 | 500 | 2,000+ |
| GitHub stars in 24h | 50 | 200 | 1,000+ |
| TechCrunch / Verge / Register inbound | No | No | Yes (1 reporter ping) |

The bar is the "Target" column. Below the floor: the campaign needs a serious post-mortem. At target: Beacon is exceeding plan. At stretch: Lictor is on track to be a category-defining brand on launch day.

---

## After the Show HN

Whatever happens, document it. The Show HN data point — what worked, what didn't, what comments revealed about the audience — is one of the highest-signal artifacts in the whole pre-launch campaign. Write it up that night while it's fresh. The writeup goes in `~/Lictor/docs/business/diligence/show-hn-2026-07-23.md` for future you (and any future investor who asks how Lictor got distribution).
