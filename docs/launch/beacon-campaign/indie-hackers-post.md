# Indie Hackers post — submit Wednesday May 20

> Indie Hackers rewards long-form founder narrative. ~1500-2000 words. Lead with the personal moment that made you start, not the product.

---

**Title:** I've spent 9 months building Lictor — a free open-source security tool for vibe-coded apps. Here's why.

**Tag:** Building in Public · Open Source · AI / ML

**Body:**

---

Last August, a friend of mine shipped a Lovable app.

He's not a coder. He's a designer with a great product instinct, a couple thousand Twitter followers, and the kind of taste that builds successful B2C products. The app — let's call it Idea — was a beautifully-designed productivity tool. He launched on a Friday and had 5,000 signups by Sunday.

That Sunday evening he showed me the app on his phone. He was glowing. I was happy for him. Then, out of habit — twenty years of cybersecurity does this to you — I tapped through to his deployed site, right-clicked, "View Source." Found his main JavaScript bundle. Searched for `service_role`.

There it was. His Supabase service-role key. Sitting in a string literal in his bundle.js, the line clearly written by an AI assistant trying to be helpful. Anyone visiting his site — any of those 5,000 signups, any random scraper, any bored 14-year-old — had the key to his entire database. Read, write, delete. The whole thing.

I asked him about it. He didn't know what RLS was. He didn't know what a service-role key was. He'd used the Supabase template his AI assistant generated, the AI had embedded the key, and no part of his deployment pipeline had flagged it. Lovable hadn't flagged it. His AI hadn't flagged it. The "security best practices" article he'd skimmed once hadn't flagged it.

He rotated the key in fifteen minutes once I showed him how. The app is fine. He has a real business now, ~2 years later, that paid back every cent he put into it.

But that night I had the realization that turned into Lictor: **the people shipping the most software in 2026 are the people who have the least access to security tooling that speaks their language.**

---

## The security tooling gap

I've worked in cybersecurity for 20 years. CISO advisory at Fortune 500 companies. Security architecture for venture-backed startups. Plenty of compliance audits, plenty of incident response, plenty of evenings explaining to leadership what a CVE actually means.

The tools I'd recommend at my day job cost $25 per developer per month, minimum. They speak compliance dialect: "information disclosure vulnerability via insufficient input validation." They gate everything important behind sales calls. They assume you have a security team. They assume you can read SOC 2 reports.

None of that helps my friend.

None of that helps the next 8 million people who are going to ship apps from Lovable, Bolt, v0, Cursor, Replit, Claude Code, and Windsurf in 2026 alone.

The existing tools were built for codebases that people wrote by hand. AI-built apps have different idioms, different defaults, different gaps. Generic SAST scanners see `process.env.SUPABASE_SERVICE_ROLE_KEY` and shrug — they don't notice that the Next.js client component is importing it. They don't connect to your Supabase project to verify your RLS policies. They don't check whether the npm package your AI assistant imported actually exists on the registry, or whether it's a name an attacker registered last week specifically because AI assistants kept hallucinating it.

If you build with AI, you need security tooling built for what AI ships. That's the wedge.

So I started building it. Nine months ago.

---

## What Lictor is

Lictor is a free, open-source AI security audit for apps built with AI. Apache 2.0. Runs locally inside Claude Code. No signup, no telemetry, no per-seat pricing.

The audit takes about 60 seconds. It walks your project, runs 7 checks tuned for vibe-coder patterns, and produces a plain-English report. Each finding includes where it is (file + line), what's wrong (no jargon — "your /api/users page gives out the customer list to anyone"), and a 1-line fix.

The 7 checks are:

1. Supabase service-role key in your JS bundle (the canonical Lovable failure)
2. Missing Row-Level Security on Supabase tables
3. Hallucinated npm packages (typical AI mistake)
4. Frontend-only auth checks (the "admin gate" that ships to every visitor's browser)
5. Unsigned Stripe / GitHub / Shopify webhooks
6. Cross-tenant data leakage via Next.js cache
7. AI endpoints with no rate limiting

Under the hood, Lictor is 11 AI agents — each one has a specific job, each one is a markdown file in the repo you can read and fork:

- **Conductor** orchestrates
- **Radar** scouts for known patterns
- **Probe** runs the deep audit
- **Sieve** scores every finding before it ships to you (anything below 6/10 doesn't make the report — noise is the enemy of action)
- **Quill** translates everything to plain English
- **Magnet** drafts the fix
- **Mirror** weekly-reviews the crew's work
- ...and four more

That last detail — the crew structure being public, readable, forkable — matters. **Most AI security tools are a black box. Lictor's reasoning is visible.** You can read why a finding scored 7 out of 10. You can read which agent flagged it. You can fork an agent's prompt and customize the audit for your stack. That's the inversion.

---

## Why open source

I've watched a lot of OSS-led businesses succeed and a lot fail. Two things are true:

**1. The AI security market is going to be enormous.** Snyk shipped "Agent Security" in March 2026. Aikido has aggressive AI features. Anthropic is funding OSS security work. Multiple startups raised eight-figure rounds in the last 12 months. The category is real.

**2. The enterprise tools won't reach the indie-hacker audience.** Their pricing architecture, sales motion, and brand voice prevent them from credibly serving the Lovable + Bolt + v0 audience without alienating their enterprise buyers. That asymmetry is the moat.

So: build the open-source layer that fills the gap. Apache 2.0 forever on the core. Commercial features (Teams flat-rate, Studio Pro, Enterprise pilots) ship under separate licenses for the segment that wants more. None of that gates what the OSS user needs.

The Lictor Foundation will incorporate Q2 2027 to make this commitment structural — the OSS code lives under the Foundation; the commercial business lives in Lictor LLC; even if Lictor gets acquired, the OSS commitment survives.

---

## Why now

The Lovable security incident in February (18,000 users exposed across 170+ databases) was the moment the AI-built-app security category became visible to people who weren't already worried about it.

40 to 62 percent of AI-generated code ships with security vulnerabilities (multiple independent studies, 2025-2026). 91.5 percent of vibe-coded apps had at least one AI-hallucination flaw in Q1 2026.

8 million people use these platforms every week. Most of them don't know what an "RLS policy" is.

The window for building the trusted brand in this category is the next 12 months. After that, either enterprise vendors figure out down-market positioning (unlikely, structurally) or someone else builds what Lictor builds. I'd rather it be me than someone else, because I've thought hard about the voice problem — translating cybersecurity into something a non-technical founder can act on — and most people who try to build this will get the voice wrong and accidentally rebuild compliance theater.

That's the bet, anyway.

---

## What I want from you

If you build AI apps, I'd love your honest take on three things:

**1. Does this sound useful?** Specifically: if Lictor existed today, would you run it against one of your projects? Or is "free open-source security audit" not actually a thing the AI-builder market wants?

**2. What am I missing?** I've designed checks for 7 patterns. What's the 8th? What vibe-coder bug has bitten you that I should be catching?

**3. The voice — does "the security crew for apps you built with AI" land? Or sound like marketing-speak?** I've gone back and forth on this 50 times.

**Also, three concrete things you can do:**

- **Get on the waitlist.** lictor.ai/waitlist — I'll email you exactly 4 more times between now and the October 6 launch. No spam.
- **Tell a builder friend.** The single most useful thing one person can do for a pre-launch OSS project is forward the waitlist URL to one other potential user. That's the multiplier.
- **If you'd be a design partner**, reply to this post or DM me. I'm picking 10 builders to audit their projects before the public launch, in exchange for feedback. No money changes hands; you get a free audit, I get the truth about whether the tool works.

---

## What's next

Repo flips public around June 1. I'll email everyone on the waitlist the moment it does. The week after that I start publishing weekly teaser content — videos, blog posts, the "meet the agents" series, the "audit Lictor with Lictor" piece in August.

Launch is **Monday October 6, 2026**. That's a real date. Even if everything goes sideways between now and then, the tool ships that day.

The whole thing is built in the open. You can track the build at github.com/lictor-ai/lictor (live June 1). You can read the strategic plan (yes, the full 12-month plan is public — `docs/launch/year-plan-2026-2027.md`). You can see every weekly Mirror review of the crew's content output. The Lictor Foundation governance docs go public when the foundation incorporates.

Building this in public is the bet. I'd rather get the criticism while I can still respond to it than ship into a vacuum.

Looking forward to your feedback. Thanks for reading this far.

— Dor

Founder, Lictor AI
dor@lictor.ai · lictor.ai · github.com/lictor-ai/lictor

---

## How to engage in the IH comments

IH community is more sophisticated than Reddit. They'll ask:

**"How are you funding this without VC?"**
*"GenerationAI consulting income funds the year. Total burn ~$50k over 12 months. The plan is at `docs/launch/year-plan-2026-2027.md` in the repo (public June 1). The acquisition-readiness path is parallel — if a strategic buyer offers a real number in 2027, that's optionality. If not, Lane B is a $1-5M ARR independent. Both are real outcomes."*

**"Why not just contribute to Snyk / make this a Snyk plugin?"**
*"Snyk's product is structurally cloud-attached. Lictor's is local-first. The architectures don't compose. Also: Snyk's voice is compliance dialect. Lictor's voice is plain English. Both are deliberate — neither team should compromise the other. I think there's a future where the two coexist cleanly. Not as one product."*

**"What's the moat?"**
*"Brand + voice + vibe-coder-vertical focus + the 15-agent crew structure. Snyk has 10x the engineering. Lictor has the indie-hacker audience's trust. Different moats."*

**"You're solo — what happens if you get hit by a bus?"**
*"Honest answer: Lictor's OSS core would survive via the Foundation. The 15-agent crew has documented SOPs in the repo. A second contributor could continue Lictor without me, though obviously slower. I'm working on the documentation precisely so this isn't a fragile dependency. Not a perfect answer, but a real one."*

**"How are you avoiding compliance dialect creep?"**
*"Two things: (1) the audit-our-own-audit protocol logs every voice-bug filing — community feedback compounds; (2) Quill (the writer agent) has a 50-line forbidden-word list that catches creep automatically. Mirror reviews weekly. It's not zero-effort; it's structural-discipline."*

---

## Metrics to track

| Metric | Target | Source |
|---|---|---|
| Upvotes by end of Day 1 | ≥40 | IH dashboard |
| Comments by end of Day 1 | ≥20 | IH dashboard |
| Click-through to lictor.ai/waitlist | ≥150 | UTM `?utm_source=ih&utm_campaign=beacon-launch` |
| Waitlist signups attributed to IH | ≥40 | Mission Control |
| Design partner DM volume | ≥5 inquiries | Manual count |

If signups attributed to IH > Reddit, double-down on IH content in Week 3-4.
