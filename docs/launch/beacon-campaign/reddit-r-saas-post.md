# r/SaaS post — submit Tuesday May 19, 10 AM PT

> Reddit is allergic to anything that smells like marketing. The post below is written in honest-founder voice, leads with utility, and asks for feedback. Comments + answers from Raffa are 80% of the value — block 2 hours Tuesday afternoon to engage in the thread.

---

## Subreddit choices (post once, mention in others)

**Primary submission:** r/SaaS (highest-fit audience, ~250k members, 30-day-old account requirement — Raffa's account should be old enough)

**Secondary (post within 48h):** r/indiehackers, r/SideProject, r/SaaSy

**Avoid:** r/programming (will be flagged as self-promo), r/startups (wrong audience density)

---

## The post

**Title:** I built a free open-source AI security audit for vibe-coded apps. Looking for honest feedback before I launch.

**Body:**

```
Hey r/SaaS,

Quick context — I've been quiet about what I'm building for ~9 months. Today I'm opening the waitlist for the first time and would love honest feedback from this community before the public launch in October.

The tool: **Lictor** — a free, open-source security audit for apps built with AI (Lovable, Bolt, v0, Cursor, Replit, Claude Code). 11 AI agents walk your project, find what's broken, and explain the fix in plain English. Runs locally inside Claude Code. Apache 2.0. No signup, no telemetry, no per-seat pricing.

**Why I built it:**

A friend shipped a Lovable app last year. Got 5,000 signups in a weekend. I clicked "view source" on his deployed app — his Supabase service-role key was sitting in his bundle.js. Anyone visiting his site could write to his database.

He didn't know. His AI assistant didn't tell him. None of the tools he used (and he had tried Snyk's free tier) flagged it.

That's the wedge. Generic security tools were built for codebases people wrote by hand. Vibe-coder apps have different idioms, different defaults, different gaps. Lictor's checks are tuned for what AI actually ships — Lovable's missing RLS, Bolt's source maps in production, v0's misused Server Actions, Cursor's hallucinated npm packages.

**The 7 patterns Lictor catches:**

1. Supabase service-role key in your JS bundle
2. Missing Row-Level Security on tables
3. Hallucinated npm packages (AI made up the package name)
4. Frontend-only auth checks (the "admin gate" that isn't)
5. Unsigned Stripe / GitHub / Shopify webhooks
6. Cross-tenant data leakage via Next.js caching
7. AI endpoints with no rate limiting

Each finding includes: where it is (file + line), what's wrong in plain English (no "information disclosure vulnerability" — just "anyone can read your customer list"), and a 1-line fix.

**About the founder bit:** I'm Raffa, 20 years in cybersecurity. CISO advisory at Fortune 500, security architecture for venture-backed startups. I built Lictor because the security tools I'd recommend at my day job cost $25/dev/month minimum and require sales calls. None of that helps an indie hacker shipping from Lovable on Saturday.

**What I'm asking from this community:**

1. **Is this useful?** If you've shipped a Lovable / Bolt / v0 app, would you run Lictor against it the day it launches? Or is "free open-source security audit" not actually a thing the indie-hacker market needs?

2. **What am I missing?** I've designed checks for 7 patterns. What's the 8th? What pattern have you seen in your own AI-built apps that I should be catching?

3. **Honest read on the positioning:** the line "the security crew for apps you built with AI" — does that land? Or does it sound like marketing-speak? I keep going back and forth.

4. **Who else is building this?** I've researched Snyk Agent Security, Aikido, Terra Security, VibeEval, Symbioticsec. Anyone I should know about? I'd rather collaborate than parallel-evolve.

**Launch + waitlist:**

Ships **October 6, 2026.** Waitlist is open today: **lictor-ai.com/waitlist**

The repo flips public around June 1. If you want to follow the build, github.com/Raffa-jarrl/Lictor-AI will be live then.

Anyone who wants to be a design partner (audit your project before the public launch, in exchange for feedback) — reply here or DM me. I'm picking 10 people.

Thanks for reading. Genuinely curious what this sub thinks.

—

Edit (will fill in after live): top 3 questions from the comments, with answers.
```

---

## How to handle replies (the 80% of the work)

Block Tuesday 12pm-3pm PT (lunch through early afternoon US, evening EU). Reply to every comment in that window. Specifically:

**If they ask "is this really free?"**
*"Yes — Apache 2.0, OSS core stays free forever. The Lictor Foundation (incorporating Q2 2027) governs the OSS code; commercial features ship from a separate LLC. The structural separation is the commitment. Full legal-structure memo in our docs."*

**If they ask "why not just use Snyk?"**
*"Snyk is great at what it does — known CVE detection in dependencies, Java/Go SAST. They're built for enterprise teams. Lictor is built for the Lovable + Bolt + v0 audience their pricing and voice can't reach. Most teams shipping AI features will benefit from both. They're complementary, not competing."*

**If they ask "what's the business model?"**
*"OSS core: free forever. Teams tier (Dec 15, $19/mo flat, unlimited seats) for small teams who want shared findings + faster support. Audit-as-a-Service for VC firms auditing portfolio companies. Enterprise pilots later. None of that gates the OSS user."*

**If they ask "are you sure indie hackers will pay $19/mo?"**
*"Honestly, that's the bet. If we get 100 paying Teams subs by year-end that's strong validation. If we get 10 it's a real signal the audience doesn't believe in paid. The waitlist is partly to measure that — even free OSS is hard to validate demand for without proof."*

**If they ask "can I help / collaborate?"**
*"Yes. Three concrete asks: (1) sign up to the waitlist + tell a builder friend, (2) if you'd be a design partner, reply with the project URL, (3) once the repo is public (June 1), open issues with the `pattern-request` label for any vibe-coder bug you've seen we should catch."*

**If they ask "why are you building this alone?"**
*"Capital efficiency + the agent crew. I have 11 AI agents that handle content / triage / weekly reviews / competitive scans. They're not engineers but they extend my reach. First human hire likely Q1 2027 if revenue supports it."*

**If they question the credibility / 20-year cybersec claim:**
*Don't argue. Link to your LinkedIn. Move on.*

**If someone says "I run a security tool, want to collab" or "I run Lovable / Bolt / v0":**
*Pull them into DM. These are platform-partnership conversations — see [platform-partnership-pitch.md](../platform-partnership-pitch.md).*

---

## Metrics to track from this post

| Metric | Target | How to capture |
|---|---|---|
| Upvotes | ≥30 in first 24h | Reddit dashboard |
| Comments | ≥15 in first 24h | Reddit dashboard |
| Top comment ratio | ≥70% positive | Manual read |
| Click-through to lictor-ai.com/waitlist | ≥100 | UTM parameter `?utm_source=reddit&utm_medium=r-saas&utm_campaign=beacon` |
| Waitlist signups attributed to Reddit | ≥30 | Mission Control dashboard's source breakdown |
| Design-partner DM volume | ≥3 inquiries | Manual count |

Below these numbers, the post underperformed. Above them, repurpose the angle for the IH submission Wednesday.

---

## Cross-post (Tuesday afternoon, ~2 hours after r/SaaS)

Post a slightly tightened version to r/indiehackers (different community vibe — even more founder-first, even less marketing tolerance):

```
Title: Built a free AI security tool for vibe-coded apps. Looking for design partners + honest feedback.

Body: [same as r/SaaS but cut the stats paragraph; lead with the "friend shipped a Lovable app" story; close with "I'm picking 10 design partners — DM if interested"]
```

Then r/SideProject (most-supportive community for new launches):

```
Title: [Side project] Lictor — open-source AI security audit, ships Oct 6, waitlist open today

Body: [significantly shorter — 200 words; for r/SideProject, brevity wins]
```

Don't cross-post the exact same text to all three — Reddit's algorithm penalizes that.
