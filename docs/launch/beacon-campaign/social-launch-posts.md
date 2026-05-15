# Beacon launch — social posts

> Monday May 18 — first 24 hours of public Lictor existence.
> All copy below is ready to paste. Replace `[Dor's X handle]` / `[Lictor X handle]` with your actual handles before posting.

---

## Dor's personal Twitter / X — Monday 10:30 AM PT (the FIRST post)

```
After ~9 months of building, I'm announcing what I've been working on:

Lictor — a free open-source AI security audit for apps built with AI.

11 agents. Plain English. Runs in Claude Code. Apache 2.0.

Ships October 6.

If you ship from Lovable / Bolt / v0 / Cursor / Replit — this is for you. Waitlist + repo:

lictor.ai/waitlist
```

**Why this works:** opens with "after 9 months" (signals real work, not vaporware) + specific stack list (catches the right audience by keyword) + concrete date + 3 nouns (free / open source / Apache 2.0) for trust + single CTA.

**Length:** ~280 chars (fits Twitter's limit with margin).

**Post-publish:** reply to your own post with: *"For context — I'm a 20-year cybersecurity engineer. Lictor exists because every Lovable founder I know almost shipped a database leak. The tool's free. The waitlist is to gauge if anyone outside my circle wants this too."*

That follow-up reply gives the credibility frame without bragging in the headline tweet.

---

## @lictor_ai — Monday 11:00 AM PT (30 min after Dor's, so Dor's gets the algorithmic spike)

### Variant A (recommended — punchy + specific)

```
🛡 Introducing Lictor.

The security crew for apps you built with AI.

11 AI agents audit your project in 60 seconds. Plain English. No signup. No telemetry. Apache 2.0.

Ships October 6, 2026 — free forever.

Get on the list ↓

lictor.ai/waitlist
```

### Variant B (problem-led)

```
40-62% of AI-generated code ships with security vulnerabilities.

Most existing security tools speak SOC 2 and charge $25/dev/month.

We built the open-source one that speaks English and costs nothing.

Lictor. Ships October 6.

lictor.ai/waitlist
```

### Variant C (founder narrative)

```
A friend shipped a Lovable app last year. Got 5,000 signups in a weekend. His Supabase service-role key was in his JavaScript bundle.

He didn't know. The AI didn't tell him. None of his tools flagged it.

I'm fixing this. Lictor — free, open source, ships October 6.

lictor.ai/waitlist
```

**Recommendation:** Default to **Variant A**. Run B + C as boosted alternates in Week 3 if engagement on A plateaus.

---

## @lictor_ai follow-up thread (1 hour after Variant A) — the depth

```
1/ A bit more on what Lictor catches:

→ Supabase service-role key in your JS bundle
→ Missing RLS on your tables
→ Hallucinated npm packages
→ Unsigned Stripe webhooks
→ Frontend-only auth checks
→ Cross-tenant data leakage
→ AI endpoints with no rate limit

These are the 7 most-common vibe-coder failure modes.

2/ Why generic tools (Snyk, Semgrep) miss most of these:

They were built for codebases people wrote by hand.

The vibe-coder patterns are different — your AI assistant has its own idioms, its own defaults, its own gaps. Lictor's checks are tuned for what AI actually ships.

3/ The 11 agents:

Each one is a markdown file in the repo. Forkable. Auditable. You can read exactly how each one decides what to flag.

That's the inversion: most security tools are a black box. Lictor's crew is named, public, and the reasoning is visible.

4/ Why free / Apache 2.0:

The market is dominated by enterprise sales motions and certification theater. None of that helps the founder shipping a SaaS from Lovable on Saturday.

We build the layer they need: open, plain English, runs locally, 60 seconds to first audit.

5/ Who's building this:

Solo founder — Dor — 20 years in cybersecurity. CISO advisory at Fortune 500, security architecture for venture-backed startups.

He realized none of his Fortune-500 tools were going to help his indie-hacker friends. So he built the one that does.

6/ Ships October 6. Waitlist is open. The repo flips public around June.

If you build AI apps: lictor.ai/waitlist

If you want to follow the build in public: github.com/lictor-ai/lictor

Thanks for being early. 🛡
```

---

## LinkedIn company page — Monday 12:00 PM PT (lunch hour, when LinkedIn skim peaks)

```
Today we're announcing Lictor — an open-source AI security audit for apps built with AI.

The problem we exist for:

40-62% of AI-generated code ships with security vulnerabilities (multiple independent studies, 2025-2026). 91.5% of vibe-coded apps had at least one AI-hallucination flaw in Q1 2026. In a single February incident, one popular AI app-builder exposed 18,000 users across 170+ databases.

8 million people now build software with AI assistants every week, and most of them don't know what an "RLS policy" is — let alone how to find a leaked Supabase service key in their own JavaScript bundle.

Enterprise security tools weren't built for them. Snyk, Veracode, Checkmarx — they assume a five-developer team and a CISO who speaks SOC 2. They charge per seat. They report in compliance jargon. They gate everything important behind a sales call.

Lictor assumes you, a Claude Code window, and a Lovable app you shipped on Saturday.

Eleven specialist AI agents audit your project. Plain English. No signup, no telemetry, no per-seat pricing. Apache 2.0. Runs locally inside Claude Code.

Ships October 6, 2026 — free forever on the open-source core.

Built by a 20-year cybersecurity engineer based in Israel. Open source so trust is verifiable by reading the code, not by certificates.

Get on the waitlist: lictor.ai/waitlist
Track the build: github.com/lictor-ai/lictor

If you're a CTO or VP Eng with builders shipping AI features and you've been waiting for tooling that didn't require a sales call, I'd love your input. Reply or DM.
```

**Why this works on LinkedIn:** opens with stats (LinkedIn loves data), names the gap explicitly, soft CTA to a real conversation. Less indie-hacker-cool, more security-leader-credible.

---

## Buttondown welcome newsletter (one-time, on Beacon launch day to existing GenerationAI list)

**Subject:** I'm announcing what I've been building
**Preview text:** Lictor — free open-source AI security audit. Launching October 6.

```
Hey,

I've been quiet about what I'm building for a while. Here's the announcement.

It's called Lictor — a free, open-source AI security audit for apps built with AI (Lovable / Bolt / v0 / Cursor / Replit / Claude Code). 11 AI agents audit your project, find what's broken, and explain the fix in plain English. Runs locally. Apache 2.0. No signup, no telemetry.

It ships October 6, 2026.

The waitlist is open today: **lictor.ai/waitlist**

Why I'm telling you first: most people on this list build with AI or work with people who do. If Lictor would be useful to one of your projects (or to a friend's), get on the waitlist now — you'll get the install command in your inbox the morning we ship.

If it wouldn't be useful: no hard feelings, ignore this email.

Why I built this: the existing security tools cost $25/dev/month minimum, speak SOC 2, and require sales calls. None of that helps an indie hacker shipping from Lovable on Saturday. Lictor exists because the people who most need security tooling are the people who have the least access to it.

The whole thing is open source. The repo flips public around June 1. You can track the build at github.com/lictor-ai/lictor.

Thanks for reading. Lictor is just one of the things I'm working on this year, but it's the one I'm most excited about.

— Dor
```

---

## Tuesday tweet (Day 2 follow-up) — proof + early-signup count

Post around 9 AM PT, after the first 24 hours of Beacon are visible.

```
24 hours of Lictor's waitlist live:

→ [N] signups (counting…)
→ [X] from Lovable builders
→ [Y] from Bolt + v0
→ [Z] from Cursor / Claude Code

Top 3 questions in my inbox:

1. "Is this really free?" — yes, Apache 2.0 forever
2. "What about Windsurf / Replit?" — yes, also catches those
3. "Can I run it before Oct 6?" — repo flips public ~June 1, I'll email everyone

lictor.ai/waitlist
```

**Why this works:** transparent metrics (builds credibility) + addresses the 3 most-common objections preemptively + repeats the CTA for new readers.

**Caveat:** only post this if signups by 9am Tuesday are ≥ 50. If <50, skip — you don't want to publicize weak numbers. Save this template for the day you have a number worth sharing.

---

## Bluesky cross-post — same as Variant A above

If Dor has a Bluesky account, post the same Variant A there with the same timing. Different audience overlap; some people only check one network.

---

## Hacker News — SAVE FOR WEEK 10 (Jul 23, not today)

HN punishes Show HN posts with empty waitlists. Wait until you have ≥500 signups + a real artifact (the public repo) to share. The Show HN draft is in [show-hn-post.md](show-hn-post.md).

If you Show HN today with 0 signups + a private repo, the post will land at #100+ and stay there. That's a wasted shot at the most-important channel.

---

## Posting cadence after launch day

After Beacon's launch Monday, the steady-state weekly cadence is in [weekly-teaser-threads.md](weekly-teaser-threads.md). Don't post all of these tweets in one day — let the launch breathe, let Tuesday's tweet (if signups warrant) be the only follow-up.

The single most important thing on Day 1: respond to every reply within 1 hour. The algorithmic boost from active threading is bigger than any individual post you'd write next.
