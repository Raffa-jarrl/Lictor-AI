# Weekly teaser threads — 12 weeks of pre-launch Twitter content

> One thread per week for 12 weeks (May 21 → Aug 5) keeps Lictor visible without burning the goodwill of the audience that just signed up for the waitlist.
> Each thread is paste-ready. Customize the opener if a current event makes a better hook.

---

## Cadence

- **Wednesdays at 09:00 AM PT** (lunch hour US East, late afternoon EU) — empirically the highest-engagement window for tech-content threads.
- **8-12 tweets per thread.** Longer than that loses momentum; shorter doesn't compound enough.
- **Always end with a CTA to the waitlist** — `lictorai.com/waitlist`.
- **Always include a P.S. tweet** (after the official "/end") that says something off-script, a little vulnerable. Those tweets get the highest engagement.

---

## Thread 1 (May 28 — Week 2) — The 5 bugs every Lovable founder should check this weekend

```
1/ If you shipped a Lovable app, run these 5 checks against your project this weekend. Total time: 15 min. Worth the read.

I'm building Lictor (free open-source AI security audit for vibe-coded apps; launches Oct 6) and these are the patterns I see every week. 🧵

2/ Check 1: Search your bundle.js for "service_role" + "sk_live_" + "AKIA" + "ghp_" + "AIza".

If you find any: rotate the key NOW. Move it server-side. Anything in your client-side JS is public — every visitor downloaded it.

3/ Check 2: Open your Supabase dashboard → Authentication → Policies.

Anything with RLS disabled is publicly readable by anyone with your anon key.

That includes your "private" pending tables, your "internal" admin tables — all of them.

4/ Check 3: Search your code for `if (user.isAdmin)`.

If that check is in a React component, it ships to every visitor's browser. The check exists in the JS bundle but doesn't actually gate anything.

Real admin checks happen server-side, after a verified JWT.

5/ Check 4: Look at your Stripe webhook handler.

Does it call `stripe.webhooks.constructEvent(...)` with a webhook secret?

If not, anyone can POST fake `checkout.session.completed` events and grant themselves premium subscriptions. 12-line fix.

6/ Check 5: Open your `package.json` and search every dependency name on npmjs.com.

If any of them return 404, you have a hallucinated package. Your AI assistant imported a name that doesn't exist. Attackers register these names weekly.

7/ Each of these is a 1-line to 12-line fix. None requires hiring a security consultant.

But each is the kind of bug that ends a project if you ship it to thousands of users.

8/ The thing that bothers me most: none of the existing security tools catch most of these by default.

Snyk doesn't connect to your Supabase. npm audit doesn't check your imports against the registry. Generic SAST tools shrug at frontend-only auth checks.

9/ That's the wedge for Lictor.

The 7 checks above + 2 more, tuned for what Lovable / Bolt / v0 / Cursor / Replit / Claude Code apps actually ship. Plain English. Runs in Claude Code. Free forever (Apache 2.0).

Ships Oct 6, 2026. Get on the list: lictorai.com/waitlist

10/ /end thread.

P.S. If you run these checks and find something, reply or DM. I'd love to hear what you found — it informs which patterns we ship with on launch day.
```

---

## Thread 2 (Jun 4 — Week 3) — Meet Wolf

```
1/ Most AI security tools are a black box: input goes in, findings come out.

Lictor's 11 agents are different. Each one is a markdown file in the public repo. You can read why every finding triggers.

Today let me introduce Wolf. 🧵

2/ Wolf is Lictor's orchestrator.

When you run `/lictor-security-check`, Wolf reads your project first. Plans the audit. Routes work to the specialists. Surfaces a daily briefing.

Without Wolf, the other 10 agents would step on each other.

3/ The conductor metaphor is real:

🎼 Wolf doesn't play an instrument. They listen to the whole orchestra, decide who plays when, and shape the final piece.

Same for the audit — Wolf doesn't run security checks itself. It runs the team.

4/ Why this matters for you:

When you read a Lictor finding, you'll see which agent flagged it. Hawk found this. Mongoose verified it. Owl scored it 8/10. Lyrebird wrote the plain-English version. Wolf decided this was worth surfacing today vs. deferring.

You see the work.

5/ Most security tools say "here are 47 findings." Lictor says "here are the 5 findings worth your time today, and here's exactly why these 5 made the cut."

That's the difference between noise and action.

6/ Wolf's full SOUL.md (the agent's instructions) is at github.com/Raffa-jarrl/Lictor-AI/blob/main/agents/planner/SOUL.md (live when repo flips public around June 1).

You can fork it. You can customize how Wolf scores findings for YOUR project's specific concerns.

7/ Next week: Owl. The agent that REJECTS findings.

Yes — Lictor has an agent whose job is to reduce the findings count, not increase it. Owl scores each finding against 3 personas, and anything below 6/10 doesn't make the report.

Quality > volume.

8/ Lictor ships Oct 6. Free, open source, Apache 2.0, runs locally.

If you build with AI, get on the list: lictorai.com/waitlist

P.S. If you have ideas for an agent we should add (the current 11 cover most patterns but I'm sure there are gaps), the GitHub issue label is `feature-request` once the repo is public.
```

---

## Thread 3 (Jun 11 — Week 4) — Why most security reports are useless

```
1/ Every security report I've read in 20 years has the same problem.

It's written for someone who already knows what to do.

It uses words like "information disclosure vulnerability" instead of "anyone can read your customer list."

Lictor solves this. 🧵

2/ The traditional security report flow:

1. Auditor finds a bug
2. Auditor writes it up using OWASP terminology
3. Engineer reads it, doesn't understand
4. Engineer Googles the term
5. Engineer reads Wikipedia, still doesn't understand
6. Engineer asks security team
7. Days/weeks/months pass before the fix ships

3/ The Lictor flow:

1. Lictor finds a bug
2. Lictor writes it in plain English ("your /api/users page gives out the customer list to anyone")
3. Lictor shows the code + the 1-line fix
4. Engineer ships the fix
5. Engineer goes back to building

The difference is voice.

4/ Lictor has a `voice-bug` issue label on GitHub.

If you read a Lictor finding and think "that sounded too jargony," you file a `voice-bug`. Mantis (our reviewer agent) goes through every voice-bug filing weekly.

Voice is the product. Every regression gets caught.

5/ The forbidden-words list Lyrebird (our writer agent) enforces:

leverage · revolutionary · transform · supercharge · disrupt · robust · paradigm · synergy · ecosystem · holistic

These words mean nothing in security. Lyrebird rejects any finding draft that uses them.

6/ Example before/after:

Bad: "Information disclosure vulnerability via insufficient input validation in the /api/users endpoint."

Good: "Anyone can pass ?role=admin to your /api/users endpoint and get admin access. Add a server-side role check."

Same finding. Completely different action signal.

7/ Why this matters for builders:

You don't have a security team. You have yourself, an AI assistant, and 48 hours to ship something.

If the security report requires its own glossary, you'll bounce off it.

If the report reads like a senior engineer pointing things out — you'll fix it.

8/ Ships Oct 6. Free. Apache 2.0. lictorai.com/waitlist

P.S. Lyrebird's full SOUL.md is in the repo. The forbidden-words list is right there at line 38. Fork it, extend it, customize it for your team's voice.
```

---

## Thread 4 (Jun 18 — Week 5) — Why open source

```
1/ I keep getting asked: "why are you making Lictor free? You could charge $25/dev/month like Snyk."

Here's the actual answer. 🧵

2/ The AI security category is going to be enormous. Snyk shipped "Agent Security" in March. Aikido has aggressive AI features. $3.6B+ has flowed into agentic-AI-security startups in 12 months.

The category is real.

3/ But the enterprise vendors won't reach the indie-hacker audience.

Their pricing architecture (per-seat minimums), sales motion (demo + procurement), and brand voice (compliance dialect) PREVENT them from serving the Lovable + Bolt + v0 audience without alienating their enterprise buyers.

4/ That asymmetry is the moat for Lictor.

A free OSS tool with plain-English voice CAN'T be built by Snyk without breaking their existing business. They have to keep being Snyk.

I have nothing to break. I can just build what builders actually need.

5/ The business model that makes free work:

OSS core: free forever (Apache 2.0).

Teams tier: $19/mo FLAT (no per-seat) for small teams who want shared findings.

Audit-as-a-Service: for VC firms auditing portfolio companies.

Enterprise pilots: later.

6/ None of those paid tiers gate features the OSS user needs.

The OSS audit is the same audit, with the same patterns, with the same plain-English voice. Forever.

The paid tier just adds shared dashboards, priority support, encrypted local history.

7/ Long-term: the Lictor Foundation (incorporates Q2 2027) governs the OSS core. Lictor LLC handles commercial.

The structural separation means even if Lictor LLC ever got acquired, the OSS commitment survives the change.

That's the bet.

8/ "Why not VC fundraise to grow faster?"

I might, later. Year 1 is self-funded from my consulting income (~$50k total burn). VC changes the math — adds dilution, board pressure, exit-velocity demands. Lane B (independent at $5-25M ARR) is a real outcome.

Both paths stay open.

9/ Ships Oct 6. Free. Apache 2.0. lictorai.com/waitlist

P.S. The full year plan + acquisition strategy + 4-quarter execution is public in the repo (or will be, June 1). Building in public means the strategy is auditable too.
```

---

## Threads 5-12 — abbreviated outlines

Customize each before posting. Don't pre-write all 12 — your audience signal in Weeks 5-6 should inform the angle of Weeks 7-12.

| Week | Date | Hook | Beat |
|---|---|---|---|
| 5 | Jun 25 | Hallucinated npm packages — the attack vector nobody talks about | walk through one real example + the 2-line fix |
| 6 | Jul 2 | Why your "isAdmin" check is broken | the frontend-only auth pattern + fix |
| 7 | Jul 9 | Meet Owl — the agent that rejects findings | quality > volume thread |
| 8 | Jul 16 | The Lovable + Stripe pattern that lets anyone get free premium | unsigned webhook deep-dive |
| 9 | Jul 23 | (SHOW HN WEEK) — quieter thread, not a hard hook | reflective thread about building in public |
| 10 | Jul 30 | Reaction to whatever has happened in the AI security space | timely commentary |
| 11 | Aug 6 | We audited Lictor with Lictor — here's what we found | self-teardown teaser thread |
| 12 | Aug 13 | The 7 patterns we ship with on Oct 6 | summary of everything covered + final CTA |

After Week 12, drop to one thread every 2 weeks until launch. The waitlist is mostly built by then; the goal shifts from acquisition to retention (keeping the existing list warm).

---

## How to know if the cadence is working

Track per-thread:

| Metric | Floor | Target |
|---|---|---|
| Impressions | 5,000 | 25,000+ |
| Engagement rate (likes + retweets + replies / impressions) | 2% | 5%+ |
| Profile visits attributed to thread | 50 | 250+ |
| Waitlist signups attributed to thread | 5 | 30+ |

After 4 threads, recalibrate: which performed best? What was the structural difference? Double-down on that shape.

The HN thread (Week 9-10) is the spike event. Everything before it is building the audience that boosts the HN post; everything after it is converting the HN spike into waitlist signups.

---

## Peacock agent integration

These threads can be drafted by the Peacock agent (per the new-agents spec) once it comes online in Q4 2026. For Beacon, Raffa drafts them weekly OR Lyrebird (the writer agent) generates the first draft and Raffa edits.

Workflow when fully automated:

```
Sun PM:  Lyrebird drafts next week's thread from this week's news + the schedule above
Mon AM:  Mantis reviews; flags any voice issues
Mon PM:  Raffa edits the draft, schedules in Hypefury/TweetDeck
Wed 09:00 PT: thread auto-posts
Wed PM:  Raffa responds to top 5-10 replies within the algorithmic boost window
```
