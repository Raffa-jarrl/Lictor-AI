# Beacon drip sequence — 5 emails between signup and launch

> Paste each into Buttondown as a stage in the "Lictor Beacon — pre-launch drip" sequence.
> Delays measured from the moment the subscriber **confirms** (double opt-in), not from signup.

---

## Email 1 — Confirmation + welcome

**Trigger:** Immediately on confirmation.
**Subject:** You're on the list — Lictor ships October 6
**Preview text:** Here's what to expect between now and launch.

---

Hey,

You're on the Lictor waitlist. Thanks for the trust.

I'm Raffa — 20-year cybersecurity engineer, building Lictor in the open. Quick honest version of what you signed up for:

**What Lictor is.** A free, open-source AI security audit for apps you built with AI — Lovable, Bolt, v0, Cursor, Replit, Claude Code, all of them. 11 AI agents walk your project, find what's broken, and explain the fix in plain English. Runs locally inside Claude Code. No signup, no telemetry, no per-seat pricing.

**When it ships.** **October 6, 2026.** That's a real date, not a moving target. Even if everything goes sideways between now and then, we ship that day.

**What you'll get from me between now and then.** Four more emails. Total. That's it.

- ~2 weeks from now: 5 specific patterns I'm catching that the other tools miss
- ~1 month from now: meet the 11 agents (one of them is named Owl and rejects bad findings before you see them)
- ~3 months from now: the audit Lictor ran on its own codebase, with the findings we shipped to fix
- The launch day: "we shipped, here's how to install it"

No newsletter spam. No "weekly product updates." No "engagement re-activation campaigns." Just the four things above, then the launch.

**What you can do today.** If you build AI-built apps, run these three checks against your project right now (takes 5 min total):

1. Open your deployed app. View source. Search for `SUPABASE_SERVICE_ROLE_KEY` and `sk-`. If you find them in client JS, rotate them today.
2. Go to your Supabase dashboard → Authentication → Policies. Anything with RLS disabled is publicly readable.
3. If you use Stripe webhooks, confirm you're verifying `stripe-signature`. If you're not, anyone can fake `checkout.session.completed` and grant themselves premium.

If any of those three matter to your project, Lictor will catch a lot more like them when it ships.

Thanks for being early.

— Raffa

P.S. The repo flips public around June. If you want to track the build, star [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI) — I'll email you the day it goes live too.

P.P.S. The unsubscribe link is at the bottom of every email. No hard feelings if you change your mind.

---

## Email 2 — 5 patterns the other tools miss

**Delay:** 14 days after confirmation
**Subject:** 5 vibe-coder bugs Snyk doesn't catch
**Preview text:** What Lictor's audit looks for that the enterprise tools skip.

---

Hey again,

Two weeks since you signed up. Here's what's in your inbox today, as promised: the 5 patterns Lictor catches that the generic tools (Snyk, Semgrep, Trivy) don't catch by default.

These are real. I see them every week in Lovable / Bolt / v0 projects:

**1. Supabase service-role key in your JS bundle.** The single most common Lovable failure mode. Service-role key gives full database write access. If it's anywhere in your client-side JS, anyone with the URL has the key. Generic SAST tools see `process.env.SUPABASE_SERVICE_ROLE_KEY` and shrug — they don't notice the Next.js client component is importing it.

**2. Missing RLS on Supabase tables.** Snyk doesn't connect to your database. Trivy doesn't scan your schema. The pattern: a table exists with a `user_id` foreign key but no Row-Level Security policy, so the table is a free-for-all for anyone with the anon key. The anon key ships in every visitor's browser.

**3. Hallucinated npm packages.** Cursor + Claude Code occasionally suggest imports for packages that don't exist on npm — like `import { useAwesomeAuth } from "next-auth-supabase-pro"`. Attackers have started registering these hallucinated names to ship malware. Generic SAST doesn't check whether the package exists.

**4. Frontend-only auth checks.** `if (user.isAdmin) { showAdminPanel(); }` in a React component, with no server-side enforcement. Generic SAST sees auth logic in JS and assumes it's a check; Lictor knows the file ships to every browser and the check is meaningless.

**5. Unsigned Stripe webhooks.** Lovable + Bolt boilerplate often skips webhook signature verification. Anyone can POST `{type: "checkout.session.completed"}` to your `/api/stripe-webhook` endpoint and grant themselves the premium plan.

Each of these is a 12-line fix or less. Each is what Lictor catches in the 60-second audit. None require enterprise sales calls or 5-developer minimums to address.

**The point of the audit isn't to scare you — it's to give you a quick honest read on which of these (if any) actually apply to your project.** Right now you have to manually check each one. October 6, you run one command and Lictor tells you.

Next email: ~2 weeks. I introduce you to the 11 agents (genuinely — they're each a markdown file you can read on GitHub).

— Raffa

P.S. If your project is something you'd want me to audit personally when Lictor ships, reply to this email with a sentence about it. I'm picking 10 design partners for the first round of audits.

---

## Email 3 — Meet the crew

**Delay:** 30 days after confirmation
**Subject:** Meet the 11 AI agents that audit your project
**Preview text:** Most security tools are a black box. Lictor's crew is named, public, forkable.

---

Hey,

Most AI security tools are a black box: input goes in, findings come out. Lictor's audit doesn't work that way. It's 11 specialized AI agents, each with its own job, each defined in a markdown file you can read on GitHub. Today let me introduce a few:

**🎼 Wolf** — orchestrator. Reads your project, plans the audit, routes work to the specialists. Surfaces a daily briefing so the audit isn't a one-shot — it's an ongoing operation.

**🔍 Owl** — the quality gate. Scores every finding against three personas before it ships to you. Anything below 6 out of 10 doesn't make the report. **That's why Lictor's reports are shorter than other tools'. Noise is the enemy of action.**

**📡 Hawk** — pattern scout. Hunts for the bug shapes that AI assistants ship most. Trained on 1,430+ real audits. Knows that Lovable's default Supabase migrations skip RLS, that Bolt's Vite config ships source maps to production, that v0's Server Actions can be misused as auth bypasses.

**🖊️ Lyrebird** — voice keeper. Translates every finding into plain English. Not "information disclosure vulnerability" — "your /api/users page gives out the customer list to anyone." Reports your non-technical co-founder can read.

**🧲 Bee** — fix designer. For every issue, drafts the smallest possible fix and the exact file + line to put it in. No 40-page remediation guides. One paragraph, one diff, one rotated key.

**🪞 Mantis** — weekly auditor. Grades the crew's own work. Catches false positives, drifting voice, missed patterns. The reason the crew gets better, not louder, over time.

Plus five more: 🦾 Octopus (engineering), 🧪 Mongoose (currency tester), 📊 Bat (hook crafter), 📈 Starling (virality intel), 🎵 Cuttlefish (aesthetic curator).

**Why this matters:** every other security tool buries the reasoning. You get a finding, you trust or don't. Lictor surfaces which agent found what, why they scored it the way they did, and what they considered. **Transparency of process is itself the product.**

The whole crew is in the GitHub repo: `agents/` directory. Every SOUL.md is a markdown file you can fork. If you want to add your own specialist agent for a pattern Lictor doesn't catch, the contributing path is open.

Next email: ~2 months from now. I'll send you the most-uncomfortable artifact in the whole campaign — the time we audited Lictor with Lictor, and what we shipped to fix.

— Raffa

P.S. Repo flips public around June 1. I'll email you the day it does. Stars appreciated when it lands.

---

## Email 4 — We audited Lictor with Lictor

**Delay:** 90 days after confirmation
**Subject:** What happened when we audited Lictor with Lictor
**Preview text:** Five findings in our own codebase. Here's what we shipped to fix.

---

Hey,

A few months ago I ran Lictor's audit against Lictor itself. The framing is too good not to use: an AI security tool, audited by an AI security tool. The recursion writes itself.

The audit found 5 things wrong.

Two of them were the kind of finding that ends most security projects — embarrassing patterns I should have caught during the build. The other three were the day-to-day stuff every shipping project has.

We fixed all 5 within 72 hours. Then we wrote up the whole thing publicly because **that's the discipline this category needs**: every security tool's most-vulnerable moment is when its own code gets audited. If we hide that, every claim we make about anyone else is suspect.

The full writeup is at `lictorai.com/blog/we-audited-lictor-with-lictor`. The TL;DR:

- 🔴 **Critical.** A Guardian dashboard endpoint returned full SOC 2 evidence to any authenticated user, not just users with the `compliance_admin` role. Classic IDOR. Found by Mantis's weekly review of audit logs. Fix: role check + audit-log entry per access.

- 🟠 **High.** A skill that wrote findings to disk did so without sanitizing the project path. Path traversal would let a malicious project name write outside the intended directory. Fix: path canonicalization.

- 🟡 **Medium.** Sentinel SDK's `wrap()` didn't validate its config object. A library that defends against malformed input that didn't defend against its own malformed config. Fix: 8-line JSON schema validation.

- 🔵 **Low.** Test fixtures bundled in the published npm package. Not a security flaw, but bloat. Fix: .npmignore.

- 🔵 **Low.** A Mission Control proxy returned 503 with the env-var name in the error. Information disclosure that aids attackers. Fix: generic error.

**The lesson is in the protocol, not the findings.** When you build a security tool, you commit to publicly auditing your own code. When you find things wrong, you publish them. When you fix them, you publish that too. Every false-positive someone reports about Lictor gets logged in public. Every false-negative becomes a new check. This is the audit-our-own-audit protocol; the whole policy is at `lictorai.com/security`.

**One final email from me.** Two weeks before launch. I'll send the install command and the link.

October 6.

— Raffa

P.S. If you found this email more interesting than the prior three, tell a builder friend. Forward this email or share `lictorai.com/waitlist`. The early signal we get from list size is the difference between launching to crickets and launching to a room.

---

## Email 5 — Launch in 7 days

**Delay:** 110 days after confirmation (≈ 5 days before launch)
**Subject:** Lictor ships in 7 days
**Preview text:** Here's how to be ready Monday morning.

---

Hey,

Lictor ships Monday October 6, 2026. That's 7 days from now.

Here's the install command, save it somewhere:

```bash
# In Claude Code, from any project root:
git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/

# Then run:
/lictor-security-check
```

That's it. No signup, no API key, no account. The skill is free. The audit runs locally on your machine — nothing leaves.

**On Monday Oct 6, I'll send you one final email with:**
- A link to the public launch announcement
- The first teardown — a real audit of a real Lovable app with findings + fixes
- A link to the GitHub repo (which goes from private → public Monday morning)
- The Twitter / HN / LinkedIn posts where the conversation will happen

**Three things you can do this weekend to be ready:**

1. **Install Claude Code if you haven't.** It's at `claude.ai/code`. The Lictor skill needs it. (We're also shipping a CLI on launch day — `cargo install lictor-cli` — if you'd prefer a command over Claude Code.)

2. **Pick the one project you want Lictor to audit first.** Don't run it on every project Monday morning. Pick the project you're most nervous about and run it there. The findings will be more useful when concentrated.

3. **If you'd be willing to publicly post about Lictor on launch day,** even a single tweet, even a "tried Lictor, found these things, fixed them," that's the single most useful thing you can do for the project. We're not asking — just letting you know that's the moment when one shared link from a real user is worth 1,000 founder posts.

Whatever happens Monday — whether Lictor finds 0 things in your project or 12 things in your project — the audit cost you nothing. The fixes are 1-12 lines of code each. By Monday evening, your AI-built app will be measurably safer than it was Sunday.

That's the whole point. See you Monday.

— Raffa

P.S. If you want the same audit method but as a CLI instead of a Claude Code skill, `lictor` ships on crates.io Monday too. `cargo install lictor-cli` → `lictor audit .`. Same engine, terminal-first.

P.P.S. Thanks for being on this list since [signup date — Buttondown will autofill]. You're the reason the launch is happening with an audience instead of with crickets.

---

## Configuration note for Buttondown

Each email above has:
- A clear subject
- A preview text suggestion (use in Buttondown's "Preview Text" field)
- A real call-to-action that doesn't ask for money

Buttondown's sequence editor lets you set:
- Per-email delay (set per the timings above)
- Send time (recommend: 10am subscriber's local time; Buttondown auto-handles timezone if enabled)
- Skip weekends? (recommend: NO for this audience — vibe-coders read email on weekends)

Total sequence: 5 emails over ~110 days. After Email 5, the subscriber graduates out of the drip — but stays subscribed to the regular weekly Lictor newsletter that starts post-launch (separate Buttondown list).

Test the sequence by subscribing yourself, then manually triggering each delay via Buttondown's "send now" override for QA.
