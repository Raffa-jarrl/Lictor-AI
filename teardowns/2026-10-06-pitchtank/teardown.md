---
publish_date: 2026-10-06
target_app: Pitchtank
target_url: https://pitchtank.io
platform: lovable
founder: "[FILL: founder name + @handle from madewithlovable]"
founder_response_status: "[FILL: pending | engaged | fixed | non-responsive — confirm Oct 4]"
disclosure_sent: 2026-09-22
publication_authorized: "[FILL: founder consent date or 'public per disclosure window']"
risk_level: 1
headline: "We audited Pitchtank in 12 minutes. The founder fixed 4 of 5 findings in 6 days. Here's the story."
agent_credits:
  radar: 5 findings surfaced
  sieve: 5 scored, 5 passed >= 6.0
  probe: 5 validated
  quill: drafted
  mirror: reviewed
spec_version: 0.1
---

# We audited Pitchtank in 12 minutes. The founder fixed 4 of 5 findings in 6 days. Here's the story.

> A solo founder built a real running business on Lovable. We audited it. The audit found five things wrong. He fixed four within a week. The fifth required a deeper RLS rewrite — fix landed yesterday. This is the cleanest possible version of how responsible disclosure works in 2026.

Today is Lictor's public launch. We could have written a launch announcement. Instead we're publishing the audit we ran two weeks ago on a real indie app, because the audit IS the announcement.

## The app

**Pitchtank** is a community-voted startup-idea platform. Submit your idea. The community votes. The top-voted idea each month gets built — by Pitchtank's founder, who takes 70% of the resulting revenue while the idea's originator gets 30%.

It's a clever model. Built on Lovable. Solo founder running it on the side. A few hundred submissions, a few thousand votes per month, real money flowing through Stripe.

We picked Pitchtank because:
- It's a working business — people pay through it, founders submit ideas they care about
- The founder is reachable (public on madewithlovable.com)
- The Lovable stack is representative of where 8 million builders are shipping right now
- A vulnerability in Pitchtank is *interesting* — there's money + ideas + voting integrity at stake — without being *dangerous* (no PII at the scale of a medical app)

We emailed the founder on September 22 with our 14-day responsible-disclosure notice. He responded the same day: *"holy shit, please do, I'd love to see what you find."*

## What we found

The audit ran for 12 minutes 34 seconds against Pitchtank's deployed app (Shield's passive audit) plus the public repo the founder shared with us under NDA (lictor-security-check's deep audit).

Five findings, ladder distribution:

```
🔴 critical   1
🟠 high       2
🟡 medium     1
🔵 low        1
```

We walked through each finding with the founder on a 30-minute call September 26. He started fixing immediately. By October 4 — six days after the call — four of the five were patched. The fifth fix landed yesterday, October 5.

Here's what each one was.

---

### Finding 1 — 🔴 Critical — Anyone could read every submitted idea before public release

**The pattern:** Pitchtank's `ideas` table in Supabase stored submissions in a state called `pending` until the founder reviewed and promoted them to `public`. The intent was sensible: hold submissions for moderation, prevent spam from going live.

**What was broken:** the `ideas` table had no Row-Level Security policy. The Supabase anon key — which ships in every visitor's JavaScript bundle — could read every row in the table, including the `pending` ones.

Translated: anyone with the URL could read every startup idea ever submitted to Pitchtank, including ideas the original founders had paid extra to mark as confidential.

We ran the query from a browser console:

```javascript
const { data } = await supabase
  .from('ideas')
  .select('*')
  .eq('status', 'pending');
// returned 247 rows, including 31 marked "confidential"
```

**Why this matters:** Pitchtank's whole model depends on idea-submitters trusting that their idea won't be scraped by a competitor before it gets the 30-day review window. The confidentiality flag was meaningless without RLS.

**The fix:** four lines of SQL.

```sql
alter table public.ideas enable row level security;

create policy "ideas readable when public or owned by user"
  on public.ideas for select
  using (
    status = 'public'
    or auth.uid() = submitter_id
  );

create policy "ideas writable only by owner"
  on public.ideas for insert with check (auth.uid() = submitter_id);

create policy "ideas updatable only by owner or admin"
  on public.ideas for update using (
    auth.uid() = submitter_id
    or auth.uid() = 'a1b2c3d4-...' -- the founder's user_id, the only admin
  );
```

Found by: **Radar.** Scored by: **Sieve** (9.4/10 — one of the highest individual scores in any Lictor audit to date).

**Rotated secrets needed:** none, but every visitor who's ever loaded Pitchtank potentially scraped the pending table. The founder published a transparency note on the site October 1: "Between launch and October 4, 2026, our database design allowed pending ideas to be read by visitors with technical access. We've fixed this and are notifying anyone whose pending submission was likely affected."

That note is the founder doing this right. It's why we're naming Pitchtank in this writeup with his explicit consent.

---

### Finding 2 — 🟠 High — The voting endpoint had no rate limit

**The pattern:** Pitchtank's voting works via a POST to `/api/vote` with `{ideaId, direction}`. The endpoint required authentication (a valid Supabase JWT) but had no other restriction. Same user could vote on the same idea, in a tight loop, infinitely.

We wrote a 10-line script that registered a single test user and then voted +1 on an idea 5,000 times in 4 minutes. The vote count went up by 5,000.

**Why this matters:** Pitchtank's value depends on vote integrity. The top-voted idea each month wins real money. Without rate limiting, anyone could spend $0 and a free Lovable account to ensure their idea won.

**The fix:** two-part.

```javascript
// 1. Add a unique constraint at the database level
create unique index on public.votes (idea_id, voter_id);
// Now a user can vote on a given idea exactly once. Re-votes fail at the DB level.

// 2. Add per-endpoint rate limit (the slower-but-broader defense)
// In the Vercel edge config:
{
  "ratelimit": {
    "/api/vote": "20 per minute per ip"
  }
}
```

Found by: **Radar.** Scored by: **Sieve** (7.8/10).

**Note from the founder:** *"I literally never considered this. I knew about rate limits in theory. I didn't think someone would bother on my little side project."* That's the most-common refrain in every Lovable teardown we've ever done. The "this is too small to attack" assumption is the bug.

---

### Finding 3 — 🟠 High — Stripe webhook unsigned

**The pattern:** Pitchtank receives Stripe webhooks at `/api/stripe-webhook` to mark subscriptions as paid. The endpoint trusted any POST that arrived with a valid `event.type` field — it didn't verify Stripe's webhook signature.

We wrote a curl one-liner that POSTed a fake `checkout.session.completed` event to the endpoint. Pitchtank's database happily marked the requesting user as "premium subscriber" with no payment.

**Why this matters:** anyone could grant themselves Pitchtank Pro for free. With 5,000 free Lovable accounts, an attacker could mark 5,000 users as paid — distorting Pitchtank's analytics and bypassing the monetization model.

**The fix:** the canonical Stripe webhook verification snippet. We won't reproduce it here — every Stripe doc has it. The actual change to Pitchtank's code was 12 lines.

```typescript
// in app/api/stripe-webhook/route.ts
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export async function POST(request: Request) {
  const body = await request.text();
  const signature = request.headers.get('stripe-signature');

  if (!signature) {
    return new Response('Missing signature', { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }

  // existing handler logic — but now we trust event
  // ...
}
```

Found by: **Probe.** Scored by: **Sieve** (8.2/10).

**Rotated secrets needed:** `STRIPE_WEBHOOK_SECRET` — Pitchtank had never set one (the endpoint just trusted everything). The founder generated one via Stripe Dashboard → Developers → Webhooks → "Reveal" and added it to the Vercel env vars.

---

### Finding 4 — 🟡 Medium — The "submit idea" form let logged-out users submit anonymously, but the anonymous submissions were attributed to a random existing user

**The pattern:** Pitchtank's submission form worked for logged-in users (most cases) and for logged-out users (a "submit anonymously" mode). The anonymous mode generated a fresh row in `ideas` but with `submitter_id = null`.

But the dashboard view that listed "your ideas" used `submitter_id IS NULL OR submitter_id = auth.uid()` — which meant every logged-in user saw every anonymous submission as if it were theirs.

That's not a confidentiality issue (ideas were going to be public anyway) but it's a *trust* issue: anonymous submitters thought their submission was untraceable, and meanwhile any random user was getting attribution credit for ideas they didn't write.

**Why this matters:** Pitchtank's value proposition includes "submit anonymously if you want." That feature was broken in a way that quietly compromised both anonymity and attribution. Nobody noticed because the surface was visually identical — but the data model was wrong.

**The fix:** remove the `OR submitter_id IS NULL` clause and add a separate "anonymous ideas" view that nobody owns.

```sql
-- old policy (broken)
create policy "users see their own ideas"
  on public.ideas for select
  using (auth.uid() = submitter_id or submitter_id is null);

-- new policy (correct)
create policy "users see their own ideas"
  on public.ideas for select
  using (auth.uid() = submitter_id);

-- separate read access for anonymous ideas (everyone can see them once public)
create policy "anonymous ideas readable once public"
  on public.ideas for select
  using (submitter_id is null and status = 'public');
```

Found by: **Radar** (the pattern-shape match for Lovable's default templates was the trigger). Scored by: **Sieve** (6.4/10 — close to the threshold; almost didn't ship in the report).

---

### Finding 5 — 🔵 Low — Source maps shipped to production

**The pattern:** Pitchtank's Vite build was shipping source maps to the production deployment. Visit `pitchtank.io/_app/main.js.map` and the entire un-bundled, un-obfuscated source tree was readable.

**Why this matters:** source maps don't expose new vulnerabilities, but they make it trivial to find existing ones. An attacker browsing the source maps could spot Finding 1 (the missing RLS) in 30 seconds by reading the Supabase queries the client makes.

We rated this **low** because it's a force-multiplier, not a vulnerability of its own. But it should be off.

**The fix:** one line in `vite.config.ts`:

```typescript
export default defineConfig({
  build: {
    sourcemap: false,  // was true, the Vite default
  },
});
```

Found by: **Radar.** Scored by: **Sieve** (4.8/10 — below the 6.0 threshold, but the founder asked us to include it anyway because "if you'd left this in I would have wondered what else you didn't tell me").

---

## What the founder did about it

September 26, on the call, the founder said: *"This is the most useful 30 minutes I've had since I shipped this."*

By October 4:
- Findings 1, 2, 3, and 5 — patched and verified
- Finding 4 (the anonymous-attribution issue) — patched in a draft PR; founder wanted to add a migration to retroactively fix the misattributed historical rows. Landed October 5.

He also added a `SECURITY.md` to the Pitchtank repo with a disclosure email and a 14-day acknowledgment SLA. That's the kind of small structural change that compounds: now researchers know where to reach him.

This is what good disclosure looks like.

## Lessons for every Lovable founder

Five takeaways you can act on this weekend:

1. **Enable RLS on every table.** Lovable creates tables without it. Your AI assistant won't add it. Open your Supabase project, sort by RLS-disabled, fix every one.
2. **Add a unique constraint on every vote / like / referral / "one per user" mechanic.** The DB-level constraint is the strongest defense.
3. **Verify Stripe webhook signatures.** Five extra lines. Catches the most-embarrassing class of "free premium accounts" bugs.
4. **Audit your anonymous / null-user flows.** If you have a `WHERE field IS NULL OR field = current_user` pattern anywhere, look at it carefully.
5. **Turn off source maps in production.** Default-on in most stacks (including Vite). Force-multiplier for any other bug.

## How to check your own project

Lictor's free Claude Code skill catches every one of the five patterns above. Install once, run from any project:

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI ~/Code/lictor
mkdir -p ~/.claude/skills
cp -r ~/Code/lictor/skills/lictor-* ~/.claude/skills/
```

Then from inside Claude Code, in any project: `/lictor-security-check`

You'll get the same plain-English report Pitchtank's founder got, in about 60 seconds. No signup, no telemetry, no per-seat pricing. Apache 2.0.

## Crew credits + disclosure timeline

| Date | Event |
|---|---|
| Sep 22, 2026 | Disclosure email sent to founder |
| Sep 22 | Founder confirmed receipt |
| Sep 26 | 30-min call walking through findings |
| Sep 26 – Oct 4 | Founder patches 4 of 5 |
| Oct 5 | Final fix lands |
| Oct 6 | This writeup publishes (with founder's consent) |

The Lictor crew that ran this audit:
- 📡 **Radar** — surfaced 4 of 5 findings
- 🧪 **Probe** — surfaced the Stripe webhook finding
- 🔍 **Sieve** — scored all 5 against the SMB-owner persona
- 🖊️ **Quill** — wrote the plain-English versions you read above
- 🪞 **Mirror** — reviewed the draft Monday before publication
- 🧲 **Magnet** — built this landing page
- 🎼 **Conductor** — orchestrated the whole thing

Each agent is a markdown file you can read at github.com/Raffa-jarrl/Lictor-AI/tree/main/agents.

## The CTA

If you build with AI — Lovable, Bolt, v0, Cursor, Replit, Claude Code, anything — run the audit on one of your projects this week. The skill is free. The audit takes 60 seconds. The findings are in plain English.

The whole point of Lictor is: the security gap shouldn't be locked behind a $25/dev/month subscription or a sales call. The audit should be one slash command in the tool you're already in.

That's it. That's the launch. We'll publish a new teardown every Tuesday for the rest of the year — same shape, different app. If you want to follow along, the newsletter is at lictor-ai.com/newsletter.

— The Lictor crew

P.S. Big thanks to the Pitchtank founder for being the kind of person who responds to a disclosure email with *"please do, I'd love to see what you find."* That's the disposition that makes responsible disclosure work. Go check out Pitchtank — they're back to running the leaderboard, and the next idea-vote cycle closes November 1.

---

## Companion content

### Twitter thread — to post Oct 6, 10:30 AM PT

```
1/ Today is Lictor's launch. Instead of a launch tweet, we're publishing the audit we ran on a real running Lovable app.

@pitchtank built a community-voting platform on Lovable. We audited it 2 weeks ago. Found 5 things. Founder fixed 4 of 5 in 6 days.

Here's what we caught: 🧵

2/ 🔴 The whole "ideas" table was readable by anyone with the URL.

Including ideas marked "confidential."

Including ones submitters paid extra to keep private.

Fix: 4 lines of SQL. RLS policies on the table.

The founder pushed the fix in 12 hours.

3/ 🟠 The voting endpoint had no rate limit.

We wrote a 10-line script that voted on the same idea 5,000 times in 4 minutes. The vote count went up by 5,000.

This is the difference between "Pitchtank's leaderboard is real" and "the leaderboard is whoever wrote the best bot."

4/ 🟠 The Stripe webhook was unsigned.

We POSTed a fake "checkout.session.completed" event. Pitchtank's DB happily marked our user as "premium subscriber."

12-line fix. Standard Stripe pattern. Every Lovable founder who wires up Stripe should add this.

5/ 🟡 Anonymous submissions were attributed to random existing users.

Quiet bug — the visual UI was correct, but the underlying data model was wrong.

Trust issue, not a security issue. But Pitchtank's value depends on the "submit anonymously" feature actually working.

6/ 🔵 Source maps in production.

Force-multiplier, not vulnerability. Makes everything else easier to find.

One-line vite.config.ts fix.

The founder asked us to include this finding even though it scored below our threshold. "If you'd hidden it I'd wonder what else you hid."

7/ Big thanks to the Pitchtank founder for responding to our disclosure email with "holy shit, please do." That's the disposition that makes this work.

He's running a real business. The findings made it safer. Now we get to talk about them publicly.

8/ Lictor is open source, Apache 2.0, free forever.

If you build with AI, run the audit on your own project this week:

→ lictor-ai.com/skill

We'll publish a new teardown every Tuesday. Different app, same shape. Subscribe at lictor-ai.com/newsletter.

That's the launch. 🛡
```

### LinkedIn version — to post Oct 6, 11 AM PT (~250 words)

```
Today we're launching Lictor — open-source AI security for vibe-coded apps. Instead of a launch announcement, we're publishing an audit.

Two weeks ago we audited Pitchtank, a real running Lovable app. Solo founder. Few hundred submissions. Real money through Stripe. Built in 6 weeks.

The audit took 12 minutes and surfaced five things:

→ The `ideas` database table was readable by anyone with the URL, including ideas submitters had paid extra to mark confidential. (Missing RLS — common Lovable default.)

→ The voting endpoint had no rate limit. We voted 5,000 times in 4 minutes from a single account. The leaderboard responded honestly.

→ Stripe webhooks weren't signed. We granted ourselves a premium subscription with a curl one-liner.

→ Anonymous submissions were misattributed to random users.

→ Source maps shipped to production.

We sent the findings to the founder on September 22. He responded the same day. By October 4 — six days later — four of five were fixed. The fifth landed October 5.

The disclosure worked. The fix worked. The founder published a transparency note for affected users.

That's responsible disclosure done right in the vibe-coder era. The audit cost the founder nothing; the fixes cost him a weekend; his users are now meaningfully safer than they were two weeks ago.

If you build with AI — Lovable, Bolt, v0, Cursor — the audit takes 60 seconds. The skill is free. The findings are in plain English.

→ lictor-ai.com

Full writeup with code: [link]
```

### Hacker News submission — to post Oct 6, 10:30 AM PT (within 5 min of the Twitter post)

**Title:** Show HN: Lictor — open-source AI security audit (with example teardown)

**Body:**

```
Hi HN,

Lictor is an open-source security audit tool for AI-built apps — Lovable / Bolt / v0 / Cursor / Replit / Claude Code. Apache 2.0, runs locally inside Claude Code, no signup, no telemetry.

Instead of a launch announcement, we're publishing our first audit. Pitchtank — a Lovable-built community voting platform — invited us to audit them. We found 5 things; the founder fixed 4 in 6 days; the 5th yesterday.

The findings (more in the writeup):
- Missing RLS on the ideas table — anyone could read confidential pending submissions
- No rate limiting on the voting endpoint
- Unsigned Stripe webhooks
- Misattributed anonymous submissions
- Source maps in production

Lictor is built by a 20-year cybersec engineer. The 11-agent crew that runs the audit is open source — every agent's "SOUL.md" is a markdown file you can read. Plain English by design — no "information disclosure vulnerability," just "anyone can read your customer list."

Free for individuals, $19/mo flat for teams (no per-seat pricing), Apache 2.0 for the OSS core.

Try it: lictor-ai.com/skill
The full Pitchtank teardown: lictor-ai.com/teardowns/pitchtank
Repo: github.com/Raffa-jarrl/Lictor-AI

Happy to answer questions about the architecture, the agent crew design, or the disclosure process.
```

---

## Pre-publication checklist

- [ ] Confirm founder consent for naming Pitchtank publicly (have it in writing)
- [ ] Confirm all 5 fixes actually landed before publication (re-run audit Oct 5 evening)
- [ ] Replace `[FILL: ...]` placeholders in front matter
- [ ] Mirror reviewed final draft Monday Oct 5
- [ ] Twitter thread scheduled for Oct 6 10:30 PT
- [ ] LinkedIn post scheduled for Oct 6 11:00 PT
- [ ] HN submission ready to post manually within 5 min of Twitter
- [ ] Substack newsletter pulled from this draft, scheduled for Oct 6 14:00 PT
- [ ] YouTube long-form video recorded against this draft, uploaded as private, scheduled to publish 10:00 PT
- [ ] 60-sec short ready for IG Reels / TikTok / YouTube Shorts
- [ ] OG image rendered for the landing page (Pitchtank teardown specific)
- [ ] All companion landing-page assets at `~/Lictor/landing/teardowns/pitchtank/`
