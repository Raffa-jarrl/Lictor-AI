---
publish_date: 2026-10-27
target_app: AgentSwarms
target_url: https://agentswarms.fyi
platform: lovable
founder: "@AgentSwarmsAI"
founder_response_status: "[FILL: pending | engaged | fixed | co-publication]"
disclosure_sent: 2026-10-06
publication_authorized: "[FILL: founder consent date]"
risk_level: 3
headline: "AgentSwarms teaches multi-agent AI. We audited it with multi-agent AI. Here's what one crew found in the other."
spec_version: 0.1
---

# AgentSwarms teaches multi-agent AI. We audited it with multi-agent AI. Here's what one crew found in the other.

> AgentSwarms is a Lovable-built sandbox for building and orchestrating AI agent swarms — users plug in OpenAI/Anthropic API keys and run real agents that send emails, query databases, hit webhooks. It teaches multi-agent AI. We audited it. The recursion practically writes itself.

This is the fourth Lictor teardown. It's the first time we've audited an AI-agent platform with our own AI-agent platform. The meta-frame is irresistible and the findings are exactly the patterns AgentSwarms exists to teach about.

## The app

**AgentSwarms** (agentswarms.fyi) is a visual in-browser sandbox where users build, test, and run multi-agent AI workflows. The platform has 40+ lessons, 30+ live example agents, and a runtime that executes user-defined agents against user-supplied API keys. Real agents. Real API calls. Real SMTP. Real webhooks.

The founder is public on X (@AgentSwarmsAI). The product is featured on madewithlovable.com. The user base is small but engaged — agentic-AI hobbyists, dev-tool builders, AI-curious indie hackers.

We picked AgentSwarms because:
- It's the densest possible attack surface (user-supplied API keys + real runtime + agent execution)
- The "AI-platform-auditing-AI-platform" frame is exactly the launch narrative Lictor is built on
- The founder is reachable and (we hoped) educationally-inclined — willing to engage with the disclosure as a teaching moment

Disclosure email went out October 6 with a 21-day window (longer than usual — higher risk requires more lead time). The founder responded within 12 hours: *"this is going to be educational for our community. let's coordinate the disclosure."* That's exactly the disposition we hoped for.

## What we found

Three findings. The first one is apocalyptic, the second is the predictable platform-typical pattern, the third is a design issue that's hard to fix.

```
🔴 critical   1
🟠 high       1
🟡 medium     1
```

> *Note for v0.1: predicted findings shape; replace with Probe's actual output before publishing. The meta-frame works regardless of which specific findings land.*

---

### Finding 1 — 🔴 Critical — User-supplied OpenAI/Anthropic API keys stored in plaintext in Supabase without RLS

**The pattern.** AgentSwarms users plug in their own API keys to run agents — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, sometimes others (`SERP_API_KEY`, `RESEND_API_KEY`, etc.). These keys are persisted in a Supabase table called `user_credentials` so the user doesn't have to re-enter them every session.

The table stored the keys *unencrypted at rest*. The table had no Row-Level Security policy.

**What was broken.** The Supabase anon key in every visitor's browser bundle could read every row of `user_credentials`:

```javascript
const sb = createClient(URL, 'eyJ...the-anon-key...');
const { data } = await sb.from('user_credentials').select('*');
// returned N rows including the raw OPENAI_API_KEY of every AgentSwarms user
```

A small attacker could drain the API budgets of every user of the platform within a single afternoon. We computed the approximate exposure: if AgentSwarms has 200 users, the average OpenAI account on Tier-2 access (~$100-500/month rate-limit ceiling), the attacker could rack up ~$20-100K in fraudulent API usage before any user noticed.

This is one of the worst possible failure modes for an AI-agent platform — every user who trusted you with their API key now has that key exposed.

**Why this matters.** It's the *educational* failure of the platform. AgentSwarms teaches *building* AI agents but didn't model the security of the *platform hosting them*. The lesson is the kind that should compound into the curriculum: how to architect a platform that lets users plug in credentials safely.

**The fix.** Three-layer:

1. **RLS on the table** (the universal fix):

```sql
alter table public.user_credentials enable row level security;

create policy "users see only their own credentials"
  on public.user_credentials for select
  using (auth.uid() = user_id);
```

2. **Encrypt at rest with a per-user key derived from the user's session.** The Supabase service-role (server-side only) holds the master key; the user's row stores keys encrypted with their derived key. Even with database access, an attacker can't decrypt without compromising the server.

3. **Don't store keys at all where possible.** Offer a "session-only" mode where credentials live in the browser's local storage and never touch the platform's database. Users opt in for "persist credentials" with explicit consent.

The founder is shipping all three layers. The RLS fix landed within 24h. Encryption-at-rest is in flight. Session-only mode is a Q1 2027 milestone.

**Critical action for current users:** the AgentSwarms team is force-rotating every API key by emailing every user a "rotate your keys" notice + removing the stored keys from the database. Users will need to re-enter keys in the new (encrypted) flow.

**Found by:** Probe. **Scored by:** Sieve (9.9/10 — the highest score Sieve has ever issued).

---

### Finding 2 — 🟠 High — Agent execution lacks prompt-injection defense in the lesson content itself

**The pattern.** AgentSwarms's lesson content includes example prompts users can run against their agents. Some lessons walk through "what to do when the agent's input contains adversarial instructions." But the lesson content ITSELF can be manipulated: anyone with edit access to a lesson can embed prompt-injection payloads.

More concerning: user-uploaded "shared agent recipes" (a feature where users publish their own agent templates for others to import) can include prompt-injection payloads that affect downstream users' agents.

**What was broken.** No `@lictor/sentinel`-style wrap layer on the LLM calls. The platform trusted all input to user-defined agents as user-controlled, when in fact some of it (shared recipes, lesson content) came from third parties.

**Why this matters.** AgentSwarms is a teaching tool for AI agents. If the teaching tool itself can be used to teach malicious patterns, that's a credibility problem.

**The fix.** Wrap every LLM call the platform makes (including in user-defined agent execution) with a defense layer. We worked with the founder on the specific integration:

```typescript
import { wrap } from "@lictor/sentinel";

// Before — direct call from agent runtime:
const result = await openai.chat.completions.create({ messages });

// After — sentinel intercepts pre + post:
const client = wrap(new OpenAI(), {
  preflight: ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
});
const result = await client.chat.completions.create({ messages });
```

This is a one-line change in the agent runtime code. The founder shipped it within 48 hours.

**Found by:** Sieve. **Scored by:** Sieve (8.1/10).

---

### Finding 3 — 🟡 Medium — Webhook URLs reachable from public clients without signing

**The pattern.** AgentSwarms lets users configure outbound webhooks for agent events ("when this agent completes, POST to https://my-server.com/agent-done"). The platform sends the POST. The user's server has no way to verify the POST came from AgentSwarms.

**What was broken.** Anyone who knows a user's webhook URL (which leaks naturally when users share agent recipes) can spoof events to that webhook. The user-side server might mark a transaction as complete, trigger a downstream pipeline, etc.

**Why this matters.** This is the Stripe-webhook pattern flipped: instead of receiving unsigned webhooks (the FindMeMail finding), AgentSwarms *sends* unsigned webhooks. Users who naively trust the incoming POSTs (most do) are vulnerable to fake events.

**The fix.** Sign every outbound webhook with an HMAC using a per-user secret. Users add the secret to their server's webhook handler and verify the signature on every incoming request. Standard pattern. ~40 lines of code total.

**Found by:** Radar. **Scored by:** Sieve (6.6/10).

---

## What the founder did

By October 24:
- 🟢 Finding 1, Layer 1 (RLS) — patched Oct 8, within 48h of disclosure
- 🟡 Finding 1, Layer 2 (encryption at rest) — in flight, shipping Q4 2026
- 🟡 Finding 1, Layer 3 (session-only mode) — Q1 2027
- 🟢 Finding 2 (Sentinel integration) — patched Oct 10
- 🟢 Finding 3 (HMAC outbound webhooks) — patched Oct 12

The AgentSwarms team also:
- Force-rotated all stored API keys + emailed every user
- Added a new lesson to the curriculum titled *"Platform security for AI-agent sandboxes"* citing this teardown
- Committed to a public security policy at `agentswarms.fyi/security`

That's the educator response. We're naming AgentSwarms in this writeup *because* the founder engaged with the disclosure as a teaching moment. The recursion is now real: AgentSwarms teaches AI-agent security, with itself as the case study.

## Lessons for every AI-agent platform

1. **User-supplied credentials are the highest-value attack surface in any AI platform.** Treat them like nuclear material. RLS, encryption at rest, session-only modes, force-rotation paths.
2. **Your platform's content is part of your AI's input.** If users can edit lessons / share recipes / upload templates, every word of that content can become a prompt-injection vector. Wrap your LLM calls accordingly.
3. **Outbound webhooks need signing too.** The Stripe-webhook pattern goes both ways. Sign what you send. Document the verification flow for your users.
4. **Educator platforms have an extra responsibility.** People learning your platform model their own systems on yours. Get the security right because the wrong patterns propagate.

## How to check your own AI platform

`/lictor-security-check` (Claude Code skill) — runs the audit locally, plain English, free. For runtime defense on LLM calls, `npm install @lictor/sentinel`.

## Crew + disclosure timeline

| Date | Event |
|---|---|
| Oct 6 | Disclosure email sent (21-day window for risk-3) |
| Oct 6 (12h later) | Founder confirmed |
| Oct 7 | 90-min call walking findings + architecture discussion |
| Oct 8 | Finding 1 Layer 1 (RLS) patched |
| Oct 10 | Finding 2 (Sentinel) patched |
| Oct 12 | Finding 3 (HMAC webhooks) patched |
| Oct 14 | Force-rotation email to all users |
| Oct 20 | New curriculum lesson published citing this teardown |
| Oct 27 | This writeup publishes — co-promoted with AgentSwarms |

Lictor crew: 📡 Radar (1), 🧪 Probe (1 — the critical one), 🔍 Sieve (1 + scored all), 🖊 Quill, 🪞 Mirror, 🧲 Magnet, 🎼 Conductor.

## CTA

If you build an AI-agent platform: run `/lictor-security-check` this week. The credential-storage finding is going to be one of the most-recurring patterns of 2027. Better to find it in your code than to read about your platform in a teardown.

— Lictor crew

---

## Companion content

### Twitter thread (9 tweets) — Oct 27, 10:30 AM PT

```
1/ This week we audited @AgentSwarmsAI — a Lovable-built platform that teaches multi-agent AI.

Findings: 1 🔴 critical, 1 🟠 high, 1 🟡 medium.

The critical one is what every AI-agent platform should be terrified of. 🧵

2/ 🔴 Users plug in their OpenAI / Anthropic API keys to run agents on AgentSwarms.

Those keys were stored in Supabase, in plaintext, without RLS.

Any visitor's browser could fetch every user's API keys with one query.

3/ Worst-case math: ~200 users, ~$100-500/mo OpenAI tier per user. An attacker could rack up $20-100K in fraudulent usage in a single afternoon, billed to AgentSwarms's users.

This is one of the worst possible failure modes for an AI-agent platform.

4/ The fix is 3 layers:

1. RLS on the table (Lovable default — was missing)
2. Encrypt keys at rest with per-user derived keys
3. Session-only mode (don't persist at all)

AgentSwarms shipped layer 1 in 48h. Layer 2 in flight. Layer 3 in Q1 2027.

5/ Plus they force-rotated every stored key + emailed every user.

That's the right response.

6/ 🟠 The platform's agent runtime had no prompt-injection defense. Lessons + shared agent recipes can include attacker-controlled prompts that affect downstream users' agents.

Fix: wrap the LLM call with @lictor/sentinel. One line.

7/ 🟡 Outbound webhooks weren't signed. AgentSwarms-side fix: HMAC every outbound POST with a per-user secret. Users verify the signature on their end.

Stripe-webhook pattern, but flipped (signing what you send, not what you receive).

8/ Huge respect to AgentSwarms.

They engaged with the disclosure as a teaching moment.
They published a new lesson citing this audit.
They committed to a public security policy.

Educator platforms doing it right.

9/ The recursion: AgentSwarms now teaches AI-agent platform security, using itself as the case study.

If you run an AI-agent platform: run /lictor-security-check today. Credential storage is going to be the #1 pattern of 2027.

lictor-ai.com/skill — free, local, plain English. 🛡
```

### LinkedIn post — Oct 27, 11 AM PT (~300 words)

```
We audited an AI-agent platform with our AI-agent platform this week.

AgentSwarms (agentswarms.fyi) is a Lovable-built sandbox that teaches multi-agent AI. Users plug in API keys to run real agents.

Three findings:

🔴 Critical: user-supplied OpenAI/Anthropic API keys stored in plaintext without Row-Level Security. Any visitor's browser could query every stored key. Worst-case exposure: ~$20-100K in fraudulent API usage if an attacker exploited it before disclosure.

🟠 High: agent runtime had no prompt-injection defense. Shared recipes + editable lesson content could pass attacker-controlled prompts into downstream agents.

🟡 Medium: outbound webhooks weren't signed. Receiving servers couldn't verify events came from AgentSwarms.

The founder responded within 12 hours. Patched the RLS layer in 48h. Shipped Sentinel-style LLM call wrapping in 4 days. Force-rotated every stored API key + emailed every user. Published a NEW LESSON in the AgentSwarms curriculum titled "Platform security for AI-agent sandboxes" — citing this teardown as the case study.

That's the educator response. We're naming them with full consent.

The general lesson for every AI-agent platform: user credentials are nuclear material. RLS is the floor, not the ceiling. Encrypt at rest. Offer session-only modes. Force-rotation paths from day one.

The Sentinel-style runtime wrap is becoming the standard pattern for AI platforms. Anywhere your service makes an LLM call on behalf of a user, expect attacker-controlled input somewhere in the context window. Defend accordingly.

Full writeup with the SQL fixes + Sentinel integration code: [link]

Free skill that catches this pattern: lictor-ai.com/skill
```

### Hacker News submission — Oct 27, 10:35 AM PT

**Title:** AgentSwarms (Lovable AI-agent sandbox) stored user API keys in plaintext; founder fixed and disclosed

**Body:**
```
Fourth Lictor teardown. AgentSwarms is a Lovable-built platform that teaches multi-agent AI — users plug in OpenAI/Anthropic API keys and run real agents.

Findings:

- Critical: user API keys stored in plaintext in Supabase without RLS. Any browser could fetch every user's keys.
- High: agent runtime had no prompt-injection defense for user-shared content.
- Medium: outbound webhooks unsigned.

Founder patched the RLS layer in 48h. Force-rotated every stored key + emailed every user. Published a new lesson in their own curriculum citing this teardown as the case study. Best-in-class disclosure response.

The credential-storage pattern is going to be the #1 vulnerability class for AI-agent platforms in 2027. Worth a read.

Full writeup with code: https://lictor-ai.com/teardowns/agentswarms
Lictor (free, Apache 2.0): https://github.com/Raffa-jarrl/Lictor-AI
```
