# Lictor × [PLATFORM] — partnership proposal

> **Document type:** Strategic memo + per-platform addendums
> **Audience:** [PLATFORM] founders, head of product, head of security (whichever exists)
> **Sender of record:** Raffa + Lictor LLC (pending — see legal-structure-memo.md)
> **Drafted:** 2026-05-15 · For Q1 2027 outreach per operation-triumph-expanded.md
> **Status:** Template + per-platform addendums (Lovable, Bolt.new, v0). Master version below; addendums at the bottom.

---

## 1. Cover + TL;DR

Lictor is the open-source security crew for apps people build with AI assistants. Apache 2.0, runs inside Claude Code, audits projects in plain English. By Q1 2027 we have 15k+ GitHub stars, 8k+ weekly active users on the audit skill, and a public archive of 12+ teardowns — most of which audited apps shipped on [PLATFORM]. We'd like to do that work *with* you instead of *adjacent to* you.

**Three bullets:**

- **What we propose:** Lictor's audit engine, available natively inside [PLATFORM] — in whatever shape fits your editor, deploy pipeline, or docs. Four integration options laid out in §4.
- **What [PLATFORM] gets:** your users ship safer code by default. You get credible security messaging without standing up a security team. Co-branded marketing for 12 months. No engineering cost on the OSS core.
- **What Lictor gets:** distribution to [PLATFORM]'s user base — the audience Lictor was built for. We're already auditing your users' apps. The partnership is just doing it together.

This is a strategic memo, not a contract. We've tried to be honest about what we can commit to (and what we can't — especially around exclusivity, §5). The intent is a 30-minute intro call, not a signature.

---

## 2. Why now

Three things are true at the same time in Q1 2027:

**The vulnerability rate is established.** Independent reports from SupaExplorer, Wiz, and Snyk's own Q4 2026 research put the AI-generated-code vulnerability rate at 40–62%, with 91.5% of vibe-coded apps shipping at least one AI-hallucination flaw. This is no longer contested. It's the table the conversation now sits on.

**The category moment already happened.** The February 2026 incident on a popular AI app-builder — 170+ apps, ~18,000 users exposed in one week — was the moment the industry stopped calling this a "developer hygiene" problem and started calling it a *category*. We don't frame that incident as anyone's failure. We frame it as the moment the surrounding ecosystem realized the gap exists. Every platform builder we've spoken to since agrees: the gap is real and it's not closing on its own.

**The incumbents have moved.** Snyk Agent Security launched March 2026. Aikido expanded their AI surface in Q4. Terra raised $30M Series A. Armadin closed $190M with Kevin Mandia. These are enterprise-priced solutions with five-developer-team assumptions and CISO-dialect interfaces. They will not show up natively inside [PLATFORM]'s editor. They will sell into [PLATFORM]'s customers' security teams *after* the apps are built and deployed.

The platform-native angle is open. The audience — solo founders, designer-builders, indie hackers shipping from your editor — is the audience Lictor was built for. The distribution point with the most leverage isn't a Snyk dashboard. It's the IDE the code was generated in. That's [PLATFORM]'s surface, not Snyk's. We'd like to put the right security layer there before the incumbents figure out how.

---

## 3. What Lictor brings

A working product, a working voice, and a working audience. Specifically:

- **The 7-check audit engine.** Tuned for the patterns that matter on [PLATFORM]'s stack — leaked credentials in client bundles, missing or misconfigured RLS, unsigned webhooks, exposed admin routes, unguarded AI surfaces, prompt-injection vectors, and source-map disclosures. The engine is configurable; we can add [PLATFORM]-specific checks (see §4 options A and D) without forking the OSS core.

- **The 11-agent crew.** Transparent, named, open-source. Each agent has a defined job and a public spec. Users see *who* found *what* — not a black-box score. This is the differentiator the enterprise tools structurally can't copy without rebuilding their UX.

- **The plain-English voice.** No "information disclosure vulnerability." Just "anyone with the URL can read your customer list." Your designer-founder users can read a Lictor report without a translator. This matters more than the engine does — it's what makes the audit *useful* rather than *generated*.

- **12+ published teardowns.** Real apps, real findings, public archive. Specific examples include Pitchtank (Oct 6, 2026 launch teardown — Lovable + Supabase, RLS gaps + anon key in bundle), Tymora (Lovable + OAuth-token exposure), FindMeMail (Lovable + B2B email database, anon-key queryable), AgentSwarms (Lovable + user-supplied API keys in plaintext). Several more by Q1 2027. The archive establishes that we audit what we ship.

- **Apache 2.0.** No IP entanglement. No licensing fees on the core. No lock-in. [PLATFORM] can integrate today and walk away in two years without owing us anything. That asymmetry is intentional — we'd rather earn the relationship than contract it.

- **A working product surface.** Pick what fits:
  - Claude Code skill suite (`/lictor-security-check`, `/lictor-explain`, `/lictor-fix-it`, `/lictor-rotate`)
  - Lictor Shield — Chrome extension that audits any deployed AI-built site
  - Lictor Sentinel — npm + PyPI SDK that wraps OpenAI/Anthropic clients at runtime
  - Lictor Guardian — hosted dashboard for AI incident timeline + audit-log export
  - SDK / programmatic API — the engine is callable from any deploy hook, CI step, or platform-side service

We don't need [PLATFORM] to adopt all of these. We need [PLATFORM] to pick the one that fits and let us build the integration with you.

---

## 4. The integration shapes — 4 options

We're not pre-picking. The right option depends on [PLATFORM]'s editor surface, engineering capacity, and how visible you want the partnership to be. Here are the four shapes, with what each side commits, timeline, and whether they exclude each other.

### Option A — "Lictor inside [PLATFORM]"

An embedded audit button in [PLATFORM]'s editor. User clicks "audit my project" → Lictor's engine runs (server-side or via the user's connected Claude Code session) → findings render in-line in your UI.

- **[PLATFORM] commits:** A UI surface (button + results panel), the API access we need to read project files, design review on how findings render.
- **Lictor commits:** The engine, the rendering components (React or framework-agnostic), [PLATFORM]-tuned checks, ongoing maintenance of the integration.
- **Timeline:** 6–10 weeks from kickoff to public beta.
- **Mutual exclusivity:** Not exclusive on Lictor's side (we're OSS). [PLATFORM] can choose to make the button *their* exclusive integration; we'd help market that.

### Option B — "Audit on deploy"

Lictor's audit runs automatically on every deploy from [PLATFORM]. Findings are emailed to the project owner with a link to the report. Optionally surfaces a badge on the published app's URL ("audited by Lictor — N findings").

- **[PLATFORM] commits:** A deploy-hook integration point, a way for users to opt in (or out, depending on your stance), the email-delivery flow.
- **Lictor commits:** The audit runner (containerized, runnable in your deploy pipeline), the report-rendering, the email templates, SLAs on audit completion time (target < 90 seconds per project).
- **Timeline:** 4–6 weeks. Lowest user friction; medium platform engineering effort.
- **Mutual exclusivity:** Not exclusive. Compatible with Option A or C.

### Option C — "Lictor as a recommended tool"

[PLATFORM] adds Lictor to your official "tools" / "integrations" / "extensions" page. A link in your docs. A mention in your onboarding. No code-level integration.

- **[PLATFORM] commits:** A page listing, a docs mention, a launch-week tweet, an optional email to your active user base.
- **Lictor commits:** Co-marketing collateral, a [PLATFORM]-branded landing page on lictorai.com, a dedicated "audit my [PLATFORM] app" skill variant.
- **Timeline:** 2 weeks. Lowest effort on both sides; good first step if you want to test the partnership signal before committing to engineering.
- **Mutual exclusivity:** Not exclusive. A natural Phase 0 before Option A or B.

### Option D — "Joint security feature"

[PLATFORM] and Lictor co-build a named feature. Example: "Secure Mode" — a toggle that runs Lictor on every save and surfaces findings as you build, not just at deploy. Co-branded. Mutual credit. Lictor's engine, [PLATFORM]'s UX, shared roadmap.

- **[PLATFORM] commits:** UX design, the feature surface, joint engineering review, co-marketing budget, sustained roadmap collaboration.
- **Lictor commits:** Engine, custom checks, dedicated engineering pairing, exclusive feature work (the specific "Secure Mode" surface is exclusive to [PLATFORM] for 12 months — see §5).
- **Timeline:** 10–16 weeks. Highest engineering effort on both sides; highest leverage; highest brand-equity build.
- **Mutual exclusivity:** *The named feature* is exclusive to [PLATFORM] for 12 months. The underlying OSS engine is not.

Our preference, if pressed: Option A as Phase 1, Option D as Phase 2 after 6 months of integration data. Option C as a no-regret starting move while we scope the rest.

---

## 5. The exclusivity question

We want to be honest about this up front because it's the most common reason platform partnerships stall.

**What we can't commit to:** OSS-core platform-exclusivity. Lictor is Apache 2.0. We cannot legally promise that the audit engine will only ever run inside [PLATFORM]. Anyone — including [PLATFORM]'s competitors — can fork Lictor and integrate it themselves. That's the deal we made with the open-source license, and it's load-bearing for the credibility that makes Lictor valuable to you in the first place.

**What we can commit to:**

- **[PLATFORM] is the first.** A signed deep integration with [PLATFORM] means [PLATFORM] is the first platform we integrate with at the depth of Option A or D. Other platforms come later or at shallower depth (Option C-level mentions).
- **12-month marketing exclusivity.** Co-promotion, joint content, conference talks, the comparison piece ("Snyk vs Lictor on [PLATFORM]") — all branded around [PLATFORM] for 12 months. We won't co-promote with [PLATFORM]'s direct competitors during that window.
- **[PLATFORM]-tuned checks.** Custom audit checks tuned specifically for [PLATFORM]'s generation patterns. Those checks live in the OSS core (transparency requirement) but the *naming, framing, and documentation* references [PLATFORM] explicitly.
- **Named-feature exclusivity (Option D only).** If we co-build "Secure Mode" or equivalent, that specific named feature is exclusive to [PLATFORM] for 12 months.

**The acquirer-perception angle.** A deep [PLATFORM] integration is a positive signal to any future acquirer of Lictor — it demonstrates distribution traction, partnership-execution capability, and platform-native fit. We'd rather be honest about this than pretend it isn't relevant. If [PLATFORM] later wants to acquire Lictor outright (§6), the existing integration shortens the diligence cycle materially.

---

## 6. The commercial terms

We want this partnership to be cheap to start and easy to grow. Specifically:

**Lictor charges $0 to [PLATFORM] for the OSS-core integration.** The Apache 2.0 engine, the standard rendering components, the [PLATFORM]-tuned check additions, and ongoing maintenance of the integration are free of charge. Forever. This isn't a promotional window — it's the deal.

**Optional paid layer: white-label and custom features.** If [PLATFORM] wants white-labeled UI components (Lictor branding removed, replaced with yours), private checks, dedicated infrastructure, or a custom feature work commitment, Lictor charges an annual partnership fee in the **$50–150k/year** range, scaled to integration depth. Option A or D at the upper end; bespoke work negotiated separately.

**Revenue share on Teams subscriptions originating from [PLATFORM]'s user base.** Lictor for Teams is $19/mo flat-rate. For subscribers acquired through the [PLATFORM] integration (tracked via referrer or signup attribution):

- **First 12 months:** 30% to Lictor, 70% to [PLATFORM]. Favoring [PLATFORM] to align incentives early.
- **Months 13+:** 50% / 50%. Balanced once the partnership has its own gravity.

**Acquisition fast-path.** If [PLATFORM] later wants to acquire Lictor outright, the partnership agreement includes a **12-month right-of-first-refusal at fair-market value** — third-party valuation, agreed-on methodology, no carve-outs. This is intentionally non-coercive. It means [PLATFORM] has the option but not the obligation, and Lictor isn't forced into a sale.

**What's deliberately *not* in the commercial terms:**
- No exclusivity on the OSS core (§5 covers why).
- No revenue minimums on [PLATFORM]'s side.
- No SLA penalties on the free integration.
- No data-sharing requirements that compromise user privacy. Lictor is local-first; we don't want your users' source code on our servers any more than you want it on Snyk's.

**Caveat:** Lictor LLC needs to legally exist before any of this is signable. See `docs/launch/legal-structure-memo.md`. The commercial terms above are illustrative until then; we'd execute them through the incorporated entity once formed. Raffa should pressure-test the entire §6 with counsel before sending.

---

## 7. What success looks like

Concrete metrics, not press-release adjectives.

**6 months in (mid-pilot):**
- 10% of [PLATFORM]'s active monthly apps have run Lictor audit at least once.
- Average time from project creation → first audit < 14 days.
- A published joint blog post on [PLATFORM]'s domain announcing the integration, with a co-branded demo.
- One published joint teardown — a famous [PLATFORM]-built app, audited by Lictor, with [PLATFORM]'s blessing and the founder's consent. (This is the trust-signal artifact. If we can land one, the rest becomes easier.)

**12 months in (full rollout):**
- 25% of [PLATFORM]'s active monthly apps audited via Lictor.
- A named comparison piece: "Snyk vs. Lictor on [PLATFORM]" — written by us, co-promoted by [PLATFORM], with concrete findings per tool on a representative project sample.
- A joint conference talk — AI Engineer Summit (March 2027), RSAC 2027, or DEF CON 2027 — on "platform-native security for AI-built apps." Raffa and a [PLATFORM] representative on stage together.
- The integration is named in [PLATFORM]'s sales material as a differentiator vs. competitors that don't have it.
- At least 50 paying Lictor Teams subscribers attributable to [PLATFORM] (modest, but proves the rev-share mechanic).

**What we're not promising:**
- That Lictor's audits will catch every vulnerability. (No tool does. We'll be honest about that publicly — it's part of the brand.)
- That the integration will be Lictor's only growth vector. (It won't. But it's the highest-leverage one for [PLATFORM].)
- That [PLATFORM] can or should rely on Lictor for compliance evidence. (Guardian helps. But compliance is a separate workstream and we won't oversell it.)

---

## 8. What we'd need from [PLATFORM]

Five things, in priority order:

1. **An engineering contact for the integration.** One named person on your side who owns the integration's technical scope. Doesn't need to be senior — needs to be empowered to make scope calls without escalating every decision.

2. **API access.** Existing public APIs are fine. We don't need privileged access. We don't need access to anyone's source code at rest. We do need a documented way to read a user's project files at audit time, with the user's consent.

3. **Co-marketing commitment.** Specifically: one blog post on [PLATFORM]'s domain announcing the integration (we'll co-draft), one email to your user base (we'll co-draft), and an integration mention in your docs. Optional but high-value: a tweet from [PLATFORM]'s founder.

4. **A named champion at [PLATFORM].** Someone — likely a co-founder or head of product — who owns the *relationship* internally. Different person from the engineering contact. This is the person we email when the partnership needs a strategic call, not a technical one.

5. **Pre-launch coordination.** Lictor's roadmap will shift; [PLATFORM]'s roadmap will shift. We'd ask for a standing monthly 30-minute sync between the named champion and Raffa for the first 6 months to keep both sides aligned.

What we are explicitly *not* asking for: budget commitments, headcount commitments, equity, board seats, or any kind of structural entanglement that constrains [PLATFORM]'s independence.

---

## 9. Next steps

Six steps. Each one has a clear "stop here if it's not working" exit.

1. **30-minute intro call** — Raffa + [PLATFORM]'s named champion (or whoever takes the meeting first). No commitments. Goal: do the two sides like each other enough to keep talking?
2. **60-minute technical discovery** — Raffa + [PLATFORM]'s engineering contact. Goal: which integration option (A/B/C/D, §4) fits [PLATFORM]'s editor surface? Stop here if no option fits.
3. **Joint scoping document** — 1 week. We draft, [PLATFORM] reviews. Goal: written agreement on scope, timeline, and what success looks like in §7 terms.
4. **Pilot integration build** — 4–8 weeks depending on option. Lictor builds the integration; [PLATFORM] reviews and merges.
5. **Pilot launch with one [PLATFORM] user** — A real project, with the user's consent, as the proof. Joint blog post. Single tweet.
6. **Full rollout** — If pilot succeeds (defined in the scoping document): full launch to [PLATFORM]'s user base, co-marketing window opens, 12-month exclusivity clock starts.

If you want to skip steps 1–2 and go straight to scoping — also fine. Tell us which option you want and we'll send a draft scoping document inside 5 business days.

---

## 10. About Lictor

Lictor is the security crew for apps people build with AI. Eleven specialist AI agents audit your project, name what's wrong, and tell you exactly how to fix it — in plain English, no compliance dialect required. Free, open source under Apache 2.0, runs locally inside Claude Code. We exist because 40–62% of AI-generated code ships with security vulnerabilities, eight million people now build software with AI assistants every week, and the existing security tools weren't built for them. Built solo by a 20-year cybersecurity engineer; growing into a community-supported open-source project with a public agent crew, a weekly teardown archive, and a roadmap voted on by users. Public launch: October 6, 2026. By Q1 2027: 15k+ GitHub stars, 8k+ weekly active skill users, 12+ published teardowns. github.com/lictor-ai · lictorai.com.

---

# Per-platform addendums

The master version above is the document we send. Each addendum below is appended to the master before sending to that specific platform — replacing the `[PLATFORM]` token throughout and adding the platform-specific frame at the top of §2 and the bottom of §4.

---

## Addendum A — Lovable specifically

**Replace `[PLATFORM]` with `Lovable` throughout. Add the following frame between §2 and §3:**

> **Why Lovable specifically, why now.** Lovable was the most-audited platform in Lictor's first 12 teardowns — Pitchtank, Tymora, FindMeMail, AgentSwarms, and at least four others not yet published. That isn't a coincidence. Lovable's Supabase-default stack creates a specific class of platform-typical gaps: missing or misconfigured RLS on the tables Lovable's generation scaffolds, Supabase anon key in the JS bundle, unsigned webhook endpoints, env-var exposure through Vite's compile-time inlining. These are not user errors — they're generation patterns. Which means they're fixable at the platform layer with the right pre-deploy guardrail.
>
> The February 2026 incident — 170+ apps, ~18,000 users — was, candidly, the moment the industry started calling vibe-coded-app security a category. The narrative around Lovable since then has been mixed: the platform is loved by builders and questioned by security press in the same week. The platform partnership we're proposing flips that narrative. **"Lovable was the first vibe-coding platform to integrate AI security natively."** Not as an apology. As a category-defining move that no competitor (Bolt, v0, Replit) can claim without doing the same partnership work.
>
> Lictor's audit archive is, in effect, a public dataset of Lovable's most-common patterns. We'd rather give that dataset to Lovable directly — as integrated guardrails — than keep publishing it as teardowns.
>
> **Concrete first-90-days plan, if Option A:** an "Audit my project" button in the Lovable editor, scoped to the 7 checks most-common in our Lovable teardowns. Co-launched with a joint post: "Why Lovable now ships with built-in security audits." Lovable owns the narrative; Lictor owns the engine. Done in 8 weeks if both sides commit by Feb 2027.

---

## Addendum B — Bolt.new (StackBlitz) specifically

**Replace `[PLATFORM]` with `Bolt.new` throughout (or `Bolt` where it reads better). Add the following frame between §2 and §3:**

> **Why Bolt specifically, why now.** Bolt is competing with Lovable and v0 for the next million builders. The differentiator isn't generation quality at this point — all three platforms generate working code most of the time. The differentiator is *which platform makes shipping safely the easier path.* The platform that makes "secure by default" feel native — not a paywall, not a separate tool, not a checklist — wins those builders for the long arc.
>
> Bolt's stack — Vite + Supabase/Drizzle + Netlify, with Stackblitz's WebContainer execution model — has its own pattern set distinct from Lovable's. Specifically: env-var prefix exposure (Vite's `VITE_` prefix inlines variables into the bundle in ways that surprise non-Vite-native builders), source-map publishing in production, unsigned webhook patterns common to the Netlify Functions default, and the WebContainer's own security surface for AI-generated server-side code. Lictor has not yet published a Bolt-specific teardown — by design — because we'd rather start by partnering than by critiquing.
>
> The pitch angle for Bolt is *forward-positioned*, not reactive. Bolt has had less of the security drama Lovable absorbed in 2026, which gives Bolt the option of being the platform that *prevented* the next category-defining incident instead of the one that *experienced* it. That's a marketing position no competitor can take by waiting. The platform-native security integration is how Bolt claims it.
>
> **Concrete first-90-days plan, if Option B:** an opt-in "audit on deploy" hook for every Bolt project that ships to Netlify. Findings emailed; optional public badge on the live URL. Co-launched with a joint post on StackBlitz's blog: "Every Bolt deploy now includes a security audit." Done in 5 weeks if Netlify integration is approved.

---

## Addendum C — v0 (Vercel) specifically

**Replace `[PLATFORM]` with `v0` throughout (or `Vercel's v0` where the disambiguation matters). Add the following frame between §2 and §3:**

> **Why v0 specifically, why now.** Vercel already has a serious security posture — at the infrastructure layer. Edge runtime hardening, deployment-level secret management, the Vercel Firewall, Vercel's existing security team and CISO function. None of that is in question. What Vercel *doesn't* have, by design, is an AI-built-app-specific audit layer that runs against the code v0 generates. Lictor fills that gap *without competing* with any existing piece of Vercel's security suite.
>
> v0's pattern set is distinct again from Lovable's and Bolt's. Next.js 15+ Server Actions create a class of authorization gaps that don't exist in client-only frameworks (Server Action callable without auth, accidentally exposing privileged operations to any client). Caching directives — `'use cache'`, `cacheLife`, the recent Next.js cache-poisoning research — create a class of side-channel exposures specific to Next.js. Image-optimization endpoints and route-handler patterns have their own typical gaps. These are the patterns Lictor's v0-tuned check pack would catch — and they sit on top of Vercel's existing security primitives rather than next to them.
>
> The pitch angle for v0 is *complementary, not competitive.* "Vercel's infrastructure security + Lictor's AI-built-app code audit = the most complete security story in the v0 category." Vercel's security team doesn't need to build the AI-code-audit piece in-house — that's six months of work and a separate brand voice (Lictor's plain-English voice is structurally hard for an infrastructure company to replicate without alienating its enterprise audience). Lictor builds the layer; Vercel ships it as a v0 native feature.
>
> **Concrete first-90-days plan, if Option A:** an "Audit" tab in the v0 chat interface, triggered alongside or after generation. Scoped to v0's Next.js patterns. Co-launched with a joint post on Vercel's blog: "v0 now includes built-in security review for every project." Done in 8–12 weeks. The Vercel marketing reach is the highest of the three platforms — this is the partnership with the largest upside if executed well.

---

> **Document end.** Master version + 3 addendums. Pressure-test before sending — see send-checklist below.

## Pre-send checklist

Before this goes to any platform:

- [ ] Lictor LLC is legally incorporated (see `legal-structure-memo.md`). The commercial terms in §6 are not signable until then.
- [ ] §6 reviewed by counsel — especially the revenue-share structure and the right-of-first-refusal language.
- [ ] §5 exclusivity language reviewed against the Apache 2.0 license (specifically: that the "12-month marketing exclusivity" doesn't accidentally constrain the OSS core's redistribution).
- [ ] Each addendum's "concrete first-90-days plan" cross-checked against Lictor's actual Q1 2027 engineering capacity.
- [ ] Pitchtank, Tymora, FindMeMail, AgentSwarms references in §3 and Addendum A — confirm each teardown is actually published by the time of send.
- [ ] Send to all three platforms within the same 2-week window — staggering creates information asymmetry across platforms that can leak.
- [ ] Each platform addendum reviewed by someone who knows that platform's culture (the Lovable founder voice, the StackBlitz formality, the Vercel brand tone are all different — addendums should read native to each).
