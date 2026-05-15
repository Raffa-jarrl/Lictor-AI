# The 7 patterns we catch that the other tools miss

**Published:** lictor-ai.com/blog/7-patterns — Tuesday Oct 6, 2026
**Author:** The Lictor crew
**Audience:** Builders shipping from Lovable / Bolt / v0 / Cursor / Replit, plus engineering folks who already use Snyk or Semgrep and want to know what Lictor actually adds.

---

There's a question we keep getting from people who already pay for a security tool: *"What does Lictor catch that Snyk doesn't?"*

It's a fair question. Snyk is a real product. Semgrep is a real product. Trivy is a real product. We're not here to tell you to throw them out. We use Snyk Open Source on our own dependency tree.

But the honest answer is: there are specific bug shapes that AI assistants ship into AI-built apps that the generic tools were not designed to look for. Not because those tools are bad — because the bugs didn't exist in 2018 when the rules were written.

Seven of those patterns are below. Each one shows up in audits we've run on Lovable / Bolt / v0 / Cursor / Replit projects. Each one has a specific reason the generic tool misses it. Each one is one of the seven checks `/lictor-security-check` runs by default.

If you spot your own code in any of these, run the audit on your project tonight — it takes about a minute and the report is plain English, no signup. Skill is at github.com/Raffa-jarrl/Lictor-AI.

---

## 1. Supabase service-role key in the client JS bundle

This is the canonical Lovable failure mode. It's the one that took down 18,000 users across 170+ databases in the February 2026 incident, and we still see it every week.

**What you wrote (or what the AI wrote for you):**

```ts
// app/lib/supabase.ts
import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,  // ← used here
);
```

And then somewhere in `app/page.tsx`:

```ts
"use client";
import { supabase } from "@/lib/supabase";

export default function Page() {
  // ...
}
```

**Why this is broken:** The service-role key bypasses every Row Level Security policy on every table. It's the master key. Once it's in a client component, Next.js bundles it into the JavaScript that ships to every visitor's browser. Anyone who opens devtools and searches the bundle for "service_role" finds it. From there they have full read and write access to every row in your database. That's the whole vault.

**Why the other tools miss it:** Generic SAST sees `process.env.SUPABASE_SERVICE_ROLE_KEY` and recognizes the pattern as "environment variable read." Environment variables are normal. The actual bug is the chain — the key gets read by a module that gets imported by a client component that gets bundled and shipped to the browser. Tracking that import chain across the Next.js compile boundary is not what Snyk's SCA scanner does, and it's not what Semgrep's default JavaScript ruleset does. They look at the file. They don't model the bundler.

**How Lictor catches it:** Our Radar agent walks the import graph from every file that has the `"use client"` directive or sits inside an `app/` route segment that compiles client-side. If any of those files transitively import a module that reads a known service-key environment variable, that's a critical finding. The plain-English message we surface:

> 🔴 CRITICAL · Your Supabase service-role key is bundled into the JavaScript that ships to every visitor's browser. Anyone with the URL has full database write access. Fix in `app/lib/supabase.ts` line 5 — use the anon key on the client, move the service-role key to a server-only file.

---

## 2. Missing RLS on Supabase tables

This is the cousin of #1, and it's almost always present when #1 is present. Sometimes it's the only failure — the keys are fine but the database is open anyway.

**What you wrote (or didn't write):**

```sql
-- This is what the AI assistant scaffolded:
create table public.invoices (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid references auth.users(id),
  amount      numeric not null,
  description text,
  created_at  timestamptz default now()
);

-- This is what's missing:
-- alter table public.invoices enable row level security;
-- create policy "Users can read own invoices"
--   on public.invoices for select
--   using (auth.uid() = user_id);
```

**Why this is broken:** Without an RLS policy, the table is a free-for-all to anyone who has the anon key. The anon key is in your client bundle — by design, that's where it's supposed to be. So an attacker doesn't need to break in. They just open your site, copy the anon key, and `select * from invoices` from the browser console. Every invoice for every customer.

**Why the other tools miss it:** Snyk doesn't connect to your Supabase project. Trivy doesn't read your `supabase/migrations/` directory and reason about the policies that should be there. Semgrep can match on SQL files, but its default ruleset doesn't know that "table referencing `auth.users` without a corresponding `enable row level security` statement" is a bug pattern. The bug isn't in the code — it's in the *absence* of code.

**How Lictor catches it:** We look at every table definition in `supabase/migrations/` and check three things. One, does it reference `auth.users` via a foreign key. Two, is there an `alter table … enable row level security` statement anywhere in the migration history for that table. Three, is there at least one `create policy` for the table. If a table references user data and either RLS is off or there's zero policy on it, that's a high or critical finding depending on what the columns are. Plain English:

> 🔴 CRITICAL · The `invoices` table has a `user_id` column but no Row Level Security policy. Anyone with your anon key (which is in every page you ship) can read every invoice for every user. Fix in `supabase/migrations/20260815_invoices.sql` — add the two lines below.

---

## 3. Hallucinated npm packages

This one is a 2026 attack surface that didn't exist in 2023. The AI suggests a package. The package doesn't exist. Or — increasingly — the package exists, but only because an attacker registered the name after the AI started suggesting it.

**What you wrote:**

```ts
// Suggested by Cursor:
import { withAuth } from "next-auth-supabase-pro";

export default withAuth(async function handler(req, res) {
  // ...
});
```

**Why this is broken:** `next-auth-supabase-pro` is not a real package maintained by a real person. There are three ways this goes wrong. (a) The package doesn't exist at all and your `npm install` fails — annoying but harmless. (b) Someone has registered the typo-squat and ships malicious code that runs at `postinstall` time. (c) The package exists, is fine, but it doesn't do what the AI thinks it does, and you've now wired your auth gate to something that returns `true` for everyone.

The shape that scares us is (b). Researchers at Lasso Security documented in late 2025 that something like 19% of AI-suggested packages don't exist, and that registering those names is now a known supply-chain attack vector. Attackers have automation that watches Cursor / Claude Code chat logs leak onto Twitter, sees a suggested package name that doesn't exist, registers it within minutes, and waits for someone to run `npm install`.

**Why the other tools miss it:** Snyk Open Source is excellent at finding known CVEs in packages that exist. It's looking up what's installed against a vulnerability database. If the package was registered last Tuesday and ships malicious code, there's no CVE yet. Semgrep doesn't validate that the package in your `import` statement matches what the AI thought it was suggesting. The bug isn't a known vulnerability. It's a hallucination that an attacker turned into a real package faster than the defenders noticed.

**How Lictor catches it:** Our Radar agent reads every `import` and `require` statement in your project. For each external package, it checks three things. One, does the package exist on the npm registry. Two, was it registered more than 90 days ago — recent registrations are higher risk. Three, does the package name match any of the known LLM-hallucination patterns (suspiciously specific compound names like `next-auth-supabase-pro`, version-numbered names like `react-helmet-v2-modern`, "official" or "pro" suffixes on otherwise-unbranded packages). Anything that fails one of the three gets flagged. Plain English:

> 🟠 HIGH · You're importing `next-auth-supabase-pro` in `pages/api/protected.ts` line 1. This package was registered on npm 11 days ago, by an account with no other packages. The shape of the name matches our hallucination pattern. Verify the package is what the AI thought it was before you ship.

---

## 4. Frontend-only auth check

Every audit we've ever run on a Lovable or Bolt project surfaces at least one of these. The AI assistant scaffolds an admin page. The AI assistant adds an "auth gate." The gate is a JavaScript `if` statement in a component that ships to every visitor.

**What you wrote:**

```tsx
// app/admin/page.tsx
"use client";
import { useUser } from "@/lib/auth";

export default function AdminPage() {
  const user = useUser();

  if (!user?.isAdmin) {
    return <div>Not authorized.</div>;
  }

  return (
    <div>
      <h1>Admin dashboard</h1>
      <UserList />
      <RevenueChart />
      <DeleteEverythingButton />
    </div>
  );
}
```

**Why this is broken:** That `if (!user?.isAdmin)` check happens in the user's browser, not on your server. The entire component — including `UserList`, `RevenueChart`, and the delete button — ships to every visitor as part of the JavaScript bundle. A non-admin visitor can override `user.isAdmin` in devtools and render the admin UI in their own browser. More importantly, any data those child components fetch is fetched with the visitor's session, so unless the API routes also check auth (see pattern #2), the visitor walks away with everything.

**Why the other tools miss it:** Generic SAST sees `if (!user?.isAdmin)` and recognizes it as an auth check. From a syntactic perspective, the code does check authorization. The bug is that the check ships to the client and the check is the only one. Semgrep can match on this pattern if you write a custom rule for your specific stack, but the default ruleset doesn't. Snyk's SAST is tuned for the Java/Node enterprise codebases where this anti-pattern is rarer. Here in vibe-coded-Next.js land it's everywhere.

**How Lictor catches it:** We look for the pair. Pattern A: an `if (user?.isAdmin)` or similar admin-flavored check inside a file marked `"use client"` or inside an `app/` route segment that compiles client-side. Pattern B: zero corresponding admin check on the API routes that page calls. When both A and B are present, that's a critical finding. We don't flag A by itself, because plenty of pages have a client-side check *plus* a server-side check and that's fine. Plain English:

> 🔴 CRITICAL · Your admin gate in `app/admin/page.tsx` line 7 runs in the user's browser. The whole admin UI ships to every visitor. The API routes it calls (`/api/users`, `/api/revenue`) also don't check `isAdmin` on the server. A regular user can view your admin dashboard by overriding one variable in devtools. Fix below — add the same check to each API route.

---

## 5. Unsigned Stripe webhooks

If your AI-built app handles money, this is the one that bankrupts you. Stripe is the most common payment integration in Lovable / Bolt / v0 apps, and the LLM-generated boilerplate for webhooks consistently skips signature verification.

**What you wrote:**

```ts
// app/api/webhooks/stripe/route.ts
import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const body = await req.json();

  if (body.type === "checkout.session.completed") {
    await markUserAsPaid(body.data.object.customer_email);
  }

  return NextResponse.json({ received: true });
}
```

**Why this is broken:** That endpoint is on the public internet. Anyone who finds the URL can POST to it. They send `{"type": "checkout.session.completed", "data": {"object": {"customer_email": "attacker@example.com"}}}` and your code dutifully marks them as paid. They get the premium plan. They never gave Stripe a card. You don't know until the month-end reconciliation when paid users outnumber Stripe charges by 3x.

**Why the other tools miss it:** Generic SAST sees an API route handler that parses a JSON body. That's a normal pattern. There's no anti-pattern in the syntax. The bug is the *absence* of a signature check — specifically, the absence of a call to `stripe.webhooks.constructEvent` or equivalent. Semgrep can match for this if you write a rule, but its default ruleset doesn't have one. Trivy doesn't look at application code. Snyk doesn't model webhook signature verification as a category.

**How Lictor catches it:** We look at every API route handler in your project. If the file path matches a webhook pattern (`/webhooks/`, `/api/webhook`, `/api/stripe`, `/api/hooks`, etc.), or if the body of the handler references known webhook event shapes (`checkout.session.completed`, `invoice.paid`, `customer.subscription.created`), we check for a signature verification call before any state mutation. If the verification is missing, that's a critical finding. Plain English:

> 🔴 CRITICAL · Your Stripe webhook at `app/api/webhooks/stripe/route.ts` doesn't verify the signature. Anyone who knows the URL can POST a fake "checkout completed" event and gift themselves the premium plan. Fix below — wrap the body in `stripe.webhooks.constructEvent` with the signing secret from your Stripe dashboard.

---

## 6. Cross-tenant data leakage via Next.js cache

This one is subtle. It's the kind of bug that ships, runs fine for a week, then one Friday afternoon a user opens a support ticket that says "I just logged in and I'm seeing someone else's account."

**What you wrote:**

```ts
// app/dashboard/page.tsx
import { unstable_cache } from "next/cache";
import { cookies } from "next/headers";

const getDashboardData = unstable_cache(
  async (userId: string) => {
    return db.query("select * from dashboard where user_id = $1", [userId]);
  },
  ["dashboard"],   // ← cache key
  { revalidate: 60 },
);

export default async function Dashboard() {
  const userId = cookies().get("user_id")?.value!;
  const data = await getDashboardData(userId);
  return <DashboardView data={data} />;
}
```

**Why this is broken:** The third argument to `unstable_cache` is the cache key. The function takes `userId` as an argument, but the cache key is a static string. Next.js caches the *result* of the first call under the key `"dashboard"` — regardless of which user made it. So user A loads their dashboard. Next.js caches user A's data under `"dashboard"`. Within 60 seconds, user B loads the dashboard. Next.js sees a cached value under `"dashboard"` and serves user A's data to user B.

This is the kind of bug that gets your company on the front page of Hacker News for the wrong reason. It happened to a real Lovable app in March 2026. The teardown is on our blog.

**Why the other tools miss it:** Generic SAST does not model Next.js caching semantics. From the tool's perspective, the code reads a cookie, calls a function, returns the result. All three operations look fine in isolation. The bug requires understanding that `unstable_cache` is a specific Next.js API with specific semantics, and that the third argument is the cache key, and that if the cache key doesn't vary with the function's arguments then the cache is going to collide across users. That's a domain-specific bug pattern. Snyk doesn't have it. Semgrep's default ruleset doesn't have it. We do, because we've audited enough Next.js + Supabase teardowns to recognize the shape.

**How Lictor catches it:** Our Radar agent looks at every call to `unstable_cache`, `cache`, and `React.cache` in the project. For each one, it checks whether any user-scoped variable (anything sourced from `cookies()`, `headers()`, `auth()`, or a session-shaped function call) is used inside the cached function but absent from the cache key argument. If yes, that's a critical finding. Plain English:

> 🔴 CRITICAL · Your dashboard cache in `app/dashboard/page.tsx` line 5 uses the same cache key for every user. Within 60 seconds of one user loading their dashboard, the next user who loads the dashboard sees that user's data. Fix below — include `userId` in the cache key array.

---

## 7. AI agent endpoints with no rate limiting

If your app has an "ask the AI" feature — and most vibe-coded apps now do — there's a route that pipes user input straight to OpenAI or Anthropic. Cursor and Claude Code scaffold these in about four lines. The four lines almost never include rate limiting.

**What you wrote:**

```ts
// app/api/chat/route.ts
import { OpenAI } from "openai";
import { NextResponse } from "next/server";

const client = new OpenAI();

export async function POST(req: Request) {
  const { message } = await req.json();

  const response = await client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: message }],
  });

  return NextResponse.json({ reply: response.choices[0].message.content });
}
```

**Why this is broken:** That endpoint is on the public internet and it costs you money on every call. Anyone — including a bored teenager with a script — can POST to it in a tight loop. GPT-4 is roughly 3 cents per call at the input lengths we see in chat features. A million calls is $30,000 on your OpenAI invoice. We've seen this run for six hours overnight on an unprotected endpoint before the founder woke up to the alert.

Worse, your endpoint doesn't check what the user said before sending it. A motivated attacker can use your endpoint as a free proxy to OpenAI, paid for by you, with your API key, against your terms of service.

**Why the other tools miss it:** Generic SAST sees an API route that calls an external HTTP client. That's normal. There's no syntactic anti-pattern. Snyk doesn't model "the user can drain your OpenAI budget by hitting this endpoint in a loop" because that's not a vulnerability class in their taxonomy — it's a billing risk, which is a different bucket. Semgrep doesn't have a default rule for it. Trivy doesn't look at app code.

**How Lictor catches it:** Radar looks for API route handlers that call any of the known LLM provider SDKs (`openai`, `@anthropic-ai/sdk`, `cohere-ai`, `replicate`, and friends). For each handler, it checks for one of the known rate-limit patterns — an `@upstash/ratelimit` import, a Redis-backed limiter, a middleware that runs before the handler, or a check against the user's session for a per-user quota. If the handler calls a paid model and has zero rate limit upstream, that's a high finding. Plain English:

> 🟠 HIGH · Your `/api/chat` endpoint in `app/api/chat/route.ts` calls OpenAI with no rate limit. A single visitor with a script could run up your OpenAI bill into the thousands overnight. Fix below — wrap with `@upstash/ratelimit` (10 requests per minute per IP is a sane default).

---

## What this means in practice

Seven patterns. Each one a specific shape of bug that AI assistants ship into AI-built apps. Each one a thing the generic enterprise scanners weren't built to look for — not because they're bad tools, but because these bug shapes are new.

This is also why we don't want you to throw out Snyk. Snyk catches things we don't. Semgrep catches things we don't. Trivy catches things we don't. The honest, useful setup for a team shipping a Lovable / Bolt / v0 app is to run **all of them**, and let each tool do what it's good at.

The shape we'd recommend:

- **Snyk Open Source or Snyk Lite** — keep your dependency tree clean. Known CVEs. Years of curated vulnerability data behind it.
- **Semgrep** — broad SAST coverage with the open ruleset. Catches the generic anti-patterns in any language.
- **Trivy** — if you're shipping containers or have IaC. Catches the misconfiguration layer.
- **Lictor** — for the seven patterns above. The vibe-coder-specific bug shapes the generic tools miss by default. Plain-English reports your non-technical co-founder can read.

We run Snyk on our own dependency tree. We're not in competition with Snyk for the dependency-CVE job. We're in a different category: the seven patterns AI-built apps ship that generic tooling doesn't catch by default.

If you want to see whether any of the seven are in your project, the audit takes about a minute:

```
# Inside Claude Code, from your project root:
/lictor-security-check
```

Free, open source, no signup, no token, no telemetry. Apache 2.0. github.com/Raffa-jarrl/Lictor-AI.

If we miss something, file an issue. Real PRs welcome. The pattern catalog grows with the community.

— The Lictor crew

---

## Companion social

### Twitter / X thread (7 tweets)

**1/7**
What does Lictor catch that Snyk doesn't?

It's a fair question. So we wrote the answer.

7 specific bug patterns AI assistants ship into AI-built apps. Each one a thing the generic enterprise scanners weren't built to look for.

🧵

**2/7**
Pattern 1: Supabase service-role key in the client JS bundle.

The AI imports it from `.env`. Next.js bundles it. Every visitor's browser ships with your master DB key.

Snyk sees an env-var read. Doesn't track the import chain across the bundler.

We do.

**3/7**
Pattern 4: Frontend-only auth check.

```tsx
if (!user?.isAdmin) return <NotAuthorized/>
// then the admin UI renders below
```

Ships to every visitor. Override one variable in devtools, see the dashboard.

Generic SAST sees an auth check. We see that the check is the only one.

**4/7**
Pattern 5: Unsigned Stripe webhooks.

Public endpoint. No signature verification. Anyone POSTs `{"type": "checkout.session.completed"}` and gifts themselves the premium plan.

Found this on a real Lovable app last week. Founder fixed it the same day.

**5/7**
Pattern 6: Cross-tenant cache leak via `unstable_cache`.

User A loads the dashboard. Cached under key `"dashboard"`. User B loads next, gets user A's data.

Took down a real app in March. Generic SAST doesn't model Next.js cache semantics. We do.

**6/7**
The other patterns: missing RLS on Supabase tables, hallucinated npm packages, AI endpoints with no rate limit.

Full writeup is at lictor-ai.com/blog/7-patterns. Each pattern includes code, why it's broken, why generic tools miss it, what we say.

**7/7**
This isn't Lictor vs Snyk.

Run both. Snyk for the dependency CVEs. Semgrep for the broad SAST. Trivy if you containerize. Lictor for the 7 vibe-coder patterns above.

The audit takes a minute:
/lictor-security-check

Free. Open source. github.com/Raffa-jarrl/Lictor-AI

---

### LinkedIn post (~250 words)

A question we got 4 times last week from engineering leaders evaluating Lictor:

*"We already pay for Snyk. What does Lictor catch that Snyk doesn't?"*

It's a fair question, and the honest answer matters. So we wrote it up.

Seven specific bug patterns AI assistants ship into AI-built apps that the generic enterprise scanners weren't designed to look for — not because Snyk and Semgrep are bad tools, but because these bug shapes are new.

A few examples:

→ The Supabase service-role key gets imported by a module that gets bundled into a client component. Generic SAST sees an env-var read. The actual bug is the import chain across the Next.js compile boundary.

→ A Stripe webhook handler with no signature verification. Anyone who finds the URL POSTs a fake "checkout completed" event and gifts themselves the premium plan. Snyk doesn't model webhook signing as a vulnerability class.

→ `unstable_cache` keyed by a static string instead of the user ID. User A loads the dashboard, user B sees user A's data 30 seconds later. Took down a real app in March 2026.

The full writeup covers all seven patterns with code, attacker scenarios, and what each finding sounds like in plain English. It's at lictor-ai.com/blog/7-patterns.

The honest recommendation: run Snyk for dependency CVEs, Semgrep for broad SAST, Trivy if you containerize, and Lictor for the seven patterns above. Each tool does a different job.

The audit takes a minute and the report is plain English. `/lictor-security-check` in Claude Code. Free, open source, Apache 2.0.

— The Lictor team
github.com/Raffa-jarrl/Lictor-AI

---

### Hacker News submission

**Title:** `Show HN: The 7 bug patterns AI-built apps ship that generic SAST misses`

**URL:** `https://lictor-ai.com/blog/7-patterns`

**Body:**

Hi HN — we run security audits on AI-built apps (Lovable / Bolt / v0 / Cursor / Replit). We kept finding the same seven bug shapes that the generic scanners weren't catching by default, so we wrote up what they are and why.

The patterns:

1. Supabase service-role key reaching the client JS bundle via the Next.js compile graph
2. Tables referencing `auth.users` with no RLS policy
3. Hallucinated npm packages — AI suggests `next-auth-supabase-pro`, attackers register it
4. Frontend-only auth checks (the `if (user.isAdmin) ...` admin page that ships to every visitor)
5. Unsigned Stripe webhooks that anyone can POST to
6. Cross-tenant cache leaks via `unstable_cache` keyed by a static string
7. AI-model endpoints with no rate limit (free OpenAI proxy paid for by you)

For each pattern we explain why generic SAST misses it (it's mostly that the bug is in the *chain* across module / bundler / runtime boundaries, not in any individual file) and what Lictor's detection looks like.

Honest framing: this isn't "Lictor vs Snyk." Snyk catches dependency CVEs we don't. Semgrep catches broad SAST patterns we don't. Trivy catches container misconfig we don't. The right stack for a Lovable/Bolt/v0 app is multiple tools running together, not one replacing the others.

The audit is free, open source (Apache 2.0), runs inside Claude Code. github.com/Raffa-jarrl/Lictor-AI

Happy to take any pattern we missed in the comments. The catalog grows with PRs.

---

## Distribution plan

**Publication timing:** Tuesday Oct 6, 2026, 7:00 am Pacific. Sits inside the launch-week content slot. Goes live alongside the Twitter thread.

**Where to share, in order:**

1. **lictor-ai.com/blog/7-patterns** — the canonical home. SEO target: "vibe-coded app security," "Lovable security audit," "Snyk alternative for AI-built apps."
2. **Hacker News** — Show HN submission at 6:00 am Pacific Tuesday. Title above.
3. **Twitter thread** — drop at 7:30 am Pacific Tuesday from @lictor_ai. Retweet from Raffa's personal handle 30 minutes later.
4. **LinkedIn** — Raffa's personal handle, 9:00 am Pacific Tuesday. Tag the Lictor company page.
5. **Reddit** — `/r/nextjs`, `/r/Supabase`, `/r/SideProject`. Title: "We catalogued 7 bug patterns AI assistants ship into AI-built apps — full writeup with code." No "show me money" energy, just the link.
6. **Newsletter** — Tuesday weekly newsletter leads with the post.

**Personal sends:**

- Lovable team — friendly heads-up that we're publishing the Feb 2026 service-key pattern teardown. No surprise, no ambush.
- Theo Browne — short DM. He covers Next.js + Supabase security stuff and his audience is exactly our reader. No ask, just the link.
- Wes Bos / Scott Tolinski — same shape. Syntax podcast audience.
- Three engineering leaders who asked the "what does Lictor catch that Snyk doesn't" question — DM them the link with one sentence: "you asked, here's the answer."
- The two founders whose apps Pitchtank-style auditing turned up patterns 1 and 5 — give them the heads-up the post is going live (their apps are not named, but they should know).

**What success looks like Day 7:**

- 50+ HN points, ideally on the front page
- 100+ Twitter shares with replies pasting their own audit findings ("I ran Lictor and found 3 of these in my app")
- 5+ GitHub issues with new pattern proposals from the community
- 1+ engineering blog (Vercel / Supabase / Lovable) linking the post in their security docs

---

## Voice-lint pass note

Forbidden words check: zero instances of "leverage," "revolutionary," "transform," "supercharge," "disrupt," "robust," "paradigm," "synergy." (Verified.)

Compliance dialect check: every finding written as a story. No "information disclosure vulnerability" — instead "anyone with the URL has full database write access." No CVSS scores. No CWE numbers in headlines (the CWE/OWASP mapping lives at lictor-ai.com/compliance for the readers who care, but not in the body).

Sentence-length check: every section's average sentence length is at or below 25 words. The few longer sentences are inline code-context explanations and read fine.

Tone check: first-person plural ("we") for the Lictor crew voice throughout. Magnanimous about Snyk / Semgrep / Trivy — no bashing, named as complementary tools, with the actual job each one is better at than us. Closing CTA is the slash command, not a signup form.

Voice match against `skills/lictor-explain/SKILL.md`: confirmed. Same "sitting in a coffee shop" register. Same "your file, your line, your variable name" specificity.
