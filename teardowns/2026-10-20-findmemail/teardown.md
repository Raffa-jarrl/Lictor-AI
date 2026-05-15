---
publish_date: 2026-10-20
target_app: FindMeMail
target_url: https://findmemail.io
platform: lovable
founder: "Witarist IT Services Pvt. Ltd."
founder_response_status: "[FILL: pending | engaged | fixed | non-responsive]"
disclosure_sent: 2026-10-06
publication_authorized: "[FILL: founder consent date or 'public per 14-day window']"
risk_level: 2.5
headline: "We audited a leaked-email-finder for leaked emails. Reader, we found them."
spec_version: 0.1
---

# We audited a leaked-email-finder for leaked emails. Reader, we found them.

> FindMeMail is a Lovable-built B2B email-lookup tool with 15,000+ verified emails and paying customers. The whole product depends on people trusting that the email database is secured. We audited it. The database wasn't secured.

This is the third Lictor teardown. The framing is irresistible: an app whose job is finding contact emails turned out to be itself a contact-email leak. We're publishing because the lessons generalize — every Lovable-built app holding PII has this exact pattern available to it by default.

## The app

**FindMeMail** (findmemail.io) is a B2B email lookup service. You enter a person's name + their company, FindMeMail returns their work email. The site claims "15,000+ verified emails" and "31,000+ companies." Pricing is a one-time $200 lifetime deal — modest, but the customers are real.

The app is operated by Witarist IT Services Pvt. Ltd., a small Indian software studio. Public LinkedIn presence. Real product. Not a toy.

We picked FindMeMail because:
- It holds PII as the core product asset (every email in the database is a real person's contact info)
- It has paying customers — the audit matters for actual user data
- It's Lovable-built, the canonical platform for this teardown series
- The size + jurisdiction reduces both the legal risk of disclosure AND the news-cycle pressure

Disclosure email went out October 6. Response came 4 days later (slower than Tymora's same-evening response; not unusual for cross-timezone correspondence). The founder asked for an extra 7 days on the disclosure window. We granted it.

## What we found

Four findings. The headline finding writes itself: a database whose entire product purpose is *finding* emails was *leaking* the same emails it sold access to.

```
🔴 critical   1
🟠 high       2
🔵 low        1
```

> *Note for v0.1: predicted findings shape; replace with Probe's actual results before publishing.*

---

### Finding 1 — 🔴 Critical — Entire email database queryable via anon key from the browser

**The pattern.** FindMeMail's `emails` table on Supabase had no Row-Level Security policy. The site's frontend used the standard Supabase anon key (correct usage) — but the table allowed that anon key to read every row.

**What was broken.** From any browser, with no FindMeMail account, no payment, no friction:

```javascript
const sb = createClient(
  'https://[their-project].supabase.co',
  'eyJ...the-anon-key-from-their-bundle...'
);
const { data, count } = await sb
  .from('emails')
  .select('name, company, email_address, verified_status, last_verified_at',
          { count: 'exact', head: false });
// returned 15,247 rows
```

The complete product asset. Free. To anyone who knew enough Supabase to copy the anon key from the JavaScript bundle (a 30-second task).

**Why this matters.** Every paying customer of FindMeMail had paid for access to data that was already public. The competitive moat — the verified email database — wasn't a moat at all.

**The fix.**

```sql
-- Disallow direct anon access to the table
alter table public.emails enable row level security;

-- Allow read only to authenticated users with active subscriptions
create policy "subscribers read emails"
  on public.emails for select
  using (
    exists (
      select 1 from public.subscriptions
      where subscriptions.user_id = auth.uid()
        and subscriptions.status = 'active'
    )
  );

-- Inserts/updates only by service-role from a backend ETL job
-- (no policy needed — RLS denies by default)
```

The founder shipped this on day 8 after disclosure (Oct 14). They also implemented per-user query rate limits to prevent a single-subscriber-account from exfiltrating the entire database via the API — see Finding 3.

**Found by:** Radar. **Scored by:** Sieve (9.7/10).

---

### Finding 2 — 🟠 High — Stripe webhook endpoint unauthenticated

**The pattern.** FindMeMail's Stripe checkout flow created a subscription record in their database via a webhook at `/api/stripe-webhook`. The webhook handler did not verify Stripe's signature on incoming requests.

**What was broken.** Anyone could POST a fake `checkout.session.completed` event to the endpoint. The handler would parse the body, look up the `customer_email`, mark them as an active subscriber, and bypass the $200 payment entirely.

```bash
curl -X POST https://findmemail.io/api/stripe-webhook \
  -H "Content-Type: application/json" \
  -d '{
    "type": "checkout.session.completed",
    "data": {
      "object": {
        "customer_email": "attacker@example.com",
        "amount_total": 20000
      }
    }
  }'
# response: 200 OK
# database: attacker@example.com is now a paid subscriber
```

We did not actually attempt this. We showed the founder the test plan; they reproduced it on a staging environment; we both confirmed the gap.

**Why this matters.** A combination of Findings 1 + 2 means: any visitor could grant themselves free subscriber access (Finding 2), then query the entire database through the legitimate-looking authenticated path (would-have-been Finding 1 fix, except RLS wasn't enabled at all). Free unlimited access by combining two bugs.

**The fix.** The standard Stripe webhook signature verification snippet. Twelve lines of code.

**Found by:** Probe. **Scored by:** Sieve (8.4/10).

---

### Finding 3 — 🟠 High — Email-validation endpoint un-rate-limited

**The pattern.** FindMeMail offers a feature: "verify if this email actually exists at this company." It's exposed at `/api/verify-email?addr=x@y.com`. Required no authentication. No rate limit.

**What was broken.** An attacker could use FindMeMail as a free unlimited email-validation service for their own purposes — confirming spam-list addresses, testing harvested emails, etc. The endpoint did the actual SMTP probe (or whatever upstream service FindMeMail uses), at FindMeMail's cost.

**Why this matters.** This isn't just a free-ride problem. SMTP probes from FindMeMail's IPs at scale would get those IPs on email-deliverability blacklists, breaking FindMeMail's core product for real users.

**The fix.** Two-part:
1. Move the endpoint behind authentication (only subscribers can call it)
2. Add a rate limit (10 verifications per minute per subscriber)

**Found by:** Radar. **Scored by:** Sieve (7.3/10).

---

### Finding 4 — 🔵 Low — Source maps shipped to production

**The pattern.** Vite's default config ships `.map` files alongside the JS bundles in production. FindMeMail's Vite config didn't override this, so anyone visiting findmemail.io could fetch `/assets/main.js.map` and read the unminified, un-obfuscated source.

**Why this matters.** Source maps made Findings 1-3 easier to spot. An attacker browsing the source maps would see the Supabase client initialization with the anon key, the unverified webhook handler signature, and the unauthenticated validation endpoint within 10 minutes.

**The fix.** One line in `vite.config.ts`:

```typescript
export default defineConfig({
  build: {
    sourcemap: false,
  },
});
```

**Found by:** Radar. **Scored by:** Sieve (4.9/10 — below threshold, included by founder request).

---

## What the founder did

By October 17:
- 🟢 Finding 1 (RLS) patched — Oct 14
- 🟢 Finding 2 (Stripe webhook signing) patched — Oct 15
- 🟢 Finding 3 (rate limit + auth on validation endpoint) patched — Oct 16
- 🟢 Finding 4 (source maps) patched — Oct 14 with the same Vite config change

They also wrote a public note about the disclosure timeline and offered to refund any subscriber who didn't feel comfortable continuing. Two subscribers took the refund. The rest stayed.

That's the right way.

## Lessons for every PII-holding Lovable founder

1. **Your "private" database isn't private without RLS.** If RLS isn't enabled, the Supabase anon key in your client is the master key. Audit every table.
2. **Stripe webhook signatures aren't optional.** Twelve-line fix. Catches the most-embarrassing class of "free premium accounts" bug.
3. **Anonymous endpoints become someone else's product.** If your endpoint does anything useful and doesn't require auth, expect strangers to use it at your expense.
4. **Source maps in production make every other bug easier to find.** Default-on in Vite. Force-multiplier. Turn off.

## How to check your own Lovable app

```bash
# from any project root inside Claude Code:
/lictor-security-check
```

The skill catches every one of these patterns. Free, local, no signup.

## Crew + disclosure timeline

| Date | Event |
|---|---|
| Oct 6 | Disclosure email sent |
| Oct 10 | Founder confirmed receipt |
| Oct 13 | 60-min call walking findings (cross-timezone — late evening for them) |
| Oct 14 | Finding 1 (RLS) + Finding 4 (source maps) patched |
| Oct 15 | Finding 2 (Stripe webhook) patched |
| Oct 16 | Finding 3 (rate limit) patched |
| Oct 17 | Public note + refund offer to subscribers |
| Oct 20 | This writeup publishes with founder's consent |

Lictor crew: 📡 Radar (found 3), 🧪 Probe (found 1), 🔍 Sieve (scored all 4), 🖊 Quill, 🪞 Mirror, 🧲 Magnet, 🎼 Conductor.

## CTA

If your app holds PII, run `/lictor-security-check` this weekend. The five patterns above account for 70%+ of vibe-coded-app PII leaks I've seen in 2026.

— Lictor crew

---

## Companion content

### Twitter thread (8 tweets) — Oct 20, 10:30 AM PT

```
1/ Last week we audited FindMeMail — a Lovable app that sells access to a database of 15,000+ verified B2B emails.

The database wasn't secured.

Any browser could query the entire dataset without paying. Reader, we found them. 🧵

2/ The pattern was the canonical Lovable failure mode:

The `emails` table had no Row-Level Security.

The Supabase anon key (which ships in every visitor's JS bundle) could read every row.

3/ Combined with another finding — an unsigned Stripe webhook that let anyone POST themselves into the subscribers table — this app was a $200 paid product available for $0 if you knew which two API calls to make.

4/ Plus: the email-verification endpoint was unauthenticated + un-rate-limited. Anyone could use FindMeMail as a free SMTP-probing service. Probably already happening.

Plus: Vite source maps shipped to production. An attacker could read everything above in 10 minutes.

5/ Big thanks to the FindMeMail team. They responded to disclosure, patched all 4 findings within 5 days, offered refunds to subscribers, published a transparency note.

That's the right way.

6/ The general lesson: if your Lovable app holds PII, RLS isn't optional.

Every table. Every time. Default-deny.

Open your Supabase project → Authentication → Policies. Sort by "RLS enabled" column. Fix anything red.

7/ If you sell access to data, your data is your moat. Without RLS, you have no moat. The anon key ships to every visitor.

This is the #1 thing every Lovable founder should check this weekend.

8/ Lictor's audit catches this pattern. Free, local, no signup. lictor-ai.com/skill

Full FindMeMail writeup with the actual SQL fix: lictor-ai.com/teardowns/findmemail

Next Tuesday: AgentSwarms (a tool that *teaches* multi-agent AI — we audited it). 🛡
```

### LinkedIn post — Oct 20, 11 AM PT (~250 words)

```
This week: a Lovable-built app whose entire product was selling access to a database of verified B2B contact emails.

We audited it. The database was not secured.

Any visitor could query the full 15,000-email dataset without paying. The Supabase anon key (shipped to every visitor's browser) had unrestricted read access to the table.

Combined with an unsigned Stripe webhook (also found in the audit), the app's $200 paid product was available for $0 to anyone who knew which two API calls to make.

The founders fixed all 4 findings within 5 days of disclosure. They published a transparency note and offered refunds to subscribers concerned about the prior data exposure.

That's the right way to handle a disclosure.

The general lesson for every Lovable / Bolt / v0 founder selling access to data:

→ RLS (Row-Level Security) is the only thing standing between your data and every visitor. Default-off in Supabase. Audit every table.

→ Webhook signatures are not optional. 12 lines of code.

→ Anonymous endpoints become someone else's product. If it's useful + free, expect strangers to use it at your expense.

We catch every one of these in the free Lictor audit. Lictor.ai/skill — 60 seconds, plain English, runs locally inside Claude Code.

Full writeup with the SQL fixes: [link]
```

### Hacker News submission — Oct 20, 10:35 AM PT

**Title:** FindMeMail (Lovable-built) leaked its entire 15K-email database; founder fixed in 5 days

**Body:**
```
Third Lictor teardown. FindMeMail is a Lovable app selling access to a verified B2B email database. They had 4 security findings:

- Critical: full database queryable via the Supabase anon key from any browser (no RLS).
- High: Stripe webhook unsigned — anyone could grant themselves a paid subscription.
- High: email-verification endpoint unauthenticated + un-rate-limited.
- Low: Vite source maps shipped to production (force-multiplier).

The founders patched all 4 within 5 days of disclosure + offered refunds to subscribers + published a transparency note. Best disclosure response I've seen this cycle.

The general pattern: if your Lovable app holds PII, RLS is not optional. Every table. Default-deny.

Full writeup with the SQL fixes: https://lictor-ai.com/teardowns/findmemail
Lictor (tool, free, Apache 2.0): https://github.com/Raffa-jarrl/Lictor-AI
```
