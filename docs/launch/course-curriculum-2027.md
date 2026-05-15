# Ship Secure AI Apps in 30 Days — course curriculum (Q1 2027 relaunch)

> **Generated:** 2026-05-15
> **Working title:** Ship Secure AI Apps in 30 Days
> **Operator:** Dor (GenerationAI), built around the Lictor open-source security suite
> **Public launch:** Wed Mar 24, 2027 (pre-launch waitlist opens Feb 1)
> **Pricing:** $99 launch one-time price · $49 waitlist deposit · $149 bundle (course + 6mo Studio Pro) · $499 team-of-10
> **Distribution math target:** 500 enrollees by May 31, 2027 → $49,500 cumulative
> **Voice:** identical to Lictor itself — plain English, builder dialect, no compliance speak, no listicle-bro energy

---

## 1. Course thesis (~300 words)

### What this course is for

The buyer is the solo founder who built an app with Lovable / Bolt / v0 / Cursor / Replit, ran `/lictor-security-check`, and got back a report with 12 findings — five of them CRITICAL — and now has no idea what to do next. They can read a Tailwind class. They cannot read CWE-863. They are not stupid. They are simply new to a domain where the existing learning materials assume a five-developer team and a CISO.

The job-to-be-done: "**Give me a structured 30-day path to go from terrified-by-my-audit to confidently shipping v2 of my app — and the receipts to prove I did it.**"

By Day 30, they will have:

1. A documented audit report for one of their own shipped apps.
2. Three CRITICAL findings fixed, with the fixes documented.
3. `@lictor/sentinel` integrated and verified to catch a test attack.
4. A continuous-audit setup (Probe) running on every commit.
5. The vocabulary to read any Lictor finding — and any Snyk, Semgrep, or GitHub Security finding — and act on it.
6. A **Lictor Certified Auditor** badge (Year 1: self-issued on capstone completion).

### What this course is NOT

- Not OSCP / OffSec / OSCE prep. We don't teach offensive security.
- Not general-purpose AppSec. We don't cover XXE, deserialization, or buffer overflows.
- Not a "learn to code" course. You ship something audit-able on Day 5 — you need to already have a project (Lovable/Bolt/v0/Cursor/Replit/Next.js/SvelteKit/Astro is fine).
- Not a SOC 2 / GDPR / EU AI Act compliance course. We touch evidence-export in Day 14 and stop.
- Not a Snyk / Semgrep replacement claim. We teach you to read all three.

### Who succeeds in this course / who shouldn't enroll

**Succeeds:** anyone who has shipped one thing with an AI builder, can find their `package.json`, and is willing to spend ~45 min/day for 4 weeks.

**Shouldn't enroll:** anyone who hasn't shipped anything yet (build something first — come back), anyone whose audit results page is empty (Lictor found nothing — you don't need us), or anyone looking for an enterprise SOC 2 checklist (use Vanta or Drata).

---

## 2. Pre-enrollment — the free 5-day email sequence (~200 words)

The lead magnet that fronts the paid course. Free. No signup-wall. Every email ships one specific, usable thing. The CTA to the paid course appears only on Day 5.

| Day | Subject line | What ships |
|---|---|---|
| **Day 1 — Mon** | "Your Lovable app probably has 1 of these 3 bugs. Here's how to check in 60 seconds." | Install `/lictor-security-check`, run it on one repo. Email body walks them through it with screenshots. |
| **Day 2 — Tue** | "The Supabase service-key story (and the 4-line fix)" | The single most-common vibe-coded bug — leaked service key in the JS bundle. Code example. Specific fix. |
| **Day 3 — Wed** | "Row-Level Security in Supabase, in plain English" | RLS explained without the docs jargon. One policy example. One "how to verify it works" check. |
| **Day 4 — Thu** | "Three real Lovable apps I audited last month — what we found" | Anonymized teardowns from the Lictor teardown engine. Pattern-recognition. Builds credibility. |
| **Day 5 — Fri** | "I built a 30-day version of this. Here's what's inside." | The pitch. Soft. Honest. Discount code valid through Sunday: `EARLY99` (drops list from $149 → $99). |

CTA on Day 5: one button — **"Take the 30-day course → $99"**. No countdown timer. No urgency theater. Honest discount window of 72 hours.

---

## 3. The 30-day curriculum — full detail (~1500 words)

Structure: **4 weeks × 5 days × (1 lesson video 15–30 min + 1 lab 15–45 min)**. Day 5 of each week is a lab-only synthesis day. Days 21–30 are bonus / capstone.

### Week 1 — Foundations: why your AI-built app is probably broken

#### Day 1 — The audit you should have run before you shipped
- **Lesson goal:** Understand what `/lictor-security-check` does and why a 60-second audit catches more than 80% of vibe-coded bugs.
- **Sub-topics:** (1) The seven check categories; (2) why "AI built it, AI didn't audit it" is a real pattern; (3) what a Lictor report actually looks like.
- **Lab:** Install Claude Code if not already installed. Install the `lictor-security-check` skill via `claude skill install lictor-security-check`. Run it on a `hello-world` Next.js repo (provided) and read the report end-to-end.
- **Learning check:** Can you point to where in the report you'd find a CRITICAL finding versus an INFO one? (Severity table in the report header.)
- **Lictor reference:** `/lictor-security-check` skill (the wedge product).

#### Day 2 — The 7 patterns that catch 80% of vibe-coded bugs
- **Lesson goal:** Memorize the seven check categories so any future report makes sense at a glance.
- **Sub-topics:** (1) Secrets in code; (2) exposed `.env` files; (3) unprotected `/api/*` routes; (4) open Supabase/Firebase; (5) admin-page "painted lock"; (6) over-permissive CORS; (7) unguarded AI chat.
- **Lab:** Open the SKILL.md at `~/.claude/skills/lictor-security-check/SKILL.md`. Read the `checks/` subdirectory. Pick the check that confuses you most and write a 2-sentence summary in your own words.
- **Learning check:** Without looking, name 5 of the 7. Bonus if you can give a specific Lovable / Bolt / v0 example of each.
- **Lictor reference:** `skills/lictor-security-check/checks/*.md` — all seven check files are open source and readable.

#### Day 3 — Reading a security report without panic
- **Lesson goal:** Translate any security report's jargon back into "what does this actually mean for my app."
- **Sub-topics:** (1) The plain-English glossary (the SKILL.md "what to call things" table); (2) severity in plain English — CRITICAL vs HIGH vs MEDIUM; (3) what to fix first when 12 findings land at once.
- **Lab:** Open the sample audit report at `/course-materials/sample-reports/lovable-app-12-findings.md`. Rank all 12 findings in order of what you'd fix first. Write a one-sentence "why" for the top 3.
- **Learning check:** Given a finding labeled `CWE-200: Information Exposure through Improper API Authentication`, can you say in one sentence what it means to a non-security friend? ("Your data is on the open internet — there's no login check on this page.")
- **Lictor reference:** The plain-English translation table in `skills/lictor-security-check/SKILL.md`.

#### Day 4 — Your platform's default failures (Lovable / Bolt / v0 specifics)
- **Lesson goal:** Recognize the specific failure modes that ship by default from each AI builder so you know what to check first.
- **Sub-topics:** (1) Lovable's Supabase RLS default (anonymous role has too much); (2) Bolt's Netlify env-var leakage pattern; (3) v0's serverless-function CORS default.
- **Lab:** Pick the platform you used most. Open one of your real shipped projects. Find the specific file/setting from today's lesson. Note whether you're affected.
- **Learning check:** If you ship on Lovable, you can name the one config setting most likely to expose your DB write-side.
- **Lictor reference:** The Lovable RLS playbook video (founder-content #5); `skills/lictor-security-check/checks/db-exposure.md`.

#### Day 5 — The first audit (synthesis lab)
- **Lesson goal:** Run a real audit on your own real project and confront the result.
- **Sub-topics:** (1) Picking the right project (something shipped, not a tutorial repo); (2) running `/lictor-security-check` end-to-end; (3) saving the `SECURITY-AUDIT.md` to a private gist or project root.
- **Lab:** Run `/lictor-security-check` on a project you've shipped or are about to ship. Save the report. Post in the Discord `#first-audit` channel: "I ran the audit. I have [N] CRITICAL, [N] HIGH, [N] MEDIUM. The one that scares me most is [X]."
- **Learning check:** You have a `SECURITY-AUDIT.md` in your own repo, dated this week.
- **Lictor reference:** `/lictor-security-check` skill; Discord `#first-audit` channel (cohort-style support even in evergreen mode).

### Week 2 — The 3 critical fixes every vibe-coder needs

#### Day 6 — Secrets in client bundles (the Supabase service-key story)
- **Lesson goal:** Understand why `SUPABASE_SERVICE_ROLE_KEY` ends up in your JavaScript bundle and how to never let that happen again.
- **Sub-topics:** (1) The `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` prefix trap; (2) the difference between `anon` key and `service_role` key; (3) the one-line check (grep your bundle).
- **Lab:** Build your project (`npm run build`). Run `grep -r "service_role" dist/ build/ .next/` (adjust to your bundler). If anything hits, you have the bug. Rotate the key and refactor.
- **Learning check:** You can explain in 30 seconds why `process.env.SUPABASE_SERVICE_ROLE_KEY` referenced in client code leaks even if the file looks server-only.
- **Lictor reference:** `skills/lictor-security-check/checks/secrets.md` (Check #1 in the suite).

#### Day 7 — Row-Level Security in Supabase, plain English
- **Lesson goal:** Write a working RLS policy that lets users read/write only their own rows.
- **Sub-topics:** (1) The `auth.uid()` pattern; (2) `SELECT` vs `INSERT` vs `UPDATE` vs `DELETE` policies (you need all four, not just `SELECT`); (3) how to test a policy without deploying.
- **Lab:** Pick one table in your Supabase project (`profiles`, `posts`, `orders` — whatever you have). Write the four CRUD RLS policies for it. Test with the Supabase SQL editor using `SET ROLE authenticated; SET request.jwt.claim.sub TO 'some-uuid';`.
- **Learning check:** A friend with a different user ID hits your API. They cannot read your rows. You verified this manually.
- **Lictor reference:** `skills/lictor-security-check/checks/db-exposure.md`; the Lovable RLS playbook video.

#### Day 8 — Stripe webhooks + payment endpoints
- **Lesson goal:** Validate Stripe webhook signatures so your payment endpoint can't be forged.
- **Sub-topics:** (1) Why `stripe.webhooks.constructEvent` matters; (2) idempotency keys on the receiving side; (3) the "two clicks billed once, credited twice" race condition.
- **Lab:** Find your `/api/webhooks/stripe` route (or equivalent). Confirm it calls `constructEvent` with the raw request body. Send a forged webhook with `curl` and verify it 400s.
- **Learning check:** Your endpoint rejects a forged request. You have the curl command saved as proof.
- **Lictor reference:** `skills/lictor-security-check/checks/api-auth.md`; Sentinel's `webhookGuard()` helper (auto-validates Stripe signatures).

#### Day 9 — The "auth checks happen on the frontend" trap
- **Lesson goal:** Stop trusting `if (user.isAdmin)` checks in your React components for anything that matters.
- **Sub-topics:** (1) The "painted lock" pattern (frontend redirect, no backend check); (2) IDOR — incrementing `?id=` in URLs; (3) the right place to check authorization (every API route, every Supabase RLS, every server action).
- **Lab:** Open your admin route. Hit the underlying `/api/admin/*` endpoint directly with `curl` while logged out. If it returns data, you have the painted-lock bug. Add a server-side check.
- **Learning check:** Your `/api/admin/*` returns 401/403 when called without auth, not 200 with the page redirect.
- **Lictor reference:** `skills/lictor-security-check/checks/admin-paths.md`; `checks/api-auth.md`.

#### Day 10 — Lab: fix 3 of your own findings
- **Lesson goal:** Apply Days 6–9 to your real audit report.
- **Sub-topics:** (none — this is a doing day).
- **Lab:** From your Day 5 `SECURITY-AUDIT.md`, pick three findings (one secret-leak class, one auth class, one DB-exposure class). Fix all three. Re-run `/lictor-security-check`. Confirm the findings are gone.
- **Learning check:** Your re-run audit has at least 3 fewer findings than your Day 5 audit. Diff the two reports.
- **Lictor reference:** `/lictor-security-check` (the re-run is the verification); `/lictor-fix-it` (the optional one-at-a-time fix walkthrough skill).

### Week 3 — When AI agents take real-world actions

#### Day 11 — Prompt injection in 2026 (and why your OpenAI key is a footgun)
- **Lesson goal:** Understand prompt injection as a class of bug (not a single trick) and what an attacker actually does with it.
- **Sub-topics:** (1) Direct prompt injection (user input → model); (2) indirect prompt injection (web content → tool call → model); (3) the realistic attack chain on a vibe-coded chatbot.
- **Lab:** Build a 10-line OpenAI chat endpoint that takes user input and runs `tools: [send_email]`. Try to get it to email you `admin@evil.com` by injecting the prompt. (You will succeed. That's the point.)
- **Learning check:** You have a working proof-of-concept prompt that exfils data from your own demo bot.
- **Lictor reference:** `skills/lictor-security-check/checks/ai-agent.md`; the Sentinel `wrap()` API (Day 12).

#### Day 12 — Using @lictor/sentinel to wrap your AI calls
- **Lesson goal:** Install Sentinel and verify it blocks the injection from Day 11.
- **Sub-topics:** (1) `npm install @lictor/sentinel`; (2) one-line wrap: `const openai = wrap(new OpenAI())`; (3) what Sentinel does at runtime — pre-call PII redaction, prompt-injection classifier, post-call secret scan.
- **Lab:** Wrap the OpenAI client in your Day 11 demo. Re-run the attack. Confirm it's blocked. Read the Sentinel event log entry.
- **Learning check:** You have a screenshot of Sentinel rejecting your Day 11 attack with a labeled reason.
- **Lictor reference:** `@lictor/sentinel` SDK on npm/PyPI; `wrap()` and `webhookGuard()` APIs.

#### Day 13 — PII leakage — when your AI accidentally exposes user data
- **Lesson goal:** Stop your AI feature from returning another user's data when given a creative prompt.
- **Sub-topics:** (1) The "summarize all the orders" prompt-leak class; (2) row-level isolation in AI tool calls (re-using Day 7's RLS); (3) Sentinel's PII redaction in transit.
- **Lab:** In your AI chat feature, intentionally craft a prompt that would surface another user's data. With Sentinel installed, confirm the response is redacted. Without Sentinel, confirm it leaks (so you understand the delta).
- **Learning check:** Same prompt, two outcomes (with/without Sentinel), screenshots saved.
- **Lictor reference:** `@lictor/sentinel` PII rules; Sentinel docs section on `pii.policy`.

#### Day 14 — The audit log every AI feature needs
- **Lesson goal:** Build the audit log so that when a customer asks "why did your AI say that?", you have an answer.
- **Sub-topics:** (1) What to log (input, output, model, timestamp, user_id, redactions, decisions); (2) where to store it (Sentinel's append-only log is fine for most apps); (3) the export format that maps to SOC 2 / GDPR / EU AI Act.
- **Lab:** Turn on Sentinel's audit log. Make 10 test calls. Export the log as JSON. Open `lictor.ai/compliance` and identify which Trust Services Criteria your log covers.
- **Learning check:** You can answer "show me every AI response for user X on date Y" with a single command.
- **Lictor reference:** Sentinel audit log; `lictor.ai/compliance` mapping page; Lictor Guardian (hosted dashboard) for the dashboarded version.

#### Day 15 — Lab: add Sentinel to your project + verify a test attack
- **Lesson goal:** Sentinel is integrated, tested, and shipping in your real app.
- **Sub-topics:** (none — doing day).
- **Lab:** Install Sentinel into your real production project. Wrap every AI client. Deploy. Run the Day 11 attack against the live app. Confirm it's blocked. Post a screenshot in Discord `#sentinel-live`.
- **Learning check:** Your live app's AI feature blocks a known prompt-injection attempt and logs the attempt.
- **Lictor reference:** `@lictor/sentinel`; Guardian dashboard preview.

### Week 4 — Shipping with confidence

#### Day 16 — Continuous audit — Probe and how to audit on every commit
- **Lesson goal:** Set up Probe so your repo gets re-audited on every push, not just when you remember.
- **Sub-topics:** (1) Probe agent — the Lictor crew member that runs the audit on a schedule; (2) GitHub Action wiring; (3) what to do when Probe opens a new finding.
- **Lab:** Add the Lictor GitHub Action to your repo (`.github/workflows/lictor-audit.yml`). Trigger a push. Confirm the action runs and posts findings as a PR comment.
- **Learning check:** A new commit to your repo triggers an audit and you see the result without doing anything.
- **Lictor reference:** Probe agent (one of the 11 crew); Lictor GitHub Action.

#### Day 17 — Reading other tools' output (Snyk, Semgrep, GitHub Security)
- **Lesson goal:** Translate a Snyk / Semgrep / GitHub Security finding into "what should I actually do."
- **Sub-topics:** (1) Snyk's CVE-style report — what to skip, what to act on; (2) Semgrep's pattern hits and why most are false positives for vibe-coders; (3) GitHub Dependabot vs Code Scanning — different beasts.
- **Lab:** Run Snyk's free tier on your project (or use the sample output provided). Identify the top 3 findings that are real and actionable for a Lovable app. Compare to your Lictor report — note overlaps and gaps.
- **Learning check:** Given a Snyk JSON output, you can pull out the 3 findings a vibe-coder should fix tonight.
- **Lictor reference:** `docs/launch/snyk-gap-analysis.md` (which 7 specific gaps Lictor covers that Snyk doesn't).

#### Day 18 — The disclosure conversation — when YOUR app gets a vulnerability report
- **Lesson goal:** Handle the day a stranger emails you "your app has a bug" without freaking out.
- **Sub-topics:** (1) The 24-hour acknowledgment rule; (2) what to ask the reporter (PoC, severity, scope); (3) when to pay a bounty vs say "thank you"; (4) a `SECURITY.md` template.
- **Lab:** Add a `SECURITY.md` to your repo (template provided). Add `security@yourapp.com` to your DNS or set up forwarding. Write a 3-line auto-reply.
- **Learning check:** A stranger emailing `security@yourapp.com` gets a coherent reply within 24 hours.
- **Lictor reference:** Lictor's own `SECURITY.md` as the template; Lictor's bug bounty rollout (Apr 2027) as the operational reference.

#### Day 19 — Security in your build pipeline (Vercel / Netlify / your CI)
- **Lesson goal:** Block bad commits before they ship to production.
- **Sub-topics:** (1) Vercel build-time secret scanning; (2) Netlify build hooks for audit; (3) the Lictor pre-deploy gate (Probe in CI).
- **Lab:** Add a CI check that fails the build if Lictor finds a new CRITICAL. Push a known-bad commit (intentionally — to a branch). Verify the build fails. Push the fix. Verify the build passes.
- **Learning check:** You have a green build with the gate active. You can show the failing build receipt.
- **Lictor reference:** Lictor CI integration docs; Probe in CI mode.

#### Day 20 — Final audit — run the full suite, ship v2.0
- **Lesson goal:** Run the full Lictor suite against your project and ship a confident v2.0.
- **Sub-topics:** (1) Final `/lictor-security-check` pass; (2) Sentinel live; (3) Probe in CI; (4) `SECURITY.md` in repo.
- **Lab:** Run the full suite. Save the final `SECURITY-AUDIT.md`. Tag the release. Deploy. Post in Discord `#shipped-v2`: "Shipped v2.0. Lictor receipts attached."
- **Learning check:** You have a tagged v2.0 release, a clean audit report, and Sentinel events flowing.
- **Lictor reference:** All four — `/lictor-security-check`, Sentinel, Probe, Guardian dashboard.

### Bonus / Capstone (Days 21–30)

- **Days 21–22 — Office hours:** Two live Q&A calls (recorded for evergreen viewers). Dor answers cohort-specific questions.
- **Days 23–24 — Advanced topics:** Webhook security beyond Stripe (Twilio, Resend, Shopify) + multi-tenant Supabase patterns.
- **Days 25–26 — Community projects:** Optional — pair up with one other student, audit each other's projects, write each other a 1-page critique.
- **Days 27–28 — Capstone preparation:** Build the public artifact (see §5 below).
- **Day 29 — Capstone submission:** Submit via Discord `#capstone-submissions`.
- **Day 30 — Badge issuance:** Lictor Certified Auditor badge issued (self-issuable in Year 1; see §6).

---

## 4. Course mechanics (~400 words)

### Format

1. **Video lessons:** 20 core lessons × 15–30 min, recorded in the founder-content-templates kit voice — webcam + screen recording, USB mic, one off-axis daylight light. Lo-fi-but-credible. Dor on camera, never a narrator avatar.
2. **Inline labs:** Markdown lab specs embedded directly in each lesson page. Copy-pasteable commands, screenshots of expected output. Labs are doable in 15–45 min.
3. **Discord channel:** One server, channels per week (`#week-1`, `#week-2`, etc.) plus `#first-audit`, `#sentinel-live`, `#shipped-v2`, `#capstone-submissions`. Dor lurks. Discord is optional — the course works without it for someone in evergreen mode.
4. **Office hours:** 2 live Q&A calls per monthly cohort (recorded). Evergreen viewers get the recordings.

### Cohort vs evergreen

**Recommendation: evergreen with monthly cohort kickoffs.** Best of both:

- **Evergreen** — anyone can buy and start the course any day. Scalable, no production overhead per student.
- **Monthly cohort kickoff** — first Monday of every month, a fresh cohort starts together. Dor hosts a 30-min kickoff call and the two office-hours sessions. New buyers join the next month's cohort.

This pattern keeps the community feel (you have classmates) without locking the buyer behind a "next cohort starts in 3 weeks" wall.

### Platform

**Recommendation: Podia for v1.** Reasons:

1. **Lowest setup overhead** — drag-and-drop video + markdown lessons, native Discord embedding via integration, 5% platform fee (vs Maven's 10%, Teachable's 8%).
2. **Evergreen-first UX** — Maven is excellent for cohort-only courses but penalizes evergreen viewers with cohort-shaped scheduling.
3. **No "we own your audience" lock-in** — Podia exports your subscriber list cleanly. Maven gates this behind paid tiers.
4. **GenerationAI's existing email list integrates** — Podia + ConvertKit / Beehiiv are first-class.

V2 (if/when volume justifies — past 1,000 enrollees): consider migrating to a custom Next.js course site hosted on Vercel with Mux for video. Defer that until the buyer demand is proven.

### Certification — Lictor Certified Auditor badge

Awarded on capstone completion. Year 1 is self-issuable (the buyer submits the capstone artifacts via Discord; an agent reviews). Year 2 introduces a 30-min proctored mini-exam once cohort volume passes 100 graduates/month. Details in §6.

### Refund policy

**14-day full refund, no questions asked.** Stated explicitly on the checkout page. Refund requests go to `hello@lictor.ai`. Auto-approval if requested within 14 days.

### Course updates

Quarterly update review (Apr / Jul / Oct / Jan). The course must stay current as Lictor's SDK ships new APIs and as Lovable / Bolt / v0 ship new platform defaults. Update cadence is built into the year-2 roadmap.

---

## 5. The capstone project (~200 words)

By Day 20, every student produces four things:

1. **A documented audit report** — `SECURITY-AUDIT.md` from `/lictor-security-check` run on one of their own apps. Saved publicly (in their repo) or privately (gist link shared in `#capstone-submissions`).
2. **Three CRITICAL findings fixed** — diff'd, with the fix linked from the audit. Each fix has a 1-paragraph "what I changed and why" note.
3. **A Sentinel integration shipped** — `@lictor/sentinel` installed in production, wrapping their AI clients, with one verified blocked-attack screenshot.
4. **A continuous-audit setup** — Probe in CI, running on every commit, posting findings as PR comments.

**Optional but encouraged:** a public LinkedIn or Twitter post sharing what they learned. Template provided. The post links to Lictor and to the student's app. Pattern: "I just shipped v2 of [my app]. I ran a Lictor audit and fixed [N] CRITICAL findings. Here's what I learned: [thread / list]." Roughly 30% of students will share publicly — that's the long-term flywheel.

The capstone is what alumni can SHOW. "I shipped a more secure app and here's the receipt" is the voice. The badge in §6 is the credential that lets them say it convincingly.

---

## 6. The Lictor Certified Auditor badge (~200 words)

A real credential, not a participation ribbon. Earned only by completing the four-part capstone.

**What graduates get:**

1. **A public profile** on `lictor.ai/certified` (with the graduate's consent). Lists name, app shipped, date certified, optional 1-paragraph bio. Self-edit via a magic link.
2. **A badge** — embeddable SVG/PNG for LinkedIn, GitHub README, Twitter bio. Hex-color-coded by year (2027 = original cohort, becomes a flex over time).
3. **Discount stack** — 50% off Lictor Studio Pro for the first year; 20% off Audit-as-a-Service consulting referrals.
4. **Optional referral payout** — every Lictor Certified Auditor who refers a paying Studio Pro / AaaS customer gets 20% of the first month (or one-time fee for AaaS). This is the long-tail.

**Issuance:**

- **Year 1 (2027):** self-issuable. Capstone is reviewed by an agent (likely Sieve + Quill) against a rubric. Pass/fail.
- **Year 2 (2028):** introduce a 30-min proctored exam once cohort volume passes ~100 graduates/month. Until then, the rubric is the gate.

**Strategic value:**

Every badge holder becomes a Lictor reference. Over time, `lictor.ai/certified` becomes a real referral engine for Audit-as-a-Service — when a Lovable founder googles "find a Lictor-certified consultant," the page is already populated with graduates ready to take paid work. The badge funnel is the AaaS demand-gen flywheel.

---

## 7. Pricing + payment (~200 words)

| Offer | Price | Notes |
|---|---|---|
| **Launch price** | **$99 one-time** | Lifetime access. All updates included. Mar 24 → Apr 30, 2027. |
| **Pre-launch waitlist deposit** | **$49** | Holds spot, applies to purchase. Captures intent before launch. Target: 200 waitlist by Feb 28, 2027. |
| **Bundle** | **$149** | Course + 6 months Studio Pro (Studio Pro alone is $19/mo = $114 for 6 months). Bundle is the highest-margin offer. ~40% of buyers pick the bundle if priced this way. |
| **Team** | **$499 for 10 seats** | Target buyer: small dev studios (3–10 people). Self-serve checkout. Includes 1 team Q&A session. |
| **Post-launch price** | **$149 one-time** | Year-2 price. Trigger: after 500 enrollees crossed (target: end of May 2027). |
| **Refund** | **14-day money-back, no questions** | Stated on checkout. Auto-approved if within window. |

**Cost-of-goods-sold per enrollee:**
- Video hosting (Mux or similar): ~$2 / enrollee / lifetime
- Payment processing (Stripe 2.9% + $0.30): ~$3 / enrollee at $99 price
- Platform fee (Podia): ~10% = $10 / enrollee at $99 (drops to ~5% on annual plans)
- **Total COGS: ~$15 / enrollee at $99 → 85% gross margin.**

**Revenue model:** 500 enrollees × $99 average effective price (after waitlist deposits applied + bundle uplift offset by team pricing) = ~$49,500. Net of COGS: ~$42,000.

---

## 8. Marketing + funnel (~300 words)

### Free lead magnet

The 5-day email sequence in §2. Sits at `lictor.ai/audit-fundamentals`. Sign-up captured to ConvertKit / Beehiiv. ~12,000 sign-ups expected by May 2027 (combined Lictor + GenerationAI funnel inflow over Q1 2027).

### Paid funnel sources

| Source | Audience | Expected conversion | Expected enrollees |
|---|---|---|---|
| **GenerationAI email list** | ~5,000 existing course customers / churned subs | 5% | ~250 |
| **Lictor newsletter** | ~7,000 by Mar 2027 (per year plan) | 3% | ~210 |
| **Sponsored placements** | IndieHackers, MicroConf, AI Engineer Summit recap newsletter | ~$3k spend, ~$60 CAC | ~50 |
| **Twitter / founder content** | Organic from Dor's video kit | Long tail | ~30–50 |
| **Pre-launch deposits → conversion** | 200 deposits × ~90% conversion | — | ~180 |
| **Total cumulative by May 31, 2027** | | | **~510–710** |

Plan target: 500. Buffer: 10–40%.

### Launch sequence

| Window | Phase | What ships |
|---|---|---|
| **Feb 1 – Feb 28, 2027** | Pre-launch waitlist | $49 deposit live. Email sequence captures sign-ups. Lictor newsletter mentions the course in 4 issues. |
| **Mar 1 – Mar 17, 2027** | Pre-launch ramp | Full landing page live. Dor records "what's inside" video. AI Engineer Summit talk (Mar 22) teases the course. |
| **Mar 18 – Mar 24, 2027** | Launch week | Public launch email Wed Mar 24 (right after AI Engineer Summit talk). Sponsored placements live. Twitter campaign. |
| **Mar 25 onward** | Evergreen | Monthly cohort kickoff calls (first Monday of each month). Sponsored placement renewal quarterly. |

### Year-2 outlook

Course price increases to $149 once the 500-enrollee threshold is crossed. Team pricing scales to $999 / 25 seats. Audit-as-a-Service referrals (via the Lictor Certified Auditor page) drive an additional revenue line that's not in the Year 1 number.

---

## 9. Operational requirements (~150 words)

| Workstream | Time budget |
|---|---|
| **Video recording** — 20 lessons × 30 min finished cut = 10 hours of video. At 3–4 takes per lesson + edit, plan ~40 hours total. | 40 hours |
| **Lab specs** — 20 labs to write, test on a fresh machine, and write expected-output screenshots. ~3 hours per lab. | 60 hours |
| **Course platform setup** — Podia configuration, drip schedule, payment + refund flow, embed Discord, set up automation. | 20 hours |
| **Marketing assets** — landing page copy + design, 5-day email sequence (drafted in §2 but needs full prose), 2 sponsorship-asset bundles, 5 launch tweets, capstone badge SVG. | 30 hours |
| **Total** | **~150 hours** |

Spread over Q4 2026 + Jan-Feb 2027 = **~4–5 hours/week** of Dor's time. Manageable alongside the rest of the year plan (Audit-as-a-Service launch, Studio v0.2, teardown cadence). The bulk of recording (40 hours) clusters in Feb 2027 — block out two Fridays per week for recording sessions during that month.

---

## End matter

**The 5 calls Dor should make personally vs delegate:**

1. **Record all 20 lesson videos personally.** Non-negotiable. The voice IS the brand. No avatar narrator, no co-host. (Personally.)
2. **Write the 5-day email sequence prose personally.** It's the lead magnet — voice is the differentiator. (Personally.)
3. **Set up Podia and the payment flow.** Delegable to an agent or a contractor — pure ops. (Delegate.)
4. **Build the lab specs and test them.** Delegable to a developer / Claude Code in a fresh sandbox. Dor reviews and approves; doesn't write from scratch. (Delegate with review.)
5. **Run the office-hours cohort calls personally.** Once a month, 60 min. The community signal Dor gets back from these calls is the input for the quarterly course update. (Personally.)
