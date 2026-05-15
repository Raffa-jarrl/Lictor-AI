# Press email template — Lictor launch outreach

**Sent:** ~11:00 am Pacific Tuesday Oct 6, 2026
**Approach:** personalized at the top, body templated.

Three categories of recipients:

- **AI / dev tools press:** TLDR AI, Ben's Bites, The Information AI vertical, Stratechery (if reachable)
- **Security press:** The Register, Krebs on Security, Risky Business, Dark Reading
- **Platform DevRel:** Anthropic Relations, Vercel DevRel, GitHub blog, Cloudflare AI team
- **Target enterprise platforms:** Make.com security/AI lead, Zapier security team, Manus.im founders

---

## Template (~150 words to fit comfortably above an email preview pane fold)

**Subject:** Open-source AI security suite launched today — Apache 2.0, three layers, one Rust engine

Hi {{first_name}},

{{personalized sentence — see "personalization bank" below}}

I'm Raffa — 20-year cybersec engineer. I just shipped **Lictor**, an open-source AI security suite. Three free layers:

- **Shield** — Chrome extension auditing AI-built sites locally (no URL leaves the browser)
- **Sentinel** — npm + PyPI SDK that wraps OpenAI/Anthropic to block prompt injection, secrets-in-input, PII leak
- **Guardian** — hosted dashboard with incident timeline, audit log export for SOC 2 / GDPR Article 32 / EU AI Act Article 12 evidence

Apache 2.0 license. 220+ tests across the suite. Built solo over 21 weeks.

The category gap I'm aiming at: every AI security incumbent (Lakera, Protect AI, HiddenLayer) is enterprise-only — none ships a free OSS layer or a consumer browser extension. Lictor flanks that.

**HN launch:** {{hn_link}}
**Repo:** github.com/Raffa-jarrl/Lictor-AI
**Compliance mapping (might interest your security audience):** lictor-ai.com/compliance

Happy to do an embargo briefing, walk through the privacy contract, or send the demo video if useful. Available all day — `raffa@lictor-ai.com` or just reply here.

— Raffa

---

## Personalization bank (one line at top of email per recipient)

**TLDR AI (Joe Pisani / Dan Ni):**
> I've been a TLDR AI reader since the early days; thought this was on-mission for your audience.

**Ben's Bites (Ben Tossell):**
> Saw the Ben's Bites coverage of Lakera's Series A. Lictor is the OSS-first version of that category — wanted you to see it.

**Krebs on Security (Brian Krebs):**
> The Shield extension is intentionally aimed at the user-protection-from-vibe-coded-apps story I think Krebs readers care about most.

**Risky Business (Patrick Gray):**
> If you have time to discuss AI security on the podcast, I'd love to. The privacy invariants in our wire format might be the most interesting angle.

**Anthropic Relations (whoever is current head):**
> Sentinel ships with first-class Anthropic SDK support (`wrap(new Anthropic())`). Wanted to make sure your team saw it before any public users start asking your team questions about it.

**Vercel DevRel:**
> Sentinel is one wrap() call to add to any Next.js + AI SDK app. Most of our early users are on Vercel. Wanted to give your team a heads-up so you're not surprised when developers start asking.

**GitHub blog:**
> Open-source AI security has been a recurring topic on the GitHub blog. Lictor is the first OSS-first suite I've seen ship; would happily contribute to a follow-up post.

**Cloudflare AI team:**
> Lictor Sentinel SDK works inside Cloudflare Workers (we tested). The privacy contract — fingerprints only, no raw user content over the wire — might be of interest given Cloudflare's AI Gateway priorities.

**Make.com security lead:**
> Make's AI scenarios run on user OAuth tokens across thousands of apps. Lictor Guardian provides the audit-log evidence layer for that activity. Happy to discuss if compliance pressure is increasing on your side.

**Zapier security team:**
> Same as Make: Zapier's AI Actions chain tools across apps. We provide a free OSS layer (Sentinel) that drops into the runtime and a hosted dashboard (Guardian) that gives compliance-grade telemetry. Worth a 30-min discussion?

**Manus.im (founders):**
> Manus is the closest thing in the market today to "AI agents that take real-world actions." That's exactly the threat model Lictor is built for. Would love to discuss whether the Sentinel SDK could ship inside Manus's runtime.

---

## What to send WITH the email (attached or linked)

- One-page PDF — the architecture diagram + the four key talking points (`docs/launch/press-onepager.pdf` — TODO to create)
- Demo video link (90 seconds; "wrap → adversarial input → blocked + reported to Guardian")
- Press contact: `press@lictor-ai.com`

## What NOT to do

- **Don't BCC.** Single recipient per email. Press cares.
- **Don't follow up more than once.** If they don't respond in 72 hours, move on. Re-engage in 30 days only with a substantive update.
- **Don't pitch Lictor as "Lakera-killer."** Don't pitch against incumbents at all. Stay positive.
- **Don't pitch features. Pitch a story.** "OSS-first version of a category that's been enterprise-only" is the story. Memorize it.

## What "win" looks like

In order of value:

1. A piece written about the category-creation framing (best case: Stratechery / Acquired / Patrick OShaughnessy)
2. Coverage in 2-3 newsletters in week 1 (TLDR AI, Ben's Bites)
3. A blog post from Anthropic / Vercel / Cloudflare DevRel (these convert)
4. An RT from one of the AI safety researchers (Marvin v. Hagen, Simon Willison) — they reach more devs in 8 hours than a TechCrunch piece does in a week
5. A reply / DM from any platform engineer at Make, Zapier, or Manus
