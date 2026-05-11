# Course email — Lictor launch announcement to GenerationAI list

**To:** GenerationAI course mailing list
**From:** Dor <dor@generationai.com>
**Sent:** ~10:00 am Pacific Tuesday Oct 6, 2026
**Subject options (A/B test):**
  - A: "We built the security tool the course is built around."
  - B: "Lictor is live."
  - C: "I shipped the OSS suite that makes the course's exercises possible."

---

## Body

Hey {{first_name}},

For the last six months I've been heads-down on something that affects every module of the course: **the security tool we keep referencing doesn't exist yet anywhere else, so I built it.**

It's called **Lictor**. It went live this morning.

### What's in it

Three free open-source tools that share one engine:

- **Lictor Shield** — a Chrome extension that audits any AI-built site for the 5 most common security holes. The thing we teach you to look for in Module 3 — now in your browser, automatic.

- **Lictor Sentinel** — an npm + PyPI package that wraps OpenAI / Anthropic. Catches prompt injection, secrets-in-input, PII leak. The thing Module 7 teaches you to *write yourself* — except we've already written it and it has 84 tests passing.

- **Lictor Guardian** — a hosted dashboard that aggregates Sentinel events across your apps. Audit log export for SOC 2 evidence (which is exactly what Module 11 covers). Free preview for 90 days.

The whole thing is **Apache 2.0 licensed**. You can use it in production, in your client work, in everything we teach you to build.

### Why this matters for the course

Every exercise that used to require you to roll your own security tooling — you can now plug Lictor in instead and focus on the actual architecture. The course's Module 0 ("audit your existing app") becomes a 60-second exercise. Module 13 ("Living Layer") is now buildable in an afternoon because you don't have to implement the wire format from scratch.

I'm updating the course modules over the next two weeks to point at Lictor instead of "build this yourself." The hand-rolled exercises stay available as advanced tracks for anyone who wants to understand what's underneath.

**The course price stays the same.** Lictor is open source. The two projects fund each other but they aren't bundled.

### What I'm asking from you

Three things, in increasing order of effort:

1. **Star the repo.** Takes 5 seconds. Tells me you saw this. [github.com/lictor-ai/lictor](https://github.com/lictor-ai/lictor)

2. **Try Shield on your most recent project.** Install the extension, visit your own app, see what it catches. Reply to this email with the most surprising thing it found.

3. **If you have a friend who'd use this — tell them.** No referral program, no payout. Just the actual ask: if Lictor is useful to you, the person who'll find it most useful is one degree out from your network.

### Why I built this

The honest answer: I spent 20 years in cybersecurity, watched the AI engineers ship apps in 2024-2026 the way the web engineers shipped apps in 2014-2016, and could not in good conscience keep teaching a course about AI security without also building the layer the industry is missing.

Lakera, Protect AI, HiddenLayer — they all raised real money for AI security in 2024. None of them ships a free Chrome extension. None has a free OSS SDK. That gap was where the course's curriculum was filling in by hand. Now Lictor fills it.

The full launch post (more detail, the architecture diagram, the privacy contract) is on Hacker News right now: [news.ycombinator.com/item?id=PLACEHOLDER]

— Dor

P.S. If you have access to your company's AI security RFP responses (or are writing one), [lictor.ai/compliance](https://lictor.ai/compliance) has Lictor's products mapped onto SOC 2, GDPR Article 32, EU AI Act, NIST AI RMF, and ISO/IEC 42001 with specific paragraphs. Free for anyone to use in their own vendor responses.

---

## Notes for sending

**Timing:**
- 10:00 am Pacific = 1:00 pm Eastern = 6:00 pm London = 8:00 pm Israel
- Tuesday morning open rates are highest for tech-audience mailings
- HN post is already 4 hours old by the time this email sends — the [news.ycombinator.com] link will work

**Segments:**
- Send to the FULL course list (active + paused + churned)
- Churned-list response is the best signal of whether the new positioning lands; their feedback is the most valuable

**A/B test:**
- A vs C for the first 10% of the list. C is more direct; A is more catchy.
- The full send goes out 60 min after the first 10% with the higher-open variant.

**Reply handling:**
- Set up auto-reply: "Thanks — I'll respond personally within 24 hours. If urgent, reply with [URGENT] in subject."
- Expect 50-200 replies in the first 48 hours

**What this email is NOT:**
- A discount offer
- A renewed pitch for the course
- A request for testimonials

It's a heads-up + a soft ask for stars/feedback/network amplification. That's it.
