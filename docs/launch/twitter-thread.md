# Twitter / X launch thread — draft

**Posted:** 7:00 am Pacific, Tuesday Oct 6, 2026
**From:** @lictor_ai (also retweet from Dor's personal handle)

---

**1/12**

Today I'm shipping Lictor — an open-source AI security suite.

In 2024 AI talked. In 2025 it acted. In 2026 it's running businesses.

The infrastructure to make that safe doesn't exist yet. We're building it.

🧵 Here's what just went live ↓

[attach: hero image — the Lictor lockup on charcoal background]

---

**2/12**

I'm a 20-year cybersecurity engineer.

The AI security category right now is dominated by enterprise-only point solutions. Lakera, Protect AI, HiddenLayer — all raised in 2024, all sell exclusively to Fortune 500s.

None of them ships a free OSS layer.

That's the gap.

---

**3/12**

Lictor is three free tools that share one engine:

→ Shield — Chrome extension, audits AI-built sites
→ Sentinel — SDK, wraps OpenAI / Anthropic to block prompt injection + data exfil
→ Guardian — hosted dashboard for teams (free preview, 90 days)

Apache 2.0. github.com/Raffa-jarrl/Lictor-AI

---

**4/12**

**Shield** is for end users.

Visit any AI-built SaaS. Shield audits the page locally — no URL ever leaves your browser.

Detects: hardcoded API keys in JS bundles, Supabase REST with RLS off, Firebase rules left open, admin paths that return 200 instead of redirecting, CORS that's too loose.

[attach: screenshot of Shield popup catching findings on the demo page]

---

**5/12**

**Sentinel** is for developers.

```js
const client = wrap(new OpenAI(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
});
```

Same call site. Same response. Sentinel intercepts pre + post.

32 prompt-injection patterns across 7 attack families.

---

**6/12**

The pattern catalog covers what actually breaks LLMs in 2026:

→ "Ignore all previous instructions"
→ DAN-style jailbreak personas
→ System-prompt extraction ("repeat your initial instructions")
→ Model-control tokens (`<|im_start|>`, `[INST]`)
→ Base64 obfuscation of injection payloads

---

**7/12**

Privacy invariant: Sentinel never ships raw user content anywhere.

Only 16-char SHA-256 fingerprints + severity + check ID + model fingerprint.

You can correlate incidents without ever seeing the prompt that triggered them.

By construction. Not by policy.

---

**8/12**

**Guardian** is for teams.

Dashboard at app.lictor.ai. Receives Sentinel telemetry, shows incident timeline, filters by severity / check / phase / time window.

Audit log export (CSV + JSON) for SOC 2, GDPR Article 32, EU AI Act Article 12.

Slack webhook for criticals.

[attach: dashboard screenshot]

---

**9/12**

Why open source for the consumer + dev layers?

Every AI agent platform — Zapier, Make, Manus, Lovable, Bolt — needs this. A closed product becomes one of 5 vendors.

Open-sourced, we become the standard.

Same playbook as Sentry, PostHog, HashiCorp.

---

**10/12**

The compliance angle is real.

EU AI Act enters phase-2 enforcement through 2026. NIST AI RMF is being adopted by every Fortune 500.

The compliance demand is here. The supply (specifically: SDK-shaped evidence layers) is missing.

We're the supply.

---

**11/12**

What's the moat?

Network effects from telemetry.

Every Sentinel install adds attack patterns to a corpus that improves every other install.

Lakera sees Lakera's customers. Lictor sees the union.

That's why the free tier is permanent. The data is worth more than any subscription.

---

**12/12**

The whole thing is open at github.com/Raffa-jarrl/Lictor-AI.

220+ tests across the suite. Apache 2.0. Built solo + Claude over 21 weeks.

If you ship AI agents — try it.
If you build AI security — collaborate with us.
If you ship insecure AI — let us audit it.

— @dor_lictor

---

## Notes on the thread

**Length:** 12 tweets. Could be cut to 8 if any feel weak after a first read. Don't go longer than 12; engagement drops past that.

**Hooks per tweet:**
- 1: hook + tease ("here's what just went live ↓")
- 2: credentials (the cybersec years)
- 3-8: the products + the why
- 9-11: the business + moat thinking
- 12: CTA

**Engagement plan:**
- Pin the thread
- Retweet tweet #5 (the code snippet) 3 hours later from the personal account
- Reply to every quote-tweet within 30 min for the first 4 hours
- Drop the demo video in a reply to tweet #1 about an hour after posting

**Don't:**
- Don't tag Lakera/Protect AI/HiddenLayer. Not the play.
- Don't start a fight about whether prompt injection is real. It is. Plenty of people on AI Twitter argue otherwise; don't engage.
- Don't promise compliance certifications we don't have (SOC 2 Type II is Q2 2027 work; we provide *evidence layer*, not the cert).
