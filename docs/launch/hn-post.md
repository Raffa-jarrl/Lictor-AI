# Hacker News launch post — draft

**Posted:** 6:00 am Pacific, Tuesday Oct 6, 2026
**Title:** `Show HN: Lictor – Safety infrastructure for the AI agent era`

---

Hi HN — I've spent 20 years in cybersecurity (CISO advisory, security architecture for venture-backed startups). For the last six months I've been building Lictor, an open-source AI security suite. Today I'm shipping the first three layers free.

In 2024, AI talked. In 2025, it acted. In 2026, it's running businesses — Zapier's AI Actions, Manus's autonomous agents, OpenAI's Operator, Anthropic's computer use, every "vibe-coded" SaaS shipping a chatbot connected to user data. The security model hasn't caught up.

What's shipping today:

**[Lictor Shield](https://github.com/Raffa-jarrl/Lictor-AI/tree/main/shield)** — Chrome extension. Audits AI-built sites locally (no URL leaves your browser) and alarms when AI agents touch your localStorage / cookies. Detects 5 common AI-app security failures: leaked secrets in JS bundles, exposed Supabase REST endpoints with RLS disabled, Firebase rules left open, admin paths returning 200 instead of redirecting, CORS misconfigurations.

**[Lictor Sentinel](https://github.com/Raffa-jarrl/Lictor-AI/tree/main/sentinel)** — npm + PyPI SDK. Wraps OpenAI / Anthropic clients with one line:

```js
const client = wrap(new OpenAI(), {
  preflight:  ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
});
```

32 prompt-injection patterns across 7 attack families (direct override, jailbreak personas, system-prompt extraction, model-control delimiter tokens like `<|im_start|>`, etc.). PII detection in model output with Luhn-validated credit cards. 15 secret patterns to catch API keys being pasted into prompts. Privacy invariant: never ships raw user content to our servers — only 16-char SHA-256 fingerprints.

**[Lictor Guardian](https://app.lictor-ai.com)** — hosted dashboard. Per-incident timeline with severity / check / phase filters. Audit log export (CSV + JSON) for SOC 2 / GDPR Article 32 / EU AI Act Article 12 evidence. Slack webhook integration. Append-only audit log enforced at the database trigger level. Free preview for 90 days.

The whole suite shares one engine — a Rust crate (`lictor-core`) that compiles to native and WASM. Every new check ships everywhere at once.

The category isn't empty. Lakera, Protect AI, HiddenLayer all raised in 2024. None of them ship a free Chrome extension. None have an MIT-licensed OSS SDK. They're enterprise-only point solutions; we're an open-source-first suite. Stripe shape, not Salesforce shape.

Apache 2.0 license (consumer + dev). The hosted Guardian dashboard is source-available (Sentry's model) — the value is in the operations team running it, not the code.

220+ tests pass across the suite. Built in public over 21 weeks; every commit on `github.com/Raffa-jarrl/Lictor-AI` since May 2026.

Why post this here: I want HN's brutal feedback on the API surface, the threat model, and what we're missing. The Sentinel API is locked but the pattern catalogs grow forever. If you see a prompt-injection family we missed, please open an issue.

I'll be in this thread all day. Ask me anything about the design, the architecture, the business model, the 20-year cybersec POV on AI risk, or whatever.

— Raffa

---

## Why this title

- "Show HN" — required for project launches
- "Safety infrastructure for the AI agent era" — the category-defining frame from STRATEGY.md §13.0
- Avoids "AI security tool" (overloaded category) and "prompt injection" (too narrow)

## What to do as comments come in

**Engineering questions** — engage deeply. Show the actual code. Don't dodge.

**"How is this different from Lakera?"** — point at:
- Free OSS layer (Lakera doesn't have one)
- Consumer Chrome extension (Lakera doesn't have one)
- Suite shape across three layers, not a point solution
- Self-serve from day one, no enterprise sales call required

**"Doesn't `regex` based detection have N% false positive rate?"** — yes, and we explicitly say so in every finding's detail. The patterns are tuned for low false-positive rate (every pattern has explicit negative test cases in CI). Severity is a prior, not a verdict.

**"What about [novel attack X]?"** — open an issue, get a pattern added in v0.2. Be honest that any rule-based detector has a fixed catalog; this is why we ship the SDK with a registry that lets you add custom checks.

**Negative comments / "this is just regex"** — engage genuinely. "Yes, the v0.1 checks are rule-based. The Rust + WASM engine is built so v0.2 can plug in a small classifier alongside. We shipped the rule layer first because it's the foundation other layers compose against."

**Comments about pricing / Sentry-style source-available Guardian** — be honest. OSS + paid hosted is the standard model (HashiCorp, Sentry, PostHog). The value of Guardian is the operations team, the SLA, the compliance reports — not the code.

## What NOT to do

- Don't argue about whether AI security is real. It is. Anyone arguing otherwise will be argued with by the rest of HN.
- Don't oversell. We have 32 prompt-injection patterns, not "industry-leading detection." Be specific.
- Don't sleep until 10pm Pacific — comments come in waves; engagement in hour 6-8 is as important as the launch hour.
