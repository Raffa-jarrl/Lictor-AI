# Why I built Lictor

**Published:** lictor-ai.com/blog/why-lictor — Tuesday Oct 6, 2026
**Author:** Raffa [last name], founder
**Audience:** Engineering managers, CISOs, AI-curious developers, journalists writing about AI security

---

# Why I built Lictor

I've spent 20 years in cybersecurity. CISO advisory, security architecture, the works. Three years ago I started watching engineers ship AI applications the way they shipped CRUD apps in 2015 — fast, loose, with a vague hope that the platform layer would handle the security problems for them.

It won't. So I built Lictor.

## The problem

In 2024, AI was a thing you typed into. Prompt → response. The security surface was narrow: prevent prompt injection, prevent the model from saying something embarrassing.

In 2025, AI started taking actions. ChatGPT plugins. OpenAI's "Actions". Vercel's AI SDK adoption. Claude's tool use. The security surface widened — now an AI could read your email, modify your Sheets, post to your Slack.

In 2026 — right now — autonomous AI agents are increasingly running entire workflows. Manus orchestrates multi-step tasks. Lovable apps spin up SaaS in an afternoon. Zapier's "AI Actions" chain together OAuth-authorized access to thousands of apps. Every "vibe-coded" SaaS is one prompt injection away from a viral incident.

The security model has not caught up. Specifically:

- **No one is auditing AI-built apps for the consumer.** If you sign up for a brand-new AI SaaS today, you have no idea whether their `/api/users` endpoint returns the full customer list without authentication. (For a non-trivial fraction of them, it does.)
- **No one is wrapping AI calls at the developer layer.** Engineers integrate OpenAI's SDK in two lines and ship to production. No prompt-injection defense, no PII leak detection, no audit trail of what the model saw.
- **No one is giving teams an evidence layer for AI safety.** When the EU AI Act auditor shows up and asks "what's your record of AI agent activity, and what did you block?" — most teams have no answer.

## What's out there

The AI security category isn't empty. **Lakera AI** raised $20M Series A in 2024. **Protect AI** raised $35M Series B. **HiddenLayer** raised $50M Series A. **Robust Intelligence** was acquired by Cisco for ~$300M. There's real venture capital here.

But every one of these companies is selling enterprise. Six-figure annual contracts. Top-down sales motions. 3-month integrations.

**None of them ships a free OSS layer. None of them ships a consumer browser extension.** The market is wide open in those segments. Specifically:

- A free Chrome extension that audits AI-built apps for the end user (Shield)
- A free MIT-licensed SDK that wraps OpenAI/Anthropic for developers (Sentinel)
- A self-serve hosted dashboard that teams can adopt without a sales call (Guardian)

That's Lictor.

## The architecture

Three layers, one engine.

```
┌──────────────────────────────────────────────────────────────┐
│  LICTOR SHIELD  (consumer / Chrome extension / free)           │
│  Detects AI-built site fingerprints, runs 5 security checks    │
│  locally, alarms on AI agent access to your localStorage.      │
├──────────────────────────────────────────────────────────────┤
│  LICTOR SENTINEL  (developer / npm + PyPI / free)              │
│  Wraps OpenAI / Anthropic SDKs. Pre-flight + post-flight       │
│  checks for prompt injection, secrets, PII leakage.            │
├──────────────────────────────────────────────────────────────┤
│  LICTOR GUARDIAN  (team / hosted / free preview 90 days)       │
│  Incident timeline, audit log export, Slack webhook,          │
│  compliance-ready record-keeping.                              │
└──────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌─────────┴─────────┐
                    │   LICTOR CORE     │
                    │   (Rust + WASM)   │  shared engine
                    └───────────────────┘
```

The engine — `lictor-core` — is a Rust crate. It compiles to native binaries (used by Sentinel SDK and Guardian backend) and to WebAssembly (used by Shield in the browser). Every check we write ships everywhere at once.

This matters because attack patterns are a moving target. When a new prompt injection family lands on Twitter at 3am, the catalog needs to update. With one engine, that's one PR.

## What ships today

**Shield** runs five checks against any AI-built site:

1. **Secrets exposure** — 15 patterns for API keys (Anthropic, OpenAI, Stripe, GitHub, AWS, &hellip;), JWT tokens, RSA private key blocks, database connection strings. Scans HTML + first 8 same-host JS bundles + 6 sensitive file paths (`/.env`, `/.git/config`, etc.).

2. **Database exposure** — Supabase REST endpoints with RLS likely disabled. Firebase Realtime DB rules with public read. `/api/users`, `/api/admin`, etc. returning JSON without auth.

3. **Auth surface** — admin-flavored paths that return 200 (which means the page rendered) instead of redirecting to login. Classic client-side-only auth gate.

4. **CORS posture** — `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`. Browsers reject the combination, but it tells you the developer doesn't understand CORS and the API probably has other holes.

5. **AI agent surface** — chat widgets, OpenAI / Anthropic SDK references, agent data attributes. Doesn't actively probe the agent (that crosses the read-only line); flags it for manual prompt-injection review.

**Sentinel** ships three checks at v0.1:

1. **Prompt injection** (preflight) — 32 patterns across 7 attack families:
   - Direct override ("ignore previous instructions")
   - Authority impersonation (`System:` role markers, "developer mode enabled")
   - Jailbreak personas (DAN, "act as evil AI")
   - System-prompt extraction ("repeat your initial instructions")
   - Delimiter injection (`<|im_start|>`, `[INST]`, fake `Assistant:` turn boundaries) — CRITICAL severity because these tokens should never legitimately appear in user input
   - Goal hijacking ("instead of that, do this")
   - Suspicious encoding (long base64 strings, hex escape soup)

2. **PII leak** (postflight) — emails, phones, SSNs (rejects invalid prefixes), Luhn-validated credit cards, IBANs, IPv4/IPv6, formatted US addresses.

3. **Secrets in input** (preflight) — same 15 patterns as Shield. Catches developers pasting their `.env` file into a chat for debugging help.

**Guardian** ships a hosted dashboard:

- Incident timeline with severity / check / phase filters
- Per-incident detail view with full metadata + privacy footnote
- Audit log export (CSV + JSON) for compliance evidence
- Slack webhook config per account
- Magic-link auth (no passwords)
- Append-only audit log enforced at the database trigger level

## The privacy contract

This is the part most AI security tools handwave. Lictor doesn't.

**Sentinel never ships raw user content to Guardian.** The wire format carries:

- Severity
- Check ID
- Category
- A 16-character SHA-256 fingerprint of the first 4 KB of the relevant input/output
- Model provider + name
- Action taken (logged / blocked / redacted)

That's it. By construction, not by policy. Reversing a fingerprint to the original text would require a rainbow table of plaintexts on a scale that doesn't exist.

This matters because the moment your AI security vendor sees the full prompt — you've created a second leak surface. The right shape for telemetry is "enough to correlate, not enough to reveal."

## What I'm betting on

Three things, in order of how convinced I am.

**(1) The category is real.** AI agents are getting more autonomous, not less. The compliance demand is real (EU AI Act, NIST AI RMF). The Fortune 500 are starting to require AI security evidence in vendor RFPs. This is not speculative.

**(2) Open source is the right wedge.** Every AI agent platform — from Zapier to Make to Manus to Lovable — needs an AI security layer. If they have to integrate a closed enterprise product, they wait. If we ship a free MIT/Apache library, they adopt it.

**(3) The data network effect compounds.** Every Sentinel install adds attack patterns to a corpus that improves every other install. Lakera sees Lakera's customers. Lictor sees the union. That's why the free tier is permanent — the telemetry is worth more than the subscription would be.

## What I'm not promising

I'm not promising AGI-grade security. I'm not promising zero false positives. I'm not promising SOC 2 Type II on launch day (that's Q2 2027 work).

I'm promising:

- Open source. Apache 2.0. You can read every line.
- The privacy contract. Verifiable in the source code.
- Active maintenance. Every prompt-injection family that emerges gets a pattern, gets tests, ships in the next minor version.
- The compliance evidence layer your auditor will ask for.

## Try it

- `npm i @lictor/sentinel` — wrap your OpenAI client
- `pip install lictor-sentinel` — wrap your Python client
- Install [Shield](https://chrome.google.com/webstore/detail/lictor-shield) (Chrome Web Store) — free
- Sign up at [app.lictor-ai.com](https://app.lictor-ai.com) — 90-day free preview

If you ship AI agents and find a category of attack we should be detecting and aren't — open an issue or DM me directly. The catalog is a living artifact.

— Raffa
[lictor-ai.com](https://lictor-ai.com) · [@lictor_ai](https://twitter.com/lictor_ai) · [github.com/lictor-ai](https://github.com/lictor-ai)
