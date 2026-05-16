# Social profile copy

Drop-in text for the Lictor social profiles. Repositioned 2026-05-15 to the **vibe-coder-vertical** wedge — built for the founder shipping a Lovable / Bolt / v0 / Cursor app, not for the CISO buying SOC 2 evidence.

Each is sized to fit the platform's stated character limits as of Q2 2026.

---

## Twitter / X

### Display name (50 chars max)

```
Lictor AI
```

### Bio (160 chars max)

```
11 AI agents audit your Lovable / Bolt / v0 project for security gaps. Plain English, runs in Claude Code, Apache 2.0.

🛡 lictorai.com
```

**Char count:** ~146 / 160

### Alternate bio (more direct)

```
The security crew for apps you built with AI.
60-second audit. No signup, no telemetry, no per-seat pricing.

→ lictorai.com · github.com/lictor-ai
```

**Char count:** ~145 / 160

### Location

```
San Francisco · Open source
```

### Website

```
https://lictorai.com
```

### Header image

`landing/og/og-image.png` (already 1200×630, fits Twitter header crop)

### Profile picture

Render a 400×400 PNG from `brand/lictor-mark.svg`:

```bash
rsvg-convert -w 400 -h 400 brand/lictor-mark.svg -o brand/profile-400.png
```

Then upload as profile picture.

---

## LinkedIn — Lictor AI company page

### Tagline (120 chars max)

```
The security crew for apps you built with AI. 11 AI agents audit your Lovable / Bolt / v0 project in plain English.
```

**Char count:** 113 / 120

### About (2,000 chars max)

```
Lictor is the security crew for apps you built with AI.

Eleven specialist AI agents audit your project, name what's wrong, and tell you exactly how to fix it — in plain English, no compliance dialect required. Free, open source (Apache 2.0), runs locally inside Claude Code.

The problem we exist for:

40 to 62 percent of AI-generated code ships with security vulnerabilities. 91.5 percent of vibe-coded apps had at least one AI-hallucination flaw in Q1 2026. In a single February incident, one popular AI app-builder exposed 18,000 users across 170+ databases. Eight million people now build software with AI assistants every week, and most of them don't know what an "RLS policy" is — let alone how to find a leaked Supabase service key in their own JavaScript bundle.

Enterprise security tools weren't built for them. Snyk, Veracode, Checkmarx — they assume a five-developer team and a CISO who speaks SOC 2. They charge per seat. They report in compliance jargon. They gate everything important behind a sales call.

Lictor assumes you, a Claude Code window, and a Lovable app you shipped on Saturday.

The product:

→ /lictor-security-check — A Claude Code skill that walks your project, runs 7 checks tuned for Lovable / Bolt / v0 / Cursor / Replit patterns, and writes a plain-English report. 60-second install. No signup. No telemetry.

→ Lictor Shield — Chrome extension. Audits any deployed AI-built site you visit. Catches leaked credentials, exposed databases, and unguarded AI surfaces before you sign up. Local-only.

→ Lictor Sentinel — npm + PyPI SDK. Wraps OpenAI / Anthropic clients at runtime to block prompt injection, PII leaks, and secret exfiltration. One-line integration: wrap(new OpenAI()).

→ Lictor Guardian — Hosted dashboard. AI incident timeline + audit-log export for SOC 2 / GDPR / EU AI Act evidence — for the day your AI-built app gets its first compliance question.

Built solo by a 20-year cybersecurity engineer. Open source so trust is verifiable by reading the code, not by certificates.

Launch: October 6, 2026.

— github.com/Raffa-jarrl/Lictor-AI
— lictorai.com
```

**Char count:** ~1,940 / 2,000

### Specialties / focus areas

```
AI Security · Vibe Coding · Open Source · Developer Tools · Claude Code · Lovable Security · Prompt Injection · OWASP LLM Top 10
```

### Industry

```
Computer & Network Security
```

### Company size

```
1 employee  (Note: update to "2-10 employees" when the crew scales)
```

### Founded

```
2026
```

### Logo

`brand/icon-512.png` (512×512 PNG of the lockup mark)

### Cover image (1192×220 recommended)

Build a horizontal crop from `landing/og/og-image.png`:

```bash
convert landing/og/og-image.png -crop 1192x220+4+205 brand/linkedin-banner.png
# Or skip the crop — LinkedIn will auto-crop the upload
```

---

## GitHub organization profile

After you create the `lictor-ai` org, you'll want a profile README. Create a public repo `github.com/lictor-ai/.github` with this README:

### `.github/profile/README.md`

```markdown
# Lictor AI

> The security crew for apps you built with AI.

Eleven AI agents audit your Lovable / Bolt / v0 / Cursor / Replit project for the security gaps the AI assistant didn't catch. Plain English. Apache 2.0. Runs locally inside Claude Code.

## What's here

- **[lictor](https://github.com/Raffa-jarrl/Lictor-AI)** — the monorepo. Claude Code skill suite (the wedge), Shield (Chrome extension), Sentinel (npm + PyPI SDK), and Guardian (hosted dashboard for incidents + compliance evidence). All Apache 2.0.

## Who this is for

- The solo founder shipping a Lovable app on Saturday
- The indie hacker prototyping in Cursor at midnight
- The designer deploying a Bolt project before morning coffee
- Anyone whose AI assistant just generated 200 lines of code they can't fully read

## Who this isn't for (yet)

- Fortune 500 CISOs buying SOC 2 evidence. Use [Snyk](https://snyk.io) or [Veracode](https://veracode.com). They're great at that lane. We're great at ours.

## Why open source

The AI security market is dominated by enterprise sales motions and certification theater. None of that helps the founder shipping a SaaS from Lovable on Saturday. We build the layer they need: free, open, in plain English, install in 60 seconds.

## Get in touch

- General: [hello@lictorai.com](mailto:hello@lictorai.com)
- Security: [security@lictorai.com](mailto:security@lictorai.com)
- Compliance / vendor risk: [compliance@lictorai.com](mailto:compliance@lictorai.com)

Website: [lictorai.com](https://lictorai.com)
```

---

## Intro tweets (for when you decide to start posting)

Three short tweets, schedule for the day after you flip the repo public. **Don't** announce the Oct 6 launch yet — these are "exists in the world" tweets, not "launch" tweets.

### Tweet 1 — existence

```
Building Lictor: the security crew for apps you built with AI.

11 AI agents audit your Lovable / Bolt / v0 / Cursor project. Plain English. Runs in Claude Code. Apache 2.0.

One slash command:
/lictor-security-check

github.com/Raffa-jarrl/Lictor-AI
```

### Tweet 2 — the why

```
Most AI security tools are built for the 5-developer team with a CISO. They charge per seat. They speak SOC 2.

Lictor is built for you. A Lovable app shipped on Saturday. A Bolt project deployed at midnight. A Cursor session that just generated 200 lines you can't fully read.

Plain English. No signup.
```

### Tweet 3 — credibility

```
Why am I building this?

20 years in cybersecurity. Wrote a lot of security reports nobody outside compliance teams could read.

40-62% of AI-built code ships vulnerable. Most builders don't know what an "RLS policy" is. They shouldn't have to.

Lictor: plain English. Free. Open.

lictorai.com
```

These three tweets, posted as a triplet, set up your account for whoever discovers the repo.

---

## A note on the repositioning (2026-05-15)

The previous social copy positioned Lictor as *"safety infrastructure for the AI agent era"* — a tagline competitive analysis on 2026-05-15 surfaced as already-occupied by Snyk's Agent Security (launched March 2026), Terra ($30M Series A), Armadin ($190M, Kevin Mandia), Straiker, Noma, and Lyrie. Six well-funded competitors had already claimed that exact phrase before Lictor's launch.

The new positioning — *"the security crew for apps you built with AI"* — narrows the wedge to:
- A specific audience (vibe-coders shipping from Lovable / Bolt / v0 / Cursor / Replit)
- A specific surface (Claude Code skill as primary, three layers underneath)
- A specific voice (plain English, builder dialect, no compliance speak)
- A specific differentiator (11 named agents, transparent crew, local-only)

This is the position no funded incumbent has claimed — because their pricing architecture, sales motion, and brand voice prevent them from claiming it without alienating their enterprise buyers. That asymmetry is the moat.

See `docs/launch/snyk-gap-analysis.md` for the evidence + the 7 specific gaps Lictor wins on.
See `docs/launch/anti-snyk-free-tier-playbook.md` for what happens when the incumbents try to follow.

---

## Notes

- All character counts checked against the platforms' stated maximums as of Q2 2026. Confirm before posting if it's been a while.
- The Twitter handle `@lictor_ai` may already be taken. Fallbacks (in order of preference): `@getlictor`, `@lictor_security`, `@lictoraisec`. The Twitter bio works for any of those.
- LinkedIn requires you to verify the domain `lictorai.com` before the page can be associated with the company. Do this after step 5 (domain deploy) of the playbook — Cloudflare Pages serves the domain, LinkedIn fetches a TXT record you add via Cloudflare DNS.
- For GitHub org avatar: re-render `brand/icon-512.png` if it doesn't currently exist:

  ```bash
  rsvg-convert -w 512 -h 512 brand/lictor-mark.svg -o brand/icon-512.png
  ```
