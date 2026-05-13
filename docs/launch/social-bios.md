# Social profile copy

Drop-in text for the social profiles you're setting up in Sprint 1. Each is sized to fit the platform's character limits.

---

## Twitter / X

### Display name (50 chars max)

```
Lictor AI
```

### Bio (160 chars max)

```
Open-source AI security suite for vibe-coders. Four free tools. No SOC 2 jargon. Apache 2.0.

🛡 lictor.ai · github.com/lictor-ai/lictor
```

**Char count:** 138 / 160

### Alternate bio (more direct)

```
Free open-source AI security for people who build with AI but don't speak security. Chrome ext + npm/pip SDK + Claude Code skills.

→ lictor.ai
```

**Char count:** 152 / 160

### Location

```
San Francisco · Open source
```

### Website

```
https://lictor.ai
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
Safety infrastructure for the AI agent era. Four free open-source security tools for AI-built apps.
```

**Char count:** 100 / 120

### About (2,000 chars max)

```
Lictor is an open-source AI security suite. We build the safety layer that gets skipped when AI generates code faster than security can review it.

Most AI security software is built for enterprise compliance teams — buyers who already speak the language of SOC 2 and CWE. That's a real market, but it's not the market that needs us most.

The market that needs us is the explosion of "vibe-coded" applications shipping from Lovable, Bolt, v0, Cursor, and direct AI prompting. The founders and designers building those apps don't have a CISO. They don't have a compliance team. They have themselves, an AI assistant, and 48 hours to ship something. They need security tooling that speaks plain English and doesn't require a sales call.

That's what Lictor is.

Four open-source products, free forever, Apache 2.0:

→ Lictor Shield — Chrome extension. Watches AI-built sites you visit and warns about leaked credentials, open databases, and unguarded AI interfaces. Local-only audit; no URL ever leaves your browser.

→ Lictor Sentinel — npm + PyPI SDK. Wraps OpenAI/Anthropic SDKs to block prompt injection and PII leaks at runtime. One-line integration: `wrap(new OpenAI())`. The privacy invariant prevents raw user content from ever crossing into our infrastructure.

→ Lictor Guardian — hosted dashboard. AI incident timeline, audit log export for SOC 2 / GDPR / EU AI Act evidence, Slack integration. Free preview for 90 days.

→ Lictor Security Suite for Claude Code — four free plugins (`/lictor-security-check`, `/lictor-explain`, `/lictor-fix-it`, `/lictor-rotate`). Run a security audit on your project before you deploy, in plain English. 60-second install.

Built solo by a 20-year cybersecurity engineer. Open source so trust is verifiable by reading the code, not by certificates.

The launch target is October 6, 2026.

— github.com/lictor-ai/lictor
— lictor.ai
```

**Char count:** 1,887 / 2,000

### Specialties / focus areas

```
AI Security · Open Source · Developer Tools · Vibe-Coding · Prompt Injection · OWASP LLM Top 10 · Compliance Evidence
```

### Industry

```
Computer & Network Security
```

### Company size

```
1 employee  (Note: when this grows, update to "2-10 employees")
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
# Crop the 1200×630 OG image to LinkedIn's 1192×220 banner aspect
# Quick: take the top center crop
convert landing/og/og-image.png -crop 1192x220+4+205 brand/linkedin-banner.png
# (Or skip the crop — LinkedIn will auto-crop the upload)
```

---

## GitHub organization profile

After you create the `lictor-ai` org, you'll want a profile README. Create a public repo `github.com/lictor-ai/.github` with this README:

### `.github/profile/README.md`

```markdown
# Lictor AI

> The bodyguard your AI didn't ship with.

Open-source AI security for builders who don't have a security team.

## What's here

- **[lictor](https://github.com/lictor-ai/lictor)** — the monorepo: Shield (browser), Sentinel (SDK), Guardian (dashboard), and the Claude Code skill suite. Apache 2.0.

## Why

The AI security market is dominated by enterprise sales motions and certification theater. None of that helps the founder shipping a SaaS from Lovable on Saturday.

We build the layer those founders need: free, open, in plain English, install in 60 seconds.

## Get in touch

- General: [hello@lictor.ai](mailto:hello@lictor.ai)
- Security: [security@lictor.ai](mailto:security@lictor.ai)
- Compliance / vendor risk: [compliance@lictor.ai](mailto:compliance@lictor.ai)

Website: [lictor.ai](https://lictor.ai)
```

This README shows on the org's public landing page once you've created the `.github` repo.

---

## Intro tweets (for when you decide to start posting)

Three short tweets, schedule for the day after you flip the repo public. **Don't** announce the Oct 6 launch yet — these are "exists in the world" tweets, not "launch" tweets.

### Tweet 1 — existence

```
Building something new in the open: Lictor AI — open-source security tools for AI-built apps.

Four free products, all Apache 2.0:
🛡 Shield (Chrome ext)
🔧 Sentinel (npm + pip SDK)
📊 Guardian (hosted dashboard)
💬 Security skills for Claude Code

github.com/lictor-ai/lictor
```

### Tweet 2 — the motivation

```
Most AI security tools are built for enterprise compliance teams who already speak the language.

Lictor is built for the people shipping AI SaaS from Lovable / Bolt / v0 / Cursor — designers and founders who don't have a CISO and don't want one.

Plain English. No SOC 2 jargon.
```

### Tweet 3 — credibility

```
Why am I building this?

20 years in cybersecurity. Spent the last 18 months watching AI engineers ship apps the way web engineers shipped them in 2014 — fast and loose. Same bugs. New attack surface.

Most security tools won't help vibe-coders. Lictor will. Free.

lictor.ai
```

These three tweets, posted as a triplet, set up your account for whoever discovers the repo.

---

## Notes

- All character counts checked against the platform's stated maximums as of Q1 2026. Confirm before posting if it's been a while.
- The Twitter handle `@lictor_ai` may already be taken. Fallbacks (in order of preference): `@getlictor`, `@lictor_security`, `@lictoraisec`. The Twitter bio works for any of those.
- LinkedIn requires you to verify the domain `lictor.ai` before the page can be associated with the company. Do this after step 5 (domain deploy) of the playbook — Cloudflare Pages serves the domain, LinkedIn fetches a TXT record you add via Cloudflare DNS.
- For GitHub org avatar: re-render `brand/icon-512.png` if it doesn't currently exist:

  ```bash
  rsvg-convert -w 512 -h 512 brand/lictor-mark.svg -o brand/icon-512.png
  ```
