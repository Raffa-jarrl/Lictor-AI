# Infographic Prompt — Lictor Tonight's Findings

Paste-ready prompts for **Gemini (image generation)** and **NotebookLM (multimedia summary)** to turn tonight's GitHub-secret findings into shareable visuals.

---

## A. GEMINI / NANO BANANA / IMAGEN PROMPT (single infographic image)

```
Create a vertical security-research infographic, 1080x1920px (Instagram-story / mobile-first
aspect). Tone: indie / hacker / friendly. Color palette: deep navy background (#0a0e27),
neon teal accents (#00ffcc), warning amber (#ffaa00), and white text. Minimal corporate
gloss — feels like a security researcher's personal site, not a SaaS landing page.

LAYOUT (top to bottom):

═══════════════════════════════════════════════
SECTION 1 — HEADER (top 15%)
═══════════════════════════════════════════════
- Small Lictor wordmark top-left in teal (small, ~24px)
- Main headline, 3 lines, bold sans-serif white:
    "Tonight"
    "Lictor scanned ~1,500"
    "recent GitHub commits"
- Below, in amber: "And found 32 leaked production keys."

═══════════════════════════════════════════════
SECTION 2 — THE HERO NUMBER (15-30%)
═══════════════════════════════════════════════
- Massive number "32" in neon teal, ~280px tall, centered
- Under it, in white sans-serif: "Live production secrets"
- Sub-caption in amber: "Indie devs, solo founders, weekend projects"

═══════════════════════════════════════════════
SECTION 3 — THE BREAKDOWN (30-55%)
═══════════════════════════════════════════════
4-row table, monospace font, teal labels, white numbers:

  ┌───────────────────────────────────────┐
  │  9    LIVE Stripe API keys (sk_live)  │
  │  20+  AWS access keys + secrets       │
  │  2    Mailchimp API keys              │
  │  1    Slack webhook URL               │
  └───────────────────────────────────────┘

═══════════════════════════════════════════════
SECTION 4 — THE 3 PATTERNS (55-80%)
═══════════════════════════════════════════════
Three short illustrated cards, stacked vertically, each with a small icon:

CARD 1 — 📄 .env committed before .gitignore
   "git add . → STRIPE_SECRET in history forever"

CARD 2 — 🔧 Terraform providers.tf with literal creds
   "aws { access_key = 'AKIA...' } pushed to public repo"

CARD 3 — 📋 'Secret' gist for quick share
   "Anyone with the URL reads it. Forever."

═══════════════════════════════════════════════
SECTION 5 — THE FIX (80-95%)
═══════════════════════════════════════════════
Highlighted teal-bordered code block:

  $ curl -sSL lictor-ai.com/install-precommit.sh | bash

Below in white: "Free. Apache 2.0. No telemetry."

═══════════════════════════════════════════════
SECTION 6 — FOOTER (bottom 5%)
═══════════════════════════════════════════════
- "github.com/Raffa-jarrl/Lictor-AI" in teal monospace
- Tiny Lictor wordmark + tagline: "the indie scanner"

VISUAL STYLE RULES:
- Subtle scanline / terminal effect over background
- Faint code-rain (Matrix-style) at 8% opacity behind text
- All numbers use a slight glow effect (teal for safe stats, amber for warnings)
- DO NOT include any donation/funding CTA, payment requests, "support us" buttons,
  or commercial language. The infographic is research/educational only.
- Replace any logo placeholders with a simple geometric "L" mark
```

---

## B. NOTEBOOKLM PROMPT (for the audio overview / mindmap / study guide)

Upload the **blog post markdown** (`blog-tonight-we-scanned-github-2026-05-20.md`) to NotebookLM. Then in chat:

```
Generate an audio overview of this research post in the style of "two friendly
security podcasters discussing tonight's findings". Length: 4-6 minutes. Cover:

1. The big-picture number (32 leaks, 1,500 commits scanned)
2. The 4 categories of leaked secrets and what attackers do with each
3. The three repeating patterns (committed .env, terraform providers.tf, secret gists)
4. The one-line fix (pre-commit hook)
5. Why Lictor exists for indie devs specifically (vs $20K/year enterprise tools)

Tone: warm, slightly nerdy, conversational. Don't sound corporate. Don't ask for
donations or stars — just share the research. End with the GitHub URL spelled
naturally ("Lictor — that's L-I-C-T-O-R — A-I on GitHub").
```

Optional follow-ups in NotebookLM:

```
Now generate a 1-page study guide of the same content. Use bullet points,
include the exact numbers, and add a "self-audit checklist" at the bottom
(3-5 questions like "Have you ever committed an .env file?").
```

```
Generate a mindmap connecting: the four secret types, the three leak patterns,
the underlying root cause (indie dev workflow), and the three remediation steps.
```

---

## C. CARD-DECK PROMPT (for LinkedIn / Twitter carousel)

If you want a 5-slide swipeable deck instead of a single tall image:

```
Generate 5 square images (1080x1080px each) for a LinkedIn carousel.
Same color palette as Section A above.

Slide 1 — Hook
    "Tonight we scanned 1,500 recent GitHub commits."
    "Found 32 leaked production keys."
    Subtitle: "Here's what they were."

Slide 2 — The breakdown
    Same 4-row table from Section A (Stripe / AWS / Mailchimp / Slack)

Slide 3 — Pattern 1
    Title: ".env committed before .gitignore"
    Visual: A terminal showing `git add .` with `.env` highlighted in red

Slide 4 — Pattern 2
    Title: "Terraform providers.tf with literal creds"
    Visual: A code block showing aws { access_key = "AKIA..." } highlighted

Slide 5 — The fix + footer
    "$ curl -sSL lictor-ai.com/install-precommit.sh | bash"
    "Free. Apache 2.0. No telemetry."
    GitHub URL at bottom
```

---

## D. RAW DATA BLOCK (for any other generator)

If a tool needs structured data instead of prose:

```yaml
research:
  date: 2026-05-20
  scanner: Lictor (Apache 2.0, github.com/Raffa-jarrl/Lictor-AI)
  scope_scanned:
    - 600 recent GitHub gists
    - 300 recent terraform repos
    - 100 recent .env commits
    - 100 recent Stripe-tagged commits
    - 258 recent cloudflare-config commits
  total_commits_walked: ~1500

findings:
  - type: Stripe live keys (sk_live_*)
    count: 9
    impact: Process refunds, read customer data, issue payouts
  - type: AWS access keys with paired secrets (AKIA*)
    count: 20+
    impact: Spin up crypto-mining EC2, exfiltrate S3, escalate to root
  - type: Mailchimp API keys
    count: 2
    impact: Read email list, send phishing as the brand
  - type: Slack incoming webhooks
    count: 1
    impact: Inject messages into private channels, phish the team

audience_pattern:
  who_leaks: indie devs, solo founders, weekend projects
  why_they_leak:
    - .env committed before .gitignore was updated
    - terraform providers.tf with literal credentials
    - "secret" gist for quick share with contractor

remediation:
  primary: install pre-commit hook (lictor-ai.com/install-precommit.sh)
  if_already_leaked: rotate key first, purge git history second
  enterprise_alternatives: GitGuardian, Gitleaks, TruffleHog, Snyk (all $20K+/yr or harder setup)
  lictor_positioning: free, Apache 2.0, no telemetry, one-line install

cta_rules:
  - NO donation / funding ask
  - NO "support us" button
  - Single neutral mention of github.com/Raffa-jarrl/Lictor-AI
  - Educational tone, not promotional
```

---

## How to use this file

1. **Gemini for the infographic image:** copy section A into Gemini's prompt box, attach no images. It'll generate the vertical infographic.

2. **NotebookLM for the audio overview / mindmap:** upload the blog post markdown first (`blog-tonight-we-scanned-github-2026-05-20.md`), then paste section B into the chat to direct the generation.

3. **LinkedIn carousel:** use section C, generate 5 squares, post as a swipeable deck.

4. **Anything else (Midjourney, DALL-E, Stable Diffusion):** use section D as the structured-data input and write your own visual brief based on it.

**Style rules across all of them:** zero commercial CTAs, single neutral repo link, educational tone, indie aesthetic.
