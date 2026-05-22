# YouTube Launch Kit — Lictor AI: Security Crew

**Video file:** `/Users/raffa/Downloads/Lictor_AI__Security_Crew.mp4`
**Publish date target:** 2026-05-20

Three artifacts below:
1. **YouTube description** (paste in description tab)
2. **Thumbnail generation prompt** (paste into Gemini/Imagen/Midjourney)
3. **Optional bonus** — title variants + tags + first-comment template

---

## 1. YOUTUBE DESCRIPTION (paste-ready)

```
Tonight my open-source scanner watched 32 live production API keys get
committed to public GitHub repos in a few hours. 9 active Stripe sk_live
keys. 20+ AWS access keys with paired secrets. All from indie devs
vibe-coding their MVP.

This is the indie-dev security gap — and Lictor is the free, Apache-2.0
scanner I built to close it.

═══════════════════════════════════════════════════
WHAT YOU'LL SEE IN THIS VIDEO
═══════════════════════════════════════════════════

⏱  0:00  The 32-leaks-in-one-night discovery
⏱  0:30  Why vibe-coded MVPs leak secrets at scale
⏱  1:00  The 3 patterns my scanner sees over and over
⏱  1:45  What Lictor actually does (28 patrols, zero telemetry)
⏱  2:30  One-line install: the pre-commit hook
⏱  3:00  Why I'm not asking for money — what I AM asking for

═══════════════════════════════════════════════════
INSTALL LICTOR IN 5 SECONDS
═══════════════════════════════════════════════════

   curl -sSL lictor-ai.com/install-precommit.sh | bash

That's it. It quietly catches secrets BEFORE they reach your commit.
Apache 2.0. No telemetry. No SaaS tier. No upsell.

═══════════════════════════════════════════════════
LINKS
═══════════════════════════════════════════════════

🔗 GitHub repo:        https://github.com/Raffa-jarrl/Lictor-AI
🌐 Website:            https://lictor-ai.com
📝 Tonight's research:  See pinned comment for the full write-up

═══════════════════════════════════════════════════
WHO IS THIS FOR
═══════════════════════════════════════════════════

✓ Solo founders shipping their first SaaS
✓ Indie devs vibe-coding with Cursor / v0 / Bolt / Lovable / Replit
✓ Anyone who has ever typed `git add .` and then thought "wait..."
✓ Security-curious devs who want to learn what scanners actually catch
✓ Open-source enthusiasts (Lictor is forever Apache 2.0)

═══════════════════════════════════════════════════
WHO MADE THIS
═══════════════════════════════════════════════════

I'm Raffa, a 20-year cybersec engineer. I got tired of watching small
projects bleed secrets onto GitHub at 3am. So I built Lictor.

One human. 28 security patrols. No team. No funding. No upsell.

The same scanner suite enterprise tools charge $20K/year for — free,
forever.

═══════════════════════════════════════════════════
THE ONLY THING I'M ASKING
═══════════════════════════════════════════════════

If Lictor catches one thing for you that would have ruined your week —
tell one other indie dev about it. Forward this video. Drop it in your
group chat. That's the whole pitch.

Vibe code freely. Just don't ship the keys with it.

═══════════════════════════════════════════════════

#cybersecurity #indiehacker #vibecoding #opensource #secrets #devsecops
#indiedev #solopreneur #github #stripe #aws #infosec #appsec
```

**Notes on the above:**
- **First 2 lines** (before "Show more" cuts off) hook with the 32-leaks number — the most click-worthy stat
- **Timestamps** are placeholders — replace with actual times once you re-watch the video
- **Hashtags at the bottom** — YouTube's algorithm actually uses them; 8-15 is the sweet spot
- **Zero monetization asks** in the body — consistent with the rest of the launch kit
- **The pinned-comment reference** points to the storyteller-pitch blog post as the "go deeper" path

---

## 2. THUMBNAIL GENERATION PROMPT

Paste this into Gemini Imagen / Midjourney / DALL-E / Nano-Banana:

```
Create a YouTube thumbnail, 1280x720 pixels (16:9 landscape).
High contrast, readable at small sizes (mobile feed), click-worthy
but NOT clickbait.

═══ STYLE ═══
- Color palette: deep navy background (#0a0e27), neon teal accent
  (#00ffcc), warning amber (#ffaa00), white headline text
- Aesthetic: indie hacker / security researcher / terminal night-coding
- Subtle scanline texture across background at 5% opacity
- Faint code-rain (Matrix style) at 8% opacity behind elements

═══ LAYOUT ═══

LEFT SIDE (60% of frame):
- Massive headline text, 3 lines, BOLD sans-serif (Inter Black or
  similar), color white:
    "32 LIVE"
    "API KEYS"
    "LEAKED TONIGHT"
- Below headline, in neon teal monospace: "scanned in 5 hours"
- Below that, in amber: "by ONE indie scanner"

RIGHT SIDE (40% of frame):
- A stylized terminal window showing scrolling output:
    [✓] AWS key found
    [✓] Stripe sk_live found
    [✓] Mailchimp key found
- Terminal frame in neon teal with subtle glow
- The text inside should look real and slightly ominous

TOP-RIGHT CORNER:
- Small Lictor wordmark in teal (subtle, ~32px)

BOTTOM-LEFT CORNER:
- Small caption in amber monospace:
    "no team. no funding. just one scanner."

═══ HARD RULES ═══
- NO faces / no photo of a person
- NO commercial / corporate look (no gradients, no glossy buttons,
  no "Pro" badges)
- NO clickbait (no shocked-face emoji, no "YOU WON'T BELIEVE" text,
  no red arrows pointing at things)
- NO donation / sponsor / payment imagery
- The vibe is "competent indie security researcher" not "viral
  influencer"
```

### Alternative thumbnail prompt (simpler, more dramatic)

If you want a starker, more minimal thumbnail:

```
Create a YouTube thumbnail, 1280x720px, 16:9 landscape.

Black background. Dead center: enormous neon-red text "32 LEAKS"
in distressed terminal font. Above it, smaller white text: "TONIGHT".
Below it, smaller neon-teal text: "LICTOR FOUND".

Bottom edge: a single line of teal monospace terminal output that
reads exactly:
"$ ./lictor-ai --scan github  # 1500 commits walked, 32 sk_live hits"

No other elements. No icons. No corporate logo. No faces.
Subtle vertical scanlines across the whole image.
The mood is 3am terminal — quiet, ominous, but not flashy.
```

---

## 3. TITLE VARIANTS (pick the strongest)

A/B test these — YouTube changes recommended titles often. Strongest first:

| Title | Why it works | Risk |
|---|---|---|
| **"I Scanned 1,500 Recent GitHub Commits. Found 32 Live API Keys."** | Specific, factual, the number hooks. No clickbait. | Generic — doesn't mention Lictor. |
| **"Why Vibe-Coded MVPs Leak Production Keys (and What to Do)"** | Targets the vibe-coding audience directly. | Less specific = lower CTR. |
| **"The Indie-Dev Security Gap — and the Free Tool I Built to Close It"** | Frames Lictor as the solution to a known pain. | "Free tool" sounds like marketing. |
| **"My Open-Source Scanner Found 32 Leaked Stripe Keys Tonight"** | Stripe is a specific brand people know — drives clicks. | Slightly stripe-centric. |
| **"32 Live API Keys Leaked in 5 Hours — Don't Be Next"** | Urgency + specific stat + warning. | "Don't be next" leans into fear. |

**My pick: #1.** Specific, factual, scroll-stopping. No fear, no hype, just the number.

---

## 4. YOUTUBE TAGS

Paste these in the Tags field (YouTube allows ~500 chars of comma-separated tags):

```
lictor, lictor ai, lictor security, cybersecurity, indie hacker, vibe coding,
solo founder, opensource security, github secrets, leaked api keys, stripe key
leak, aws key leak, devsecops, infosec, application security, pre-commit hook,
git security, indie dev, indie security tool, secret scanner, github code
search, terraform credentials, dotenv leak, raffa jarrl, apache 2.0, free
security tool, security for startups, mvp security, ai coding tools
```

---

## 5. FIRST PINNED COMMENT (write this yourself right after publishing)

```
🔗 Install Lictor in 5 seconds:

   curl -sSL lictor-ai.com/install-precommit.sh | bash

📝 Full write-up of tonight's 32 leaks (anonymized, no individuals named):
   https://lictor-ai.com/blog/tonight-we-scanned-github
   [replace with your actual blog URL]

📌 The 3 patterns that cause 90% of leaks (from the video):
   1. .env committed before .gitignore
   2. Terraform providers.tf with literal credentials
   3. "Secret" gists shared with contractors — URL leaks forever

GitHub: https://github.com/Raffa-jarrl/Lictor-AI

If Lictor catches one thing for you — the only payment I want is for
you to tell one other indie dev about it.

Vibe code freely. Just don't ship the keys with it.

— Raffa 🌅
```

Pin this comment immediately after publishing. It anchors the conversation, provides the install link to people who don't read descriptions, and reinforces the no-money message.

---

## Suggested launch sequence

1. **Generate thumbnail** with section 2 prompt (5 min)
2. **Upload video** with title "I Scanned 1,500 Recent GitHub Commits. Found 32 Live API Keys."
3. **Paste description** from section 1 (adjust timestamps after re-watching)
4. **Paste tags** from section 4
5. **Upload thumbnail** (custom, not auto-generated)
6. **Set visibility to "Unlisted"** first → share with 3 trusted friends → fix any issues → flip to Public
7. **First-pin a comment** with section 5 right after going public
8. **Cross-post YouTube link** in the Twitter thread (tweet 11 — add it as a reply or update tweet 11)
9. **Add YouTube URL to** the storyteller-pitch blog post + LinkedIn long-form
10. **Sleep**

The video becomes a permanent artifact that all the other content (blog, threads, podcast appearances) can point back to.
