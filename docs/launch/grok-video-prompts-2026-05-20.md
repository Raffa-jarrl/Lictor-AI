# Grok Video Generation Kit — Lictor

Paste-ready prompts for **Grok Imagine / Grok Video** (xAI's text-to-video generator). Most Grok Video outputs are 5-10 seconds and work best with strong visual specificity + cinematography direction.

⚠️ Grok Video constraints to keep in mind:
- ~6 second max clips (chain multiple for longer narratives)
- 9:16 (mobile/short) or 16:9 (landscape) aspect
- Better at atmospheric / abstract / VFX than long dialogue scenes
- Will refuse explicit branding sometimes — use generic "scanner" or "terminal" framing

---

## 🎬 PROMPT 1 — "The 3am Discovery" (atmospheric hero clip)

**Vibe:** lonely researcher catching a leak in the dark. The signature mood piece.

```
Cinematic 6-second clip, 9:16 vertical mobile aspect.

OPENING: Slow push-in on a single mechanical keyboard glowing under
RGB underlight, a developer's hands hovering over it but not typing.
The room is pitch dark except for the monitor glow. It's 3am — visible
clock on the wall reads 3:17.

MID: Camera tilts up to reveal the monitor. The screen shows a terminal
with scrolling text in neon teal. Suddenly one line stops the scroll
in bright amber:

    [!] LEAKED STRIPE KEY DETECTED — sk_live_…

A subtle red glow pulses once across the screen as it's flagged.

END: Quick pull-back. The room is silent. The screen reflects in the
window behind the developer — outside, a sleeping city. A single LED
on the keyboard blinks teal.

Color palette: deep navy + neon teal + warning amber.
Style: cinematic, A24 indie film, Mr. Robot terminal aesthetic.
Audio direction: low ambient hum, single mechanical keyboard click at
the END moment.
```

---

## 🎬 PROMPT 2 — "The Code Rain Reveals" (logo / brand reveal)

**Vibe:** Matrix-style code rain that resolves into the Lictor name.

```
Cinematic 5-second clip, 9:16 vertical.

START: Full-screen falling green-cyan code rain (Matrix style) at high
speed. Letters and numbers, no recognizable words yet.

MID (2-second mark): The code rain begins to slow. Random characters
start FREEZING in place, forming larger glyphs.

END: All falling text has frozen into a single word centered on screen:

    LICTOR

The letters glow softly in neon teal (#00ffcc). Below in a smaller,
calmer font in white:

    open-source. apache 2.0. free forever.

Final frame holds for half a second before fade to black.

Color palette: deep navy + neon teal + faint amber accents.
Style: Mr. Robot title card, retro-cyberpunk minimalism.
Audio direction: digital glitch sounds during the rain, single soft
synth chord on the LICTOR reveal.
```

---

## 🎬 PROMPT 3 — "32 LEAKS / 5 HOURS" (stats reveal)

**Vibe:** kinetic counter going up, builds tension fast, ends on the punchline.

```
Cinematic 6-second clip, 9:16 vertical, mobile-first.

START: Black screen. White monospace text fades in:

    "Lictor walked 1,500 recent GitHub commits."

(holds for 1 second, then text dissolves)

MID: A large counter appears center-screen, neon teal:

    "0 LEAKED"

The number begins counting up rapidly — 0... 7... 14... 21... 28...
— each number flashing briefly in amber before settling. The counter
stops at:

    "32 LEAKED"

(holds, glowing teal)

END (final second): Below the number, smaller white text appears one
line at a time:

    "9 STRIPE."
    "20+ AWS."
    "1 SLACK."

Final frame: amber tagline at the very bottom:

    "all indie devs."

Color palette: deep navy bg, neon teal + warning amber accents.
Style: tech documentary, Tron-esque minimalism, terminal aesthetic.
Audio direction: rhythmic clicking sound for the counter, single bass
hit on "32 LEAKED" reveal.
```

---

## 🎬 PROMPT 4 — "The Pre-Commit Save" (educational hero)

**Vibe:** the moment the scanner catches a leak BEFORE it ships. Hopeful, not scary.

```
Cinematic 6-second clip, 16:9 landscape.

OPENING: Tight shot on a developer's terminal. They type:

    $ git commit -m "first push for SaaS launch"

Camera holds. Cursor blinks. Suddenly the screen FLASHES with a
clear amber overlay and the terminal interrupts:

    ⚠️  LICTOR PRE-COMMIT HOOK
    AWS key detected in .env
    Commit blocked.

The developer's hand pulls back from the keyboard. Their face is
out of frame — just hands, just the screen.

MID: The screen text resolves to teal:

    "Saved you a $14,000 AWS bill tonight."

END: Slow pull-out. The terminal sits quietly. A single line of
text appears at the bottom in white:

    "Lictor — the indie scanner."

Color palette: dark workspace, amber warning + neon teal resolution.
Style: cinematic, Apple-product-launch quality, real-world workflow.
Audio direction: keyboard typing → soft alert chime → silence.
```

---

## 🎬 PROMPT 5 — "Vibe Code Freely" (tagline closer)

**Vibe:** the closing line of the brand campaign. Use as the LAST clip in any chain.

```
Cinematic 5-second clip, 9:16 vertical.

OPENING: Time-lapse footage of a developer typing fast in a dimly-lit
room. Hands blur across a keyboard. Code reflections on glasses, eyes
not visible. Mood: focused, joyful, productive.

MID (2-second mark): Time-lapse slows to real-time. The typing stops.
The developer leans back. The camera pulls away from them and pushes
into the monitor.

The monitor screen fades to deep navy. Center text fades in, large
white sans-serif:

    "Vibe code freely."

(holds 1 second)

Below it in neon teal:

    "Just don't ship the keys with it."

END: Hold. Single soft note. Fade to black.

Color palette: warm workspace lighting (yellows, oranges) → cool navy
+ teal end card.
Style: indie short film, hopeful not dystopian.
Audio direction: rapid typing sounds → silence → single piano note.
```

---

## 🎬 PROMPT 6 — "The Three Patterns" (educational explainer chain)

**Vibe:** A 3-shot sequence — chain these together for a longer educational piece. Each is its own 5-second Grok prompt.

### Shot A — `.env committed`

```
Cinematic 5-second clip, 16:9 landscape.

Close-up on a terminal. Text being typed:

    $ git add .

Pause. A glow appears around the file ".env" in the staged-files
list. Camera zooms in. Below, in red text appearing letter-by-letter:

    "Committed to public repo. Forever."

Hold. Fade out.

Color palette: dark navy, red accent. Style: minimalist tech tutorial.
```

### Shot B — `providers.tf with creds`

```
Cinematic 5-second clip, 16:9 landscape.

A code editor showing a Terraform file:

    provider "aws" {
      access_key = "AKIA..."
      secret_key = "..."
    }

Camera zooms in on the access_key value. The "AKIA..." string begins
GLOWING amber, then flashes red. Text overlays the editor:

    "Indexed by GitHub Code Search in 90 seconds."

Hold. Fade out.

Color palette: editor dark theme, amber + red highlight. Style:
minimal tech tutorial.
```

### Shot C — `secret gist`

```
Cinematic 5-second clip, 16:9 landscape.

A web browser showing a GitHub gist URL bar:

    gist.github.com/.../secret-config

The URL is clearly visible. Camera pulls back to reveal MULTIPLE
hands reaching for the URL from off-screen — like Shutterstock
"hand reaching from darkness" stock footage. Text overlay:

    "'Secret' just means unlisted. Anyone with the URL reads it."

Hold. Fade out.

Color palette: GitHub light theme, dark hands silhouette. Style:
minimal documentary, slightly ominous.
```

---

## 🎬 PROMPT 7 — "One Human, 28 Scanners" (founder story)

**Vibe:** humble, behind-the-scenes feel. Personalizes the project.

```
Cinematic 6-second clip, 16:9 landscape.

OPENING: A wide shot of a small home office at night. One monitor.
One person sitting at a desk, back to camera (no face visible). A
mug of coffee on the desk, the steam curling up.

MID: Camera slowly pushes in toward the monitor. The screen comes
into focus — a Python terminal scrolling thousands of lines of scan
output. The terminal title bar shows:

    patrol-aws-keys.py | patrol-stripe.py | patrol-takeovers.py |
    ...and 25 more

END: Camera continues pushing past the monitor INTO the screen,
through the code, emerging into a black void with a single line of
text:

    "One human. 28 scanners. No team."

Below, in neon teal:

    "github.com/Raffa-jarrl/Lictor-AI"

Color palette: warm desk lighting → cold screen blue → black void
with teal text.
Style: A24 indie documentary, intimate and quiet.
Audio direction: ambient room tone → keyboard clicks → a single
gentle piano chord.
```

---

## 🎞 SUGGESTED CHAINS (combine clips for a longer cut)

### 30-second hero reel (for embedded use on lictor-ai.com homepage)

1. **Prompt 1** (3am Discovery — 6s)
2. **Prompt 3** (32 LEAKS counter — 6s)
3. **Prompt 6A + B + C** (the three patterns — 15s)
4. **Prompt 4** (Pre-Commit Save — 6s)
5. **Prompt 5** (Vibe Code Freely tagline — 5s)
6. **Prompt 2** (Lictor logo reveal — 5s)

= **~43 seconds**, perfect for a homepage hero loop.

### 15-second TikTok / Reels cut

1. **Prompt 3** (32 LEAKS counter — 6s)
2. **Prompt 4** (Pre-Commit Save — 6s)
3. **Prompt 5** (Tagline closer — 3s, trim)

= **~15 seconds**. Optimized for TikTok algorithm.

### 6-second hook for Twitter/X autoplay

Just **Prompt 1** (3am Discovery) alone. Stops the scroll, builds intrigue.

---

## 🛠 PRACTICAL GROK TIPS

| | |
|---|---|
| **Best output settings** | 9:16 for mobile-first social (Twitter, TikTok, Reels) · 16:9 for YouTube/homepage |
| **Iterations** | Each Grok prompt usually needs 3-4 generations to get a usable take. Don't settle on the first. |
| **Style anchors** | Words like "cinematic", "A24", "Mr. Robot", "Tron", "minimal" reliably push Grok toward film aesthetic and away from generic stock |
| **What Grok struggles with** | Realistic faces (use back-of-head, hands-only, or out-of-frame composition) · Specific brand logos (use generic "scanner" / "terminal" framing) · Long readable text on screen (keep text to 3-5 words max per frame) |
| **Stitching multiple clips** | Use CapCut or DaVinci Resolve free version to chain — Grok doesn't export multi-shot sequences natively |
| **Audio** | Grok video is typically silent. Add audio after in CapCut/Resolve. For the Lictor mood: ambient electronic + minimal piano works best. Free libraries: Pixabay, FreePD. |

---

## 🚫 What NOT to ask Grok for

- ❌ Don't ask Grok to reproduce the specific YouTube video you already published — different medium, will fail
- ❌ Don't include real Stripe key prefixes, real AWS access keys, or any real secret strings (Grok will refuse, or worse, the model might generate text that looks like the real key)
- ❌ Don't reference specific company names that Grok recognizes as trademark (xAI itself, OpenAI, Stripe, AWS) — keep it generic
- ❌ Don't ask for a face / likeness of Raffa himself — Grok won't reliably reproduce real people

---

## ✅ Recommended starting prompt (if you only try ONE)

**Use Prompt 3 — "32 LEAKS / 5 HOURS"** as your first generation.

Why: it's punchy, contains the strongest hook stat, requires the least visual complexity (Grok handles text + counters reliably), and works perfectly as a Twitter-autoplay teaser to drive clicks to your YouTube video.

Then iterate from there.
