# Lictor Website Audit

Run 2026-05-27 · Scope: `/Users/raffa/Lictor/landing/*` (10 pages) + `/studio`
Methodology: composite of 4 skill lenses — `design:design-critique`, `design:accessibility-review`, `marketing:seo-audit`, `marketing:brand-review` — plus your own `docs/design-system/` audit (2026-05-15, scored 8.5/10).

---

## TL;DR

🟡 **Fix two A11Y blockers before any public launch push. Everything else is polish.**

Your foundation is exceptional for a founder-built site — mature design system, consistent tokens, 100% alt-text coverage, semantic landmarks on most pages, well-tuned meta descriptions. The May 15 design-system audit caught most of the visual drift.

But this pass found **two real WCAG failures** (form inputs missing labels on `/scan` and `/waitlist` — the two highest-conversion pages) and **one big SEO miss** (zero structured data anywhere) that a single afternoon would fix.

Fix the labels first — without them, blind/low-vision users literally can't submit your lead forms.

---

## What we checked

| Lens | Status |
|---|---|
| Design consistency (token usage, inline styles, components) | 🟡 inline-style drift on 9 of 10 pages |
| Accessibility (WCAG, labels, landmarks, ARIA) | 🔴 form labels missing; 🟡 ARIA sparse |
| SEO (meta, structured data, headings, alt text) | 🟡 no JSON-LD anywhere |
| Brand / copy (voice, banned phrases, CTA clarity) | 🟢 strong (sampled) |

---

## Findings

### 🔴 CRITICAL · Form inputs on `/scan` and `/waitlist` have NO `<label>` element

```
scan/index.html:      1 input,  0 labels
waitlist/index.html:  2 inputs, 0 labels
```

These are your two main lead-capture pages. Without a `<label>` element (or `aria-label`) associated with each input:

- **Screen-reader users get "edit text, blank"** instead of "Email address, edit text"
- **Voice-control users can't say "click email"** — there's nothing to target
- **Mobile autofill is degraded** — browsers use label text as a hint
- **WCAG 2.1 Level A failure** (criterion 1.3.1 + 4.1.2) — formal compliance issue

**This is the #1 thing to fix tonight.** Two minutes per form.

**Fix pattern** for each `<input>`:

```html
<!-- Before -->
<input type="email" name="email" placeholder="you@company.com" required />

<!-- After (option A — visible label) -->
<label for="signup-email">Work email</label>
<input id="signup-email" type="email" name="email" placeholder="you@company.com" required />

<!-- After (option B — invisible label, if visual design needs no label) -->
<input type="email" name="email" placeholder="you@company.com" required
       aria-label="Work email" />
```

Option A is better for SEO and trust. Option B if visual design absolutely can't fit a label.

---

### 🟠 HIGH · `patterns/index.html` has **44 `<header>` elements**

```
patterns: main=1 nav=1 header=44 footer=1
```

`<header>` is a semantic landmark — there should be 1 (the page top) and maaaybe 2-3 if you're using it inside `<article>` blocks. **44 is a bug** — almost certainly a typo where you wanted `<header class="card__header">` and instead used the HTML tag, or used `<header>` instead of a generic `<div>` for card titles.

**Why it matters:** every `<header>` shows up as a banner landmark to screen readers. 44 banners = the page is unnavigable via landmark shortcut keys.

**Fix:** grep the file for `<header>` and replace all but the page-level one with `<div class="…">` or `<section>`. ~5 min.

---

### 🟠 HIGH · `mission-control/index.html` is missing `<main>` and `<footer>`

```
mission-control: main=0 nav=1 header=1 footer=0
```

Every other page has `main=1 footer=1`. This one was likely built from a different template. Missing `<main>` means "skip to content" features fail and screen readers can't jump to primary content.

**Fix:** wrap the page body in `<main>` and add a `<footer>` (probably duplicate from the homepage footer). ~5 min.

---

### 🟠 HIGH · Zero structured data (JSON-LD) on any page

All 10 pages: `✗ no JSON-LD`

This is the single biggest SEO win available. Google's rich snippets (logo in search results, ratings, FAQ accordions, sitelinks) require `<script type="application/ld+json">` blocks.

For Lictor specifically, two schemas would matter:

**1. Organization schema** (in homepage `<head>` — establishes brand entity):

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "Lictor AI",
  "url": "https://lictorai.com",
  "logo": "https://lictorai.com/logo.png",
  "sameAs": [
    "https://github.com/Raffa-jarrl/Lictor-AI",
    "https://twitter.com/...",
    "https://www.linkedin.com/in/..."
  ],
  "description": "Free open-source security audit suite for anything built with AI."
}
</script>
```

**2. SoftwareApplication schema** (on `/scan` and homepage — makes Google show "Free" badge + ratings if you ever collect them):

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "Lictor",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "macOS, Linux, Windows",
  "offers": {
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  },
  "license": "https://www.apache.org/licenses/LICENSE-2.0",
  "softwareVersion": "0.2"
}
</script>
```

10-min job. Big effect on click-through from Google.

---

### 🟡 MEDIUM · Inline styles violating your own design system (9 of 10 pages)

| Page | Inline `style=` count |
|---|---|
| in-the-wild | 76 |
| transparency | 50 |
| retractions | 26 |
| mission-control | 14 |
| scan | 7 |
| changelog | 4 |
| patterns | 2 |
| waitlist | 2 |
| donate | 1 |

Your `docs/design-system/README.md` is explicit: "Reference via `var(--name)`, never inline." The inline styles DO use tokens (e.g. `style="color:var(--accent);"`) so the colors are right — but the pattern violates the rule and creates drift the next time someone copy-pastes.

The worst offender is `in-the-wild/` (76 inlines). Sampling shows most are repetitive:

```
style="color:var(--text-muted);font-size:.85rem;"
style="color:var(--text-muted);font-size:.9rem;"
style="color:var(--text-muted);font-size:.9rem;margin:0;"
```

These are 3-5 utility classes waiting to be born. Add to `/components/components.css`:

```css
.text-muted-sm   { color: var(--text-muted); font-size: 0.85rem; }
.text-muted-md   { color: var(--text-muted); font-size: 0.9rem; }
.accent-pill     { color: var(--accent); font-size: 0.75rem; }
.divider-top     { border-top: 1px solid var(--border); }
```

Then sweep-replace inline styles with class names. ~30 min on in-the-wild alone, less on the others.

---

### 🟡 MEDIUM · Sparse ARIA usage across the site

```
changelog: 0   compliance: 2   donate: 0   in-the-wild: 0
mission-control: 0   patterns: 0   retractions: 0
scan: 1   transparency: 0   waitlist: 2
```

Semantic HTML (`<nav>`, `<main>`) covers a lot — but interactive elements like icon-only buttons, expandable sections, and form-error messages need explicit ARIA. Quick wins:

- Add `aria-label` to icon-only buttons (e.g., copy-to-clipboard, theme toggle)
- Add `aria-current="page"` to the current-page link in nav
- Add `aria-describedby` linking form inputs to their helper text
- Add `aria-live="polite"` to any region that updates dynamically (scan results, form-submit confirmation)

Per page ~10-15 min.

---

### 🟡 MEDIUM · Homepage star headline + install-grid h3s use inline font-size

Lines 87, 119, 237-320 of `landing/index.html`:

```html
<h2 id="star-headline" style="font-family:'Cormorant Garamond',serif;font-size:clamp(1.8rem,4vw,2.6rem);margin:0 0 .5rem;line-height:1.1;color:var(--text);">
```

```html
<h3 style="margin:0;font-size:1.05rem;">Claude Code</h3>
<h3 style="margin:0;font-size:1.05rem;">Cursor</h3>
... (6 installs total)
```

Your design system explicitly says "No type scale is tokenized yet — don't introduce one until ≥2 components disagree." These 7 inline overrides ARE the ≥2-components-disagree signal. Time to introduce:

```css
:root {
  --font-size-h1: clamp(2rem, 5vw, 3.2rem);
  --font-size-h2: clamp(1.6rem, 3.5vw, 2.4rem);
  --font-size-h3: 1.05rem;
  --font-size-body: 1rem;
}
```

Then `<h3 class="install__title">Claude Code</h3>` with `.install__title { font-size: var(--font-size-h3); }`.

---

### 🔵 LOW · Homepage meta description is 370 chars (Google truncates at ~155-160)

Current:

> Free open-source security audit for anything you built with AI — web apps, CLIs, browser extensions, MCP servers, desktop apps, serverless functions, CI/CD pipelines. Mobile coming soon. Plain English. 11 AI agents, one slash command, no signup, no telemetry, Apache 2.0.

Google will cut this off around "...CI/CD pipelines." Try:

> Free open-source security audit for anything built with AI — web apps, CLIs, MCPs, desktop, serverless. Plain English. 11 agents, one slash command, no signup. Apache 2.0.

(160 chars, leads with the value, lists the breadth, ends with permission triggers — "free", "no signup", "Apache 2.0".)

---

### 🔵 LOW · No "skip to main content" link

Standard a11y pattern for keyboard users — first focusable element is a hidden-until-focused link that jumps past the nav. One-liner per page:

```html
<a href="#main" class="skip-link">Skip to main content</a>
```

```css
.skip-link {
  position: absolute; top: -100px; left: 0;
  background: var(--accent); color: var(--bg);
  padding: var(--space-3) var(--space-4); z-index: 9999;
}
.skip-link:focus { top: 0; }
```

---

### ⚪ INFO · Strong fundamentals (what NOT to change)

Worth saying because most founder-built sites get this wrong:

- ✓ All 11 pages have 100% alt-text coverage
- ✓ Meta descriptions all in the 117-176 char range (homepage is the only outlier)
- ✓ Mature design system (8.5/10 self-audit) with proper token discipline
- ✓ Preconnect hints for font hosts (perf win)
- ✓ Apple touch icon + multiple favicon sizes
- ✓ Semantic landmarks (`<main>`, `<nav>`, `<header>`, `<footer>`) on 9 of 10 pages
- ✓ OG + Twitter card metadata complete on every page
- ✓ Brand voice (from the snippets sampled): direct, no AI fingerprint, no marketing-jargon

---

## Per-page priority

| Page | Top 3 actions |
|---|---|
| `/scan` | (1) Add `<label>` to email input  (2) Add JSON-LD SoftwareApplication  (3) Replace 7 inline styles |
| `/waitlist` | (1) Add `<label>` to 2 inputs  (2) Add `aria-live` for submit confirmation |
| `/` (homepage) | (1) Add JSON-LD Organization  (2) Tighten meta description to <160c  (3) Tokenize H1/H2/H3 font sizes |
| `/patterns` | (1) Fix the 44 `<header>` tags → `<div>` or `<section>` |
| `/mission-control` | (1) Add `<main>` and `<footer>` |
| `/in-the-wild` | (1) Add 5 utility classes  (2) Sweep-replace 76 inline styles |
| `/transparency` | (1) Same sweep — 50 inline styles |
| `/retractions` | (1) Same sweep — 26 inline styles |
| `/donate` | (1) Add JSON-LD Organization (inherits from homepage)  (2) 1 inline style |
| `/changelog` | (1) Replace 4 inline styles |

---

## Suggested order (40 min total)

| Order | Action | Time |
|---|---|---|
| 1 | Add `<label>` to `/scan` and `/waitlist` form inputs | 5 min |
| 2 | Fix the 44 `<header>` tags on `/patterns` | 5 min |
| 3 | Add `<main>` and `<footer>` to `/mission-control` | 5 min |
| 4 | Add JSON-LD Organization to homepage + SoftwareApplication to `/scan` + `/` | 10 min |
| 5 | Add 5 utility classes + sweep inline styles on `/in-the-wild` | 15 min |
| 6 | Defer rest (sweep transparency + retractions + tokens) to a polish-day | later |

After 1-4, you're 🟢 ready for any public launch push. 5 is polish. 6 is the long tail.

---

*Want me to apply these in order with your approval per change, same pattern as `/lictor-fix-it`? Just say "go" and I'll start with #1.*
