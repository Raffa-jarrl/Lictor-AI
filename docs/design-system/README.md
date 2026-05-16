# Lictor Design System — canonical reference

> **Status:** living document, established 2026-05-15. Source of truth for every visual surface that carries the Lictor wordmark.
> **Audience:** anyone (or any agent) producing a Lictor visual — Quill, Reel, Translator, designers, future contractors.
> **Source CSS:** [`landing/style.css`](../../landing/style.css) is the canonical token + base-style file. Page-specific stylesheets (`landing/waitlist/waitlist.css`, etc.) reference these tokens — never redefine them.

---

## Audit — 2026-05-15

### Surfaces in scope

| Surface | File | Status |
|---|---|---|
| Marketing homepage | `landing/index.html` | ✅ Uses tokens consistently |
| `/compliance` | `landing/compliance/index.html` | ✅ Uses tokens |
| Beacon waitlist (EN) | `landing/waitlist/index.html` | ✅ Now uses `/waitlist/waitlist.css` (was inline `<style>`) |
| Beacon waitlist (ES) | `landing/translations/es/waitlist.html` | ✅ Links to `/waitlist/waitlist.css` (which now exists) |
| Beacon waitlist (PT-BR) | `landing/translations/pt-BR/waitlist.html` | ✅ Same |
| Course landing (separate biz) | `~/GenerationAI/landing/course/index.html` | ⚠️ **OUT OF SCOPE** — separate brand (consulting), uses different palette (purple gradient `#7c3aed → #06b6d4`). Don't reconcile. |

### Issues found and fixed in this audit

| # | Severity | Issue | Fix landed |
|---|---|---|---|
| 1 | 🟠 HIGH | ES + PT-BR waitlist translations linked to `/waitlist/waitlist.css` — **file did not exist**. Pages would silently fall back to unstyled content for non-English visitors. | Extracted inline `<style>` from `waitlist/index.html` into `waitlist/waitlist.css`; all three locales now resolve. |
| 2 | 🟡 MED | One hardcoded hex (`#d8b04a`) for the gold-button hover state in the Beacon form. Drifts independently from `--accent` if anyone tweaks the brand. | Promoted to `--accent-hover` token. |
| 3 | 🟡 MED | Tint colors (button-eyebrow background `rgba(201, 162, 59, 0.10)` and border `rgba(201, 162, 59, 0.30)`) were RGB-literal hardcodes. Same drift risk. | Promoted to `--accent-tint` and `--accent-tint-strong`. |
| 4 | 🔵 LOW | No spacing scale, no radius scale, no motion tokens. Every component shipped with arbitrary px / rem values. | Added scales: `--space-1` through `--space-10`, `--radius-{sm,md,lg,pill}`, `--motion-{fast,base,slow}`. Existing code unchanged; new components must use the scale. |
| 5 | 🔵 LOW | `waitlist/index.html` had ~280 lines of inline `<style>` that duplicated patterns reusable across surfaces (stat cards, form inputs, eyebrow pills). | Moved to `waitlist.css`. Inline block left commented-out as a delete-on-next-pass marker. |
| 6 | ⚪ INFO | No documented severity-badge component, but multiple surfaces will render security findings (audit reports, Studio, Mission Control public pages). Drift incoming. | New component spec shipped (see below). |

### Score

**8.5 / 10.** Token discipline was already strong (10 named CSS variables, used everywhere except the 4 issues above). The main gap was completeness, not consistency.

---

## Tokens

All token values live in `landing/style.css` under `:root`. Reference via `var(--name)`, never inline.

### Color

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0F1419` (Charcoal) | Page background |
| `--surface` | `#1A2028` | Cards, code blocks, raised surfaces |
| `--surface-2` | `#232B36` | Hovered card / nested surface |
| `--text` | `#E8E2D5` (Bone) | Primary text |
| `--text-muted` | `#6E7780` | Secondary text, captions, meta |
| `--accent` | `#C9A23B` (Gold Leaf) | Highlights, links, buttons, brand mark |
| `--accent-hover` | `#D8B04A` | Hover state on gold buttons + accents |
| `--accent-tint` | `rgba(201,162,59,0.10)` | Faint gold background (pills, eyebrow) |
| `--accent-tint-strong` | `rgba(201,162,59,0.30)` | Border on gold-tinted bg |
| `--primary` | `#3D2C5E` (Imperial Purple) | Secondary brand color, deep CTA bg |
| `--primary-2` | `#5A4280` | Lighter purple, hover/active on primary |
| `--critical` | `#C0392B` | 🔴 Critical severity findings |
| `--warning` | `#D68910` | 🟠 High severity findings |
| `--success` | `#3D7C5E` | ✅ Pass states, all-clear |
| `--critical-tint` | `rgba(192,57,43,0.12)` | Background under critical-text |
| `--warning-tint` | `rgba(214,137,16,0.12)` | Background under warning-text |
| `--success-tint` | `rgba(61,124,94,0.14)` | Background under success-text |
| `--info-tint` | `rgba(110,119,128,0.14)` | Background under muted/info-text |
| `--border` | `#2A323E` | Default border |
| `--border-light` | `#3A4250` | Emphasized border (focused/hovered) |

### Typography

Three families, all loaded from Google Fonts in every page that uses them:

| Family | Weights | Use |
|---|---|---|
| **Cormorant Garamond** | 500, 700 | Display: `h1`, `h2`, hero titles, stat values, `<em>` inside hero titles |
| **Inter** | 400, 500, 600, 700 | Body, navigation, paragraph copy. Default `<body>` font. |
| **JetBrains Mono** | 400, 500 | Eyebrows, captions, code, footer meta, anything that needs "this is a system message" feel |

No type scale is tokenized yet — sizes are inlined as `clamp(...)` or `rem` values per component. **Don't introduce a numeric size scale until ≥2 components disagree** on what "h2" means. Premature scaling becomes its own form of drift.

### Spacing

4px base. Use these tokens in any new CSS; existing files weren't backfilled.

| Token | Value | Common use |
|---|---|---|
| `--space-1` | 4px | Tight inline gaps |
| `--space-2` | 8px | Icon-to-text |
| `--space-3` | 12px | Form-input internal padding |
| `--space-4` | 16px | Card padding, default block spacing |
| `--space-5` | 24px | Section sub-spacing |
| `--space-6` | 32px | Card-to-card gap |
| `--space-8` | 48px | Section spacing |
| `--space-10` | 64px | Hero / band spacing |

### Borders

| Token | Value | Use |
|---|---|---|
| `--radius-sm` | 4px | Inline tags, small inputs |
| `--radius-md` | 8px | Buttons, inputs, list items |
| `--radius-lg` | 12px | Cards, stat tiles |
| `--radius-pill` | 999px | Eyebrows, severity badges, status chips |

### Motion

| Token | Value | Use |
|---|---|---|
| `--motion-fast` | 0.05s ease | Active-state press effects (scale(0.98)) |
| `--motion-base` | 0.15s ease | Hover transitions on color/border |
| `--motion-slow` | 0.30s ease | Reveal animations, drawer slides |

### Shadows

**Intentionally not tokenized.** The Lictor design language is flat. Surfaces stack via background + border, never via shadow. If you find yourself reaching for `box-shadow`, you're probably solving the wrong problem — pick a different surface token instead.

---

## Components — current

These exist in `landing/style.css` and the per-page stylesheets. Brief reference; details in the source.

| Component | Where defined | Variants | States |
|---|---|---|---|
| **Nav bar** | `style.css .nav` | (single) | scroll-shadow on scroll (TODO) |
| **Brand wordmark** | `style.css .brand` | (single) | hover: no underline (overrides default `a:hover`) |
| **Button** | `style.css .btn` | `.btn--primary` (gold), `.btn--ghost` (outline) | hover, active |
| **Section heading** | `style.css .section__title` | (single) | — |
| **Card** | `style.css .card` | `.card--shield`, `.card--sentinel` (per-product accent) | hover (lift via border-color) |
| **Code block** | `style.css .card__code` | Inside cards only | — |
| **Link** | `style.css a` | `.link` (gold + 500 weight) | hover: underline |
| **Form input** | `waitlist.css .waitlist-form input` | email, select | focus (gold border) |
| **Form button** | `waitlist.css .waitlist-form button` | (single) | hover, active (scale 0.98) |
| **Stat tile** | `waitlist.css .waitlist-stat` | (single) | — |
| **Eyebrow pill** | `waitlist.css .waitlist-hero__eyebrow` | (single) | — |
| **Checklist item** | `waitlist.css .waitlist-checks li` | (single) | — |

---

## Components — new in this audit

### SeverityBadge (4-level severity indicator)

→ See [`components/severity-badge.md`](./components/severity-badge.md)

Why it matters: `/lictor-security-check` produces findings tagged Critical / High / Medium / Low / Info, which are rendered in:

- `SECURITY-AUDIT.md` (markdown — currently emoji-prefix only)
- Lictor Studio (Tauri desktop — currently inline span)
- Future Mission Control public pages
- The launch teardown drafts (currently emoji-prefix + bold)
- Eventually: the dashboard at `lictorai.com/transparency`

Standardizing this **before** the surfaces multiply prevents the "every product page renders severity differently" disease that hits OSS projects at year 1.

---

## Roadmap — what to build next

In priority order. Each gets its own `components/<name>.md` spec when started.

1. **FindingCard** — wraps a severity badge + title + body + "fix in N minutes" footer. Used in audit reports + Studio + transparency reports. Currently rendered ad-hoc in markdown headings.
2. **CrewBadge** — attributes work to a specific agent (🎼 Conductor, 📡 Radar, 🔍 Sieve, etc.). Used in monthly transparency reports + the public agent-roster page (not built yet).
3. **MetricTile** — stat-card variant for the upcoming `lictorai.com/transparency` page. Differs from `.waitlist-stat` by adding a delta-vs-last-period footer.
4. **PromiseBlock** — already exists as `.waitlist-promise` inline; promote to global component so the Studio + dashboard + landing variants don't drift.

---

## Rules

1. **Reference tokens, never inline values.** Every new file uses `var(--name)`. The exception is the 4 base Google Font names (Cormorant Garamond / Inter / JetBrains Mono) which are font-family strings, not tokens.
2. **No new color is allowed without justification.** If you need a color that's not in the token set, write it into `style.css` as a token first, then use it. Don't anonymously hex.
3. **Components live in their own stylesheet, never page-inline.** The pattern set this audit: `<page>/<page>.css` next to `<page>/index.html`. Inline `<style>` is for one-off documents and prototypes only.
4. **Don't reconcile generationai.com.** It's a separate brand (consulting). Different palette, different fonts, deliberately distinct.
5. **Don't introduce shadows.** Flat surfaces only — restate the rule above.
