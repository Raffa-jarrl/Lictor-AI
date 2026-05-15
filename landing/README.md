# lictor-ai.com — landing page

Vanilla HTML/CSS, no build step. Drop the contents of this directory on any static host (Vercel, Netlify, Cloudflare Pages, S3 + CloudFront, GitHub Pages).

## What's here

```
landing/
├── index.html              — single-page hero + suite + why + waitlist + founder
├── style.css               — brand palette, mobile-responsive
├── lictor-mark.svg         — primary mark (copied from brand/)
├── lictor-favicon.svg      — favicon (copied from brand/)
├── compliance/
│   ├── index.html          — full SOC 2 / GDPR / EU AI Act / NIST / ISO 42001 mapping
│   └── compliance.css      — TOC + prose layout + print stylesheet
└── README.md               — this file
```

## Deploy

```bash
# Sync from brand/ in case anything changed
cp ../brand/lictor-mark.svg ../brand/lictor-favicon.svg .

# Deploy to any static host:
vercel deploy --prod              # or netlify deploy --prod
# or just drop the directory on Cloudflare Pages
```

## What still needs to happen before launch

1. **Register `lictor-ai.com`** (and `lictor.dev`, `getlictor.com`) via Cloudflare Registrar
2. **Replace the Formspree placeholder** in `index.html` (`action="https://formspree.io/f/REPLACE_ME"`) with a real Formspree form ID or your own email-collection endpoint
3. ~~**Compliance page** at `/compliance`~~ ✅ **DONE** (see `compliance/`)
4. **OG image** (1200×630) — currently the meta tag references one but the file doesn't exist. Could generate from the lockup SVG.

None of these block the page from being usable today — they're polish items for the actual public launch.

## /compliance subpage details

The procurement-team artifact. Two files, vanilla HTML, no build step.

- Desktop: sticky two-column (TOC on the left, prose on the right)
- Mobile: single column, TOC collapses to a card at the top
- **Print stylesheet included** — procurement teams who print these get clean B&W output with all tables and callouts intact

The HTML is hand-written from `~/Lictor/docs/compliance.md`. When the source markdown updates, the HTML page needs to be regenerated (or hand-edited). In lockstep as of 2026-05.

## Tested

- Chrome desktop / Safari desktop / Firefox desktop
- Mobile width breakpoint at 700px works
- All links resolve to either:
  - in-page anchors (`#suite`, `#why`, `#waitlist`)
  - GitHub repo (will be public at launch)
  - `mailto:` for hello@ and security@
