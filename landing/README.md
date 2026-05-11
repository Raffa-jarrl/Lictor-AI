# lictor.ai — landing page

Vanilla HTML/CSS, no build step. Drop the contents of this directory on any static host (Vercel, Netlify, Cloudflare Pages, S3 + CloudFront, GitHub Pages).

## What's here

```
landing/
├── index.html          — single-page hero + suite + why + waitlist + founder
├── style.css           — brand palette, mobile-responsive
├── lictor-mark.svg     — primary mark (copied from brand/)
├── lictor-favicon.svg  — favicon (copied from brand/)
└── README.md           — this file
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

1. **Register `lictor.ai`** (and `lictor.dev`, `getlictor.com`) via Cloudflare Registrar
2. **Replace the Formspree placeholder** in `index.html` (`action="https://formspree.io/f/REPLACE_ME"`) with a real Formspree form ID or your own email-collection endpoint
3. **Compliance page** at `/compliance` (we have the source content in `docs/compliance.md` — just need to render it; can be markdown-to-HTML at build, or sub-page in same vanilla style)
4. **OG image** (1200×630) — currently the meta tag references one but the file doesn't exist. Could generate from the lockup SVG.

None of these block the page from being usable today — they're polish items for the actual public launch.

## Tested

- Chrome desktop / Safari desktop / Firefox desktop
- Mobile width breakpoint at 700px works
- All links resolve to either:
  - in-page anchors (`#suite`, `#why`, `#waitlist`)
  - GitHub repo (will be public at launch)
  - `mailto:` for hello@ and security@
