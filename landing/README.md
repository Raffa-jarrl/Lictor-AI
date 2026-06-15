# lictor-ai.com — landing site

Vanilla HTML/CSS plus a thin layer of Cloudflare Pages Functions. **No build
step** for the pages themselves — the HTML/CSS/JS ship as-is. The dynamic bits
(waitlist capture, passive scanner) run as Pages Functions on Cloudflare.

Deploy target: **Cloudflare Pages** (the Functions + `_headers` + `_redirects`
are Pages-specific). A plain static host will serve the marketing pages but
`/api/*` won't work there.

## What's here

```
landing/
├── index.html              — single-page hero + suite + why + waitlist + founder
├── style.css / security.css / codex.css — brand palette, mobile-responsive
├── coming-soon.html        — friendly stub for not-yet-shipped routes
├── business.html           — business-tier page
├── scan/                   — public passive-scanner UI (scan/index.html, scan.js)
├── waitlist/               — Buttondown-embed waitlist page (+ translations/)
├── compliance/             — SOC 2 / GDPR / EU AI Act / NIST / ISO 42001 mapping
├── changelog/ transparency/ mission-control/ — live GitHub-fed dashboards
├── static/                 — shared JS/CSS (fx, a11y, waitlist, copy, etc.)
├── og/og-image.png         — 1200×630 social card (referenced by index.html)
├── functions/              — Cloudflare Pages Functions (see below)
│   ├── api/waitlist.js      — POST capture + admin GET  (KV-backed)
│   ├── api/scan.js          — POST passive scan + GET health
│   └── _lib/                — waitlist-core.mjs + scan-core.mjs (unit-tested logic)
├── _headers                — security headers incl. CSP (no 'unsafe-inline' JS)
├── _redirects              — clean-URL + coming-soon routing
└── _routes.json            — restricts Functions invocation to /api/*
```

## Waitlist (real, KV-backed — not Formspree)

The waitlist is **self-hosted on Cloudflare**, not a third-party form service.

- **Endpoint:** `POST /api/waitlist` → `functions/api/waitlist.js` →
  `functions/_lib/waitlist-core.mjs`.
- **Storage:** a Cloudflare **KV namespace bound as `WAITLIST`**. Each signup is
  one key `wl:<product>:<lowercased-email>` with a small JSON value
  (`{ email, product, use_case, ts }`). Emails are lowercased and de-duped
  case-insensitively. `<product>` is whitelisted; unknown products fall back to
  the `lictor` bucket.
- **No-JS path:** the home-page form (`index.html`, `action="/api/waitlist"`,
  `method="post"`) works with JavaScript disabled — a plain form POST returns a
  `303` redirect back with `?subscribed=1`, and `static/waitlist.js` renders the
  same thank-you on load when it sees that param. With JS on, `waitlist.js`
  intercepts submit and posts JSON instead (no full-page reload).
- **Open-redirect safe:** the `redirect` field is forced back to the same host.
- **Fails loud:** if the `WAITLIST` binding is missing the endpoint returns
  `503 storage_unavailable` rather than silently dropping a signup.
- **Admin read:** `GET /api/waitlist?token=<ADMIN_TOKEN>&product=<p>` returns a
  count (and list). Requires `env.ADMIN_TOKEN`; without a valid token → `401`.

> The `waitlist/` page (and its `es` / `pt-BR` translations) is a **separate**
> Buttondown-embed form, kept as an email-list fallback. It posts to Buttondown
> and is allowed by the CSP `form-action` / `connect-src`. Activating it needs a
> Buttondown account (see the comment block at the top of `waitlist/index.html`).

### Test the waitlist logic

A unit test exercises the core against an in-memory KV (no network, no deploy):

```bash
node scripts/test-waitlist-fn.mjs    # run from the repo root
```

## Passive scanner

`/scan` (UI) → `POST /api/scan` → `functions/api/scan.js` →
`functions/_lib/scan-core.mjs`. It runs a **passive, same-origin** scorecard of
a submitted URL (security headers, exposed config signatures, etc.). `GET
/api/scan` is a health check. The optional `WAITLIST` KV is reused for per-IP
rate limiting and opt-in anonymous telemetry.

## Security headers / CSP

`_headers` ships the same hardening the scanner checks for (CSP,
Permissions-Policy, HSTS, nosniff, frame-deny, referrer policy).

- **`script-src 'self' https://cdnjs.cloudflare.com`** — **no `'unsafe-inline'`**.
  Every page script is an external file; the former inline `onsubmit`/`onclick`
  handlers and inline `<script>` blocks were refactored to `addEventListener`
  in `static/*.js` (and per-page `*.js`). The only remote script origin is
  cdnjs (Three.js for the `/mission-control` background).
- `style-src` still allows `'unsafe-inline'` (per-element `style=""` + a few
  `<style>` blocks). That's a separate, lower-risk hardening item — no script
  execution — and is noted inline in `_headers`.
- The live GitHub star/commit widgets call `api.github.com` and load avatars
  from `avatars.githubusercontent.com`. Those origins are **not** in
  `connect-src` / `img-src` yet, so the widgets **fail closed** (degrade to a
  dash or a "view on GitHub" link). To enable them, add the two origins as noted
  in `_headers`.

## Deploy (Cloudflare Pages)

```bash
# From this directory — deploy the static assets + Functions:
npx wrangler pages deploy . --project-name lictor-ai
# (or connect the repo in the Cloudflare dashboard for git-push deploys)
```

Required Pages bindings on the **production** project:

- **KV namespace `WAITLIST`** — bound to both Production and Preview.
- **Environment variable `ADMIN_TOKEN`** — secret, for the admin waitlist read.

## /compliance subpage

The procurement-team artifact. Vanilla HTML, no build step.

- Desktop: sticky two-column (TOC left, prose right); Mobile: single column.
- **Print stylesheet included** for procurement teams who print it.

Hand-written from `~/Lictor/docs/compliance.md`; regenerate the HTML when the
source markdown changes.

## Before public launch (owner-gated)

These need the owner's credentials / accounts and are **not** done here:

1. **Register `lictor-ai.com`** and point DNS at the Pages project.
2. **Bind `WAITLIST` KV + `ADMIN_TOKEN`** on the **production** Pages project
   (without the KV binding the waitlist returns `503` by design).
3. **Flip the GitHub repo public** (links already point at the public repo).
4. *(Optional)* activate the Buttondown form and/or light up the GitHub
   live-data widgets by widening `connect-src`/`img-src` as noted in `_headers`.

## Tested

- Chrome / Safari / Firefox desktop; mobile breakpoint at 700px.
- Waitlist core: `node scripts/test-waitlist-fn.mjs` (in-memory KV, 15 cases).
- All links resolve to in-page anchors, the public GitHub repo, or `mailto:`.
