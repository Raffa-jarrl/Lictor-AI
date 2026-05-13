# Sprint 1 launch playbook — what's left

> **Updated:** 2026-05-13, after Claude shipped the Sprint 1 P1 work.
> **Status today:** Repo is on GitHub (private). CI is wired and green locally. Landing site + skills + 4 products all ready to publish. **Six manual actions left** — total estimated time **~70 minutes spread over the week.**

This file is the literal runbook. Each section is one task. Each task has:

1. **What to do** — exact commands or button paths
2. **Estimated time** — be honest with yourself
3. **Verify** — how you know it worked

Work top-to-bott2. Don't skip ahead. The order is the dependency chain.

---

## 1. Register the domains (15 min)

Cloudflare Registrar is the cheapest + cleanest option (at-cost pricing, free WHOIS privacy, no upsell).

1. Open https://dash.cloudflare.com → **Domain Registration** → **Register Domains**
2. Search `lictor.ai`. Add to cart.
3. Add `lictor.dev`. Add to cart.
4. Add `getlictor.com`. Add to cart. (Insurance — `lictor.ai` could get sold to a competitor; this gives you a fallback name.)
5. Choose **2-year registration** for each (current pricing: ~$60-90 total)
6. Set DNS to Cloudflare nameservers (default, just confirm)
7. Pay. Get the confirmation email.

**Verify:**

```bash
dig lictor.ai NS +short
# Should show 2 Cloudflare nameservers
```

---

## 2. Create the `lictor-ai` GitHub organization (5 min)

The repo is currently at `github.com/Raffa-jarrl/lictor`. Long-term it should live under a `lictor-ai` org. (GitHub doesn't let you create orgs via API — must be done in the UI.)

1. Open https://github.com/account/organizations/new
2. Plan: **Free** (we're under 5 collaborators)
3. Name: **lictor-ai**
4. Contact email: `hello@lictor.ai` (or your personal — switch later)
5. This org belongs to: **My personal account**
6. (Skip the "invite members" page; you can add later)

Then transfer the repo:

```bash
gh repo transfer Raffa-jarrl/lictor lictor-ai
# Or via UI: github.com/Raffa-jarrl/lictor → Settings → bottom → Transfer
```

GitHub auto-redirects the old URL, so no broken links anywhere.

**Verify:**

```bash
gh repo view lictor-ai/lictor --json url 2>/dev/null
```

---

## 3. Reserve npm + PyPI namespaces (15 min)

Lock in `@lictor` on npm and `lictor-sentinel` on PyPI before anyone else takes them.

### npm

```bash
# Login (or sign up at npmjs.com first — needs an email account)
npm login

# Create the @lictor org (free for open source)
npm org create lictor

# Publish the alpha — pre-release tag so it doesn't show as latest
cd ~/Code/lictor/sentinel
pnpm publish --access public --tag alpha
```

If `pnpm publish` complains about uncommitted changes, use `pnpm publish --no-git-checks --access public --tag alpha`.

**Verify:**

```bash
npm view @lictor/sentinel
# Should show 0.1.0-alpha.0
```

### PyPI

```bash
# Sign up at pypi.org if you haven't (with 2FA — required for new accounts)
# Generate an API token: pypi.org → Account settings → Add API token (scoped to "lictor-sentinel" once it exists; "all projects" for the first publish)

# Install twine
pip install --user twine

# Build (already done by you or by CI — but to be safe)
cd ~/Code/lictor/sentinel-py
python3 -m build

# Upload
python3 -m twine upload dist/lictor_sentinel-0.1.0a0*
```

When twine asks for credentials, paste your API token as the password and use `__token__` as the username.

**Verify:**

```bash
pip install lictor-sentinel==0.1.0a0
python3 -c "from lictor_sentinel import wrap, SENTINEL_VERSION; print(SENTINEL_VERSION)"
# Should print: 0.1.0a0
```

---

## 4. Reserve Twitter / X + LinkedIn (10 min)

### Twitter / X

1. Open https://twitter.com/i/flow/signup (or create from your existing account → Settings → Add Account)
2. **Username:** `lictor_ai` (or `getlictor` if `lictor_ai` is taken)
3. **Display name:** `Lictor AI`
4. **Bio:** see `docs/launch/social-bios.md`
5. **Profile picture:** upload `brand/lictor-mark.svg` rendered as PNG (use `landing/og/og-image.png` for the header, or render a 400×400 from `lictor-mark.svg`)
6. **Pinned tweet:** none yet — wait until Sprint 2 to post the first warm-up tweet

### LinkedIn

1. Open https://www.linkedin.com/company/setup/new/
2. Company type: **Self-employed** or **Small business**
3. **Company name:** Lictor AI
4. **Public URL:** linkedin.com/company/lictor-ai
5. **Industry:** Computer & Network Security
6. **Company size:** 1
7. **About:** see `docs/launch/social-bios.md`
8. **Logo:** `brand/icon-512.png`

**Verify:** open both URLs in an incognito window. Profile picture should render. Bio should be readable.

---

## 5. Deploy the landing site to Cloudflare Pages (10 min)

Cloudflare Pages is free, integrates with the repo + the domain in one place.

1. Open https://dash.cloudflare.com → **Workers & Pages** → **Create application** → **Pages** → **Connect to Git**
2. Authorize the Cloudflare GitHub app on the `lictor-ai/lictor` repo (it'll redirect to GitHub, approve, come back)
3. **Project name:** `lictor-landing` (no spaces, all lowercase)
4. **Production branch:** `main`
5. **Build settings:**
   - Framework preset: **None** (vanilla HTML)
   - Build command: *(leave empty)*
   - Build output directory: `landing`
6. **Environment variables:** none
7. Click **Save and Deploy**

After it builds (~30 seconds for static HTML):

1. **Custom domains** → **Set up a custom domain** → `lictor.ai`
2. Cloudflare auto-configures the DNS record (since you registered the domain through Cloudflare)
3. Wait ~30 seconds for the certificate

**Verify:**

```bash
curl -I https://lictor.ai
# Should return 200, served by Cloudflare
curl -I https://lictor.ai/compliance/
# Should also return 200
```

Open https://lictor.ai in a browser and confirm:
- The hero renders
- The /compliance link in the nav works
- Sharing the URL on Slack/Twitter shows the OG image (the lockup with the gold mark)

---

## 6. Email 5 design-partner candidates (15 min)

The full email drafts are in [`docs/launch/design-partner-outreach.md`](./docs/launch/design-partner-outreach.md). Each is personalized.

1. Pick 5 names from your network or course alumni (prioritize: anyone who's recently launched an AI-built SaaS, anyone who's complained about AI security publicly, anyone who runs a small dev team)
2. Open the outreach doc, copy the relevant template, customize the first line per recipient
3. Send via your normal email client (NOT bcc — one personal message per recipient)
4. Track responses in a simple spreadsheet or doc

Don't expect 5/5 response rates. Plan for 60% — if you email 5 and get 3 confirmed, you're at target. If you get 1 or 2, email 3 more from a second-tier list.

**Verify:** 5 emails sent. Spreadsheet started with one row per recipient.

---

## After all 6 are done

You'll be in this state:

- `lictor.ai` resolves to the landing page (HTTPS, OG image working)
- `lictor.ai/compliance` renders the full SOC2/GDPR/EU-AI-Act mapping
- `github.com/lictor-ai/lictor` is a private repo with CI green on every push
- `@lictor/sentinel@0.1.0-alpha.0` installable from npm
- `lictor-sentinel==0.1.0a0` installable from PyPI
- `@lictor_ai` Twitter + Lictor AI LinkedIn pages live (no content yet)
- 5 emails out to design partners, ~3 expected to confirm by end of sprint

**That's the entire Sprint 1 goal.** When you're here, run `/lictor-sprint-retro` (or just message me) and we'll move into Sprint 2 — "5 testers have run the suite against their own apps."

---

## Flipping the repo public

I deliberately left the repo as PRIVATE because flipping public is irreversible (anything that's exposed during the public window gets indexed by GitHub's search + crawled by aggregators). Do this LAST, only after you've:

- [ ] Verified there are no secrets in commit history (`git log --all -p -- '.env*' '*.local'`)
- [ ] Verified `docs/launch/` doesn't contain anything that would embarrass you to ship as drafts
- [ ] Decided you're committed to the launch story for Oct 6

Then:

```bash
gh repo edit lictor-ai/lictor --visibility public --accept-visibility-change-consequences
```

Once public, the CI badges in the README start working, Dependabot starts filing PRs, and the world can see the repo.

The Oct 6 launch tweet/HN post happens AFTER this flip — but the flip doesn't have to be on Oct 6. Plenty of "building in public" advocates flip 4-8 weeks before the public launch to start picking up organic stars. Your call.

---

## What happens if Sprint 1 slips

The 70-minute total is realistic. The thing that adds time is:

- **Domain registration verification email** can take a few minutes
- **npm publish first time** sometimes needs 2FA setup
- **Cloudflare Pages build** is fast but the custom-domain DNS step can take up to 60 seconds for cert provisioning
- **Twitter signup** if your email is associated with an existing account

If you hit a snag on one of these and lose an evening, push the rest of the sprint by one day. Don't let one stuck step block the others — Tasks 1, 4, and 6 can be done in any order. Only 5 depends on 1.
