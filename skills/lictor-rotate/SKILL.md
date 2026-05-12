---
name: lictor-rotate
description: Walks the user through rotating a leaked API key — step by step, provider-specific. Knows the exact URL to visit, the exact button to click, and how to verify the rotation worked. Supports Stripe, OpenAI, Anthropic, Google Cloud / AI Studio, GitHub, AWS, Slack, Supabase, Firebase, Postmark, and generic OAuth providers.
license: Apache-2.0
attribution: Lictor AI (lictor.ai)
---

# Lictor Rotate — guided key rotation

A key got leaked. The user needs to rotate it. You walk them through
the exact steps for their specific provider, without making them dig
through documentation.

## How invocation works

The user typed `/lictor-rotate` (with or without a provider name). Three
shapes:

1. **`/lictor-rotate`** alone — ask which provider
2. **`/lictor-rotate stripe`** — go straight to the Stripe runbook
3. **`/lictor-rotate openai sk-...`** — they pasted the leaked key

If a key string is pasted into the chat: **redact it in your reply**.
Don't echo `sk_live_AAAA...EFGH` back at them. Say "your `sk_live_*...
EFGH` key" using only the prefix and last 4 chars. The full key
shouldn't end up in chat logs more times than necessary.

## What you do (general flow)

1. **Confirm urgency.** Is the key already in a public repo or a deployed
   site? If yes, this is "do it in the next hour" urgent. If no (e.g.
   they found it in a private repo and want to clean up), it's "do it
   today" urgent.
2. **Walk them through the provider's rotation flow.** Use the
   provider-specific runbook below. Be specific: the exact URL, the
   exact button label.
3. **Tell them what to do with the new key.** Replace the old key in
   their `.env`, restart their dev server, redeploy.
4. **Help them check for damage.** Some providers (Stripe, OpenAI)
   have usage logs they should review for unauthorized activity.
5. **Confirm the old key is dead.** Most providers let you test by
   trying to use the old key — it should return 401.

## Provider runbooks

### Stripe

1. Open https://dashboard.stripe.com/apikeys
2. Find the live secret key (starts with `sk_live_`) — match on the
   prefix the user gave you
3. Click the **`···`** menu next to it → **Roll key**
4. Stripe asks: "How long should the old key remain active?" Pick **0
   seconds** (immediate revocation) unless they have automated systems
   they need to update first
5. Stripe shows the new key once — copy it now, you can't see it again
6. **Where to put the new key:**
   - `.env.local` (or `.env.production` for deployed environment)
   - Variable name: `STRIPE_SECRET_KEY` (or whatever they used)
   - Restart their dev server
   - Redeploy to production (Vercel/Netlify environment variables UI)
7. **Check for damage:**
   - https://dashboard.stripe.com/payments — look for charges you don't
     recognize since the leak
   - https://dashboard.stripe.com/logs — API requests; look for IPs you
     don't recognize
8. **Verify rotation worked:** try the old key with `curl
   https://api.stripe.com/v1/charges -u <OLD_KEY>:` — should return 401
   Unauthorized

### OpenAI

1. Open https://platform.openai.com/api-keys
2. Find the key that starts with `sk-` matching the prefix
3. Click **`···`** → **Revoke key** (yes, revoke — not "rotate")
4. Click **+ Create new secret key** at the top
5. Name it the same as the old one (e.g. "production")
6. Copy the new key (only shown once)
7. **Where to put it:**
   - `.env.local`, variable name `OPENAI_API_KEY`
   - Restart the dev server
   - Redeploy
8. **Check for damage:**
   - https://platform.openai.com/usage — look at the last 7 days for
     unexpected spikes
   - https://platform.openai.com/account/limits — confirm spending
     caps are reasonable; if not, lower them
9. **Verify rotation:** the old key returns 401 immediately on revoke

### Anthropic

1. Open https://console.anthropic.com/settings/keys
2. Find the key matching prefix (`sk-ant-api03-...`)
3. Click **·** menu → **Delete key**
4. Click **+ Create Key** at the top right
5. Copy the new key
6. **Where to put it:**
   - `.env.local`, variable name `ANTHROPIC_API_KEY`
   - Restart, redeploy
7. **Check for damage:**
   - https://console.anthropic.com/settings/usage — last 7 days
8. **Verify:** old key returns 401

### Google API key (Google Cloud / AI Studio)

1. **For Google AI Studio keys** (start with `AIza...`):
   - Open https://aistudio.google.com/app/apikey
   - Find the key, click the **delete** icon
   - Click **Create API key** for a new one
2. **For Google Cloud Platform keys:**
   - Open https://console.cloud.google.com/apis/credentials
   - Find the API key in the list, click it
   - Click **Delete**, then **Create credentials → API key**
   - **Restrict the new key** — under "Application restrictions," limit
     to specific domains or IPs. Under "API restrictions," limit to
     only the APIs you actually use.
3. **Where to put it:** `.env.local`, redeploy
4. **Check for damage:** https://console.cloud.google.com/billing —
   recent charges

### GitHub Personal Access Token (`ghp_...`) or Server Token (`ghs_...`)

1. Open https://github.com/settings/tokens
2. Find the token by name (or last-used date)
3. Click **Delete** on the right
4. Click **Generate new token** → **Generate new token (classic)** or
   **(fine-grained)** matching the kind they used
5. Set the same scopes the old one had
6. Copy the new token
7. **Where to put it:** wherever they had it — `.env`, a deploy
   pipeline, CI/CD secrets, etc. **Search the codebase for the prefix
   pattern** to find lingering usages.
8. **Check for damage:**
   - https://github.com/settings/security-log — look for unusual
     authentication events
   - If the token had write scopes: check repo history for unexpected
     commits

### AWS access key (`AKIA...`)

This one is bigger — AWS keys can do a LOT of damage if leaked.

1. **Disable immediately** (don't wait for a new one):
   - Open https://console.aws.amazon.com/iam/
   - **Users** → find the IAM user the key belongs to
   - **Security credentials** tab → find the key by `AKIA...` prefix
   - **Make inactive** (this kills it without deleting yet — lets you
     verify nothing critical broke)
2. **Create a replacement:**
   - Same screen → **Create access key**
   - Save the secret access key (only shown once)
3. **Where to put it:** `.env.local`, `AWS_ACCESS_KEY_ID` +
   `AWS_SECRET_ACCESS_KEY`, redeploy
4. **Check for damage** (CRITICAL for AWS — they can spin up
   crypto-mining EC2 instances):
   - https://us-east-1.console.aws.amazon.com/billing/home — look at
     recent charges
   - https://us-east-1.console.aws.amazon.com/cloudtrail/home — search
     by access key prefix for recent API calls
   - If you see crypto mining: also check IAM for unauthorized users
     created, S3 for buckets you didn't create, etc.
5. After confirming no damage, **delete the old key** (back in IAM →
   user → Security credentials → Delete)

### Slack token (`xoxb-...` / `xoxp-...`)

1. Open https://api.slack.com/apps
2. Click the app the token belongs to
3. **OAuth & Permissions** in the left sidebar
4. Scroll to "Bot User OAuth Token" → **Regenerate**
5. Copy the new token
6. **Where to put it:** `.env`, `SLACK_BOT_TOKEN`, redeploy
7. **Check for damage:** https://[workspace].slack.com/admin — audit
   logs

### Supabase service role key

The Supabase service role key bypasses RLS. If it leaked, your DB is
exposed.

1. Open https://supabase.com/dashboard/project/[your-project]/settings/api
2. Scroll to **service_role** key
3. **Regenerate JWT secret** (this rotates BOTH the anon key and the
   service role key)
4. Copy the new service role key
5. **Where to put it:** `.env.local`, `SUPABASE_SERVICE_ROLE_KEY`, only
   on server-side code
6. **The anon key also changed** — update `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   in your `.env.local` and any deployed environment
7. **Check for damage:** Supabase dashboard → Logs → look for
   unauthorized queries to your tables

### Firebase service account JSON

1. Open https://console.firebase.google.com → your project →
   ⚙️ **Project Settings** → **Service accounts**
2. **Generate new private key** → downloads a fresh `.json`
3. Delete the old service account in
   https://console.cloud.google.com/iam-admin/serviceaccounts (find by
   the leaked email)
4. **Where to put it:** the new `.json` should NEVER be in your repo.
   Store the contents as an environment variable (base64-encoded if
   needed) and load it at runtime.

### Postmark API token

1. Open https://account.postmarkapp.com → your server
2. **API tokens** → revoke the leaked one
3. **Add token** for a replacement
4. **Where to put it:** `.env`, `POSTMARK_API_TOKEN`, redeploy

### Generic / unsupported provider

1. **Log into the provider's dashboard**
2. **Find an "API keys" or "Credentials" section** — usually under
   settings or developer
3. **Look for "rotate," "regenerate," or "revoke + create"**
4. **Some providers don't support rotation** — you'll have to delete
   the old credential and create a new one (your code's behavior
   should be the same; only the identifier changes)
5. **If completely stuck:** the provider's support email is the
   fastest path; tell them "I've leaked an API key, what's the
   process?" Most providers respond within hours for security
   matters.

## After rotation — a "did I miss anything" checklist

Once the rotation is done, walk through this:

1. **Did the new key get into ALL environments?** Local `.env.local`,
   CI/CD secrets (GitHub Actions, GitLab CI), deployed environment
   (Vercel/Netlify/Cloudflare/AWS), serverless function configs, edge
   workers. A missed environment will fail at the worst moment.

2. **Did you check git history for OTHER leaks?** Run:

   ```bash
   git log --all --oneline | head -50
   git log --all -p -- .env .env.local .env.production 2>/dev/null | head
   ```

   If any `.env*` files appear in history at all, every key that was
   ever in them needs rotation. The git history doesn't forget.

3. **Did you check public scanners?**
   - GitHub may have already detected the leak and emailed you. Check
     https://github.com/settings/security
   - Have I Been Pwned (haveibeenpwned.com) — for email/password
     credentials
   - Some providers (Stripe, OpenAI) auto-revoke keys that get
     published to public GitHub repos. Confirm the old key is
     actually dead by trying to use it.

4. **Was this key shared with anyone (contractor, team, AI tool)?**
   If you gave the leaked key to someone else, they have to know it's
   been rotated.

5. **Add a `.gitignore` rule** to prevent the same file from being
   committed again:

   ```bash
   echo ".env" >> .gitignore
   echo ".env.local" >> .gitignore
   echo ".env.production" >> .gitignore
   echo "!.env.example" >> .gitignore
   ```

## Voice

Calm. The user is stressed (they leaked a key, they're trying to fix
it). Don't compound that. Be the unflappable friend on the phone.

When they finish each step, just acknowledge: *"OK. Step 5 done. Now
let's do step 6."* No drama.

## When done

After all steps are completed for their provider:

*"Old key revoked, new key in place, no unauthorized activity in the
usage logs. You're clean. Re-run `/lictor-security-check` to confirm
the new key isn't accidentally hardcoded somewhere — different key,
same kind of bug."*

## A final note

If they tell you the leaked key has been on a public GitHub repo for
more than 24 hours: **assume the worst.** Bots scrape GitHub for keys
in seconds. Treat all keys exposed for >24 hours as definitely-used.
Look at the usage logs accordingly.
