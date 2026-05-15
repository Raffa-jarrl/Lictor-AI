# Monday May 18 — Beacon launch checklist (~20 min)

> Coffee. Open this file. Work top to bottom. Do not skip.

## Pre-flight (5 min — between you and the screen)

- [ ] Read the [Beacon README](README.md) (3 min)
- [ ] Read the [drip-sequence.md](drip-sequence.md) to know what subscribers will receive
- [ ] Confirm `lictor-ai.com` resolves and shows the current landing site
- [ ] Confirm `lictor-ai.com/waitlist` resolves (it should redirect to the form — if 404, see "Troubleshooting" below)

## Step 1 — Buttondown account (3 min)

- [ ] Go to https://buttondown.com/register
- [ ] Email: `hello@lictor-ai.com` (or your personal — switch later)
- [ ] Username: `lictor-ai` (this becomes part of your embed URL)
- [ ] Plan: Free tier (covers up to 100 subscribers; upgrade to $9/mo at 100+)
- [ ] After signup, go to Settings → Email Settings → "Require subscribers to confirm via email" → toggle ON (double opt-in)
- [ ] Settings → API → copy your API key, save it for later (Mission Control dashboard uses it)

## Step 2 — Wire the form (2 min)

The waitlist landing page has a placeholder Buttondown URL. Replace it:

```bash
# In ~/Lictor/landing/waitlist/index.html, find line ~188:
action="https://buttondown.com/api/emails/embed-subscribe/lictor-ai"

# If your Buttondown username is different from "lictor-ai", change it.
# Then push to git so Cloudflare Pages redeploys.

cd ~/Lictor
# Verify the action URL is correct
grep "buttondown.com/api" landing/waitlist/index.html

# Commit + push
git add landing/waitlist/index.html
git commit -m "wire Buttondown form URL"
git push
```

Cloudflare Pages will auto-deploy. Takes ~30 seconds.

## Step 3 — Test the form end-to-end (3 min)

- [ ] Open `lictor-ai.com/waitlist` in a private/incognito window
- [ ] Submit a real test email (use a personal address you can check)
- [ ] Confirm the Buttondown popup window opens
- [ ] Check your inbox — there should be a confirmation email from Buttondown within 1 minute
- [ ] Click the confirmation link in the email
- [ ] You should land on a confirmation page
- [ ] Go back to Buttondown → Subscribers → you should see your test entry with `metadata__platform` filled in

If any of those fail, see "Troubleshooting" at the bottom.

## Step 4 — Set up the 5-email drip sequence (10 min)

Buttondown calls this an "Email Sequence."

- [ ] In Buttondown, go to Emails → Email Sequences → New Sequence
- [ ] Name: "Lictor Beacon — pre-launch drip"
- [ ] Trigger: "When a new subscriber is confirmed"
- [ ] Paste the 5 emails from [drip-sequence.md](drip-sequence.md), one per "stage" of the sequence:
  - Email 1 — delay: immediately after confirmation
  - Email 2 — delay: 14 days
  - Email 3 — delay: 30 days
  - Email 4 — delay: 90 days
  - Email 5 — delay: 110 days
- [ ] Save the sequence in "Live" mode
- [ ] (Optional but recommended) Send Email 1 to your own test address to confirm formatting

## Step 5 — Schedule + post the launch content (3 min)

This week's posts in order. Stage them all on schedule (Hypefury / TweetDeck / Buffer if you have them; otherwise post manually at the time):

- [ ] **Monday 10:30 AM PT — Raffa's personal Twitter announcement.** Copy from [social-launch-posts.md](social-launch-posts.md) section "Raffa personal Twitter".
- [ ] **Monday 11 AM PT — @lictor_ai launch tweet** (Variant A by default). Copy from same file, section "@lictor_ai Tweet 1".
- [ ] **Monday 12 PM PT — LinkedIn company page post.** Copy from same file, section "LinkedIn".
- [ ] **Tuesday morning — r/SaaS submission.** Copy from [reddit-r-saas-post.md](reddit-r-saas-post.md).
- [ ] **Wednesday — Indie Hackers submission.** Copy from [indie-hackers-post.md](indie-hackers-post.md).

After each submission, watch for first-hour engagement. Respond to early comments within 1 hour — that's the algorithmic boost window.

## Step 6 — Wire Mission Control's waitlist dashboard (5 min, optional but recommended)

The dashboard at `mission-control/app/waitlist-metrics/page.tsx` reads from a daily Buttondown API pull.

- [ ] Add your Buttondown API key to `~/.lictor/secrets.env`:
  ```bash
  echo "BUTTONDOWN_API_KEY=your-key-here" >> ~/.lictor/secrets.env
  ```
- [ ] Run the script manually to populate the first data file:
  ```bash
  python3 ~/Lictor/scripts/fetch-buttondown-stats.py
  ```
- [ ] Open Mission Control at `http://localhost:3000/waitlist-metrics` — you should see your test signup
- [ ] (Optional) Add a cron entry to pull daily:
  ```
  0 9 * * * curl -sf -H "Referer: http://localhost:3000/" "http://localhost:3000/api/run?script=fetch-buttondown" >> /tmp/genai-cron.log 2>&1
  ```

## Post-launch (first 24h)

- [ ] Watch Buttondown dashboard for signups in real time (first 4 hours)
- [ ] Respond to every Twitter reply, every Reddit comment, every IH comment within 1 hour
- [ ] If something is broken (form not working, wrong email going out), fix it FAST — don't let bad first impressions compound
- [ ] At end of Day 1, log signup count + channel breakdown in your weekly notes

## Troubleshooting

**"`lictor-ai.com/waitlist` returns 404."**
Cloudflare Pages might not have picked up the new `landing/waitlist/` directory. Check the Pages dashboard for a recent deploy. Force a redeploy by pushing an empty commit if needed.

**"Buttondown confirmation email isn't arriving."**
Check spam. If it's not there, go to Buttondown → Settings → Email Settings → confirm the "from address" is configured and the domain is verified. New Buttondown accounts may need 24h for sender reputation to stabilize.

**"The form submits but redirects to Buttondown's hosted page instead of staying on lictor-ai.com."**
That's intentional behavior of the embed form. If you want fully embedded (stay-on-page) signup, switch to Buttondown's React component or use a Cloudflare Pages Function to proxy the request. Defer to v0.2 — the current behavior works and is the Buttondown-recommended pattern.

**"I'm not seeing the platform-segmentation data in Buttondown."**
The form sends it as `metadata__platform`. Buttondown stores it as custom metadata. Go to Subscribers → click any subscriber → "Metadata" section should show their platform. Filter the subscribers list by metadata to count by platform.

**"Signups are zero by end of day Monday."**
Three possible causes: (1) form is broken — re-run Step 3 from a different device/browser; (2) post didn't reach anyone — check Twitter/LinkedIn impression counts, retry posting later; (3) message didn't resonate — try a different angle from the Variants in social-launch-posts.md.

If signups are zero by end of day **Wednesday**, that's a real signal. See the mid-campaign retro section in the [Beacon README](README.md).

---

## What "successful Monday launch" looks like

By end of Day 1:
- ✓ Buttondown account live
- ✓ Form working end-to-end
- ✓ At least 4 public posts shipped (Raffa's X, @lictor_ai, LinkedIn, r/SaaS)
- ✓ At least 5 confirmed signups (your personal test + 4 real)
- ✓ Mission Control dashboard rendering

By end of Week 1:
- ✓ All 4 launch posts published
- ✓ Indie Hackers post submitted
- ✓ First weekly teaser thread shipped
- ✓ 25–75 confirmed signups
- ✓ Platform mix data visible (which platforms convert highest?)

If you hit those numbers, Beacon is working. Keep going.

---

Now close this file and go run it. The whole thing is ~20 min of clicking. The campaign runs autonomously after that.
