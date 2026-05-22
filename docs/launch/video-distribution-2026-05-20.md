# Lictor Video — Distribution Kit

**Video URL:** https://youtu.be/RelXN5g1sac
**Published:** 2026-05-20

This file = everything you should do in the next 60 minutes to maximize the video's reach.

---

## 1. POST THE PINNED COMMENT (do this FIRST, on YouTube itself)

Open the video → click the comment box → paste this → click "Comment" → click the pin icon on your own comment.

```
🔗 Install Lictor in 5 seconds:

   curl -sSL lictor-ai.com/install-precommit.sh | bash

📌 What we found tonight (anonymized — no individuals named):
   • 9 active Stripe sk_live keys
   • 20+ AWS access keys with paired secrets
   • 2 Mailchimp API keys
   • 1 Slack incoming webhook

🛠 GitHub repo: https://github.com/Raffa-jarrl/Lictor-AI

If Lictor catches one thing for you that would have ruined your week —
the only thing I'm asking is for you to tell one other indie dev about it.

Vibe code freely. Just don't ship the keys with it.

— Raffa 🌅
```

---

## 2. TWEET 1 — Drop the video link NOW

Best format: standalone tweet that drives clicks to the video (since the 11-tweet thread we drafted was for *before* the video existed).

```
I just spent the night watching my scanner find 32 live production
API keys leaking on GitHub.

9 active Stripe keys. 20+ AWS keys with paired secrets.

All from indie devs vibe-coding their MVP.

I made a short video about what I saw 👇

https://youtu.be/RelXN5g1sac
```

**269 chars.** Posts the video immediately. After this lands, you can post the longer 11-tweet thread we drafted as a SECOND post the next day (different framing, different lifetime).

---

## 3. TWEET REPLY (post 30 min after tweet 1 to bump the algorithm)

Reply to your own tweet 1 with this:

```
The 3 patterns my scanner sees over and over:

1️⃣ .env committed before .gitignore was added
2️⃣ Terraform providers.tf with literal AWS credentials
3️⃣ "Secret" gists shared with contractors — URL leaks forever

GitHub bots scrape commits in SECONDS, not days.
```

---

## 4. LINKEDIN POST (longer-form, post 1-2 hours after Twitter)

```
Tonight my open-source security scanner watched 32 live production
API keys get committed to public GitHub repos.

9 active Stripe sk_live keys. The kind that can process refunds,
read customer cards, send payouts to a bank account that isn't
yours.

20+ AWS access keys WITH their paired secret — the exact pair an
attacker needs to spin up crypto-mining EC2s on someone's personal
card overnight.

None of them were enterprise security failures. They were indie
devs. Solo founders. People shipping their first SaaS on a Saturday
with Cursor, ChatGPT, v0, Bolt, Lovable, Replit, Claude.

The vibe coding renaissance is real and it's beautiful. Founders
ship in days what took months. A 15-year-old in Lagos launches a
SaaS over a weekend. People who couldn't write a single line of
code two years ago are running real businesses.

But I've been doing security for 20 years. And I know what comes
next: the vibe-coded MVP ships with the API key in the .env in the
public repo. The Stripe key gets leaked. The AWS keys mine $40K
of crypto on the founder's personal card. The dream evaporates.

So I built Lictor.

It's an open-source scanner. 28 different patrols. Runs locally.
Zero telemetry. Apache 2.0 forever. The same checks enterprise
tools charge $20K/year for — free.

If you're vibe-coding something right now:

   curl -sSL lictor-ai.com/install-precommit.sh | bash

That's it. It catches the AWS key before you commit it.

I made a short video about tonight's findings:
https://youtu.be/RelXN5g1sac

I'm not asking you for money. No sponsor button. No telemetry next
year. No SaaS pivot.

What I'm asking: if Lictor catches one thing for you — tell one
other indie dev about it. That's the whole pitch.

Vibe code freely. Just don't ship the keys with it.

— Raffa
github.com/Raffa-jarrl/Lictor-AI
```

---

## 5. SHOW HN POST (HackerNews — post tomorrow morning ~9am ET)

**Title:** `Show HN: Lictor – open-source secret scanner for indie/vibe-coded projects`

**URL:** `https://github.com/Raffa-jarrl/Lictor-AI`

**Text body:**

```
Hi HN — I'm Raffa, 20 years in cybersec. I built Lictor because I got
tired of watching small projects bleed secrets onto GitHub at 3am.

What it is: an open-source scanner (Apache 2.0) with 28 patrols across
secrets (AWS/Stripe/Mailchimp/Slack/Cloudflare/Postgres/MongoDB),
subdomain takeovers (60+ provider fingerprints), CORS misconfigs,
source-map exposure, GraphQL introspection, exposed services (Redis/
Mongo/Elasticsearch), and a pre-commit hook for indie devs who don't
want a $20K/year enterprise scanner.

What I tested tonight: I pointed it at ~1,500 recent GitHub commits
and found 9 active Stripe sk_live keys, 20+ AWS access-key+secret
pairs, 2 Mailchimp API keys, and a Slack incoming webhook. None of
them were enterprise failures — all were indie devs and weekend
projects.

I made a short video about it: https://youtu.be/RelXN5g1sac

Install (pre-commit hook): curl -sSL lictor-ai.com/install-precommit.sh | bash

It has zero telemetry. There is no paid tier. It will be Apache 2.0
forever. If it catches one thing for you, my only ask is that you tell
one other indie dev about it.

Honest caveats:
- Some scanner patrols have known false-positive patterns (CloudFront
  TLS/SNI mismatches, GitHub Pages bare-user-page non-existent-org).
  I'm fixing those.
- Doesn't replace GitGuardian/TruffleHog/Snyk for enterprise needs.
- Source-maps and CORS scanners have higher signal:noise than the secret
  scanners, which require manual triage for attribution.

Roast it / suggest patrols / tell me what's broken — I'm reading every
comment.
```

---

## 6. REDDIT POSTS (drop these the next day, spread across 12+ hours)

### r/netsec
Title: `Open-source scanner found 32 live production API keys in 1,500 recent GitHub commits — anonymized research`
Body: shorter version of the Show HN post + video link

### r/devops
Title: `Indie devs are leaking AWS keys + secrets pairs in Terraform providers.tf at scale — here's the pattern`
Body: focus on the AWS/terraform-specific finding, link to video

### r/indiehackers
Title: `Why your vibe-coded MVP is one git push away from a $14K AWS bill — and the free tool to stop it`
Body: focus on indie-founder framing, link to video

### r/programming
Title: `I built an open-source secret scanner because $20K/yr enterprise tools price out indie devs`
Body: lead with the build story, link to repo + video

⚠️ **Reddit anti-spam rules:** post each one organically, engage with comments. Don't post all 4 in the same hour or any of them will get auto-flagged.

---

## 7. DEV.TO + MEDIUM + SUBSTACK CROSS-POSTS

Take the storyteller-pitch essay (`storyteller-pitch-2026-05-20.md`) and post it word-for-word to:

- **dev.to** — best for tactical / indie-dev audience
- **Medium / Better Programming** — for broader reach
- **Substack** (your own, or as a guest post on a security one)

In each, EMBED the YouTube video near the top:

```markdown
> Tonight my scanner watched 32 live production API keys get committed
> to public GitHub repos. Watch the 3-minute story:

[Embed: https://youtu.be/RelXN5g1sac]
```

---

## 8. SUGGESTED 24-HOUR SEQUENCE

| Time | Action | Why |
|---|---|---|
| **0:00** | Pin the YouTube comment (section 1) | Anchor the conversation BEFORE views build |
| **+0:05** | Post Tweet 1 with video link (section 2) | Hits when your followers are most likely awake |
| **+0:30** | Post the reply tweet (section 3) | Bumps the algorithm, gives early viewers more context |
| **+1:30** | LinkedIn post (section 4) | Different audience, no overlap penalty with Twitter |
| **+3:00** | Update GitHub README with video embed | New visitors land and immediately see the story |
| **+8:00** | Sleep |
| **+24:00** | Show HN post (section 5) | HN morning peak (9am ET = Tuesday-Thursday optimal) |
| **+32:00** | r/netsec post (section 6) | Spaced to avoid cross-platform spam flags |
| **+40:00** | r/indiehackers post | Different framing for that audience |
| **+48:00** | r/devops + r/programming + dev.to + Medium | Spread out to keep momentum 2 days deep |

---

## 9. WHAT TO TRACK (next 7 days)

- **YouTube:** views, watch time (the 50%+ retention mark matters more than view count), subscriber additions
- **GitHub:** new stars on the Lictor-AI repo (the most honest metric of "this resonated")
- **Twitter:** impressions on tweet 1, but more importantly: how many of your followers DM you about it
- **HN:** position on the front page (anywhere in top 50 in first 2 hours = solid)
- **Reddit:** upvote ratio (>80% = healthy, <70% = community pushback to learn from)
- **Discord/Slack DMs:** the quietest but most predictive metric — security researchers reaching out is the leading indicator of momentum

---

## 10. WHAT TO DO IF IT GOES VIRAL

(low probability but worth prepping for)

- **Pin the GitHub Sponsors button.** NO — keep your no-sponsor pledge. Add a footer instead: "If you've used Lictor and want to contribute, the highest-leverage thing is a PR fixing a false-positive pattern."
- **Triage the issue tracker** within 4 hours of any HN spike — viral threads bring contributors AND trolls, both deserve fast responses
- **Don't announce a SaaS tier** even if you get DMs offering to invest. Lictor's whole positioning is built on the "free forever" pledge. The moment that wavers, the brand collapses.
- **Do an AMA** (HN, r/netsec) within 48 hours of going viral — answering questions in real-time is the multiplier on the original spike

---

## 11. WHAT TO DO IF IT GETS NO TRACTION

(this is the most likely outcome — 70-80% probability for any single launch)

- The artifacts are PERMANENT. Every blog post, video, thread, README mention compounds over months.
- Don't repost the same content. Make the next thing better.
- Keep filing bug bounties (the Xiaomi, PayPal, Stripe pipeline is the deepest signal — those reports resolving will give you concrete proof to point at)
- The triage queue resolving over the next 1-4 weeks will create natural follow-up content ("Update: Xiaomi accepted the report, here's what they fixed")

---

## You've now shipped 6 launch artifacts in one session

| Artifact | File |
|---|---|
| Blog post (research-tone) | `blog-tonight-we-scanned-github-2026-05-20.md` |
| Storyteller essay | `storyteller-pitch-2026-05-20.md` |
| Twitter thread (11 + 5 tweet) | `twitter-thread-2026-05-20.md` |
| Infographic prompts | `infographic-prompt-2026-05-20.md` |
| YouTube launch kit | `youtube-launch-kit-2026-05-20.md` |
| Video distribution playbook | `video-distribution-2026-05-20.md` (this file) |

Plus the actual video at https://youtu.be/RelXN5g1sac.

This is a complete launch package. Push it tonight, sleep, and see what tomorrow brings.

— Good luck. Vibe code freely. Just don't ship the keys with it. 🌅
