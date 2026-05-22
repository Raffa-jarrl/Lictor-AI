# The Lictor Story — told the way I'd tell it at 3am over coffee

**Author voice:** Raffa (or the storyteller speaking for Raffa)
**Audience:** indie devs, vibe coders, solo founders, security-curious humans
**Tone:** honest, not corporate, not preachy
**Length:** ~600 words / 3 minute read or 10-tweet thread

---

It's almost 9am here. I've been awake all night watching scanners.

Tonight Lictor walked through about 1,500 recent GitHub commits and found 32 live production keys leaking. Nine of them were active Stripe keys — the kind that can refund money, read customer cards, send payouts to a bank account that isn't yours. Twenty were AWS keys with their paired secrets, the combination an attacker needs to spin up a hundred crypto-mining EC2s on someone's credit card before they wake up.

None of these were enterprise security failures. They were **indie devs**. Solo founders. People building cool things on a Saturday with Cursor, ChatGPT, v0, Bolt, Lovable, Replit, Claude. The vibe-coding generation.

And here's what I want to say:

**The vibe coding renaissance is real, and it's beautiful.**

Founders are shipping in days what used to take months. Designers are deploying production apps. A 15-year-old in Lagos is launching a SaaS over a weekend. People who couldn't write a single line of code two years ago are running entire businesses on systems they built with AI as their co-engineer. This is the most democratizing moment in software since the web browser.

But I've been doing security for twenty years. And I know what comes next.

The vibe-coded MVP ships with the API key in the .env file in the public repo. The vibe-coded admin panel has no auth check because the AI never suggested one. The vibe-coded GraphQL endpoint has introspection wide open because the tutorial said to enable it for testing. The Stripe key gets leaked, the AWS keys mine $40K in crypto on the founder's personal card, the customer database leaks into the wrong Discord. The founder wakes up to a $14K AWS bill or a tweet from a security researcher and the dream evaporates.

This isn't a hypothetical. This is what I scan for every night.

So I built Lictor.

Lictor is one human's open-source security scanner. It's 28 different patrols — one for AWS keys leaking on GitHub, one for subdomain takeovers, one for CORS misconfigs, one for source maps exposing your source code, one for exposed Mongo databases. It runs locally on your laptop. It has zero telemetry. It costs nothing. It is and will always be Apache 2.0. You can fork it, sell derivatives of it, run it on competitors. I don't care. I just want fewer indie projects bleeding secrets.

Tonight I personally:
- Scanned ~2,000 bounty-program domains for takeovers, CORS, exposed services
- Submitted 12 verified vulnerabilities to companies that have paid programs (Xiaomi, PayPal, Expedia, Elastic, Atlassian) — every single bounty I earn from those goes back into Lictor's development
- Watched a Worldcoin developer-training subdomain sit fully claimable on Vercel for who knows how long
- Found a publicly readable Logitech storefront GraphQL schema exposed
- Drafted a write-up on 32 leaked secrets from random indie devs and chose **not to email any of them** with a donation ask, because that's not what Lictor is

There's no Series A behind Lictor. No team of engineers. No marketing budget. There's just me and a stubborn refusal to let small builders get destroyed by mistakes the enterprise tools could have caught — if those tools weren't $20K a year.

**I'm not asking you for money.**

I'm not putting a "Sponsor" button anywhere. I'm not adding telemetry next year. I'm not pivoting to a SaaS tier.

What I'm asking is this: if you're vibe-coding something right now, install Lictor's pre-commit hook tonight. One line:

```
curl -sSL lictor-ai.com/install-precommit.sh | bash
```

It will quietly catch the AWS key you were about to commit. It will warn you when the .env you forgot to .gitignore is staged. It will save you from the post you didn't want to write — the one that starts "I'm shutting down my SaaS because my Stripe key leaked and someone refunded everything."

And if you appreciate it — if Lictor catches one thing for you that would have ruined your week — the only payment I want is for you to **tell one other indie dev about it.** Forward this post. Drop it in your group chat. Mention it on the next podcast. Let the next solo founder running their MVP not become the next leaked-key story I scan up at 3am.

That's the whole pitch. That's the whole company. That's the whole stack.

Vibe code freely. Just don't ship the keys with it.

— Raffa
github.com/Raffa-jarrl/Lictor-AI · lictor-ai.com

---

## How to use this piece

- **Full essay:** post on Lictor blog + dev.to + medium + substack
- **HN "Show HN":** post the URL with title *"Show HN: Lictor — open-source security scanner for indie/vibe-coded projects"*
- **Twitter thread:** chop at every paragraph break for ~10 tweets, end with the curl one-liner
- **LinkedIn:** post the full text as a long-form post (LinkedIn rewards long posts when they're personal)
- **Hacker newsletters / weekly digests:** TLDR / Bytes / The Pragmatic Engineer — submit the essay
- **YouTube/TikTok security creators:** send to specific creators who cover indie-dev security topics, suggest as content
- **Inside Lictor's GitHub README:** consider putting the first 3 paragraphs as the project's manifesto section

## What this piece does NOT do

- Does not ask for money or sponsors
- Does not pressure anyone
- Does not name individual leak victims
- Does not over-promise what Lictor does
- Does not pretend Lictor is bigger than it is — it's honest about the "one human + 28 scanners" reality

The believability comes from the honesty.
