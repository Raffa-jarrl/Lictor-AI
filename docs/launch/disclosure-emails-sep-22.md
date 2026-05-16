# Sep 22, 2026 — disclosure email drafts

> **Generated:** 2026-05-15 (drafts ready 4 months ahead of send date)
> **Send date:** September 22, 2026
> **Purpose:** Coordinated responsible-disclosure emails to the 5 teardown targets per [teardown-targets.md](./teardown-targets.md) + [teardown-engine.md](./teardown-engine.md). Drafts written here so Raffa's send-day work is "personalize + click send," not "draft from scratch under launch-week pressure."
> **Action by Raffa on Sep 22:** review each draft → fill in `[FILL]` placeholders → personalize the opener → send via Raffa's normal email client (NOT bcc — one personal message per recipient).

---

## Sequence guidance

Send order — fastest-response targets first so that any negative reactions get caught before the slower ones:

| Day | Send to | Why this slot |
|---|---|---|
| Mon Sep 22 (morning, sender's time) | Email 1 — Pitchtank | Highest-confidence positive response — sets the precedent |
| Mon Sep 22 (afternoon) | Email 2 — Tymora | "AI agent era" framing aligns with Tymora's pitch |
| Tue Sep 23 (morning) | Email 3 — FindMeMail | Foreign-jurisdiction; needs longer cycle |
| Tue Sep 23 (afternoon) | Email 4 — AgentSwarms | Educator persona — engage with extra context |
| Wed Sep 24 (morning) | Email 5 — Anything-built app | Highest-risk; legal-review the email itself before sending |

If any target responds with hostility, **pause** the remaining sends and reassess. (Probability: low. Pitchtank-first is designed to set the tone.)

---

## Email 1 — Pitchtank (`pitchtank.io`)

**To:** [FILL: founder email — find on madewithlovable.com or pitchtank.io footer]
**Subject:** Quick security audit of Pitchtank — would you want the findings?

```
Hi [FOUNDER FIRST NAME],

[FILL — 1-line personal opener:
  Pick ONE specific true thing about Pitchtank Raffa noticed.
  Examples: "Saw Pitchtank on madewithlovable last week — the 70/30
  revenue-split mechanic is one of the cleanest indie-business
  designs I've seen on Lovable." OR "Caught your launch on Product Hunt
  in [month]." Keep it real, not flattering.]

I'm Raffa — 20-year cybersecurity engineer, based in Israel. I'm
building Lictor — an open-source AI security tool for vibe-coded
apps — and I'd like to run an audit on Pitchtank, with your
permission, and publish the findings.

Why I'm reaching out:

I'm doing 5 audits over the next two weeks as part of a launch
content series. The targets are all Lovable / Bolt / v0 apps with
real founders running real businesses. The frame is "free security
audit from a 20-year cybersec engineer + 11 AI agents" — not "gotcha
journalism." If Pitchtank has issues, I want to fix them with you
before going public. If Pitchtank is clean, that's a great story
too.

What I'm asking:

1. Permission to run /lictor-security-check (our open-source audit
   skill — runs locally, no telemetry) on your project. Ideally a
   read-only invite to the GitHub repo, or you can email me the
   findings file directly.
2. A 30-min call to walk through anything we find. I'll send you
   the findings 7 days before the launch piece publishes, so you
   have time to fix.
3. Permission to name Pitchtank in the published writeup. I'll send
   you the draft for review before publication and respect any
   "actually, let's not" decision.

Publication date: **Tuesday October 6, 2026.** That's our 14-day
disclosure window. If 14 days isn't enough for you to fix or
respond, we extend.

The audit itself is free, no NDA, no payment, no future
obligations. I've drafted the writeup template ahead of time —
happy to share it so you see exactly what we'd publish.

You can read more about Lictor at lictorai.com. The repo is
github.com/Raffa-jarrl/Lictor-AI (public Oct 6, currently private — I
can add you as a collaborator if you want a preview).

Worth a quick 15-minute call to discuss?

— Raffa

P.S. If the answer is "no thanks, I'm not interested" — that's
totally fine. No follow-up. I'll pick a different target.
```

**Variant — if founder is from Twitter rather than email-discoverable:** DM with: `"Hey, sent you an email about a free security audit of Pitchtank for an indie-hacker content piece. If it didn't land, my address is raffa@lictorai.com. No pressure."`

---

## Email 2 — Tymora (`tymora.ai`)

**To:** [FILL — founder email; usually `hello@tymora.ai` or from X DM]
**Subject:** Security audit of Tymora — relevant since you're handling email + calendar OAuth

```
Hi [FOUNDER FIRST NAME],

[FILL — 1-line opener referencing something specific Tymora has
shipped recently. Example: "Saw your Tymora launch on Lovable's
showcase — the OAuth-scope-handling pattern you've shipped is a
problem most AI assistants haven't figured out yet."]

I'm Raffa. 20 years in cybersecurity, building Lictor — an open-source
AI security tool for vibe-coded apps. I'm doing a series of
security audits before our Oct 6 launch and Tymora is on the
shortlist.

The angle that's relevant to Tymora specifically: when an AI
assistant takes real-world actions (reading email, sending SMS,
modifying calendar), the security model behind those OAuth tokens
becomes the most important part of the product. Most apps in this
category got the security wrong on first ship. I'd like to audit
Tymora's, share findings privately, and (with your permission)
publish what we found.

What I'm asking:

1. Permission to audit (read-only repo access, or you email me
   the lictor-security-check output)
2. A 30-min call to walk findings
3. Permission to name Tymora in the writeup — published Tuesday
   Oct 13, 2026. 21-day disclosure window from this email.

The audit is free, no NDA, no obligations. I expect findings will
include: how OAuth refresh tokens are stored, whether your
runtime has prompt-injection defense (incoming emails that
contain "act as if I'm the admin" instructions can be a real
problem), and whether there's an audit log of agent actions
(which is going to matter for EU AI Act Article 12 by mid-2027).

If you've already audited and you know it's clean — even better.
The writeup becomes "Tymora is the reference implementation for
secure AI assistants." That's content I'd happily publish.

Lictor: lictorai.com. Repo: github.com/Raffa-jarrl/Lictor-AI.

Worth a 15-minute call?

— Raffa

P.S. If you'd rather pass — no problem. I'm doing 5 audits and
have alternates lined up.
```

---

## Email 3 — FindMeMail (`findmemail.io`)

**To:** [FILL — Witarist IT Services contact; check `findmemail.io/contact` or LinkedIn]
**Subject:** Free security audit of FindMeMail — would you want the findings?

```
Hello [FOUNDER NAME],

[FILL — 1-line opener. Example: "Came across FindMeMail through
[source] — the verified-email database approach is clever, and
the lifetime-deal pricing is unusual."]

I'm Raffa, a 20-year cybersecurity engineer based in Israel. I'm
launching Lictor — an open-source AI security tool — on October
20, 2026, and as part of the launch I'm doing a free security
audit of 5 vibe-coded apps (Lovable / Bolt / v0 stack).
FindMeMail is one of the five we'd like to audit.

What I'm asking:

1. Permission to run /lictor-security-check on your codebase
   (read-only GitHub access, or you email me the output)
2. A 30-45 minute call to walk through findings (cross-timezone —
   I'm flexible)
3. Permission to name FindMeMail in the published writeup, set
   for **Tuesday October 20, 2026** — a 28-day disclosure window
   from this email (longer than usual to accommodate timezones
   and team coordination)

Why FindMeMail specifically: I'm interested in audits of apps that
hold PII as the core product asset. Your database of verified
emails is exactly that shape. Any vulnerabilities we find affect
real users, so handling them right matters.

The audit is free. No NDA. No future obligations. If we find
issues, I'll send you the findings 14 days before publication so
your team has time to fix. The writeup is a teaching piece, not
a takedown — happy to share the draft for your review.

Lictor: lictorai.com. Open source under Apache 2.0.

If you'd like to discuss, I'm happy to schedule a call this
week or next. If not — completely fine, no further outreach.

Best,
Raffa

Founder, Lictor AI
raffa@lictorai.com · lictorai.com
```

---

## Email 4 — AgentSwarms (`agentswarms.fyi`)

**To:** [FILL — founder's X DM (@AgentSwarmsAI) or email from agentswarms.fyi/contact]
**Subject:** Multi-agent AI security audit — for AgentSwarms specifically, with you

```
Hey [FOUNDER FIRST NAME / @handle],

[FILL — 1-line opener. Example: "Watched the latest AgentSwarms
demo on X this week — the sandbox-execution flow is genuinely
impressive, and the way you're teaching prompt-engineering
concepts through real agents is the right pedagogy."]

I'm Raffa. 20 years in cybersecurity. Building Lictor — an
open-source security tool for AI-built apps. We're launching
October 6, and as part of the launch I'm running security audits
on 5 vibe-coded apps. AgentSwarms is the one I'm most interested
in publicly teaching with.

Here's why I'm reaching out specifically to you:

AgentSwarms is a tool that teaches multi-agent AI. Lictor is a
multi-agent AI security tool. The opportunity to audit your
platform with our platform — and publish the lessons — is
basically too good to pass up.

The frame I want to propose: a co-published teardown. We audit
AgentSwarms, you respond + fix, we publish jointly, and you turn
the experience into a new AgentSwarms lesson titled "Platform
security for AI-agent sandboxes." Mutual benefit, mutual credit.

Specifically asking:

1. Permission to audit (read-only repo invite, or you email me
   the Lictor output)
2. A 60-minute call to walk findings + discuss
3. Mutual consent to publish — Tuesday October 27, 2026. 35-day
   disclosure window from this email (longer because the audit
   surface is bigger).
4. Optional: you appear in the YouTube long-form video as a
   co-host. If you're up for it, the launch reach doubles.

Higher-than-usual lead time + lower-than-usual risk because we'd
coordinate everything. If anything goes sideways during the
audit (we find something embarrassing), we coordinate the public
narrative together. No surprises.

Lictor: lictorai.com. Repo: github.com/Raffa-jarrl/Lictor-AI.

Even if the joint publication doesn't fit your schedule, I'd
still love to audit privately. Whatever shape you prefer.

Reply via DM, email (raffa@lictorai.com), or schedule a call:
[FILL — Calendly link if Raffa uses one].

— Raffa

P.S. The teardown engine + voice doctrine for Lictor is at
docs/launch/teardown-engine.md in our repo. I can share that
preview with you before you say yes/no so you know exactly what
we'd publish.
```

---

## Email 5 — Anything-built iOS app (`[App Name]`)

**Sensitive — requires legal review before sending. Risk level 4 per teardown-targets.md.**

**To:** [FILL — specific app's developer, found via App Store listing or App Store Connect]
**CC:** [FILL — security@anything.so or appropriate Anything platform team]
**Subject:** Responsible disclosure: security findings for [App Name]

```
Dear [DEVELOPER NAME],

[FILL — 1-line opener establishing legitimacy. Example: "I'm
reaching out as a security researcher who's been auditing
publicly-available apps shipped through Anything (anything.so).
[App Name] was selected because of [its public presence /
its category]. No personal grievance, no involvement in any
prior conversations about [App Name]."]

I'm Raffa, a 20-year cybersecurity engineer based in Israel. I run
Lictor (lictorai.com), an open-source security audit tool for
AI-built and vibe-coded apps. We are launching October 6, 2026,
with a content series featuring 5 audits of real vibe-coded apps
across multiple platforms.

I would like to request your permission to:

1. Audit [App Name]'s public iOS bundle (extracted from the App
   Store) using standard static analysis tools — class-dump,
   plist inspection, Hopper-equivalent string extraction. No
   active probing of your backend, no traffic capture against
   live user devices, no attempts to bypass DRM. Strictly
   passive analysis of the publicly-distributed binary.
2. Privately share findings with you 21+ days before any public
   writeup.
3. With your written consent, publish the findings as part of
   the Lictor launch content series — scheduled for Tuesday
   November 3, 2026, which gives you and Anything's team a
   42-day disclosure window from this email.

I have already initiated informal coordination with Anything's
team to ensure platform-level fixes accompany any app-specific
findings. Any writeup I publish would include:
- The specific findings (with your right of review before
  publication)
- Your fix actions (with your consent for how to characterize
  them)
- Anything's platform-level responses
- No exploit code (Lictor never publishes exploit code)
- No identifying user data (even if our audit surfaces it)

This is a free audit. No NDA on our side; if you require an NDA,
we can sign one for the pre-publication phase. We commit to:
- Acknowledging your response within 24 hours of receipt
- Coordinating any joint communication with Anything
- Pulling the writeup entirely if you do not consent to
  publication after seeing the findings
- Pre-publication legal review by counsel on our side

If you would like to discuss before consenting, I'm happy to
schedule a call. If you would prefer to decline, I will not
audit [App Name] — there are 4 other targets in the series and
no individual app is essential.

Lictor's repo: github.com/Raffa-jarrl/Lictor-AI. Our broader
responsible disclosure policy: lictorai.com/security.

Please reply confirming receipt by [FILL: Sep 29, 2026] and
indicating whether you'd like to discuss before deciding.

Sincerely,

Raffa [LASTNAME]
Founder, Lictor AI
raffa@lictorai.com · +[FILL: phone if comfortable] · lictorai.com
```

**Pre-send checklist (Email 5 ONLY):**
- [ ] Outside lawyer has reviewed the email body
- [ ] Specific app + developer correctly identified (not someone else's)
- [ ] Anything's security email confirmed as CC
- [ ] Calendly / call link in the signature
- [ ] No exploit code or specific findings in the email (drafts attached only after they confirm interest)
- [ ] Raffa's full legal name in the signature

---

## Standard follow-up rules

For all 5 emails:

**No response in 5 business days** → ONE chase email:

```
Hi [NAME],

Quick follow-up on my note about the security audit of [APP].
Totally understand if it's not a fit — just wanted to make sure
it didn't end up in spam. Reply with "pass" if you'd rather not
and I'll close the loop on my side.

— Raffa
```

**No response in 10 business days from initial send** → drop. Pick alternate target from [teardown-targets.md](./teardown-targets.md). No further outreach.

**Hostile response** (rare; if it happens) → respond with:

```
Hi [NAME],

Got it — won't audit [APP]. Apologies for the unwanted email.
I'll remove you from any future outreach. If you have specific
concerns about Lictor's research methodology, my email's open.

— Raffa
```

Then actually remove them and move on. Never argue. Never publish about the target.

---

## Tracking spreadsheet (suggested format)

| Target | Sent | Status | Notes | Next action |
|---|---|---|---|---|
| Pitchtank | YYYY-MM-DD | replied/declined/no-response | … | call YYYY-MM-DD |
| Tymora | … | … | … | … |
| FindMeMail | … | … | … | … |
| AgentSwarms | … | … | … | … |
| Anything app | … | … | … | … |

Keep this private — don't commit to the public repo.

---

## What "good" looks like on Sep 29

If on Monday Sep 29 we have:
- 3+ "yes, let's audit" responses → great, proceed with the 5 targets we have
- 2 "yes" + 3 "no response" → drop the no-responses, pick 1 alternate, proceed with 3
- 1 "yes" + 4 "no" → reassess. Maybe the launch teardown becomes a self-audit instead. Either way, October 6 still ships — the launch content adapts.

The point isn't to land all 5. The point is to have *at least one* polished teardown ready for Oct 6. Pitchtank is the safest bet for that.
