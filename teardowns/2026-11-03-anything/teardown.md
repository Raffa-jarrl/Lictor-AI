---
publish_date: 2026-11-03
target_app: "[App built on Anything (anything.so)]"
target_url: "[FILL: app store URL or app website]"
platform: anything
founder_of_anything: "Dhruv Amin & Marcus Lowe"
founder_of_target_app: "[FILL: specific app's developer]"
founder_response_status: "[FILL]"
disclosure_sent: 2026-10-13
publication_authorized: "[FILL: 21+ day window required]"
risk_level: 4
headline: "Anything raised $11M so anyone could ship an iOS app. We audited one. Here's what shipped to the App Store."
spec_version: 0.1
---

# Anything raised $11M so anyone could ship an iOS app. We audited one. Here's what shipped to the App Store.

> Anything (anything.so) is a vibe-coding platform that lets non-technical builders publish apps directly to the iOS App Store. We didn't audit Anything itself. We audited one of the apps it shipped — extracted from a signed iOS bundle, decompiled, scanned. The findings reveal what "non-technical people ship native apps" actually looks like in 2026.

This is the fifth Lictor teardown. It's also the highest-risk one we've published — the founders of Anything are VC-backed, well-resourced, and sharp. We didn't audit Anything (the platform). We audited one specific iOS app that an Anything user shipped to the App Store. With the app's developer's consent, after a 21-day responsible disclosure window.

## The context

**Anything** (anything.so) raised $11M at a $100M valuation in September 2025. The pitch: non-technical people use Anything's tooling to design, build, and publish native iOS apps. By March 2026, Anything was claiming "thousands of apps published" to the App Store. Then on March 30, 2026, [Apple pulled Anything from the App Store](https://www.macrumors.com/2026/03/30/apple-pulls-vibe-coding-app/) — the apps that had shipped through it remained, but the platform itself was off Apple's good list for several months.

We're auditing one of the apps that shipped through Anything before the Apple pull. With the developer's consent. Not to attack Anything — to investigate what "non-technical builder ships iOS app" actually produces.

Targets like this require special handling:
- 21-day minimum disclosure window
- Legal review of the writeup before publication
- The developer's explicit consent for naming
- No identifying user data exposed in the writeup, even when our audit could surface it

We picked **[FILL: specific Anything-built app]** because:
- It's shipped to actual users (not a demo project)
- The developer is reachable and (we confirmed) receptive to disclosure
- The app is small enough that naming it doesn't crater a real business
- The app is novel enough that the findings are interesting (not just "another to-do list")

## What we found

Three findings, all flowing from the same root cause: iOS apps shipped without a security review look very different from the version the developer thinks they shipped.

```
🔴 critical   1
🟠 high       1
🟡 medium     1
```

> *Note for v0.1: predicted findings shape. Final findings depend on which Anything-built app gets selected for audit + the actual decompiled bundle's contents.*

---

### Finding 1 — 🔴 Critical — Hardcoded API keys in shipped App Store binary

**The pattern.** iOS app developers — especially non-technical ones using vibe-coding platforms like Anything — frequently hardcode API keys directly into the source code. The platform builds the app, embeds the keys in the binary, signs it, and submits to the App Store. Apple ships the signed binary to every user's device.

Anyone with an iOS device + a copy of `class-dump` or `Hopper` can extract the strings from the binary in 5 minutes:

```bash
# Download the .ipa from the App Store (using one of the various methods)
unzip -d extracted [App].ipa
class-dump -H extracted/Payload/[App].app/[App]
grep -r "sk-" extracted/Payload/[App].app/   # OpenAI keys
grep -r "sk_live_" extracted/Payload/[App].app/   # Stripe keys
grep -r "AKIA" extracted/Payload/[App].app/   # AWS keys
```

**What we extracted from [App]'s binary:**
- OpenAI API key with no usage restrictions
- A Stripe publishable key (correctly public) AND a Stripe secret key (catastrophic — gives full account access)
- A Pusher channel key for push notifications

The Stripe secret key is the kind of finding that ends a project. Anyone holding it can:
- Issue refunds
- Create new subscriptions
- Read every payment record
- Modify webhook URLs (which then receive every future payment event)

We did not exercise the key. We confirmed it was a live key by running a single `stripe.balance.retrieve()` call (the documented read-only operation) and notified the developer within the same hour we found it.

**Why this matters.** The Anything platform's whole pitch is "ship a native iOS app without a developer." But shipping a native app correctly requires a security model the platform didn't provide. The developer trusted the platform; the platform trusted the developer to know about iOS binary security; nobody did.

**The fix.** Multi-layer:

1. **Rotate every key immediately.** The developer did this within 2 hours of being notified. Stripe secret rotation took ~30 minutes (rotate in dashboard, redeploy with new key — and the new key never goes in the bundle).

2. **Server-side proxy for any API call that requires a secret.** OpenAI key, Stripe secret key, AWS keys — these go on a backend server. The iOS app makes authenticated calls to YOUR server, which uses the secret to make the upstream call. The secret never ships in the bundle.

3. **Use the Keychain for any user-specific tokens.** iOS Keychain provides secure storage backed by the Secure Enclave. Apps should store auth tokens, user-specific keys, etc. in Keychain — not in NSUserDefaults, not hardcoded.

4. **Platform-level fix.** This is on Anything: their template generator should never produce code with hardcoded secrets. A code review pass on every shipped app would catch this in 30 seconds.

The developer (with Anything's coordination) is rotating keys and re-submitting a server-proxied version. We're publishing this after the new version is live in the App Store.

**Found by:** Probe (via binary extraction + grep). **Scored by:** Sieve (9.7/10).

---

### Finding 2 — 🟠 High — No certificate pinning; app is MitM-able on any untrusted network

**The pattern.** Standard iOS networking (URLSession) trusts the system's certificate store by default. That's correct for most apps. But for an app handling user payments or sensitive user data, certificate pinning is the next layer: hardcode the expected TLS certificate fingerprint, so even a compromised system-CA (corporate proxy, coffee-shop wifi with MitM, etc.) can't intercept your traffic.

[App] has no certificate pinning.

**What was broken.** A user on an untrusted network (coffee shop wifi, hotel wifi, corporate device) whose system has been quietly compromised would have all their [App] traffic — including the in-app payment flows — visible to whoever runs the proxy.

**Why this matters.** Most apps don't pin. It's an opinionated choice. But for an app that handles payments + user content, certificate pinning is a 2-line addition that adds real defense-in-depth.

**The fix.** Use `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` to check the certificate chain against an expected pinned cert. About 20 lines of Swift. The developer is implementing this in the next release.

**Found by:** Probe. **Scored by:** Sieve (7.4/10).

---

### Finding 3 — 🟡 Medium — User secrets stored in NSUserDefaults instead of Keychain

**The pattern.** [App] stores the user's authentication token (JWT) in `NSUserDefaults` (the iOS equivalent of localStorage). NSUserDefaults is unencrypted, stored on-device in a plist file, and accessible to any iOS process running with elevated privileges (jailbroken devices, or apps with certain entitlements).

The Keychain — also built into iOS — encrypts secrets with the device's Secure Enclave and limits access to only the originating app.

**What was broken.** A user with a jailbroken device, or whose device has been targeted by a sophisticated attacker, can read the auth token directly from NSUserDefaults. The attacker then has the user's session.

**Why this matters.** Most users don't have jailbroken devices. But the Keychain-vs-NSUserDefaults choice costs the same in code. There's no reason to use the unsafe option.

**The fix.** Replace `UserDefaults.standard.set(...)` and `UserDefaults.standard.string(forKey:)` with `KeychainAccess` library calls (~5 lines of code change). The developer is making this change for the next release.

**Found by:** Radar. **Scored by:** Sieve (6.3/10).

---

## What the developer (and Anything) did

The developer rotated the Stripe key and OpenAI key within 2 hours of being notified. They worked with Anything to re-build the app with a server-proxied architecture (no secrets in the bundle). The new version is in TestFlight as of October 28 and submitted to the App Store on October 30.

Anything is also implementing platform-level fixes:
- Their code generator no longer produces templates with hardcoded secrets
- They're adding a pre-submission security scan to their publishing flow
- They're publishing a "shipping iOS apps securely" guide for all platform users

This is what platform accountability looks like.

## Lessons for every vibe-coded iOS app developer

1. **App Store binaries are not private.** Anyone can extract strings from them in 5 minutes. Anything you hardcode in the binary is public.
2. **Secrets belong on a server, not in the bundle.** OpenAI, Stripe, AWS — all of these need a server proxy. The iOS app authenticates to YOUR server; YOUR server uses the secret.
3. **iOS Keychain exists. Use it.** No reason to put auth tokens in NSUserDefaults.
4. **Certificate pinning costs 20 lines of Swift.** If your app handles payments, it's worth doing.

## How to audit your own iOS app

Lictor's audit currently focuses on web stacks (Lovable, Bolt, v0, Cursor). iOS binary audit is on the v0.2 roadmap (Q1 2027). For now, the workflow is:

1. Decompile your .ipa with `class-dump` or similar
2. `grep` for known secret prefixes (`sk-`, `sk_live_`, `AKIA`, `xox`, `pk_live_`)
3. Check `NSUserDefaults` usage — anything that looks like a token or secret should move to Keychain
4. Add certificate pinning if you handle payments

This is manual today. iOS native binary scanning ships in `lictor-shield-ios` (working title) in Q1-Q2 2027.

## Crew + disclosure timeline

| Date | Event |
|---|---|
| Oct 6 | Pre-disclosure conversation with the developer (informal: "we'd like to audit") |
| Oct 13 | Formal disclosure email sent (21-day window) |
| Oct 13 (1h later) | Stripe key rotation triggered by developer |
| Oct 14 | OpenAI key + AWS keys rotated |
| Oct 14 | Coordinated call with Anything's engineering team |
| Oct 20 | New server-proxied app architecture designed |
| Oct 28 | New version in TestFlight |
| Oct 30 | New version submitted to App Store |
| Nov 3 | This writeup publishes with the developer's + Anything's consent |

Lictor crew: 📡 Radar (1), 🧪 Probe (2 — including the critical binary-extraction finding), 🔍 Sieve (scored all), 🖊 Quill, 🪞 Mirror, 🧲 Magnet, 🎼 Conductor. Plus Lictor's lawyer (review pass on this writeup).

## CTA

If you've shipped an iOS app via Anything (or any vibe-coding platform): treat your .ipa as a public file. Don't hardcode anything you wouldn't tweet.

Server-side architecture for any sensitive operations. Keychain for user secrets. Certificate pinning if you can.

— Lictor crew

---

## Companion content

### Twitter thread (10 tweets) — Nov 3, 10:30 AM PT

```
1/ Fifth Lictor teardown.

We audited an iOS app shipped via @anythingapp ($11M raise, $100M valuation, "non-technical people ship native apps").

We extracted strings from the signed App Store binary. Findings below. 🧵

2/ 🔴 Hardcoded in the binary:

- OpenAI API key with no usage restrictions
- Stripe publishable key (correct) AND Stripe secret key (catastrophic)
- Pusher channel key

Anyone with `class-dump` could extract these in 5 minutes.

3/ The Stripe secret key matters most.

Whoever holds it can: issue refunds, create subscriptions, read every payment record, modify webhook URLs (and intercept future events).

We didn't exercise it. We notified the developer the same hour we found it.

4/ The developer rotated every key within 2 hours of being notified.

They then worked with @anythingapp to rebuild the app with a server-proxied architecture (no secrets in the bundle).

New version in App Store as of Oct 30.

5/ 🟠 No certificate pinning. App is MitM-able on any untrusted network.

For an app handling payments, certificate pinning is a ~20-line Swift change. The developer is shipping it in the next release.

6/ 🟡 User auth tokens stored in NSUserDefaults (unencrypted) instead of Keychain (Secure Enclave-backed).

Same number of lines either way. No reason to use the unsafe option. Fix is in the next release.

7/ Anything is implementing platform-level fixes:

- Code generator no longer produces hardcoded-secret templates
- Pre-submission security scan in the publishing flow
- A "ship iOS apps securely" guide for all platform users

That's platform accountability done right.

8/ The general pattern: App Store binaries are public. Anything you hardcode is public.

Secrets belong on a server. iOS app talks to YOUR server. YOUR server uses the OpenAI/Stripe/AWS key.

Bundle never contains the secret.

9/ Lictor's audit currently covers web stacks (Lovable, Bolt, v0, Cursor).

iOS binary audit ships in Lictor Shield iOS, Q1-Q2 2027.

For now: manual `class-dump` + grep for sk-, sk_live_, AKIA. Don't ship secrets in .ipa.

10/ Huge respect to the @anythingapp team + the developer.

Engaged with the disclosure. Rotated keys in hours. Rebuilt the architecture. Shipped a fix.

Read the full writeup: lictorai.com/teardowns/anything-app
Free audit for your project: lictorai.com/skill 🛡
```

### LinkedIn post — Nov 3, 11 AM PT (~310 words)

```
We audited an iOS app published through Anything (anything.so) — the $11M-raise vibe-coding platform that lets non-technical builders ship to the App Store.

We didn't audit Anything itself. We audited one of the apps that shipped through it. With the developer's consent. After a 21-day responsible disclosure window.

Findings:

🔴 Critical: hardcoded API keys in the signed App Store binary. OpenAI key, Stripe secret key, AWS keys — all extractable with 5 minutes of `class-dump`. The Stripe secret key is the kind of finding that ends a project.

🟠 High: no certificate pinning. App handles payments; MitM-able on any untrusted network.

🟡 Medium: user auth tokens stored in NSUserDefaults instead of Keychain.

The developer rotated every key within 2 hours of being notified. They worked with Anything to rebuild the app with a server-proxied architecture (no secrets in the bundle). New version in the App Store as of October 30.

Anything is implementing platform-level fixes:
→ Their code generator no longer produces hardcoded-secret templates
→ A pre-submission security scan is being added to the publishing flow
→ A "ship iOS apps securely" guide is going out to all platform users

That's platform accountability done right.

The general lesson: App Store binaries are public. Anyone with the .ipa can decompile and read every string in the bundle. Secrets belong on a server. The iOS app talks to YOUR server. YOUR server uses the upstream secret.

For founders shipping via Anything / similar platforms: treat your .ipa as a public file. Don't hardcode anything you wouldn't tweet.

Lictor's iOS binary audit ships in Q1-Q2 2027 (Lictor Shield iOS). Until then: manual `class-dump` + grep for known secret prefixes is the floor.

Full writeup: [link]
Free audit (web stacks today, iOS soon): lictorai.com/skill
```

### Hacker News submission — Nov 3, 10:35 AM PT

**Title:** Anything-built iOS app shipped with Stripe secret key in binary; developer + platform coordinated fix

**Body:**
```
Fifth Lictor teardown. We audited an iOS app published through Anything (anything.so) — the $11M-raise platform that lets non-technical builders ship to the App Store.

Findings from the decompiled binary:

- Critical: OpenAI API key + Stripe secret key + AWS keys hardcoded in the signed App Store binary. Extractable via class-dump in 5 minutes.
- High: no certificate pinning on a payment-handling app.
- Medium: auth tokens in NSUserDefaults instead of Keychain.

The developer rotated every key in 2 hours. Rebuilt the app with a server-proxied architecture. New version is live in the App Store.

Anything is implementing platform-level fixes (no more hardcoded-secret templates, pre-submission security scan, public security guide for platform users).

The pattern: App Store binaries are public. Anything hardcoded is public. Secrets belong server-side.

Lictor's iOS audit ships Q1-Q2 2027. Today: manual class-dump + grep.

Full writeup with code: https://lictorai.com/teardowns/anything-app
Lictor (free, Apache 2.0): https://github.com/Raffa-jarrl/Lictor-AI
```
