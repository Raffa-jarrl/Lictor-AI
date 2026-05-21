# Voice guide — Lictor v3 submission drafts

This guide governs how Raven writes drafts and how Lion enforces them.

## Tone

Neutral technical. Like a colleague writing a code review comment — direct, specific, no hype.

## What you write

- Short declarative sentences
- Specific evidence (quoted headers, command outputs)
- Numbered repro steps that work cold
- Defensible CVSS vectors
- Specific remediations (config flags, code changes)

## What you DON'T write

| Don't write | Why |
|---|---|
| "Critical" without proven exfil chain | Over-severity = triager skepticism |
| "Obvious" | Reads as condescending |
| "Trivial to exploit" | Reads as condescending |
| "You should" | Use direct imperative ("Pin ACAO to allow-list") |
| "Easily" / "simply" / "just" | All hype words |
| "RCE possible" without working chain | Speculation |
| "Industry standard" without citation | Vague |
| "Massive impact across all users" without quantification | Vague |
| "Like CVE-XXXX" | Comparison without proof |
| First-person speculation | Stick to what you observed |
| "I would have done X" | Irrelevant |
| Emojis | Unprofessional in this context |
| Bold for emphasis | Use structure instead |
| "Hoping this is rewardable" / "looking forward to your reply" | Begging tone |

## What you MUST include

1. **Title** — problem + impact in ≤140 chars
2. **Summary** — 2-4 sentences, no hype
3. **Steps to reproduce** — numbered, with exact commands
4. **Impact** — specific scenarios, quantified where possible
5. **Remediation** — specific config/code changes
6. **Tooling line** — `Discovered via Lictor (https://lictor-ai.com) — open-source security scanner (Apache 2.0).`
7. **Scope citation paragraph** — quoting the program's scope page directly
8. **Ethical-disclosure footer** — customized to the finding class

## Anti-patterns Lion auto-rejects

- Missing ethical-disclosure footer
- Any "star us" / "donate" / "sponsor" language anywhere in the draft
- CVSS Critical with no proven exfil OR no proven write capability
- "Estimated payout: $X" in the draft body (that's internal, not in submission)
- Speculation without evidence
- Generic remediation ("be more careful with CORS")
- Comparison to other reports without specific contrast

## Worked example: GOOD vs BAD

### BAD (auto-rejected by Lion)
> An attacker can easily and trivially exploit this critical CORS vulnerability to obviously dump all user data. Industry standard remediation applies. Looking forward to the bounty — please give us a star at github.com/Raffa-jarrl/Lictor-AI!

### GOOD
> The endpoint reflects any Origin with credentials=true. Attached PoC (Steps 1-3) demonstrates cross-origin credentialed read of /api/me on the authenticated user. CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N = 7.4 (High). Remediation: pin Access-Control-Allow-Origin to a specific allow-list of trusted origins when ACAC: true is required. See OWASP CORS Cheat Sheet.

## Per-platform tonal nudges

- **HackerOne**: triagers are technical, expect CVSS-vector defensibility
- **Bugcrowd**: VRT classification matters, slightly more terse
- **Intigriti**: European triagers, slightly more formal English
- **YesWeHack**: similar to Intigriti, French-influenced, formal
