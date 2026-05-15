---
name: Pattern request — add a vulnerability pattern Lictor should catch
about: There's a specific attack pattern (XSS variant, AI prompt injection family, supply-chain shape, etc.) Lictor doesn't currently detect. These are our highest-value requests.
title: 'pattern: '
labels: ['pattern-request', 'triage', 'high-value']
assignees: ''
---

## The pattern

<!-- One-line: what kind of bug should Lictor catch? -->

## A real example

<!-- Paste real-looking code (anonymized if needed) that has this pattern.
     If you're aware of a public app where this pattern actually shipped,
     link it (only if it's already been disclosed publicly). -->

```
[paste the vulnerable code]
```

## Why generic tools miss this

<!-- Lictor's edge is patterns generic SAST tools don't catch.
     Why does Snyk / Semgrep / Trivy / GitHub Advanced Security miss this?
     - Platform-specific (Lovable / Bolt / v0 idiom)?
     - AI-built-app specific (hallucinated package, embedded prompt)?
     - Cross-tenant / RLS specific?
     - Other? -->

## What a Lictor finding would look like

<!-- Sketch the plain-English finding text. Voice matters.
     Title: short
     Summary: 1-2 sentences in plain English
     Fix: 1-line summary -->

```
🔴 [SEVERITY] [TITLE]
[SUMMARY in plain English]
Fix: [1-line summary]
```

## How sure are you this is real?

- [ ] I've seen this in production (someone shipped it)
- [ ] I've seen this in an AI-generated codebase
- [ ] I've theorized this but haven't seen it in the wild
- [ ] I read about it in [link]

## Test cases you'd want

<!-- POSITIVE: code that should trigger the new check.
     NEGATIVE: code that looks similar but should NOT trigger (false-positive risk). -->

**Should trigger:**
```
[positive test case]
```

**Should NOT trigger:**
```
[negative test case — similar but safe]
```

---

## Why pattern requests are our highest-value reports

A new pattern request, well-formed, is the single most impactful thing a community member can contribute. Every accepted pattern becomes a check that protects every future Lictor user. Pattern contributors get:

- Credit in the Lictor CHANGELOG
- Listing on the "pattern authors" page (with consent)
- For high-severity patterns tied to real public incidents: **$100–$1000 from the Lictor bug-bounty program** (launching Apr 2027)
- The deep satisfaction of having improved the security of every Lovable / Bolt / v0 app ever built

Pattern requests go to Radar (the scout agent) + Probe (the validator agent) + a maintainer review pass.

Thanks for filing. This is real OSS contribution.
