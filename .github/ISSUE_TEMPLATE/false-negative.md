---
name: False negative — bug Lictor should have caught
about: Lictor scanned your code and missed a real security bug. We want to add a pattern.
title: '[false-negative] '
labels: ['false-negative', 'high-value']
assignees: []
---

> **Why this template exists separately:** false negatives are the most valuable bug reports we get. They expand the catalog. Please use this instead of the generic bug template when applicable.

## The attack pattern Lictor missed

One sentence naming the bug class. Examples:

- "Lictor missed an unauthenticated `/api/v2/profile` endpoint because the matcher only checks `/api/`"
- "`@lictor/sentinel` doesn't catch the new `sk-svcacct-` prefix for OpenAI service-account keys"
- "PII-leak doesn't catch UK National Insurance Numbers in model output"

## A minimal repro

Either:

**(a) A small code snippet** that should have tripped a check:

```ts
// What we expected Lictor to flag:
const key = "sk-svcacct-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ";
```

**(b) A real (anonymized) example** from your own codebase + the audit report:

> `src/lib/auth.ts:14` had `apiKey = process.env.OPENAI_KEY ?? "sk-..."` — Lictor missed the fallback string. Audit reported "no findings."

## Why it's an attack pattern worth catching

Brief: what category of attacker exploits this, what damage they can cause.

## (Optional) Proposed pattern

If you have an idea of what the regex/rule should look like:

```
sk-svcacct-[A-Za-z0-9_-]{40,}
```

## (Optional) Public reference

A blog post, CVE, OWASP entry, or social media thread documenting the attack.

---

**What happens next:** if confirmed, we'll add the pattern + a positive test case + a negative test case (something that LOOKS similar but is safe) in the next minor release. You'll get credit in the changelog and (with your permission) in the SECURITY.md hall of fame.
