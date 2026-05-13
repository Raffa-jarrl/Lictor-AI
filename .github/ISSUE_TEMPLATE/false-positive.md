---
name: False positive — Lictor flagged safe code
about: Lictor reported a problem in code that's actually fine. We want to tighten the pattern.
title: '[false-positive] '
labels: ['false-positive']
assignees: []
---

## What Lictor flagged

Copy-paste the finding from your `SECURITY-AUDIT.md` or your Sentinel `IncidentEvent`:

```
> 1. ...
🟠 HIGH · src/some/file.ts:42
```

## The code that was flagged

```ts
// paste 5-10 lines of context around the flagged line
```

## Why it's actually safe

One paragraph. The shape of a good explanation:

> "The string `sk-xxx-test-only` is a hardcoded TEST value used in the unit test fixtures (see `tests/fixtures/`). It's not a real key. Stripe will reject any attempt to use it."

Or:

> "The `/api/users` endpoint requires the `Authorization` header — which is verified at line 18 by `await getServerSession(authOptions)`. Lictor's grep didn't see this because the auth call uses a wrapper function `requireAuth()` whose body imports `getServerSession` from a separate file."

## (Optional) Proposed fix

How should Lictor's pattern be tightened? Examples:

- "Skip secrets-in-input patterns inside files under `tests/` or `fixtures/`"
- "Allow `Authorization` header check to count as auth even when wrapped in a helper function"
- "Recognize `sk-test_` prefix as informational, not critical"

---

**What happens next:** if we can reproduce the false positive without breaking the original detection, we'll tighten the rule + add a regression test (with both the false-positive sample as a negative case and a real attack sample as a positive case). Changelog credit.

False-positive feedback is genuinely valuable — every fix here makes Lictor more trustworthy. Thanks.
