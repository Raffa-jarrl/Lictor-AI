---
name: Bug report
about: Something Lictor did wrong, or something Lictor should have caught but didn't
title: '[bug] '
labels: ['bug']
assignees: []
---

## Which component?

- [ ] `core` (Rust check engine)
- [ ] `shield` (Chrome extension)
- [ ] `sentinel` (TypeScript SDK)
- [ ] `sentinel-py` (Python SDK)
- [ ] `guardian` (Next.js dashboard)
- [ ] `skills` (Claude Code plugins — `/lictor-*`)
- [ ] `landing` (marketing site)
- [ ] Multiple / unclear

## Version / commit

The version of the package you used (e.g. `@lictor/sentinel@0.1.0-alpha.0`), or the git SHA if you built from source.

## What you expected to happen

One sentence.

## What actually happened

One paragraph + a code snippet, error message, or screenshot if useful.

## Repro steps

1. ...
2. ...
3. ...

(If the bug is in `/lictor-security-check`: paste the offending file or code snippet directly — that's the most useful repro.)

## Your environment

- OS: macOS / Linux distro / Windows version
- Node / Python / Rust version (if relevant)
- Browser + version (if Shield-related)
- Claude Code version (if skills-related)

## Anything else

Logs, related issues, gut feelings about what's broken.

---

*Bug reports that include specific file paths, line numbers, and copy-pasteable repros get triaged the fastest.*
