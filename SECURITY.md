# Security policy

## How we disclose issues we find in *your* code

Lictor is a security scanner. When our research surfaces a **potential** issue in
someone else's project, **we disclose it privately — never as a public GitHub
issue.** A public "security finding" issue points every onlooker at a possible
weakness before the maintainer has had a chance to fix it. That is the opposite of
helping. Our outbound-disclosure rules:

- **Private first.** We contact the maintainer through a private channel (their
  `SECURITY.md` contact or a GitHub *private security advisory*) — never a public
  issue, PR, or comment.
- **Detection-only, non-exploitative.** Lictor confirms a *signature*, not a
  payload. We do not read your data, dump your database, or exploit the finding.
  Every disclosure states explicitly what we did **not** do.
- **No naming-and-shaming.** We never publish the name of an affected project
  next to an unfixed finding. Aggregate, anonymized statistics only.
- **You set the clock.** Coordinated disclosure on the maintainer's timeline.

> **Correction (June 2026):** earlier in development we opened a small number of
> *public* "Security finding" issues on third-party repositories. That was a
> mistake — it is exactly the practice this section now forbids. Those issues have
> been closed, no Lictor tooling opens public issues, and our thanks go to the
> maintainers who flagged it.

## Reporting a vulnerability

If you've found a security issue **in Lictor itself** (not in a site that Lictor scans), please report it privately.

**Do not open a public GitHub issue.**

### Report channel

Email: `security@lictor-ai.com` (PGP key forthcoming).

Include in your report:
- The affected version (commit SHA or release tag)
- Steps to reproduce
- The attacker model — what does an attacker need to be able to do?
- Impact assessment — what does the attacker gain?

### What to expect

| Time | What happens |
|---|---|
| < 48 hours | Acknowledgement of receipt |
| < 7 days  | Initial triage — confirmed / not-a-vulnerability / need-more-info |
| < 30 days | Fix shipped or coordinated disclosure date agreed |
| < 90 days | Public disclosure (sooner with reporter consent) |

We follow [coordinated vulnerability disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process) and credit reporters by default unless they request anonymity.

## What's in scope

- `lictor-core` — the engine, native and WASM
- `lictor-shield` — the Chrome extension
- `lictor-sentinel` — the SDK (when Phase 2 ships)
- `lictor-guardian` — the hosted service (when Phase 3 ships)
- The `lictor-ai.com` website and infrastructure

## What's NOT in scope

- Vulnerabilities in dependencies (those should be reported upstream — but please tell us if Lictor's pinned version is affected)
- Vulnerabilities in sites that Lictor scans — Lictor's checks are detection-only and don't exploit anything; if a site Lictor flagged actually has the bug Lictor flagged, please report it to that site's operator
- Findings about Lictor's brand (e.g. "you used the wrong shade of purple") — those go in regular issues
- Self-XSS or social-engineering attacks against Lictor users that don't involve a Lictor bug

## Bounty

We do not currently run a bug bounty program. We aim to start one once Lictor is past Phase 3 (Guardian shipped, paying customers, sustainable revenue). Until then, our gratitude + public credit is what we can offer.

## Safe-harbor language

Good-faith security research is welcome. We will not pursue legal action against researchers who:
- Stay within the scope above
- Avoid degrading service for users (no DDoS, no automated mass-scanning of `lictor-ai.com`)
- Give us a reasonable disclosure window before going public
- Don't access, modify, or destroy data that isn't theirs

If you're unsure whether something is in scope, **ask first** — `security@lictor-ai.com`.
