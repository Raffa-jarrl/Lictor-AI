# Security policy

## Reporting a vulnerability

If you've found a security issue **in Lictor itself** (not in a site that Lictor scans), please report it privately.

**Do not open a public GitHub issue.**

### Report channel

Email: `security@lictorai.com` (PGP key forthcoming).

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
- The `lictorai.com` website and infrastructure

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
- Avoid degrading service for users (no DDoS, no automated mass-scanning of `lictorai.com`)
- Give us a reasonable disclosure window before going public
- Don't access, modify, or destroy data that isn't theirs

If you're unsure whether something is in scope, **ask first** — `security@lictorai.com`.
