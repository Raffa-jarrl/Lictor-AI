# FloQast HackerOne Submission — `qe-dashboard-test.floqast.engineering`

**Submit at:** https://hackerone.com/floqast/reports/new
**FloQast paid H1 program · in-scope:** `https://*.floqast.engineering` (wildcard)
**Realistic payout for takeover:** $500-$2,500

---

## Title
```
Subdomain takeover — qe-dashboard-test.floqast.engineering (GitHub Pages, unclaimed)
```

## Weakness
`CWE-269 Improper Privilege Management` or use HackerOne's "Server Security Misconfiguration > Subdomain Takeover"

## Severity (CVSS)
**6.5 — Medium-High** (network attack vector, low complexity, no auth needed, full content control)

## Description (paste into HackerOne form)

```
## Summary

`qe-dashboard-test.floqast.engineering` has a CNAME record pointing to a
GitHub Pages URL (`shiny-dollop-mve9z8e.pages.github.io`), but no GitHub
Pages site currently serves content at that location. GitHub returns the
standard "Page not found · GitHub Pages" 404 page — the takeover
signature.

The `shiny-dollop-mve9z8e` repository identifier suggests this CNAME was
previously pointed at an output of `actions/deploy-pages` from a workflow
run. The destination repository or Pages config has since been removed,
leaving the DNS record orphaned.

## Steps to reproduce

1. Verify DNS:
   $ dig +short CNAME qe-dashboard-test.floqast.engineering
   shiny-dollop-mve9z8e.pages.github.io.

2. Verify takeover signature:
   $ curl -ki https://qe-dashboard-test.floqast.engineering/
   HTTP/2 404
   server: GitHub.com
   content-length: 9379

   <!DOCTYPE html>
   <html>
     <head>
       <title>Page not found &middot; GitHub Pages</title>
     ...
       <h1>404</h1>
       <p><strong>File not found</strong></p>
       <p>The site configured at this address does not contain the requested file.</p>

3. Exploitation: An attacker creates a repository at the matching
   organization/path, enables GitHub Pages, and configures the same
   custom domain. GitHub provisions a Let's Encrypt cert for the host
   and serves attacker-controlled content from
   `https://qe-dashboard-test.floqast.engineering/`.

## Scope

The asset matches FloQast's published in-scope wildcard:
`https://*.floqast.engineering` (per the HackerOne FloQast program page).

## Impact

- **Phishing**: a "qe-dashboard" page on a legitimate FloQast subdomain
  is an excellent phishing target for FloQast employees and QA team
  members who'd recognize the URL.
- **Internal tool confusion**: anyone with bookmarks to this URL (likely
  the QA/engineering team) will land on attacker content.
- **Cookie scope abuse**: any cookies set with `Domain=.floqast.engineering`
  can be read/set from the takeover host.
- **Phishing employees with insider knowledge**: the URL pattern
  ("qe-dashboard-test") is internal naming — only FloQast employees
  would recognize and trust the host, making targeted attacks higher-
  conversion.

## Remediation

One of:
1. Remove the CNAME record entirely if `qe-dashboard-test` is deprecated.
2. Re-claim the GitHub Pages site at the repo/org that owns
   `shiny-dollop-mve9z8e.pages.github.io`.
3. Point the CNAME elsewhere.

## Suggested broader hygiene

This CNAME pattern (`*.pages.github.io` output from
`actions/deploy-pages`) is easy to miss when repos are deleted. I'd
recommend an audit of all DNS records in `floqast.engineering` against
their corresponding GitHub Pages claims.

## Tooling

Discovered via [Lictor](https://lictor-ai.com) automated subdomain
takeover patrol (open-source, Apache 2.0). Lictor enumerated subdomains
via crt.sh + Wayback Machine + Certificate Transparency, then matched
each CNAME against ~66 known-vulnerable provider fingerprints from
can-i-take-over-xyz.

## References

- can-i-take-over-xyz GitHub Pages entry:
  https://github.com/EdOverflow/can-i-take-over-xyz#github-pages
- GitHub Pages takeover writeup:
  https://hackerone.com/reports/1101111
```
