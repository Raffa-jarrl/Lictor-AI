# Booking.com HackerOne Submission — Production source map exposed on fareharborsites.com

**Submit at:** https://hackerone.com/booking_com/reports/new (or `/booking` slug)
**Program:** Booking.com Bug Bounty (paid) · **In-scope:** `fareharborsites.com` (URL, max_severity: critical, eligible_for_bounty: true)
**Realistic payout:** $200–$1,500 (typical for production source-map exposure)

---

## Title
```
Production JavaScript source map exposed on fareharborsites.com — reveals internal frontend source code
```

## Weakness
`CWE-540 Inclusion of Sensitive Information in Source Code` (or HackerOne's "Information Disclosure > Source Code Exposure")

## Severity (CVSS:3.1)
**Medium — 5.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

The production JavaScript bundle served from
`https://fareharborsites.com/wp-content/themes/vendor/fareharbor-sites/the-anchor/dist/assets/frontend/`
ships with `sourceMappingURL=*.js.map` directives, and the referenced
`.map` files are publicly fetchable (HTTP 200 with valid source-map
JSON structure).

Source maps expose the pre-minified, pre-mangled source code of the
shipped bundle — including original filenames, original variable
names, inline comments, and any string literals that didn't need to
be public (internal API endpoints, feature flags, test-mode toggles,
etc.).

## Steps to reproduce

1. Visit the fareharborsites.com WordPress storefront. Observe in
   Network tab the frontend bundle loading from a `/dist/assets/`
   path.

2. Fetch the JS file directly:
   $ curl -sk "https://fareharborsites.com/wp-content/themes/vendor/fareharbor-sites/the-anchor/dist/assets/frontend/index.l0sNRNKZ.js" | tail -1
   ...
   //# sourceMappingURL=index.l0sNRNKZ.js.map

3. Fetch the source map:
   $ curl -skI "https://fareharborsites.com/wp-content/themes/vendor/fareharbor-sites/the-anchor/dist/assets/frontend/index.l0sNRNKZ.js.map"
   HTTP/2 200
   server: nginx
   date: Wed, 20 May 2026 00:16:18 GMT

4. The body is a valid source map JSON (contains `version`, `sources`,
   `mappings`, etc.) — the original source code can be reconstructed
   using any source-map viewer (Chrome DevTools, sourcemap-explorer,
   source-map-cli).

## Impact

Source-map exposure on a production storefront is medium-severity:

- **Reveals internal frontend source code** — original function
  names, comments, code structure that minification was meant to
  obscure
- **Surfaces internal API endpoints** that may be referenced as string
  literals in the source (booking flow URLs, payment callbacks,
  feature flags)
- **Reveals the build pipeline structure** — paths suggest a
  Vite/Webpack build with `the-anchor` theme architecture, useful
  recon for further analysis
- **Eases vulnerability research** generally — any future bug in the
  FareHarbor sites becomes easier to find with the source available

The file is on `fareharborsites.com` which is in scope for Booking.com's
Bug Bounty Program at max_severity: critical (eligible_for_bounty: true).

## Remediation

Pick one (preferred order):
1. **Strip the `sourceMappingURL` comment** from production builds.
   The `.map` files can still be uploaded to Sentry / Datadog /
   Bugsnag for internal stack-trace symbolication without being
   publicly fetchable.
2. **Don't deploy `.map` files to public-facing CDNs** — keep them in
   a private artifact store accessible only to error-reporting backends.
3. **Configure nginx to 403 on `*.map`** if step 1 isn't easy.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor enumerates production JS bundles on
bounty-program domains and checks each for `sourceMappingURL`
references + confirms the `.map` file is publicly fetchable.

## References

- CWE-540: Inclusion of Sensitive Information in Source Code
- Source-map exposure writeup:
  https://www.bugcrowd.com/blog/javascript-source-mapping
- Sample H1 payouts for similar pattern: report #1041979 ($500)

## Note

I'm also submitting a separate source-map exposure for Expedia Group
(`apps.expediapartnercentral.com`) which is a different program. Filing
this one separately for Booking.com / FareHarbor as the scope is
clearly distinct.
```
