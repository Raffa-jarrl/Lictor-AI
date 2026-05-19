# Expedia HackerOne Submission — Production source map exposed on apps.expediapartnercentral.com

**Submit at:** https://hackerone.com/expediagroup_bbp/reports/new
**Program:** Expedia Group Bug Bounty (paid) · **In-scope:** `*.expediapartnercentral.com` (WILDCARD, max_severity: critical)
**Realistic payout:** $300-$1,500

---

## Title
```
Production JavaScript source map exposed — apps.expediapartnercentral.com/.../arkose.js.map (reveals internal source)
```

## Weakness
`CWE-540 Inclusion of Sensitive Information in Source Code` (or HackerOne's "Information Disclosure > Source Code Exposure")

## Severity (CVSS:3.1)
**Medium — 5.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

The production JavaScript file `arkose.js` served from
`https://apps.expediapartnercentral.com/static-assets/epc/epc-login-web-dw/...`
ships with a `sourceMappingURL=arkose.js.map` directive, and the
referenced `.map` file is publicly fetchable (HTTP 200 with valid JSON
source-map structure).

Source maps expose the pre-minified, pre-mangled source code of the
shipped bundle — including original filenames, original variable names,
inline comments, and any string literals that didn't need to be public
(e.g., internal API endpoints, feature flags, test-mode toggles).

## Steps to reproduce

1. Open the EPC login page in a browser. Observe `arkose.js` loaded
   from a `static-assets/` path on `apps.expediapartnercentral.com`.

2. View the JS file directly:
   $ curl -sk "https://apps.expediapartnercentral.com/static-assets/epc/epc-login-web-dw/bc1fd2f6bafbc61f28e80e1e70cd3910282cb63a/assets/arkose.js" | tail -1
   ...
   //# sourceMappingURL=arkose.js.map

3. Fetch the source map:
   $ curl -sk -I "https://apps.expediapartnercentral.com/static-assets/epc/epc-login-web-dw/bc1fd2f6bafbc61f28e80e1e70cd3910282cb63a/assets/arkose.js.map"
   HTTP/2 200
   content-type: application/json
   x-amz-id-2: Sq2O2ER16JgxaOHqn+WEeRYmKigEkQrufJAxPHKxu/qhMuTfvgSKJLQaQdV8+xnY67xmlad9Treswu1ckbz07HROjCH8E9Gd
   x-amz-request-id: B6B3SVN8V37Q32PH

4. The body is a valid JSON source map (contains `version`, `sources`,
   `mappings`, etc.) — the original source code can be reconstructed
   using any source-map viewer (Chrome DevTools, sourcemap-explorer,
   source-map-cli, etc.).

## Impact

Source-map exposure on a production auth bundle is medium-severity:

- **Reveals internal source code** of the EPC login flow — original
  function names, comments, code structure that minification was meant
  to obscure
- **Surfaces internal API endpoints** that may be referenced as string
  literals in the source (auth callbacks, validation URLs, feature
  flags, etc.)
- **Reveals the Arkose Labs integration details** — including how the
  challenge is invoked, what custom config is passed, and any fallback
  logic. This makes Arkose challenge bypasses easier to research.
- **Eases vulnerability research** generally — any future bug in the
  EPC login flow becomes easier to find with the source available.

The file is on `*.expediapartnercentral.com` which is in scope for
Expedia Group's Bug Bounty Program at max_severity: critical.

## Remediation

Pick one (preferred order):
1. **Strip the `sourceMappingURL` comment** from production builds. The
   `.map` files can still be uploaded to Sentry/Datadog/Bugsnag for
   internal stack-trace symbolication without being publicly fetchable.
2. **Don't deploy `.map` files to public-facing CDNs** — keep them in a
   private artifact store accessible only to error-reporting backends.
3. **Set Cloudfront/S3 to 403 on `*.map`** if step 1 isn't easy.

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor enumerates production JS bundles on
bounty-program domains and checks each for `sourceMappingURL` references
+ confirms the `.map` file is publicly fetchable.

## References

- CWE-540: Inclusion of Sensitive Information in Source Code
- Source-map exposure writeup: https://www.bugcrowd.com/blog/javascript-source-mapping
- Sample H1 payout for similar pattern: report #1041979 ($500)
```
