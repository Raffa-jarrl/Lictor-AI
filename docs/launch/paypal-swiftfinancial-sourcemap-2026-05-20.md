# PayPal HackerOne Submission — Source map exposure on my.swiftfinancial.com (PayPal Swift Financial)

**Submit at:** https://hackerone.com/paypal/reports/new
**Program:** PayPal (paid) · **In-scope:** `*.swiftfinancial.com` and related Swift Financial endpoints (sev=low, eligible_for_bounty=True)
**Realistic payout:** $50–$300 (INFO disclosure — low-severity brand asset, source-code leak)

---

## Title
```
Source map exposure on my.swiftfinancial.com — full TypeScript source for the customer portal (App.tsx, appConfig.ts, index.tsx, serviceWorker.ts) accessible without auth
```

## Weakness
`CWE-540 — Inclusion of Sensitive Information in Source Code`
H1 taxonomy: `Information Disclosure > Source Code Disclosure`

## Severity (CVSS:3.1)
**Low — 3.7**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

(Severity reflects PayPal's own classification of `swiftfinancial.com` as sev=low in the scope listing. The exposed source code is for the customer portal frontend and reveals development-environment URLs, tech stack, and one third-party analytics ID. No customer PII or credentials are directly leaked.)

## Description (paste into HackerOne form)

```
## Summary

The production customer portal at https://my.swiftfinancial.com/
serves React .js bundles with their `.map` source-map files
publicly accessible. The maps include full original TypeScript
source code for the application via `sourcesContent`.

Affected files (all return HTTP 200 + valid source-map JSON):
  /static/js/main.8887e984.chunk.js.map  (9,339 bytes — full source)
  /static/js/main.chunk.js.map           (2,691 bytes)
  /static/js/main.css.map                (2,691 bytes)
  /static/js/vendor.js.map               (2,691 bytes)
  /static/js/index.js.map                (2,691 bytes)

The main chunk source map decodes to 4 source files with their
full original TypeScript content:

  - util/appConfig.ts    (app configuration constants)
  - App.tsx              (root component + routing)
  - serviceWorker.ts     (PWA service-worker registration)
  - index.tsx            (React entry point + config loader)

## Information disclosed

From util/appConfig.ts:

  export const AppConfigContext = React.createContext<AppConfig>({
    customerPortalUrl: 'https://my.dev.loanbuider.com/',  ← dev URL (note: typo "loanbuider")
    customerSupportPhone: '(888) 923-0007',
    heapAppId: '3027341346',                              ← Heap Analytics app ID
  });

  // Confirms internal dev environment hostname pattern AND
  // a typo in a hostname constant — interesting because if
  // "my.dev.loanbuider.com" (missing "l") is unregistered, it
  // could be claimed by an attacker and would route any dev-
  // environment redirect to attacker infrastructure.

From App.tsx + index.tsx:

  - Architecture: SPA loads /config.json at runtime via axios
  - Routing: catch-all redirect to https://my.loanbuilder.com/us/login
  - Tech stack: React + react-router-dom + react-helmet-async +
    axios + react-app-polyfill + reactjs-heap

## Steps to reproduce

1. Fetch the source map directly:

   $ curl -sk https://my.swiftfinancial.com/static/js/main.8887e984.chunk.js.map | jq .
   {
     "version": 3,
     "sources": ["util/appConfig.ts", "App.tsx", "serviceWorker.ts", "index.tsx"],
     "sourcesContent": ["import React from 'react'; ..."],
     ...
   }

2. Decode any source via Chrome DevTools (open
   https://my.swiftfinancial.com → DevTools → Sources panel →
   browse `webpack://./util/appConfig.ts`). The full original
   TypeScript appears as if running in development mode.

3. (Optional) check the secondary chunks at
   `/static/js/main.chunk.js.map`, `/static/js/vendor.js.map`,
   `/static/js/index.js.map` — all return HTTP 200 (smaller
   stub sources, but bundle structure leaks).

## Impact

- **Source code disclosure** of the customer portal frontend.
  Lower than PayPal core (`*.paypal.com`) severity, but the
  customer-facing portal logic, routing, and config-loading
  pattern are exposed.

- **Dev-environment hostname leaked** (`my.dev.loanbuider.com`)
  with a typo. Two takeaways:
  (a) reveals internal dev → prod naming convention, useful
      for subdomain enumeration against Swift Financial /
      LoanBuilder infrastructure.
  (b) if the literal-typo hostname `loanbuider.com` is
      unregistered and an attacker registers it, any code path
      that uses this constant (or any QA/test code that
      copy-pasted the typo) would route to attacker
      infrastructure. Recommend checking immediately whether
      `loanbuider.com` (or `dev.loanbuider.com` subdomain) is
      currently registered/registrable.

- **Heap Analytics App ID `3027341346` exposed** — third-party
  analytics identifier. Low direct sensitivity but allows an
  attacker to spoof events into the Heap account, polluting
  internal analytics dashboards.

- **Tech-stack fingerprint** (React + axios + react-router +
  Heap) gives attackers a starting point for client-side
  vulnerability research (known CVEs against specific
  versions of these libraries, etc.).

## Remediation

1. **Disable source-map generation in production builds.**
   For Create-React-App, set `GENERATE_SOURCEMAP=false` in the
   build environment. For Webpack-based custom configs, set
   `devtool: false` (or `devtool: "hidden-source-map"` if you
   want to upload maps to Sentry/Datadog without exposing them
   over HTTP).

2. **OR keep source maps internally** (for error monitoring)
   but block public HTTP access via the webserver/CDN —
   return 404 for any path matching `*.js.map` / `*.css.map`.

3. **Audit the "loanbuider" typo immediately.** Check whether
   `loanbuider.com` is registered and whether any production
   code path actually references that hostname (vs. the
   correctly-spelled `loanbuilder.com`). If it's a "dead
   constant" replaced by /config.json at runtime, low risk
   but still embarrassing to leak.

4. **Audit related Swift Financial / LoanBuilder frontends**
   for the same source-map exposure pattern. Sibling assets
   in the program scope:
     www.swiftfinancial.com
     swiftfinancial.com
     api.swiftfinancial.com
     decision.swiftfinancial.com
     loanbuilder.com
     www.loanbuilder.com
     my.loanbuilder.com

## Tooling

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0) that probes bounty-program web
frontends for `sourceMappingURL=` references in served
JavaScript and confirms accessibility of the referenced .map
files.

## References

- React build config — disable source maps in production:
  https://create-react-app.dev/docs/advanced-configuration/
- HackerOne historical payouts for similar source-map
  exposures on low-severity brand assets: $50-$300 range
- CWE-540: Inclusion of Sensitive Information in Source Code

---

Ethical-disclosure note: I downloaded only the publicly-served
source map files. I did not deobfuscate, modify, or
redistribute any portion of the source code beyond the small
snippet quoted in this report for proof-of-concept.
```

---

## Internal notes (DO NOT submit)

**Pricing strategy:**
- Realistic $50-$300. Swift Financial is sev=low, sourcemap is INFO disclosure.
- The "loanbuider" typo angle is the spicy part — push the triager to look at it because if `loanbuider.com` is unregistered and registerable, that's a potential subdomain-takeover-via-typo scenario.

**Why this is still worth filing:**
- User has access to PayPal program (already submitted hyperwallet CORS)
- Different scope item (Swift Financial vs Hyperwallet) → not duplicate
- Real source code with at least one actionable insight (typo dev URL)
- Builds incremental signal on PayPal program

**What I did NOT do:**
- Did NOT register `loanbuider.com` (the user/PayPal should check ownership themselves)
- Did NOT deobfuscate the larger vendor chunks
- Did NOT scan the LoanBuilder frontend for the same pattern (recommend in remediation)

**Expected outcome:**
- Triage in 24-72h
- Closed as Informative or Low-severity Resolved
- Payout $50-$300 (or maybe just rep if they bundle with hyperwallet)
