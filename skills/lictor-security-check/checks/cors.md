# Check 6 — CORS misconfiguration

**What you're looking for:** API endpoints that send `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. This is invalid per the spec (browsers reject it), but it's a strong signal the developer relaxed CORS without understanding it — and other CORS settings are probably broken too. Or worse, they're echoing the request's Origin back, which is a real cross-origin attack.

## How to scan

CORS config typically lives in middleware, API route handlers, or a CORS library config:

```bash
# Generic CORS configuration search
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  'Access-Control-Allow-Origin|cors\s*\(|cors\s*:|"cors"' \
  . 2>/dev/null | head -20

# Look for the `*` star-origin pattern
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E "Access-Control-Allow-Origin.*\*|origin\s*:\s*['\"]\*['\"]" \
  . 2>/dev/null

# Look for "echo back the request origin" — even more dangerous
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E "Access-Control-Allow-Origin.*req\.|origin\s*:\s*req\.headers" \
  . 2>/dev/null
```

## The dangerous patterns

**Pattern 1: `*` + credentials (invalid but signals other bugs)**

```ts
// next.config.js or middleware
return new Response(data, {
  headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",  // ← invalid combination
  },
});
```

Browsers reject this combination per the CORS spec. But its presence means:
- The dev tried "make CORS just work" without understanding the model
- Other API responses likely have other CORS bugs
- Worth a HIGH severity flag because it indicates a confused threat model

**Pattern 2: echoing request Origin (REAL VULNERABILITY)**

```ts
// THIS IS A SECURITY BUG, not just a misconfig
const origin = req.headers.get("origin");
return new Response(data, {
  headers: {
    "Access-Control-Allow-Origin": origin,  // ← echoes whatever the attacker sends
    "Access-Control-Allow-Credentials": "true",
  },
});
```

This is exploitable: an attacker hosts a malicious page that requests your authenticated API. The browser sends the user's session cookie because `credentials: true` permits it, and the response is readable because the server echoes the attacker's origin. Cross-Site Request Forgery via misconfigured CORS.

CRITICAL severity.

**Pattern 3: wildcard subdomain matching done wrong**

```ts
if (origin.endsWith(".example.com")) {  // ← attacker-controlled
  return new Response(data, { headers: { "Access-Control-Allow-Origin": origin }});
}
```

An attacker can register `evil-example.com` (note: not a subdomain of example.com, but `endsWith` matches it). HIGH severity. Fix: use `URL` parsing and check `host === "example.com" || host.endsWith(".example.com")`.

## Safe patterns

Specific origins only, ideally from an allowlist:

```ts
const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"];
const origin = req.headers.get("origin") ?? "";
const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

return new Response(data, {
  headers: {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",  // ← important for caching correctness
  },
});
```

## Report a finding as

**Title:** "CORS echoes attacker-controlled Origin with credentials"

(use this title when pattern 2 is present; adapt for patterns 1 and 3)

**Detail:**
> `src/app/api/me/route.ts:14` reads the incoming request's `Origin` header and returns it unchecked in the `Access-Control-Allow-Origin` response header, while also setting `Access-Control-Allow-Credentials: true`. This is exploitable:
>
> 1. An attacker hosts a page at `https://evil.com`.
> 2. The page sends a `fetch("https://yourapp.com/api/me", { credentials: "include" })` request.
> 3. The user's browser sends their session cookie (because the user is logged into yourapp.com).
> 4. Your server reads `Origin: https://evil.com`, echoes it back as `Access-Control-Allow-Origin: https://evil.com`.
> 5. The browser allows the attacker's JavaScript to read the response — which contains the logged-in user's profile, settings, etc.
>
> **What to do tonight:**
> 1. Replace the dynamic Origin echo with an explicit allowlist:
>    ```ts
>    const ALLOWED = new Set(["https://app.example.com"]);
>    const requested = req.headers.get("origin") ?? "";
>    const allowed = ALLOWED.has(requested) ? requested : null;
>    if (!allowed) return new Response("CORS denied", { status: 403 });
>    return new Response(data, {
>      headers: {
>        "Access-Control-Allow-Origin": allowed,
>        "Access-Control-Allow-Credentials": "true",
>        "Vary": "Origin",
>      },
>    });
>    ```
> 2. Verify: from a malicious-test browser console (use a different domain like jsfiddle.net), run `fetch("https://yourapp.com/api/me", {credentials:"include"}).then(r=>r.text()).then(console.log)`. Should fail.
> 3. Check every other API route for the same pattern.

## Don't false-positive on

- Truly-public endpoints with `Access-Control-Allow-Origin: *` and NO credentials — that's the correct CORS for a public API. Note as INFO, not a finding.
- Static asset CORS headers in `next.config.js` for `_next/static/*` — that's framework-internal, not a security concern.
- Frameworks that automatically add CORS for development (Vite proxy, Next.js dev server) — only relevant if those settings ship to production.
