# Check — Missing security headers & leaky cookies

**What you're looking for:** Your app's responses don't tell the browser to protect itself, and your login cookie is readable by JavaScript or sent over plain HTTP. The headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy — are small, boring settings that turn on the browser's built-in defenses. Most AI-generated apps ship with none of them, because the AI built the feature, not the seatbelts. The cookie flags (`HttpOnly`, `Secure`, `SameSite`) decide whether a stolen-script or a sniffed-network can walk off with your user's session.

This one is rarely the *worst* bug in an app, but it's almost always *present*, and it's the cheapest thing on this whole list to fix.

## How to scan

Security headers can be set in three places: framework config, response middleware, or per-route handlers. Cookies are set wherever you log a user in. Check all of them. Start by checking whether headers exist *at all* — for most vibe-coded apps, the honest finding is "none of these are set anywhere."

### JavaScript / TypeScript (Next.js, Express, Hono, SvelteKit, Remix, Astro, Fastify, NestJS)

```bash
# Are ANY security headers set anywhere? (often: zero hits)
grep -rEin --include='*.ts' --include='*.js' --include='*.mjs' \
  --exclude-dir={node_modules,.next,dist,build,.svelte-kit} \
  'content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy' \
  . 2>/dev/null | head -30

# Next.js: headers live in next.config.js `headers()` or middleware.ts
grep -rEn 'headers\s*\(|key:\s*[\x27"]X-|key:\s*[\x27"]Content-Security' \
  next.config.* middleware.* 2>/dev/null

# Is the helmet middleware installed (Express/Fastify/Nest)?
grep -rEn 'require\([\x27"]helmet|from [\x27"]helmet|@fastify/helmet|helmet\(\)' \
  --include='*.ts' --include='*.js' --exclude-dir=node_modules . 2>/dev/null
grep -En '"helmet"|"@fastify/helmet"' package.json 2>/dev/null

# How are cookies being set? (look at the options object on each one)
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  'res\.cookie\(|setCookie|cookies\(\)\.set|Set-Cookie|serialize\(' \
  . 2>/dev/null | head -30
```

### Python (Django, Flask, FastAPI)

```bash
# Django: these settings control headers + cookie flags
grep -rEn 'SECURE_HSTS_SECONDS|SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SAMESITE|CSRF_COOKIE_SECURE|SECURE_CONTENT_TYPE_NOSNIFF|X_FRAME_OPTIONS|CSP_' \
  settings.py */settings.py settings/ 2>/dev/null

# Flask / FastAPI: headers set on the response, cookies via set_cookie
grep -rEn --include='*.py' \
  'set_cookie|response\.headers|Strict-Transport|X-Frame-Options|Content-Security|after_request|Talisman' \
  . 2>/dev/null | head -30
```

### Go

```bash
grep -rEn --include='*.go' \
  'w\.Header\(\)\.Set|http\.SetCookie|http\.Cookie\{|Strict-Transport|X-Frame-Options|Content-Security|secure\.New|HttpOnly|SameSite' \
  . 2>/dev/null | head -30
```

### Ruby (Rails, Sinatra)

```bash
# Rails sets these in config/initializers + config/application.rb
grep -rEn 'force_ssl|default_headers|Content-Security-Policy|content_security_policy|X-Frame-Options|secure_headers|cookies\.signed|httponly|same_site' \
  config/ app/ 2>/dev/null
grep -En '"secure_headers"|gem .secure_headers' Gemfile 2>/dev/null
```

### PHP (Laravel, plain PHP, WordPress)

```bash
grep -rEn --include='*.php' \
  'header\(|setcookie\(|->cookie\(|Strict-Transport|X-Frame-Options|Content-Security-Policy|httponly|samesite' \
  . 2>/dev/null | head -30
# Laravel: also check config/session.php for secure / http_only / same_site
grep -En "'secure'|'http_only'|'same_site'" config/session.php 2>/dev/null
```

### Mobile (the part everyone forgets)

Mobile apps don't render in a browser, so CSP/X-Frame-Options don't apply to the app's own screens. But two things absolutely do: **(a)** any in-app WebView (these run real HTML and *do* need CSP/no-mixed-content), and **(b)** insecure transport (the mobile equivalent of "no HSTS" is allowing plain `http://` traffic).

```bash
# iOS / Swift — ATS exceptions = the app is allowed to talk over plain HTTP
grep -rEn 'NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking' \
  --include='*.plist' --include='Info.plist' . 2>/dev/null
# WKWebView loading remote content
grep -rEn --include='*.swift' 'WKWebView|loadHTMLString|allowsArbitraryLoads' . 2>/dev/null

# Android / Kotlin — cleartext traffic allowed + WebView with JS bridge
grep -rEn 'usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted="true"' \
  --include='AndroidManifest.xml' --include='*.xml' . 2>/dev/null
grep -rEn --include='*.kt' --include='*.java' \
  'setJavaScriptEnabled\(true\)|addJavascriptInterface|loadDataWithBaseURL' . 2>/dev/null

# Flutter — usesCleartextTraffic + insecure WebView config
grep -rEn 'usesCleartextTraffic|allowsArbitraryLoads' --include='*.xml' --include='*.plist' . 2>/dev/null
grep -rEn --include='*.dart' 'WebView\(|javascriptMode|onWebResourceError|badCertificateCallback' . 2>/dev/null

# React Native — cleartext + WebView with injectedJavaScript
grep -rEn 'usesCleartextTraffic|NSAllowsArbitraryLoads' android/ ios/ 2>/dev/null
grep -rEn --include='*.js' --include='*.tsx' 'WebView|injectedJavaScript|originWhitelist' . 2>/dev/null
```

## What each header does (the one-line version)

So you can explain it to the user without a spec dump:

- **Content-Security-Policy (CSP)** — "only run scripts from places I trust." The single strongest defense against someone injecting a `<script>` into your page.
- **Strict-Transport-Security (HSTS)** — "never talk to me over plain HTTP again." Stops a coffee-shop-wifi attacker from downgrading the connection and reading everything.
- **X-Frame-Options** (or CSP `frame-ancestors`) — "don't let other sites put me in a hidden iframe." Blocks clickjacking, where an attacker tricks your user into clicking your real buttons through an invisible overlay.
- **X-Content-Type-Options: nosniff** — "don't guess file types." Stops the browser from treating an uploaded image as if it were JavaScript.
- **Referrer-Policy** — "don't leak the full URL (with its tokens) to other sites." Vibe-coded apps love to put session tokens in URLs; this keeps them from spilling.

## The dangerous patterns

**Pattern 1: no headers anywhere (the common case)**

You grepped and got zero hits. The app sends a response, the browser gets no instructions, every defense above is off. This isn't a single exploit — it's a missing seatbelt across the whole site. **MEDIUM** on its own; bump to **HIGH** if the app also accepts user-generated content (comments, profiles, markdown, file uploads) because that's exactly where CSP earns its keep.

**Pattern 2: the session cookie is readable by JavaScript**

```ts
// Express
res.cookie("session", token);                       // ← no flags at all
res.cookie("session", token, { secure: false });    // ← sent over plain HTTP
```
```python
# Flask
resp.set_cookie("session", token)                   # ← httponly defaults to False here
```

If a cookie holding a session/auth token lacks `HttpOnly`, then *any* injected script can read it with `document.cookie` and ship the user's logged-in session to an attacker. Missing `Secure` means it rides over plain HTTP and a network sniffer grabs it. Missing `SameSite` opens the door to another site triggering authenticated actions. For an auth/session cookie this is **HIGH**.

**Pattern 3: a CSP that does nothing**

```
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
```
It looks like a policy, so it gets a green check in a naive scan, but `*` + `unsafe-inline` + `unsafe-eval` permits exactly what CSP is supposed to block. **LOW/MEDIUM** — flag it as "this header is decorative."

**Pattern 4 (mobile): the app is allowed to speak plain HTTP**

```xml
<!-- Info.plist (iOS) — turns OFF App Transport Security globally -->
<key>NSAppTransportSecurity</key>
<dict><key>NSAllowsArbitraryLoads</key><true/></dict>
```
```xml
<!-- AndroidManifest.xml -->
<application android:usesCleartextTraffic="true" ...>
```
Same risk as a missing HSTS on the web: a user on hostile wifi has their traffic read or tampered with. **HIGH** if the app handles logins, payments, or personal data. (Often the AI added the exception to make one stubborn API call work, then left it global.)

## Safe patterns

**Next.js** — set it once in `next.config.js`, covers every route:

```js
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'" },
];
module.exports = {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};
```

**Express / Fastify / Nest** — one line does most of it:

```ts
import helmet from "helmet";
app.use(helmet());           // HSTS, nosniff, frame-options, a baseline CSP, and more
```

**Cookies** (any JS framework):

```ts
res.cookie("session", token, {
  httpOnly: true,            // JS can't read it
  secure: true,              // HTTPS only
  sameSite: "lax",           // or "strict" for pure first-party apps
  maxAge: 60 * 60 * 24 * 7 * 1000,
});
```

**Django** — flip these in `settings.py`:

```python
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
```

**Mobile** — remove the blanket exception and allow plain HTTP only for the one domain that truly needs it (or, better, fix that endpoint to use HTTPS):

```xml
<!-- Android: res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false"/>
</network-security-config>
```
For iOS, delete `NSAllowsArbitraryLoads` and add a narrow `NSExceptionDomains` entry only if unavoidable.

## Report a finding as

**Title:** "Your site isn't telling browsers to defend themselves (and your login cookie is exposed)"

(adapt — lead with the cookie problem if that's what you found, it's the higher-severity half)

**Detail:**
> 🟠 **HIGH** — Your login cookie can be stolen, and the browser's built-in protections are turned off.
>
> Two things, both small to fix:
>
> **1. The session cookie.** In `src/auth/login.ts:24` you set the login cookie with `res.cookie("session", token)` — no flags. That means any script that ends up on your page can read it with `document.cookie` and send your user's logged-in session to someone else. It also rides over plain HTTP, so anyone on the same wifi can grab it.
>
> **2. The headers.** I grepped your whole project for security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy) and found none. These are the instructions that switch on the browser's own defenses — without them, if a bad `<script>` ever gets onto your page, nothing stops it from running, and another site can hide your app inside an invisible frame and trick your users into clicking things.
>
> **What can go wrong:** You launch, someone posts a comment containing `<script>` (or your AI-built markdown renderer doesn't escape it). With no CSP, that script runs. With no `HttpOnly` on your cookie, it reads the logged-in user's session and emails it to the attacker. The attacker is now logged in as your user. None of this requires a sophisticated attacker — it's a copy-paste from a blog post.
>
> **How to fix tonight (10 minutes):**
> 1. Add the cookie flags wherever you set the session:
>    ```ts
>    res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
>    ```
> 2. Add the headers once, app-wide. Express/Nest: `app.use(helmet())`. Next.js: paste the `headers()` block into `next.config.js` (snippet below). Django: flip the `SECURE_*` / `SESSION_COOKIE_*` settings.
> 3. After deploy, verify both at once:
>    ```bash
>    curl -sI https://yourapp.com | grep -iE 'strict-transport|content-security|x-frame|x-content-type|set-cookie'
>    ```
>    You should see your headers, and your `set-cookie` line should include `HttpOnly; Secure; SameSite`.
> 4. (Optional, free) paste your URL into securityheaders.com after deploy for a letter-grade.
>
> [include the relevant safe-pattern snippet for their stack here]

Write one finding per real problem — don't merge "missing headers" and "leaky cookie" into one if their severities differ. The cookie issue is usually HIGH; bare missing headers are usually MEDIUM.

## Don't false-positive on

- **A pure static site / marketing page with no login, no cookies, no user input.** Missing CSP on a brochure site is **INFO at most**, often not worth mentioning. No session to steal, no script-injection surface. Don't ring the alarm.
- **Non-auth cookies missing `HttpOnly`.** A theme preference, a "cookie banner dismissed" flag, an A/B-test bucket — these are *meant* to be readable by JS and carry nothing sensitive. Only flag `HttpOnly` on cookies that hold a session/auth/CSRF token. Read what the cookie actually contains before flagging.
- **The host/CDN already sets the headers.** Vercel, Netlify, Cloudflare, Cloud Run, and many reverse proxies can inject HSTS and friends at the edge. Check for a `vercel.json` `headers` block, a `_headers` file (Netlify/Cloudflare Pages), `netlify.toml`, or an nginx/Caddy config before concluding "no headers anywhere." If the edge sets them, the app code doesn't need to.
- **HSTS on `localhost` / dev.** It's normal and correct *not* to force HTTPS in local development. Only the production config matters. Don't flag a `secure: false` that's clearly gated behind `if (process.env.NODE_ENV !== 'production')`.
- **`SameSite=None; Secure` on a cookie that genuinely needs cross-site use** (embedded widgets, an SSO flow, a payment iframe). `None` *with* `Secure` is a deliberate, valid choice for those — not a bug. It's only a problem when `None` appears without `Secure`.
- **Mobile cleartext scoped to a single dev/staging domain.** An Android `network-security-config` or iOS `NSExceptionDomains` entry that permits HTTP for `localhost`, `10.0.2.2`, or an internal staging host is fine. The finding is the *global* `NSAllowsArbitraryLoads` / `usesCleartextTraffic="true"`, not a narrow, named exception.
- **A backend API with no browser at all** (a pure server-to-server JSON API, a cron worker). CSP and X-Frame-Options are browser instructions; they do nothing for a service no browser ever loads. HSTS and cookie flags can still matter if it issues cookies — but skip the browser-rendering headers.
- **Report-only CSP that's intentional.** `Content-Security-Policy-Report-Only` is how teams roll out CSP safely before enforcing it. That's a sign of someone doing it *right*, not a gap. Note it, don't flag it.
