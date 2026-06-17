# Check — Open redirect (your site bounces visitors to wherever a link tells it to)

**What you're looking for:** Anywhere your app sends a visitor to a destination URL that came from the *request* — a `?next=`, `?url=`, `?returnTo=`, `?redirect=` query parameter, a form field, a posted body — without checking that the destination is one of *your* pages. If an attacker can put their own URL in that parameter, they can craft a link that *starts* on your trusted domain and silently lands the visitor on a site they control.

The short version: people trust `https://yourapp.com/...`. An open redirect lets an attacker borrow that trust. The link looks like yours, the visitor clicks because it's yours, and your own server hands them off to the attacker.

This is rated **medium** on its own — it doesn't directly leak data. It's dangerous because of what it *enables*:

- **Phishing that survives a careful look.** `https://yourapp.com/login?next=https://yourapp-secure.com/` shows *your* domain in the email. The victim hovers the link, sees your real domain, clicks — and ends up on the fake login page. Your brand did the convincing.
- **OAuth / token theft.** If the redirect happens *after* login and carries a token, code, or session in the URL or the `Referer`, bouncing to an attacker host hands them that token. This is the classic OAuth `redirect_uri` / `returnTo` abuse.
- **Referer leak.** The destination page sees your URL (which may contain a reset token, an invite code, or a session value) in its `Referer` header.

## How to scan

You're hunting for two things in the same code path: (1) a destination that comes from the request, and (2) a redirect using it. Find the redirects, then check where the destination came from.

```bash
# JS / TS — Express / Next.js / Node redirects + Location header
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  'res\.redirect|\.redirect\(|NextResponse\.redirect|Location[\"'\'' :]|sendRedirect|setHeader\(\s*[\"'\'']Location' \
  . 2>/dev/null | head -40

# Then narrow to the ones fed by request input (the actual bug)
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  'redirect\([^)]*(req\.(query|params|body)|searchParams|query\.|params\.|next|returnTo|return_to|redirect_uri|redirectUri|callback|continue|url=)' \
  . 2>/dev/null | head -40

# Client-side navigation driven by a URL param (DOM open-redirect)
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  'window\.location\s*=|location\.href\s*=|location\.replace\(|location\.assign\(|router\.(push|replace)\(' \
  . 2>/dev/null | head -40

# Python — Flask / Django redirects
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  'redirect\(|HttpResponseRedirect\(|HttpResponsePermanentRedirect\(|RedirectResponse\(' \
  . 2>/dev/null | head -40

# Go — http.Redirect / Location header
grep -rEn --include='*.go' \
  'http\.Redirect|c\.Redirect|ctx\.Redirect|Header\(\)\.Set\(\s*\"Location|w\.Header\(\)\.Set\(\s*\"Location' \
  . 2>/dev/null | head -40

# Ruby (Rails / Sinatra)
grep -rEn --include='*.rb' --include='*.erb' --exclude-dir={vendor} \
  'redirect_to|redirect\s|response\.headers\[.Location' \
  . 2>/dev/null | head -40

# PHP — header("Location: ...")
grep -rEn --include='*.php' --exclude-dir={vendor} \
  'header\(\s*[\"'\'']Location|->redirect\(|RedirectResponse|wp_redirect|wp_safe_redirect' \
  . 2>/dev/null | head -40

# Mobile / cross-platform — opening a URL that came from a deep link / param
grep -rEn --include='*.swift' --include='*.kt' --include='*.dart' \
  'UIApplication\.shared\.open|openURL|startActivity\(.*ACTION_VIEW|Intent\(Intent\.ACTION_VIEW|launchUrl|launch\(|canLaunchUrl' \
  . 2>/dev/null | head -40
```

### The two questions that decide if it's a finding

For each redirect you found, answer both:

1. **Does the destination trace back to the request?** A query string (`?next=`, `?url=`, `?returnTo=`, `?continue=`, `?redirect_uri=`), a form field, a posted body, a deep-link parameter on mobile. If the value the redirect uses is attacker-influenced, the answer is yes.
2. **Is there a guard before the redirect?** A check that the destination is one of *your* allowed paths/hosts, or that it's a **relative path** with no scheme and no host. If you see *nothing* between "read the destination" and "redirect to it," that's the bug.

## The dangerous patterns

**Pattern 1: redirect straight to a query param (the classic)**

```ts
// Express
app.get("/go", (req, res) => {
  res.redirect(req.query.url);          // ← whatever they put in ?url=
});

// Next.js route handler
export function GET(req: Request) {
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  return NextResponse.redirect(next);   // ← attacker controls ?next=
}
```

Attacker shares `https://yourapp.com/go?url=https://evil.com`. The visitor sees your domain, clicks, and your server 302s them to `evil.com`. MEDIUM.

**Pattern 2: the login / OAuth `returnTo` bounce (the high-impact one)**

```python
# Flask — "send the user back where they came from after login"
@app.route("/login", methods=["POST"])
def login():
    do_login()
    return redirect(request.args.get("next"))   # ← unchecked ?next=
```

```ts
// after OAuth callback, bounce to the saved returnTo
const returnTo = req.query.returnTo as string;
res.redirect(returnTo);                          // ← attacker-chosen
```

This is worse than Pattern 1 because the redirect fires **after** authentication. If anything sensitive rides along — an OAuth `code`, a token in the URL, a freshly-set session reflected in the `Referer` — the attacker's destination receives it. This is the textbook OAuth open-redirect / token-leak. MEDIUM, edging to HIGH when a token is in play.

**Pattern 3: Django redirect from request data**

```python
from django.http import HttpResponseRedirect

def go(request):
    return HttpResponseRedirect(request.GET["url"])   # ← unchecked
```

Django ships `url_has_allowed_host_and_scheme()` precisely for this — its absence is the tell. MEDIUM.

**Pattern 4: client-side (DOM) open redirect**

```js
// reads ?redirect= from the URL and navigates there in the browser
const target = new URLSearchParams(location.search).get("redirect");
window.location = target;                 // ← also fires on javascript: URLs
```

Two bugs here: it's an open redirect, *and* `window.location = "javascript:..."` (or React Router `navigate(userValue)` with a `javascript:` string) can execute script — a stored/reflected XSS via the redirect param. MEDIUM, HIGH if `javascript:` isn't blocked.

**Pattern 5: PHP `header("Location: ...")`**

```php
// continue.php?to=...
header("Location: " . $_GET["to"]);       // ← unchecked; also enables header injection
exit;
```

Note `wp_redirect()` does **not** validate the host — only `wp_safe_redirect()` does. MEDIUM.

**Pattern 6: the "I added a check" that doesn't actually work**

```ts
// looks safe, isn't
if (next.startsWith("https://yourapp.com")) res.redirect(next);
//   attacker uses: https://yourapp.com.evil.com/   → passes startsWith
//   or:            https://yourapp.com@evil.com/    → host is evil.com, prefix matches

if (next.startsWith("/")) res.redirect(next);
//   attacker uses: //evil.com   → browser reads this as protocol-relative → goes to evil.com
//   or:            /\evil.com    → some parsers treat \ as /
```

A `startsWith("https://yourapp.com")` prefix check is bypassable, and `startsWith("/")` alone is bypassable with `//evil.com` (protocol-relative) or `/\evil.com`. These are *real* bypasses, not theory. MEDIUM (it's a broken guard, treat it as unguarded).

## The fix: only ever redirect to a place you chose

There are two correct shapes. Use whichever fits.

**Shape A — relative-path only (best for `next` / `returnTo` after login).** The destination is meant to be a page *on your site*, so refuse anything that has a scheme or a host. The trick is to reject the protocol-relative `//host` and backslash forms too:

```ts
function safeNext(raw: string | null): string {
  if (!raw) return "/";
  // must start with a single slash, and the 2nd char must NOT be another slash or a backslash
  if (!/^\/[^/\\]/.test(raw)) return "/";   // rejects "//evil.com", "/\evil.com", "https://…", "javascript:…"
  return raw;
}

const next = safeNext(new URL(req.url).searchParams.get("next"));
return NextResponse.redirect(new URL(next, req.url));  // resolved against YOUR origin
```

The regex `^\/[^/\\]` means: first char is `/`, second char is anything except `/` or `\`. So `/dashboard` passes; `//evil.com`, `/\evil.com`, `https://evil.com`, and `javascript:alert(1)` all fail and fall back to `/`.

**Shape B — host allowlist (when you genuinely need cross-host redirects).** Parse the URL and compare the **host** (not a string prefix) against a fixed set:

```ts
const ALLOWED_HOSTS = new Set(["yourapp.com", "app.yourapp.com"]);

function safeRedirect(raw: string): string {
  try {
    const u = new URL(raw, "https://yourapp.com");   // base makes relative URLs resolve to you
    if (u.protocol !== "https:") return "/";          // blocks javascript:, data:, http:
    if (!ALLOWED_HOSTS.has(u.hostname)) return "/";   // host compare, not startsWith
    return u.toString();
  } catch {
    return "/";
  }
}
```

Per-stack equivalents:

```python
# Django — the built-in, use it
from django.utils.http import url_has_allowed_host_and_scheme

def go(request):
    nxt = request.GET.get("next", "/")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=True):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect("/")

# Flask — relative-only check (urlparse splits out any scheme/host)
from urllib.parse import urlparse
def is_safe(target):
    p = urlparse(target)
    return not p.scheme and not p.netloc and target.startswith("/") and not target.startswith("//")
```

```go
// Go — relative-only: reject anything with a scheme or host
func safeNext(raw string) string {
    u, err := url.Parse(raw)
    if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
        return "/"
    }
    return raw
}
```

```php
// PHP — relative-only, or use wp_safe_redirect() on WordPress
$to = $_GET['to'] ?? '/';
$p = parse_url($to);
if (!empty($p['scheme']) || !empty($p['host']) || str_starts_with($to, '//')) {
    $to = '/';
}
header("Location: " . $to);   // (still strip CR/LF if you ever build the value yourself)
```

```swift
// Swift — only open https URLs to hosts you allow
let allowed: Set<String> = ["yourapp.com"]
if let u = URL(string: raw), u.scheme == "https", let h = u.host, allowed.contains(h) {
    UIApplication.shared.open(u)
}   // refuses custom schemes and arbitrary hosts from a deep link
```

> **The slash trap, stated once more because everyone hits it:** `startsWith("/")` is *not* enough. `//evil.com` starts with `/` and browsers treat it as `https://evil.com`. Require a single leading slash whose next character is not `/` or `\`.

## Report a finding as

**Title:** "Your login link can send users to a phishing site"

(adapt to the feature — "Your `?next=` redirect lets attackers borrow your domain for phishing," "Your OAuth `returnTo` can leak the login token," "Your `/go` link will forward visitors to any site")

**Detail:**
> `app/login/route.ts:12` reads a destination from the request (`?next=`) and redirects the visitor there after login, with no check that the destination is one of your own pages. Whatever URL someone puts in that parameter, your server sends the visitor to it.
>
> **What can go wrong:** People trust links that start with `https://yourapp.com`. An attacker crafts `https://yourapp.com/login?next=https://yourapp-login.com/` and emails it to your users. They hover the link, see *your* real domain, and click — because it's you. Your server logs them in (or shows your login page), then bounces them to the attacker's lookalike site, which asks them to "log in again." Your brand did the convincing. If the redirect happens after OAuth and a token or code is in the URL, the attacker's site receives it directly in the `Referer` and can take over the account.
>
> **How to fix tonight (10 minutes):**
> 1. If the destination is meant to be a page on *your* site (the usual case for `next`/`returnTo`), only accept a relative path — reject anything with a scheme or a host, including the protocol-relative `//` form:
>    ```ts
>    // accept only a single leading slash whose next char isn't / or \
>    const raw = new URL(req.url).searchParams.get("next") ?? "/";
>    const next = /^\/[^/\\]/.test(raw) ? raw : "/";
>    return NextResponse.redirect(new URL(next, req.url));   // resolved against your origin
>    ```
> 2. If you genuinely need to redirect across hosts, **parse the URL and compare the host** against a fixed allowlist — never `startsWith()` on the raw string (`https://yourapp.com.evil.com` and `https://yourapp.com@evil.com` both defeat a prefix check).
> 3. Block non-`http(s)` schemes (`javascript:`, `data:`) — on the client side, `window.location = userValue` with a `javascript:` URL is also an XSS.
> 4. On Django use `url_has_allowed_host_and_scheme()`; on WordPress use `wp_safe_redirect()` not `wp_redirect()`; both validate for you.
> 5. Verify after deploy: `curl -sI "https://yourapp.com/login?next=https://evil.com"` should show a `Location:` pointing at *your* domain (or `/`), not `evil.com`.

Repeat the report block for each user-controlled redirect you found.

## Don't false-positive on

- **Hardcoded or relative destinations.** `res.redirect("/dashboard")`, `redirect_to root_path`, `header("Location: /thanks")` — the destination is fixed by *you*, not the request. Not a finding.
- **Destination comes from your own server state, not the request.** Redirecting to `user.homepage` loaded from *your* database, or `process.env.APP_URL`, is your choice of destination — only flag it if the value itself is something users can set to an arbitrary external URL (e.g. a self-chosen profile link the app then redirects to).
- **A real guard is present.** A relative-only check (`^/[^/\\]`, or Flask's `not scheme and not netloc`), a host allowlist that compares `new URL(x).hostname` against a fixed set, Django's `url_has_allowed_host_and_scheme()`, or `wp_safe_redirect()`. If the guard parses the URL (not a `startsWith`/`includes` on the raw string), it's correct — note as INFO at most.
- **Forced single-slash / same-origin resolution.** `new URL(next, req.url)` *after* the value has been confirmed relative resolves against your own origin, so even a weird value can't escape your host. (But `new URL(next, base)` with an *absolute* `next` still goes wherever `next` points — the relative check has to come first.)
- **Client-side `router.push(staticString)` / `<Link href="/x">`.** Framework navigation to a literal in-app path is not user-controlled. Only the variants that pass a *request-derived* value are in scope.
- **The OAuth `redirect_uri` registered with your provider.** The value you *send to* Google/GitHub/Auth0 is validated by *them* against the allowlist you configured in their dashboard — that's their job, not an open redirect in your code. (Do still confirm you didn't add a wildcard or `localhost` entry to that provider allowlist in production.)
- **Pure server-side fetches of a user URL.** If your *backend* fetches the URL rather than telling the *browser* to navigate to it, that's SSRF (`ssrf.md`), not open redirect — different check, different fix.
