# Check — Unsafe consumption of third-party APIs (over-trusting the data you pull in)

**What you're looking for:** Your app calls *someone else's* API — Stripe, a shipping
quote, a weather feed, a CRM, an AI model, a partner's webhook-reply, a price oracle —
and then trusts whatever comes back a little too much. There are three flavors of this
bug, and they all come from the same place: "it's a real company's API, so the response
must be fine."

1. **You turned off TLS verification on the outbound call.** Now anyone on the network
   path between you and the upstream (a coffee-shop router, a compromised ISP hop, a
   cloud-provider rebind) can pretend to be that API and feed you whatever they like.
2. **You follow the upstream's redirects blindly.** A response that's supposed to be a
   200 with JSON says "302, go fetch this other URL" — and your server obediently goes,
   sometimes into your own private network.
3. **You take the response body and feed it straight into something dangerous** — a DB
   write, an `eval`, a template render, a shell command, a file path, or *another* fetch
   — without parsing or validating it first.

This is **not** the same as two checks you may have already run:

- **Dependencies** (`dependencies.md`) is about *code you installed* (npm/pip packages).
  This is about *data you fetch at runtime*.
- **SSRF** (`ssrf.md`) is about the *user controlling the URL your server hits*. This is
  about *the upstream you already chose to trust* sending you something hostile —
  either because the channel got hijacked (TLS off) or because the upstream itself is
  compromised, buggy, or being impersonated.

The mental model: **the network is not your friend, and "a trusted vendor" is not the
same as "a trusted byte stream."** OWASP calls this API10:2023 — Unsafe Consumption of
APIs. It is the newest entry in the API Top 10 precisely because everyone now wires ten
SaaS APIs together and assumes the wires are clean.

**Severity:** 🟠 HIGH (🔴 escalate to CRITICAL when TLS verification is off on a call
carrying credentials/payment data, or when an upstream body lands in `eval`/shell/DB
with zero validation).

---

## How to scan

Three passes — one per flavor. Run all of them; a single integration often trips more
than one.

### Pass A — TLS verification turned off on outbound calls

This is the highest-signal, lowest-false-positive grep in the whole module. There is
almost never a good reason for it in shipping code.

```bash
# JS / TS — rejectUnauthorized, the env kill-switch, agents with verify off
grep -rEn --include='*.ts' --include='*.js' --include='*.mjs' --include='*.cjs' \
  --exclude-dir={node_modules,.next,dist,build} \
  'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|checkServerIdentity\s*:\s*\(\s*\)\s*=>|secureProtocol|insecureHTTPParser\s*:\s*true' \
  . 2>/dev/null

# JS / TS — also check .env files and CI config for the env kill-switch
grep -rEn --include='*.env*' --include='*.yml' --include='*.yaml' --include='Dockerfile*' \
  --exclude-dir={node_modules} \
  'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|NODE_TLS_REJECT_UNAUTHORIZED.*0' \
  . 2>/dev/null

# Python — requests/httpx/aiohttp verify off, urllib unverified context
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  'verify\s*=\s*False|_create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False|ssl\._create_default_https_context\s*=\s*ssl\._create_unverified_context' \
  . 2>/dev/null

# Go — InsecureSkipVerify
grep -rEn --include='*.go' \
  'InsecureSkipVerify\s*:\s*true' \
  . 2>/dev/null

# Ruby — Net::HTTP / OpenURI / Faraday verify off
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  'OpenSSL::SSL::VERIFY_NONE|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|ssl_verify\s*:\s*false|verify\s*:\s*false|ssl_verify_none' \
  . 2>/dev/null

# PHP — curl + Guzzle verify off
grep -rEn --include='*.php' --exclude-dir={vendor} \
  'CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|CURLOPT_SSL_VERIFYHOST\s*,\s*0|'\''verify'\''\s*=>\s*false|"verify"\s*=>\s*false' \
  . 2>/dev/null

# Shell scripts and Makefiles — curl -k / --insecure, wget --no-check-certificate
grep -rEn --include='*.sh' --include='Makefile' --include='*.mk' \
  'curl[^|]*(-k|--insecure)|wget[^|]*--no-check-certificate' \
  . 2>/dev/null

# Mobile — Swift, Kotlin/Java (Android), Flutter/Dart, React Native
# iOS: ATS exceptions in Info.plist + trust-all URLSession delegates
grep -rEn --include='Info.plist' \
  'NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking' \
  . 2>/dev/null
grep -rEn --include='*.swift' \
  'URLSession.*didReceive challenge|\.useCredential.*serverTrust|URLCredential\(trust:' \
  . 2>/dev/null
# Android: trust-all TrustManager / HostnameVerifier, cleartext config
grep -rEn --include='*.kt' --include='*.java' \
  'TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|HostnameVerifier\s*\{\s*.*true|sslSocketFactory' \
  . 2>/dev/null
grep -rEn --include='*.xml' \
  'cleartextTrafficPermitted\s*=\s*"true"|usesCleartextTraffic\s*=\s*"true"' \
  . 2>/dev/null
# Flutter/Dart: badCertificateCallback that returns true
grep -rEn --include='*.dart' \
  'badCertificateCallback|onBadCertificate|allowBadCertificates' \
  . 2>/dev/null
```

### Pass B — unbounded / unchecked redirects on outbound calls

You called a vendor URL; the vendor (or whoever hijacked the response) says "go
somewhere else." Following that blindly turns a benign integration into an SSRF pivot
or an exfiltration of the `Authorization` header you attached.

```bash
# JS / TS — explicitly cranked-up or unlimited redirects, or auto-redirect with auth
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  'maxRedirects\s*:\s*([1-9][0-9]|Infinity)|followRedirect\s*:\s*true|follow\s*:\s*[1-9][0-9]|redirect\s*:\s*['\''"]follow' \
  . 2>/dev/null

# Python — requests follows redirects by default; flag where it's NOT disabled on
# auth'd calls. Find the calls, then read for allow_redirects=False.
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  'allow_redirects\s*=\s*True|follow_redirects\s*=\s*True' \
  . 2>/dev/null

# Go — a custom client that does NOT set CheckRedirect is worth a read
grep -rEn --include='*.go' \
  'CheckRedirect' \
  . 2>/dev/null    # presence is GOOD; absence near sensitive calls is the smell

# PHP — Guzzle 'allow_redirects' => true with no limit
grep -rEn --include='*.php' --exclude-dir={vendor} \
  "'allow_redirects'\s*=>\s*true|CURLOPT_FOLLOWLOCATION\s*,\s*(1|true)" \
  . 2>/dev/null
```

For Python/Ruby/PHP, redirect-following is often the **default**, so the bug is the
*absence* of a limit on an authenticated call, not a flag you can grep. Read the call
sites you found in Pass A/C and ask: "if this 302'd to `http://169.254.169.254/` with my
bearer token attached, what happens?"

### Pass C — upstream response body flowing into a dangerous sink

Find where you read a third-party response, then trace the variable into a sink. The
tell is a `.json()` / `res.data` / `response.body` / `r.text` that's used **without a
schema parse or field validation** in between.

```bash
# JS / TS — pull the response, then see if it lands in a sink unvalidated
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  'await\s+(res|resp|response|r)\.json\(\)|\.data\b|response\.text\(\)' \
  . 2>/dev/null | head -40
# Sinks to trace the body into: DB writes, eval/Function, template render, shell, fs path
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  '\beval\(|new Function\(|child_process|exec\(|execSync|\$\{[^}]*\b(data|body|json|resp|result)\b|dangerouslySetInnerHTML|\.createObjectURL|\.insertMany\(|\.create\(\s*\{?\s*\.\.\.' \
  . 2>/dev/null | head -40

# Python — response body into exec/eval/format/subprocess/ORM bulk-create
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  '\.json\(\)|resp\.text|response\.content' \
  . 2>/dev/null | head -40
grep -rEn --include='*.py' --exclude-dir={venv,.venv,site-packages,__pycache__} \
  'eval\(|exec\(|subprocess\.|os\.system\(|\.bulk_create\(|render_template_string\(|\.format\(' \
  . 2>/dev/null | head -40
```

This pass is judgment work: a grep can't prove the *same* variable flows from fetch to
sink. Read the handful of call sites and follow the data by eye.

---

## The dangerous patterns

### Pattern 1 — TLS verification disabled (the "it worked on my machine" trap) 🔴/🟠

The single most common cause: a self-signed cert in dev threw an error, the founder
googled it, pasted in the kill-switch, and it shipped.

```ts
// Node — DON'T. This disables cert checking for the ENTIRE process, every outbound call.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// axios — same bug, scoped to one client (still bad on a real upstream)
const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }), // ←
});
const balance = await client.get("https://api.payment-vendor.com/v1/balance");
```

```python
# Python — requests / httpx
r  = requests.get("https://api.partner.com/orders", verify=False)        # ←
rx = httpx.Client(verify=False).get("https://api.partner.com/orders")     # ←
```

```go
// Go
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // ←
client := &http.Client{Transport: tr}
```

```php
// PHP — curl
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // ←
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);     // ←
```

```kotlin
// Android — a TrustManager that approves everything
val trustAll = object : X509TrustManager {
  override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {} // ← approves any cert
  override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
  override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
```

```dart
// Flutter — accepting any cert
httpClient.badCertificateCallback = (cert, host, port) => true; // ←
```

Why it's a real bug, not paranoia: with verification off, an attacker who can sit on the
network path (public Wi-Fi, a malicious egress proxy, BGP/DNS tricks, a poisoned
cloud-internal hop) presents *their own* cert, your client accepts it, and now they
**read and rewrite every byte** between you and the vendor — including the API key you
sent in the `Authorization` header and the payment data that came back. It silently
downgrades HTTPS to "HTTPS-shaped." **CRITICAL when the call carries credentials or money.**

### Pattern 2 — blindly following third-party redirects 🟠

```ts
// You asked the vendor for an image; the "image" is a 302 to your metadata service.
const res = await fetch(vendorImageUrl, {
  redirect: "follow",            // ← default in fetch; fine for static assets, risky with auth
  headers: { Authorization: `Bearer ${SECRET}` },
});
```

Two distinct harms:
- **Header leak:** many HTTP clients re-send your `Authorization` header to the redirect
  target. If the upstream is compromised and 302s to `https://attacker.com`, your secret
  walks out the door.
- **SSRF pivot:** a 302 to `http://169.254.169.254/latest/meta-data/` or
  `http://localhost:5432` aims your *server's* trusted network position at internal
  resources — even though the user never controlled the original URL (so your SSRF check
  may have passed it).

### Pattern 3 — upstream body straight into a dangerous sink 🔴/🟠

```ts
// "It's just the CRM's response, it's structured." Until it isn't.
const profile = await crm.get(`/contacts/${id}`).then(r => r.json());

// → DB write, spreading an attacker-shaped object into your record (mass assignment)
await db.user.update({ where: { id }, data: { ...profile } }); // ← role:"admin" sneaks in

// → template render of an HTML field that the upstream let through
return `<div>${profile.bio}</div>`;                            // ← stored XSS via partner data

// → another fetch, using a URL the upstream handed you
await fetch(profile.avatarUrl);                                // ← SSRF seeded by upstream
```

```python
# A "config" pulled from a feature-flag/remote-config service, eval'd. Never do this.
cfg = requests.get("https://config.vendor.com/app").json()
rule = eval(cfg["pricing_rule"])     # ← upstream now runs code in your process
```

The upstream might be perfectly honest — and still get breached, still have a bug, still
get impersonated (see Pattern 1). The fix is the same regardless of *why* the bytes are
hostile: **don't trust the shape, prove it.**

---

## Safe patterns (what good looks like)

**Keep TLS verification ON — always, in every environment.** If a dev box has a
self-signed upstream, add *that one cert* to the trust store; never disable checking.

```python
# Pin the dev CA instead of turning verification off
r = requests.get("https://internal-dev.local/api", verify="/etc/ssl/dev-ca.pem")  # ✅
```

```ts
// Node: provide the CA, keep rejectUnauthorized true (its default)
const agent = new https.Agent({ ca: fs.readFileSync("dev-ca.pem") });             // ✅
```

**Bound redirects, and strip auth across origins.**

```ts
const res = await fetch(vendorUrl, {
  redirect: "manual",                 // ✅ inspect the Location yourself
  headers: { Authorization: `Bearer ${SECRET}` },
});
if (res.status >= 300 && res.status < 400) {
  const next = new URL(res.headers.get("location")!, vendorUrl);
  if (!ALLOWED_HOSTS.has(next.host)) throw new Error("refused cross-host redirect");
  // re-fetch WITHOUT the Authorization header if the host changed
}
```

```python
# requests: cap and inspect
r = requests.get(url, allow_redirects=False)   # ✅ then validate Location host yourself
```

**Validate the response against a schema before it touches anything.** Parse, don't
trust. Pull only the fields you expect, with the types you expect.

```ts
import { z } from "zod";
const Contact = z.object({
  id: z.string(),
  email: z.string().email(),
  bio: z.string().max(500),
  // note: NO "role", NO "isAdmin" — you decide the shape, not the upstream
});
const profile = Contact.parse(await crm.get(`/contacts/${id}`).then(r => r.json())); // ✅ throws on junk
await db.user.update({ where: { id }, data: { email: profile.email, bio: profile.bio } }); // explicit fields
```

```python
from pydantic import BaseModel, HttpUrl
class Quote(BaseModel):
    price_cents: int
    currency: str
quote = Quote.model_validate(requests.get(url, timeout=5).json())  # ✅
```

```go
// Decode into a struct with exactly the fields you trust; DisallowUnknownFields catches drift
dec := json.NewDecoder(resp.Body)
dec.DisallowUnknownFields()
var q Quote
if err := dec.Decode(&q); err != nil { return err }   // ✅
```

Then add the basics every outbound call should have anyway: a **timeout**, a **response
size cap** (don't read an unbounded body into memory), and a **content-type check**
(reject `text/html` when you asked for JSON — see the diverse-shape lesson in the scanner
FP notes).

---

## Report a finding as

**Title:** "TLS certificate verification disabled on calls to the payment API"

(adapt the title to the flavor: "App follows unbounded redirects from <vendor> with auth
header attached" for Pattern 2; "<Vendor> response written to the DB without validation"
for Pattern 3.)

**Detail:**
> `src/lib/payments.ts:23` creates an axios client with
> `httpsAgent: new https.Agent({ rejectUnauthorized: false })` and uses it for every call
> to `https://api.payment-vendor.com`. That switches off TLS certificate verification.
> Your app will accept *any* certificate the other end presents — including one from an
> attacker sitting on the network path (public Wi-Fi, a sketchy egress proxy, a hijacked
> DNS/BGP hop, a compromised cloud-internal route).
>
> The concrete attack: that attacker presents their own cert, your client says "looks
> fine," and now they sit invisibly in the middle. They read the API key you send in the
> `Authorization` header and they can rewrite the balance/charge data that comes back.
> The padlock is a lie — you have HTTPS-shaped traffic with none of the protection.
>
> **What to do tonight:**
> 1. Delete the `rejectUnauthorized: false` (and grep for the process-wide
>    `NODE_TLS_REJECT_UNAUTHORIZED=0` in your `.env`, Dockerfile, and CI config — kill
>    those too). The default is verification ON; that's what you want.
>    ```ts
>    // before
>    const client = axios.create({
>      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
>    });
>    // after
>    const client = axios.create(); // verifies certs by default
>    ```
> 2. If this was added because a *dev/staging* upstream uses a self-signed cert, pin that
>    one CA instead of disabling checks for everything:
>    ```ts
>    const agent = new https.Agent({ ca: fs.readFileSync(process.env.DEV_CA_PATH!) });
>    ```
> 3. While you're in this file, give the call a `timeout`, cap how much body you read, and
>    parse the response with a schema (zod/pydantic/struct) before using any field.
> 4. Verify: temporarily point the client at a host with a bad cert (e.g.
>    `https://self-signed.badssl.com`) and confirm the request now **fails** instead of
>    succeeding. Then revert the test URL.
>
> If a payment/credential-bearing call ran with verification off in production, treat any
> keys sent over it as potentially exposed and rotate them (see the rotate skill).

Repeat the report block for each distinct call site you found.

---

## What NOT to flag (false-positive guard)

Crying wolf on a non-security founder is worse than a missed nit. Do **not** raise a
finding for:

- **A pinned internal/dev host with `verify=False` and an explanatory comment**, e.g.
  `requests.get("https://localhost:8443/health", verify=False)  # local self-signed,
  health probe only` — and it clearly targets `localhost`/`127.0.0.1`/an internal
  `.local`/`*.svc.cluster.local` host carrying **no credentials and no sensitive data**.
  Note it as INFO and suggest pinning the CA, but it isn't the high-sev bug. (If it
  targets a *public* host or carries an API key, it IS the bug — comment or not.)
- **Test files and fixtures.** `verify=False`, `InsecureSkipVerify: true`, or
  `badssl.com` calls inside `*.test.ts`, `*_test.go`, `spec/`, `__tests__/`, `e2e/`,
  mock servers, or VCR/nock cassettes are exercising TLS behavior, not shipping it.
- **Localhost / loopback redirects and same-origin redirects** where no auth header is
  attached and the host can't change to something external. Following a redirect *within
  the same trusted vendor origin* is normal API behavior.
- **Responses that ARE validated before use.** If a `zod.parse` / `pydantic
  .model_validate` / `json.Decoder` with `DisallowUnknownFields` / an explicit
  field-by-field copy sits between the `.json()` and the sink, the consumption is safe —
  that's exactly the fix. Don't flag the very thing you'd recommend.
- **Reading a third-party body and just returning/logging it as opaque text**, with no DB
  write, no `eval`/template/shell, and no downstream fetch. Displaying a vendor's status
  string is not a sink (though if it's rendered as raw HTML, that's an XSS finding — hand
  it to `injection.md`, not here).
- **The redirect/fetch where the URL is *user-controlled*** — that's SSRF; report it
  under `ssrf.md` so it isn't double-counted. This module owns the case where *you* chose
  the upstream and over-trusted its reply.
- **Mutual-TLS / cert-pinning setups** (custom `checkServerIdentity` that actually
  *tightens* validation, Android `network_security_config` with a `<pin-set>`, iOS
  `URLSession` delegates that pin a known public key). These are stronger than default,
  not weaker — the opposite of the bug. Read the delegate before flagging: only a
  *trust-everything* delegate (`.useCredential` with the server trust unconditionally, or
  a `checkServerTrusted` with an empty body) is a finding.
