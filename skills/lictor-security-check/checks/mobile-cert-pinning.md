# Check — Mobile TLS trust overrides & certificate pinning

**What you're looking for:** mobile code that turns *off* the part of HTTPS that actually protects users — the bit that checks "am I really talking to my server, or to whoever is sitting in the middle?" There are two ways apps get this wrong, and this check is about both:

1. **Trust-all overrides (the active bug, HIGH).** The app keeps using `https://`, so it *looks* secure, but the developer pasted in a custom trust manager / hostname verifier that accepts **any** certificate from **any** server. The padlock is fake. Anyone on the same Wi-Fi can sit in the middle, present their own certificate, and the app says "looks good to me" — reading and rewriting every login, token, and payment in flight. This is worse than plain HTTP, because plain HTTP at least *looks* insecure; a trust-all override looks encrypted while being wide open.

2. **No pinning where the app clearly needs it (MEDIUM, tightly gated).** The app handles money or health data, *and* the project already wired up a slot for certificate pinning (a `network_security_config` file, a `TrustKit` dependency, an `OkHttp` `CertificatePinner` import) — but left the pin empty or never finished it. Here the developer signalled "we intend to pin" and then shipped without it.

> **Scope — read this so this check stays in its lane.** This module is the **trust-manager layer**: who the app decides to trust. Plain cleartext / `http://` traffic and the `usesCleartextTraffic` / `NSAllowsArbitraryLoads` switches belong to **`mobile.md`** (Pattern 2) and **`security-headers.md`**, not here. And `mobile.md`'s "missing pinning is not a finding on a normal app" guidance still holds — this check only flags *absence* of pinning under the narrow MEDIUM gate in #2 above. The HIGH part (#1, trust-all overrides) is an active, exploitable bug and is always in scope.

This applies to native Android (Kotlin/Java), native iOS (Swift/Objective-C), and the cross-platform stacks (Flutter, React Native, Capacitor/Cordova) — they all wrap the same two OS trust APIs and break them the same way.

## How to scan

You're reading the repo, not the store binary. The dangerous patterns are short and very greppable — a trust-all override is almost always an empty method body or a `return true`.

```bash
# ── 1A. Android/Java/Kotlin — custom TrustManager that trusts everything ──────
# A checkServerTrusted with an empty body = "accept any cert". This is the #1 offender.
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.kt' --include='*.java' \
  -E 'X509TrustManager|checkServerTrusted|TrustManager\[\]|getAcceptedIssuers' \
  . 2>/dev/null

# ── 1B. Android/OkHttp/Java — hostname verifier that returns true for everything ──
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.kt' --include='*.java' \
  -E 'ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier|hostnameVerifier\s*\{|verify\([^)]*\)\s*\{?\s*return\s+true|setHostnameVerifier|NoopHostnameVerifier' \
  . 2>/dev/null

# ── 2. iOS — URLSession delegate that approves any server trust ──────────────
# The smell: a didReceive challenge handler that calls completionHandler(.useCredential, ...)
# with a URLCredential(trust:) and no real evaluation.
grep -rEn --exclude-dir={Pods,build,.git,DerivedData} \
  --include='*.swift' --include='*.m' \
  -E 'didReceive challenge|URLAuthenticationChallenge|serverTrust|URLCredential\(trust|\.useCredential|allowsAnyHTTPSCertificate|continueWithoutCredentialForAuthenticationChallenge|setAllowsAnyHTTPSCertificate|kCFStreamSSLValidatesCertificateChain' \
  . 2>/dev/null

# ── 3. Flutter/Dart — badCertificateCallback that returns true ───────────────
grep -rEn --exclude-dir={.dart_tool,build,.git} --include='*.dart' \
  -E 'badCertificateCallback|onBadCertificate|allowBadCertificates|HttpClient\(\)\.\.' \
  . 2>/dev/null

# ── 4. React Native — trust-all libs / disabled validation ───────────────────
grep -rEn --exclude-dir=node_modules \
  -E 'react-native-ssl-pinning|trustkit|disableAllSecurity|fetch\([^)]*sslPinning|NSAppTransport' \
  . 2>/dev/null

# ── 5. (gate for finding #2) Does the project even OFFER pinning? ────────────
# If the app handles money/health AND none of these exist, that's the MEDIUM gate.
grep -rEln --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  -E 'network_security_config|<pin-set|<pin |NSPinnedDomains|NSPinnedLeafIdentities|CertificatePinner|TrustKit|kTSKPinnedDomains|certificate_pinning|sslPinning' \
  . 2>/dev/null
```

Also open directly:
- **`res/xml/network_security_config.xml`** (Android) — a `<pin-set>` block is how Android-native pinning is declared. Empty/absent = no pinning.
- **`Info.plist`** (iOS) — `NSAppTransportSecurity` → `NSPinnedDomains` is Apple's built-in pinning (iOS 14+). Also check for a `TrustKit` config dictionary.
- Any **`OkHttpClient` builder** (Android/Java/Kotlin) — look for `.certificatePinner(...)` vs. a custom `.sslSocketFactory(...)` / `.hostnameVerifier(...)`.
- Any **`URLSession` delegate** (iOS) — read the `urlSession(_:didReceive:completionHandler:)` body.

## The dangerous patterns

### Pattern 1 — Android custom `TrustManager` with an empty `checkServerTrusted` (HIGH)

```kotlin
// "Accept every certificate from every server." This is the classic trust-all.
val trustAll = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}  // ← empty body = no check
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
OkHttpClient.Builder().sslSocketFactory(ctx.socketFactory, trustAll).build()
```

`checkServerTrusted` is the method that's *supposed* to throw `CertificateException` if the server's certificate is forged or untrusted. An **empty body** means it never throws — so every certificate, including an attacker's self-signed one, is accepted. The connection is still `https://`, so it looks encrypted, but there is no longer any guarantee the other end is your server. This is the most common mobile MITM bug in the wild, and AI assistants generate it constantly when asked to "fix a certificate error" against a self-signed dev server.

**HIGH** whenever this is in code that ships in the release build.

### Pattern 2 — Hostname verifier that always returns `true` (HIGH)

```kotlin
// OkHttp — accepts a cert for ANY hostname (cert for evil.com is accepted for myapp.com)
OkHttpClient.Builder()
    .hostnameVerifier { _, _ -> true }   // ← never compares cert host to the URL host
    .build()
```
```java
// Apache / legacy Android — the named "allow all" verifier
SSLSocketFactory sf = ...;
sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);   // ← deprecated for exactly this reason
// or:
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```

Hostname verification is the *second* half of TLS trust: even with a valid certificate, the client must check the certificate was issued for the host it's actually talking to. A verifier that returns `true` skips that — so an attacker who holds *any* valid certificate (e.g. for a domain they legitimately own) can present it for *your* domain and the app accepts it. **HIGH** in release code.

### Pattern 3 — iOS `URLSession` delegate that unconditionally trusts the server (HIGH)

```swift
// "Whatever cert you sent, I'll use it." No SecTrustEvaluate, no pin check.
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    let trust = challenge.protectionSpace.serverTrust!
    completionHandler(.useCredential, URLCredential(trust: trust))   // ← accepts any server, unconditionally
}
```

The right behaviour here is to *evaluate* the trust (`SecTrustEvaluateWithError`) and, for a pinned app, compare the leaf/public key against your pin — and call `completionHandler(.cancelAuthenticationChallenge, nil)` when it fails. Building a `URLCredential(trust:)` and calling `.useCredential` with **no evaluation in between** tells iOS to trust whatever certificate the server presented. Same effect as Pattern 1. Also flag the old AFNetworking/ASIHTTPRequest knobs that do this by name:

```objc
[policy setAllowInvalidCertificates:YES];          // AFNetworking — disables validation
request.allowsAnyHTTPSCertificate = YES;           // ASIHTTPRequest (legacy)
// NSURLConnection trust-all: a delegate returning a credential for any serverTrust
```

**HIGH** in release code.

### Pattern 4 — Flutter `badCertificateCallback` returning `true` (HIGH)

```dart
final client = HttpClient()
  ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;  // ← accept any bad cert
```

`badCertificateCallback` is only invoked *when the certificate already failed validation*. Returning `true` means "ignore that failure and connect anyway" — a blanket bypass. Returning `false` (or not setting it) is the safe default. **HIGH** in release builds.

### Pattern 5 — Missing pinning where the app handles sensitive data AND config offers it (MEDIUM — tightly gated)

This is **not** "the app doesn't pin, flag it." Normal apps don't need pinning and standard system-CA HTTPS is correct (see `mobile.md`). Flag this **only** when *both* are true:

1. The app clearly handles **money, health, or equivalently sensitive data** (payments, banking, medical records, identity), **and**
2. The project **already wired up a pinning mechanism but left it empty/unfinished** — e.g. a `network_security_config.xml` with a `<domain>` but no `<pin-set>`, a `TrustKit`/`react-native-ssl-pinning` dependency in the manifest with no pins configured, an `OkHttp` `CertificatePinner.Builder()` with no `.add(...)`, or an empty `NSPinnedDomains` dict.

```xml
<!-- Android: pinning scaffolding present, but the <pin-set> is missing → intent without follow-through -->
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.mybank.com</domain>
    <!-- no <pin-set> here → the dev meant to pin and didn't -->
  </domain-config>
</network-security-config>
```

**MEDIUM**, framed as "you started pinning and didn't finish," not "you must pin." If neither condition holds, don't flag it at all.

## Safe patterns

**Don't override trust at all — the system default is correct.** The single best fix for Patterns 1–4 is to *delete the custom trust code* and let the OS validate against the system CA store. If a dev server has a self-signed cert, install the dev CA on the test device (or use a real cert from a free CA) instead of disabling validation in app code.

**Android — public-key pinning via `network_security_config` (declarative, no code):**
```xml
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.myapp.com</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">base64-of-your-leaf-or-intermediate-spki</pin>
      <pin digest="SHA-256">base64-of-your-BACKUP-key-spki</pin>  <!-- always pin a backup -->
    </pin-set>
  </domain-config>
</network-security-config>
```

**Android/OkHttp — `CertificatePinner` (don't touch the trust manager):**
```kotlin
val pinner = CertificatePinner.Builder()
    .add("api.myapp.com", "sha256/AAAA…", "sha256/BBBB…")  // primary + backup
    .build()
OkHttpClient.Builder().certificatePinner(pinner).build()
```

**iOS — built-in `NSPinnedDomains` (iOS 14+, Info.plist, no delegate needed):**
```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSPinnedDomains</key>
  <dict>
    <key>api.myapp.com</key>
    <dict>
      <key>NSPinnedLeafIdentities</key>
      <array><dict><key>SPKI-SHA256-BASE64</key><string>base64-spki…</string></dict></array>
    </dict>
  </dict>
</dict>
```
…or `TrustKit` if you need richer reporting. Either way the delegate **evaluates** trust:
```swift
func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                completionHandler ch: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let trust = c.protectionSpace.serverTrust,
          SecTrustEvaluateWithError(trust, nil) else {           // ← real evaluation
        ch(.cancelAuthenticationChallenge, nil); return          // ← reject on failure
    }
    ch(.useCredential, URLCredential(trust: trust))
}
```

**Flutter — leave validation on (don't set the callback), or pin with a `SecurityContext`/`http_certificate_pinning`.**

## Report a finding as

**Title:** "Your app accepts any HTTPS certificate — the encryption padlock is fake"

(adapt per pattern: "Your app skips the hostname check, so a cert for any domain is accepted for yours" · "Your iOS app trusts whatever certificate the server sends, with no check" · "Your Flutter app ignores certificate errors and connects anyway" · for #5: "You started certificate pinning on your payments app and left it unfinished")

**Detail (trust-all override — Patterns 1–4):**
> `android/app/src/main/java/com/myapp/Net.kt:31` installs a custom `X509TrustManager` whose `checkServerTrusted` method has an empty body. That method is the part of HTTPS that's supposed to reject a forged or untrusted certificate — and an empty body means it never rejects anything. **Your traffic is still `https://`, so it looks encrypted, but the lock no longer checks who's on the other end.**
>
> **What can go wrong:** Anyone on the same network as your user — coffee-shop Wi-Fi, an airport, a hotel, a compromised router — can put themselves in the middle, present their own certificate, and your app says "looks good." From that point they read and can rewrite everything the app sends: logins, session tokens, payment details. This is *worse* than plain HTTP, because plain HTTP at least looks insecure to anyone reviewing it — this looks fully encrypted while being wide open. It's also an automatic App Store / Play Store risk and a common audit failure.
>
> **What to do tonight:**
> 1. **Delete the custom trust code.** The single correct fix is to stop overriding trust and let the OS validate against the system certificate store — that's the secure default and it's free:
>    ```kotlin
>    // remove the trustAll TrustManager + sslSocketFactory(...) override entirely
>    val client = OkHttpClient.Builder().build()   // system validation is back on
>    ```
> 2. If you only disabled validation to talk to a **self-signed dev server**, don't ship that. Install the dev CA on your test device, or get a free real certificate (Let's Encrypt) for the dev host, and remove the override before release.
> 3. If you genuinely want extra protection for a sensitive endpoint, *add pinning* (the secure way) instead of *removing validation* — see the safe patterns: Android `CertificatePinner` / `<pin-set>`, iOS `NSPinnedDomains`. Always include a backup pin so a cert rotation doesn't brick the app.
> 4. Re-check: search the repo for `checkServerTrusted`, `hostnameVerifier`, `badCertificateCallback`, and `URLCredential(trust:` — all should be gone or doing real evaluation.

**Detail (missing pinning, gated — Pattern 5):**
> `app/src/main/res/xml/network_security_config.xml:4` declares a `<domain-config>` for `api.mybank.com` but has no `<pin-set>` inside it — the scaffolding for certificate pinning is there, but no pin was ever added. Because this app handles payments, that's worth finishing. Add a `<pin-set>` with your server's public-key hash plus a backup hash (see the safe pattern above). This is a **MEDIUM** "finish what you started," not an emergency — standard HTTPS is still validating; you're adding a second lock on a high-value door.

Repeat the report block for each location you found, swapping in the right per-stack story (Kotlin/Java empty trust manager, OkHttp hostname verifier, iOS delegate, Flutter callback, RN trust-all lib).

## What NOT to flag (false-positive guards — read this before reporting)

This check looks for trust *overrides*, so the default state is safe — be careful not to invert that.

- **No custom trust manager / no delegate / no callback at all = SAFE.** The vast majority of apps never touch TLS trust, and that's exactly right — the OS validates against the system CA store by default. **Absence of trust-override code is the good outcome, not a finding.** Only flag when an override actively *weakens* validation.
- **No certificate pinning on a normal app.** Standard HTTPS with system CAs is the correct baseline. Missing pinning is **not** a finding for a typical app (matches `mobile.md`). Only the narrow Pattern 5 gate applies — sensitive-data app *and* half-wired pinning config — and even then it's MEDIUM, not HIGH.
- **Trust override behind a debug-only guard.** `if (BuildConfig.DEBUG) { ... }`, `#if DEBUG`, `if (__DEV__)`, a `debug`-only Gradle `buildType`/`sourceSet`, an Xcode Debug-only config, or a Flutter `kDebugMode` check that relaxes trust **only for the dev/staging build** is a deliberate dev convenience and does not ship to users. Read the surrounding guard before flagging. (If you can't tell whether it's stripped from release, note it as a question, not a HIGH.)
- **A delegate that actually evaluates trust.** A `didReceive challenge` handler that calls `SecTrustEvaluateWithError(...)` / compares an SPKI hash / checks a pin before calling `.useCredential` is *correct* — that's pinning done right, not a bypass. The bug is only the *unconditional* `URLCredential(trust:)` with no evaluation.
- **`getAcceptedIssuers()` returning an empty array on its own.** That method legitimately returns `[]` in many *correct* custom trust managers (it's only meaningful for client-cert auth). The red flag is an **empty `checkServerTrusted`**, not an empty `getAcceptedIssuers`. Don't flag the latter in isolation.
- **A hostname verifier with real logic.** `hostnameVerifier { host, session -> host == "api.myapp.com" }` or one that delegates to `OkHostnameVerifier.INSTANCE` / `HttpsURLConnection.getDefaultHostnameVerifier()` is doing a real check. Only `return true` / `ALLOW_ALL_HOSTNAME_VERIFIER` / `NoopHostnameVerifier` is the bug.
- **Plain `http://` / cleartext flags.** `usesCleartextTraffic="true"`, `NSAllowsArbitraryLoads`, and `http://` endpoints are the **cleartext** problem and belong to `mobile.md` / `security-headers.md`. Don't double-report them here — this check is specifically about *certificate/trust* validation on `https://` connections.
- **Test code, mocks, and sample fixtures.** Trust-all in `src/test/`, `androidTest/`, `*Test.kt`, `__tests__/`, an MSW/WireMock mock server, or an example snippet in a README is not shipped to users. Confirm the file is part of the release build before flagging.
- **Self-signed handling that pins the dev CA rather than trusting all.** A trust manager that validates against a *bundled, specific* dev/internal CA certificate (not an empty body) is a legitimate way to talk to an internal server — that's pinning, not a bypass.

When in doubt, the deciding question is: **"if a stranger sat between this app and the server on a shared Wi-Fi and presented their own certificate, would the app accept it?"** If the override makes the answer *yes* (empty trust check, always-true hostname verifier, unconditional iOS credential, Flutter callback returning true) → flag it HIGH. If the code actually evaluates the certificate, or there's simply no override at all → not a finding.

---
*Source: OWASP Mobile Top 10 2024 — M5: Insecure Communication. Free, repo-read-only; no paid scanners or live traffic needed.*
