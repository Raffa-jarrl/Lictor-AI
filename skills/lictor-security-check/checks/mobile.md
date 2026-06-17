# Check — Mobile app leaks (iOS / Android / Flutter / React Native)

**What you're looking for:** the handful of mistakes that turn a shipped mobile app into a data leak — secrets baked into the app bundle, traffic sent over plain HTTP, sensitive data dropped into storage that any other process (or anyone with the phone) can read, Android components left open for any other app to poke, and passwords/tokens printed into the device logs. Mobile is different from web in one scary way: **once you ship a binary, anyone can download it from the store and pull it apart.** A web bundle is annoying to reverse-engineer; an `.ipa` or `.apk` is a zip file. Treat everything inside the app as public.

This matters whether the app was hand-built in Xcode/Android Studio or vibe-coded in Flutter, React Native, Expo, Capacitor, or a "make me an app" AI tool — they all produce the same five bugs.

## How to scan

You're reading the repo, not the store binary, so look at source + the config files that control packaging. Cast a wide net across the mobile stacks.

```bash
# ── 1. Hardcoded secrets in the app bundle (every stack) ──────────────
# Strong-prefix keys baked into mobile source / config / plist / gradle
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.swift' --include='*.m' --include='*.h' --include='*.kt' \
  --include='*.java' --include='*.dart' --include='*.js' --include='*.ts' \
  --include='*.tsx' --include='*.xml' --include='*.plist' --include='*.gradle' \
  --include='*.properties' --include='*.json' \
  'sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}|sk-(proj-)?[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{24,}|AIza[A-Za-z0-9_-]{35}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[abp]-[A-Za-z0-9-]{10,}' \
  . 2>/dev/null

# Generic "key/secret/token/password = literal" in mobile source
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.m' --include='*.xml' \
  -E '(apiKey|api_key|secret|password|token|accessKey|clientSecret)\s*[:=]\s*"[^"]{8,}"' \
  . 2>/dev/null

# React Native / Expo: secrets in app.json/app.config + .env shipped to the bundle
grep -rEn --exclude-dir=node_modules \
  -E 'EXPO_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN)|"(apiKey|secret|password)"\s*:' \
  app.json app.config.js app.config.ts eas.json .env* 2>/dev/null

# ── 2. Cleartext / non-HTTPS traffic allowed ─────────────────────────
# iOS — App Transport Security turned off in Info.plist
grep -rEn --include='*.plist' \
  -E 'NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking' \
  . 2>/dev/null

# Android — cleartext HTTP allowed in the manifest or network-security-config
grep -rEn --include='AndroidManifest.xml' --include='*.xml' \
  -E 'usesCleartextTraffic="true"|cleartextTrafficPermitted="true"' \
  . 2>/dev/null

# Anyone: literal http:// (not https) endpoints in code
grep -rEn --exclude-dir={node_modules,Pods,build,.git} \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.js' --include='*.ts' \
  -E '"http://[^"]+' \
  . 2>/dev/null | grep -vE 'localhost|127\.0\.0\.1|10\.0\.2\.2|schemas\.android|w3\.org|xmlns'

# ── 3. Secrets in insecure local storage ─────────────────────────────
# React Native — AsyncStorage holding tokens (it's plaintext on disk)
grep -rEn --exclude-dir=node_modules \
  -E 'AsyncStorage\.(set|get)Item\([^)]*(token|password|secret|auth|jwt|session|card)' \
  . 2>/dev/null

# Android — SharedPreferences storing creds (plaintext XML in app sandbox)
grep -rEn --include='*.kt' --include='*.java' \
  -E '(getSharedPreferences|edit\(\))[^;]*\.(putString|putStringSet)\([^)]*(token|password|secret|pin|jwt|auth)' \
  . 2>/dev/null

# iOS — UserDefaults storing creds (plaintext plist, not the Keychain)
grep -rEn --include='*.swift' --include='*.m' \
  -E '(UserDefaults|NSUserDefaults)[^;\n]*\.(set|setObject)\([^)]*(token|password|secret|pin|jwt|auth)' \
  . 2>/dev/null

# Flutter — shared_preferences holding creds (also plaintext)
grep -rEn --include='*.dart' \
  -E 'prefs\.(setString|setStringList)\([^)]*(token|password|secret|jwt|auth)' \
  . 2>/dev/null

# ── 4. Exported Android components (open to any other app) ────────────
grep -rEn --include='AndroidManifest.xml' \
  -E 'android:exported="true"|<intent-filter' \
  . 2>/dev/null

# ── 5. Sensitive data written to logs ────────────────────────────────
# Android Logcat + iOS NSLog/print + RN/Flutter console
grep -rEn --exclude-dir={node_modules,Pods,build,.git} \
  --include='*.kt' --include='*.java' --include='*.swift' --include='*.m' \
  --include='*.dart' --include='*.js' --include='*.ts' \
  -E '(Log\.[dveiw]|println|NSLog|print|console\.log|debugPrint)\([^)]*(token|password|secret|jwt|auth|card|cvv|ssn|otp)' \
  . 2>/dev/null
```

Also worth opening directly:
- **`Info.plist`** (iOS) — look for the `NSAppTransportSecurity` dictionary.
- **`AndroidManifest.xml`** — look at every `<activity>`, `<service>`, `<receiver>`, `<provider>` and its `android:exported` value + whether it has an `<intent-filter>`.
- **`res/xml/network_security_config.xml`** (Android) — controls cleartext + which CAs are trusted.
- **`app.json` / `app.config.js` / `eas.json`** (Expo/RN) and **`google-services.json` / `GoogleService-Info.plist`** (Firebase) — these get bundled into the app.

## The dangerous patterns

### Pattern 1 — Secrets baked into the app binary (CRITICAL for server secrets, HIGH/INFO otherwise)

```swift
// iOS — the key is now inside every copy of the app on the App Store
let openAIKey = "sk-proj-AbCd...realkey...1234"
```
```kotlin
// Android — same story, lives in the decompilable .apk
const val STRIPE_SECRET = "sk_live_51Hxxxx..."
```
```dart
// Flutter — strings compile into the binary; `strings app.so` finds them
const apiSecret = "AIzaSyD...realkey";
```
```jsonc
// React Native / Expo — anything EXPO_PUBLIC_* is shipped to the device
"extra": { "EXPO_PUBLIC_OPENAI_KEY": "sk-proj-..." }
```

The mental model founders get wrong: *"it's a mobile app, the code is compiled, nobody can see it."* Wrong. An `.apk` is a renamable `.zip`; an `.ipa` is too. `strings`, `apktool`, `jadx`, and `class-dump` pull every string literal out in seconds. Anything in the bundle — server API keys, signing secrets, third-party tokens — is effectively published the moment the app hits the store.

Severity by what the secret unlocks:
- A **server secret** that can spend money or read your database (OpenAI/Anthropic/Stripe `sk_live`, AWS, a DB connection string, an admin token) → **CRITICAL**. This should never be in the app at all — the app should call *your* backend, and your backend holds the key.
- A **third-party key that's scoped + restricted** (a Google Maps key locked to your bundle ID, a Firebase `apiKey`) → **INFO / LOW**, *if* it's properly restricted (see "What NOT to flag"). These are designed to live in the client.
- A **publishable/anon key** (Stripe `pk_live`, Supabase `anon`) → **INFO**, *as long as* the real protection (RLS, server-side checks) is in place behind it.

### Pattern 2 — Cleartext (non-HTTPS) traffic allowed (HIGH)

```xml
<!-- iOS Info.plist — the global "let me talk to anything over HTTP" switch -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>          <!-- ← disables HTTPS enforcement app-wide -->
</dict>
```
```xml
<!-- AndroidManifest.xml -->
<application android:usesCleartextTraffic="true">  <!-- ← any http:// allowed -->
```
```kotlin
val url = "http://api.myapp.com/login"   // ← login over plain HTTP
```

When traffic isn't encrypted, anyone on the same Wi-Fi (coffee shop, airport, hotel) — or any router between the phone and your server — can read it as plain text. For a login screen that means they read the password. The AI flips `NSAllowsArbitraryLoads` on (or sets `usesCleartextTraffic="true"`) early in development to talk to a local `http://` dev server, and the switch never gets turned back off before release.

**HIGH** when login, tokens, or personal data flow over it. If the only `http://` URL is a localhost dev endpoint, that's fine — see "What NOT to flag."

### Pattern 3 — Secrets in insecure local storage (HIGH)

```js
// React Native — AsyncStorage is an UNENCRYPTED file in the app sandbox
await AsyncStorage.setItem('authToken', token);
await AsyncStorage.setItem('password', pw);
```
```kotlin
// Android — SharedPreferences is plaintext XML in /data/data/<app>/shared_prefs/
prefs.edit().putString("jwt", token).apply()
```
```swift
// iOS — UserDefaults is a plaintext plist, NOT the Keychain
UserDefaults.standard.set(refreshToken, forKey: "refreshToken")
```
```dart
// Flutter — shared_preferences is also plaintext
await prefs.setString('access_token', token);
```

`AsyncStorage`, `SharedPreferences`, `UserDefaults`, and `shared_preferences` are all **plaintext, unencrypted** stores meant for *settings* (theme, last-tab, onboarding-seen) — not secrets. On a rooted/jailbroken phone, in an unencrypted device backup, or via a malicious app exploiting a sandbox bug, these files are readable. A long-lived auth token or password sitting there means full account takeover from a recovered or backed-up phone.

The fix is to use the OS-provided secure store: **iOS Keychain**, **Android Keystore / EncryptedSharedPreferences**, `expo-secure-store` (RN/Expo), `flutter_secure_storage` (Flutter). **HIGH** when it's an auth token, password, refresh token, or payment data.

### Pattern 4 — Exported Android components (HIGH when they do something sensitive)

```xml
<!-- Any other app on the phone can launch this and reach the screen/logic behind it -->
<activity android:name=".AdminActivity" android:exported="true" />

<receiver android:name=".PaymentReceiver" android:exported="true">
  <intent-filter>
    <action android:name="com.myapp.CHARGE" />   <!-- ← any app can fire this -->
  </intent-filter>
</receiver>

<provider android:name=".UserDataProvider"
          android:authorities="com.myapp.data"
          android:exported="true" />              <!-- ← any app can query your data -->
```

`android:exported="true"` means *other apps* on the device can start that Activity, send Intents to that Service/Receiver, or query that ContentProvider. If the component does something sensitive — opens an internal admin screen, triggers a charge, hands back user records, accepts a deep link that mutates state — a malicious app the user also installed can drive it. Since Android 12 (API 31), any component with an `<intent-filter>` *must* declare `exported` explicitly, so AI-generated manifests now sprinkle `exported="true"` to make the build pass, often on components that should be private.

**HIGH** for exported components guarding sensitive actions/data with no permission check. **LOW/INFO** for the launcher Activity (which *must* be exported) or components protected by a signature-level permission.

### Pattern 5 — Sensitive data in logs (MEDIUM, HIGH if it's the password/token itself)

```kotlin
Log.d("Auth", "Logging in with token=$jwt password=$password")  // ← Android logcat
```
```swift
print("login response: \(responseBody)")   // tokens/PII land in device logs
NSLog("user card: \(cardNumber)")
```
```js
console.log('auth response', { token, user });   // RN / Flutter debugPrint(...)
```

Device logs aren't private. On Android, any app with `READ_LOGS` (and crash-reporting SDKs, and `adb logcat` over USB) can read what you log; on both platforms, logged tokens/PII get swept into Crashlytics/Sentry/analytics breadcrumbs and end up sitting in a third-party dashboard. A token printed to the log is a token leaked. **MEDIUM** generally; **HIGH** when the logged value is a credential, full auth response, card number, or other PII, especially in code that runs in the *release* build (not behind a `if (BuildConfig.DEBUG)` / `#if DEBUG` guard).

### Bonus — Missing certificate pinning (LOW → INFO)

Not having cert pinning is **not a bug by itself** — standard HTTPS with system CAs is the correct baseline and fine for the vast majority of apps. Mention pinning only as a **LOW/INFO** "level-up" for apps handling money or health data, and only after Patterns 1–5 are clean. Do not flag "no pinning" as a finding on a normal app — that's crying wolf.

## Safe patterns

**Secrets stay on your server; the app calls your backend:**
```swift
// The app never holds the OpenAI key. It calls YOUR endpoint; your server adds the key.
let resp = try await URLSession.shared.data(for: request(to: "https://api.myapp.com/chat"))
```

**HTTPS enforced (the default — leave ATS on, don't add the cleartext flag):**
```xml
<!-- Android network_security_config.xml — explicit, locked down -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```

**Tokens in the secure OS store, not plaintext storage:**
```swift
// iOS — Keychain
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrAccount as String: "authToken",
                            kSecValueData as String: token.data(using: .utf8)!]
SecItemAdd(query as CFDictionary, nil)
```
```js
// React Native / Expo
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('authToken', token);
```
```dart
// Flutter
final storage = FlutterSecureStorage();
await storage.write(key: 'authToken', value: token);
```

**Android components private by default:**
```xml
<activity android:name=".AdminActivity" android:exported="false" />
```

**No secrets in release logs:**
```kotlin
if (BuildConfig.DEBUG) Log.d("Auth", "login ok")   // no token, debug-only
```

## Report a finding as

**Title:** "Your app ships your OpenAI key inside the download — anyone can pull it out"

(adapt per pattern: "Your app sends logins over plain HTTP", "Your login token is saved unencrypted on the phone", "Another app on the user's phone can open your admin screen", "Your app prints user passwords into the phone's log")

**Detail:**
> `ios/Chat/APIClient.swift:22` has your OpenAI key written directly into the code as `let openAIKey = "sk-proj-..."`. Here's the part that surprises most people: **a mobile app isn't a black box.** Once it's on the App Store or Play Store, anyone can download it and unzip it — an `.ipa` and an `.apk` are both just zip files — and run a one-line `strings` command to dump every piece of text inside, including that key. Compiling the code does not hide it.
>
> **What can go wrong:** Someone pulls your key out of the published app and runs their own traffic through your OpenAI account. You get the bill — and these bills get large fast, because once a working key is posted in a scraper's list, bots hammer it around the clock. Same story for a Stripe `sk_live` key (they can move your money) or a database string (they can read your whole database).
>
> **What to do tonight:**
> 1. **Rotate the key now** — it's effectively public. (For OpenAI: platform.openai.com → API keys → revoke + create new.)
> 2. **Get the key out of the app entirely.** The app should never hold a server secret. Stand up a tiny backend endpoint (`https://api.myapp.com/chat`) that holds the key in a server-side env var, and have the app call *your* endpoint instead of OpenAI directly:
>    ```swift
>    // app side — no key here anymore
>    let req = URLRequest(url: URL(string: "https://api.myapp.com/chat")!)
>    // ...your server attaches the OpenAI key and forwards the request
>    ```
> 3. **Add auth + rate limits on that endpoint** so it can't be abused the same way.
> 4. Re-scan the bundle after the change: `unzip -p YourApp.ipa | strings | grep -i 'sk-'` should come back empty.
>
> If the "key" is actually a *restricted* client key (a Google Maps key locked to your bundle ID, a Firebase config key, a Stripe `pk_live`), this is fine — those are designed to live in the app. See the note below.

Repeat the report block for each pattern you found, swapping in the right story:
- **Cleartext:** "Anyone on the same coffee-shop Wi-Fi can read your users' passwords as they log in, because the app talks to your server over plain HTTP instead of HTTPS." Fix: remove `NSAllowsArbitraryLoads` / `usesCleartextTraffic="true"`, switch the URL to `https://`.
- **Insecure storage:** "Your login token is saved in [AsyncStorage / SharedPreferences / UserDefaults], which is an unencrypted file. If someone gets the phone, a backup, or roots the device, they read the token and become that user." Fix: move it to the secure store (Keychain / Keystore / `expo-secure-store` / `flutter_secure_storage`).
- **Exported component:** "Any other app the user installs can open your `AdminActivity` directly, because it's marked `exported=\"true\"` with no permission check." Fix: set `android:exported="false"` (or guard it with a signature-level permission).
- **Logs:** "Your app prints the user's password/token into the phone's log, where crash-reporting SDKs and any USB-connected machine can read it." Fix: stop logging the value; wrap any debug logging in a `BuildConfig.DEBUG` / `#if DEBUG` guard so it never runs in release.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires easily. Mobile has a lot of things that *look* like leaks but are correct by design. Don't cry wolf on:

- **Restricted client keys that are meant to ship.** A **Google Maps / Places API key locked to your bundle ID + an API restriction**, a **Firebase `apiKey`** in `google-services.json` / `GoogleService-Info.plist`, a **Stripe `pk_live`** publishable key, a **Supabase `anon` key** — these are *designed* to be embedded in the client. Google explicitly says the Firebase `apiKey` is not a secret. Don't flag them as CRITICAL. At most note ⚪ INFO and ask one question: "is your Maps key restricted to this app's bundle ID, and is your Supabase/Firebase protected by Row Level Security / security rules?" The risk lives in those backend rules, not the visible key.
- **`http://` to localhost / loopback / the emulator.** `http://localhost`, `http://127.0.0.1`, `http://10.0.2.2` (Android emulator's host alias) are dev-only and never reach a real network. Skip them.
- **Scoped ATS / cleartext exceptions for a known dev or third-party host** — e.g. a `network_security_config.xml` that permits cleartext only for a specific test domain or a partner that's HTTP-only, not the global `NSAllowsArbitraryLoads` / `usesCleartextTraffic="true"`. A narrow, named exception is a judgment call, not an automatic finding.
- **The launcher Activity being `exported="true"`.** The main `MAIN`/`LAUNCHER` Activity *must* be exported or the app can't start. Same for components the OS launches (a `FirebaseMessagingService`, a deep-link Activity that only reads data). Exported isn't dangerous on its own — only when the component performs a sensitive action or returns sensitive data with no permission check.
- **Non-sensitive data in `SharedPreferences` / `UserDefaults` / `AsyncStorage`.** Theme, language, "onboarding seen," feature flags, last-opened-tab, a non-secret user ID — that's exactly what these stores are *for*. Only flag tokens, passwords, refresh tokens, PINs, payment data.
- **Logs that are debug-only.** Anything inside `if (BuildConfig.DEBUG) { ... }`, `#if DEBUG`, `if (__DEV__)`, or stripped by ProGuard/R8 in release doesn't ship. Read the surrounding guard before flagging. Also fine: logging an opaque request ID, a status code, or a redacted/masked value.
- **Example / template / sample values.** `"YOUR_API_KEY_HERE"`, `"sk-xxxxxxxx"`, `.env.example`, placeholder strings in README/sample code, test fixtures with known-fake keys. Not real secrets.
- **No certificate pinning on a normal app.** Standard HTTPS with system CAs is the correct, expected baseline. Missing pinning is *not* a finding for the typical app — only mention it as an optional LOW/INFO hardening step for finance/health apps, and only after the real issues are clean.
- **`react-native-keychain`, `expo-secure-store`, `flutter_secure_storage`, `EncryptedSharedPreferences`, Keychain APIs.** Seeing these is the *good* sign — the app is already storing secrets correctly. Don't flag the presence of the secure store.

When in doubt, the deciding question is: **"if a stranger downloaded this app from the store and unzipped it — or picked up a user's unlocked phone — could they get a working secret, read a credential in transit, or pull a token off the disk?"** If yes → flag it. If it's a restricted-by-design client key, a localhost URL, a debug-only log, or non-sensitive settings → at most an INFO heads-up.
