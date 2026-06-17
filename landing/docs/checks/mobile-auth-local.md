# Check — Client-side-only auth decisions in mobile apps (trust-the-client)

**What you're looking for:** mobile code that makes the *authorization decision itself* on the phone — Face ID / fingerprint "succeeded" so the app unlocks the data, `if (user.isAdmin)` decides what the app shows, or a deep link / custom URL scheme does something privileged just because it was opened. This is the mobile twin of the "painted lock" admin page (`admin-paths.md`): the gate is real-looking, but it's a gate the attacker controls, because **it runs on a device they own.**

Here's the mental model founders get wrong: *"the fingerprint check passed, so the user is authorized."* No — the fingerprint check passed, so you know **who is holding the phone**, that's it. Whether that person is *allowed* to read this data or perform this action is a question only your **server** can answer, because only your server can't be patched, hooked, or lied to by someone with the binary in hand. A rooted phone, a Frida hook, or a repackaged `.apk` can make any local `if` return whatever the attacker wants. Anything the client *decides* is a suggestion. Anything the server *validates* is a rule.

This applies whether the app was hand-built in Xcode / Android Studio or vibe-coded in Flutter, React Native, Expo, or a "make me an app" tool — they all generate the same three mistakes, because the happy-path demo (biometric unlocks the screen, admin button appears for admins) looks finished and *works in the simulator*. The hole only shows when someone attacks it.

> This check is about the *decision*, not the *storage*. Where the token is **kept** (Keychain vs plaintext), cleartext HTTP, baked-in secrets, exported components, and logged tokens are covered by `mobile.md`. Here we only care about: **does a privileged action / data access depend on a check the client makes, with nothing re-checking it server-side?**

## How to scan

You're reading the repo, not a running device. Cast a wide net across the mobile stacks. The three patterns are: (1) biometric/local-auth success used *as* the authorization, (2) role/entitlement decided in client code, (3) deep link / URL scheme that grants access or acts on an unvalidated token.

```bash
# ── 1. Biometric / local-auth success used AS the auth decision ───────
# iOS — LocalAuthentication evaluatePolicy success closure
grep -rEn --exclude-dir={Pods,build,DerivedData,.git} \
  --include='*.swift' --include='*.m' \
  -E 'evaluatePolicy|LAContext|deviceOwnerAuthentication' \
  . 2>/dev/null

# Android — BiometricPrompt onAuthenticationSucceeded
grep -rEn --exclude-dir={build,.gradle,.git} \
  --include='*.kt' --include='*.java' \
  -E 'onAuthenticationSucceeded|BiometricPrompt|FingerprintManager' \
  . 2>/dev/null

# Flutter — local_auth authenticate()
grep -rEn --include='*.dart' --exclude-dir={build,.dart_tool} \
  -E 'local_auth|authenticateWithBiometrics|LocalAuthentication\(\)|\.authenticate\(' \
  . 2>/dev/null

# React Native / Expo — LocalAuthentication / TouchID / FaceID libs
grep -rEn --exclude-dir=node_modules \
  -E 'expo-local-authentication|LocalAuthentication\.authenticate|TouchID\.authenticate|ReactNativeBiometrics|simplePrompt' \
  . 2>/dev/null

# ── 2. Role / entitlement / "is this person allowed" decided in client ─
grep -rEn --exclude-dir={node_modules,Pods,build,DerivedData,.git,.dart_tool} \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.js' --include='*.ts' --include='*.tsx' \
  -E '(if|when|guard)[^=\n]*\.(isAdmin|is_admin|isPremium|isPro|isPaid|role|userRole|isOwner|hasAccess|isEntitled|isSubscribed|canEdit|isStaff)\b' \
  . 2>/dev/null

# ── 3. Deep links / custom URL schemes / app links that act on a token ─
# iOS — URL scheme & universal link entry points
grep -rEn --exclude-dir={Pods,build,DerivedData,.git} \
  --include='*.swift' --include='*.m' \
  -E 'open(URL|url)?Contexts|application\([^)]*openURL|continue userActivity|onOpenURL|handleUniversalLink' \
  . 2>/dev/null

# Android — deep-link Intent data, custom schemes
grep -rEn --exclude-dir={build,.gradle,.git} \
  --include='*.kt' --include='*.java' --include='AndroidManifest.xml' \
  -E 'intent\.data|getData\(\)|Intent\.ACTION_VIEW|android:scheme|<data ' \
  . 2>/dev/null

# Flutter / RN deep-link handlers
grep -rEn --exclude-dir={node_modules,build,.dart_tool} \
  --include='*.dart' --include='*.js' --include='*.ts' \
  -E 'uni_links|getInitialLink|onAppLink|Linking\.(addEventListener|getInitialURL)|onDeepLink|app_links' \
  . 2>/dev/null

# Magic-link / token-in-URL patterns reachable from a deep link
grep -rEn --exclude-dir={node_modules,Pods,build,.dart_tool,.git} \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.js' --include='*.ts' \
  -E 'queryParam[^)]*(token|auth|key|otp|reset|magic)|\["(token|auth|key|otp)"\]' \
  . 2>/dev/null
```

Then **read the handler** for each hit and ask the one question that decides everything: *after this check passes, does the app reach into protected data or do a privileged thing using a token the device already has — or does it go to the server, which independently re-checks the user before answering?* If there's no server round-trip carrying a server-validated token, it's a finding.

## The dangerous patterns

### Pattern 1 — Biometric success treated AS the authorization (HIGH)

The biometric prompt passes, and the success branch *directly* unlocks data, navigates to the protected screen, or hands back a secret — with no server call that re-establishes who this is and what they're allowed to see.

```swift
// iOS — Face ID success directly reveals the data. No server in the loop.
let ctx = LAContext()
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                   localizedReason: "Unlock your account") { success, _ in
    if success {
        self.showAccountBalance(self.cachedBalance)   // ← decision made on-device
        self.navigateTo(.adminDashboard)              // ← privileged screen, no server check
    }
}
```
```kotlin
// Android — onAuthenticationSucceeded IS the gate
biometricPrompt.authenticate(promptInfo)
// callback:
override fun onAuthenticationSucceeded(result: AuthenticationResult) {
    unlockVault()                 // ← reveals local secrets purely on local success
    startActivity(Intent(this, AdminActivity::class.java))
}
```
```dart
// Flutter — local_auth result is the only thing standing between user and data
final ok = await auth.authenticate(localizedReason: 'Log in');
if (ok) {
  Navigator.push(context, MaterialPageRoute(builder: (_) => AdminPage()));
  showSecrets(localSecrets);     // ← no token exchange, no server authorization
}
```
```js
// React Native / Expo — same shape
const { success } = await LocalAuthentication.authenticateAsync();
if (success) {
  setAuthed(true);               // ← client flips its own "I'm logged in" flag
  navigation.navigate('Admin');
}
```

**Why it's broken:** the biometric API only answers "is a registered fingerprint/face present on *this device*?" It is a **local convenience gate**, not an identity assertion your server can trust. An attacker with the binary doesn't even take the prompt — they hook the success callback (Frida: force `success = true`), patch the `if`, or replay the cached data the app already pulled. Since the data/secret is right there on the device and the only thing guarding it is a local boolean, the boolean falls. **HIGH** when the success branch reveals account data, money, admin functions, or a long-lived secret with no server re-authorization.

The fix isn't "stop using biometrics." Biometrics are great — for *UX gating*. The biometric should unlock access to a **server-issued token** (already validated server-side at login), and every privileged action then carries that token to the server, which authorizes it. The fingerprint guards the door to the token; the server guards the data.

### Pattern 2 — Role / entitlement decided in client code (HIGH)

The app decides what a user is *allowed* to do based on a flag it computed or read locally — and the privileged action runs purely off that flag, with no server-side authorization behind it.

```swift
// iOS — admin power gated by a local property
if currentUser.isAdmin {
    deleteAllUsers()             // ← if this calls an endpoint that doesn't re-check, it's wide open
    showAdminPanel()
}
```
```kotlin
// Android — premium/paid feature unlocked by a client flag
if (user.subscriptionTier == "PRO" || user.isPremium) {
    enableProExport()            // ← attacker flips the flag, gets Pro free
}
```
```dart
// Flutter — "is this person staff" answered on the phone
if (currentUser.role == 'admin' && currentUser.canEdit) {
  await api.deletePost(postId);  // ← only safe if the SERVER also checks role on deletePost
}
```
```ts
// React Native — entitlement read from a locally-stored/decoded value
const isPro = await AsyncStorage.getItem('isPro');
if (isPro === 'true') unlockPaidContent();   // ← trivially editable on a rooted device
```

**Why it's broken:** the client flag (`isAdmin`, `isPro`, `role`) lives in memory or local storage on a device the attacker controls. They can edit storage, hook the getter, or repackage the app so the check returns `true`. That's fine *if it's only cosmetic* — hiding a button is OK. It becomes a **vulnerability the moment the privileged action behind it (`deleteAllUsers`, `enableProExport`, `deletePost`) isn't independently authorized by the server.** Flip the flag → the button appears → the user taps it → the server happily honors the request because nothing server-side checks the role. This is broken access control (IDOR's cousin), just initiated from a mobile client.

**HIGH** when flipping the client flag yields a privileged action or paid feature the server doesn't re-check. The fix: treat client role/entitlement checks as **UI hints only**. The server must authorize every privileged endpoint against the *server's* record of that user's role — see `api-auth.md` and `idor.md`.

### Pattern 3 — Deep link / URL scheme grants access or acts on an unvalidated token (HIGH)

A custom URL scheme (`myapp://…`), an Android `<intent-filter>` deep link, or a universal/app link opens the app straight into a privileged state, or performs an action carried in the link — and the app *trusts the link* instead of validating it server-side.

```swift
// iOS — opening myapp://admin drops you into the admin screen, authenticated
func application(_ app: UIApplication, open url: URL, ...) -> Bool {
    if url.host == "admin" { navigateTo(.adminDashboard); return true }   // ← no auth at all
    if url.host == "reset" {
        let token = url.queryParam("token")
        resetPasswordLocally(with: token)   // ← acts on a token the app never verified
    }
}
```
```xml
<!-- Android — any app (or any web page) can fire this Intent and land in the app authenticated -->
<activity android:name=".AutoLoginActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="myapp" android:host="auth"/>
  </intent-filter>
</activity>
```
```kotlin
// Android handler — trusts the inbound link's token without server validation
val token = intent.data?.getQueryParameter("token")
sessionManager.setLoggedIn(token)            // ← attacker crafts the link, becomes logged in
```
```dart
// Flutter — uni_links handler grants entry from the URL alone
uriLinkStream.listen((uri) {
  if (uri.host == 'unlock') Navigator.pushNamed(context, '/premium');  // ← link == access
});
```

**Why it's broken:** deep links are an **untrusted, attacker-reachable entry point.** Any other app on the phone can fire that Intent / open that scheme; a web page the user taps can launch it; the user can be social-engineered into opening a crafted link. Custom URL schemes in particular are *not unique* — a malicious app can register the same `myapp://` scheme and intercept, or simply send you one. So a deep link that *itself* grants access (`myapp://admin` → admin screen), or carries a token/OTP the app acts on **without asking the server to validate it**, hands the attacker the keys. Token-in-URL is doubly bad: URLs leak into logs, history, and analytics. **HIGH** when the link grants a privileged state or performs a sensitive action off an unvalidated token.

The fix: a deep link is **input, not authorization.** Treat its parameters as hostile. Any token in a link must be sent to the server and *exchanged for a session there* (the server validates it, checks expiry/one-time-use, and decides). Privileged screens reached via a link must still run the normal server-authorized session check on arrival.

## Safe patterns

**Biometric gates the door to a *server-issued* token; the server authorizes the action:**
```swift
// iOS — Face ID releases the token from the Keychain; the SERVER then authorizes.
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock") { ok, _ in
    guard ok else { return }
    let token = Keychain.read("sessionToken")          // token was validated server-side at login
    api.getBalance(bearer: token) { balance in ... }   // server checks the token, then answers
}
```
The fingerprint controls *local access to the token*. The token's authority is decided by the server every request. (Keep that token in the Keychain/Keystore, not plaintext — that's the `mobile.md` storage check.)

**Client role check is cosmetic; the server re-checks the privileged endpoint:**
```kotlin
// UI hint only — fine to hide the button locally
if (user.isAdmin) adminButton.isVisible = true
// …but deleting still goes to the server, which authorizes against ITS record:
api.deleteUser(targetId)   // server: verify caller's session, verify caller.role == ADMIN, THEN delete
```

**Deep-link token is validated server-side before anything happens:**
```kotlin
val token = intent.data?.getQueryParameter("token")
api.exchangeMagicLink(token) { result ->            // server validates token: real? expired? used?
    if (result.ok) sessionManager.start(result.session)  // server hands back a real session
    else showError()
}
```
Plus: keep auth-sensitive Activities `android:exported="false"` (or require a permission), and prefer **App Links / Universal Links** (domain-verified) over raw custom schemes so other apps can't impersonate yours.

## Report a finding as

**Title:** "Face ID success unlocks your account data on the phone, with nothing checking on the server"

(adapt per pattern: "Admin powers are decided by a flag on the phone the user can flip", "A link like `myapp://admin` drops anyone straight into your admin screen", "A password-reset link is trusted without your server ever validating it")

**Detail:**
> `ios/Account/UnlockViewController.swift:31` runs a Face ID prompt and, on success, calls `showAccountBalance(cachedBalance)` and navigates to the admin dashboard. The biometric result is the *only* thing standing between the user and the data — there's no call to your server in the success branch.
>
> Here's the part that surprises most people: **the fingerprint check doesn't tell your app what someone is *allowed* to do — only that a registered finger touched *this specific phone*.** It's a convenience lock on the device, not a decision your server can trust. And because the check runs entirely on a device the user owns, anyone who downloads your app from the store can repackage it, or attach a standard tool (Frida) that forces the "success" path to fire without any fingerprint at all. The moment they do, the cached data is right there — the local `if` was the whole defense, and the local `if` is theirs to rewrite.
>
> **What can go wrong:** someone with a rooted/jailbroken phone (or just your published binary) flips the biometric result to "success," skips the prompt, and reads the account balance / opens the admin screen / lifts the secret the success branch revealed. No server ever got a chance to say "this person isn't allowed."
>
> **What to do tonight:**
> 1. **Keep using Face ID — but only to gate the UX.** Let it unlock *access to a token* that your server already validated when the user logged in:
>    ```swift
>    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock") { ok, _ in
>        guard ok else { return }
>        let token = Keychain.read("sessionToken")        // validated server-side at login
>        api.getBalance(bearer: token) { balance in self.show(balance) }   // server authorizes
>    }
>    ```
> 2. **Move the actual data/permission decision to the server.** The balance, the admin action, the secret — none of it should be reachable until your server checks the token and the user's role and *then* answers. The client should hold nothing sensitive that a local `if` is the only guard for.
> 3. **Verify:** with the app's network calls visible (any HTTP proxy), confirm that reaching the protected screen triggers a server request carrying the token, and that hitting that endpoint **without** a valid token returns 401 — not the data.
>
> Same principle for the other two shapes:
> - **Client role flag:** `if (user.isAdmin) deleteAllUsers()` is fine for *hiding the button*, but the `deleteAllUsers` endpoint must independently verify the caller's role on the server. Treat the client flag as a hint, never as the lock. (See `api-auth.md`, `idor.md`.)
> - **Deep link grants access:** `myapp://admin` must not land anyone in the admin screen — run the normal server-authorized session check on arrival. Any token in a link (`?token=…`, OTP, magic-link, password-reset) must be **sent to the server and exchanged for a session there**, where it's checked for validity/expiry/single-use. Treat the link as hostile input. Prefer domain-verified App Links / Universal Links and keep sensitive Activities `android:exported="false"`.

Repeat the report block for each pattern you found, swapping in the matching story.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires on a lot of code that is **correct by design**. Biometrics, role flags, and deep links are normal, good things — the bug is *only* when the client's check is the **sole** gate on a privileged action. Don't cry wolf on:

- **Biometric used to release a server-validated token (the right way).** If the success branch reads a token from the Keychain / Keystore / `expo-secure-store` / `flutter_secure_storage` and then **calls the server**, which authorizes the request — that's exactly the correct pattern. The presence of `evaluatePolicy` / `BiometricPrompt` / `local_auth` is **not** a finding on its own. Read the success branch: token-then-server = safe.
- **Biometric / passcode protecting purely local, non-sensitive UX.** A journaling app that Face-ID-locks the *local* notes, a "require unlock to open the app" toggle, hiding a photos folder — when there's no server-side resource and no shared account to take over, a local-only lock is the *entire, appropriate* security model. Not a finding.
- **Client role checks that are genuinely cosmetic AND have a server check behind them.** `if (user.isAdmin) showButton()` / `if (isPro) hidePaywall()` is correct **as long as** the privileged endpoint the button calls re-checks authorization server-side. If you can confirm (or the route file shows) the server enforces it, the client check is just UX — note it INFO at most. Only escalate to HIGH when the client flag is the *only* thing gating the action.
- **Deep links that just navigate to a non-sensitive, still-auth-gated screen.** `myapp://settings` or `myapp://product/123` that lands on a screen which *then* runs the normal logged-in session check is fine — the link is routing, not authorization. Only flag links that grant a privileged *state* or act on a token without server validation.
- **Magic-link / OTP / password-reset flows that send the token to the server for validation.** If the deep-link handler takes the token and calls something like `api.exchangeMagicLink(token)` / `verifyOtp(token)` and the **server** decides — that's the correct design. Token-in-link is only a problem when the *client* acts on it locally without that server exchange.
- **Server-side biometric / WebAuthn / passkey assertions.** If the app uses the Secure Enclave / `SECURITY` key to sign a server-issued challenge that the **server verifies** (passkeys, WebAuthn, app-attest, key-attestation) — that's cryptographic, server-validated auth, the gold standard. Don't flag it; it's the opposite of this bug.
- **`exported="false"` deep-link / auth Activities, or App Links / Universal Links with domain verification.** These already close the "any app can fire it" hole. The presence of a deep link is fine; only the *trusting-the-link-for-authorization* part is the bug.
- **Demo / example / placeholder code.** `if (true)`-style stubs, `// TODO: real auth`, sample screens in an `examples/` or `storybook/` folder, obvious mock users (`isAdmin: true` in a fixture). Note it, but it's not a shipped vulnerability.

When in doubt, the deciding question is: **"if an attacker forced this client-side check to pass — flipped the boolean, edited the stored flag, or crafted the deep link — could they reach data or perform a privileged action that the server never independently authorized?"** If yes → flag it (HIGH). If the server re-checks behind the client gate, or the locked thing is purely local and non-sensitive → at most an INFO heads-up.
