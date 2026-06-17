# Check — Mobile insecure data storage (databases, files, logs)

**What you're looking for:** sensitive data — auth tokens, passwords, PII, payment/card data — sitting **unencrypted at rest** on the phone, where it shouldn't be. Specifically the three places founders forget about once they move past the obvious key/value stores:

1. **Local databases** (SQLite, Realm, Core Data, Room, Drift) that hold tokens/PII with **no encryption** — no SQLCipher, no Realm `encryptionKey`, no iOS file protection.
2. **Files written to shared / world-readable / external storage** — `MODE_WORLD_READABLE`, the SD card / `getExternalStorageDirectory()`, or an iOS file with `FileProtectionType.none`.
3. **Secrets printed into device logs** — a token or password passed straight to `NSLog` / `print` / `Log.d` / `os_log` / `console.log`.

This is the **OWASP Mobile Top 10 2024 — M9: Insecure Data Storage** class. It's the sibling of the key/value-store problem in the main **`mobile.md`** check (UserDefaults / SharedPreferences / AsyncStorage). That check covers the small "settings" stores; **this one goes one layer deeper** — the actual database the app builds, the files it writes, and the logs it emits. Run both.

The mental model that gets founders burned is the same as the rest of mobile: **the phone is not a safe.** A lost or stolen device, an unencrypted cloud/iTunes backup, a rooted/jailbroken phone, a shared family tablet, a malicious app the user also installed, or a support engineer with `adb` access — any of these can read what your app left lying around in plaintext. If the answer to *"could someone with the phone (or its backup) read a working token or a user's personal data straight off the disk?"* is yes, that's the finding.

Applies to every stack: native iOS (Swift/Obj-C), native Android (Kotlin/Java), Flutter (Dart), and React Native / Expo (JS/TS).

## How to scan

You're reading the repo, not the device, so look at where the app opens databases, writes files, and logs. Cast the net across stacks.

```bash
# ── 1. Local DATABASES holding data — are they encrypted? ─────────────
# Find the database engines in use (then check each for an encryption key)
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.swift' --include='*.m' --include='*.kt' --include='*.java' \
  --include='*.dart' --include='*.js' --include='*.ts' --include='*.tsx' \
  -E 'Realm\(|Realm\.open|realm_|Room\.databaseBuilder|RoomDatabase|SQLiteOpenHelper|SQLiteDatabase|sqlite3_open|FMDatabase|GRDB|DatabaseQueue|NSPersistentContainer|NSManagedObject|openDatabase\(|SQLite\.openDatabase|drift|moor|expo-sqlite|react-native-sqlite|WatermelonDB' \
  . 2>/dev/null | head -40

# Is encryption present anywhere? (absence near sensitive DBs = the finding)
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.js' --include='*.ts' --include='*.gradle' --include='*.podspec' \
  -E 'SQLCipher|SQLCipher|sqlcipher|net\.zetetic|encryptionKey|Realm.*encrypt|PRAGMA\s+key|setPassword|cipher_|SQLiteDatabaseHook|supportFactory\(' \
  . 2>/dev/null | head -30

# ── 2. FILES written to shared / world-readable / external storage ────
# Android — world-readable/writable modes + external (SD-card) storage
grep -rEn --include='*.kt' --include='*.java' \
  -E 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|Environment\.DIRECTORY|/sdcard/|openFileOutput\([^,]+,\s*[123]\b' \
  . 2>/dev/null

# Android manifest — broad storage permissions (a hint the app writes there)
grep -rEn --include='AndroidManifest.xml' \
  -E 'WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|requestLegacyExternalStorage' \
  . 2>/dev/null

# iOS — file protection explicitly turned OFF, or writes with no protection class
grep -rEn --include='*.swift' --include='*.m' \
  -E 'FileProtectionType\.none|NSFileProtectionNone|\.noFileProtection|completeFileProtection\s*:\s*false' \
  . 2>/dev/null

# Flutter / RN — writing app data to a shared/external/public directory
grep -rEn --exclude-dir={node_modules,.dart_tool} \
  --include='*.dart' --include='*.js' --include='*.ts' \
  -E 'getExternalStorageDirectory|getDownloadsDirectory|/storage/emulated|RNFS\.(ExternalStorage|DownloadDir|ExternalDirectoryPath)|Downloads(DirectoryPath)?' \
  . 2>/dev/null

# ── 3. SECRETS / tokens written to device logs ───────────────────────
# Android Log.* + iOS NSLog/print/os_log + Flutter/RN console — with a secret in the arg
grep -rEn --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  --include='*.kt' --include='*.java' --include='*.swift' --include='*.m' \
  --include='*.dart' --include='*.js' --include='*.ts' \
  -E '(Log\.[dveiwa]|Timber\.|NSLog|os_log|Logger\(|print|debugPrint|console\.(log|debug|info|warn|error))\s*\(' \
  . 2>/dev/null \
  | grep -iE 'token|password|passwd|pwd|secret|jwt|bearer|api[_-]?key|auth|session|cookie|refresh|otp|pin|card|cvv|ssn|credential' \
  | head -40
```

Also worth opening directly:
- The **DB setup / migration file** (`*Database.kt`, `RealmConfiguration`, `NSPersistentContainer` setup, `openDatabase(...)`, `drift`/`moor` `@DriftDatabase`) — that's where the encryption key would be passed if it existed. Its absence is the signal.
- Any **export / share / download / backup** feature — that's the usual reason data lands on external storage.
- The **logging utility / interceptor** (an OkHttp/Retrofit `HttpLoggingInterceptor` at `BODY` level, an Alamofire/`URLSession` request logger, an Axios/`fetch` logger in RN) — these dump full request/response bodies, headers and all, which is how tokens get logged wholesale.

## The dangerous patterns

### Pattern 1 — Sensitive data in an unencrypted local database (🟠 HIGH)

The app builds a real on-device database and stores tokens, profile info, messages, or payment data in it **in the clear**. The default SQLite/Realm/Core Data file is just a regular file in the app sandbox — plaintext rows anyone with the device or a backup can read with free tools (`sqlite3`, Realm Studio, `strings`).

```kotlin
// Android Room — no SupportFactory / SQLCipher → plaintext .db on disk
@Entity data class Session(@PrimaryKey val id: Int, val authToken: String, val ssn: String)

val db = Room.databaseBuilder(ctx, AppDb::class.java, "app.db").build()  // ← no encryption
```
```swift
// iOS — Core Data store with no file protection; or GRDB/FMDB plain SQLite
let container = NSPersistentContainer(name: "Model")
container.loadPersistentStores { _, _ in }      // ← default = readable in backups
// store holds: token, card number, full name, DOB...
```
```js
// React Native — expo-sqlite / react-native-sqlite-storage, plaintext
const db = SQLite.openDatabase('app.db');
db.transaction(tx => tx.executeSql(
  'INSERT INTO auth (jwt, card) VALUES (?, ?)', [jwt, cardNumber]));   // ← in the clear
```
```dart
// Flutter — Realm without an encryptionKey, or sqflite/drift plain
final config = Configuration.local([User.schema]);   // ← no encryptionKey:
final realm = Realm(config);                          // tokens/PII stored plaintext
```

**HIGH** when the table holds auth tokens, passwords, payment/card data, or regulated PII (government IDs, health data). The fix is to **encrypt the store** (SQLCipher for SQLite/Room, Realm's `encryptionKey`, iOS `completeFileProtection`/`completeUntilFirstUserAuthentication`) **and keep the *encryption key itself* in the Keychain/Keystore** — never hardcoded, never in the same DB.

### Pattern 2 — Files written to shared / world-readable / external storage (🟠 HIGH, 🔴 CRITICAL if it's credentials/payment data)

The app writes data somewhere **outside its private sandbox**, so other apps and the user (and any backup) can read it.

```kotlin
// Android — world-readable file: EVERY other app can open it
val fos = openFileOutput("user.json", Context.MODE_WORLD_READABLE)   // ← deprecated for a reason
fos.write(json.toByteArray())

// Android — external storage (SD card / shared): not sandboxed, readable by others
val f = File(getExternalStorageDirectory(), "tokens.txt")            // ← world-readable medium
f.writeText(refreshToken)
```
```swift
// iOS — file protection explicitly disabled → readable even on a locked device / in backup
try data.write(to: url, options: .init(rawValue: 0))            // no protection
FileManager.default.createFile(atPath: p, contents: pii,
  attributes: [.protectionKey: FileProtectionType.none])        // ← .none is the bug
```
```dart
// Flutter — writing to external/public storage instead of app-private
final dir = await getExternalStorageDirectory();                // shared, not private
await File('${dir!.path}/session.json').writeAsString(token);   // ← exposed
```

`MODE_WORLD_READABLE` (and `MODE_WORLD_WRITEABLE`) literally make the file readable (or writable) by every other app on the device — Android deprecated them and throws on modern API levels for exactly this reason. **External storage** (`getExternalStorageDirectory()`, `getExternalFilesDir()`, the SD card, the Downloads folder) is shared, world-readable space — fine for a photo the user wants to keep, **not** for a token or a `users.json`. On iOS, `FileProtectionType.none` means the file isn't tied to the device passcode, so it's readable even while the phone is locked and survives into unencrypted backups.

**HIGH** for PII; **CRITICAL** when it's a token, password, or payment data — that's account/wallet takeover from a backup or a sibling app. Fix: write sensitive data to **app-private internal storage** (`MODE_PRIVATE` / `filesDir` on Android, the app container with `.completeFileProtection` on iOS, `getApplicationDocumentsDirectory()` on Flutter), and put actual secrets in the Keychain/Keystore.

### Pattern 3 — Secrets / tokens written to device logs (🟡 MEDIUM, 🔴 CRITICAL if it's the credential itself in a release build)

A token, password, full auth response, or card number gets passed straight to a log call.

```kotlin
Log.d("Auth", "login ok, token=$jwt, pw=$password")          // ← Android logcat
Timber.i("response: %s", authResponse)                       // full body incl. token
```
```swift
print("token: \(accessToken)")                               // → device console
os_log("card %{public}@", log: .default, type: .info, pan)   // %{public}@ = not redacted
NSLog("auth: %@", responseBody)                              // tokens/PII in the log
```
```js
console.log('auth', { token, refreshToken, user });          // RN / Flutter debugPrint(...)
```

Device logs are **not private**. On Android, crash-reporting SDKs (Crashlytics/Sentry/Bugsnag) sweep logcat into breadcrumbs that land in a third-party dashboard, and anyone with `adb logcat` over USB reads them live. On iOS, `os_log` with `%{public}%` (or `print`/`NSLog`) writes into the unified log, captured by sysdiagnose and anything plugged in. A token in a log is a token leaked — and worse, copied into systems you never threat-modeled.

A common amplifier: an **HTTP logging interceptor at `BODY` level** (OkHttp `HttpLoggingInterceptor(Level.BODY)`, an Alamofire event monitor, Axios logging) that dumps every request/response — `Authorization` headers and all — wholesale.

**MEDIUM** in general; **🔴 CRITICAL** when the logged value is a live credential / full auth response / card number **and the log line ships in the release build** (i.e. it's *not* wrapped in `if (BuildConfig.DEBUG)` / `#if DEBUG` / `if (__DEV__)`). Fix: stop logging the value (log a status code or a masked `****1234` instead), and gate any debug logging so it never runs in release.

> Note: the main `mobile.md` check also has a logs pattern. If you already flagged a logged secret there, don't double-count it — fold it into one finding. This module's job is to go deeper on the *database* and *file* storage classes; treat the logs pattern here as the same finding viewed through the M9 lens.

## Safe patterns (this is what "done right" looks like — don't flag these)

**Encrypted database, key held in the Keychain/Keystore:**
```kotlin
// Android Room + SQLCipher; passphrase comes from the Keystore-backed store
val passphrase = SQLiteDatabase.getBytes(secureKey.toCharArray())
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(ctx, AppDb::class.java, "app.db")
    .openHelperFactory(factory).build()              // ← encrypted at rest
```
```dart
// Flutter Realm with an encryption key (key stored via flutter_secure_storage)
final key = await secureStorage.read(key: 'realmKey');   // from Keystore/Keychain
final config = Configuration.local([User.schema], encryptionKey: base64Decode(key!));
final realm = Realm(config);
```
```swift
// iOS — strong file protection on the store
let desc = container.persistentStoreDescriptions.first
desc?.setOption(FileProtectionType.complete as NSObject,
                forKey: NSPersistentStoreFileProtectionKey)
```

**Sensitive files stay app-private with protection:**
```kotlin
openFileOutput("session.json", Context.MODE_PRIVATE)     // sandboxed, not world-readable
```
```swift
try data.write(to: url, options: .completeFileProtection)  // tied to passcode
```

**Actual secrets go in the secure store, not a DB/file at all:** Keychain (iOS), Keystore / `EncryptedSharedPreferences` (Android), `flutter_secure_storage`, `expo-secure-store`, `react-native-keychain`. Seeing these is the *good* sign.

**Logs that are masked or debug-only:**
```kotlin
if (BuildConfig.DEBUG) Log.d("Auth", "login ok")          // no secret, debug-only
Log.i("Pay", "charged card ****${pan.takeLast(4)}")        // masked
```

## Report a finding as

**Title:** "Your app stores login tokens in a database with no encryption — a stolen phone or a backup hands them over"

(adapt per pattern: "Your app writes user data to shared storage any other app can read", "Your app saves the session token to the SD card", "Your app prints the user's auth token into the phone's log")

**Detail:**
> `android/app/src/main/java/com/app/data/AppDatabase.kt:18` builds a Room database (`app.db`) that stores the user's `authToken` and `ssn`, and there's no encryption on it — no SQLCipher `SupportFactory`, no passphrase. That database is just a plain SQLite file sitting in the app's sandbox.
>
> Here's the part that surprises people: **the file isn't protected just because it's "inside the app."** Pull it via an unencrypted backup, off a rooted/lost phone, or through a sibling app exploiting a sandbox bug, open it in the free `sqlite3` tool, and every row is right there in plain text — tokens, the SSN, everything.
>
> **What can go wrong:** someone who recovers a user's phone or its backup reads the saved token and logs in *as that user* — no password needed. With the SSN/PII in there too, that's now a privacy/GDPR incident with your name on it.
>
> **What to do tonight:**
> 1. **Encrypt the database** with SQLCipher and feed Room an encrypted helper factory:
>    ```kotlin
>    val passphrase: ByteArray = SQLiteDatabase.getBytes(key.toCharArray())
>    val factory = SupportFactory(passphrase)
>    val db = Room.databaseBuilder(ctx, AppDatabase::class.java, "app.db")
>        .openHelperFactory(factory)   // ← now encrypted at rest
>        .build()
>    ```
> 2. **Store the encryption key in the Android Keystore** (or `EncryptedSharedPreferences`) — never hardcode it and never keep it in the same DB.
> 3. **Better still for the token specifically:** don't put a long-lived auth token in a DB at all — keep it in the Keystore / `EncryptedSharedPreferences`, and store only non-sensitive app data in the database.
> 4. Verify: pull the DB off a debug device (`adb`), open it in `sqlite3`, and confirm the token/SSN columns are now ciphertext, not readable strings.
>
> Same fix shape for the other engines: **Realm** → pass an `encryptionKey` (key from the secure store); **iOS Core Data / files** → set `FileProtectionType.complete`; **expo-sqlite/react-native-sqlite** → use SQLCipher-backed builds.

Repeat the report block for each pattern you found, swapping in the right story:
- **Shared/external/world-readable file:** "Your app writes `[file]` to [external storage / a world-readable file], which means any other app on the phone — and any backup — can read it. Right now that file contains [token / PII]." Fix: write it to app-private storage (`MODE_PRIVATE` / `filesDir`, the app container with `.completeFileProtection`, `getApplicationDocumentsDirectory()`), and move real secrets to the Keychain/Keystore.
- **Secret in logs:** "Your app prints the user's [token / password / card] into the phone's log, where crash-reporting SDKs and any USB-connected machine can read it." Fix: stop logging the value (log a status code or a masked `****1234`), and wrap any debug logging in a `BuildConfig.DEBUG` / `#if DEBUG` / `__DEV__` guard so it never ships in release.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires easily. A lot of on-device storage is correct by design. Don't cry wolf on:

- **Non-sensitive data in a plain database.** A SQLite/Realm/Core Data store full of *cached content* — product catalogs, the offline copy of public articles, map tiles, an analytics queue, draft notes, app config, a "what's new" feed — does **not** need encryption. Encryption-at-rest is for **secrets, credentials, payment data, and regulated PII**, not for everything. Flag only when the table actually holds tokens/passwords/cards/PII.
- **Data that's already in the Keychain / Keystore / a secure-storage wrapper.** `flutter_secure_storage`, `expo-secure-store`, `react-native-keychain`, `EncryptedSharedPreferences`, `SecItemAdd`, Android Keystore APIs — these are the *correct* place for secrets. Their presence is the good sign, not a finding.
- **Databases that are already encrypted.** If you see SQLCipher / `SupportFactory` / a Realm `encryptionKey` / `PRAGMA key` / a `completeFileProtection` option on the store, it's handled. Don't flag an encrypted store.
- **Files the user deliberately exports to shared storage.** A "Save to Photos," "Export PDF to Downloads," "share this file" feature *should* write to shared/external storage — that's the whole point, and the content is something the user chose to export (a receipt PDF, a photo, a CSV they asked for). Flag external-storage writes only when the data is sensitive *and* the user didn't ask to export it (e.g. the app silently dumping `tokens.txt` or a session DB to the SD card).
- **`getExternalFilesDir()` / scoped storage for genuinely non-sensitive bulk data.** App-scoped external dirs are reasonable for large non-secret media/caches. The finding is sensitive data on a *world-readable* medium, not "uses external storage" by itself.
- **iOS default file protection.** iOS applies `completeUntilFirstUserAuthentication` to most files **by default** — that's already a sane baseline. The finding is when protection is *explicitly downgraded* to `FileProtectionType.none` / `NSFileProtectionNone`, not the absence of an explicit `.complete`.
- **Logs that are debug-only or masked.** Anything inside `if (BuildConfig.DEBUG)`, `#if DEBUG`, `if (__DEV__)`, stripped by ProGuard/R8 in release, or logging a masked/redacted value (`****1234`), an opaque request ID, or a status code — fine. Read the surrounding guard before flagging.
- **Test fixtures, sample data, seed scripts.** A DB seeded with fake users / placeholder tokens (`"test-token"`, `"user@example.com"`) in test or sample code is not a real leak.
- **Encryption "key" that's actually a per-user key derived/fetched at runtime.** If the encryption key comes from the Keychain/Keystore, a user passphrase, or a server round-trip — that's correct. The bug is a key **hardcoded in source** or **stored next to the data it "protects"** (which is just plaintext with extra steps — that one *is* a finding).

When in doubt, the deciding question is: **"if someone got this user's phone — or just an unencrypted backup of it — could they read a working token, a credential, or the user's personal/payment data straight off the disk?"** If yes → flag it (HIGH, or CRITICAL for credentials/payment data). If it's cached public content, an already-encrypted store, data sitting in the Keychain/Keystore, a file the user chose to export, a default-protected iOS file, or a debug-only/masked log → at most an ⚪ INFO heads-up.
