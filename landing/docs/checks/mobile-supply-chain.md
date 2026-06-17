# Check — Mobile dependency hygiene (supply chain)

**What you're looking for:** the mobile equivalent of leaving the side gate open. Your app is mostly other people's code — pods, Swift packages, Gradle libraries, Flutter packages — and how *loosely* you pin those, plus *which* ones you trust, decides whether a bad release or a malicious SDK update can walk straight into the build you ship to the store. This check reads the mobile manifests and lockfiles for two problems: **(1) versions that float** — a dependency declared as "whatever's newest" instead of one exact version with a committed lockfile, and **(2) known-risky, abandoned, or unofficial third-party SDKs** — the ad/analytics/tracking libraries with a documented history of malware, data exfiltration, or quiet abandonment.

Why mobile deserves its own check (the general `dependencies` check already covers npm/pip/Go/etc.): mobile manifests have their own pinning footguns that the generic tooling and the existing mobile-leaks check both skip. Gradle has a `1.2.+` dynamic-version syntax that silently grabs new code on every build. CocoaPods lets you write `pod 'Thing'` with *no version at all*. SwiftPM and Flutter both let you point a dependency at a moving git branch instead of a frozen tag. And the SDK you embed for ads or analytics runs *inside your signed app* with your users' data — if it goes rogue in an update, you ship the rogue version. Once an `.ipa` / `.apk` / `.aab` is on the store, **what's baked in is baked in** — there's no server-side patch.

This applies whether the app was hand-built in Xcode / Android Studio or vibe-coded in Flutter, React Native, Expo, Capacitor, or a "make me an app" AI tool. The AI adds whatever dependency made the demo compile; it does not pin it or vet who maintains it.

**Severity: 🟠 HIGH** when a production dependency floats with no committed lockfile, or a known-risky/abandoned SDK is bundled. (OWASP Mobile Top 10 2024 — **M2: Inadequate Supply Chain Security**.)

## How to scan

You're reading the repo, not the store binary. Cast a wide net across the four mobile manifest families, then check whether each has a **committed** lockfile.

```bash
# ── 0. Which mobile manifests + lockfiles exist, and are the locks committed? ──
ls -la \
  Podfile Podfile.lock \
  Package.swift Package.resolved \
  build.gradle build.gradle.kts settings.gradle settings.gradle.kts \
  gradle/libs.versions.toml \
  pubspec.yaml pubspec.lock \
  ios/Podfile ios/Podfile.lock \
  android/build.gradle android/build.gradle.kts \
  2>/dev/null

# Is each lockfile actually TRACKED by git? (an untracked/.gitignored lock = not pinned for the team/CI)
git ls-files Podfile.lock Package.resolved pubspec.lock '**/Podfile.lock' '**/Package.resolved' '**/pubspec.lock' 2>/dev/null
# ...and double-check it isn't ignored:
grep -rEn 'Podfile\.lock|Package\.resolved|pubspec\.lock' .gitignore */.gitignore 2>/dev/null

# ── 1. CocoaPods — pods declared with NO version (floats to latest) ──
# A pod line with no comma+version after the name = unpinned.
grep -nE "^\s*pod\s+'[^']+'\s*$" Podfile ios/Podfile 2>/dev/null            # bare pod, no version at all
grep -nE "^\s*pod\s+'[^']+'\s*,\s*(:git|:branch|:commit|:path|:podspec)" Podfile ios/Podfile 2>/dev/null  # git/branch/path pin
grep -nE "^\s*pod\s+'[^']+'\s*,\s*'~>" Podfile ios/Podfile 2>/dev/null       # optimistic operator (fine WITH a committed lock)

# ── 2. Swift Package Manager — branch/revision instead of a release tag ──
grep -nE 'branch:|revision:|\.branch\(|\.revision\(|upToNextMajor|upToNextMinor|"main"|"master"|"develop"' \
  Package.swift 2>/dev/null
# In Package.resolved, a pin with "branch" set (instead of "version") is a moving target:
grep -nE '"branch"\s*:\s*"[^"]|"revision"\s*:\s*null' Package.resolved 2>/dev/null

# ── 3. Gradle — dynamic '+' versions (the classic mobile floating-version bug) ──
grep -rnE "(implementation|api|compileOnly|runtimeOnly|kapt|ksp|classpath)[^\n]*['\"][^'\"]*(\+|\.\+|latest\.release|latest\.integration|\[)['\"]" \
  --include='build.gradle' --include='build.gradle.kts' . 2>/dev/null
# Dynamic versions in the version catalog too:
grep -nE '=\s*"[^"]*(\+|latest\.release)"' gradle/libs.versions.toml 2>/dev/null
# Does this project even enforce verification metadata? (good if present, just note absence as INFO)
ls gradle/verification-metadata.xml 2>/dev/null

# ── 4. Flutter / Dart (pubspec) — any version (^/blank/git/path) + lock committed? ──
grep -nE "^\s+[a-z0-9_]+:\s*(any|\^?\d|>=|<=)?\s*$" pubspec.yaml 2>/dev/null  # blank or 'any' version
grep -nE "git:|ref:|path:|hosted:" pubspec.yaml 2>/dev/null                    # non-pub.dev / moving sources

# ── 5. Known-risky / abandoned / unofficial SDKs bundled anywhere ──
# Ad / analytics / tracking SDKs with a documented malware or exfiltration history,
# plus telltale "unofficial mirror" patterns. (See the list below — tune to the repo.)
grep -rEni --exclude-dir={node_modules,Pods,build,.git,DerivedData,.dart_tool} \
  'mintegral|mobvista|igexin|getui|moplus|baidu[._]?(mtj|location|map)|youmi|kuguo|adincube|startapp|appodeal|tnkfactory|sdk\.shareit|kochava|teemo|fidzup|sharkbot' \
  Podfile Podfile.lock Package.swift Package.resolved \
  build.gradle build.gradle.kts gradle/libs.versions.toml \
  pubspec.yaml pubspec.lock AndroidManifest.xml \
  --include='build.gradle' --include='build.gradle.kts' --include='*.toml' \
  --include='*.yaml' --include='*.lock' . 2>/dev/null
```

Then open the manifests directly and read them — the regexes above are a net, not a verdict. For each declared dependency ask: **is it pinned to one exact version (or one commit), and is the lockfile committed?** And: **do I recognize this SDK, and is it from its official publisher?**

## The patterns, and what each one means

### Pattern 1 — Floating / unpinned versions (🟠 HIGH without a committed lock, 🔵 INFO with one)

The whole point of pinning is reproducibility: the build you tested is the build you ship, and a compromised upstream release can't sneak in without someone choosing it. These all defeat that:

```ruby
# Podfile — CocoaPods
pod 'Alamofire'            # ← NO version. Resolves to "latest" on a fresh `pod install`.
pod 'SomeSDK', :git => 'https://github.com/vendor/SomeSDK.git', :branch => 'main'  # ← moving branch
```
```swift
// Package.swift — SwiftPM pointed at a branch, not a release
.package(url: "https://github.com/vendor/Lib.git", branch: "main"),     // ← moves every push
.package(url: "https://github.com/vendor/Lib.git", .upToNextMajor(from: "3.0.0")),  // range (fine WITH a committed Package.resolved)
```
```gradle
// build.gradle(.kts) — the classic Android floating-version footgun
implementation 'com.squareup.okhttp3:okhttp:4.+'        // ← any 4.x, picked at build time
implementation 'com.example:analytics:latest.release'   // ← literally "newest, whatever it is"
implementation "androidx.core:core-ktx:1.12.+"          // ← any 1.12.x patch, silently
```
```toml
# gradle/libs.versions.toml — dynamic version in the catalog
okhttp = "4.+"
```
```yaml
# pubspec.yaml — Flutter/Dart
dependencies:
  http: any            # ← any published version
  sdk_thing:           # ← blank version = any
  vendor_lib:
    git:               # ← moving git source, no committed ref
      url: https://github.com/vendor/vendor_lib.git
```

**Why it bites in mobile specifically:** a `+` Gradle version or a `branch:` git source means the next clean build — yours, a teammate's, or CI's right before a store release — can pull code you never reviewed. That's exactly the channel a hijacked upstream release rides in on. And because you then sign and ship a binary, the bad version is now in every user's pocket with no way to hot-patch it.

**The deciding factor is the lockfile.** A range/optimistic operator (`~> 5.0`, `^1.2.3`, `.upToNextMajor`) is *fine* when there's a **committed** lockfile (`Podfile.lock`, `Package.resolved`, `pubspec.lock`) freezing the exact resolved version for everyone. It's a problem when the lock is missing, untracked, or `.gitignore`d — then every machine resolves the range independently. A literal `+`/`latest.release`/moving-branch is a problem **even with** a lock, because it advertises intent to drift.

**Severity:** 🟠 HIGH for a dynamic `+`/`latest.release`/moving-branch dependency, or any unpinned range **with no committed lockfile**, on a production dependency. 🔵 INFO when ranges exist but the lockfile is committed (note it as "fine, the lock is doing its job").

### Pattern 2 — Missing / uncommitted lockfile (🟠 HIGH)

```bash
# Podfile exists but Podfile.lock is absent or .gitignore'd
$ ls Podfile.lock        # No such file
$ grep Podfile.lock .gitignore   # → Podfile.lock     (it's being ignored!)
```

No committed lockfile means "every `pod install` / `swift package resolve` / `flutter pub get` decides versions fresh." Your CI box, your co-founder's laptop, and the machine that cut the release build can each resolve to *different* code — and a tampered upstream release lands in whichever one resolves after it's published, with nobody choosing it. The lockfile is the thing that turns "ranges are convenient" into "ranges are safe."

A frequent AI/starter-template mistake: `Podfile.lock` or `pubspec.lock` listed in `.gitignore` (some old templates did this for libraries, which is wrong for an *app*). For an application, **all three lockfiles must be committed.**

**Severity:** 🟠 HIGH (it's the mechanism that turns any future bad release into your incident, and it makes Pattern 1's ranges genuinely dangerous).

### Pattern 3 — Git-ref / branch dependency instead of a tag or commit (🟠 HIGH)

```ruby
pod 'PaymentKit', :git => 'https://github.com/vendor/PaymentKit.git'                    # ← no ref at all = default branch
pod 'PaymentKit', :git => 'https://github.com/vendor/PaymentKit.git', :branch => 'dev'  # ← tracks a branch
```
```swift
.package(url: "https://github.com/vendor/Auth.git", branch: "main")   // ← not .exact("1.4.2")
```
```yaml
vendor_lib:
  git:
    url: https://github.com/vendor/vendor_lib.git
    ref: main        # ← a branch name, not a tag/commit SHA
```

Pulling a dependency straight from a git **branch** (or no ref, which means the default branch) means you get whatever was last pushed there — including a force-push that rewrites history, a compromised maintainer account's commit, or an unreviewed change. There's no integrity anchor. If the dependency *must* come from git (not yet on the registry), pin it to an immutable **tag** or, better, a full **commit SHA** so the bytes can't change under you.

**Severity:** 🟠 HIGH for a branch/no-ref git dependency in the production app. 🔵 LOW/INFO if it's pinned to an exact commit SHA or an immutable tag *and* the lockfile records that exact revision.

### Pattern 4 — Known-risky / abandoned / unofficial SDK bundled (🟠 HIGH → 🔴 CRITICAL)

Some third-party SDKs — overwhelmingly **ad networks, analytics, and "tracking/attribution" libraries** — have a documented history of shipping malware, silently exfiltrating contacts/SMS/location, or running click-fraud from inside the host app. When you embed one, it runs with *your* app's permissions and sees *your* users' data, and an over-the-air SDK update can turn a clean version malicious. Watch for:

- **SDKs with a documented bad history** — e.g. ad/analytics libraries that have been caught exfiltrating data or running fraud in published research and store takedowns. The grep list above seeds some recurring names; treat any *ad/analytics/attribution/"free monetization"* SDK you don't recognize as guilty-until-vetted.
- **Abandoned SDKs** — last release years ago, archived repo, dead publisher, open unanswered security issues. An unmaintained SDK never gets a fix when a vuln drops, and an abandoned package name is a prime target for a hijack/takeover.
- **Unofficial mirrors / forks** — a pod or package that *looks* like a popular SDK but is published by a random account instead of the real vendor (the mobile cousin of a typosquat / dependency-confusion). E.g. a `pod 'FirebaseUnofficial'` or a Gradle coordinate under a personal `com.github.<randomuser>` group where the real one is `com.google.firebase`.

```gradle
// Android — an ad SDK with a documented exfiltration history, bundled deep in the app
implementation 'com.mintegral.msdk:videojs:+'          // floating AND historically risky
implementation 'com.github.someuser:firebase-fork:1.0' // ← unofficial fork of an official SDK
```
```ruby
pod 'StartApp'                 # ad SDK; vet the publisher + check it's the official spec
pod 'IGExin'                   # historically-flagged push/analytics SDK
```

**What can go wrong:** these SDKs have, in real incidents, harvested users' contacts, location, installed-app lists, and clipboard, and committed ad fraud — all attributed to *your* app, which is what gets pulled from the store and what regulators come asking about. Because the SDK auto-updates server-side in some cases, a clean version today can ship a payload tomorrow.

**Severity:** 🟠 HIGH for an abandoned or unofficial/unvetted SDK; 🔴 CRITICAL for an SDK with a concrete documented malware/exfiltration history that's still bundled. Always pair "drop it" with "pin whatever you keep" (Pattern 1).

## Safe patterns

**Exact pins + committed lockfile (the goal everywhere):**
```ruby
# Podfile — exact version, and Podfile.lock IS committed
pod 'Alamofire', '5.9.1'
```
```swift
// Package.swift — exact, and Package.resolved committed
.package(url: "https://github.com/Alamofire/Alamofire.git", exact: "5.9.1"),
// (a range like .upToNextMajor(from: "5.9.0") is also fine WITH a committed Package.resolved)
```
```gradle
// build.gradle.kts — exact versions, centralized in the version catalog
implementation(libs.okhttp)            // libs.versions.toml: okhttp = "4.12.0"
```
```yaml
# pubspec.yaml — caret range is fine because pubspec.lock is committed
dependencies:
  http: ^1.2.0
```

**Git dependency pinned to an immutable revision (when a git source is unavoidable):**
```yaml
vendor_lib:
  git:
    url: https://github.com/vendor/vendor_lib.git
    ref: a1b2c3d4e5f6...   # ← a full commit SHA (or an immutable tag), not a branch
```

**SDKs only from their official publisher, vetted, and kept current** — and no ad/tracking SDK you can't name the vendor of.

## Report a finding as

**Title (Pattern 1/3 example):** "Your app pulls in code that can change under you — three dependencies aren't pinned"

**Detail:**
> Your `android/build.gradle:42` declares `implementation 'com.squareup.okhttp3:okhttp:4.+'`, your `Podfile:18` has `pod 'Alamofire'` with no version, and your `pubspec.yaml:21` points `vendor_lib` at the `main` git branch. None of these is locked to one exact version, and I don't see a committed `Podfile.lock`.
>
> **What can go wrong:** "`4.+`", a versionless pod, and a `main` branch all mean "whatever's newest when this builds." The next clean build — yours, a teammate's, or the machine that cuts your App Store / Play Store release — can pull code none of you reviewed. That's the exact path a hijacked upstream release takes into an app: nobody chose the bad version, the build just resolved to it. And once you sign and ship the binary, that code is in every user's pocket with no way to hot-patch it.
>
> **What to do tonight:**
> 1. Pin every dependency to one exact version (or, for a git source, one commit SHA / immutable tag):
>    ```gradle
>    implementation 'com.squareup.okhttp3:okhttp:4.12.0'   // ← exact, no '+'
>    ```
>    ```ruby
>    pod 'Alamofire', '5.9.1'
>    ```
>    ```yaml
>    vendor_lib:
>      git:
>        url: https://github.com/vendor/vendor_lib.git
>        ref: a1b2c3d4e5f6...   # ← commit SHA, not "main"
>    ```
> 2. Generate and **commit the lockfiles** so every machine and CI installs identical code:
>    ```bash
>    pod install        # → commit Podfile.lock
>    flutter pub get    # → commit pubspec.lock
>    swift package resolve  # → commit Package.resolved
>    git add Podfile.lock pubspec.lock Package.resolved && git commit -m "Pin mobile deps + commit lockfiles"
>    ```
> 3. Make sure none of the lockfiles are in `.gitignore` — for an *app*, all three belong in git.
> 4. Going forward, bump versions deliberately (read the release notes), not automatically.

---

**Title (Pattern 4 example):** "You're shipping an ad SDK with a history of stealing user data"

**Detail:**
> Your `android/build.gradle:55` bundles `com.mintegral.msdk:videojs` — an ad/monetization SDK that's been caught in published research and store takedowns exfiltrating user data and committing ad fraud from inside its host apps. It's also pinned to `+`, so it auto-updates to whatever the vendor pushes. It runs inside your signed app, with your app's permissions, against your users' data.
>
> **What can go wrong:** This class of SDK has, in real incidents, harvested users' contacts, location, installed-app lists, and clipboard, and run click-fraud — all attributed to *your* app. That's what gets your app pulled from the store and what a regulator (or Apple/Google review) asks you about. Because the floating `+` lets it update server-side, a clean build today can ship a payload tomorrow.
>
> **What to do tonight:**
> 1. Remove the SDK unless it's genuinely load-bearing:
>    ```gradle
>    // delete: implementation 'com.mintegral.msdk:videojs:+'
>    ```
> 2. If you need that capability, replace it with a reputable, well-maintained SDK from a named vendor, and **pin it to an exact version** with the lockfile committed.
> 3. Audit what permissions/data the removed SDK had access to; if it shipped in a released build, treat any data it could reach (contacts, location, device IDs) as potentially exposed and note it in your records.
> 4. Re-scan: confirm no other ad/analytics/tracking SDK you can't name the vendor of is bundled.

Repeat the report block for each manifest/SDK you flag.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires easily on perfectly healthy projects. Don't cry wolf on:

- **Fully pinned deps with a committed lockfile — this is the goal, not a finding.** If versions are exact (or sensible ranges) **and** `Podfile.lock` / `Package.resolved` / `pubspec.lock` is committed and tracked, the supply chain is pinned correctly. Do not report it. The committed lockfile is the whole defense — its presence means ranges in the manifest are fine.
- **Caret/tilde/optimistic ranges (`^1.2.0`, `~> 5.9`, `.upToNextMajor`) when the lockfile is committed.** Ranges in the *manifest* are normal and expected; the lockfile is what actually pins the install. Only flag a range when there's **no committed lockfile** to freeze it. (A literal `+` / `latest.release` / moving git branch is the exception — flag those even with a lock, because they declare intent to drift.)
- **A git dependency pinned to an exact commit SHA or an immutable tag**, with the lockfile recording that revision. That's a legitimate, reproducible way to use a not-yet-published package. Only the *branch / no-ref* form is the problem.
- **Reputable, well-maintained SDKs from named vendors.** Firebase (`com.google.firebase`, the official pod/SPM), AdMob, Stripe, Sentry, Amplitude, Mixpanel, Branch, AppsFlyer, Adjust, Facebook SDK, OneSignal, Datadog, etc. — these are mainstream and actively maintained. Embedding analytics/attribution is a normal product decision; only flag a *tracking* SDK when it's one with a documented bad history, is abandoned, or is from an unofficial publisher. Don't flag a vendor purely for being an ad/analytics SDK.
- **Lockfile present but the install/resolve tool isn't available on this machine.** If you can read the manifest + committed lock but can't actually run `pod install` / `flutter pub get`, say so plainly rather than implying you verified resolution. Reading a committed lock is enough to confirm pinning.
- **Pre-release / beta versions chosen on purpose** (`6.0.0-beta.3`, a specific reviewed commit) when they're pinned exactly and locked. Being on a deliberate pin is fine; that's not floating.
- **`Podfile.lock` / `pubspec.lock` correctly *un*committed in a reusable LIBRARY/package repo (not an app).** Libraries intentionally don't commit a lock so consumers resolve their own. Only an **application** must commit all lockfiles. Check what kind of repo this is before flagging a missing lock.
- **The version catalog (`gradle/libs.versions.toml`) and `verification-metadata.xml`.** Seeing these is the *good* sign — centralized, pinned versions and dependency verification. Don't flag their presence; flag only a `+`/`latest.release` *inside* the catalog.
- **Transitive/native sub-dependencies you don't control directly.** React Native and Flutter pull native pods/gradle deps transitively; a `+` you can't see in your own manifest, coming from a dependency's own podspec, isn't something you set. Note it as INFO and aim the fix at the top-level package, not the transitive line.

When in doubt, the deciding question is: **"if this dependency's upstream pushed a malicious release tomorrow, could it land in my next store build without anyone choosing it — and do I actually trust who maintains this SDK?"** If a float/missing-lock means yes → flag it. If everything's pinned-and-locked from vendors you can name → at most an INFO heads-up.
