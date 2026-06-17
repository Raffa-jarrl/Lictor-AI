# Check — Mobile privacy controls (the app collects more than it admits)

**What you're looking for:** a mismatch between what a mobile app *says* it does with people's data and what the code *actually* does. Two ways that mismatch shows up, and they're both reportable on store-review day:

1. **The permission / usage-string mismatch.** The app pulls precise location, contacts, photos, the microphone, or a tracking ID — but the matching declaration is missing or wrong. On iOS that's a usage-description string in `Info.plist` (`NSLocationWhenInUseUsageDescription` and friends); on Android it's a `<uses-permission>` in `AndroidManifest.xml`. Either the app touches data it never asked permission for, or it asks for a scary permission it never actually uses.

2. **The privacy-manifest / data-safety mismatch.** The app collects a tracking identifier (Apple's IDFA, Android's Advertising ID / AAID), precise location, contacts, or photos, and/or it ships a known analytics/ad SDK — but there is **no iOS `PrivacyInfo.xcprivacy` privacy manifest** (or it doesn't set `NSPrivacyTracking` / list the collected data), and/or **no Android Data Safety declaration**. This is the OWASP Mobile Top 10 2024 **M6 — Inadequate Privacy Controls** category, and it's also a hard store-submission gate: Apple *rejects* apps that use certain APIs or SDKs without a privacy manifest, and Google rejects apps whose Data Safety form doesn't match the code.

The founder mental model that goes wrong here: *"I added the permission popup, so I'm covered."* The permission prompt is one of three separate things the stores now require — the runtime permission, the **per-platform privacy declaration**, and (for tracking IDs on iOS) an **App Tracking Transparency consent prompt**. AI app builders reliably generate the first and forget the other two.

This check is about **honest disclosure and consent**, not about secrets in the bundle — secrets, cleartext traffic, insecure storage, exported components, and PII-in-logs live in the separate `mobile.md` check. Here we only care: does the app collect/transmit personal or tracking data without a matching, truthful declaration and (for tracking) consent?

## How to scan

You're reading the repo, so you cross-reference three things: (a) what data-touching APIs the code calls, (b) what's declared in the manifests/plists, and (c) whether a privacy manifest / data-safety declaration exists at all. Works across native iOS (Swift/Obj-C), native Android (Kotlin/Java), Flutter (Dart), and React Native / Expo.

```bash
# ── A. What sensitive data / tracking IDs does the code actually touch? ──

# iOS — tracking ID (IDFA), precise location, contacts, photos, mic, health
grep -rEn --exclude-dir={Pods,build,.git,DerivedData} \
  --include='*.swift' --include='*.m' --include='*.h' \
  -E 'ASIdentifierManager|advertisingIdentifier|CLLocationManager|requestAlwaysAuthorization|kCLLocationAccuracyBest|CNContactStore|PHPhotoLibrary|AVCaptureDevice|HKHealthStore|ATTrackingManager' \
  . 2>/dev/null

# Android — Advertising ID (AAID), precise location, contacts, photos, mic
grep -rEn --exclude-dir={build,.git,.gradle} \
  --include='*.kt' --include='*.java' \
  -E 'AdvertisingIdClient|getAdvertisingIdInfo|FusedLocationProviderClient|ACCESS_FINE_LOCATION|ContactsContract|MediaStore\.(Images|Video)|getSystemService\(.*AUDIO|requestPermissions' \
  . 2>/dev/null

# Flutter / React Native — same data classes via popular plugins
grep -rEn --exclude-dir={node_modules,build,.git,.dart_tool} \
  --include='*.dart' --include='*.js' --include='*.ts' --include='*.tsx' \
  -E 'advertising_id|AdvertisingId|getAdvertisingId|getTrackingPermissionStatus|requestTrackingPermission|Geolocator\.|getCurrentPosition|enableHighAccuracy|FlutterContacts|expo-contacts|ImagePicker|Permissions\.(LOCATION|CONTACTS|CAMERA)' \
  . 2>/dev/null

# ── B. What analytics / ad / tracking SDKs are bundled? ──────────────────
# These are the SDKs that, by themselves, trigger Apple's privacy-manifest
# requirement and Google's Data Safety "data shared with third parties".
grep -rEn --exclude-dir={.git} \
  --include='Podfile' --include='*.gradle' --include='*.gradle.kts' \
  --include='package.json' --include='pubspec.yaml' \
  -E 'Firebase/Analytics|firebase-analytics|firebase_analytics|GoogleAppMeasurement|AppsFlyer|appsflyer|Adjust|com\.adjust|Amplitude|amplitude|Mixpanel|mixpanel|Segment|analytics-react-native|Branch|branch-sdk|facebook-android-sdk|FBSDK|react-native-fbsdk|Google-Mobile-Ads|play-services-ads|admob|Sentry|Bugsnag|Flurry|OneSignal|onesignal|Singular|Kochava|Braze|appboy' \
  . 2>/dev/null

# ── C. Does an iOS privacy manifest exist, and does it declare tracking? ──
find . -path '*/.git' -prune -o -name 'PrivacyInfo.xcprivacy' -print 2>/dev/null
# If found, check whether it actually declares tracking + collected types:
grep -rEn --include='PrivacyInfo.xcprivacy' \
  -E 'NSPrivacyTracking|NSPrivacyCollectedDataTypes|NSPrivacyTrackingDomains|NSPrivacyAccessedAPITypes' \
  . 2>/dev/null

# ── D. Does an Android data-collection / data-safety declaration exist? ───
# Data Safety lives in Play Console (not always in-repo), but teams that
# manage it as code keep a YAML/JSON or a documented mapping. Look for one:
grep -rlEn --exclude-dir={.git,node_modules,build} \
  -E 'data.?safety|dataCollection|collectedDataTypes|privacy.?manifest' \
  . 2>/dev/null | head -20
# And the AD_ID permission Google now requires apps using AAID to declare:
grep -rEn --include='AndroidManifest.xml' \
  -E 'com\.google\.android\.gms\.permission\.AD_ID' \
  . 2>/dev/null
```

Also open these directly and read them side by side:

- **`Info.plist`** (iOS) — every `NS*UsageDescription` key. This is the list of sensitive data the app *claims* it touches.
- **`PrivacyInfo.xcprivacy`** (iOS, app target + every bundled SDK) — the privacy manifest. Look for `NSPrivacyTracking` (a boolean — is tracking happening?), `NSPrivacyCollectedDataTypes` (the list of what's collected and why), and `NSPrivacyTrackingDomains`. **Its absence is the finding** when tracking IDs / sensitive data / tracking SDKs are present.
- **`AndroidManifest.xml`** — every `<uses-permission>`. This is what Android *claims* the app accesses. Cross-check against the data-touching APIs from scan A.
- **`Podfile` / `*.gradle` / `package.json` / `pubspec.yaml`** — the SDK inventory from scan B.

## The dangerous patterns

### Pattern 1 — Tracking ID collected with no privacy manifest + no consent gate (MEDIUM)

```swift
// iOS — grabs the IDFA and ships it to an ad SDK, no ATT prompt, no PrivacyInfo
let idfa = ASIdentifierManager.shared().advertisingIdentifier   // ← tracking identifier
Analytics.logEvent("open", parameters: ["idfa": idfa.uuidString])
```
```kotlin
// Android — pulls the Advertising ID and sends it to analytics
val adInfo = AdvertisingIdClient.getAdvertisingIdInfo(context)   // ← AAID
analytics.setUserProperty("aaid", adInfo.id)
```

Reading the IDFA / AAID and sending it to an analytics or ad SDK **is tracking** by both stores' definitions. That triggers three obligations the code is skipping:

- **iOS:** a `PrivacyInfo.xcprivacy` with `NSPrivacyTracking = true`, the data type listed under `NSPrivacyCollectedDataTypes` with `NSPrivacyCollectedDataTypeUsedForTracking = true`, the receiving domains under `NSPrivacyTrackingDomains` — **and** an App Tracking Transparency prompt (`ATTrackingManager.requestTrackingAuthorization`) before the IDFA is read. Reading the IDFA before ATT consent returns all-zeros anyway, and shipping without the manifest is an automatic App Store rejection.
- **Android:** the `com.google.android.gms.permission.AD_ID` permission declared, and a **Data Safety** entry saying a device/advertising identifier is collected and shared.

**MEDIUM.** Flag when a tracking ID is read *and* (no privacy manifest declares it, or no consent/ATT gate precedes the read).

### Pattern 2 — Sensitive data accessed with no matching usage description / permission (MEDIUM)

```swift
// iOS — uses precise location, but Info.plist has NO NSLocationWhenInUseUsageDescription
locationManager.requestWhenInUseAuthorization()   // ← app crashes / store-rejects without the string
locationManager.desiredAccuracy = kCLLocationAccuracyBest
```
```xml
<!-- AndroidManifest.xml declares the permission... -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<!-- ...but precise location is never used in code, OR it IS used and feeds an ad SDK
     while Data Safety says "no location collected" — both are mismatches -->
```

Two failure shapes, both reportable:

- **Touches data it never declared** — code calls `CLLocationManager` / `CNContactStore` / `PHPhotoLibrary` / `AVCaptureDevice`, or Android requests `ACCESS_FINE_LOCATION` / `READ_CONTACTS` at runtime, but the matching `NS*UsageDescription` string (iOS) is absent. iOS hard-crashes on first use without the string; the store rejects it. This is the app being *less* honest than required.
- **Declares more than it uses** — a scary permission (`ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `RECORD_AUDIO`) sits in the manifest but nothing in code uses it. Over-asking erodes trust and gets flagged in store review. Note as LOW (privacy-hygiene), not a breach.

The truly dangerous version is when the data **is** used and sent off-device to analytics/ads, but the privacy declaration claims it isn't collected. That's the disclosure lie store reviewers and regulators care about — **MEDIUM**.

### Pattern 3 — Analytics / ad SDK bundled, no privacy manifest / data-safety entry reflects it (MEDIUM)

```ruby
# iOS Podfile — these SDKs collect data and REQUIRE a privacy manifest entry
pod 'Firebase/Analytics'
pod 'AppsFlyerFramework'      # attribution → device + advertising identifiers
pod 'FBSDKCoreKit'            # Facebook SDK → advertising data
```
```gradle
// Android build.gradle — same: each collects/shares data
implementation 'com.google.firebase:firebase-analytics'
implementation 'com.appsflyer:af-android-sdk:6.+'
implementation 'com.google.android.gms:play-services-ads'
```
```json
// React Native package.json
"react-native-fbsdk-next": "*", "@amplitude/analytics-react-native": "*",
"react-native-appsflyer": "*"
```

Apple maintains a list of **"commonly used SDKs"** (Firebase, AppsFlyer, Adjust, Amplitude, Branch, the Facebook SDK, Google Mobile Ads, and more) that **must** ship a privacy manifest *and* a code signature. If the app target's `PrivacyInfo.xcprivacy` is missing — or it exists but doesn't aggregate what these SDKs collect — the upload is rejected. On Android, every one of these maps to a **Data Safety** "data shared with third parties" entry that must be filled in truthfully.

**MEDIUM** when a known data-collecting SDK is in the dependency manifest and no privacy manifest / data-safety declaration accounts for it. The fix is mechanical (ship the manifest), but the *missing* manifest is exactly the M6 gap.

### Pattern 4 — Privacy manifest exists but lies / is empty (MEDIUM)

```xml
<!-- PrivacyInfo.xcprivacy — present, but claims no tracking while the code reads IDFA -->
<key>NSPrivacyTracking</key>
<false/>                                  <!-- ← contradicts the ASIdentifierManager call -->
<key>NSPrivacyCollectedDataTypes</key>
<array/>                                  <!-- ← empty, but analytics ships location + email -->
```

A manifest that exists but says "we don't track / collect nothing" while the code clearly does is worse than a missing one — it's an affirmative false statement. Cross-check `NSPrivacyTracking` against any `ASIdentifierManager` call, and `NSPrivacyCollectedDataTypes` against the data the code actually reads and the SDKs it bundles. **MEDIUM.**

## Safe patterns (do NOT flag these)

**iOS — IDFA read only after ATT consent, with a manifest that declares it:**
```swift
ATTrackingManager.requestTrackingAuthorization { status in
  guard status == .authorized else { return }          // consent gate first
  let idfa = ASIdentifierManager.shared().advertisingIdentifier
  // ...and PrivacyInfo.xcprivacy declares NSPrivacyTracking=true + the data type
}
```
```xml
<!-- Info.plist — usage string present and specific for every data class touched -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>We use your location to show nearby stores.</string>
<key>NSUserTrackingUsageDescription</key>
<string>We use your data to measure ad performance.</string>
```
```xml
<!-- PrivacyInfo.xcprivacy — present AND matches reality -->
<key>NSPrivacyTracking</key><true/>
<key>NSPrivacyTrackingDomains</key><array><string>analytics.example.com</string></array>
<key>NSPrivacyCollectedDataTypes</key>
<array><dict>
  <key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataTypeDeviceID</string>
  <key>NSPrivacyCollectedDataTypeUsedForTracking</key><true/>
</dict></array>
```

**Android — permission declared, used for a real feature, AD_ID + Data Safety in place:**
```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>  <!-- used by the map screen -->
<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>   <!-- because analytics uses AAID -->
```
(and the Play Console Data Safety form lists location + advertising ID as collected/shared)

## Report a finding as

**Title:** "Your app collects a tracking ID but never tells Apple/Google — the store will reject it, and it's a privacy violation"

(adapt per pattern: "Your app uses location but is missing the required usage description", "You bundle [Firebase/AppsFlyer] but ship no privacy manifest", "Your privacy manifest says you don't track, but the code reads the advertising ID")

**Detail:**
> `ios/MyApp/Analytics.swift:31` reads the device's advertising identifier (`ASIdentifierManager.shared().advertisingIdentifier`) and sends it to your analytics SDK. There is no `PrivacyInfo.xcprivacy` privacy manifest in the project, and no App Tracking Transparency prompt before the read.
>
> Here's the part founders miss: the permission popup you may have added is **one of three separate things** the stores now require. Reading the advertising ID and sending it to analytics counts as *tracking*, and tracking has to be (1) consented to via the ATT prompt, (2) declared in a privacy manifest, and (3) listed on the store's data-safety/privacy page. Skipping the manifest is an automatic App Store rejection; skipping the consent prompt means the ID comes back all-zeros anyway *and* it's a privacy violation regulators (GDPR/CCPA) care about.
>
> **What can go wrong:** the build gets rejected at upload, or — worse if it slips through — you're shipping an app whose store privacy label is a false statement, which is the kind of thing that draws regulator attention and app-store takedowns.
>
> **What to do tonight:**
> 1. **Gate the tracking ID behind consent.** Read the IDFA only after the ATT prompt returns `.authorized`:
>    ```swift
>    import AppTrackingTransparency
>    ATTrackingManager.requestTrackingAuthorization { status in
>      guard status == .authorized else { return }   // no consent → don't read it
>      let idfa = ASIdentifierManager.shared().advertisingIdentifier
>      // ... existing analytics call
>    }
>    ```
>    Add the prompt's copy to `Info.plist` under `NSUserTrackingUsageDescription`.
> 2. **Ship a privacy manifest that matches reality.** Add `PrivacyInfo.xcprivacy` to the app target declaring `NSPrivacyTracking = true`, the receiving domains under `NSPrivacyTrackingDomains`, and the device-ID data type under `NSPrivacyCollectedDataTypes` with `UsedForTracking = true`.
> 3. **On Android, declare it too.** Add `<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>` and fill in the Play Console **Data Safety** form to say the advertising/device ID is collected and shared.
> 4. **Make the declaration match the code, not the other way around** — if you don't actually need tracking, the cleaner fix is to stop reading the advertising ID entirely (use a first-party random install ID instead), set `NSPrivacyTracking = false`, and you're done.

Repeat the report block for each pattern you found, swapping in the right story:
- **Missing usage description:** "Your code uses [location/contacts/photos/mic] but `Info.plist` has no matching `NS*UsageDescription`. The app crashes the first time it asks, and the store rejects it." Fix: add the specific usage-description string for each data class the code touches.
- **Over-declared permission:** "Your manifest asks for `ACCESS_FINE_LOCATION` / `READ_CONTACTS` but nothing in the code uses it. It scares users and gets flagged in review." Fix: remove the unused permission (LOW — privacy hygiene).
- **SDK with no manifest:** "You bundle [Firebase Analytics / AppsFlyer / the Facebook SDK], which collects data, but there's no privacy manifest / Data Safety entry covering what it collects." Fix: ship `PrivacyInfo.xcprivacy` and complete the Data Safety form to match the SDK's collection.
- **Manifest that lies:** "Your `PrivacyInfo.xcprivacy` says you don't track, but the code reads the advertising ID. A false privacy label is worse than a missing one." Fix: make the manifest honest, or stop the tracking.

## What NOT to flag (false-positive guards — read this before reporting)

This check fires easily because almost every app touches *some* user data. Don't cry wolf on:

- **A complete, matching privacy declaration.** If `PrivacyInfo.xcprivacy` exists and its `NSPrivacyTracking` / `NSPrivacyCollectedDataTypes` honestly reflect the code and bundled SDKs — and/or the Android Data Safety mapping is present and matches — there is **no finding**. The whole check is about the *mismatch*; a truthful, complete declaration is the goal state.
- **A permission that's clearly tied to a declared feature.** `ACCESS_FINE_LOCATION` in a maps/delivery/ride app, `RECORD_AUDIO` in a voice-memo app, `CAMERA` in a scanner, `READ_CONTACTS` in a contacts-sync feature — with a matching usage string and a real on-device use — is correct. Permission + matching usage string + obvious feature = not a finding.
- **First-party / random install identifiers.** A self-generated UUID (`UIDevice.identifierForVendor`, a random install ID stored in your own backend) is **not** the IDFA/AAID and is **not** cross-app tracking. Don't flag `identifierForVendor` or app-scoped IDs as tracking.
- **Data that never leaves the device.** Location used purely to center a map locally, photos picked and processed on-device and never uploaded, contacts read to populate a local picker — if it isn't transmitted to analytics/ads or a third party, the tracking/data-safety obligations are far lighter. Look at whether the data is *sent off-device* before escalating.
- **Vendored SDK privacy manifests that already exist.** Many SDKs now ship their *own* `PrivacyInfo.xcprivacy` inside their bundle (that's Apple's requirement working as intended). Seeing one inside `Pods/SomeSDK/` is the *good* sign — it doesn't replace the app target's manifest, but it's not a finding against the SDK.
- **Apps with App Tracking Transparency / consent SDKs already wired in.** `ATTrackingManager.requestTrackingAuthorization`, a CMP/consent SDK (Google UMP, OneTrust, Usercentrics), or a "deny tracking" toggle gating the ID read — that's the consent gate working. Don't flag a tracking ID that's already behind a consent check.
- **Permissions/SDKs only in a debug/staging flavor.** A logging or analytics SDK pulled in only under a `debug`/`staging` build flavor or `#if DEBUG`, not in the release artifact, doesn't ship to users. Check the build configuration before flagging.
- **Example / placeholder usage strings in a template.** A scaffold's stock `NSLocationWhenInUseUsageDescription` of `"$(PRODUCT_NAME) needs location"` in a starter the team hasn't shipped is a TODO, not a privacy violation — note it, don't escalate.
- **Server-side analytics with no device identifier.** If the app sends events to *your own* backend keyed by your authenticated user ID (no IDFA/AAID, no third-party ad SDK), that's first-party analytics, not cross-app tracking. Far lighter obligations; don't treat it like an ad SDK.

When in doubt, the deciding question is: **"does the app read a cross-app tracking ID (IDFA/AAID), precise location, contacts, photos, or the mic — and send it off-device or to an ad/analytics SDK — without a privacy manifest / Data Safety entry that honestly says so, and (for tracking IDs) without a consent prompt?"** If yes → flag it MEDIUM. If the declaration is complete and matches, the data stays on-device, or the identifier is first-party → at most an INFO heads-up.
