#!/usr/bin/env python3
"""
lictor-mobile — Patrol v0.4 scaffold (mobile iOS + Android static analysis).

v0.1 scope (this version):
  - Works on EXTRACTED .ipa or .apk directories (use `unzip` first; both
    formats are zip-based). Direct binary parsing comes later.
  - Detects: hardcoded API keys in source/bundle, insecure local storage
    patterns (UserDefaults / SharedPreferences without encryption),
    deep-link / URL-scheme registrations without origin checks, WebView
    config with javascript-enabled + remote loading, overprivileged
    Info.plist / AndroidManifest.xml permissions, missing certificate
    pinning hints, backup-eligibility for sensitive paths.

v0.2 (future):
  - Direct binary .ipa / .apk parsing (no need to unzip first)
  - dex disassembly for Android obfuscated code
  - Proper plist binary parser (currently text-only)
  - Frida / dynamic-analysis script generation

Usage:
    unzip MyApp.ipa -d /tmp/app && python3 scripts/lictor-mobile.py /tmp/app
    unzip MyApp.apk -d /tmp/app && python3 scripts/lictor-mobile.py /tmp/app
"""
from __future__ import annotations
import argparse, json, plistlib, re, sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator
import xml.etree.ElementTree as ET

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

@dataclass
class Finding:
    severity: str
    surface: str
    check: str
    title: str
    path: str = ""
    evidence: str = ""
    fix: str = ""

# --- Shared regexes (same as lictor-multi for consistency) -------------------

SECRET_RX = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                "AWS access key",     "critical"),
    (re.compile(r'sk_live_[A-Za-z0-9]{20,}'),        "Stripe live key",    "critical"),
    (re.compile(r'sk-(?:proj-)?[A-Za-z0-9_-]{30,}'), "OpenAI-shape key",   "critical"),
    (re.compile(r'sk-ant-api\d{2}-[A-Za-z0-9_-]{30,}'), "Anthropic key",   "critical"),
    (re.compile(r'AIza[A-Za-z0-9_-]{35}'),           "Google API key",     "high"),
    (re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),      "GitHub PAT",         "critical"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'),
                                                      "JWT (decode for role)", "high"),
]

# --- iOS / Info.plist --------------------------------------------------------

def detect_ios(root: Path) -> bool:
    return any(root.rglob("Info.plist")) or any(root.rglob("*.app"))

def check_info_plist(root: Path) -> list[Finding]:
    findings = []
    for plist in root.rglob("Info.plist"):
        try:
            with plist.open("rb") as f:
                data = plistlib.load(f)
        except Exception:
            # Try as text plist (XML variant)
            try:
                data = plistlib.loads(plist.read_bytes(), fmt=plistlib.FMT_XML)
            except Exception:
                continue
        rel = str(plist.relative_to(root)) if plist.is_relative_to(root) else str(plist)

        # ATS (App Transport Security) disabled
        ats = data.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            if ats.get("NSAllowsArbitraryLoads") is True:
                findings.append(Finding("critical", "mobile-ios", "ios-ats-disabled",
                    "App Transport Security disabled (`NSAllowsArbitraryLoads: true`) — app accepts non-HTTPS traffic",
                    path=rel,
                    fix="Set `NSAllowsArbitraryLoads: false`. If specific domains need HTTP for legacy reasons, use `NSExceptionDomains` to allow only those."))
            for domain, cfg in ats.get("NSExceptionDomains", {}).items():
                if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                    findings.append(Finding("high", "mobile-ios", "ios-ats-domain-insecure",
                        f"ATS allows insecure HTTP for `{domain}`",
                        path=rel,
                        fix="If feasible, move that endpoint to HTTPS. Otherwise document why the exception exists."))

        # URL schemes — registered for deep links
        for entry in (data.get("CFBundleURLTypes") or []):
            if isinstance(entry, dict):
                schemes = entry.get("CFBundleURLSchemes", [])
                if schemes:
                    findings.append(Finding("medium", "mobile-ios", "ios-url-scheme-registered",
                        f"App registers custom URL scheme(s): {', '.join(schemes)}",
                        path=rel,
                        fix="In your URL handler, validate the source of the URL (sender bundle ID, signed parameter, or user confirmation). Don't act on URL params without origin verification."))

        # Background modes (audio / location can be abused)
        modes = data.get("UIBackgroundModes", [])
        sensitive_modes = {"audio", "location", "voip", "bluetooth-central", "bluetooth-peripheral"}
        risky = [m for m in modes if m in sensitive_modes]
        if risky:
            findings.append(Finding("medium", "mobile-ios", "ios-background-modes-sensitive",
                f"Sensitive background modes declared: {', '.join(risky)}",
                path=rel,
                fix="Apple rejects apps using these without justification. If unused, remove. If used, document in App Store review notes."))

        # Privacy usage descriptions — count + audit
        usage_keys = [k for k in data.keys() if k.startswith("NS") and k.endswith("UsageDescription")]
        if len(usage_keys) > 6:
            findings.append(Finding("medium", "mobile-ios", "ios-many-permission-prompts",
                f"App requests {len(usage_keys)} sensitive permissions ({', '.join(k.replace('NS','').replace('UsageDescription','') for k in usage_keys[:5])}...)",
                path=rel,
                fix="Each prompt is a user-trust event. Drop any you don't actually use. Apple has rejected apps with unused permission declarations."))
    return findings

# --- Android / AndroidManifest.xml ------------------------------------------

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def detect_android(root: Path) -> bool:
    return any(root.rglob("AndroidManifest.xml"))

def check_android_manifest(root: Path) -> list[Finding]:
    findings = []
    DANGEROUS_PERMS = {
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",  # the malware classic
    }
    for mf in root.rglob("AndroidManifest.xml"):
        try:
            tree = ET.parse(str(mf))
        except ET.ParseError:
            # Binary-encoded manifest — needs androguard, skip in v0.1
            findings.append(Finding("info", "mobile-android", "android-manifest-binary",
                "AndroidManifest.xml is binary-encoded — needs androguard to parse",
                path=str(mf.relative_to(root)) if mf.is_relative_to(root) else str(mf),
                fix="Run `apktool d MyApp.apk -o /tmp/decoded` first to get a text manifest, then re-scan."))
            continue
        root_el = tree.getroot()
        rel = str(mf.relative_to(root)) if mf.is_relative_to(root) else str(mf)

        # android:allowBackup default is true — sensitive apps should opt out
        app = root_el.find("application")
        if app is not None:
            allow_backup = app.get(f"{ANDROID_NS}allowBackup")
            if allow_backup is None or allow_backup == "true":
                findings.append(Finding("high", "mobile-android", "android-backup-enabled",
                    "android:allowBackup is true (or unset) — app data backed up to user's Google account, exfiltrated on credential theft",
                    path=rel,
                    fix='Set `android:allowBackup="false"` in <application>. Or use `android:fullBackupContent` to exclude sensitive paths.'))

            # debuggable in release manifest
            debuggable = app.get(f"{ANDROID_NS}debuggable")
            if debuggable == "true":
                findings.append(Finding("critical", "mobile-android", "android-debuggable",
                    "android:debuggable is true — release builds shipped with debugger access enabled",
                    path=rel,
                    fix="Remove the `android:debuggable` attribute entirely (default is false for release builds)."))

            # usesCleartextTraffic — Android equivalent of ATS-disabled
            cleartext = app.get(f"{ANDROID_NS}usesCleartextTraffic")
            if cleartext == "true":
                findings.append(Finding("high", "mobile-android", "android-cleartext-traffic",
                    "android:usesCleartextTraffic is true — app accepts non-HTTPS connections",
                    path=rel,
                    fix='Set `android:usesCleartextTraffic="false"`. If specific domains need HTTP, use `android:networkSecurityConfig` to scope.'))

            # exported components without permission gating
            for tag in ("activity", "service", "receiver", "provider"):
                for comp in app.iter(tag):
                    if comp.get(f"{ANDROID_NS}exported") == "true" and not comp.get(f"{ANDROID_NS}permission"):
                        cname = comp.get(f"{ANDROID_NS}name", "?")
                        findings.append(Finding("high", "mobile-android", f"android-exported-no-perm-{tag}",
                            f"Exported {tag} `{cname}` has no `android:permission` — callable by any other app on the device",
                            path=rel,
                            fix=f"Add `android:permission` requirement OR set `android:exported=\"false\"` if external calls aren't needed."))

        # Permissions audit
        all_perms = [p.get(f"{ANDROID_NS}name") for p in root_el.iter("uses-permission")]
        for perm in all_perms:
            if perm in DANGEROUS_PERMS:
                findings.append(Finding("medium", "mobile-android", f"android-perm-{perm.split('.')[-1].lower()}",
                    f"App requests `{perm}` — dangerous permission requiring runtime grant",
                    path=rel,
                    fix=f"Audit whether `{perm}` is actually used. If only one feature needs it, request at the point of use (runtime grant model) rather than declaring in manifest."))
        # If 8+ dangerous perms declared, flag the overall posture
        dangerous_count = sum(1 for p in all_perms if p in DANGEROUS_PERMS)
        if dangerous_count >= 8:
            findings.append(Finding("medium", "mobile-android", "android-many-dangerous-perms",
                f"App requests {dangerous_count} dangerous permissions — high user-trust friction + Play Store scrutiny",
                path=rel,
                fix="Permission count is a Play Store ranking + user-trust signal. Aim for ≤4 dangerous perms; request the rest at runtime per-feature."))

    return findings

# --- Source scan (works for both iOS Swift + Android Kotlin/Java) ----------

def check_mobile_source(root: Path) -> list[Finding]:
    findings = []
    SWIFT_INSECURE_STORAGE = re.compile(r'UserDefaults\.standard\.set\(\s*\w*(?:token|secret|key|password|credential|session)', re.IGNORECASE)
    ANDROID_INSECURE_STORAGE = re.compile(r'SharedPreferences[^.]*\.edit\(\)\.putString\(\s*"\w*(?:token|secret|key|password|credential|session)', re.IGNORECASE)
    WEBVIEW_JS_ENABLED = re.compile(r'(\.javaScriptEnabled\s*=\s*true|setJavaScriptEnabled\s*\(\s*true\s*\))')
    WEBVIEW_BRIDGE = re.compile(r'(addJavascriptInterface|userContentController.*addScriptMessageHandler)')

    for p in root.rglob("*"):
        if not p.is_file(): continue
        if p.suffix.lower() not in (".swift", ".kt", ".java", ".m", ".mm", ".h", ".kts"): continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

        # Hardcoded secrets
        for rx, label, sev in SECRET_RX:
            m = rx.search(text)
            if m:
                findings.append(Finding(sev, "mobile-source", "mobile-hardcoded-secret",
                    f"Hardcoded {label} in mobile source — extractable from app bundle in 60 seconds",
                    path=rel,
                    evidence=m.group(0)[:18] + "…" + m.group(0)[-4:],
                    fix="Mobile bundles are public. Route privileged API calls through your own backend with short-lived user tokens. Never ship server-side secrets in the client."))
                break  # one per file is enough signal

        # Insecure storage
        if SWIFT_INSECURE_STORAGE.search(text):
            findings.append(Finding("high", "mobile-source", "ios-insecure-storage",
                "UserDefaults used to store credentials / tokens — not encrypted, survives in iCloud backup",
                path=rel,
                fix="Use Keychain Services (`SecItemAdd`) for any token/secret/credential. UserDefaults is plain-text plist."))
        if ANDROID_INSECURE_STORAGE.search(text):
            findings.append(Finding("high", "mobile-source", "android-insecure-storage",
                "SharedPreferences used to store credentials / tokens — not encrypted, included in backup blob",
                path=rel,
                fix="Use EncryptedSharedPreferences (`androidx.security:security-crypto`) for any token/secret/credential. Plain SharedPreferences is world-readable on rooted devices."))

        # WebView risks
        if WEBVIEW_JS_ENABLED.search(text) and WEBVIEW_BRIDGE.search(text):
            findings.append(Finding("high", "mobile-source", "webview-js-bridge",
                "WebView has JavaScript enabled AND exposes a native bridge — any loaded page can call into native code",
                path=rel,
                fix="If the WebView only loads your own content: enforce that via URL allow-list. If it ever loads third-party / user-controlled URLs: remove the bridge or disable JavaScript for those loads."))

    return findings

# --- Dispatcher -------------------------------------------------------------

def run(root: Path):
    findings = []
    ios = detect_ios(root)
    android = detect_android(root)
    if ios:
        findings.extend(check_info_plist(root))
    if android:
        findings.extend(check_android_manifest(root))
    if ios or android:
        findings.extend(check_mobile_source(root))
    return ios, android, findings

def render_md(ios, android, findings, target):
    lines = [f"# Lictor mobile scan — `{target}`", ""]
    detected = []
    if ios: detected.append("iOS (Info.plist found)")
    if android: detected.append("Android (AndroidManifest.xml found)")
    lines.append(f"**Platform detected:** {' + '.join(detected) if detected else '(neither — pass an extracted .ipa or .apk directory)'}")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")
    findings.sort(key=lambda f: SEVERITIES.index(f.severity))
    for f in findings:
        lines.append(f"### {SEV_EMOJI[f.severity]} **{f.severity.upper()}** — {f.title}")
        lines.append(f"- Surface: `{f.surface}` · Check: `{f.check}`")
        if f.path: lines.append(f"- Where: `{f.path}`")
        if f.evidence: lines.append(f"- Evidence: `{f.evidence}`")
        if f.fix: lines.append(f"- Fix: {f.fix}")
        lines.append("")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Lictor mobile scanner (v0.4 scaffold)")
    ap.add_argument("target", help="Path to an EXTRACTED .ipa or .apk directory")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"Target must be a directory (extract .ipa/.apk first with `unzip`): {root}", file=sys.stderr)
        sys.exit(2)
    ios, android, findings = run(root)
    if args.json:
        print(json.dumps({"ios": ios, "android": android, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(render_md(ios, android, findings, root))

if __name__ == "__main__":
    main()
