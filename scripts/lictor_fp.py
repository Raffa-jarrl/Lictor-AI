#!/usr/bin/env python3
"""
lictor_fp.py — canonical false-positive knowledge base for all Lictor scanners.

THE MOAT: a security scanner is only as trustworthy as its false-positive rate.
Every FP class below was learned the hard way — from a real triager N/A, a bounced
disclosure, or a deep-verify pass that caught noise before it reached a human.
Consolidating them here means every scanner (and the shipped products — Sentinel,
Shield, Guardian) inherits the same hard-won quality filter from one source of truth.

Each class carries PROVENANCE (where/when learned) so the knowledge is traceable
and defensible — useful both for debugging and as a credibility artifact.

Usage:
    from lictor_fp import (
        is_catchall_response, is_spa_fallback, is_json_error_envelope,
        is_public_by_design_secret, is_customer_resource_host,
        is_account_gated_takeover, TAKEOVER_TIER1, classify_finding_fp,
    )

Established 2026-05-28, consolidating FP classes #1–#19 discovered 2026-05-12 → 05-28.
"""
from __future__ import annotations
import re

# ============================================================================
# SECTION 1 — HTTP RESPONSE FP CLASSES
# (a "200 OK" means nothing on its own; these distinguish real exposure from noise)
# ============================================================================

# FP #6 (2026-05-26, koubei.com /credentials.json): API error envelopes returned
# with HTTP 200. A JSON body like {"success":"false"} or {"errormsg":...} is an
# application error, not an exposed credentials file.
_JSON_ERROR_ENVELOPE = [
    re.compile(rb'"success"\s*:\s*"?false', re.I),
    re.compile(rb'"errormsg"|"errorMessage"', re.I),
    re.compile(rb'"error"\s*:\s*("|\{|true)', re.I),
    re.compile(rb'"code"\s*:\s*[1-9]\d{2}'),       # {"code":404,...}
    re.compile(rb'"status"\s*:\s*"(error|fail)', re.I),
]

# FP #11 (2026-05): SPA fallback — single-page apps return index.html (200) for
# EVERY path, including /.env, /.git/config, /credentials.json. The 200 is the
# router, not the file.
_HTML_MARKERS = re.compile(rb'<!DOCTYPE html|<html[\s>]|<head[\s>]|<body[\s>]', re.I)

# FP #8 (2026-05): Cloudflare / WAF challenge pages return 200/403 with challenge
# HTML, not the requested resource.
_WAF_CHALLENGE = re.compile(
    rb'Just a moment|cf-browser-verification|cdn-cgi/challenge|challenge-platform|'
    rb'Attention Required|Checking your browser|Access denied', re.I)

# FP #7: generic HTML 404 served with a 200 status (common on misconfigured SPAs/CDNs)
_HTML_404 = re.compile(rb'<title>\s*404|404 Not Found|Page Not Found|Not Found</', re.I)


def is_json_error_envelope(body: bytes) -> bool:
    """FP #6: body is a JSON API error response, not an exposed file."""
    if not body:
        return False
    return any(p.search(body) for p in _JSON_ERROR_ENVELOPE)


def is_spa_fallback(body: bytes) -> bool:
    """FP #11: body is an HTML SPA shell, not the requested sensitive file."""
    if not body:
        return False
    head = body[:600]
    return bool(_HTML_MARKERS.search(head))


def is_waf_challenge(body: bytes) -> bool:
    """FP #8: body is a Cloudflare/WAF interstitial, not the resource."""
    return bool(body and _WAF_CHALLENGE.search(body[:1500]))


def is_html_404(body: bytes) -> bool:
    """FP #7: body is a soft-404 HTML page served with 200."""
    return bool(body and _HTML_404.search(body[:600]))


def is_tiny_stub(body: bytes, path: str, min_bytes: int = 100) -> bool:
    """FP #18 (2026-05-28): a /credentials.json or similar that's < min_bytes and
    JSON is almost always an error stub like {"error":true}, not real creds."""
    if path.endswith(('credentials.json', 'config.json')) and body and len(body) < min_bytes:
        if body.lstrip()[:1] in (b'{', b'['):
            return True
    return False


def sensitive_file_is_fp(body: bytes, path: str, content_type: str = "", size: int = 0) -> tuple[bool, str]:
    """Composite gate for sensitive-file findings (.env / .git/config / credentials.json
    / wp-config backups). Returns (is_fp, reason)."""
    ct = (content_type or "").lower()
    if is_json_error_envelope(body):
        return True, "json_error_envelope"
    if is_spa_fallback(body):
        return True, "spa_fallback_html"
    if is_waf_challenge(body):
        return True, "waf_challenge"
    if is_html_404(body):
        return True, "soft_404_html"
    if is_tiny_stub(body, path, 100):
        return True, "tiny_json_stub"
    # FP #19: .env / .git/config served as text/html = SPA, not the raw file
    if path.endswith(('.env', '.git/config', '.php~', '.bak')) and 'text/html' in ct:
        return True, "served_as_html_not_raw"
    return False, ""


# ============================================================================
# SECTION 2 — SECRET-CLASS FP (strings that look like secrets but are public)
# ============================================================================

# FP (2026-05-28, reports.remax.co.il): Sentry DSNs are PUBLIC by design — the
# Sentry browser SDK requires the DSN in client JS. Not a secret.
# FP: VITE_ / NEXT_PUBLIC_ / REACT_APP_ prefixed env vars are inlined into the
# bundle intentionally — public by framework design.
_PUBLIC_BY_DESIGN_SECRET_CLASSES = {
    "sentry_dsn",            # client-side error tracking, public DSN
    "ga_measurement_id",     # Google Analytics G-XXXX
    "gtm_id",                # Google Tag Manager
    "stripe_publishable",    # pk_live_ / pk_test_ are public by design
    "firebase_public_config",# apiKey in firebaseConfig is NOT secret (Firebase docs)
    "mapbox_public_token",   # pk.* mapbox tokens are public
    "recaptcha_site_key",
}

# FP #45/#46 (2026-05): third-party vendor SDK bundles contain key-shaped stubs
_VENDOR_BUNDLE_HOSTS = [
    "sentry-cdn.com", "browser.sentry-cdn.com", "js.sentry-cdn.com",
    "googletagmanager.com", "google-analytics.com", "googleapis.com",
    "fullstory.com", "hotjar.com", "intercom.io", "intercomcdn.com",
    "datadoghq.com", "datadog-rum", "logrocket.com", "cdn.segment.com",
    "js.stripe.com", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
]


def is_public_by_design_secret(secret_class: str) -> bool:
    """FP: this 'secret' class is intentionally public (Sentry DSN, VITE_*, pk_live_)."""
    return (secret_class or "").lower() in _PUBLIC_BY_DESIGN_SECRET_CLASSES


def is_vendor_bundle(js_url: str) -> bool:
    """FP #45/#46: key-shaped string lives in a third-party SDK bundle, not the app's."""
    u = (js_url or "").lower()
    return any(v in u for v in _VENDOR_BUNDLE_HOSTS)


def is_public_env_prefix(key_name: str) -> bool:
    """FP: env var with a framework public prefix is inlined into the bundle by design."""
    return bool(re.match(r'^(VITE_|NEXT_PUBLIC_|REACT_APP_|GATSBY_|PUBLIC_|VUE_APP_|EXPO_PUBLIC_)', key_name or ""))


# ============================================================================
# SECTION 3 — SUBDOMAIN TAKEOVER FP (the class we declared dead 2026-05-28)
# ============================================================================

# FP (2026-05-27, DigitalOcean N/A from @neho + Coca-Cola Fastly/Magento): hosts on
# shared customer-resource infra belong to the CUSTOMER, not the provider. A finding
# on *.digitaloceanspaces.com is out of scope for DigitalOcean's program.
CUSTOMER_RESOURCE_HOST_PATTERNS = [
    "s3.amazonaws.com", "s3-website", ".cloudfront.net",
    ".blob.core.windows.net", ".digitaloceanspaces.com",
    ".appspot.com", ".firebaseapp.com", ".web.app",
    ".herokuapp.com", ".workers.dev", ".pages.dev",
    ".vercel.app", ".netlify.app", ".glitch.me", ".replit.app", ".repl.co",
    ".fly.dev", ".up.railway.app", ".azurewebsites.net", ".onrender.com",
    ".pythonanywhere.com", "magentocloud.map.fastly.net",
]

# FP (2026-05-28, 3/3 Intigriti N/A — here/coca-cola/wpengine): takeover findings
# without active claim are out of scope on most modern programs. Only these vendors
# still have public self-signup + no domain verification = actually exploitable.
TAKEOVER_TIER1 = {
    "AWS_S3", "GitHub_Pages", "Heroku", "Surge",
    "Webflow", "Cargo", "Azure_WebApp", "Netlify",
}
# Everything else (Fastly, Tumblr, Magento Cloud, CloudFront, etc.) is account-gated
# = takeover is theoretical = demote to INFO, never auto-submit.


def is_customer_resource_host(host: str) -> bool:
    """FP: scan target is on shared customer-resource infra → out of scope for the provider."""
    h = (host or "").lower()
    return any(pat in h for pat in CUSTOMER_RESOURCE_HOST_PATTERNS)


def is_account_gated_takeover(service: str) -> bool:
    """FP: takeover vendor requires account-level claim (not self-signup) → not exploitable."""
    return (service or "") not in TAKEOVER_TIER1


# ============================================================================
# SECTION 4 — DATABASE / INFRA FP
# ============================================================================

# FP (2026-05-28, otzar.co.il + nofar.org.il): MySQL/MariaDB port 3306 is OPEN but
# the server returns "Host 'X' is not allowed to connect" — it has a host ACL.
# Reachable != exploitable. Only flag if the server sends a real handshake.
_DB_BLOCKED_MARKERS = [
    b"is not allowed to connect",
    b"is blocked because of many connection errors",
    b"Host '",
]

# FP (2026-05-27, fiftyshadesandblinds + cbre.co.il): WHM/cPanel on ports 2082-2087
# is STANDARD shared-hosting config. Every cPanel customer has these open. Not a vuln.
CPANEL_STANDARD_PORTS = {2082, 2083, 2086, 2087, 2095, 2096}


def mysql_is_host_acled(greeting: bytes) -> bool:
    """FP: MySQL port open but greeting is a host-ACL rejection, not a real handshake.
    A REAL exposure: greeting[4]==0x0a (protocol v10 handshake). A blocked one: error msg."""
    if not greeting:
        return False
    if any(m in greeting for m in _DB_BLOCKED_MARKERS):
        return True
    # Real MySQL handshake starts with length(3) + seq(1) + 0x0a
    if len(greeting) > 5 and greeting[4] == 0x0a:
        return False  # real handshake = NOT an FP, genuinely exposed
    return False


def is_cpanel_standard_port(port: int) -> bool:
    """FP: WHM/cPanel on a standard hosting port — by-design, not a finding."""
    return port in CPANEL_STANDARD_PORTS


# ============================================================================
# SECTION 5 — SMART CONTRACT FP (Slither noise)
# ============================================================================

# FP (2026-05-28, SavingsDai/sDAI): Slither flags weak-prng on _rpow/_rmul/_wmul,
# but these are MakerDAO-style modular exponentiation helpers using `n % 2` for
# bit-checking — NOT random number generation. Repeats across every DSR-style contract.
def slither_is_fp(check: str, description: str) -> bool:
    """FP: Slither weak-prng on modular-exp helper functions (not real RNG)."""
    if check == "weak-prng":
        for fn in ("_rpow", "rpow(", "_rmul", "rmul(", "_wmul", "wmul(", "_wpow", "wpow("):
            if fn in (description or ""):
                return True
    return False


# ============================================================================
# SECTION 6 — TOP-LEVEL DISPATCHER
# ============================================================================

def classify_finding_fp(finding: dict) -> tuple[bool, str]:
    """Single entry point. Given a finding dict, return (is_fp, reason).
    Routes to the right filter by the finding's scanner/class. Used by
    protection-gate + deep-verify + (eventually) the shipped Sentinel runtime."""
    scanner = finding.get("scanner", "") or finding.get("_scanner", "")
    host = finding.get("host", "")

    # Cross-cutting: customer-resource infra is out of scope for everything
    if is_customer_resource_host(host):
        return True, "customer_resource_host_out_of_scope"

    if "sensitive-file" in scanner or finding.get("path"):
        body = finding.get("body_preview", "")
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return sensitive_file_is_fp(body, finding.get("path", ""),
                                    finding.get("content_type", ""), finding.get("size", 0))

    if "frontend-secret" in scanner or finding.get("secret_class"):
        if is_public_by_design_secret(finding.get("secret_class", "")):
            return True, f"public_by_design:{finding.get('secret_class')}"
        if is_vendor_bundle(finding.get("matched_in_url", "")):
            return True, "vendor_bundle_sdk"

    if "takeover" in scanner:
        if is_account_gated_takeover(finding.get("service", "")):
            return True, "account_gated_takeover_not_exploitable"

    if "smart-contract" in scanner or finding.get("detector"):
        if slither_is_fp(finding.get("detector", ""), finding.get("description", "")):
            return True, "slither_weak_prng_modexp"

    return False, ""


# Self-test when run directly
if __name__ == "__main__":
    tests = [
        ({"scanner": "sensitive-files-v3", "path": "/credentials.json", "size": 20,
          "content_type": "application/json", "body_preview": '{"success":"false"}'}, True),
        ({"scanner": "sensitive-files-v3", "path": "/.git/config", "size": 314,
          "content_type": "", "body_preview": "[core]\n\trepositoryformatversion = 0"}, False),
        ({"scanner": "web3-frontend-secrets", "secret_class": "sentry_dsn", "host": "x.com"}, True),
        ({"scanner": "takeover-claim-proof", "service": "Fastly", "host": "x.com"}, True),
        ({"scanner": "takeover-claim-proof", "service": "Surge", "host": "x.com"}, False),
        ({"scanner": "smart-contracts", "detector": "weak-prng",
          "description": "SavingsDai._rpow uses a weak PRNG"}, True),
        ({"host": "victim.digitaloceanspaces.com", "scanner": "sensitive-files-v3"}, True),
    ]
    passed = 0
    for finding, expect_fp in tests:
        is_fp, reason = classify_finding_fp(finding)
        ok = (is_fp == expect_fp)
        passed += ok
        print(f"  {'✓' if ok else '✗'} expect_fp={expect_fp} got={is_fp} ({reason}) :: {finding.get('scanner','?')}")
    print(f"\n  {passed}/{len(tests)} self-tests passed")
