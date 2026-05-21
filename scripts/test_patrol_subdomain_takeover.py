#!/usr/bin/env python3
"""
Regression tests for patrol-subdomain-takeover v0.2 FP fixes.

Covers the 4 FP patterns that produced noise in production (May 2026):
  1. CloudFront — live distros responding "Bad request" but with x-amz-cf-id header
  2. Azure CloudApp — live signin pages with "404" substring in JS error handlers
  3. GitHub Pages — bare-org probes where the org actually exists
  4. Netlify — generic 404s that aren't actually takeover markers

Plus 4 positive cases (one per fixed provider) to confirm real takeovers still
pass through.

Run:  python3 -m pytest scripts/test_patrol_subdomain_takeover.py -v
  or: python3 scripts/test_patrol_subdomain_takeover.py
"""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

# Load the patrol script as a module (its filename has a hyphen so we can't `import` it directly).
_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("patrol_takeover", _HERE / "patrol-subdomain-takeover.py")
patrol = importlib.util.module_from_spec(_SPEC)
sys.modules["patrol_takeover"] = patrol
_SPEC.loader.exec_module(patrol)


# ---------- helpers ----------

def fp_by_provider(name: str) -> dict:
    """Find a fingerprint dict by its provider label."""
    for fp in patrol.TAKEOVER_FINGERPRINTS:
        if fp["provider"] == name:
            return fp
    raise KeyError(f"no fingerprint for provider={name!r}")


def assert_fp_skipped(provider: str, body: str, headers: dict, status: int, host: str = "test.example.com", reason_contains: str = "") -> None:
    fp = fp_by_provider(provider)
    assert fp["body_rx"].search(body), f"setup error: body should match {provider} body_rx"
    is_real, reason = patrol._passes_fp_filters(fp, body, headers, status, host)
    assert not is_real, f"{provider}: expected FP-skip but passed (reason={reason!r})"
    if reason_contains:
        assert reason_contains.lower() in reason.lower(), f"reason {reason!r} should contain {reason_contains!r}"


def assert_real_takeover(provider: str, body: str, headers: dict, status: int, host: str = "test.example.com") -> None:
    fp = fp_by_provider(provider)
    assert fp["body_rx"].search(body), f"setup error: body should match {provider} body_rx"
    is_real, reason = patrol._passes_fp_filters(fp, body, headers, status, host)
    assert is_real, f"{provider}: expected real takeover but filtered as FP (reason={reason!r})"


# ---------- CloudFront ----------

CF_BAD_REQUEST_BODY = (
    "<H1>403 ERROR</H1>"
    "<H2>The request could not be satisfied.</H2>"
    "Bad request. We can't connect to the server for this app or website at this time."
)

def test_cloudfront_fp_live_distro_has_xamzcfid():
    """The komoju-style FP: live CloudFront responds with the matching body BUT also includes x-amz-cf-id."""
    headers = {"x-amz-cf-pop": "FRA56-P15", "x-amz-cf-id": "bwieKGW7HLw7FCbieV87PATKcnmeSujS0BZ_y8_9Gmkh5i6CZTwxEA=="}
    assert_fp_skipped("AWS/CloudFront", CF_BAD_REQUEST_BODY, headers, 403, "cdn.test.komoju.com", reason_contains="x-amz-cf-id")

def test_cloudfront_real_takeover_no_xamzcfid():
    """Real CloudFront takeover: distro doesn't exist, no x-amz-cf-id header."""
    assert_real_takeover("AWS/CloudFront", CF_BAD_REQUEST_BODY, {"server": "CloudFront"}, 403, "abandoned.example.com")


# ---------- Azure CloudApp ----------

AZURE_CLOUDAPP_REAL_BODY = "<title>This page can't be displayed</title>"
AZURE_CLOUDAPP_FP_BODY = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<title>Citrix Secure Sign In</title>'
    '<script>window.onerror=function(e){console.log("404", e)}</script>'
)

def test_azure_cloudapp_fp_live_signin_with_404_in_js():
    """The Citrix-style FP: live signin page with the substring "404" in JS."""
    # Old regex matched on `|404`; new regex requires canonical "This page can't be displayed" only.
    fp = fp_by_provider("Azure/CloudApp")
    assert not fp["body_rx"].search(AZURE_CLOUDAPP_FP_BODY), "live Citrix signin should NOT match the new tightened body_rx"

def test_azure_cloudapp_fp_correct_body_but_200_status():
    """Even with the right body text, status=200 means it's a live page (FP)."""
    assert_fp_skipped("Azure/CloudApp", AZURE_CLOUDAPP_REAL_BODY, {}, 200, reason_contains="status")

def test_azure_cloudapp_real_takeover_404():
    """Real Azure CloudApp takeover: canonical error body + 404 status."""
    assert_real_takeover("Azure/CloudApp", AZURE_CLOUDAPP_REAL_BODY, {}, 404)


# ---------- GitHub Pages ----------

GH_PAGES_NOT_HERE_BODY = "<h1>There isn't a GitHub Pages site here.</h1>"

def test_github_pages_fp_real_org_exists(monkeypatch=None):
    """If the org exists on GitHub (api returns 200), the 404 body is from a real Pages site = FP."""
    # Prime the cache so we don't hit the network in tests.
    patrol._GITHUB_ORG_CACHE["existing-org"] = True
    assert_fp_skipped("GitHub Pages", GH_PAGES_NOT_HERE_BODY, {}, 404, "existing-org.github.io", reason_contains="verifier")

def test_github_pages_real_takeover_org_does_not_exist():
    """If the org does NOT exist on GitHub (404), the body is a real takeover signal."""
    patrol._GITHUB_ORG_CACHE["abandoned-org"] = False
    assert_real_takeover("GitHub Pages", GH_PAGES_NOT_HERE_BODY, {}, 404, "abandoned-org.github.io")


# ---------- Netlify ----------

def test_netlify_real_takeover_request_id_format():
    """Classic Netlify 404 takeover marker (Request-ID present)."""
    body = "Not Found - Request ID: 01HXYZ..."
    assert_real_takeover("Netlify", body, {}, 404)

def test_netlify_real_takeover_nothing_here_yet():
    """The drop-domain UI marker (now included in v0.2)."""
    body = "<h2>There is nothing here yet</h2>"
    assert_real_takeover("Netlify", body, {}, 200)

def test_netlify_does_not_match_generic_404():
    """A generic 'Page not found' page without the canonical markers should NOT match."""
    fp = fp_by_provider("Netlify")
    assert not fp["body_rx"].search("<h1>Page not found</h1>"), "generic 404 should not match Netlify body_rx"


# ---------- Heroku ----------

HEROKU_REAL_BODY = "<h1>No such app</h1>"

def test_heroku_real_takeover_404():
    """Real Heroku takeover: canonical 'No such app' + HTTP 404."""
    assert_real_takeover("Heroku", HEROKU_REAL_BODY, {}, 404)

def test_heroku_fp_correct_body_but_200_status():
    """If somehow the body has 'No such app' but status is 200, treat as FP."""
    assert_fp_skipped("Heroku", HEROKU_REAL_BODY, {}, 200, reason_contains="status")

def test_heroku_no_longer_matches_generic_nothing_here():
    """The old broad 'There's nothing here' / 'herokucdn' patterns are removed in v0.2."""
    fp = fp_by_provider("Heroku")
    assert not fp["body_rx"].search("<h1>There's nothing here</h1>"), "v0.2 should require canonical 'No such app' phrase"
    assert not fp["body_rx"].search("Powered by herokucdn"), "v0.2 should not match generic herokucdn substring"


# ---------- fetch_body backward compatibility shim ----------

def test_fetch_body_returns_string():
    """The v0.1 fetch_body() shim must still exist and return a str."""
    # Calling it on a likely-failing host shouldn't crash; just returns "".
    assert isinstance(patrol.fetch_body("nonexistent-host-for-test.invalid"), str)


# ---------- module-level smoke ----------

def test_all_fingerprints_have_required_keys():
    """Every fingerprint must have at minimum cname_rx + body_rx + provider."""
    for fp in patrol.TAKEOVER_FINGERPRINTS:
        assert "provider" in fp and isinstance(fp["provider"], str), f"missing/bad provider in {fp}"
        assert "cname_rx" in fp, f"missing cname_rx in {fp['provider']}"
        assert "body_rx" in fp, f"missing body_rx in {fp['provider']}"

def test_version_bumped_to_0_2():
    """UA string must report v0.2."""
    assert "0.2" in patrol.UA, f"UA string should report 0.2, got: {patrol.UA!r}"


if __name__ == "__main__":
    # Manual runner so the user can run without pytest.
    import inspect
    tests = [(name, fn) for name, fn in globals().items() if name.startswith("test_") and callable(fn)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✓ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {name}  →  {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ {name}  →  {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed+failed} tests passed")
    sys.exit(0 if failed == 0 else 1)
