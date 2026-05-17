#!/usr/bin/env python3
"""
verify-finding — re-check a flagged finding with stricter heuristics.

Goal: kill WAF / bot-challenge / SPA-fallback false positives BEFORE we
ever email a maintainer with a bad finding.

Usage:
  python3 verify-finding.py exposed-env https://example.com
  python3 verify-finding.py admin-no-auth https://example.com
"""
from __future__ import annotations
import argparse, re, sys, urllib.request, urllib.error, ssl
from urllib.parse import urljoin

UA = "Lictor-Verifier/0.1 (+https://lictorai.com)"
TIMEOUT = 10

# Common WAF / bot-challenge fingerprints — any of these = response is WAF, not real content
WAF_FINGERPRINTS = [
    b"Radware",
    b"rdwr",
    b"Cloudflare",
    b"cf-ray",
    b"__uzdbm",      # Radware bot mgmt
    b"__cfduid",
    b"challenge-platform",
    b"Akamai",
    b"AkamaiGHost",
    b"BotManager",
    b"Imperva",
    b"Incapsula",
    b"Distil",
    b"PerimeterX",
    b"DataDome",
    b"_pxAction",
    b"hCaptcha",
    b"reCAPTCHA",
    b"checking your browser",
    b"DDoS protection",
    b"Just a moment",
    b"Please enable JavaScript",
    b"Are you human",
    b"Access denied",
    b"403 Forbidden",
    b"404 Not Found",
    b"<title>Error",
    b"<title>302",
    b"<title>301",
]

def http_get_norepeat(url, follow_redirect=False, max_bytes=10_000):
    """GET that does NOT auto-follow redirects (so we see the raw response)."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    opener = urllib.request.build_opener(NoRedirect) if not follow_redirect else urllib.request.build_opener()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return (r.status, dict(r.headers), r.read(max_bytes))
    except urllib.error.HTTPError as e:
        return (e.code, dict(e.headers) if e.headers else {}, e.read(max_bytes) if hasattr(e,'read') else b"")
    except Exception:
        return None

def is_waf_response(body):
    if not body: return False
    head = body[:3000]
    for sig in WAF_FINGERPRINTS:
        if sig in head: return True
    return False

def looks_like_real_env(body):
    """Real .env files: multiple KEY=VALUE lines, no HTML, no JS."""
    if not body: return False
    text = body.decode("utf-8", "replace")[:4000]
    if "<html" in text.lower() or "<script" in text.lower(): return False
    # Count plausible env lines: KEY=VALUE or KEY="VALUE" or KEY='VALUE'
    env_lines = re.findall(r'^[A-Z_][A-Z0-9_]{2,}=\S', text, re.MULTILINE)
    return len(env_lines) >= 3

def looks_like_real_admin(body):
    """Real admin panel: has admin/dashboard/users/settings/etc. markup."""
    if not body: return False
    head = body[:5000].lower()
    if b"<html" not in head: return False
    # Real admin signals
    signals = [b"dashboard", b"administrat", b"manage user", b"settings panel", b"system status",
               b"<aside", b"admin-nav", b"adminbar", b"wp-admin", b"navbar", b"sidebar"]
    return sum(1 for s in signals if s in head) >= 2

def verify_exposed_env(homepage):
    """Returns (verdict, reason). verdict in {confirmed, false-positive, inconclusive}."""
    base = homepage if homepage.endswith("/") else homepage + "/"
    results = {}
    for path in (".env", ".env.local", ".env.production"):
        url = urljoin(base, path)
        r = http_get_norepeat(url, follow_redirect=False)
        if not r:
            results[path] = ("inconclusive", "no response")
            continue
        status, headers, body = r
        ct = (headers.get("Content-Type","") or headers.get("content-type","")).lower()
        if status != 200:
            results[path] = ("false-positive", f"status {status} (not 200)")
            continue
        if "html" in ct:
            results[path] = ("false-positive", f"Content-Type {ct} (not text/plain)")
            continue
        if is_waf_response(body):
            results[path] = ("false-positive", "WAF/bot-challenge page")
            continue
        if not looks_like_real_env(body):
            results[path] = ("false-positive", "body doesn't have multiple KEY=VAL lines")
            continue
        results[path] = ("confirmed", f"{len(body)}B, looks real")
    overall = "confirmed" if any(v[0]=="confirmed" for v in results.values()) else "false-positive"
    return overall, results

def verify_admin_no_auth(homepage):
    base = homepage if homepage.endswith("/") else homepage + "/"
    url = urljoin(base, "admin")
    r = http_get_norepeat(url, follow_redirect=False)
    if not r: return "inconclusive", "no response"
    status, headers, body = r
    if status in (301, 302, 303, 307, 308):
        loc = headers.get("Location","") or headers.get("location","")
        if "login" in loc.lower() or "auth" in loc.lower() or "signin" in loc.lower():
            return "false-positive", f"redirects to login: {loc[:80]}"
        return "false-positive", f"redirects to {loc[:80]}"
    if status in (401, 403):
        return "false-positive", f"properly gated (HTTP {status})"
    if status == 404:
        return "false-positive", "/admin doesn't exist"
    if status != 200:
        return "false-positive", f"unexpected status {status}"
    if is_waf_response(body):
        return "false-positive", "WAF/bot-challenge page"
    head = body[:3000].lower()
    if b"login" in head or b"sign in" in head or b"log in" in head or b"\xd7\x94\xd7\x9b\xd7\xa0\xd7\xa1" in head:  # "login" or Hebrew "כניסה"
        return "false-positive", "page contains login form"
    if not looks_like_real_admin(body):
        return "false-positive", "doesn't look like real admin panel"
    return "confirmed", f"200 with admin-like markup ({len(body)}B)"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["exposed-env","admin-no-auth"])
    ap.add_argument("homepage")
    args = ap.parse_args()
    if args.kind == "exposed-env":
        verdict, details = verify_exposed_env(args.homepage)
        print(f"VERDICT: {verdict}")
        for k,(v,why) in details.items():
            print(f"  {k:20s} {v:18s} {why}")
    else:
        verdict, why = verify_admin_no_auth(args.homepage)
        print(f"VERDICT: {verdict}")
        print(f"  reason: {why}")

if __name__ == "__main__":
    main()
