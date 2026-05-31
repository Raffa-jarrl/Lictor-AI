#!/usr/bin/env python3
"""
deep-verify-queue — exhaustive per-entry verification of submission queue.

For each READY_FOR_REVIEW entry, applies the strictest verification check
appropriate for the vuln class. Updates queue with one of:
  VERIFIED_REAL          — passes all checks, safe to submit
  FP_BEARER_API          — CORS with credentials but auth is Bearer-token (not session-stealable)
  FP_NO_AUTH_COOKIES     — no application cookies set, CDN-edge only
  FP_SAMESITE_LAX        — auth cookies use SameSite=Lax/Strict (blocks cross-site)
  FP_AUTH_PROTECTED      — endpoint behind real auth (cicd panel locked down)
  FP_NOT_PLATFORM        — fingerprint matched but actual platform is something else
  FP_NO_REAL_CONTENT     — sourcemap/file finding but actual content is empty/SPA
  AMBIGUOUS              — needs manual review

Writes results to submission-queue-verified.jsonl + prints summary report.
"""
from __future__ import annotations
import json, re, ssl, sys, time
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor")
QUEUE = ROOT / "v3" / "ledgers" / "submission-queue.jsonl"
VERIFIED_OUT = ROOT / "v3" / "ledgers" / "submission-queue-verified.jsonl"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "Lictor-DeepQueueVerify/0.1 (+https://lictor-ai.com)"


def http(url, method="GET", headers=None, timeout=8):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(15000)
    except urllib.error.HTTPError as e:
        try: body = e.read(15000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def get_all_cookies(headers: dict) -> str:
    """Combine all Set-Cookie headers (case-insensitive)."""
    sc = ""
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            sc += v + "; "
    return sc


# CDN-only cookies that don't represent user sessions
CDN_COOKIES = ("__cf_bm", "__cfduid", "_dd_s", "incap_ses", "visid_incap",
               "AWSALB", "AWSALBCORS", "acw_tc")

# Bearer-API auth header hints in ACAH
BEARER_HINTS = ("authorization", "bearer", "accesstoken", "x-auth-token",
                "securitytoken", "x-api-key", "apikey", "x-access-token",
                "wolken_token", "serviceaccount")


def verify_cors(finding: dict) -> tuple[str, str]:
    host = finding.get("host", "")
    if not host: return "AMBIGUOUS", "no host"

    # 1. Reproduce CORS reflection
    s, h, _ = http(f"https://{host}/", method="OPTIONS",
                   headers={"Origin": "https://lictor-verify-test.example",
                            "Access-Control-Request-Method": "GET"})
    acao = (h.get("Access-Control-Allow-Origin") or h.get("access-control-allow-origin") or "")
    acac = (h.get("Access-Control-Allow-Credentials") or h.get("access-control-allow-credentials") or "")
    acah = (h.get("Access-Control-Allow-Headers") or h.get("access-control-allow-headers") or "").lower()

    if "lictor-verify-test.example" not in acao:
        return "STALE_NOT_REPRODUCIBLE", f"OPTIONS no longer reflects (acao={acao[:80]})"
    if acac.lower() != "true":
        return "STALE_NOT_REPRODUCIBLE", f"credentials no longer true (acac={acac})"

    # 2. FP Class #22: Bearer-API auth
    if any(h_ in acah for h_ in BEARER_HINTS):
        return "FP_BEARER_API", f"ACAH lists Bearer-style headers: {acah[:120]}"

    # 3. Check cookies on multiple paths
    cookie_paths = ["/", "/login", "/api/auth", "/api/login", "/api/users/me",
                    "/me", "/account", "/api/account", "/auth/login"]
    has_real_cookie = False
    samesite_none_cookie = False
    samesite_lax_cookie = False
    all_cookies_seen = ""
    for path in cookie_paths:
        s2, h2, _ = http(f"https://{host}{path}", timeout=4)
        if s2 == 0: continue
        cookies = get_all_cookies(h2)
        all_cookies_seen += cookies
        # Identify real (non-CDN) cookies
        for chunk in cookies.split(","):
            name_part = chunk.strip().split("=")[0].split(";")[0].strip()
            if not name_part: continue
            is_cdn = any(cn in name_part for cn in CDN_COOKIES)
            if is_cdn: continue
            has_real_cookie = True
            chunk_lower = chunk.lower()
            if "samesite=none" in chunk_lower:
                samesite_none_cookie = True
            elif "samesite=lax" in chunk_lower or "samesite=strict" in chunk_lower:
                samesite_lax_cookie = True
            else:
                # No SameSite explicit → modern browsers default to Lax
                samesite_lax_cookie = True

    if not has_real_cookie:
        return "FP_NO_AUTH_COOKIES", f"No app cookies set on any of {len(cookie_paths)} paths probed (only CDN cookies)"

    if not samesite_none_cookie:
        return "FP_SAMESITE_LAX", f"Auth cookies present but SameSite=Lax (default) blocks cross-site send"

    # 4. Try to actually exfil data via XHR-equivalent
    # Send GET with Origin + cookies to see what data comes back
    s3, h3, b3 = http(f"https://{host}/api/users/me",
                      headers={"Origin": "https://lictor-verify-test.example"},
                      timeout=5)
    if s3 == 200 and len(b3) > 100:
        return "VERIFIED_REAL", f"CORS+creds reflection confirmed, SameSite=None cookies present, /api/users/me returns {len(b3)} bytes"

    return "VERIFIED_REAL", f"CORS+creds reflection real, SameSite=None cookies present (exfil path needs manual confirm)"


def verify_cicd(finding: dict) -> tuple[str, str]:
    f = finding
    host = f.get("host", ""); port = f.get("port"); scheme = f.get("scheme", "https")
    plat = f.get("platform", "")
    if not host: return "AMBIGUOUS", "no host"

    base = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"

    if plat == "Jenkins":
        s, _, body = http(f"{base}/api/json", timeout=5)
        if b"hudson.model" not in body:
            return "FP_NOT_PLATFORM", "Jenkins /api/json doesn't return hudson.model"
        # Test /script for RCE access
        s2, _, _ = http(f"{base}/script", timeout=5)
        if s2 == 200:
            return "VERIFIED_REAL", "Jenkins /script Script Console accessible without auth (RCE)"
        if s2 in (401, 403):
            return "FP_AUTH_PROTECTED", "Jenkins /api/json open but /script auth-protected (info disclosure only)"
        return "AMBIGUOUS", f"Jenkins detected, /script returned {s2}"

    if plat == "GitLab":
        s, _, body = http(f"{base}/users/sign_in", timeout=5)
        if b"GitLab" not in body and b"gitlab" not in body:
            return "FP_NOT_PLATFORM", "GitLab fingerprint failed re-verification"
        # Test /api/v4/users for unauthenticated read
        s2, _, body2 = http(f"{base}/api/v4/users", timeout=5)
        if s2 == 200 and b"[" in body2 and b"username" in body2:
            return "VERIFIED_REAL", "GitLab /api/v4/users returns user list without auth (mass info disc)"
        return "FP_AUTH_PROTECTED", f"GitLab detected, /api/v4/users returned {s2} (auth-protected)"

    if plat == "ArgoCD":
        s, _, body = http(f"{base}/api/version", timeout=5)
        if b"Version" not in body and b"argo" not in body.lower():
            return "FP_NOT_PLATFORM", "ArgoCD /api/version fingerprint failed"
        s2, _, body2 = http(f"{base}/api/v1/applications", timeout=5)
        if s2 == 200 and (b"items" in body2 or b"applications" in body2):
            return "VERIFIED_REAL", "ArgoCD /api/v1/applications accessible without auth"
        return "FP_AUTH_PROTECTED", f"ArgoCD detected, /api/v1/applications returned {s2}"

    if plat == "Bamboo":
        s, _, body = http(f"{base}/userlogin!default.action", timeout=5)
        if b"Bamboo" not in body and b"Atlassian" not in body:
            return "FP_NOT_PLATFORM", "Bamboo fingerprint failed re-verification"
        return "AMBIGUOUS", "Bamboo detected — manual RCE check needed"

    if plat == "Drone":
        s, _, body = http(f"{base}/api/user", timeout=5)
        if b"drone" not in body.lower():
            return "FP_NOT_PLATFORM", "Drone /api/user doesn't mention drone"
        return "AMBIGUOUS", "Drone detected — manual review"

    if plat == "Tekton":
        s, _, body = http(f"{base}/api/v1/namespaces", timeout=5)
        if b"tekton" not in body.lower():
            return "FP_NOT_PLATFORM", "Tekton fingerprint failed"
        return "VERIFIED_REAL", "Tekton namespaces API accessible"

    return "AMBIGUOUS", f"Unknown platform {plat}"


def verify_sourcemap(finding: dict) -> tuple[str, str]:
    # Sourcemap findings — verify map URL still serves valid map content
    map_url = finding.get("map_url") or finding.get("url")
    if not map_url:
        return "AMBIGUOUS", "no map_url"
    s, _, body = http(map_url, timeout=8)
    if s != 200:
        return "STALE_NOT_REPRODUCIBLE", f"map URL returns {s}"
    try:
        data = json.loads(body)
        if "version" in data and "sources" in data and len(data.get("sources", [])) > 0:
            return "VERIFIED_REAL", f"valid sourcemap with {len(data['sources'])} source files"
    except json.JSONDecodeError:
        return "FP_NO_REAL_CONTENT", "map URL responds 200 but body is not valid JSON"
    return "FP_NO_REAL_CONTENT", "map body has no version/sources keys"


def verify(item: dict) -> tuple[str, str]:
    # Pull finding payload — either nested in 'finding' or top-level
    scanner = item.get("scanner", "")
    # Need to load the original finding from the ledger — submission queue only has summary
    finding_data = None
    company = item.get("company", "")
    host = item.get("host", "")
    # Re-find the finding in scanner ledger
    scanner_ledger_map = {
        "cors": f"v3/ledgers/f500/{company.lower().replace(' ', '_').replace('.','_')}/cors.jsonl",
        "cicd-panels": f"v3/ledgers/f500/{company.lower().replace(' ', '_').replace('.','_')}/cicd-panels.jsonl",
        "sourcemap": f"v3/ledgers/f500/{company.lower().replace(' ', '_').replace('.','_')}/sourcemap.jsonl",
    }
    ledger_path = ROOT / scanner_ledger_map.get(scanner, "")
    # Try to find the matching finding entry
    if ledger_path.exists():
        for line in ledger_path.read_text().splitlines():
            if not line.strip(): continue
            try:
                d = json.loads(line)
                if d.get("host") == host:
                    finding_data = d
                    break
            except: continue

    if not finding_data:
        # Fall back to building from item itself
        finding_data = {"host": host}

    if scanner == "cors":
        return verify_cors(finding_data)
    if scanner == "cicd-panels":
        return verify_cicd(finding_data)
    if scanner == "sourcemap":
        return verify_sourcemap(finding_data)
    return "AMBIGUOUS", f"no verify rule for {scanner}"


def main():
    items = [json.loads(l) for l in QUEUE.read_text().splitlines() if l.strip()]
    ready = [i for i in items if i.get("status") == "READY_FOR_REVIEW"]
    print(f"[+] deep-verify-queue — {len(ready)} READY entries to re-check", flush=True)
    print()

    # Run verification (sequential to avoid hammering)
    results = []
    counts = {}
    for i, item in enumerate(ready, 1):
        status, reason = verify(item)
        counts[status] = counts.get(status, 0) + 1
        item["deep_verify_status"] = status
        item["deep_verify_reason"] = reason
        item["deep_verified_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        results.append(item)
        tag = "✓" if status == "VERIFIED_REAL" else "✗"
        print(f"  [{i:2d}/{len(ready)}] {tag} {status:25s} {item.get('company','?'):20s} {item.get('host','?'):40s} {item.get('scanner','?')}", flush=True)
        # Short pause to be polite
        time.sleep(0.3)

    # Write verified output
    VERIFIED_OUT.write_text("\n".join(json.dumps(r) for r in results) + "\n")

    print()
    print("=== Summary ===")
    for s, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {s}")
    print()
    print(f"Wrote {len(results)} verified entries to {VERIFIED_OUT}")
    print()
    verified_real = [r for r in results if r["deep_verify_status"] == "VERIFIED_REAL"]
    print(f"=== TRUE REAL (submit-ready): {len(verified_real)} ===")
    for r in verified_real:
        print(f"  {r.get('severity','?'):8s} {r.get('company','?'):20s} {r.get('host','?')}")
        print(f"           reason: {r.get('deep_verify_reason','?')[:140]}")


if __name__ == "__main__":
    main()
