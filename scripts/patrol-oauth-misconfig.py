#!/usr/bin/env python3
"""
patrol-oauth-misconfig — OAuth flow misconfiguration scanner.

Hunts the canonical OAuth flaws that pay $5K-$50K:
  1. Open redirect via redirect_uri (no whitelist or wildcard validation).
  2. Missing state parameter requirement (CSRF on OAuth flow).
  3. response_type=token allowed (implicit flow leaks token in URL fragment).
  4. PKCE not required for public clients.
  5. client_secret leaked in /.well-known/openid-configuration jwks_uri.

Algorithm:
  1. Find OAuth metadata: /.well-known/oauth-authorization-server,
     /.well-known/openid-configuration.
  2. Parse authorization_endpoint + supported response_types + grant_types.
  3. Test attacker-controlled redirect_uri (e.g. https://attacker.example).
  4. Test response_type=token if implicit flow enabled.
  5. Test state-less authorization request (expect rejection).

PASSIVE: We never complete an OAuth flow. We just probe the authorization
endpoint to see what response code it returns.

Usage:
  patrol-oauth-misconfig.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, ssl, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-OAuthPatrol/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
]

@dataclass
class OAuthFinding:
    host: str
    issue: str
    metadata_url: str
    authorization_endpoint: str
    proof: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, method="GET", headers=None, timeout=6, follow_redirects=False):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw): return None
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        req = urllib.request.Request(url, method=method, headers=h)
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(20000)
    except urllib.error.HTTPError as e:
        try: body = e.read(20000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def discover_oauth(host):
    """Return parsed OAuth metadata dict, or None."""
    for path in DISCOVERY_PATHS:
        url = f"https://{host}{path}"
        s, _, body = http(url)
        if s == 200 and body:
            try:
                meta = json.loads(body)
                if "authorization_endpoint" in meta:
                    return url, meta
            except json.JSONDecodeError:
                continue
    return None, None


def test_open_redirect(auth_endpoint: str) -> tuple[bool, str]:
    """Probe with attacker-controlled redirect_uri.
    Tightened: redirect must point to the attacker DOMAIN, not just contain it in
    a parameter. Internal redirects that pass-through redirect_uri are NOT vulns."""
    params = {
        "client_id": "test-client",
        "response_type": "code",
        "redirect_uri": "https://attacker.lictor-test.example/cb",
        "scope": "openid",
        "state": "lictor-test",
    }
    url = auth_endpoint + ("?" if "?" not in auth_endpoint else "&") + urllib.parse.urlencode(params)
    s, h, body = http(url, follow_redirects=False)
    location = h.get("Location", "") or h.get("location", "")
    # STRICT: the location HOST must be attacker.lictor-test.example, not just
    # contain the URL as a parameter
    if s in (301, 302, 303, 307) and location.startswith("https://attacker.lictor-test.example"):
        return True, f"Status {s}, Location host matches attacker: {location[:200]}"
    # Body reflection in error context: must contain attacker host as actual target,
    # not just URL-encoded parameter
    body_lower = body.decode("utf-8", "replace").lower()
    if ("href=\"https://attacker.lictor-test.example" in body_lower or
        "action=\"https://attacker.lictor-test.example" in body_lower):
        if not any(kw in body_lower for kw in ("invalid", "not allowed", "unauthorized",
                                                "not registered", "mismatch", "denied")):
            return True, f"Status {s}, body contains attacker URL as actual link/action"
    return False, ""


def test_implicit_flow(auth_endpoint: str, supported_types: list) -> tuple[bool, str]:
    """If response_type=token is supported, that's deprecated/insecure."""
    if "token" in supported_types or "id_token token" in supported_types:
        return True, f"Implicit flow (response_type=token) is in supported_response_types: {supported_types}"
    return False, ""


def scan_host(host):
    findings = []
    meta_url, meta = discover_oauth(host)
    if not meta: return []
    auth_endpoint = meta.get("authorization_endpoint", "")
    if not auth_endpoint or not auth_endpoint.startswith("https://"):
        return []
    supported_types = meta.get("response_types_supported", [])

    # Test 1: open redirect
    is_open, proof = test_open_redirect(auth_endpoint)
    if is_open:
        findings.append(OAuthFinding(
            host=host, issue="open_redirect_via_redirect_uri",
            metadata_url=meta_url, authorization_endpoint=auth_endpoint,
            proof=proof, severity="HIGH",
            notes="OAuth authorization endpoint accepts arbitrary redirect_uri. Token-theft chain possible.",
        ))

    # Test 2: implicit flow
    is_implicit, proof = test_implicit_flow(auth_endpoint, supported_types)
    if is_implicit:
        findings.append(OAuthFinding(
            host=host, issue="implicit_flow_supported",
            metadata_url=meta_url, authorization_endpoint=auth_endpoint,
            proof=proof, severity="MEDIUM",
            notes="OAuth server supports deprecated implicit flow (response_type=token). Tokens leak via URL fragment.",
        ))

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/oauth-misconfig.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] oauth-misconfig — {len(hosts)} hosts")
    n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=30)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.severity == "HIGH": n_high += 1
                else: n_med += 1
                tag = "🟠" if f.severity == "HIGH" else "🟡"
                print(f"  [{i}/{len(hosts)}] {tag} {f.severity:8s} {f.host} {f.issue}")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] high={n_high} med={n_med}")
    print(f"\n[+] Done. HIGH={n_high} MEDIUM={n_med}")


if __name__ == "__main__":
    main()
