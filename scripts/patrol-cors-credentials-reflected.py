#!/usr/bin/env python3
"""
patrol-cors-credentials-reflected — scanner #72.

Hunts CORS misconfigurations that enable cross-origin session theft.

The vulnerability matrix:

| Server response combo | Severity | Why it's bad |
|-----------------------|----------|--------------|
| ACAO reflects attacker.com + ACAC: true | CRITICAL | Full cross-origin authenticated read = session theft |
| ACAO: null + ACAC: true | HIGH | Sandboxed-iframe attack works (data: URLs etc.) |
| ACAO: * + ACAC: true | HIGH | Spec-violation; some clients accept anyway |
| ACAO reflects but no ACAC: true | LOW | Info disclosure but no auth bypass |
| ACAO: specific allowlist of attacker.com | CRITICAL | Pre-allowed attacker origin |
| ACAO: allowlist contains user-controlled regex match (e.g. https://*.attacker.com) | HIGH | Easy bypass with subdomain |

Real-world bounty payouts for this class:
  - $20k Glassdoor (Bugcrowd, 2020)
  - $7k Twitter (HackerOne, 2019)
  - $5k-$15k consistently across F500
  - Dozens of CVEs per year

Detection method (passive, ethical):
  1. For each target endpoint (especially /api, /auth, /me, /account):
  2. Send a GET (and OPTIONS preflight) with a clearly-attacker Origin header:
     Origin: https://lictor-cors-test.example
  3. Parse the response headers
  4. Score based on the combinations above
  5. NEVER send cookies, NEVER include real credentials, NEVER follow up
     by actually fetching the user data — pure header probe only

We do NOT exploit. We do NOT send actual auth cookies. We do NOT read user data.

Usage:
  patrol-cors-credentials-reflected.py --hosts hosts.txt
"""
from __future__ import annotations
import argparse, json, urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-CORSPatrol/0.1 (+https://lictor-ai.com)"
ATTACKER_ORIGIN = "https://lictor-cors-test.example"

# Common auth-sensitive endpoint paths to probe per host
# (these are where session-theft matters most)
AUTH_SENSITIVE_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/api/v1/me",
    "/api/v1/user",
    "/api/v1/account",
    "/api/v2",
    "/api/v2/me",
    "/api/v2/user",
    "/api/user",
    "/api/me",
    "/api/account",
    "/auth",
    "/auth/me",
    "/auth/user",
    "/auth/session",
    "/me",
    "/user",
    "/account",
    "/session",
    "/profile",
    "/graphql",
    "/oauth/token",
    "/oauth/userinfo",
    "/.well-known/openid-configuration",
]

@dataclass
class CorsFinding:
    host: str
    url: str
    method: str               # OPTIONS or GET
    sent_origin: str
    returned_acao: str = ""    # Access-Control-Allow-Origin
    returned_acac: str = ""    # Access-Control-Allow-Credentials
    returned_acam: str = ""    # Access-Control-Allow-Methods
    returned_acah: str = ""    # Access-Control-Allow-Headers
    status: int = 0
    classification: str = ""   # human-readable vuln class
    severity: str = "INFO"
    notes: str = ""

def probe(url: str, method: str, origin: str, timeout: int = 8) -> dict | None:
    """Send a request with the test Origin header. Return response info."""
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA,
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {
                "status": r.status,
                "acao": r.headers.get("Access-Control-Allow-Origin", ""),
                "acac": r.headers.get("Access-Control-Allow-Credentials", ""),
                "acam": r.headers.get("Access-Control-Allow-Methods", ""),
                "acah": r.headers.get("Access-Control-Allow-Headers", ""),
                "www_authenticate": r.headers.get("WWW-Authenticate", ""),
                "set_cookie": r.headers.get("Set-Cookie", ""),
            }
    except urllib.error.HTTPError as e:
        # HTTP errors still return CORS headers we want to inspect
        return {
            "status": e.code,
            "acao": e.headers.get("Access-Control-Allow-Origin", "") if e.headers else "",
            "acac": e.headers.get("Access-Control-Allow-Credentials", "") if e.headers else "",
            "acam": e.headers.get("Access-Control-Allow-Methods", "") if e.headers else "",
            "acah": e.headers.get("Access-Control-Allow-Headers", "") if e.headers else "",
            "www_authenticate": e.headers.get("WWW-Authenticate", "") if e.headers else "",
            "set_cookie": e.headers.get("Set-Cookie", "") if e.headers else "",
        }
    except Exception:
        return None

def check_uses_cookie_auth(url: str, timeout: int = 8) -> tuple[bool, str]:
    """
    FP Class #22 gate: ORIGIN_REFLECTED + ACAC:true is only EXPLOITABLE when
    the endpoint actually uses cookie-based auth. APIs that use Bearer/Basic
    in the Authorization header don't have cookies to steal, so the CORS
    reflection doesn't enable session-theft.

    Returns (likely_uses_cookies, evidence_string).
    """
    # Derive the host from the URL
    p = urllib.parse.urlparse(url)
    host = p.netloc

    # Probe several common auth-required paths on this host to find an auth
    # challenge. Root paths often return 200 with no auth signal, but
    # specific API endpoints will WWW-Authenticate or set cookies.
    probe_paths = [
        # The original path first
        p.path or "/",
        # Then common auth-required API endpoints
        "/v1/me", "/v1/customers", "/v1/user", "/v1/account",
        "/api/me", "/api/user", "/api/v1/me", "/api/v2/me",
        "/me", "/user", "/account", "/auth/user", "/auth/me",
    ]

    bearer_basic_evidence: str | None = None
    cookie_evidence: str | None = None
    probed = 0
    for path in probe_paths:
        if probed >= 6: break  # cap probes
        try_url = f"{p.scheme}://{host}{path}"
        req = urllib.request.Request(try_url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                sc = r.headers.get("Set-Cookie", "")
                wa = r.headers.get("WWW-Authenticate", "")
        except urllib.error.HTTPError as e:
            sc = e.headers.get("Set-Cookie", "") if e.headers else ""
            wa = e.headers.get("WWW-Authenticate", "") if e.headers else ""
        except Exception:
            continue
        probed += 1

        wa_lower = wa.lower()
        if ("bearer" in wa_lower or "basic" in wa_lower) and not bearer_basic_evidence:
            bearer_basic_evidence = f"path={path} WWW-Authenticate: '{wa[:60]}'"
        if sc and not cookie_evidence:
            cookie_evidence = f"path={path} Set-Cookie present"

    # Decision: Bearer/Basic challenge from ANY endpoint = likely Bearer API host
    if bearer_basic_evidence and not cookie_evidence:
        return False, f"Bearer/Basic API ({bearer_basic_evidence})"
    if cookie_evidence:
        return True, f"cookies in use ({cookie_evidence})"
    if bearer_basic_evidence:
        # Both signals — could be mixed (e.g. SPA + API on same host)
        return True, f"mixed signals — cookies AND bearer ({bearer_basic_evidence}; {cookie_evidence})"
    # No challenge from any endpoint — could be public API or anonymous endpoints
    return True, f"no clear bearer/basic challenge across {probed} paths — assume cookie-auth (manual verify required)"

def classify(acao: str, acac: str, sent_origin: str) -> tuple[str, str, str]:
    """Return (classification, severity, notes)."""
    if not acao:
        return "", "INFO", "no CORS headers — not applicable"

    acac_true = acac.lower().strip() == "true"

    # CRITICAL: Reflects attacker origin + credentials
    if acao.strip() == sent_origin and acac_true:
        return (
            "ORIGIN_REFLECTED_WITH_CREDENTIALS",
            "CRITICAL",
            f"Server reflects arbitrary Origin '{sent_origin}' AND sets "
            f"Access-Control-Allow-Credentials: true. Cross-origin authenticated "
            f"read possible — full session theft via XSS-equivalent."
        )

    # HIGH: null origin + credentials (sandboxed-iframe attack)
    if acao.strip().lower() == "null" and acac_true:
        return (
            "NULL_ORIGIN_WITH_CREDENTIALS",
            "HIGH",
            "Server allows Origin: null with credentials. Sandboxed-iframe "
            "(data: URL, sandbox without allow-same-origin) attack works."
        )

    # HIGH: wildcard + credentials (spec violation; some clients accept)
    if acao.strip() == "*" and acac_true:
        return (
            "WILDCARD_WITH_CREDENTIALS",
            "HIGH",
            "Server returns Access-Control-Allow-Origin: * WITH "
            "Access-Control-Allow-Credentials: true. Spec violation; most "
            "browsers reject but some clients/old browsers don't, and the "
            "config itself indicates misconfiguration."
        )

    # MEDIUM: reflects origin but NO credentials
    if acao.strip() == sent_origin and not acac_true:
        return (
            "ORIGIN_REFLECTED_NO_CREDENTIALS",
            "MEDIUM",
            "Server reflects arbitrary Origin. No credentials flag — so no "
            "auth bypass — but indicates lax CORS policy and may leak "
            "unauthenticated data the server thought was same-origin-only."
        )

    # LOW: wildcard, no credentials (common and usually safe for public APIs)
    if acao.strip() == "*" and not acac_true:
        return (
            "WILDCARD_NO_CREDENTIALS",
            "LOW",
            "Wildcard ACAO without credentials. Usually safe (public API), "
            "but worth confirming there's no sensitive data behind it."
        )

    # OK: specific origin that is NOT our test origin (intended allowlist)
    return (
        "ALLOWLIST_NOT_ATTACKER",
        "INFO",
        f"Server returned ACAO='{acao[:80]}' — does not reflect attacker. "
        f"Looks like a proper allowlist."
    )

def probe_host_path(host: str, path: str) -> list[CorsFinding]:
    """Probe a single host+path pair with OPTIONS + GET."""
    findings: list[CorsFinding] = []
    url = f"https://{host}{path}"
    for method in ("OPTIONS", "GET"):
        result = probe(url, method, ATTACKER_ORIGIN)
        if not result: continue
        cls, sev, notes = classify(
            result["acao"], result["acac"], ATTACKER_ORIGIN)
        # Only record HIGH/MEDIUM/CRITICAL or low (skip INFO to keep clean)
        if sev in ("INFO",): continue

        # FP Class #22 gate: if CRITICAL or HIGH on a Bearer/Basic API,
        # downgrade because no cookies to steal
        if sev in ("CRITICAL", "HIGH") and cls in (
                "ORIGIN_REFLECTED_WITH_CREDENTIALS", "NULL_ORIGIN_WITH_CREDENTIALS",
                "WILDCARD_WITH_CREDENTIALS"):
            uses_cookies, cookie_evidence = check_uses_cookie_auth(url)
            if not uses_cookies:
                sev = "LOW"
                notes = (f"[FP Class #22] Pattern detected but downgraded — "
                        f"{cookie_evidence}. CORS reflection without cookie "
                        f"auth doesn't enable session theft. Manual review "
                        f"still warranted to confirm no cookie path exists.")
                cls = cls + "_BEARER_API_FP"

        findings.append(CorsFinding(
            host=host, url=url, method=method, sent_origin=ATTACKER_ORIGIN,
            returned_acao=result["acao"][:200],
            returned_acac=result["acac"][:50],
            returned_acam=result["acam"][:100],
            returned_acah=result["acah"][:200],
            status=result["status"],
            classification=cls, severity=sev, notes=notes
        ))
    return findings

def scan_host(host: str, paths: list[str]) -> list[CorsFinding]:
    # Strip protocol if present
    host = host.replace("https://", "").replace("http://", "").rstrip("/")
    # Skip if not a hostname
    if "/" in host or " " in host: return []
    findings: list[CorsFinding] = []
    seen_classifications: set[str] = set()
    for path in paths:
        for f in probe_host_path(host, path):
            # Dedup per host + classification (avoid logging same vuln on every path)
            key = f"{f.host}|{f.classification}"
            if key in seen_classifications: continue
            seen_classifications.add(key)
            findings.append(f)
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--max-hosts", type=int, default=500)
    ap.add_argument("--paths-per-host", type=int, default=10,
                    help="how many paths from AUTH_SENSITIVE_PATHS to try per host")
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/cors-credentials-reflected.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines()
             if h.strip() and not h.startswith('#')][:args.max_hosts]
    paths = AUTH_SENSITIVE_PATHS[:args.paths_per_host]
    print(f"[+] CORS credentials-reflection hunt: {len(hosts)} hosts × {len(paths)} paths each")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit = n_high = n_med = n_low = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, paths): h for h in hosts}
        done = 0
        for fut in as_completed(futures):
            host = futures[fut]
            done += 1
            try:
                findings = fut.result()
            except Exception as e:
                print(f"  [{done}/{len(hosts)}] {host} EXC: {e}")
                continue
            for f in findings:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
                       "LOW":"⚪"}.get(f.severity, "?")
                print(f"  [{done}/{len(hosts)}] {tag} {f.host}{f.url.split(f.host,1)[1] if f.host in f.url else ''}  "
                      f"{f.method} → {f.classification}  ({f.severity})")
                if f.severity == "CRITICAL": n_crit += 1
                elif f.severity == "HIGH": n_high += 1
                elif f.severity == "MEDIUM": n_med += 1
                else: n_low += 1
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] 🔴 CRITICAL = origin reflection + credentials → submit immediately.")
    print(f"[+]   PoC: serve a page at https://attacker.com/ that fetches the URL")
    print(f"[+]   with credentials:include and reads the response. We do NOT")
    print(f"[+]   demonstrate the PoC — the header combo IS the vulnerability.")

if __name__ == "__main__":
    main()
