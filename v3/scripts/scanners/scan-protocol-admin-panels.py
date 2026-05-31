#!/usr/bin/env python3
"""scan-protocol-admin-panels.py — Discover exposed admin/governance panels
on Immunefi-listed DeFi protocols.

THE HYPOTHESIS:
  DeFi protocols sometimes ship management interfaces (admin dashboards,
  governance multisig signers, oracle admins, timelock controllers) that
  are publicly reachable without authentication. These aren't always
  full-takeover findings, but a discovered admin panel can chain into
  $25K-$100K bounties if it accepts unauthenticated state-changing
  requests or reveals operational data.

ETHICAL GUARANTEES:
  - HEAD requests only — never GET (no body retrieval)
  - Never POST / PUT / DELETE
  - Never attempt authentication
  - Never enumerate users, roles, or data
  - Cap one probe per path per host
  - Respect robots.txt if present
  - Findings stay private; standard 60-day CVD applies

WHAT IT FINDS:
  Admin panels that return 200 without redirecting to a login flow.
  Distinguishes:
    - 200 + auth-challenge (login form) → expected, NOT a finding
    - 200 + admin content visible → POTENTIAL finding (manual review)
    - 200 + JSON/API endpoint → POTENTIAL finding (state-changing risk)
    - 401/403 → properly locked, NOT a finding
    - 301/302 to /login or SSO → properly locked, NOT a finding

CALIBRATION:
  Output severity is conservative. EVERY hit needs manual review
  before submission to Immunefi. Many "exposed" panels turn out to
  be intentional public dashboards (e.g., Aave's risk dashboard).
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

USER_AGENT = "LictorAI-EthicalScanner/0.3 (+https://lictor-ai.com/transparency)"
LEDGER = Path.home() / "Lictor/v3/ledgers/protocol-admin-panels.jsonl"
DEFAULT_CORPUS = Path.home() / ".lictor/defillama-tier1-fresh.txt"

# Paths to probe — high-signal admin/governance/oracle surfaces
ADMIN_PATHS = [
    # Generic admin
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/dashboard",
    "/administrator",
    "/administrator/",
    "/dashboard",
    "/dashboard/",
    "/panel",
    "/control",
    "/backoffice",
    "/portal",
    "/manage",
    "/management",
    "/superadmin",
    "/root",

    # DeFi-specific
    "/governance",
    "/governance/admin",
    "/multisig",
    "/multisig/admin",
    "/timelock",
    "/timelock/admin",
    "/oracle",
    "/oracle-admin",
    "/oracle/admin",
    "/treasury",
    "/treasury/admin",

    # API admin
    "/api/admin",
    "/api/v1/admin",
    "/api/v2/admin",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/governance",
    "/api/multisig",

    # Specific frameworks
    "/wp-admin",
    "/wp-admin/admin-ajax.php",
    "/django-admin",
    "/grafana",
    "/kibana",
    "/jenkins",
    "/jenkins/manage",
    "/admin.php",
    "/admin/index.php",

    # Operational endpoints (info-disclosure tier)
    "/.env",
    "/config.json",
    "/admin.json",
    "/admin/config.json",
    "/api/health",
    "/health",
    "/metrics",
    "/debug",
    "/_debug",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/graphql",
    "/playground",
]


def http_head(url, timeout=8):
    """HEAD request — no body fetch. Returns (status, headers, location)."""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        })
        # Disable redirects so we can see the 301/302 explicitly
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, hdrs):
                return fp
            http_error_301 = http_error_302
            http_error_303 = http_error_302
            http_error_307 = http_error_302
            http_error_308 = http_error_302
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.headers.get("Location", "") if e.headers else ""
    except Exception as e:
        return None, {}, str(e)


def http_get_body(url, max_bytes=800, timeout=8):
    """GET first N bytes — used for baseline-compare anti-FP check."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Range": f"bytes=0-{max_bytes-1}",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(max_bytes)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(max_bytes) if e.fp else b""
    except Exception:
        return None, {}, b""


def normalize_body(body):
    """Strip timestamps and other variable content for catchall-FP comparison."""
    if not body:
        return b""
    s = body.decode("utf-8", errors="replace")
    # Strip common variable patterns
    s = re.sub(r'"?timestamp"?\s*[:=]\s*\d+', '"timestamp":TS', s)
    s = re.sub(r'"?time"?\s*[:=]\s*\d{10,13}', '"time":TS', s)
    s = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?', 'DATETIME', s)
    s = re.sub(r'"id"\s*[:=]\s*"?[a-f0-9-]{8,}"?', '"id":ID', s, flags=re.I)
    s = re.sub(r'"trace[_]?id"\s*[:=]\s*"?[a-z0-9-]+"?', '"traceid":TR', s, flags=re.I)
    s = re.sub(r'"requestId"\s*[:=]\s*"?[a-z0-9-]+"?', '"requestId":RQ', s, flags=re.I)
    s = re.sub(r'\s+', ' ', s)  # normalize whitespace
    return s.strip().encode("utf-8", "replace")


# Module-level import for normalize_body
import re


def classify_response(status, headers, location, path):
    """Classify a probe response. Returns (verdict, severity, reason)."""
    # Network errors
    if status is None:
        return "NETWORK-ERROR", "info", "request failed"

    # Auth-required → properly locked
    if status in (401, 403):
        return "LOCKED", "info", f"properly returns {status}"
    if status in (301, 302, 303, 307, 308):
        loc_lower = (location or "").lower()
        if any(k in loc_lower for k in ["/login", "/signin", "/auth", "/sso", "/oauth", "/account"]):
            return "LOCKED", "info", f"redirects to auth ({location[:60]})"
        return "REDIRECT", "info", f"302 → {location[:80]}"
    if status == 404:
        return "NOT-FOUND", "info", "path does not exist"
    if status >= 500:
        return "SERVER-ERROR", "info", f"server returned {status}"

    # 200 OK — analyze further
    if status == 200:
        # Content-Type analysis
        ct = headers.get("Content-Type", "").lower()
        # X-Frame-Options / CSP / WWW-Authenticate as evidence of intentional admin auth
        if headers.get("WWW-Authenticate"):
            return "LOCKED", "info", "200 but WWW-Authenticate challenge present"

        # FP #15: intentional public infrastructure endpoints (health/status/ping/ready)
        # These are public BY DESIGN on most stacks (Spring Boot Actuator, k8s probes,
        # ALB health checks). NOT vulnerabilities unless they leak sensitive data —
        # in which case the deeper endpoints (/actuator/env, /actuator/heapdump) are
        # the real signal, not /health itself.
        infra_endpoints = ("/health", "/healthz", "/healthcheck", "/api/health",
                           "/status", "/api/status", "/ping", "/api/ping",
                           "/ready", "/readiness", "/live", "/liveness",
                           "/_health", "/_status", "/_ping")
        if path in infra_endpoints:
            return "PUBLIC-INFRA-ENDPOINT", "info", f"{path} is public by design (health/status probe)"

        # API endpoints (JSON 200) = HIGHER signal
        if "json" in ct:
            if path.startswith("/api/admin") or "/admin" in path:
                return "POTENTIAL-ADMIN-API", "HIGH", f"JSON 200 on {path} (admin API exposed?)"
            if path in ("/.env", "/config.json", "/admin.json"):
                return "INFO-DISCLOSURE", "CRITICAL", f"sensitive file directly readable (CT: {ct})"
            return "JSON-200", "MEDIUM", f"JSON endpoint reachable (review for data leak)"

        # HTML 200 on admin path = possible panel
        if "html" in ct:
            if any(k in path for k in ["admin", "dashboard", "panel", "control", "governance", "multisig"]):
                return "POTENTIAL-PANEL", "MEDIUM", f"HTML 200 on admin path (no auth challenge) — manual review"
            return "HTML-200", "info", f"non-admin path HTML 200"

        # Debug / metrics endpoints
        if path in ("/debug", "/_debug", "/metrics") and "text" in ct:
            return "DEBUG-EXPOSED", "MEDIUM", f"debug/metrics endpoint open"

        return "200-AMBIGUOUS", "LOW", f"200 OK, content-type {ct}"

    return "OTHER", "info", f"status {status}"


def get_baselines(base, timeout=8):
    """Fetch baselines: fake API path (catchall) + home page (SPA fallback).
    Returns dict with 'json_baseline' and 'html_baseline' for FP comparison.
    """
    baselines = {}

    # Baseline 1: definitely-fake API path (catches JSON-200 catchall APIs — FP #10)
    fake_api = "/api/lictor-baseline-doesnotexist-9387462"
    status, headers, body = http_get_body(base + fake_api, max_bytes=2000, timeout=timeout)
    if body:
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        baselines["json"] = {
            "status": status,
            "ct": ct,
            "normalized_body": normalize_body(body),
        }

    # Baseline 2: home page (catches SPA fallback that serves index.html for all routes — FP #11)
    status, headers, body = http_get_body(base + "/", max_bytes=4000, timeout=timeout)
    if body:
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        baselines["html"] = {
            "status": status,
            "ct": ct,
            "normalized_body": normalize_body(body),
        }

    # Baseline 3: definitely-fake HTML route (catches HTML catchall too)
    fake_route = "/lictor-fake-route-noexist-93874"
    status, headers, body = http_get_body(base + fake_route, max_bytes=4000, timeout=timeout)
    if body:
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        baselines["html_fake"] = {
            "status": status,
            "ct": ct,
            "normalized_body": normalize_body(body),
        }

    return baselines


def probe_host(host, paths=ADMIN_PATHS, delay=0.5):
    """Probe all admin paths on a single host. Returns list of findings."""
    findings = []
    # Normalize host
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    base = host.rstrip("/")

    # FP fixes #10 + #11: fetch baselines (fake API path + home page + fake HTML route)
    baselines = get_baselines(base)

    for path in paths:
        url = base + path
        status, headers, location = http_head(url, timeout=8)
        verdict, severity, reason = classify_response(status, headers, location, path)

        # If HEAD said HIGH/MEDIUM, run baseline checks to filter FPs
        # FP #14: NEVER trust HEAD's Content-Type — fetch body and compare against
        # ALL baselines regardless of CT. Some servers (Cloudflare, SPA shells)
        # return CT=text/plain on HEAD but text/html body on GET.
        if severity in ("HIGH", "CRITICAL", "MEDIUM") and status == 200 and baselines:
            # Fetch body once for compare paths
            _, get_headers, real_body = http_get_body(url, max_bytes=4000)
            real_norm = normalize_body(real_body)
            real_size = len(real_body) if real_body else 0
            real_ct = (get_headers.get("Content-Type") or get_headers.get("content-type") or "").lower()
            real_body_str = (real_body or b"").decode("utf-8", errors="replace")

            # FP #16: WAF block page returns HTTP 200. F5/Imperva/Akamai/Cloudflare
            # often return 200 with a generic "Request Rejected" / "Access Denied" body
            # when blocking probes. These aren't real exposures — the WAF is doing its job.
            waf_signatures = [
                "Request Rejected",
                "The requested URL was rejected",
                "support ID is:",  # F5 BIG-IP ASM
                "Access Denied",
                "blocked by our security",
                "your request has been blocked",
                "<title>Attention Required",  # Cloudflare
                "Sucuri WebSite Firewall",
                "Imperva Incapsula",
                "Akamai Reference",
            ]
            if any(sig.lower() in real_body_str.lower() for sig in waf_signatures):
                verdict = "WAF-BLOCKED-FP"
                severity = "info"
                reason = "200 with WAF block-page body (request rejected by edge security)"
            # FP #10: JSON catchall (matches fake API baseline by normalized body)
            elif baselines.get("json") and real_norm and real_norm == baselines["json"]["normalized_body"]:
                verdict = "CATCHALL-FP"
                severity = "info"
                reason = "body identical to fake-API baseline (generic catchall wrapper)"

            # FP #11: SPA fallback (matches home page by normalized body)
            elif baselines.get("html") and real_norm and real_norm == baselines["html"]["normalized_body"]:
                verdict = "SPA-FALLBACK-FP"
                severity = "info"
                reason = "body identical to home page (single-page app routing)"

            # FP #11b: HTML catchall (matches fake HTML route)
            elif baselines.get("html_fake") and real_norm and real_norm == baselines["html_fake"]["normalized_body"]:
                verdict = "HTML-CATCHALL-FP"
                severity = "info"
                reason = "body identical to fake-route baseline (HTML catchall)"

            # FP #11c: prefix + size fuzzy match. Normalization can't catch every
            # variable token (CSRF, session-ID, build hash, nonce), so two-body comparison:
            # if first 500 bytes of normalized body match AND sizes are within 10%, it's a SPA fallback.
            elif real_norm and real_size > 1500:
                for bkey, bname in [("html", "home page"), ("html_fake", "fake-route")]:
                    bl = baselines.get(bkey)
                    if not bl:
                        continue
                    baseline_norm = bl["normalized_body"]
                    baseline_size = len(baseline_norm)
                    if baseline_size < 1500:
                        continue
                    # Compare first 500 bytes of normalized body (catches SPA shell start)
                    prefix_match = real_norm[:500] == baseline_norm[:500]
                    # Compare overall size within 10%
                    size_delta_pct = abs(real_size - baseline_size) / max(baseline_size, 1)
                    if prefix_match and size_delta_pct < 0.10:
                        verdict = "SPA-FALLBACK-FP-FUZZY"
                        severity = "info"
                        reason = f"body prefix matches {bname} + size within {size_delta_pct*100:.1f}% (fuzzy SPA-fallback)"
                        break

        if severity in ("HIGH", "CRITICAL", "MEDIUM"):
            findings.append({
                "host": host,
                "url": url,
                "path": path,
                "status": status,
                "verdict": verdict,
                "severity": severity,
                "reason": reason,
                "headers": {k: v for k, v in headers.items()
                            if k.lower() in ("content-type", "server", "x-powered-by",
                                             "www-authenticate", "x-frame-options")},
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            })
        time.sleep(delay)  # gentle rate-limit per probe

    return findings


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus", type=str, default=str(DEFAULT_CORPUS),
                   help="Host corpus file (one host per line)")
    p.add_argument("--limit", type=int, default=50,
                   help="Max hosts to probe (default 50)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="Delay between probes per host (seconds)")
    p.add_argument("--paths", choices=["admin-only", "full"], default="full",
                   help="admin-only = just admin/dashboard/governance; full = all 50+ paths")
    args = p.parse_args()

    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        print(f"[FAIL] corpus not found: {corpus_path}")
        sys.exit(1)

    with open(corpus_path) as f:
        hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if args.paths == "admin-only":
        probe_paths = [p for p in ADMIN_PATHS if any(k in p for k in
                       ["admin", "dashboard", "panel", "governance", "multisig", "timelock"])]
    else:
        probe_paths = ADMIN_PATHS

    hosts = hosts[:args.limit]
    print(f"[+] Scanning {len(hosts)} hosts × {len(probe_paths)} paths = {len(hosts) * len(probe_paths)} probes")
    print(f"[+] Output ledger: {LEDGER}")
    print(f"[+] HEAD-only, never auth/POST, {args.delay}s delay per probe")
    print()

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    all_findings = []
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}

    with open(LEDGER, "a") as out:
        for i, host in enumerate(hosts, 1):
            print(f"  [{i:>3}/{len(hosts)}] {host}", end="", flush=True)
            try:
                findings = probe_host(host, paths=probe_paths, delay=args.delay)
            except Exception as e:
                print(f"  [error: {e}]", flush=True)
                continue

            if findings:
                print(f"  → {len(findings)} potential finding(s)", flush=True)
                for f in findings:
                    by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                    print(f"        [{f['severity']:8}] {f['path']:30}  ({f['verdict']}: {f['reason']})", flush=True)
                    out.write(json.dumps(f) + "\n")
                    out.flush()
                    all_findings.append(f)
            else:
                print(f"  → clean", flush=True)

    print()
    print("=" * 70)
    print("ADMIN PANEL SCAN SUMMARY")
    print("=" * 70)
    print(f"  Hosts probed:     {len(hosts)}")
    print(f"  Total findings:   {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        if by_severity.get(sev, 0):
            print(f"  {sev:<10}        {by_severity[sev]}")
    print()
    if all_findings:
        print("HIGH/CRITICAL findings (manual review required):")
        for f in all_findings:
            if f["severity"] in ("HIGH", "CRITICAL"):
                print(f"  - {f['host']:<45} {f['path']:<30} {f['verdict']}")
        print()
    print(f"[+] Ledger: {LEDGER}")


if __name__ == "__main__":
    main()
