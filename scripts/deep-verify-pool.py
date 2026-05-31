#!/usr/bin/env python3
"""
deep-verify-pool — one-shot triage of the existing finding pool.

Reads CRIT/HIGH from:
  - sensitive-files-v3.jsonl
  - web3-frontend-secrets.jsonl
  - smart-contracts.jsonl (after weak-prng FP filter)
  - nuclei-cve.jsonl

Applies a STRICTER second-pass verification per scanner class and
splits the pool into:
  - verified-real.jsonl    (passed every gate, ready for human review)
  - verified-fp.jsonl      (failed at least one gate, with reason)

This is the "stop adding scanners, extract the signal we already have"
pass per Option A on 2026-05-28.
"""
from __future__ import annotations
import json, re, ssl, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/raffa/Lictor/v3/ledgers")
OUT_REAL = ROOT / "verified-real.jsonl"
OUT_FP = ROOT / "verified-fp.jsonl"

UA = "Lictor-DeepVerify/0.1"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# ── FP body patterns for sensitive-files ──
# If body_preview matches any of these regex patterns, mark as FP-class
SENSITIVE_FILE_BODY_FP = [
    (re.compile(rb'"success"\s*:\s*"?false', re.IGNORECASE), "json_error_envelope_success_false"),
    (re.compile(rb'"errormsg"', re.IGNORECASE),               "json_error_envelope_errormsg"),
    (re.compile(rb'"errorMessage"'),                          "json_error_envelope_errorMessage"),
    (re.compile(rb'"error"\s*:\s*"', re.IGNORECASE),         "json_error_envelope_error_str"),
    (re.compile(rb'"code"\s*:\s*[1-9]'),                      "json_error_envelope_code"),
    (re.compile(rb'<title>404|404 Not Found', re.IGNORECASE), "html_404"),
    (re.compile(rb'Just a moment|cf-browser-verification|cdn-cgi/challenge'), "cloudflare_challenge"),
    (re.compile(rb'cloudfront|Bad Request|AccessDenied'),    "cloud_provider_error"),
    (re.compile(rb'<\!DOCTYPE html|<html', re.IGNORECASE),    "html_spa_fallback"),
]

# ── FP context patterns for web3-frontend-secrets ──
# Many "AKIA..." or "sk-..." matches in JS bundles are actually:
#  - Sentry DSN public keys (allowed exposure)
#  - Analytics IDs that look like AWS prefixes
#  - Public CDN URLs containing key-like strings
FRONTEND_SECRET_FP_BUNDLES = [
    "sentry-cdn.com", "browser.sentry-cdn.com",
    "googletagmanager.com", "google-analytics.com",
    "fullstory.com", "hotjar.com", "intercom.io",
    "datadog-rum", "logrocket",
]


def http_get(url, max_bytes=8000, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(max_bytes), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(max_bytes)
        except: body = b""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return 0, b"", {}


def verify_sensitive_file(d: dict) -> tuple[bool, str]:
    """Return (is_real, reason_if_fp)."""
    body_preview = d.get("body_preview", "")
    if not body_preview:
        return False, "no_body_preview"

    # Encode if str (preview may be utf-8 with escapes)
    body_bytes = body_preview.encode("utf-8", errors="replace") if isinstance(body_preview, str) else body_preview

    # 1. JSON error envelope check
    for pattern, reason in SENSITIVE_FILE_BODY_FP:
        if pattern.search(body_bytes):
            return False, f"body_fp:{reason}"

    # 2. Content-Type mismatch — .env/.git/.sql should NOT be text/html or application/json
    ctype = (d.get("content_type") or "").lower()
    path = (d.get("path") or "").lower()
    if path.endswith((".env", ".git/config", ".bashrc", ".bash_history", ".aws/credentials")):
        if "text/html" in ctype or "application/json" in ctype:
            return False, f"ctype_mismatch:{ctype}"

    # 3. Size sanity — real .env files are usually >50 bytes, real .git/config >100
    size = d.get("size", 0)
    if path.endswith(".env") and size < 30:
        return False, f"size_too_small:{size}"

    return True, "passed_all_gates"


def verify_frontend_secret(d: dict) -> tuple[bool, str]:
    """Re-fetch JS bundle, check context around the match."""
    js_url = d.get("matched_in_url", "")
    prefix = d.get("matched_value_prefix", "")
    secret_class = d.get("secret_class", "")
    if not js_url or not prefix:
        return False, "missing_fields"

    # 1. Vendor-bundle FP — skip well-known third-party SDKs
    for fp_bundle in FRONTEND_SECRET_FP_BUNDLES:
        if fp_bundle in js_url.lower():
            return False, f"vendor_bundle:{fp_bundle}"

    # 2. Re-fetch the JS file (we sample only — looking for context, not exfil)
    status, body, _ = http_get(js_url, max_bytes=200_000)
    if status != 200 or not body:
        return False, f"js_unreachable:status={status}"

    # 3. Find the prefix in the bundle, check context (32 bytes before)
    idx = body.find(prefix.encode("utf-8"))
    if idx < 0:
        return False, "prefix_not_in_bundle_anymore"

    context = body[max(0, idx-32):idx+64].decode("utf-8", errors="replace")

    # 4. Common-FP context patterns
    # AWS key followed by analytics-ID-like pattern (no AWS context)
    if secret_class == "aws_akia_in_js":
        # Look for AWS API endpoints / sdk markers near the prefix
        aws_context_markers = ["aws-sdk", "amazonaws", "s3.upload", "AWS.config", "X-Amz-",
                               "ses.", "cognito", "sigv4", "AccessKeyId"]
        nearby = body[max(0,idx-500):idx+500].decode("utf-8", errors="replace")
        has_aws_context = any(m in nearby for m in aws_context_markers)
        if not has_aws_context:
            return False, "akia_no_aws_context_nearby"

    # 5. Sanity: prefix immediately followed by '@' (email-like) or '/' (path-like) = analytics ID
    after = body[idx+len(prefix):idx+len(prefix)+1]
    if after in (b"@", b"/", b".", b"-"):
        return False, f"prefix_continues_with:{after.decode('ascii','replace')}"

    return True, f"context_ok:{context[:80]}"


def main():
    real_w = OUT_REAL.open("w")
    fp_w = OUT_FP.open("w")
    stats = {"real": 0, "fp": 0, "by_scanner": {}}

    def log(scanner: str, d: dict, is_real: bool, reason: str):
        d["_verify_reason"] = reason
        d["_verify_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        d["_scanner"] = scanner
        line = json.dumps(d) + "\n"
        if is_real:
            real_w.write(line); stats["real"] += 1
            stats["by_scanner"].setdefault(scanner, {"real":0,"fp":0})["real"] += 1
        else:
            fp_w.write(line); stats["fp"] += 1
            stats["by_scanner"].setdefault(scanner, {"real":0,"fp":0})["fp"] += 1

    # --- sensitive-files-v3 ---
    sf_path = ROOT / "sensitive-files-v3.jsonl"
    if sf_path.exists():
        for line in sf_path.read_text().splitlines():
            if not line.strip(): continue
            try:
                d = json.loads(line)
                sev = (d.get("severity") or "").upper()
                if sev not in ("CRITICAL", "HIGH"): continue
                is_real, reason = verify_sensitive_file(d)
                log("sensitive-files-v3", d, is_real, reason)
            except Exception as e:
                pass

    # --- web3-frontend-secrets (CRIT/HIGH only) ---
    wf_path = ROOT / "web3-frontend-secrets.jsonl"
    if wf_path.exists():
        # Limit to first 50 CRIT to control time (fetches JS bundles)
        n_processed = 0
        for line in wf_path.read_text().splitlines():
            if not line.strip(): continue
            if n_processed >= 50: break
            try:
                d = json.loads(line)
                sev = (d.get("severity") or "").upper()
                if sev != "CRITICAL": continue
                is_real, reason = verify_frontend_secret(d)
                log("web3-frontend-secrets", d, is_real, reason)
                n_processed += 1
            except Exception:
                pass

    # --- nuclei-cve (already strict — pass through as-is for now) ---
    nc_path = ROOT / "nuclei-cve.jsonl"
    if nc_path.exists():
        for line in nc_path.read_text().splitlines():
            if not line.strip(): continue
            try:
                d = json.loads(line)
                sev = (d.get("severity") or "").upper()
                if sev not in ("CRITICAL", "HIGH"): continue
                # Nuclei is well-tuned; trust until we have evidence otherwise
                log("nuclei-cve", d, True, "nuclei_trusted_pending_audit")
            except: pass

    real_w.close(); fp_w.close()

    print(f"\n=== DEEP-VERIFY RESULT ===\n")
    print(f"  Total REAL: {stats['real']}")
    print(f"  Total  FP:  {stats['fp']}")
    print(f"\n  Per-scanner:")
    for scanner, s in sorted(stats["by_scanner"].items()):
        total = s["real"] + s["fp"]
        pct_real = (s["real"]*100//total) if total > 0 else 0
        print(f"    {scanner:<28s} real={s['real']:>3d}  fp={s['fp']:>4d}  ({pct_real}% real)")
    print(f"\n  → Real findings written to:  {OUT_REAL}")
    print(f"  → FP findings written to:    {OUT_FP}")


if __name__ == "__main__":
    main()
