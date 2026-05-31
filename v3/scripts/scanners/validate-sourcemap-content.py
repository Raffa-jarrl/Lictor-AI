#!/usr/bin/env python3
"""validate-sourcemap-content.py — Tier-classify the 292 sourcemap findings
by actual content quality.

WHAT IT FIXES:
  Lesson from Visa + Expedia rejections: sourcemap existence ≠ exploitable
  finding. Most "sourcemap exposures" are vendor library boilerplate
  (Stencil.js framework, React internals, etc.) with zero customer code.

  This validator parses each sourcemap's JSON, separates customer code
  from vendor code, and classifies the finding into one of four tiers:

    HIGH         — custom code + secrets / internal URLs / API endpoints
    MEDIUM       — significant custom code revealed (>10KB), but no secrets
    LOW          — minimal custom code (mostly framework boilerplate)
    EMPTY        — no parseable content or <500 bytes

  The HIGH tier is bounty-submittable. The LOW tier becomes courtesy-email
  hygiene notes (no bounty expected). Honest, calibrated, defensible.

ETHICAL:
  - GET only on public web content
  - 5MB cap per fetch
  - No further enumeration once content is parsed
  - All output stays local
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

USER_AGENT = "LictorAI-EthicalScanner/0.3 (+https://lictor-ai.com/transparency)"
INPUT_LEDGER = Path.home() / "Lictor/v3/ledgers/sourcemap-exposure.jsonl"
OUTPUT_LEDGER = Path.home() / "Lictor/v3/ledgers/sourcemap-validated.jsonl"

# Secret patterns (strict)
SECRET_PATTERNS = [
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github_pat"),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "github_server"),
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "github_oauth"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "stripe_live"),
    (re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"), "google_api"),
    (re.compile(r"\bxox[bp]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b"), "slack"),
    (re.compile(r"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_-]{40,}\b"), "anthropic"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"), "openai_proj"),
]

# Heuristic: vendor-code path indicators (these are framework boilerplate)
VENDOR_FRAGMENTS = [
    "node_modules/",
    "/vendor/",
    "@stencil/",
    "@angular/",
    "@vue/",
    "react-dom/",
    "react/",
    "lodash/",
    "moment/",
    "webpack/",
    "core-js/",
    "regenerator-runtime/",
    "polyfill",
    "@babel/runtime",
    "tslib",
]


def is_vendor_source(path):
    """Determine if a source path is vendor/framework code vs customer code."""
    if not path:
        return False
    return any(frag in path for frag in VENDOR_FRAGMENTS)


def fetch_sourcemap(url, max_bytes=5 * 1024 * 1024):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status != 200:
                return None, r.status
            return r.read(max_bytes), r.status
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception:
        return None, None


def _empty_result(reason, body_len):
    """Always return a complete dict so the main loop doesn't KeyError."""
    return {
        "tier": "EMPTY",
        "reason": reason,
        "bytes": body_len,
        "sources_total": 0,
        "custom_source_count": 0,
        "vendor_source_count": 0,
        "custom_code_chars": 0,
        "vendor_code_chars": 0,
        "secrets_found": [],
        "internal_urls": [],
        "api_paths": [],
        "sample_custom_sources": [],
    }


def analyze_sourcemap(body, source_host=""):
    """Parse sourcemap JSON and classify content tier."""
    if not body or len(body) < 100:
        return _empty_result("no content or too small", len(body) if body else 0)

    try:
        data = json.loads(body)
    except Exception:
        # Not valid JSON — might still be useful as plain text (rare)
        return _empty_result("not valid JSON sourcemap", len(body))

    sources = data.get("sources", []) or []
    sources_content = data.get("sourcesContent", []) or []

    # Separate vendor vs customer sources
    custom_sources = []
    vendor_sources = []
    custom_chars = 0
    vendor_chars = 0

    for i, src_path in enumerate(sources):
        content = sources_content[i] if i < len(sources_content) else None
        content_len = len(content) if content else 0
        if is_vendor_source(src_path):
            vendor_sources.append(src_path)
            vendor_chars += content_len
        else:
            custom_sources.append(src_path)
            custom_chars += content_len

    # Aggregate all custom code for content analysis
    custom_code = ""
    for i, src_path in enumerate(sources):
        if is_vendor_source(src_path):
            continue
        content = sources_content[i] if i < len(sources_content) else None
        if content:
            custom_code += content + "\n"

    # Look for high-value indicators in custom code
    secrets_found = []
    for pat, name in SECRET_PATTERNS:
        for m in pat.finditer(custom_code):
            redacted = m.group(0)[:8] + "..." + m.group(0)[-4:]
            secrets_found.append({"type": name, "redacted": redacted})

    # Internal URLs (URLs containing the source host or "api" path)
    host_base = source_host.replace("www.", "").split(".")[0] if source_host else ""
    internal_urls = []
    api_paths = []
    if custom_code:
        for url_match in re.findall(r"https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/._-]*)?", custom_code):
            if host_base and host_base in url_match.lower():
                internal_urls.append(url_match[:120])
            elif "/api/" in url_match or re.search(r"/v\d+/", url_match):
                internal_urls.append(url_match[:120])
        for path_match in re.findall(r"[\"']/(api/[a-zA-Z0-9/_-]+|v\d+/[a-zA-Z0-9/_-]+|admin/[a-zA-Z0-9/_-]+|graphql)[\"']", custom_code):
            api_paths.append("/" + path_match)
    internal_urls = list(set(internal_urls))[:20]
    api_paths = list(set(api_paths))[:20]

    # Classification logic
    has_secrets = bool(secrets_found)
    has_internal_endpoints = bool(internal_urls or api_paths)
    significant_custom_code = custom_chars >= 10000  # 10KB threshold

    if has_secrets:
        tier = "HIGH"
        reason = f"{len(secrets_found)} live-credential pattern(s) found in custom code — bounty-submittable"
    elif has_internal_endpoints and significant_custom_code:
        tier = "HIGH"
        reason = f"{len(internal_urls + api_paths)} internal endpoint(s) revealed + {custom_chars:,} chars of custom code"
    elif significant_custom_code:
        tier = "MEDIUM"
        reason = f"{custom_chars:,} chars of custom code revealed but no secrets/endpoints"
    elif custom_chars > 500:
        tier = "LOW"
        reason = f"only {custom_chars:,} chars of custom code (mostly vendor boilerplate)"
    else:
        tier = "LOW"
        reason = f"essentially no customer code ({len(custom_sources)} custom paths, {custom_chars} chars)"

    return {
        "tier": tier,
        "reason": reason,
        "bytes": len(body),
        "sources_total": len(sources),
        "custom_source_count": len(custom_sources),
        "vendor_source_count": len(vendor_sources),
        "custom_code_chars": custom_chars,
        "vendor_code_chars": vendor_chars,
        "secrets_found": secrets_found,
        "internal_urls": internal_urls,
        "api_paths": api_paths,
        "sample_custom_sources": custom_sources[:5],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=292)
    p.add_argument("--input", type=str, default=str(INPUT_LEDGER))
    args = p.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[FAIL] input not found: {in_path}")
        sys.exit(1)

    print(f"[+] Validating sourcemap content quality")
    print(f"[+] Input: {in_path}")
    print(f"[+] Output: {OUTPUT_LEDGER}")
    print(f"[+] Limit: {args.limit}")
    print()

    tier_counts = Counter()
    high_findings = []
    medium_findings = []

    OUTPUT_LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with open(in_path) as f, open(OUTPUT_LEDGER, "w") as out:
        for i, line in enumerate(f):
            if i >= args.limit:
                break
            try:
                entry = json.loads(line)
            except Exception:
                continue

            url = entry.get("url", "") or entry.get("matched-at", "")
            host = entry.get("host", "")
            if not url or not url.startswith("http"):
                continue

            print(f"  [{i+1:>3}/{args.limit}] {url[:75]}", end=" ", flush=True)
            body, status = fetch_sourcemap(url)
            if body is None:
                print(f"[fetch failed: {status}]", flush=True)
                continue

            analysis = analyze_sourcemap(body, source_host=host)
            tier = analysis["tier"]
            tier_counts[tier] += 1
            print(f"→ {tier} ({analysis['custom_code_chars']:,} chars custom, {len(analysis['secrets_found'])} secrets, {len(analysis['internal_urls'])} URLs)", flush=True)

            output_entry = {
                "source_url": url,
                "host": host,
                **analysis,
                "validated_at": datetime.now(timezone.utc).isoformat(),
            }
            out.write(json.dumps(output_entry) + "\n")
            out.flush()

            if tier == "HIGH":
                high_findings.append(output_entry)
            elif tier == "MEDIUM":
                medium_findings.append(output_entry)

    print()
    print("=" * 75)
    print("SOURCEMAP VALIDATION SUMMARY")
    print("=" * 75)
    total = sum(tier_counts.values())
    print(f"  Total validated: {total}")
    for tier in ["HIGH", "MEDIUM", "LOW", "EMPTY"]:
        n = tier_counts[tier]
        pct = (n * 100 // total) if total else 0
        print(f"  {tier:<10}  {n:>4}  ({pct}%)")
    print()

    if high_findings:
        print("🔴 HIGH — bounty-submittable findings:")
        for f in high_findings:
            print(f"  - {f['host']:<35} {f['source_url'][:70]}")
            print(f"    {f['reason']}")
            if f["secrets_found"]:
                for s in f["secrets_found"]:
                    print(f"      [{s['type']}] {s['redacted']}")
            if f["internal_urls"]:
                for u in f["internal_urls"][:3]:
                    print(f"      URL: {u}")
        print()

    if medium_findings:
        print(f"🟠 MEDIUM — {len(medium_findings)} hosts with custom code revealed (case-by-case):")
        for f in medium_findings[:10]:
            print(f"  - {f['host']:<35} {f['custom_code_chars']:,} chars custom code")
        if len(medium_findings) > 10:
            print(f"  ... and {len(medium_findings) - 10} more")
        print()

    print(f"[+] LOW tier ({tier_counts['LOW']}): courtesy-email only, no bounty expected")
    print(f"[+] Validated ledger: {OUTPUT_LEDGER}")


if __name__ == "__main__":
    main()
