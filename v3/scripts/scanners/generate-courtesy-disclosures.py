#!/usr/bin/env python3
"""generate-courtesy-disclosures.py — Draft hygiene-level disclosure emails
for HIGH + MEDIUM tier sourcemap findings (excluding bounty-program targets).

WHAT IT DOES:
  Reads sourcemap-validated.jsonl, generates one .md draft per finding for
  the hosts that should get a courtesy email (no bounty expected, just
  hygiene note). Skips the 9 bounty-eligible hosts (those go through
  Immunefi/HackerOne instead).

ETHICAL:
  - Drafts written to disk; NOT auto-sent
  - User reviews + sends manually
  - Each draft follows the "I did NOT" footer pattern
  - No bounty ask, no sales pitch, no follow-up demand
  - Brief and professional
"""
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import re

INPUT_LEDGER  = Path.home() / "Lictor/v3/ledgers/sourcemap-validated.jsonl"
OUTPUT_DIR    = Path.home() / "Lictor/disclosures/courtesy-sourcemaps"

# Hosts that have known bug bounty programs — SKIP these (they go through proper channels)
BOUNTY_HOSTS = [
    "hashflow.com", "evaa.finance", "ember.so", "fanduel.com",
    "eth.verusbridge.io", "agni.finance", "aave.com", "compound.finance",
    "binance.us", "chain.link", "manta.network", "dashlane.com",
    # Add others as we discover them
]


def is_bounty_host(host):
    h = host.lower()
    return any(b in h for b in BOUNTY_HOSTS)


def extract_domain(host_or_url):
    """Extract clean domain for email + filename."""
    if host_or_url.startswith("http"):
        return urlparse(host_or_url).netloc.replace("www.", "")
    return host_or_url.replace("www.", "")


def render_email(entry):
    """Generate the disclosure email body in markdown."""
    host = entry.get("host", "")
    domain = extract_domain(host)
    url = entry.get("source_url", "")
    chars = entry.get("custom_code_chars", 0)
    urls_count = len(entry.get("internal_urls", []))
    tier = entry.get("tier", "?")

    # Description based on what was revealed
    if urls_count > 0 and entry.get("internal_urls"):
        sample_urls = entry["internal_urls"][:3]
        endpoint_note = (
            f"and reveals {urls_count} internal URL(s) including patterns like:\n"
            + "\n".join(f"  - `{u[:80]}`" for u in sample_urls)
            + "\n"
        )
    else:
        endpoint_note = "and reveals your application's internal file structure and function names."

    body = f"""# Courtesy disclosure — sourcemap exposure on {domain}

**Recipient:** `security@{domain}` (or generic `info@{domain}` if no security mailbox)
**Tier:** {tier}
**Source URL:** `{url}`
**Custom code revealed:** {chars:,} chars
**Internal URLs revealed:** {urls_count}
**Severity:** Informational / hygiene only — no bounty expected
**Auto-generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

---

## Email body

Subject: Sourcemap exposure hygiene note — {domain}

Hi security team at {domain},

I'm Raffa, founder of Lictor — an open-source security scanner
(https://lictor-ai.com, Apache 2.0).

While running external attack-surface scans, I noticed your production
bundle serves a JavaScript sourcemap file at:

  {url}

The sourcemap is {chars:,} characters of your custom application code
{endpoint_note}

This is information disclosure (not a critical vulnerability) — but it
does reveal internal application structure that's typically intended to
stay server-side in production. Standard remediation:

- **Webpack / Vite / Rollup:** set `sourcemap: false` in production build
  config (or `sourcemap: 'hidden'` to keep source maps for error tracking
  without serving them publicly)
- **Next.js:** set `productionBrowserSourceMaps: false` in `next.config.js`
- **CDN layer:** block `*.map` files at the CDN/edge

No bounty expected — sharing as a hygiene note. No response required.

I did NOT download or analyze the sourcemap content beyond the metadata
needed to validate the finding (file size, source path count, internal
URL extraction via regex). I did NOT attempt to use any URLs found inside,
log into your systems, enumerate your users, or share this finding
with any third party. All details stay private to your team.

— Raffa
   raffajarrl@gmail.com
   https://lictor-ai.com
   Open-source security disclosure programme

---

## What I did NOT do (audit trail)

- I did NOT download the full sourcemap content for analysis beyond
  metadata extraction
- I did NOT visit, probe, or interact with the URLs revealed inside
- I did NOT attempt to authenticate to any system at {domain}
- I did NOT share this finding with any third party, blog, or public
  channel
- I did NOT request payment, bounty, or compensation of any kind

This disclosure is governed by the Lictor Coordinated Vulnerability
Disclosure policy at https://lictor-ai.com/transparency.
"""
    return body


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] Reading {INPUT_LEDGER}")
    print(f"[+] Drafts → {OUTPUT_DIR}")
    print()

    seen_hosts = set()  # one draft per host (dedupe multi-sourcemap hosts)
    written = 0
    skipped_bounty = 0
    skipped_dup = 0
    skipped_low = 0

    with open(INPUT_LEDGER) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except Exception:
                continue

            tier = entry.get("tier", "")
            host = entry.get("host", "")

            if tier not in ("HIGH", "MEDIUM"):
                skipped_low += 1
                continue
            if is_bounty_host(host):
                skipped_bounty += 1
                continue
            domain = extract_domain(host)
            if domain in seen_hosts:
                skipped_dup += 1
                continue
            seen_hosts.add(domain)

            # Write the draft
            safe_name = re.sub(r"[^a-z0-9.-]", "_", domain.lower())
            out_path = OUTPUT_DIR / f"{tier.lower()}-{safe_name}.md"
            out_path.write_text(render_email(entry))
            written += 1
            print(f"  [{written:>3}] {tier:<6} {domain:<35} → {out_path.name}")

    print()
    print("=" * 70)
    print("COURTESY DRAFT SUMMARY")
    print("=" * 70)
    print(f"  Drafts written:           {written}")
    print(f"  Skipped (bounty-eligible): {skipped_bounty}  (those go through Immunefi/H1)")
    print(f"  Skipped (duplicate host): {skipped_dup}")
    print(f"  Skipped (LOW/EMPTY tier): {skipped_low}")
    print()
    print(f"[+] Drafts saved to: {OUTPUT_DIR}")
    print(f"[+] Review each before sending. NONE auto-sent.")


if __name__ == "__main__":
    main()
