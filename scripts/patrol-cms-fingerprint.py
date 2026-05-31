#!/usr/bin/env python3
"""
patrol-cms-fingerprint — outdated CMS detector (Joomla / Drupal / Magento / TYPO3 / OpenCart).

WordPress is covered by patrol-wordpress-vulns.py. This catches the other
common CMSs SMBs use:

  Joomla   → /administrator/ + /index.php?option=com_ + version in HTML
  Drupal   → /user/login + ?q=user/login + version in /CHANGELOG.txt
  Magento  → /admin/ + skin/frontend + version in /magento_version
  TYPO3    → /typo3/ + TYPO3 in meta + /typo3_src/...
  OpenCart → admin/ + index.php?route= + version in /admin/index.php
  PrestaShop → /admin-*/ + presta-* assets + version in HTML

Flags when version is outdated (cutoffs per CMS major version):
  Joomla   < 4.4 (current 5.x) → MEDIUM
  Drupal   < 10  (current 11.x) → MEDIUM
  Magento  < 2.4.6 (current 2.4.7) → HIGH
  TYPO3    < 12   (current 13) → MEDIUM

Just detection — does NOT exploit any known CVE.

Usage:
  patrol-cms-fingerprint.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-CMSFingerprint/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


@dataclass
class CMSFinding:
    host: str
    cms: str
    version: str
    is_outdated: bool
    evidence_url: str
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def http(url, timeout=5, max_bytes=20000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(max_bytes)
    except urllib.error.HTTPError as e:
        try: body = e.read(max_bytes)
        except: body = b""
        return e.code, dict(e.headers) if e.headers else {}, body
    except Exception:
        return 0, {}, b""


def detect_joomla(host: str) -> tuple[str, str, str] | None:
    """Returns (version, evidence_url, raw_indicator) or None."""
    s, _, body = http(f"https://{host}/")
    if b"Joomla" in body or b"/templates/" in body:
        # Try /administrator/manifests/files/joomla.xml
        s2, _, b2 = http(f"https://{host}/administrator/manifests/files/joomla.xml")
        if s2 == 200:
            m = re.search(rb"<version>([^<]+)</version>", b2)
            if m: return (m.group(1).decode(), f"https://{host}/administrator/manifests/files/joomla.xml", "manifest")
        # Try meta generator
        m = re.search(rb'<meta name="generator" content="Joomla! ([0-9.]+)', body)
        if m: return (m.group(1).decode(), f"https://{host}/", "meta_generator")
        if b"Joomla" in body[:5000]:
            return ("unknown", f"https://{host}/", "joomla_keyword_in_body")
    return None


def detect_drupal(host: str):
    s, h, body = http(f"https://{host}/")
    headers_lower = {k.lower(): v for k, v in h.items()}
    if "drupal" in headers_lower.get("x-generator", "").lower() or b"Drupal" in body[:5000]:
        # CHANGELOG.txt usually has version
        s2, _, b2 = http(f"https://{host}/CHANGELOG.txt")
        if s2 == 200:
            m = re.search(rb"Drupal\s+(\d+\.\d+)", b2)
            if m: return (m.group(1).decode(), f"https://{host}/CHANGELOG.txt", "changelog")
        # Check X-Generator header
        if "drupal" in headers_lower.get("x-generator", "").lower():
            return (headers_lower["x-generator"], f"https://{host}/", "x_generator_header")
        return ("unknown", f"https://{host}/", "drupal_keyword")
    return None


def detect_magento(host: str):
    s, _, body = http(f"https://{host}/")
    if b"Magento" in body or b"/skin/frontend/" in body or b"Mage.Cookies" in body:
        # /magento_version often returns version (Magento 2.x)
        s2, _, b2 = http(f"https://{host}/magento_version")
        if s2 == 200 and len(b2) < 100:
            return (b2.decode("utf-8", "replace").strip(), f"https://{host}/magento_version", "magento_version")
        return ("unknown", f"https://{host}/", "magento_keyword")
    return None


def detect_typo3(host: str):
    s, _, body = http(f"https://{host}/")
    if b"TYPO3" in body or b"/typo3conf/" in body or b"typo3temp" in body:
        s2, _, b2 = http(f"https://{host}/typo3/")
        if s2 in (200, 302) and b"TYPO3" in b2:
            return ("unknown", f"https://{host}/typo3/", "typo3_admin_visible")
        return ("unknown", f"https://{host}/", "typo3_keyword")
    return None


def detect_opencart(host: str):
    s, _, body = http(f"https://{host}/")
    if b"OpenCart" in body or b"catalog/view/javascript" in body:
        # Check admin path
        s2, _, b2 = http(f"https://{host}/admin/")
        if s2 == 200 and b"OpenCart" in b2:
            return ("unknown", f"https://{host}/admin/", "opencart_admin")
        return ("unknown", f"https://{host}/", "opencart_keyword")
    return None


def detect_prestashop(host: str):
    s, _, body = http(f"https://{host}/")
    if b"PrestaShop" in body or b"prestashop" in body:
        return ("unknown", f"https://{host}/", "prestashop_keyword")
    return None


def is_outdated(cms: str, version: str) -> bool:
    """Cutoff per CMS — TRUE if older than recommended."""
    if version == "unknown": return False
    try:
        if cms == "Joomla":
            major, minor = map(int, version.split(".")[:2])
            return major < 4 or (major == 4 and minor < 4)
        if cms == "Drupal":
            major = int(version.split(".")[0])
            return major < 10
        if cms == "Magento":
            parts = version.split(".")
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2] if len(parts)>2 else 0)
            return major < 2 or (major == 2 and minor < 4) or (major == 2 and minor == 4 and patch < 6)
    except Exception: pass
    return False


CMS_DETECTORS = [
    ("Joomla", detect_joomla),
    ("Drupal", detect_drupal),
    ("Magento", detect_magento),
    ("TYPO3", detect_typo3),
    ("OpenCart", detect_opencart),
    ("PrestaShop", detect_prestashop),
]


def scan_host(host: str) -> list[CMSFinding]:
    findings = []
    for cms_name, detector in CMS_DETECTORS:
        try:
            result = detector(host)
        except Exception: result = None
        if not result: continue
        version, evidence_url, raw_indicator = result
        outdated = is_outdated(cms_name, version)
        sev = "HIGH" if outdated else "MEDIUM"
        if version == "unknown":
            sev = "MEDIUM"  # can't tell, but CMS is detected
        findings.append(CMSFinding(
            host=host, cms=cms_name, version=version,
            is_outdated=outdated, evidence_url=evidence_url,
            severity=sev,
            notes=f"{cms_name} {version} detected via {raw_indicator}{'  (OUTDATED)' if outdated else ''}",
        ))
        break  # one CMS detection per host
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=3000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/cms-fingerprint.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] cms-fingerprint — {len(hosts)} hosts")
    n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: results = fut.result(timeout=60)
            except: results = []
            for f in results:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.severity == "HIGH": n_high += 1
                else: n_med += 1
                tag = "🟠" if f.severity == "HIGH" else "🟡"
                print(f"  [{i}/{len(hosts)}] {tag} {f.cms:12s} {f.version:10s} {f.host}{'  OUTDATED' if f.is_outdated else ''}")
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] high={n_high} med={n_med}")
    print(f"\n[+] Done. HIGH(outdated)={n_high} MEDIUM(detected)={n_med}")


if __name__ == "__main__":
    main()
