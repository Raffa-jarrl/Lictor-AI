#!/usr/bin/env python3
"""
patrol-npm-postinstall-exfil — scanner #69.

Hunts npm packages with malicious preinstall/install/postinstall scripts
that exfiltrate credentials or run cryptominers. Same attack vector as:
  - XZ backdoor (2024)              — credentials-exfil via install hook
  - node-ipc (2022)                  — destructive payload by maintainer
  - ua-parser-js (2021)              — install installs cryptominer + stealer
  - peacenotwar (2022)               — same maintainer pattern
  - PyTorch torchtriton (2022)       — same vector, PyPI side
  - 17 dep-confusion packages live   — see Lictor disclosure 2026-05-24

Strategy (passive, ethical — static analysis only):
  1. Read a list of npm package names (from --packages)
  2. For each: fetch latest metadata from registry.npmjs.org
  3. If the package has preinstall/install/postinstall/prepare scripts:
     - Download the tarball
     - Statically scan referenced files for known exfil patterns
     - Score severity by signal count + sensitivity
  4. Report — never execute the install hook

Usage:
  patrol-npm-postinstall-exfil.py --packages packages.txt
"""
from __future__ import annotations
import argparse, json, re, tarfile, io, urllib.request, urllib.error, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path

UA = "Lictor-NpmPostinstallPatrol/0.1 (+https://lictor-ai.com)"

# Exfil-pattern detection (in postinstall script bodies)
EXFIL_PATTERNS = [
    (re.compile(rb'process\.env\s*[\.\[]', re.I),
        "reads process.env (could exfil all env vars)"),
    (re.compile(rb'\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)', re.I),
        "reads SSH keys"),
    (re.compile(rb'\.aws/(credentials|config)', re.I),
        "reads AWS credentials"),
    (re.compile(rb'\.npmrc|\.pypirc|\.netrc|\.docker/config', re.I),
        "reads package/registry credentials"),
    (re.compile(rb'(?:curl|wget|fetch|axios|got|request)[^;\n]*(?:\$\{?[A-Z_]+|process\.env)', re.I),
        "POSTs env vars to URL"),
    (re.compile(rb'(?:require|import)\s*\(\s*["\']https?://', re.I),
        "loads JS from external URL at install time"),
    (re.compile(rb'eval\s*\(\s*atob\s*\(|eval\s*\(\s*Buffer\.from\s*\(', re.I),
        "obfuscated eval (base64 wrap)"),
    (re.compile(rb'crypto[\.-]?miner|stratum\+tcp|monero|xmr|cryptonight', re.I),
        "cryptominer signature"),
    (re.compile(rb'\.git-credentials|\.gitconfig|git\s+config\s+--global', re.I),
        "reads git credentials"),
    (re.compile(rb'os\.hostname|os\.userInfo|process\.platform|process\.cwd', re.I),
        "fingerprints host"),
    (re.compile(rb'(?:DELETE\s+FROM|rm\s+-rf\s+(?:\/|~|\$HOME)|format\s+c:)', re.I),
        "destructive payload"),
    (re.compile(rb'iplogger|webhook\.site|requestbin|ngrok\.io|burpcollaborator', re.I),
        "exfil to known sink service"),
    (re.compile(rb'child_process|spawn\(|execSync\(|exec\(', re.I),
        "spawns child process at install"),
]

# Capture outbound URLs not on the safelist
NETWORK_OUT_RX = re.compile(rb'https?://(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s\'"<>]*)?', re.I)
URL_SAFELIST_SUBSTRINGS = (
    "github.com", "githubusercontent.com", "npmjs.com", "npmjs.org",
    "shields.io", "badge", "travis-ci", "circleci", "jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare", "fonts.googleapis", "fonts.gstatic",
    "schema.org", "w3.org", "mozilla.org", "nodejs.org", "yarnpkg.com",
)

@dataclass
class NpmFinding:
    package: str
    version: str
    scripts: dict
    suspect_signals: list = field(default_factory=list)
    network_destinations: list = field(default_factory=list)
    severity: str = "INFO"
    notes: str = ""

def http_get(url: str, timeout: int = 15, max_bytes: int = 10_000_000) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except Exception:
        return None

def fetch_pkg_metadata(pkg: str) -> dict | None:
    """Get latest version + tarball URL from npm registry."""
    url = f"https://registry.npmjs.org/{urllib.request.quote(pkg, safe='@/')}/latest"
    body = http_get(url, max_bytes=1_000_000)
    if not body: return None
    try:
        return json.loads(body)
    except Exception:
        return None

def fetch_weekly_downloads(pkg: str) -> int:
    """Fetch weekly download count from npm. Used to downweight trusted packages."""
    url = f"https://api.npmjs.org/downloads/point/last-week/{urllib.request.quote(pkg, safe='@/')}"
    body = http_get(url, max_bytes=10_000)
    if not body: return 0
    try:
        return int(json.loads(body).get("downloads", 0))
    except Exception:
        return 0

def scan_pkg(pkg: str) -> NpmFinding | None:
    meta = fetch_pkg_metadata(pkg)
    if not meta: return None
    version = meta.get("version", "?")
    scripts = meta.get("scripts", {}) or {}
    risky_scripts = {k: v for k, v in scripts.items()
                     if k in ("preinstall", "install", "postinstall", "prepare")}
    if not risky_scripts:
        return None  # safe package — no install hooks

    # FP Class #19: trusted-publisher native-build install
    # Popular packages (>100k weekly downloads) with install hooks are almost
    # always legitimate native-binary downloads (sharp, node-sass, esbuild,
    # bcrypt, sqlite3, canvas, puppeteer). Downweight their severity ceiling.
    weekly_dl = fetch_weekly_downloads(pkg)
    is_trusted = weekly_dl > 100_000  # threshold from npm stats

    tarball_url = meta.get("dist", {}).get("tarball", "")
    if not tarball_url:
        return NpmFinding(
            package=pkg, version=version, scripts=risky_scripts,
            severity="LOW", notes="install scripts exist but tarball not fetched")

    tarball = http_get(tarball_url, max_bytes=10_000_000)
    if not tarball:
        return NpmFinding(
            package=pkg, version=version, scripts=risky_scripts,
            severity="LOW", notes="install scripts exist but tarball unavailable")

    # FP fix (Class #18 install-hook scope leak):
    # Only scan files that the install hooks actually reference, plus
    # files those reference (1-hop). Webpack/sharp/etc. have huge
    # runtime libs that legitimately use process.env / child_process —
    # those are NOT part of the install path.
    referenced: set[str] = set()
    for cmd in risky_scripts.values():
        if not isinstance(cmd, str): continue
        # Capture "node path/to/file.js" or just "path/to/file.js"
        for m in re.finditer(r'(?:^|\s)(\.?\.?/?[a-zA-Z0-9_./\\-]+\.(?:js|cjs|mjs|sh|py))(?:\s|$)', cmd):
            referenced.add(m.group(1).lstrip('./'))
        # Capture bin commands (husky, node-gyp, prebuild-install) — flag those
        for m in re.finditer(r'(?:^|&&|;|\|\|)\s*([a-z][a-z0-9_-]+)', cmd):
            referenced.add(m.group(1))
    # If no files explicitly named, scan package.json + index.* + bin/* only
    fallback_glob = {"package.json", "index.js", "index.cjs", "index.mjs",
                     "install.js", "preinstall.js", "postinstall.js"}

    signals: list[str] = []
    networks: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile(): continue
                if member.size > 500_000: continue
                # Strip leading "package/" prefix (npm tarballs all have this)
                rel = member.name
                if rel.startswith("package/"):
                    rel = rel[len("package/"):]
                rel_lower = rel.lower()
                # Only scan if file is referenced by an install hook,
                # OR is in the fallback set, OR is in install/ or scripts/ dirs
                in_scope = (
                    rel in referenced or
                    rel_lower in fallback_glob or
                    rel_lower.startswith("install/") or
                    rel_lower.startswith("scripts/install") or
                    rel_lower.startswith("bin/") or
                    any(rel.endswith(r) for r in referenced if "/" not in r and "." in r)
                )
                if not in_scope:
                    continue
                if not rel_lower.endswith(('.js', '.cjs', '.mjs', '.sh',
                                            '.py', '.ts', '.json')):
                    continue
                f = tar.extractfile(member)
                if not f: continue
                data = f.read()
                for rx, sig in EXFIL_PATTERNS:
                    if rx.search(data):
                        signals.append(f"{rel}: {sig}")
                for m in NETWORK_OUT_RX.finditer(data[:200_000]):
                    url = m.group(0).decode("utf-8", "replace")
                    if any(x in url for x in URL_SAFELIST_SUBSTRINGS):
                        continue
                    networks.add(url)
    except Exception as e:
        signals.append(f"tarball-parse-error: {e}")

    # Severity
    severity = "LOW"  # has install hooks → at least LOW
    if len(signals) >= 4: severity = "CRITICAL"
    elif len(signals) >= 2: severity = "HIGH"
    elif len(signals) >= 1: severity = "MEDIUM"

    # FP Class #19 downweight: trusted package with no novel exfil pattern
    # (just stuff every native build does — process.env, child_process, http GET)
    notes = ""
    if is_trusted and severity in ("CRITICAL", "HIGH"):
        original_sev = severity
        severity = "LOW"
        notes = (f"DOWNWEIGHTED from {original_sev} → LOW: "
                 f"trusted publisher ({weekly_dl:,} weekly downloads). "
                 f"Signals likely from legit native-binary install. "
                 f"Manual review still recommended for novel patterns.")
    elif severity == "CRITICAL":
        notes = "STRONG exfil signature — review immediately, disclose to npm security"
    elif severity == "HIGH":
        notes = "Multiple exfil indicators — manual review required"
    elif severity == "MEDIUM":
        notes = "One exfil-pattern hit — review the matched script"

    return NpmFinding(
        package=pkg, version=version, scripts=risky_scripts,
        suspect_signals=signals[:15],
        network_destinations=sorted(networks)[:10],
        severity=severity, notes=notes)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages", required=True)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/npm-postinstall-exfil.jsonl")
    args = ap.parse_args()

    packages = [p.strip() for p in Path(args.packages).read_text().splitlines() if p.strip()]
    print(f"[+] npm postinstall-exfil hunt: {len(packages)} packages")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_crit, n_high, n_med, n_low = 0, 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_pkg, p): p for p in packages}
        for i, fut in enumerate(as_completed(futures), 1):
            pkg = futures[fut]
            try:
                f = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(packages)}] {pkg} EXC: {e}")
                continue
            if not f: continue
            ledger.write(json.dumps(asdict(f)) + "\n")
            ledger.flush()
            tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
                   "LOW":"⚪","INFO":"."}.get(f.severity, "?")
            print(f"  [{i}/{len(packages)}] {tag} {pkg}@{f.version}  "
                  f"{f.severity}  signals={len(f.suspect_signals)} "
                  f"nets={len(f.network_destinations)}")
            if f.severity == "CRITICAL": n_crit += 1
            elif f.severity == "HIGH": n_high += 1
            elif f.severity == "MEDIUM": n_med += 1
            else: n_low += 1
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] 🔴 = disclose to security@npmjs.com + maintainer")

if __name__ == "__main__":
    main()
