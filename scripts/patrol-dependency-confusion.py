#!/usr/bin/env python3
"""
patrol-dependency-confusion — scanner #49.

Hunts the PayPal/Uber pattern: internal package names (e.g.
`@company/internal-utils`, `company-private-sdk`) referenced in public
configs but NEVER published to the public npm/PyPI registry. An attacker
can publish a malicious package with the same name and higher version,
and the victim's build will silently pull the attacker's package on the
next `npm install` / `pip install`.

Top-tier discovery pattern (per HackerOne TOPRCE analysis):
  - PayPal — internal libraries installable from public registry  $30,000
  - Uber   — same pattern                                          $9,000
  - Microsoft, Apple, Yelp, etc. all had this — typical $10K-$30K

Method (ETHICAL — Lictor never publishes the squat package):
  1. GitHub Code Search for `package.json`, `requirements.txt`,
     `Gemfile`, `composer.json`, etc. under bounty-program orgs.
  2. For each manifest, extract dependency names.
  3. For each scoped-private-looking name (matches our heuristics),
     check: is this name CLAIMED on the public registry?
  4. If NOT claimed → squat candidate → report to the org.
  5. We DO NOT publish the squat — only verify the name is unclaimed.

Bounty: report to the affected org so they can register the name
defensively (the standard remediation). $5K-$30K typical.

Usage:
  patrol-dependency-confusion.py --orgs github-orgs.txt --ledger dep-confusion.jsonl
"""
from __future__ import annotations
import argparse, base64, json, re, subprocess, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-DepConfusionPatrol/0.1 (+https://lictor-ai.com)"

# Heuristics for "looks private/internal"
# - npm scoped: @<org>/anything
# - prefix patterns: company-internal-*, internal-*, private-*, <org>-*
PRIVATE_HEURISTIC_NPM = re.compile(r'^@([a-z0-9][a-z0-9-]+)/[a-z0-9][\w.-]*$', re.IGNORECASE)
INTERNAL_PREFIX = re.compile(r'^(internal|private|corp|secret|company)[-_]', re.IGNORECASE)

# Known-public scopes we should NOT flag (popular OSS scopes)
KNOWN_PUBLIC_SCOPES = {
    "babel", "types", "vue", "angular", "nestjs", "nrwl", "playwright",
    "storybook", "ng-bootstrap", "tanstack", "vitejs", "rollup", "swc",
    "fortawesome", "mui", "material-ui", "emotion", "testing-library",
    "react-native-community", "react-router", "redux", "reduxjs", "next",
    "supabase", "sveltejs", "remix-run", "trpc", "tailwindcss",
    "shopify", "stripe", "sentry", "octokit", "google-cloud", "aws-sdk",
    "azure", "firebase", "expo", "auth0", "okta", "datadog",
}

@dataclass
class SquatCandidate:
    org: str
    repo: str
    manifest_path: str
    package_name: str
    ecosystem: str         # "npm", "pypi", "rubygems", "composer"
    public_registry_status: str  # "unclaimed", "claimed_by_other", "claimed_by_org"
    manifest_url: str = ""
    notes: str = ""

def gh_code_search(query: str, max_pages: int = 2) -> list:
    results, seen = [], set()
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
                 "--jq", ".items"], stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
        except Exception:
            break
        if not items: break
        for it in items:
            key = (it["repository"]["full_name"], it["path"])
            if key in seen: continue
            seen.add(key)
            results.append(it)
        time.sleep(2)
    return results

def gh_raw_file(repo: str, path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=15)
        return base64.b64decode(out.decode().strip().replace("\n","")).decode("utf-8","replace")
    except Exception:
        return None

def extract_npm_deps(content: str) -> list[tuple[str, str]]:
    """Return list of (name, specifier) tuples. Specifier preserved verbatim
    so the dep-confusion gate can filter non-registry resolvers."""
    try: j = json.loads(content)
    except Exception: return []
    out = []
    for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        d = j.get(k) or {}
        if isinstance(d, dict):
            for name, spec in d.items():
                out.append((name, str(spec) if spec is not None else ""))
    return out

def extract_pypi_deps(content: str) -> list[tuple[str, str]]:
    out = []
    for line in content.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"): continue
        # PyPI rarely uses non-registry specifiers, but capture the spec
        # too for symmetry. Format examples:
        #   foo==1.0
        #   foo @ git+https://github.com/...    ← FP class
        #   -e git+...                          ← FP class (caught by startswith('-'))
        #   foo[extra]>=1.0
        m = re.match(r'^([A-Za-z0-9._-]+)\s*(.*)$', line)
        if m:
            name = m.group(1).lower()
            spec = m.group(2).strip()
            out.append((name, spec))
    return out

# ─── FP Class #23 gate: non-registry specifiers don't resolve via public npm
#
# Patterns that REDIRECT npm install away from the public registry:
#   workspace:*  workspace:^  workspace:1.0  → pnpm/yarn monorepo internal
#   github:org/repo  github:org/repo#sha     → direct GitHub fetch
#   git+https://...  git://...  git@...      → direct git fetch
#   file:./path  file:foo.tgz                → local filesystem
#   link:./path  portal:./path               → local filesystem (symlink)
#   http://...  https://...                  → direct URL fetch (tarball)
#   npm:other-package@1.0                    → npm alias (resolves a DIFFERENT package name)
#
# If a manifest declares "@scope/name": "<any of the above>", a name squat
# on @scope/name at registry.npmjs.org CANNOT be resolved against this
# manifest. Dep-confusion finding is a false positive for this entry.
NON_REGISTRY_SPECIFIER_PREFIXES = (
    'workspace:', 'github:', 'git+', 'git://', 'git@',
    'file:', 'link:', 'portal:',
    'http://', 'https://',
    'npm:',  # alias to a different package
)

def is_registry_resolvable_specifier(specifier: str) -> bool:
    """Return True if the specifier WILL resolve against the public registry.
    Return False if it's a non-registry path (FP Class #23 — git/file/workspace)."""
    if not specifier: return True   # missing spec → registry default behavior
    spec_lower = specifier.strip().lower()
    for prefix in NON_REGISTRY_SPECIFIER_PREFIXES:
        if spec_lower.startswith(prefix):
            return False
    return True

def looks_private(name: str, org_hint: str = "") -> bool:
    m = PRIVATE_HEURISTIC_NPM.match(name)
    if m:
        scope = m.group(1).lower()
        if scope in KNOWN_PUBLIC_SCOPES: return False
        return True
    if INTERNAL_PREFIX.match(name): return True
    if org_hint and name.lower().startswith(org_hint.lower() + "-"): return True
    return False

def check_npm(name: str) -> str:
    """Return 'unclaimed' / 'claimed_by_other' (we treat as same-existing for now)."""
    url = f"https://registry.npmjs.org/{urllib.request.quote(name, safe='@/')}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status == 200: return "claimed_by_other"
            return "unknown"
    except urllib.error.HTTPError as e:
        if e.code == 404: return "unclaimed"
        return "unknown"
    except Exception:
        return "unknown"

def check_pypi(name: str) -> str:
    url = f"https://pypi.org/pypi/{name.lower()}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status == 200: return "claimed_by_other"
            return "unknown"
    except urllib.error.HTTPError as e:
        if e.code == 404: return "unclaimed"
        return "unknown"
    except Exception:
        return "unknown"

def process_manifest(item, org_hint: str) -> list[SquatCandidate]:
    repo = item["repository"]["full_name"]
    path = item["path"]
    url = item.get("html_url", "")
    content = gh_raw_file(repo, path)
    if not content: return []

    out = []
    if path.endswith("package.json"):
        deps = extract_npm_deps(content)   # list of (name, spec) tuples
        ecosystem = "npm"
        checker = check_npm
    elif path.endswith("requirements.txt") or path.endswith("pyproject.toml"):
        deps = extract_pypi_deps(content)
        ecosystem = "pypi"
        checker = check_pypi
    else:
        return []

    # Dedup on name, but keep FIRST specifier seen (matters for FP gate)
    seen_names: dict[str, str] = {}
    for name, spec in deps:
        if name not in seen_names:
            seen_names[name] = spec

    for name, specifier in seen_names.items():
        if not looks_private(name, org_hint): continue
        # ─── FP Class #23 gate ───
        # Skip non-registry specifiers (github:, workspace:, file:, link:, etc.)
        # Even if the name is unclaimed on npm, this manifest doesn't resolve
        # through the registry, so a squat is impossible.
        if not is_registry_resolvable_specifier(specifier):
            continue
        time.sleep(0.5)  # be nice to registries
        status = checker(name)
        if status == "unclaimed":
            out.append(SquatCandidate(
                org=org_hint or repo.split("/")[0], repo=repo, manifest_path=path,
                package_name=name, ecosystem=ecosystem,
                public_registry_status=status, manifest_url=url,
                notes=(f"Private-looking name not registered on public registry "
                       f"→ squat candidate (specifier: '{specifier[:40]}')")))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orgs", required=True,
                     help="newline-delimited GitHub orgs (e.g. paypal, uber, shopify)")
    ap.add_argument("--threads", type=int, default=4,
                     help="GitHub rate limit forces low concurrency")
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/dep-confusion.jsonl")
    ap.add_argument("--per-org-max", type=int, default=50)
    args = ap.parse_args()

    orgs = [o.strip() for o in Path(args.orgs).read_text().splitlines() if o.strip()]
    print(f"[+] Hunting dependency-confusion squat candidates across {len(orgs)} orgs")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    n_total = 0
    with open(args.ledger, "a") as ledger:
        for org in orgs:
            print(f"\n[+] Org: {org}")
            queries = [
                f'org:{org} filename:package.json',
                f'org:{org} filename:requirements.txt',
            ]
            manifests = []
            for q in queries:
                items = gh_code_search(q, max_pages=2)
                for it in items:
                    manifests.append(it)
                    if len(manifests) >= args.per_org_max: break
                if len(manifests) >= args.per_org_max: break
            print(f"    {len(manifests)} manifests to inspect")
            for i, it in enumerate(manifests, 1):
                try:
                    hits = process_manifest(it, org)
                except Exception as e:
                    print(f"    [{i}/{len(manifests)}] EXC: {e}")
                    continue
                for h in hits:
                    ledger.write(json.dumps(asdict(h)) + "\n")
                    ledger.flush()
                    n_total += 1
                    print(f"    🔴 SQUAT-CANDIDATE  {h.ecosystem}:{h.package_name}  in {h.repo}/{h.manifest_path}")
                time.sleep(0.8)

    print(f"\n[+] Done. {n_total} dependency-confusion squat candidates → {args.ledger}")
    print(f"[+] Each is reportable to the affected org for defensive registration.")
    print(f"[+] DO NOT publish any squat packages — that's malicious. Report only.")

if __name__ == "__main__":
    main()
