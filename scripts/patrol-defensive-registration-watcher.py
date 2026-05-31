#!/usr/bin/env python3
"""
patrol-defensive-registration-watcher — alert when an unclaimed package gets
registered (= our dep-confusion bounty window closes, OR the org defensively
acted on our disclosure).

Reads a JSON config of {package_name: ecosystem} and polls npm/PyPI registries.
Compares to last-known state in a state file. On any change, appends to alert log.

Designed to run as a cron (every 6h):
   0 */6 * * * /opt/homebrew/bin/python3 /Users/raffa/Lictor/scripts/patrol-defensive-registration-watcher.py

Output:
  - state file (~/.lictor/dep-confusion-watcher-state.json)
  - alert log (~/.lictor/dep-confusion-watcher-alerts.jsonl)
  - macOS notification on state change (osascript)
"""
from __future__ import annotations
import json, time, urllib.request, urllib.error, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-DefRegWatcher/0.1 (+https://lictor-ai.com)"
STATE_FILE = Path.home() / ".lictor" / "dep-confusion-watcher-state.json"
ALERT_LOG = Path.home() / ".lictor" / "dep-confusion-watcher-alerts.jsonl"
CONFIG_FILE = Path.home() / ".lictor" / "dep-confusion-watcher-config.json"

# Default config — the 17 packages from our current disclosure queue
DEFAULT_CONFIG = {
    "npm": [
        "@actions/artifact-legacy",
        "@github-ui/storybook-config",
        "@internal/backstage-plugin-soundcheck-backend-module-branch",
        "@reddit/eslint-plugin-i18n-shreddit",
        "@reddit/faceplate-docs",
        "@reddit/eslint-plugin-no-unsafe",
        "@atlaskit/extract-react-types",
        "@atlassiansox/analytics-web-client",
        "@cloudflare/workers-tsconfig",
        "@cloudflare/mock-npm-registry",
        "@cloudflare/workflows-shared",
        "@modelcontextprotocol/specification",
        "@lwc/test-utils-lwc-internals",
        "@lwc/eslint-plugin-lwc-internal",
        "@cds/figma-api",
        "@hashicorp/vault-client-typescript",
        "@hashicorp/github-actions-core",
        "@hashicorp-internal/vault-reporting",
        "@css-blocks/test-utils",
    ],
    "pypi": [],
}

def check_npm(pkg: str, timeout: int = 10) -> tuple[str, dict]:
    """Return ('unclaimed' | 'claimed' | 'error', metadata)"""
    url = f"https://registry.npmjs.org/{urllib.request.quote(pkg, safe='@/')}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return "error", {"http_status": r.status}
            data = json.loads(r.read(64 * 1024))
            maint = (data.get("maintainers") or [{}])[0].get("name", "?")
            modified = data.get("time", {}).get("modified", "")
            versions = list(data.get("versions", {}).keys())
            return "claimed", {
                "maintainer": maint,
                "modified": modified,
                "versions": versions[-3:],  # last 3 versions
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "unclaimed", {}
        return "error", {"http_status": e.code}
    except Exception as e:
        return "error", {"exception": str(e)}

def check_pypi(pkg: str, timeout: int = 10) -> tuple[str, dict]:
    url = f"https://pypi.org/pypi/{pkg.lower()}/json"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return "error", {"http_status": r.status}
            data = json.loads(r.read(64 * 1024))
            return "claimed", {
                "author": data.get("info", {}).get("author", "?"),
                "version": data.get("info", {}).get("version", ""),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "unclaimed", {}
        return "error", {"http_status": e.code}
    except Exception as e:
        return "error", {"exception": str(e)}

def macos_notify(title: str, message: str):
    """Pop a macOS notification."""
    try:
        subprocess.run([
            "osascript", "-e",
            f'display notification "{message}" with title "{title}"'
        ], check=False, capture_output=True, timeout=5)
    except Exception:
        pass

def main():
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)

    # Load or initialize config
    if CONFIG_FILE.exists():
        config = json.loads(CONFIG_FILE.read_text())
    else:
        config = DEFAULT_CONFIG
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

    # Load previous state
    prev_state = {}
    if STATE_FILE.exists():
        try:
            prev_state = json.loads(STATE_FILE.read_text())
        except Exception:
            prev_state = {}

    now = datetime.now(timezone.utc).isoformat()
    new_state = {}
    changes = []

    checker = {"npm": check_npm, "pypi": check_pypi}
    for ecosystem, pkgs in config.items():
        if ecosystem not in checker: continue
        for pkg in pkgs:
            time.sleep(0.5)
            status, meta = checker[ecosystem](pkg)
            key = f"{ecosystem}:{pkg}"
            new_state[key] = {"status": status, "meta": meta, "checked_at": now}
            prev = prev_state.get(key, {})
            if prev.get("status") and prev["status"] != status:
                # State change!
                change = {
                    "key": key, "from": prev["status"], "to": status,
                    "changed_at": now, "new_meta": meta,
                }
                changes.append(change)
                print(f"  🔔 STATE CHANGE: {key}  {prev['status']} → {status}")
                if meta: print(f"     {json.dumps(meta)}")
            else:
                print(f"  {status:9s}  {key}")

    # Persist
    STATE_FILE.write_text(json.dumps(new_state, indent=2))

    if changes:
        # Append to alert log
        with ALERT_LOG.open("a") as f:
            for c in changes:
                f.write(json.dumps(c) + "\n")
        # macOS notify
        n = len(changes)
        macos_notify(
            "Lictor: dep-confusion state change",
            f"{n} package(s) changed status. See {ALERT_LOG}"
        )
        # Exit nonzero so cron can email
        print(f"\n{len(changes)} STATE CHANGE(S). See {ALERT_LOG}")
        sys.exit(0)  # 0 to avoid cron noise; check alert log
    else:
        print(f"\n[+] No state changes. All {len(new_state)} packages in expected state.")

if __name__ == "__main__":
    main()
