#!/usr/bin/env python3
"""
Lictor v3 — device fingerprinting scanner v4 (HTTP-only, NEVER auth)

REBUILT THRICE 2026-05-21:
  v1: substring-matched vendor names in HTML body → 96/96 FPs
  v2: path probes + CDN pre-filter (Server header) → 2 FPs from
      Akamai-stripped Server + SPA wildcards
  v3: extra CDN signals + SPA-wildcard canary → 1 FP from
      fareharbor.com (WordPress with catch-all serving 4MB page on
      /css/pfSense.css path)
  v4: content-type sanity + max-body-size + per-path nonsense canary
      + drop loose "server is nginx" patterns (too many WordPress
      sites match)

v4 design — STRICT multi-signal verification:
  1. CDN PRE-FILTER (CF-RAY, X-Akamai-*, X-Served-By, X-Amz-CF-*,
     X-Vercel-*, Via varnish/cloudfront/akamai/fastly, Server
     substring match) — skip CDN-fronted hosts entirely
  2. SPA-WILDCARD CANARY — probe /__lictor_canary_<random>; if 200,
     host serves SPA wildcards; skip
  3. PROBE device-specific paths with strict gates:
     a. Probe body MUST DIFFER from root body (anti-SPA wildcard)
     b. Probe body MUST be <100KB (devices return small login pages)
     c. Probe content-type MUST match expected (text/css for css,
        text/html for html, application/json for json APIs) — defeats
        CMS catch-alls serving HTML for any path
  4. REQUIRE >=2 confirming signals
  5. NEVER attempt credentials

Goal: 0 false positives at internet scale. Better to miss real devices
than report fictional ones.

Detects (high-confidence only):
  - Hikvision IP cameras (App-webs Server + /doc/page/login.asp)
  - Dahua cameras / DVRs (RPC2_Login + Account1 path)
  - Axis cameras (axis-cgi paths + AXIS auth realm)
  - pfSense / OPNsense (specific HTML structure + csrfMagic token)
  - Synology DSM / QNAP QTS (vendor-specific paths)
  - Mikrotik RouterOS (Mikrotik HttpProxy header)
  - F5 BIG-IP (BIG-IP Server header + /tmui/login.jsp)
  - Citrix NetScaler (NetScaler Server header)
  - FortiGate (specific login.html structure)
  - Jenkins (X-Jenkins header + Hudson cookie)
  - phpMyAdmin / Grafana / Kibana (specific JSON API responses)

Usage:
  python3 patrol-device-fingerprint.py --corpus PATH --max-domains N
  python3 patrol-device-fingerprint.py example.com  # single target

Output: ~/Lictor/v3/ledgers/device-fingerprint-candidates.jsonl
"""
from __future__ import annotations
import argparse, hashlib, ipaddress, json, re, secrets, socket, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-DeviceFingerprint/0.4 (+https://lictor-ai.com)"


def _resolves_to_private(host: str) -> bool:
    """Skip hosts that resolve to loopback/private IPs — TCP would hit
    our own machine. Saw baoliyun.com → 127.0.0.1 in port-exposure scan."""
    try:
        ips = socket.getaddrinfo(host, None, socket.AF_INET)
    except Exception:
        return True
    for _, _, _, _, sockaddr in ips:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except Exception:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
    return False
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "device-fingerprint-candidates.jsonl"
MAX_PROBE_BODY = 100_000  # 100 KB — devices return small login pages

CDN_SERVER_BLOCKLIST = {
    "cloudflare", "amazons3", "amazon s3", "cloudfront", "fastly",
    "akamai", "akamaighost", "akamainetstorage", "vercel", "netlify",
    "github.com", "squarespace", "wix.com", "wpx-cloud", "imperva",
    "sucuri", "incapsula", "ddos-guard", "qrator", "barracuda",
    "atlassianedge", "shopify", "esa", "istio-envoy",
}

# Probes: (path, body_regex_or_None, response_header_regex_or_None,
#         expected_content_type_prefix_or_None)
# - body_regex: if set, must match against response body to credit signal
# - header_regex: if set, must match against "Key: Value" in response headers
# - expected_content_type: if set, response Content-Type MUST start with this
#   (defeats CMS catch-alls that serve text/html for any path)
#
# Signal counting:
# - Probe gives +1 signal if: response status in (200, 401), body differs
#   from root body, body <100KB, content-type matches (if specified), AND
#   either body_regex matches OR header_regex matches OR (both are None AND
#   the path itself is device-only — like Dahua's /current_config/Account1)
# - server_pattern adds +1 signal if Server header matches (only set for
#   device-SPECIFIC server values like "BIG-IP" or "Mikrotik HttpProxy",
#   never for generic "nginx" or "Apache")
# - auth_realm_pattern adds +1 signal if WWW-Authenticate realm matches
# - title_pattern adds +1 signal if root page <title> matches

DEVICE_PROBES = [
    {
        "vendor": "Hikvision IP Camera",
        "severity": "critical",
        "probes": [
            ("/doc/page/login.asp", re.compile(r"hikvision|web ?service|loginpage|/scripts/login\.js", re.I), None, "text/html"),
            ("/ISAPI/System/deviceInfo", None, re.compile(r"App-webs|Hikvision", re.I), None),
        ],
        "server_pattern": re.compile(r"App-webs|Hikvision-Webs", re.I),
        "impact": "Hikvision cameras have known default-credential history (admin/12345, admin/admin) and multiple CVEs. Banner-grab alone is enough to alert the owner.",
    },
    {
        "vendor": "Dahua IP Camera/DVR",
        "severity": "critical",
        "probes": [
            ("/RPC2_Login", None, re.compile(r"DH-|Dahua", re.I), None),
            ("/current_config/Account1", None, None, None),
        ],
        "server_pattern": re.compile(r"Dahua|DH-|^Webs/", re.I),
        "impact": "Dahua cameras / DVRs have default-credential history and CVE-rich firmware.",
    },
    {
        "vendor": "Axis IP Camera",
        "severity": "high",
        "probes": [
            ("/axis-cgi/usergroup.cgi", None, None, None),
            ("/view/view.shtml", re.compile(r"axis|/axis-cgi/", re.I), None, "text/html"),
        ],
        "server_pattern": re.compile(r"AxisOnvif|Axis-Webs|GoAhead", re.I),
        "auth_realm_pattern": re.compile(r"AXIS", re.I),
        "impact": "Axis cameras — older firmware shipped with root/pass default; current models require setup but exposure to internet is best avoided.",
    },
    {
        "vendor": "pfSense Firewall",
        "severity": "high",
        "probes": [
            ("/", re.compile(r"(login\.php|csrfMagic).*pfSense|<title>pfSense|/themes/pfSense", re.I), None, "text/html"),
            ("/index.php?logout=1", re.compile(r"pfSense|csrfMagic", re.I), None, "text/html"),
        ],
        "impact": "pfSense firewall admin UI exposed — should be VPN-only.",
    },
    {
        "vendor": "OPNsense Firewall",
        "severity": "high",
        "probes": [
            ("/", re.compile(r"<title>OPNsense|opnsense_logo|opn-?sense", re.I), None, "text/html"),
            ("/api/diagnostics/system/system_information", None, None, "application/json"),
        ],
        "impact": "OPNsense firewall admin UI exposed — should be VPN-only.",
    },
    {
        "vendor": "Mikrotik RouterOS",
        "severity": "high",
        "probes": [
            ("/", re.compile(r"RouterOS|Mikrotik|<title>RouterOS", re.I), re.compile(r"Mikrotik HttpProxy", re.I), "text/html"),
            ("/webfig/", None, None, "text/html"),
        ],
        "server_pattern": re.compile(r"Mikrotik HttpProxy", re.I),
        "impact": "Mikrotik RouterOS admin exposed — CVE-2018-14847 (Winbox) and others; default admin/blank common on older firmware.",
    },
    {
        "vendor": "Synology DSM",
        "severity": "high",
        "probes": [
            ("/webman/index.cgi", re.compile(r"synology|diskstation|dsm", re.I), None, "text/html"),
            ("/webapi/auth.cgi?api=SYNO.API.Info&version=1&method=query", None, None, "application/json"),
        ],
        "title_pattern": re.compile(r"Synology|DSM|DiskStation", re.I),
        "impact": "Synology DSM exposed — CVE-rich (DSM RCE history), ransomware target.",
    },
    {
        "vendor": "QNAP QTS",
        "severity": "high",
        "probes": [
            ("/cgi-bin/qts.cgi", None, None, None),
            ("/cgi-bin/authLogin.cgi", None, re.compile(r"QTS|QNAP", re.I), None),
        ],
        "title_pattern": re.compile(r"QNAP|QTS|QuTS", re.I),
        "impact": "QNAP QTS exposed — QLocker ransomware target, many CVEs.",
    },
    {
        "vendor": "F5 BIG-IP",
        "severity": "high",
        "probes": [
            ("/tmui/login.jsp", re.compile(r"BIG-?IP|F5 Networks|tmui_data", re.I), None, "text/html"),
            ("/mgmt/tm/sys/version", None, re.compile(r"BIG-?IP|F5", re.I), "application/json"),
        ],
        "server_pattern": re.compile(r"BIG-?IP|BigIP", re.I),
        "impact": "F5 BIG-IP exposed — CVE-2020-5902 history; even banner-grab is enough to alert owner.",
    },
    {
        "vendor": "Citrix NetScaler/ADC",
        "severity": "high",
        "probes": [
            ("/vpn/index.html", re.compile(r"NetScaler|Citrix Gateway", re.I), None, "text/html"),
            ("/nitro/v1/config/nsversion", None, None, "application/json"),
        ],
        "server_pattern": re.compile(r"NetScaler|Citrix-?ADC", re.I),
        "impact": "Citrix NetScaler/ADC exposed — CVE-2019-19781 (Shitrix), CVE-2023-3519 history.",
    },
    {
        "vendor": "Fortinet FortiGate",
        "severity": "high",
        "probes": [
            ("/login", re.compile(r"FortiGate|FortiOS|/fgt_lang/", re.I), None, "text/html"),
            ("/remote/login", re.compile(r"FortiGate|sslvpn", re.I), None, "text/html"),
        ],
        "server_pattern": re.compile(r"FortiGate|FortiWeb|xxxxxxxx", re.I),
        "impact": "FortiGate exposed — many CVEs in SSL-VPN component; even banner is enough.",
    },
    {
        "vendor": "Jenkins",
        "severity": "medium",
        "probes": [
            ("/login", re.compile(r"<title>Sign in \[Jenkins\]|Hudson|j_username", re.I), re.compile(r"X-Jenkins", re.I), "text/html"),
            ("/api/json", None, re.compile(r"X-Jenkins", re.I), "application/json"),
        ],
        "server_pattern": re.compile(r"Jetty\(.*Jenkins|^Jenkins ", re.I),
        "impact": "Jenkins exposed — anonymous-access often enabled on legacy installs; CI secrets at risk.",
    },
    {
        "vendor": "phpMyAdmin",
        "severity": "high",
        "probes": [
            ("/phpmyadmin/", re.compile(r"<title>phpMyAdmin|pma_username|pma_password|phpMyAdmin v", re.I), None, "text/html"),
            ("/pma/", re.compile(r"<title>phpMyAdmin", re.I), None, "text/html"),
        ],
        "impact": "phpMyAdmin exposed — direct DB login interface; often default root/blank on legacy.",
    },
    {
        "vendor": "Grafana",
        "severity": "medium",
        "probes": [
            ("/login", re.compile(r"<title>Grafana|grafana_session", re.I), re.compile(r"Grafana", re.I), "text/html"),
            ("/api/health", re.compile(r'"database":\s*"ok"|"version":\s*"\d+\.\d+', re.I), None, "application/json"),
        ],
        "server_pattern": re.compile(r"Grafana", re.I),
        "impact": "Grafana exposed — default admin/admin on fresh installs; dashboards may leak business data.",
    },
    {
        "vendor": "Kibana",
        "severity": "medium",
        "probes": [
            ("/app/kibana", re.compile(r"<title>Kibana|kbn-name|kibanaApp", re.I), None, "text/html"),
            ("/api/status", None, re.compile(r"kbn-", re.I), "application/json"),
        ],
        "impact": "Kibana exposed — older versions had no auth by default; may leak ES index data.",
    },
]


def _fetch(url: str, timeout: int = 6) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {"status": r.status, "headers": {k: v for k, v in r.headers.items()}, "body": r.read(MAX_PROBE_BODY + 1).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_PROBE_BODY + 1).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": {k: v for k, v in e.headers.items()} if e.headers else {}, "body": body}
    except Exception:
        return None


def _is_cdn_host(headers: dict) -> bool:
    lh = {k.lower(): v for k, v in headers.items()}
    server = (lh.get("server", "") or "").lower().strip()
    via    = (lh.get("via", "") or "").lower()
    powered = (lh.get("x-powered-by", "") or "").lower()

    if lh.get("cf-ray") or lh.get("cf-cache-status") or lh.get("cf-mitigated"):
        return True
    if any(k.startswith("x-akamai") or k.startswith("akamai-") for k in lh):
        return True
    if lh.get("x-ak-reference-id") or lh.get("x-ak-client-ip"):
        return True
    if lh.get("x-served-by") and ("cache-" in lh["x-served-by"].lower()):
        return True
    if lh.get("fastly-debug-digest") or lh.get("x-fastly-request-id"):
        return True
    if lh.get("x-amz-cf-id") or lh.get("x-amz-cf-pop"):
        return True
    if any(k.startswith("x-vercel-") for k in lh):
        return True
    if lh.get("x-nf-request-id"):
        return True
    if server and any(cdn in server for cdn in CDN_SERVER_BLOCKLIST):
        return True
    if via and any(cdn in via for cdn in {"varnish", "cloudfront", "akamai", "fastly"}):
        return True
    if "vercel" in powered or "next.js" in powered:
        return True
    # WordPress signal — apex domains running WordPress are not devices
    if "wp-json" in str(lh.get("link", "")).lower():
        return True
    return False


def _is_spa_wildcard(base: str, root_body: str, fetch_fn) -> bool:
    """Probe a root-level nonsense path. If it returns 200 with similar
    body to root, this host is a SPA-wildcard."""
    nonce = secrets.token_hex(8)
    probe = fetch_fn(f"{base}/__lictor_canary_{nonce}", timeout=4)
    if probe is None or probe["status"] != 200:
        return False
    nonsense_body = probe.get("body", "") or ""
    if not nonsense_body:
        return False
    if hashlib.md5(nonsense_body.encode("utf-8", "replace")).hexdigest() == hashlib.md5(root_body.encode("utf-8", "replace")).hexdigest():
        return True
    if root_body and abs(len(nonsense_body) - len(root_body)) / max(len(root_body), 1) < 0.05:
        return True
    return True


def _is_path_catchall(base: str, sample_path: str, fetch_fn) -> bool:
    """Per-path catch-all detector. For a path like /css/pfSense.css,
    probe /css/lictor_canary_<random>.css. If both return 200 with
    similar size, this directory is a catch-all and probe is useless."""
    if "/" not in sample_path.lstrip("/"):
        return False  # no directory to probe
    parts = sample_path.rsplit("/", 1)
    if len(parts) != 2 or not parts[1]:
        return False
    nonce = secrets.token_hex(6)
    ext = ""
    if "." in parts[1]:
        ext = "." + parts[1].rsplit(".", 1)[-1]
    canary_path = f"{parts[0]}/lictor_canary_{nonce}{ext}"
    probe = fetch_fn(f"{base}{canary_path}", timeout=4)
    if probe is None or probe["status"] != 200:
        return False
    body = probe.get("body", "") or ""
    if len(body) > MAX_PROBE_BODY:
        return True  # catch-all serving huge SPA bundle
    if not body:
        return False
    return True  # any 200 on a nonsense path with same dir means catch-all


def fingerprint_one_host(host: str) -> list[dict]:
    findings = []
    # Skip hosts that resolve to private/loopback (avoids hitting our own machine)
    if _resolves_to_private(host):
        return findings
    root = None
    used_scheme = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        r = _fetch(url)
        if r is not None:
            root = r
            used_scheme = scheme
            break
    if root is None:
        return findings

    if _is_cdn_host(root["headers"]):
        return findings

    base = f"{used_scheme}://{host}"
    root_body = root.get("body", "") or ""
    root_server = (root["headers"].get("Server", "") or "").strip()
    root_auth = (root["headers"].get("WWW-Authenticate", "") or "").strip()
    root_body_hash = hashlib.md5(root_body.encode("utf-8", "replace")).hexdigest()

    if _is_spa_wildcard(base, root_body, _fetch):
        return findings

    # Cache per-directory catch-all status across all device probes
    catchall_cache: dict[str, bool] = {}

    def _path_is_catchall(path: str) -> bool:
        # Cache by directory
        dir_part = path.rsplit("/", 1)[0] if "/" in path.lstrip("/") else ""
        if dir_part in catchall_cache:
            return catchall_cache[dir_part]
        result = _is_path_catchall(base, path, _fetch)
        catchall_cache[dir_part] = result
        return result

    for d in DEVICE_PROBES:
        signals = []

        # Server header — only for device-SPECIFIC patterns (never "nginx"/"Apache")
        if d.get("server_pattern") and d["server_pattern"].search(root_server):
            signals.append(("server_header", root_server[:80]))

        # WWW-Authenticate realm
        if d.get("auth_realm_pattern") and d["auth_realm_pattern"].search(root_auth):
            signals.append(("auth_realm", root_auth[:80]))

        # Title
        if d.get("title_pattern"):
            tm = re.search(r"<title>([^<]+)</title>", root_body, re.I)
            if tm and d["title_pattern"].search(tm.group(1)):
                signals.append(("title", tm.group(1)[:80]))

        # Path probes
        for path, body_rx, header_rx, expected_ct in d["probes"]:
            # If this directory is a catch-all, all probes in it are useless
            if _path_is_catchall(path):
                continue
            probe = _fetch(base + path, timeout=4)
            if probe is None:
                continue
            if probe["status"] not in (200, 401):
                continue
            probe_body = probe.get("body", "") or ""
            # Body size gate — devices return small login pages
            if len(probe_body) > MAX_PROBE_BODY:
                continue
            # Anti-SPA — probe body must differ from root
            if hashlib.md5(probe_body.encode("utf-8", "replace")).hexdigest() == root_body_hash:
                continue
            # Content-type gate — defeats CMS catch-alls serving text/html for any path
            if expected_ct:
                probe_ct = (probe["headers"].get("Content-Type", "") or "").lower()
                if not probe_ct.startswith(expected_ct.lower()):
                    continue
            # All gates passed — credit signals
            if body_rx and body_rx.search(probe_body):
                signals.append(("path_body", f"{path}: matched"))
            if header_rx:
                for hk, hv in probe.get("headers", {}).items():
                    if header_rx.search(f"{hk}: {hv}"):
                        signals.append(("path_header", f"{path}: {hk}: {hv[:80]}"))
                        break
            if body_rx is None and header_rx is None and probe["status"] == 200:
                signals.append(("path_exists", f"{path}: HTTP 200 (ct={probe['headers'].get('Content-Type', '?')[:40]})"))

        if len(signals) >= 2:
            findings.append({
                "host": host,
                "url": base,
                "vendor": d["vendor"],
                "severity": d["severity"],
                "signals": signals,
                "impact_if_default_creds": d["impact"],
                "server_header": root_server,
                "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
            print(f"  🟢 DEVICE  {host} → {d['vendor']} ({d['severity']}) [{len(signals)} signals]", flush=True)
            break

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", help="Single host to probe")
    ap.add_argument("--corpus", help="Path to apex-domain corpus file")
    ap.add_argument("--max-domains", type=int, default=500)
    ap.add_argument("--workers", type=int, default=20)
    args = ap.parse_args()

    if args.target:
        hosts = [args.target]
    elif args.corpus:
        p = Path(args.corpus).expanduser()
        if not p.exists():
            sys.exit(f"❌ Corpus file not found: {p}")
        hosts = [l.strip() for l in p.read_text().splitlines() if l.strip()][:args.max_domains]
    else:
        ap.print_help()
        sys.exit(1)

    print(f"[+] device-fingerprint v4 — {len(hosts)} hosts × {len(DEVICE_PROBES)} device classes", flush=True)
    print(f"[+] STRICT v4: CDN pre-filter + SPA-canary + per-dir catch-all + content-type gate + ≥2 signals", flush=True)
    print(f"[+] HTTP banner-grab only — NEVER attempts default creds", flush=True)

    all_findings = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fingerprint_one_host, h): h for h in hosts}
        for fut in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} devices identified", flush=True)
            try:
                hits = fut.result(timeout=120)
            except Exception:
                continue
            all_findings.extend(hits)

    print(f"\n[+] scan complete: {len(all_findings)} HIGH-CONFIDENCE devices", flush=True)

    if all_findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in all_findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(all_findings)} entries to {LEDGER}", flush=True)


if __name__ == "__main__":
    main()
