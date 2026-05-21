#!/usr/bin/env python3
"""
Lictor v3 — device fingerprinting scanner v3 (HTTP-only, NEVER auth)

REBUILT TWICE 2026-05-21:
  v1: substring-matched vendor names in HTML body → 96/96 FPs
  v2: path probes + CDN pre-filter (Server header) → still flagged
      ad.nl & album.link because Akamai/Fastly strip Server header on
      success and serve SPA-wildcards (every path returns HTTP 200)
  v3: ANTI-SPA + EXTRA CDN signals + nonsense-path canary

v3 design — strict multi-signal verification + anti-SPA:
  1. PROBE a random nonsense path FIRST as a canary
     - If nonsense returns 200 → host is SPA-wildcard, skip everything
     - If nonsense body is similar to root body → SPA-wildcard, skip
  2. SKIP CDN-fronted hosts via MULTIPLE signals:
     - CF-RAY (cloudflare), X-Akamai-*, X-Served-By/X-Cache (Fastly)
     - Via header containing varnish/akamai/cloudfront/fastly
     - Server header substring match (cloudflare/akamaighost/etc)
     - X-Amz-* / x-amzn-* (AWS), x-vercel-* (Vercel)
  3. PROBE device-specific paths
  4. REQUIRE >=2 confirming signals AND probe body must DIFFER from
     root body (to defeat SPA wildcards that survive other filters)
  5. NEVER attempt credentials

A real Hikvision device emits Server: "App-webs/" or "Webs" + a
device-specific HTML title + serves /doc/page/login.asp with a
specific login HTML structure. A fintech marketing page emits Server:
"cloudflare" and serves a React SPA — completely different signals.

Detects (high-confidence only):
  - Hikvision IP cameras (Server: App-webs/* + /doc/page/login.asp)
  - Dahua IP cameras (Server: Webs/* + /RPC2_Login)
  - Axis cameras (Server: AxisOnvif/* + /axis-cgi/admin/restart.cgi)
  - pfSense / OPNsense (specific cookie + login page structure)
  - Synology DSM (Server: nginx + /webman/index.cgi presence)
  - Mikrotik RouterOS (Server: 'Mikrotik HttpProxy' or unique JS)
  - F5 BIG-IP (Server: BIG-IP + /tmui/login.jsp)
  - Citrix NetScaler (Server: NetScaler + /vpn/index.html)
  - Fortinet FortiGate (Server-side specific + /login URL match)

Usage:
  python3 patrol-device-fingerprint.py --corpus PATH --max-domains N
  python3 patrol-device-fingerprint.py example.com  # single target

Output: ~/Lictor/v3/ledgers/device-fingerprint-candidates.jsonl
"""
from __future__ import annotations
import argparse, hashlib, json, re, secrets, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-DeviceFingerprint/0.3 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "device-fingerprint-candidates.jsonl"

# CDN/cloud fingerprints — if we see these in the Server header on the
# root page, abort entirely. Marketing pages behind CDNs are NEVER the
# actual embedded device.
CDN_SERVER_BLOCKLIST = {
    "cloudflare", "amazons3", "amazon s3", "cloudfront", "fastly",
    "akamai", "akamaighost", "akamainetstorage", "vercel", "netlify",
    "github.com", "squarespace", "wix.com", "wpx-cloud", "imperva",
    "sucuri", "incapsula", "ddos-guard", "qrator", "barracuda",
    "atlassianedge", "shopify", "esa", "istio-envoy",
}

# Device probes: (vendor, severity, [(path, expected_body_regex, expected_header_regex)], impact)
# Multi-signal — we require BOTH a path returns 200 AND the body OR a
# response header matches a device-specific pattern. Substring matching
# on root-page HTML body alone is NEVER enough.
DEVICE_PROBES = [
    {
        "vendor": "Hikvision IP Camera",
        "severity": "critical",
        "probes": [
            # Hikvision-specific login page (NOT served by any normal website)
            ("/doc/page/login.asp", re.compile(r"hikvision|web ?service|loginpage|/scripts/login\.js", re.I), None),
            # Hikvision ISAPI endpoint
            ("/ISAPI/System/deviceInfo", None, re.compile(r"App-webs|Hikvision", re.I)),
        ],
        "server_pattern": re.compile(r"App-webs|Hikvision|Webs", re.I),
        "impact": "Hikvision cameras have known default-credential history (admin/12345, admin/admin) and multiple CVEs. Banner-grab alone is enough to alert the owner.",
    },
    {
        "vendor": "Dahua IP Camera/DVR",
        "severity": "critical",
        "probes": [
            ("/RPC2_Login", None, re.compile(r"DH-|Dahua|Webs", re.I)),
            ("/current_config/Account1", None, None),  # Dahua-specific path; 200 = device
        ],
        "server_pattern": re.compile(r"Dahua|DH-|Webs", re.I),
        "impact": "Dahua cameras / DVRs have default-credential history and CVE-rich firmware.",
    },
    {
        "vendor": "Axis IP Camera",
        "severity": "high",
        "probes": [
            ("/axis-cgi/usergroup.cgi", None, None),  # 401 with WWW-Auth: realm="AXIS_..." = device
            ("/view/view.shtml", re.compile(r"axis|/axis-cgi/", re.I), None),
        ],
        "server_pattern": re.compile(r"AxisOnvif|Axis|lighttpd|GoAhead", re.I),
        "auth_realm_pattern": re.compile(r"AXIS", re.I),
        "impact": "Axis cameras — older firmware shipped with root/pass default; current models require setup but exposure to internet is best avoided.",
    },
    {
        "vendor": "pfSense Firewall",
        "severity": "high",
        "probes": [
            # pfSense login page has a very specific structure
            ("/", re.compile(r"login\.php.*pfSense|<title>pfSense", re.I), None),
            ("/css/pfSense.css", None, None),  # pfSense-specific CSS file
        ],
        "server_pattern": re.compile(r"nginx|lighttpd", re.I),
        "impact": "pfSense firewall admin UI exposed — should be VPN-only.",
    },
    {
        "vendor": "OPNsense Firewall",
        "severity": "high",
        "probes": [
            ("/", re.compile(r"<title>OPNsense|opnsense_logo", re.I), None),
        ],
        "server_pattern": re.compile(r"lighttpd|nginx", re.I),
        "impact": "OPNsense firewall admin UI exposed — should be VPN-only.",
    },
    {
        "vendor": "Mikrotik RouterOS",
        "severity": "high",
        "probes": [
            ("/", re.compile(r"RouterOS|Mikrotik|<title>RouterOS", re.I), re.compile(r"Mikrotik HttpProxy", re.I)),
            ("/webfig/", None, None),
        ],
        "server_pattern": re.compile(r"Mikrotik", re.I),
        "impact": "Mikrotik RouterOS admin exposed — CVE-2018-14847 (Winbox) and others; default admin/blank common on older firmware.",
    },
    {
        "vendor": "Synology DSM",
        "severity": "high",
        "probes": [
            ("/webman/index.cgi", re.compile(r"synology|diskstation|dsm", re.I), None),
            ("/webapi/auth.cgi", None, None),  # DSM API endpoint
        ],
        "server_pattern": re.compile(r"nginx", re.I),
        "title_pattern": re.compile(r"Synology|DSM|DiskStation", re.I),
        "impact": "Synology DSM exposed — CVE-rich (DSM RCE history), ransomware target.",
    },
    {
        "vendor": "QNAP QTS",
        "severity": "high",
        "probes": [
            ("/cgi-bin/qts.cgi", None, None),
            ("/cgi-bin/", None, re.compile(r"QTS|QNAP", re.I)),
        ],
        "server_pattern": re.compile(r"QTS|QNAP|http server|Apache", re.I),
        "title_pattern": re.compile(r"QNAP|QTS", re.I),
        "impact": "QNAP QTS exposed — QLocker ransomware target, many CVEs.",
    },
    {
        "vendor": "F5 BIG-IP",
        "severity": "high",
        "probes": [
            ("/tmui/login.jsp", re.compile(r"BIG-?IP|F5 Networks|tmui", re.I), None),
            ("/mgmt/tm/sys/version", None, None),
        ],
        "server_pattern": re.compile(r"BIG-?IP|BigIP", re.I),
        "impact": "F5 BIG-IP exposed — CVE-2020-5902 history; even banner-grab is enough to alert owner.",
    },
    {
        "vendor": "Citrix NetScaler/ADC",
        "severity": "high",
        "probes": [
            ("/vpn/index.html", re.compile(r"NetScaler|Citrix", re.I), None),
            ("/nitro/v1/config/nsversion", None, None),
        ],
        "server_pattern": re.compile(r"NetScaler|Citrix|nsvpnd", re.I),
        "impact": "Citrix NetScaler/ADC exposed — CVE-2019-19781 (Shitrix), CVE-2023-3519 history.",
    },
    {
        "vendor": "Fortinet FortiGate",
        "severity": "high",
        "probes": [
            ("/login", re.compile(r"FortiGate|FortiOS|Fortinet|fgt_", re.I), None),
            ("/remote/login", None, None),  # SSL-VPN login
        ],
        "server_pattern": re.compile(r"Fortinet|FortiGate|xxxxxxxx", re.I),
        "impact": "FortiGate exposed — many CVEs in SSL-VPN component; even banner is enough.",
    },
    {
        "vendor": "Jenkins",
        "severity": "medium",
        "probes": [
            ("/login", re.compile(r"<title>Sign in \[Jenkins\]|hudson|jenkins", re.I), re.compile(r"Jenkins|X-Jenkins", re.I)),
            ("/api/json", None, re.compile(r"X-Jenkins", re.I)),
        ],
        "server_pattern": re.compile(r"Jetty.*Jenkins|Jenkins", re.I),
        "impact": "Jenkins exposed — anonymous-access often enabled on legacy installs; CI secrets at risk.",
    },
    {
        "vendor": "phpMyAdmin",
        "severity": "high",
        "probes": [
            ("/phpmyadmin/", re.compile(r"<title>phpMyAdmin|pma_username", re.I), None),
            ("/pma/", re.compile(r"phpMyAdmin", re.I), None),
        ],
        "server_pattern": re.compile(r"Apache|nginx", re.I),
        "impact": "phpMyAdmin exposed — direct DB login interface; often default root/blank on legacy.",
    },
    {
        "vendor": "Grafana",
        "severity": "medium",
        "probes": [
            ("/login", re.compile(r"<title>Grafana|grafana_session", re.I), re.compile(r"Grafana", re.I)),
            ("/api/health", None, None),  # returns {"database": "ok", "version": "..."} on real Grafana
        ],
        "server_pattern": re.compile(r"Grafana", re.I),
        "impact": "Grafana exposed — default admin/admin on fresh installs; dashboards may leak business data.",
    },
    {
        "vendor": "Kibana",
        "severity": "medium",
        "probes": [
            ("/app/kibana", re.compile(r"<title>Kibana|kbn-name|elastic-kibana", re.I), None),
            ("/api/status", None, re.compile(r"kbn-", re.I)),
        ],
        "server_pattern": re.compile(r"Kibana", re.I),
        "impact": "Kibana exposed — older versions had no auth by default; may leak ES index data.",
    },
]


def _fetch(url: str, timeout: int = 6, allow_404: bool = False) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {"status": r.status, "headers": {k: v for k, v in r.headers.items()}, "body": r.read(20000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": {k: v for k, v in e.headers.items()} if e.headers else {}, "body": body}
    except Exception:
        return None


def _is_cdn_host(headers: dict) -> bool:
    """Filter: if root page is served by a CDN, it's NOT an embedded device.
    Uses MANY signals because CDNs sometimes strip Server header."""
    # Normalize header keys to lowercase for reliable lookup
    lh = {k.lower(): v for k, v in headers.items()}
    server = (lh.get("server", "") or "").lower().strip()
    via    = (lh.get("via", "") or "").lower()
    powered = (lh.get("x-powered-by", "") or "").lower()

    # Cloudflare always emits CF-RAY (and cf-cache-status, cf-ray)
    if lh.get("cf-ray") or lh.get("cf-cache-status") or lh.get("cf-mitigated"):
        return True
    # Akamai signals
    if any(k.startswith("x-akamai") or k.startswith("akamai-") for k in lh):
        return True
    if lh.get("x-ak-reference-id") or lh.get("x-ak-client-ip"):
        return True
    # Fastly signals
    if lh.get("x-served-by") and ("cache-" in lh["x-served-by"].lower()):
        return True
    if lh.get("fastly-debug-digest") or lh.get("x-fastly-request-id"):
        return True
    # AWS CloudFront signals
    if lh.get("x-amz-cf-id") or lh.get("x-amz-cf-pop"):
        return True
    # Vercel / Netlify signals
    if any(k.startswith("x-vercel-") for k in lh):
        return True
    if lh.get("x-nf-request-id"):
        return True
    # Server header substring match (catches AkamaiGHost, cloudflare, etc)
    if server and any(cdn in server for cdn in CDN_SERVER_BLOCKLIST):
        return True
    # Via header
    if via and any(cdn in via for cdn in {"varnish", "cloudfront", "akamai", "fastly"}):
        return True
    if "vercel" in powered or "next.js" in powered:
        return True
    return False


def _is_spa_wildcard(base: str, root_body: str, fetch_fn) -> bool:
    """Detect single-page apps that return HTTP 200 for every path.
    Probe a random nonsense path: if it returns 200 with similar body
    to the root page, this host is a SPA wildcard and we can't trust
    any path-based device probe."""
    nonce = secrets.token_hex(8)
    probe = fetch_fn(f"{base}/__lictor_canary_{nonce}", timeout=4)
    if probe is None:
        return False  # probe failed → not necessarily SPA
    if probe["status"] != 200:
        return False  # 404/403/etc — proper routing
    # If nonsense returned 200, very suspicious. Compare body.
    nonsense_body = probe.get("body", "") or ""
    if not nonsense_body:
        return False
    # Compare hashes — if identical, definitely SPA wildcard
    if hashlib.md5(nonsense_body.encode("utf-8", "replace")).hexdigest() == hashlib.md5(root_body.encode("utf-8", "replace")).hexdigest():
        return True
    # Compare lengths — if within 5%, probably same SPA HTML with minor variation
    if root_body and abs(len(nonsense_body) - len(root_body)) / max(len(root_body), 1) < 0.05:
        return True
    # 200 on a nonsense URL is itself suspicious — be conservative
    return True


def fingerprint_one_host(host: str) -> list[dict]:
    """Probe each host with strict multi-signal verification."""
    findings = []
    # Step 1: fetch root page (https first, http fallback) to check CDN status
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
        return findings  # host unreachable

    # Filter 1: skip CDN-fronted hosts
    if _is_cdn_host(root["headers"]):
        return findings  # marketing page, not a device

    base = f"{used_scheme}://{host}"
    root_body = root.get("body", "") or ""
    root_server = (root["headers"].get("Server", "") or "").strip()
    root_auth = (root["headers"].get("WWW-Authenticate", "") or "").strip()
    root_body_hash = hashlib.md5(root_body.encode("utf-8", "replace")).hexdigest()

    # Filter 2: SPA-wildcard canary
    if _is_spa_wildcard(base, root_body, _fetch):
        return findings  # every path returns 200 with same content — useless to probe

    # Phase 2: for each device candidate, look for >=2 confirming signals
    for d in DEVICE_PROBES:
        signals = []  # list of (signal_type, value) we collected

        # Server header match
        if d.get("server_pattern") and d["server_pattern"].search(root_server):
            signals.append(("server_header", root_server))

        # WWW-Authenticate realm match
        if d.get("auth_realm_pattern") and d["auth_realm_pattern"].search(root_auth):
            signals.append(("auth_realm", root_auth))

        # Title pattern match on root body
        if d.get("title_pattern"):
            title_match = re.search(r"<title>([^<]+)</title>", root_body, re.I)
            if title_match and d["title_pattern"].search(title_match.group(1)):
                signals.append(("title", title_match.group(1)))

        # Probe device-specific paths
        for path, body_rx, header_rx in d["probes"]:
            probe = _fetch(base + path, timeout=4)
            if probe is None:
                continue
            # We want a device-specific response: 200 or 401 (auth-required)
            if probe["status"] not in (200, 401):
                continue
            probe_body = probe.get("body", "") or ""
            probe_body_hash = hashlib.md5(probe_body.encode("utf-8", "replace")).hexdigest()
            # CRITICAL anti-SPA check — probe body MUST differ from root.
            # If they're identical, the host serves the same SPA HTML on
            # every path and is not a device.
            if probe_body_hash == root_body_hash:
                continue
            # Body match (only credit if probe body is meaningfully different)
            if body_rx and body_rx.search(probe_body):
                signals.append(("path_body", f"{path}: matched"))
            # Header match
            if header_rx:
                for hk, hv in probe.get("headers", {}).items():
                    if header_rx.search(f"{hk}: {hv}"):
                        signals.append(("path_header", f"{path}: {hk}: {hv[:80]}"))
                        break
            # If body_rx and header_rx are both None but status is 200 AND
            # the body differs from root, the PATH ITSELF is device-specific
            # (e.g. /current_config/Account1 exists only on Dahua).
            if body_rx is None and header_rx is None and probe["status"] == 200:
                signals.append(("path_exists", f"{path}: HTTP 200 (differs from root)"))

        # STRICT GATE: require >=2 independent signals
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
            break  # one device per host is enough

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

    print(f"[+] device-fingerprint v3 — {len(hosts)} hosts × {len(DEVICE_PROBES)} device classes", flush=True)
    print(f"[+] STRICT MODE: CDN pre-filter + SPA-canary + ≥2 confirming signals + probe-body≠root-body", flush=True)
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
