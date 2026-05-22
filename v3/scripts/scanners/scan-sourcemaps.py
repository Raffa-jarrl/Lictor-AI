"""Source map (.js.map) scanner — find production sites that ship source maps,
exposing internal source code + often embedded secrets.

Method:
1. Fetch homepage HTML
2. Extract <script src="/path/to/file.js"> tags
3. For each script, HEAD the corresponding .js.map file
4. If 200, fetch first 5KB and check for sources/sourceContent fields

Ethical: signature-only confirmation (presence of valid sourcemap structure).
NEVER downloads full source content. Reports presence + size only.
"""
import urllib.request, urllib.error, ssl, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-Sourcemap/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "sourcemap-exposure.jsonl"

SOURCEMAP_SIG = re.compile(rb'"sources"\s*:\s*\[|"sourceContent"\s*:|"mappings"\s*:')

# Common source-map paths to try if HTML script-src parsing fails
COMMON_JS_PATHS = [
    "/static/js/main.js.map",
    "/static/js/app.js.map",
    "/static/js/bundle.js.map",
    "/assets/index.js.map",
    "/dist/bundle.js.map",
    "/build/static/js/main.js.map",
    "/js/app.js.map",
    "/js/main.js.map",
]


def fetch(url, max_bytes=8000, timeout=8, method="GET"):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(max_bytes), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(max_bytes), dict(e.headers.items() if e.headers else [])
        except: return e.code, b"", {}
    except Exception:
        return None, b"", {}


def find_js_maps(host):
    """Find candidate .js.map URLs for this host via homepage scrape + common paths."""
    candidates = set()
    for scheme in ("https", "http"):
        st, body, _ = fetch(f"{scheme}://{host}/", max_bytes=50000)
        if st != 200 or not body: continue
        # Extract script srcs
        srcs = re.findall(rb'<script[^>]*\bsrc=["\']([^"\']+\.js[^"\']*)["\']', body)
        for src in srcs[:20]:
            src_s = src.decode("utf-8", "replace")
            # Relative → absolute
            if src_s.startswith("//"): map_url = scheme + ":" + src_s + ".map"
            elif src_s.startswith("http"): map_url = src_s + ".map"
            elif src_s.startswith("/"): map_url = f"{scheme}://{host}{src_s}.map"
            else: map_url = f"{scheme}://{host}/{src_s}.map"
            candidates.add(map_url)
        # Also try common paths
        for p in COMMON_JS_PATHS:
            candidates.add(f"{scheme}://{host}{p}")
        break  # one scheme is enough
    return list(candidates)[:25]  # max 25 candidates per host


def scan_host(host):
    findings = []
    maps = find_js_maps(host)
    seen_sizes = set()
    for url in maps:
        st, body, hdr = fetch(url, max_bytes=5000)
        if st != 200 or not body: continue
        # Must be valid sourcemap shape
        if not SOURCEMAP_SIG.search(body): continue
        cl = int(hdr.get("Content-Length", "0") or 0) if hdr.get("Content-Length", "").isdigit() else len(body)
        # Skip duplicate sizes (catch-all)
        if cl in seen_sizes: continue
        seen_sizes.add(cl)
        # Extract some sample source paths (first ~5)
        sources_match = re.search(rb'"sources"\s*:\s*\[([^\]]{0,500})', body)
        sample_sources = []
        if sources_match:
            raw = sources_match.group(1).decode("utf-8", "replace")
            sample_sources = re.findall(r'"([^"]+)"', raw)[:5]
        print(f"  🔴 SOURCEMAP  {url}  size={cl}  sources_sample={sample_sources[:3]}", flush=True)
        findings.append({
            "type": "exposed-sourcemap",
            "host": host, "url": url, "size": cl,
            "sample_sources": sample_sources[:10],
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        if len(findings) >= 3: break  # 3 is enough per host
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
print(f"[+] Source-map scan — {len(hosts)} hosts (homepage scrape + common paths)", flush=True)
print(f"[+] Ethical: 5KB signature check only, no full source download", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=20) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 250 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} sourcemaps exposed", flush=True)
        try:
            r = fut.result(timeout=30)
            if r: all_findings.extend(r)
        except Exception:
            pass

print(f"\n[+] Sourcemap scan complete: {len(all_findings)} exposures", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
