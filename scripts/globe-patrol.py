#!/usr/bin/env python3
"""
globe-patrol — Lictor's continuous geo-risk mapper.

The slow-and-sure crawler behind the Lictor Globe. Each run takes the NEXT
rolling slice of a master target list (cursor tracked in state, so over many
runs it covers everything, then wraps to re-scan for NEW risk), does a light,
HEAD-only risk recon per host, geo-tags it, and appends a zone record. A
companion aggregator rolls these into a world heatmap ("warm areas").

ETHICS (same discipline as the Patrol scanners):
  - HEAD-only on sensitive paths. We never download a credential/file body —
    we only observe whether an exposure surface RESPONDS. Detect, don't exfil.
  - Short timeouts, capped workers, a rolling slice — gentle on every host.
  - Targets come from bounty-eligible corpora by default.
  - Sends nothing. Produces a local ledger + heatmap only.

Usage:
  python3 scripts/globe-patrol.py [--corpus FILE] [--slice 200] [--workers 16]
  # state: ~/.lictor/globe-state.json   ledger: ~/.lictor/globe-zones.jsonl
"""
from __future__ import annotations
import argparse, json, socket, ssl, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
STATE = HOME / ".lictor" / "globe-state.json"
LEDGER = HOME / ".lictor" / "globe-zones.jsonl"
HEATMAP = HOME / "Lictor" / "output" / "globe-heatmap.json"

# HEAD-only signal paths — a 200/auth response is an exposure SIGNAL; we read no body.
SIGNAL_PATHS = [
    ("/.env", "env-file", 3),
    ("/.git/config", "git-dir", 3),
    ("/.aws/credentials", "aws-creds", 3),
    ("/config.json", "config-json", 1),
    ("/server-status", "apache-status", 2),
    ("/actuator/health", "spring-actuator", 2),
    ("/.well-known/security.txt", "security-txt", -1),  # negative = good hygiene
]

# country-code TLD → ISO country (heuristic, free, instant).
CCTLD = {
    "il": "IL", "de": "DE", "uk": "GB", "co.uk": "GB", "fr": "FR", "br": "BR",
    "in": "IN", "jp": "JP", "au": "AU", "ca": "CA", "nl": "NL", "es": "ES",
    "it": "IT", "ru": "RU", "cn": "CN", "kr": "KR", "se": "SE", "ch": "CH",
    "sg": "SG", "ae": "AE", "sa": "SA", "za": "ZA", "mx": "MX", "pl": "PL",
    "tr": "TR", "no": "NO", "fi": "FI", "dk": "DK", "be": "BE", "at": "AT",
    "ie": "IE", "pt": "PT", "gr": "GR", "cz": "CZ", "ro": "RO", "hu": "HU",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def cctld_country(host: str) -> str | None:
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        last2 = ".".join(parts[-2:])
        if last2 in CCTLD:
            return CCTLD[last2]
    if parts and parts[-1] in CCTLD:
        return CCTLD[parts[-1]]
    return None


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def geo_by_ip(ips: list[str]) -> dict[str, str]:
    """Batch IP→country via ip-api.com (free, stdlib urllib). <=100 per call."""
    out: dict[str, str] = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        body = json.dumps([{"query": ip, "fields": "query,countryCode"} for ip in chunk]).encode()
        try:
            req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                for row in json.loads(r.read().decode()):
                    if row.get("countryCode"):
                        out[row["query"]] = row["countryCode"]
        except Exception:
            pass
        time.sleep(1.4)  # ip-api free tier ~45 req/min; we batch, so this is plenty
    return out


_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def head(url: str, timeout: float = 4.0):
    """HEAD-only. Returns (status, content_type). Never reads a body."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Lictor-Globe/1.0 (+https://lictorai.com)"})
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return r.status, (r.headers.get("Content-Type") or "").lower()
    except urllib.error.HTTPError as e:
        ct = (e.headers.get("Content-Type") or "").lower() if getattr(e, "headers", None) else ""
        return e.code, ct
    except Exception:
        return None, ""


def probe(host: str) -> dict:
    """Light, HEAD-only risk recon for one host. No body is ever read.

    FP guards (per the scanner FP rules):
      - catch-all canary: a random path that 200s ⇒ host serves everything ⇒ drop signals
      - text/html drop: a real .env/.git/config is not an HTML page
    """
    import hashlib
    rec = {"host": host, "ip": None, "cc": None, "https": False, "catchall": False,
           "risk": 0, "signals": [], "ts": now_iso()}
    ip = resolve(host)
    rec["ip"] = ip
    if not ip:
        rec["dead"] = True
        return rec
    scheme = "https"
    root, _ = head(f"https://{host}/")
    if root is None:
        root, _ = head(f"http://{host}/")
        scheme = "http"
    rec["https"] = (scheme == "https" and root is not None)
    if root is None:
        rec["dead"] = True
        return rec
    base = f"{scheme}://{host}"
    # canary: a unique, certainly-nonexistent path. If it responds present, the host is a catch-all.
    canary = "/" + hashlib.md5(host.encode()).hexdigest()[:18] + "-lictor-canary.html"
    ccode, _ = head(base + canary)
    rec["catchall"] = ccode in (200, 401, 403)
    if rec["catchall"]:
        rec["signals"].append("catch-all")   # noted, but no exposure signals counted below
    for path, name, weight in SIGNAL_PATHS:
        code, ctype = head(base + path)
        is_html = "text/html" in ctype
        if weight > 0:
            # a genuine exposure: 200, host is NOT a blanket catch-all, and the body isn't an HTML page
            if code == 200 and not rec["catchall"] and not is_html:
                rec["signals"].append(name)
                rec["risk"] += weight
        elif weight < 0 and code == 200 and not is_html:  # security.txt = hygiene credit
            rec["signals"].append("+security-txt")
            rec["risk"] = max(0, rec["risk"] - 1)
    # WAF / blanket-responder guard (body-free): a host that "exposes" .env AND
    # .git AND .aws AND server-status AND actuator all at once is not five real
    # leaks — it's a WAF/CDN serving a generic 200 block page (often text/plain,
    # so the html-drop above misses it). HEAD can't read the body, so we infer
    # it from the implausible breadth. Real exposures don't cluster like this.
    exposure_hits = [s for s in rec["signals"] if s not in ("catch-all", "+security-txt")]
    if len(exposure_hits) >= 4:
        rec["catchall"] = True
        rec["risk"] = 0
        rec["signals"] = [s for s in rec["signals"] if s not in exposure_hits]
        rec["signals"].append("waf-catchall")
    if not rec["https"]:
        rec["risk"] += 1
        rec["signals"].append("no-https")
    return rec


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"cursor": 0, "runs": 0, "scanned_total": 0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(HOME / ".lictor" / "bounty-corpus.txt"))
    ap.add_argument("--slice", type=int, default=200, help="hosts per run (slowly, surely)")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--corpus-cc", default=None, help="force a country for this corpus (e.g. IL)")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 1
    hosts = [h.strip() for h in corpus.read_text().splitlines() if h.strip() and not h.startswith("#")]
    if not hosts:
        print("empty corpus", file=sys.stderr)
        return 1

    st = load_state()
    cur = st.get("cursor", 0) % len(hosts)
    sl = hosts[cur:cur + args.slice]
    if len(sl) < args.slice:                       # wrap around — re-scan for NEW risk
        sl += hosts[: args.slice - len(sl)]
    print(f"[globe-patrol] {now_iso()} corpus={corpus.name} hosts={len(hosts)} "
          f"cursor={cur} slice={len(sl)} run#{st.get('runs',0)+1}")

    records = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(probe, h): h for h in sl}
        for f in as_completed(futs):
            try:
                records.append(f.result())
            except Exception:
                pass

    # geo: corpus-cc / ccTLD first, ip-api for the rest
    need_ip_geo = []
    for r in records:
        cc = args.corpus_cc or cctld_country(r["host"])
        if cc:
            r["cc"] = cc
        elif r.get("ip"):
            need_ip_geo.append(r["ip"])
    if need_ip_geo:
        ipcc = geo_by_ip(sorted(set(need_ip_geo)))
        for r in records:
            if not r["cc"] and r.get("ip"):
                r["cc"] = ipcc.get(r["ip"], "ZZ")
    for r in records:
        r["cc"] = r["cc"] or "ZZ"

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    alive = [r for r in records if not r.get("dead")]
    warm = [r for r in alive if r["risk"] >= 2]
    print(f"[globe-patrol] scanned={len(records)} alive={len(alive)} "
          f"warm(risk>=2)={len(warm)} → {LEDGER}")
    for r in sorted(warm, key=lambda x: -x["risk"])[:12]:
        print(f"   🔥 [{r['cc']}] risk={r['risk']} {r['host']} {','.join(r['signals'])}")

    st["cursor"] = (cur + args.slice) % len(hosts)
    st["runs"] = st.get("runs", 0) + 1
    st["scanned_total"] = st.get("scanned_total", 0) + len(records)
    st["last_run"] = now_iso()
    STATE.write_text(json.dumps(st, indent=2))

    # refresh the world heatmap for the Globe view
    try:
        import subprocess
        subprocess.run([sys.executable, str(Path(__file__).parent / "globe-aggregate.py")], timeout=60)
    except Exception as e:
        print(f"[globe-patrol] aggregate skipped: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
