#!/usr/bin/env python3
"""
Otter's primary tool — HTTP probe with full response capture + secondary 200-endpoint probe.

The KEY v3 behavior: when a 4xx response has reflect-with-creds CORS headers,
this tool AUTOMATICALLY probes a known-good 200 endpoint (homepage / robots.txt)
with the same attacker-Origin header. The secondary probe is included in the
output as `secondary_200_probe` so Owl can compare and filter the
"CORS error-page-only" FP class.

Output: one JSON line per probe, suitable for appending to output/prober-*.jsonl.

Usage:
  python3 scripts/probe-http.py {url} [--cname {cname}] [--apex {apex}]
  python3 scripts/probe-http.py --from-jsonl scout-2026-05-21.jsonl --out prober-2026-05-21.jsonl
"""
from __future__ import annotations
import argparse, json, socket, ssl, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

UA = "Lictor-v3-Otter/0.1 (+https://lictor-ai.com)"
ATTACKER_ORIGIN = "https://attacker.example.com"  # neutral test origin


def resolve_cname(host: str) -> str:
    """Get the CNAME target for a hostname. Empty string if no CNAME."""
    try:
        import dns.resolver
        try:
            resp = dns.resolver.resolve(host, "CNAME", lifetime=5)
            return str(resp[0].target).rstrip(".")
        except Exception:
            return ""
    except ImportError:
        import subprocess
        try:
            out = subprocess.check_output(["dig", "+short", "CNAME", host], stderr=subprocess.DEVNULL, timeout=5)
            line = out.decode().strip().splitlines()[0] if out.strip() else ""
            return line.rstrip(".")
        except Exception:
            return ""


def fetch_response(url: str, with_attacker_origin: bool = True, timeout: int = 8) -> dict:
    """Fetch URL, return {status, headers, body_snippet}."""
    headers = {"User-Agent": UA}
    if with_attacker_origin:
        headers["Origin"] = ATTACKER_ORIGIN
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(20000).decode("utf-8", "replace")
            return {
                "url": url,
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body_first_20k": body,
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {
            "url": url,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body_first_20k": body,
        }
    except Exception as ex:
        return {"url": url, "status": 0, "headers": {}, "body_first_20k": "", "error": str(ex)[:200]}


def needs_secondary_probe(primary: dict) -> bool:
    """Does this primary response warrant a secondary 200-endpoint probe?

    The v3 trigger: 4xx response WITH `access-control-allow-credentials: true`
    AND `access-control-allow-origin` containing the attacker origin (reflect pattern).
    """
    if primary.get("status", 0) < 400:
        return False  # primary already a 200, no secondary needed
    h = primary.get("headers", {})
    if h.get("access-control-allow-credentials", "").lower() != "true":
        return False
    acao = h.get("access-control-allow-origin", "")
    return ATTACKER_ORIGIN in acao or acao == "*"


def probe_secondary(apex: str) -> Optional[dict]:
    """Probe a known-good 200 endpoint on the apex. Try homepage, robots.txt, /."""
    candidates = [
        f"https://{apex}/",
        f"https://www.{apex}/",
        f"https://{apex}/robots.txt",
        f"https://{apex}/health",
    ]
    for c_url in candidates:
        resp = fetch_response(c_url)
        if resp.get("status", 0) == 200:
            return resp
    # Fall back to whatever the first probe returned
    return fetch_response(f"https://{apex}/")


def probe_one(subdomain: str, apex: str = "", cname: str = "") -> dict:
    """Full v3 probe pipeline: primary HTTPS, fall back to HTTP, secondary if needed."""
    if not apex:
        apex = ".".join(subdomain.split(".")[-2:]) if "." in subdomain else subdomain
    if not cname:
        cname = resolve_cname(subdomain)

    # Try HTTPS first
    primary = fetch_response(f"https://{subdomain}/")
    if primary.get("status", 0) == 0:
        # HTTPS failed → try HTTP
        primary = fetch_response(f"http://{subdomain}/")

    result = {
        "subdomain": subdomain,
        "apex": apex,
        "cname": cname,
        "primary": primary,
        "probed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if needs_secondary_probe(primary):
        result["secondary_200_probe"] = probe_secondary(apex)

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("subdomain", nargs="?", help="Single subdomain to probe")
    ap.add_argument("--apex", default="", help="Override apex (else inferred)")
    ap.add_argument("--cname", default="", help="Pre-resolved CNAME (else looked up)")
    ap.add_argument("--from-jsonl", help="Read subdomain candidates from JSONL file (one subdomain per line, or with 'subdomain' field)")
    ap.add_argument("--out", help="Append output to this JSONL file (else stdout)")
    args = ap.parse_args()

    if args.subdomain:
        result = probe_one(args.subdomain, args.apex, args.cname)
        line = json.dumps(result)
        if args.out:
            with open(args.out, "a") as f:
                f.write(line + "\n")
        else:
            print(line)
        return

    if args.from_jsonl:
        in_path = Path(args.from_jsonl)
        if not in_path.exists():
            sys.exit(f"❌ Input file not found: {in_path}")
        out_fp = open(args.out, "a") if args.out else sys.stdout
        with in_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    rec = json.loads(line)
                    sub = rec.get("subdomain", "")
                    apex = rec.get("apex", "")
                else:
                    sub = line
                    apex = ""
                if not sub:
                    continue
                result = probe_one(sub, apex)
                out_fp.write(json.dumps(result) + "\n")
                out_fp.flush()
        if args.out:
            out_fp.close()
        return

    ap.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
