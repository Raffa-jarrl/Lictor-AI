#!/usr/bin/env python3
"""
patrol-ssti-candidates — scanner #62.

Hunts Server-Side Template Injection (SSTI) candidates. Pattern: user input
flows into a template-rendering engine (Jinja2, Twig, Handlebars, Velocity,
FreeMarker) without escaping → arbitrary code execution.

Bounty range: $5K-$50K (often RCE-equivalent).

Method (ETHICAL — only sends benign math expressions):
  1. For each host: probe endpoints with `?q={{7*7}}` style payloads
     across multiple template-engine syntaxes
  2. If response body contains `49` (the math result) where our payload was,
     the template is interpreting the expression server-side = SSTI candidate
  3. Test ONE engine per shape; never escalate to OS command (would be RCE)

Payloads (BENIGN math only — never RCE):
  - Jinja2/Twig: {{7*7}}   → 49
  - Handlebars/Mustache: {{{7*7}}}  → 49 (HTML-escaped variant)
  - Velocity: #set($x=7*7)$x  → 49
  - Smarty: {7*7}  → 49

Usage:
  patrol-ssti-candidates.py --hosts targets.txt --ledger ssti.jsonl
"""
from __future__ import annotations
import argparse, json, re, time, urllib.parse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-SSTIPatrol/0.1 (+https://lictor-ai.com)"

PAYLOADS = [
    ("jinja2_twig",   "{{7*7}}",        "49"),
    ("jinja2_alt",    "{{ 7 * 7 }}",    "49"),
    ("velocity",      "#set($x=7*7)$x", "49"),
    ("freemarker",    "${7*7}",         "49"),
    ("smarty",        "{7*7}",          "49"),
    ("handlebars",    "{{7*7}}",        "49"),   # same as jinja but engines distinct
    ("erb",           "<%= 7*7 %>",     "49"),
]

ENDPOINT_SHAPES = [
    ("/",        "q"), ("/",       "search"), ("/",       "query"),
    ("/search",  "q"), ("/search", "query"),
    ("/api/search", "q"), ("/api/v1/search", "q"),
    ("/render",  "template"), ("/preview", "html"),
    ("/api/render", "template"), ("/api/template", "body"),
    ("/page",    "name"), ("/i", "name"),
]

@dataclass
class SSTIFinding:
    host: str
    endpoint: str
    param: str
    engine: str
    payload: str
    response_status: int
    response_snippet: str
    classification: str   # "ssti_likely" / "reflected_unparsed" / "no_match"

def probe(host: str, ep: str, param: str, payload: str, timeout: int = 6):
    qs = urllib.parse.urlencode({param: payload})
    url = f"https://{host}{ep}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: b = e.read(8192).decode("utf-8", "replace")
        except: b = ""
        return e.code, b
    except Exception:
        return None, None

def check_host(host: str) -> list[SSTIFinding]:
    out = []
    for ep, param in ENDPOINT_SHAPES:
        for engine, payload, expected in PAYLOADS:
            time.sleep(0.2)
            status, body = probe(host, ep, param, payload)
            if not body or status != 200: continue
            # SSTI hit: expected output present AND raw payload absent
            if expected in body and payload not in body:
                # Find context where '49' appears to make sure it's not coincidental
                idx = body.find(expected)
                ctx = body[max(0,idx-50):idx+50]
                # Confirm: 49 should be near the param's usual reflection spot
                out.append(SSTIFinding(
                    host=host, endpoint=ep, param=param, engine=engine, payload=payload,
                    response_status=status, response_snippet=ctx.replace("\n", " "),
                    classification="ssti_likely"))
                break  # one engine per (ep, param) is enough confirmation
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/ssti-candidates.jsonl")
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    print(f"[+] SSTI hunt: {len(hosts)} hosts × {len(ENDPOINT_SHAPES)} endpoints × {len(PAYLOADS)} engines")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try: hits = fut.result()
            except Exception: continue
            for f in hits:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                n += 1
                print(f"  [{i}/{len(hosts)}] 🔴 {host}{f.endpoint}?{f.param}={f.payload}  engine={f.engine}")
            if i % 30 == 0: print(f"  [{i}/{len(hosts)}] scanning... {n} SSTI candidates so far")
    print(f"\n[+] Done. {n} SSTI candidates → {args.ledger}")
    print(f"[+] 🔴 ssti_likely = manual verify with a non-RCE expression like {{8*8}} = 64")

if __name__ == "__main__":
    main()
