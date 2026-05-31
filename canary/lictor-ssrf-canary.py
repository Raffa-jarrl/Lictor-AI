#!/usr/bin/env python3
"""
lictor-ssrf-canary — public-facing HTTP listener for SSRF confirmation.

Deploy this on any publicly-reachable host (Vercel, Render, Railway, a small VPS,
even a $5/mo droplet). The patrol-import-ssrf scanner sends each target a URL
parameter pointing to this canary. If the target's server fetches the URL
server-side, the canary receives the request and we have CONFIRMED SSRF.

Deployment paths:

  1. Local dev / VPS:
        python3 lictor-ssrf-canary.py --port 8080
     Then expose port 8080 publicly via your firewall.

  2. Vercel (recommended free tier):
        - Create new Vercel project, framework = "Other"
        - Place this file at api/canary.py
        - Add vercel.json:
            { "rewrites": [{ "source": "/(.*)", "destination": "/api/canary" }] }
        - Deploy. Public URL = https://your-project.vercel.app

  3. Railway / Render / Fly.io / any container host:
        Use the included Dockerfile snippet at the bottom of this file.

What the canary does:
  - Listens on the configured port
  - Logs EVERY incoming request: timestamp, source IP, path, query, headers
  - Writes log entries as JSONL to canary-log.jsonl
  - Responds with an innocuous HTML page (so server-side fetchers see a "valid" response)
  - Provides /lictor-status to view recent hits without parsing the log

To confirm SSRF candidates:
  After running patrol-import-ssrf, grep canary-log.jsonl for any path that
  starts with /lictor-<host>-<timestamp>. Each match = ONE confirmed SSRF
  (your scanner's URL parameter reached the canary).

EXAMPLE: the scanner sent http://my-canary.example.com/lictor-shopify-com-1738012345
If you see in canary-log.jsonl:
  {"ts": "...", "ip": "23.x.x.x", "path": "/lictor-shopify-com-1738012345", ...}
then shopify.com fetched our URL server-side. CONFIRMED SSRF on whatever endpoint
that shopify.com URL was. Cross-reference against the import-ssrf.jsonl ledger.
"""
from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG_FILE = Path("canary-log.jsonl")
RECENT_HITS = []  # in-memory ring buffer for /lictor-status
MAX_RECENT = 200

INNOCUOUS_HTML = b"""<!DOCTYPE html>
<html><head><title>Lictor Canary</title></head>
<body>
<h1>Lictor SSRF Canary</h1>
<p>This is a security-research canary endpoint operated by Lictor
(<a href="https://lictor-ai.com">lictor-ai.com</a>).</p>
<p>If you reached this page via a server-side fetch from your application,
your application has a Server-Side Request Forgery (SSRF) vulnerability.
The Lictor team will be in touch via coordinated-disclosure channels.</p>
<p>If you reached this page by accident in a browser, you can safely ignore it.</p>
</body></html>
"""

class CanaryHandler(BaseHTTPRequestHandler):
    def _record(self, method: str):
        global RECENT_HITS
        # X-Forwarded-For is set by most reverse-proxies (Vercel/Render/etc.)
        ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
             or self.client_address[0]
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": self.path,
            "ip": ip,
            "user_agent": self.headers.get("User-Agent", ""),
            "host_hdr": self.headers.get("Host", ""),
            "referer": self.headers.get("Referer", ""),
            "x_forwarded_for": self.headers.get("X-Forwarded-For", ""),
            "via": self.headers.get("Via", ""),
            "all_headers": dict(self.headers),
        }
        try:
            with LOG_FILE.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[canary] log write failed: {e}", file=sys.stderr)
        RECENT_HITS.append(entry)
        if len(RECENT_HITS) > MAX_RECENT:
            RECENT_HITS = RECENT_HITS[-MAX_RECENT:]
        print(f"[canary] {method} {self.path} from {ip} UA={entry['user_agent'][:50]!r}")

    def _serve_status(self):
        payload = json.dumps({
            "canary": "lictor-ssrf-canary",
            "total_hits_in_buffer": len(RECENT_HITS),
            "recent": RECENT_HITS[-50:]
        }, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/lictor-status" or self.path == "/lictor-status/":
            return self._serve_status()
        self._record("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(INNOCUOUS_HTML)))
        self.send_header("X-Lictor-Canary", "yes")
        self.end_headers()
        self.wfile.write(INNOCUOUS_HTML)

    def do_POST(self):
        self._record("POST")
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(min(length, 8192))
            # Log the body too (truncated) so we see what the SSRF sender was POSTing
            with LOG_FILE.open("a") as f:
                f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                     "kind": "post_body", "path": self.path,
                                     "body": body[:2000].decode("utf-8", "replace")}) + "\n")
        except Exception:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_HEAD(self):
        self._record("HEAD")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(INNOCUOUS_HTML)))
        self.end_headers()

    def log_message(self, format, *args):
        return  # silence default access log; we have our own

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--log", default="canary-log.jsonl")
    args = ap.parse_args()

    global LOG_FILE
    LOG_FILE = Path(args.log)
    print(f"[+] Lictor SSRF canary starting")
    print(f"[+] Listening on http://{args.bind}:{args.port}")
    print(f"[+] Log: {LOG_FILE.absolute()}")
    print(f"[+] Status endpoint: /lictor-status")
    print(f"[+] Stop with Ctrl-C")

    server = HTTPServer((args.bind, args.port), CanaryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[+] Canary stopped. Total in-memory hits: {len(RECENT_HITS)}")
        print(f"[+] Log preserved at: {LOG_FILE.absolute()}")

if __name__ == "__main__":
    main()

# DOCKERFILE (for Render/Railway/Fly.io/etc.):
# ----
# FROM python:3.11-slim
# WORKDIR /app
# COPY lictor-ssrf-canary.py .
# EXPOSE 8080
# CMD ["python3", "lictor-ssrf-canary.py", "--port", "8080"]
# ----
