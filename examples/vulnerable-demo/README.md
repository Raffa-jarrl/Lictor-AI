# Vulnerable Demo

A static HTML page with **deliberately** seeded vulnerabilities. Used as a fixture to validate that `lictor-core` actually catches the bugs it claims to catch.

> **DO NOT** deploy this to a real domain. The seeded "secrets" are fake but the file is laid out to look exactly like a careless AI-built app.

## Run it

From the repo root:

```bash
# Spin up a local HTTP server in this directory
( cd examples/vulnerable-demo && python3 -m http.server 8765 ) &
SERVER_PID=$!

# Run the native CLI against it
cargo run --release --example audit -- http://localhost:8765/ -o /tmp/demo-report.md

# Tear down
kill $SERVER_PID

# Read the report
less /tmp/demo-report.md
```

## What you should see

A report with at least:
- **Critical**: OpenAI API key in page HTML
- **Critical**: Anthropic API key in page HTML
- **Critical**: Stripe live secret key in page HTML
- **Critical**: PostgreSQL connection string in page HTML
- **Info**: Stripe publishable key (informational)
- **Medium**: AI agent / chat surface detected (api.openai.com)
- A handful of high/info findings as the auth/CORS/admin probes run

If the report doesn't include those, `lictor-core`'s pattern matchers regressed.
