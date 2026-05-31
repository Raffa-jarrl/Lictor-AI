# lictor-sentinel (Python)

> 🤖 **Part of the [Lictor AI security suite](../README.md)** — Lictor for AI. Sentinel guards the **prompt** boundary (Python SDK).

> The security crew for apps you built with AI — runtime defense for your OpenAI / Anthropic calls.
> Sister package to [`@lictor/sentinel`](https://www.npmjs.com/package/@lictor/sentinel) (TypeScript). Same API contract, Pythonic ergonomics.

[![PyPI](https://img.shields.io/pypi/v/lictor-sentinel.svg)](https://pypi.org/project/lictor-sentinel/)
[![Python](https://img.shields.io/pypi/pyversions/lictor-sentinel.svg)](https://pypi.org/project/lictor-sentinel/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: pre-release.** `lictor-sentinel` is not on PyPI yet — the PyPI badges above go live at GA (Oct 6, 2026). Until then, [install from source](#install-from-source-available-today) (works today).

## Why Sentinel

Any Python app that calls `openai.chat.completions.create()` or `anthropic.messages.create()` with user-controlled input is one prompt-injection payload away from acting against the user's interest.

Sentinel intercepts every call — same call site, same response shape:

```python
from openai import OpenAI
from lictor_sentinel import wrap

# Before:
client = OpenAI()

# After:
client = wrap(OpenAI(), config={
    "preflight":  ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
})

# Your existing code works unchanged.
completion = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}],
)
```

## What Sentinel catches

**Prompt injection (32 patterns across 7 attack families):**

| Family | Severity | What it catches |
|---|---|---|
| direct-override | high / medium | "ignore previous instructions", "from now on", "your real goal is…" |
| authority-impersonation | high | `System:`, `[SYSTEM]`, "admin override", "developer mode enabled" |
| jailbreak | high / medium | DAN-style personas, "act as evil AI", "you have been jailbroken" |
| system-prompt-extraction | medium / high | "repeat your system prompt", "what were your initial instructions" |
| delimiter-injection | **critical** | Model-control tokens: `<\|im_start\|>`, `[INST]`, fake `Assistant:` turn boundaries |
| goal-hijacking | medium | "instead of that, do this", "your new objective is…" |
| suspicious-encoding | medium | Long base64 strings, hex-escape soup, zero-width characters |

**Secrets in input (15 patterns)**: OpenAI/Anthropic/Stripe/GitHub/AWS/Slack/Google keys, JWT tokens, MongoDB connection strings, private keys. Catches users accidentally pasting their own credentials into prompts.

**PII in output**: credit-card numbers (Luhn-validated), social security numbers, email addresses leaked from training data. Configurable per-field.

## Install

Requires Python 3.10+.

### Coming at launch (Oct 6, 2026)

At GA, Sentinel will be on PyPI and these will Just Work:

```bash
pip install lictor-sentinel
# or with uv:
uv add lictor-sentinel
# or with poetry:
poetry add lictor-sentinel
```

> Not published yet — running these today returns a 404. Use the from-source path below in the meantime.

### Install from source (available today)

Install straight from the cloned repo (PEP 517 source install):

```bash
git clone https://github.com/Raffa-jarrl/Lictor-AI
cd Lictor-AI/sentinel-py
python3 -m pip install .
```

Prefer to build a wheel first (e.g. to vendor it or install into another env)? Use `build`:

```bash
python3 -m pip install build
python3 -m build              # → dist/lictor_sentinel-0.1.0a0-py3-none-any.whl (+ .tar.gz sdist)
python3 -m pip install dist/lictor_sentinel-0.1.0a0-py3-none-any.whl
```

Either way, import exactly as documented below — the import name is `lictor_sentinel`:

```python
from lictor_sentinel import wrap
```

## Quick start

### With OpenAI

```python
from openai import OpenAI
from lictor_sentinel import wrap

def on_incident(event):
    print(f"[lictor] {event.severity}: {event.title}")

client = wrap(OpenAI(), config={
    "preflight":  ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
    "on_incident": on_incident,
})

# Same call site — Sentinel intercepts pre-flight and post-flight.
completion = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}],
)
```

### With Anthropic

```python
from anthropic import Anthropic
from lictor_sentinel import wrap

client = wrap(Anthropic(), config={
    "preflight":  ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
})

message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": user_input}],
)
```

### With async clients

Both OpenAI and Anthropic's async clients work the same way:

```python
from openai import AsyncOpenAI
from lictor_sentinel import wrap

client = wrap(AsyncOpenAI(), config={
    "preflight": ["prompt-injection"],
})

async def chat(user_input):
    return await client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_input}],
    )
```

### With Guardian (optional — for team-level monitoring)

```python
import os
from lictor_sentinel import wrap

client = wrap(OpenAI(), config={
    "preflight":  ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
    "guardian": {
        "endpoint": "https://app.lictorai.com/api/ingest",
        "token": os.environ["LICTOR_GUARDIAN_TOKEN"],
    },
})
```

Guardian gives you: per-incident timeline, audit-log export for SOC 2 / GDPR / EU AI Act evidence, Slack webhook for critical incidents. Free preview at app.lictorai.com.

## Privacy contract

Sentinel **never** ships raw user content to Guardian. The wire format includes only:
- Severity (`critical` / `high` / `medium` / `low` / `info`)
- Check ID (`prompt-injection` / `secrets-in-input` / `pii-leak`)
- 16-hex-char fingerprint (sha256 of the first 4 KB of content)
- Timestamp + request metadata

See [`docs/specs/wire-format.md`](https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/specs/wire-format.md) §4 for the privacy invariants.

Telemetry is opt-in: if `guardian` config is absent, no network calls are made. Sentinel works fully offline.

## Configuration

| Option | Type | Default | Purpose |
|---|---|---|---|
| `preflight` | `list[str]` | `["prompt-injection"]` | Checks to run on input before LLM call |
| `postflight` | `list[str]` | `[]` | Checks to run on output after LLM call |
| `mode` | `"block" \| "log" \| "redact"` | `"block"` | What to do on incident |
| `on_incident` | `Callable[[Event], None]` | None | Hook fired on every incident |
| `guardian` | `dict` | None | Telemetry destination (opt-in) |
| `fingerprint_bytes` | `int` | `4096` | Size of fingerprinted prefix |

## Type hints

The package ships with full type hints (`py.typed` marker). All `wrap()` returns preserve the wrapped client's type signature, so mypy / pyright will catch usage errors.

```python
from openai import OpenAI
from lictor_sentinel import wrap

client: OpenAI = wrap(OpenAI())  # OpenAI client interface preserved
```

## Troubleshooting

**"Sentinel is blocking legitimate inputs."**
Switch to `mode: "log"` first. Sentinel will report incidents but not block. Review the captured incidents at app.lictorai.com/incidents (if Guardian is wired) or in the `on_incident` callback.

**"My async/streaming responses aren't intercepted."**
Post-flight checks on streaming responses ship in v0.2 (Q1 2027). For v0.1, post-flight only runs on the final completion message. Pre-flight always runs.

**"Guardian telemetry isn't appearing."**
Confirm the token in `guardian.token` matches the project token in your Guardian project settings. Check `print()` output for `[lictor] outbound telemetry error` — common causes: firewall blocking outbound to `app.lictorai.com`, or token revocation.

## How Sentinel fits in the Lictor suite

- **Lictor Skill Suite** — audit your Python project once with `/lictor-security-check`
- **`lictor-sentinel`** — *you are here* — runtime defense in your Python app
- **`@lictor/sentinel`** — sister TypeScript package, same contract
- **Lictor Guardian** — hosted dashboard for incidents + compliance evidence
- **Lictor Studio** — offline desktop audit for privacy-paranoid devs

Most teams shipping AI features want Sentinel + Guardian. Both are free for individuals.

## Develop

```bash
pip install -e '.[dev]'
pytest
mypy lictor_sentinel
ruff check .
```

## License

[Apache-2.0](LICENSE). The Lictor commitment: this code stays free and open forever. Pro features for Studio + Guardian ship under BUSL with 4-year Apache-2.0 conversion (per Lictor's [legal structure memo](https://github.com/Raffa-jarrl/Lictor-AI/blob/main/docs/launch/legal-structure-memo.md)).

## Links

- **Main repo**: [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI)
- **Documentation**: [lictorai.com/sentinel](https://lictorai.com/sentinel)
- **TypeScript sibling**: [`@lictor/sentinel` on npm](https://www.npmjs.com/package/@lictor/sentinel)
- **Issues + feature requests**: [github.com/Raffa-jarrl/Lictor-AI/issues](https://github.com/Raffa-jarrl/Lictor-AI/issues)
- **Security disclosure**: security@lictorai.com

Built by a 20-year cybersecurity engineer. Tested across [12+ public teardowns](https://lictorai.com/teardowns) of real vibe-coded apps.
