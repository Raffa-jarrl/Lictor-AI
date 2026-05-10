# lictor-sentinel (Python)

> Wraps OpenAI / Anthropic Python SDKs to block prompt injection, data exfiltration, and unsafe AI behaviour.

## Status

Pre-alpha **stub**. Sister package to [`@lictor/sentinel`](../sentinel/) (TypeScript).

| Feature | Status |
|---|---|
| `wrap()` API surface + types | ✅ stable, mirrors the TS contract |
| Real interception | ⏳ W7 (June 22, 2026) — same proxy semantics, Python-flavoured |
| Real checks (prompt-injection / pii-leak / secrets-in-input) | ⏳ W7-8 |
| Telemetry → Guardian | ⏳ W8 |

## Install

```bash
pip install lictor-sentinel
# or, with uv
uv add lictor-sentinel
```

## Quick start

```python
from openai import OpenAI
from lictor_sentinel import wrap

client = wrap(OpenAI(), config={
    "preflight": ["prompt-injection", "secrets-in-input"],
    "postflight": ["pii-leak"],
    "on_incident": lambda event: print(f"[lictor] {event.severity}: {event.title}"),
})

# Same call site — Sentinel intercepts pre-flight and post-flight.
completion = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}],
)
```

## Privacy contract

Same as the TypeScript SDK — Sentinel **never** ships raw user content. See [`../docs/specs/wire-format.md`](../docs/specs/wire-format.md) §4 for the privacy invariants.

## Develop

```bash
pip install -e '.[dev]'
pytest
```

## License

MIT.
