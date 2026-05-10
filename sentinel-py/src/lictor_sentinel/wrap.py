"""
The ``wrap()`` function — Sentinel's entire user-facing API in Python.

Mirrors the TypeScript implementation. v0.1 returns the client unchanged
(no-op); the real interception lands W7 (June 22 onward) when the Python
implementation is filled in against `lictor-core` via PyO3 bindings or
pure-Python ports of the check rules.

Until then, this stub lets users write::

    from lictor_sentinel import wrap

    client = wrap(OpenAI(), config={...})

with no runtime difference, so they can adopt the dependency early.
"""

from __future__ import annotations

from typing import Any

from .types import SentinelConfig


def wrap(client: Any, config: SentinelConfig | None = None) -> Any:
    """
    Wrap an AI client (OpenAI, Anthropic, or any object) so model calls
    pass through Sentinel's checks before reaching the provider, and the
    provider's response passes through Sentinel's checks before reaching
    the caller.

    v0.1 returns the client unchanged. W7 lands the real interception via
    a Python-level analog of the TS Proxy pattern (most likely
    ``__getattr__`` on a wrapping class, since Python doesn't have Proxy).

    The function signature is the contract — it won't change between v0.1
    and v1.0. Code written against this stub today will work against the
    real implementation tomorrow.
    """
    _ = config  # accepted but unused at v0.1
    return client
