"""
Guardian telemetry sender (Python).

Mirrors @lictor/sentinel/src/telemetry.ts. Same wire format, same retry
policy, same privacy invariants (never ships raw user content). Uses
urllib (stdlib) — zero runtime dependencies.

Best-effort by design: failures never block the user's model call.
"""

from __future__ import annotations

import dataclasses
import json
import random
import time
import urllib.error
import urllib.request
from typing import Callable

from .agent_id import AGENT_ID
from .types import GuardianConfig, IncidentEvent

ENVELOPE_VERSION = "1"
LICTOR_CORE_VERSION = "0.1.0"
SENTINEL_VERSION = "0.1.0a0"

_DEFAULT_TIMEOUT_S = 5.0
_MAX_RETRIES = 3
_BASE_BACKOFF_S = 0.2
_MAX_QUEUE = 100


def _event_to_wire(e: IncidentEvent) -> dict:
    """Serialize an IncidentEvent dataclass to the wire-format JSON shape.

    Note: wire format uses camelCase (matches TS); Python dataclass uses
    snake_case (Python convention). This is the translation layer.
    """
    return {
        "ts": e.ts,
        "agentId": e.agent_id,
        "phase": e.phase,
        "checkId": e.check_id,
        "severity": e.severity,
        "title": e.title,
        "detail": e.detail,
        "model": dataclasses.asdict(e.model),
        "fingerprint": e.fingerprint,
        "action": e.action,
        "sentinelVersion": e.sentinel_version,
    }


def build_envelope(event: IncidentEvent) -> dict:
    """Build a wire-format envelope around a single event."""
    return {
        "envelope_version": ENVELOPE_VERSION,
        "sentinel_version": SENTINEL_VERSION,
        "lictor_core_version": LICTOR_CORE_VERSION,
        "agent_id": AGENT_ID,
        "sent_at": _now_iso(),
        "events": [_event_to_wire(event)],
    }


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


# Pluggable transport for tests. Returns (status, body_text).
# Default uses urllib; tests inject a mock.
Transport = Callable[[str, bytes, dict[str, str], float], tuple[int, str]]


def _urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


_transport: Transport = _urllib_transport
_in_flight = 0


def set_transport_for_tests(t: Transport | None) -> None:
    """Override the transport. Tests use this to inject a mock."""
    global _transport
    _transport = t if t is not None else _urllib_transport


def pending_count() -> int:
    """Number of in-flight sends (for tests / health checks)."""
    return _in_flight


def send_to_guardian(event: IncidentEvent, config: GuardianConfig) -> None:
    """
    Send a single event to Guardian. Best-effort, synchronous (Python's
    sync model — the application can run this in a thread / background
    task if it wants to avoid blocking the model call).

    Retry policy mirrors the TS SDK:
      - 5xx / network error → up to 3 retries with exponential backoff
      - 4xx → permanent failure, no retry
      - 2xx → success
    """
    global _in_flight
    if _in_flight >= _MAX_QUEUE:
        return  # drop; never accumulate unbounded under outage
    _in_flight += 1
    try:
        _send_with_retry(event, config)
    finally:
        _in_flight -= 1


def _send_with_retry(event: IncidentEvent, config: GuardianConfig) -> None:
    body_dict = build_envelope(event)
    body = json.dumps(body_dict).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.get('token', '')}",
    }
    timeout = config.get("timeout_ms", _DEFAULT_TIMEOUT_S * 1000) / 1000

    for attempt in range(_MAX_RETRIES + 1):
        try:
            status, _ = _transport(
                config.get("endpoint", ""),
                body,
                headers,
                timeout,
            )
            if 200 <= status < 300:
                return  # success
            if 400 <= status < 500:
                return  # permanent
            # 5xx: fall through to retry
        except Exception:
            # Network error: fall through to retry
            pass

        if attempt < _MAX_RETRIES:
            backoff = _BASE_BACKOFF_S * (2**attempt)
            jitter = backoff * (0.8 + random.random() * 0.4)
            time.sleep(jitter)
    # All retries exhausted.
