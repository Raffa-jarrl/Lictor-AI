"""
Smoke tests for the v0.1 wrap() stub.

The full integration test suite (matching the TS suite) lands W7 alongside
the real Python implementation.
"""

from __future__ import annotations

import re

import pytest

from lictor_sentinel import (
    SENTINEL_VERSION,
    IncidentEvent,
    IncidentModel,
    SentinelBlockedError,
    wrap,
)


def test_wrap_returns_client_unchanged_at_v01() -> None:
    fake_client = object()
    assert wrap(fake_client) is fake_client


def test_wrap_accepts_a_config() -> None:
    fake_client = object()
    wrapped = wrap(fake_client, config={"preflight": ["prompt-injection"]})
    assert wrapped is fake_client


def test_sentinel_version_is_set() -> None:
    assert re.match(r"^\d+\.\d+\.\d+", SENTINEL_VERSION)


def test_incident_event_is_frozen_dataclass() -> None:
    ev = IncidentEvent(
        ts="2026-10-06T14:00:00Z",
        agent_id="agent-test",
        phase="preflight",
        check_id="prompt-injection",
        severity="high",
        title="test",
        detail="test detail",
        model=IncidentModel(provider="openai", name="gpt-4"),
        fingerprint="abcdef0123456789",
        action="logged",
        sentinel_version=SENTINEL_VERSION,
    )
    assert ev.severity == "high"
    with pytest.raises(Exception):  # frozen dataclass — assignment raises
        ev.severity = "low"  # type: ignore[misc]


def test_sentinel_blocked_error_carries_the_incident() -> None:
    ev = IncidentEvent(
        ts="2026-10-06T14:00:00Z",
        agent_id="agent-test",
        phase="preflight",
        check_id="prompt-injection",
        severity="critical",
        title="bad input",
        detail="test",
        model=IncidentModel(provider="anthropic", name="claude-3-sonnet"),
        fingerprint="0123456789abcdef",
        action="blocked",
        sentinel_version=SENTINEL_VERSION,
    )
    err = SentinelBlockedError(ev)
    assert err.incident is ev
    assert "prompt-injection" in str(err)
