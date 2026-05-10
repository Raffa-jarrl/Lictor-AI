"""
Public types — Python mirror of the TypeScript SDK's `types.ts`.

These are the contract from `docs/specs/sentinel-api.md`. Keep in lockstep
with the TS definitions; breaking changes are major version bumps and
must update the spec + the wire format in the same release.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, TypedDict

SENTINEL_VERSION = "0.1.0a0"

CheckId = Literal[
    "prompt-injection",
    "secrets-in-input",
    "pii-leak",
    "unsafe-tool-call",  # v0.2
]
"""The set of checks Sentinel can run. v0.1 ships the first three."""

Severity = Literal["critical", "high", "medium", "low", "info"]
"""Severity ranking, matching `lictor-core::Severity`."""

TripAction = Literal["log", "block", "redact"]
"""What to do when a check trips."""

Phase = Literal["preflight", "postflight"]
"""Which side of the model call the check ran on."""

IncidentAction = Literal["logged", "blocked", "redacted"]
"""What action was taken on this specific event."""


@dataclass(frozen=True)
class IncidentModel:
    """Reference to the model whose call triggered the incident."""

    provider: Literal["openai", "anthropic", "other"]
    name: str


@dataclass(frozen=True)
class IncidentEvent:
    """
    Single event Sentinel emits per check trip.

    Same shape goes to ``on_incident`` callbacks AND across the wire to
    Guardian. Privacy invariant: never contains raw user content. See
    ``docs/specs/wire-format.md`` §4.
    """

    ts: str
    agent_id: str
    phase: Phase
    check_id: CheckId
    severity: Severity
    title: str
    detail: str
    model: IncidentModel
    fingerprint: str
    action: IncidentAction
    sentinel_version: str


class GuardianConfig(TypedDict, total=False):
    """Optional Guardian connector configuration."""

    endpoint: str
    token: str
    timeout_ms: int


class SentinelConfig(TypedDict, total=False):
    """The full Sentinel configuration, passed to ``wrap()``."""

    preflight: list[CheckId]
    postflight: list[CheckId]
    on_trip: TripAction
    on_incident: Callable[[IncidentEvent], None]
    guardian: GuardianConfig


class SentinelBlockedError(Exception):
    """Raised when ``on_trip == 'block'`` and a check trips."""

    incident: IncidentEvent

    def __init__(self, incident: IncidentEvent) -> None:
        super().__init__(
            f"[lictor:sentinel] blocked by {incident.check_id}: {incident.title}"
        )
        self.incident = incident
