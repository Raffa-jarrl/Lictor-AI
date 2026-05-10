"""
lictor-sentinel — wraps OpenAI / Anthropic Python clients to block prompt
injection, data exfiltration, and unsafe AI behaviour.

Sister package to @lictor/sentinel (TypeScript). Same API surface, same
wire format to Guardian, same `IncidentEvent` shape.

See ../docs/specs/sentinel-api.md for the full contract.
"""

from .types import (
    SENTINEL_VERSION,
    CheckId,
    GuardianConfig,
    IncidentAction,
    IncidentEvent,
    IncidentModel,
    Phase,
    SentinelBlockedError,
    SentinelConfig,
    Severity,
    TripAction,
)
from .wrap import wrap

__all__ = [
    "SENTINEL_VERSION",
    "CheckId",
    "GuardianConfig",
    "IncidentAction",
    "IncidentEvent",
    "IncidentModel",
    "Phase",
    "SentinelBlockedError",
    "SentinelConfig",
    "Severity",
    "TripAction",
    "wrap",
]
