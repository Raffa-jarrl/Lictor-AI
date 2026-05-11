"""
The wrap() function — Python mirror of @lictor/sentinel's src/wrap.ts.

Python doesn't have JavaScript's Proxy, so we use a wrapping class with
__getattr__ that walks the dotted-path the way a JS Proxy would. The
end result: `wrap(client).chat.completions.create(args)` is intercepted
identically to the TypeScript SDK.

v0.1 ships preflight + postflight check dispatch end-to-end. Real checks
(prompt-injection, pii-leak, secrets-in-input) are registered as
side-effect of importing `lictor_sentinel`.
"""

from __future__ import annotations

import time
import threading
from typing import Any

from .agent_id import AGENT_ID
from .check_runner import run_checks
from .extractors import KNOWN_PATHS, extract_input_text, extract_model_name, extract_output_text
from .fingerprint import fingerprint
from .telemetry import SENTINEL_VERSION, send_to_guardian
from .types import (
    IncidentAction,
    IncidentEvent,
    IncidentModel,
    SentinelBlockedError,
    SentinelConfig,
)


def wrap(client: Any, config: SentinelConfig | None = None) -> Any:
    """Wrap an AI client. See docs/specs/sentinel-api.md."""
    return _wrap_path(client, [], config or {})


def _wrap_path(target: Any, path: list[str], config: SentinelConfig) -> Any:
    """
    Recursive wrapper. Returns a _Proxy that watches for known method paths
    and installs an interceptor when it sees one. Non-objects pass through.
    """
    if target is None or isinstance(target, (int, float, str, bool, bytes, bytearray)):
        return target
    if callable(target) and not _is_object_like(target):
        return target  # standalone functions pass through
    return _Proxy(target, path, config)


def _is_object_like(t: Any) -> bool:
    """Heuristic: is this a class instance vs a bare function?"""
    return hasattr(t, "__dict__") or hasattr(t, "__class__")


class _Proxy:
    """Recursive attribute proxy that watches for known method paths."""

    __slots__ = ("_target", "_path", "_config", "_lock")

    def __init__(self, target: Any, path: list[str], config: SentinelConfig) -> None:
        # bypass __setattr__ since we override it
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_config", config)
        object.__setattr__(self, "_lock", threading.Lock())

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            # Internal dunders — pass through.
            return getattr(self._target, name)

        next_attr = getattr(self._target, name)
        new_path = [*self._path, name]
        dot_path = ".".join(new_path)
        intercept = KNOWN_PATHS.get(dot_path)

        if intercept is not None and callable(next_attr):
            return _make_interceptor(next_attr, self._target, intercept["provider"], self._config)
        return _wrap_path(next_attr, new_path, self._config)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._target, name, value)


def _make_interceptor(
    original_fn: Any,
    original_parent: Any,
    provider: str,
    config: SentinelConfig,
) -> Any:
    """Build the actual interceptor function for a known method path."""

    def intercepted(*args: Any, **kwargs: Any) -> Any:
        # In Python, OpenAI/Anthropic SDKs are called with kwargs:
        #   client.chat.completions.create(model="gpt-4", messages=[...])
        # So extract from kwargs primarily; fall back to first positional arg.
        call_kwargs = kwargs if kwargs else (args[0] if args else {})
        if not isinstance(call_kwargs, dict):
            call_kwargs = {}
        model_name = extract_model_name(provider, call_kwargs)
        model = IncidentModel(provider=provider, name=model_name)  # type: ignore[arg-type]

        # ── Preflight ──
        input_text = extract_input_text(provider, call_kwargs)
        preflight_trips = run_checks(input_text, config.get("preflight", []), "preflight")
        for check_id, result in preflight_trips:
            ev = _make_event(
                phase="preflight",
                check_id=check_id,
                result=result,
                model=model,
                evidence=input_text,
                action=_action_for(config.get("on_trip")),
            )
            _emit(ev, config)

        # ── Forward to underlying SDK ──
        response = original_fn(*args, **kwargs)

        # ── Postflight ──
        output_text = extract_output_text(provider, response)
        postflight_trips = run_checks(output_text, config.get("postflight", []), "postflight")
        for check_id, result in postflight_trips:
            ev = _make_event(
                phase="postflight",
                check_id=check_id,
                result=result,
                model=model,
                evidence=output_text,
                action=_action_for(config.get("on_trip")),
            )
            _emit(ev, config)

        return response

    return intercepted


def _action_for(on_trip: str | None) -> IncidentAction:
    if on_trip == "block":
        return "blocked"
    if on_trip == "redact":
        return "redacted"
    return "logged"


def _make_event(
    phase: str,
    check_id: str,
    result: Any,
    model: IncidentModel,
    evidence: str,
    action: IncidentAction,
) -> IncidentEvent:
    return IncidentEvent(
        ts=_now_iso(),
        agent_id=AGENT_ID,
        phase=phase,  # type: ignore[arg-type]
        check_id=check_id,  # type: ignore[arg-type]
        severity=result.severity,
        title=result.title,
        detail=result.detail,
        model=model,
        fingerprint=fingerprint(evidence),
        action=action,
        sentinel_version=SENTINEL_VERSION,
    )


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _emit(event: IncidentEvent, config: SentinelConfig) -> None:
    """Fire on_incident, optionally send to Guardian, optionally raise."""
    on_incident = config.get("on_incident")
    if on_incident is not None:
        try:
            on_incident(event)
        except Exception:
            pass  # never let a callback bug block the user request

    guardian = config.get("guardian")
    if guardian is not None:
        try:
            send_to_guardian(event, guardian)
        except Exception:
            pass

    if config.get("on_trip") == "block" and event.action == "blocked":
        raise SentinelBlockedError(event)
