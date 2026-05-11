"""
Provider extractors — Python mirror of @lictor/sentinel/src/extractors.ts.
"""

from __future__ import annotations

from typing import Any

KNOWN_PATHS: dict[str, dict[str, str]] = {
    "chat.completions.create": {"provider": "openai"},
    "completions.create": {"provider": "openai"},
    "messages.create": {"provider": "anthropic"},
}


def extract_input_text(provider: str, args: dict[str, Any]) -> str:
    """Pull user text out of model-call arguments."""
    if provider in ("openai", "anthropic"):
        return _extract_messages(args.get("messages"))
    return ""


def extract_model_name(_provider: str, args: dict[str, Any]) -> str:
    m = args.get("model")
    return m if isinstance(m, str) else "unknown"


def _extract_messages(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    out: list[str] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        content = m.get("content")
        if isinstance(content, str):
            out.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    t = part.get("text")
                    if isinstance(t, str):
                        out.append(t)
    return "\n".join(out)


def extract_output_text(provider: str, response: Any) -> str:
    """Pull the model's text response out of a (non-streaming) result."""
    if provider == "openai":
        choices = _get_attr_or_key(response, "choices")
        if not isinstance(choices, list):
            return ""
        out: list[str] = []
        for c in choices:
            msg = _get_attr_or_key(c, "message")
            if msg is not None:
                content = _get_attr_or_key(msg, "content")
                if isinstance(content, str):
                    out.append(content)
                    continue
            text = _get_attr_or_key(c, "text")
            if isinstance(text, str):
                out.append(text)
        return "\n".join(out)

    if provider == "anthropic":
        content = _get_attr_or_key(response, "content")
        if not isinstance(content, list):
            return ""
        out2: list[str] = []
        for part in content:
            t = _get_attr_or_key(part, "text")
            if isinstance(t, str):
                out2.append(t)
        return "\n".join(out2)

    return ""


def _get_attr_or_key(obj: Any, name: str) -> Any:
    """Try attribute access first (for SDK objects), then dict lookup."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
