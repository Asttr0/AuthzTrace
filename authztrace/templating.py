"""Small placeholder renderer used by contracts and generated checks."""
from __future__ import annotations

import re
from typing import Any

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_EXACT_PLACEHOLDER = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def render(value: Any, context: dict[str, Any]) -> Any:
    """Recursively replace ``{name}`` placeholders with context values."""
    if isinstance(value, str):
        exact = _EXACT_PLACEHOLDER.match(value)
        if exact:
            return context.get(exact.group(1), value)
        return _PLACEHOLDER.sub(lambda m: str(context.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render(item, context) for item in value]
    return value
