"""Shared helpers for producing starter authorization contracts."""
from __future__ import annotations

import re
from typing import Any


def resource_name(path: str, param: str) -> str:
    """Derive a stable singular resource name from an identifier location."""
    parts = [part for part in path.strip("/").split("/") if part]
    marker = "{" + param + "}"
    if marker in parts:
        index = parts.index(marker)
        if index > 0:
            return re.sub(r"(?<!s)s$", "", parts[index - 1].replace("-", "_")) or "resource"
    return param.removesuffix("_id").removesuffix("Id").replace("-", "_") or "resource"


def template_name(value: str) -> str:
    """Turn an API identifier name into a valid AuthzTrace template field."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not name or name[0].isdigit():
        name = "_" + name
    return name


def env_name(resource: str, owner: str, field: str | None = None) -> str:
    """Build a deterministic environment placeholder for a generated fixture."""
    safe = re.sub(r"[^A-Za-z0-9]+", "_", resource).strip("_").upper() or "RESOURCE"
    if field:
        suffix = re.sub(r"[^A-Za-z0-9]+", "_", field).strip("_").upper()
        return f"${{{owner.upper()}_{safe}_{suffix}}}"
    return f"${{{owner.upper()}_{safe}_ID}}"


def nested_resource_spec(resource: str, fields: list[str]) -> dict[str, Any]:
    """Create generated owner fixtures for a multi-identifier resource."""
    return {
        "target_id": fields[-1],
        "ids": {
            owner: {field: env_name(resource, owner, field) for field in fields}
            for owner in ("alice", "bob")
        },
        "endpoints": [],
    }
