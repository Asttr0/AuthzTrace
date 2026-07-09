"""Core data models for authorization contracts and execution results."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def effective_safe(method: str, override: bool | None = None) -> bool:
    """Return whether an operation is safe to execute in read-only mode."""
    if override is not None:
        return override
    return method.upper() in SAFE_METHODS


@dataclass
class Actor:
    """A test identity (a user, a role, or the anonymous caller)."""

    name: str
    auth: dict = field(default_factory=lambda: {"type": "none"})


@dataclass
class Endpoint:
    """A templated API operation that will be expanded across actors and objects."""

    name: str
    method: str
    path: str
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    json: Any = None
    data: Any = None
    allow: list[str] = field(default_factory=lambda: ["owner"])
    assertions: dict[str, Any] = field(default_factory=dict)
    safe: bool | None = None


@dataclass
class Resource:
    """A protected object type and concrete object ids owned by each actor."""

    name: str
    endpoints: list[Endpoint]
    ids: dict[str, Any]
    markers: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """Default expectations for generated checks."""

    default: str = "owner-only"
    deny_status: list[int] = field(default_factory=lambda: [401, 403, 404])
    allow_status: list[int] = field(default_factory=list)


@dataclass
class Contract:
    base_url: str
    actors: dict[str, Actor]
    resources: dict[str, Resource]
    policy: Policy
    checks: list[Check] = field(default_factory=list)


@dataclass
class Check:
    """A single HTTP probe the engine will execute."""

    name: str
    resource: str
    actor: str
    method: str
    path: str
    path_template: str = ""
    endpoint_name: str = ""
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    json: Any = None
    data: Any = None
    object_id: str = ""
    target_owner: str = ""
    expect: str = "deny"
    assertions: dict[str, Any] = field(default_factory=dict)
    safe: bool = True


@dataclass
class Result:
    check: Check
    status: int | None
    outcome: str
    category: str = "ok"
    note: str = ""
    elapsed_ms: int | None = None
