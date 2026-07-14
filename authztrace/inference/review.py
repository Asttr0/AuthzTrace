"""Policy review and deterministic evidence output."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .models import Discovery, RouteEvidence


class UnresolvedPolicyError(ValueError):
    """Raised when source facts cannot safely determine authorization intent."""

    def __init__(self, routes: list[str]):
        self.routes = routes
        super().__init__(
            f"{len(routes)} endpoint policy decision(s) remain unresolved: "
            + ", ".join(routes)
        )


def _render_route(route: RouteEvidence, output: Callable[[str], None]) -> None:
    output(f"\n{route.method} {route.path}")
    output(f"  resource: {route.resource}")
    if route.auth_dependencies:
        output("  authentication: " + ", ".join(route.auth_dependencies))
    if route.owner_field:
        output(f"  probable ownership: {route.owner_field} -> {route.principal_field}")
    else:
        output("  policy: unresolved; no supported ownership rule was found")
    source = next((item.source for item in route.evidence if item.source), None)
    if source:
        output(f"  evidence: {source.path}:{source.line}")


def _custom_allow(
    input_fn: Callable[[str], str],
    output: Callable[[str], None],
) -> list[str]:
    while True:
        value = input_fn("Allow entries, comma-separated (for example owner,admin): ").strip()
        allow = [item.strip() for item in value.split(",") if item.strip()]
        if allow:
            return allow
        output("Enter at least one allow entry.")


def _ask_policy(
    route: RouteEvidence,
    input_fn: Callable[[str], str],
    output: Callable[[str], None],
) -> list[str] | None:
    _render_route(route, output)
    default = "o" if route.suggested_allow == ["owner"] else ""
    suffix = " [O/a/p/c/s] (default: owner): " if default else " [o/a/p/c/s]: "
    output("  o=owner only  a=authenticated  p=public  c=custom  s=skip")
    while True:
        choice = input_fn("Expected access" + suffix).strip().lower() or default
        if choice == "o":
            return ["owner"]
        if choice == "a":
            return ["authenticated"]
        if choice == "p":
            return ["all"]
        if choice == "c":
            return _custom_allow(input_fn, output)
        if choice == "s":
            return None
        output("Choose o, a, p, c, or s.")


def review_policies(
    discovery: Discovery,
    *,
    existing: dict[str, list[str] | None] | None = None,
    accept_probable: bool = False,
    interactive: bool = True,
    input_fn: Callable[[str], str] = input,
    output: Callable[[str], None] = print,
) -> dict[str, list[str] | None]:
    """Resolve every route policy without treating implementation gaps as intent."""
    existing = existing or {}
    route_keys = {route.key for route in discovery.routes}
    decisions = {
        key: value
        for key, value in existing.items()
        if key in route_keys
    }
    remaining: list[RouteEvidence] = []
    for route in discovery.routes:
        if route.key in decisions:
            continue
        if accept_probable and route.policy_state == "probable" and route.suggested_allow:
            decisions[route.key] = list(route.suggested_allow)
        else:
            remaining.append(route)

    if remaining and not interactive:
        raise UnresolvedPolicyError([route.key for route in remaining])
    for route in remaining:
        decisions[route.key] = _ask_policy(route, input_fn, output)
    return decisions


def read_decisions(path: str) -> dict[str, list[str] | None]:
    """Read reviewed route decisions from an earlier evidence document."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid inference evidence JSON: {exc}") from exc
    routes = data.get("routes") if isinstance(data, dict) else None
    if not isinstance(routes, list):
        raise ValueError("inference evidence must contain a routes list")

    decisions: dict[str, list[str] | None] = {}
    for route in routes:
        if not isinstance(route, dict):
            continue
        key = route.get("key")
        decision = route.get("decision", "unresolved")
        if not isinstance(key, str) or decision == "unresolved":
            continue
        if decision is None:
            decisions[key] = None
            continue
        if not isinstance(decision, list) or not decision or not all(
            isinstance(item, str) and item for item in decision
        ):
            raise ValueError(f"invalid policy decision for {key!r}")
        decisions[key] = decision
    return decisions


def write_evidence(
    discovery: Discovery,
    path: str,
    decisions: dict[str, list[str] | None] | None = None,
) -> None:
    """Write source provenance without embedding source text or credentials."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(discovery.to_dict(decisions), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
