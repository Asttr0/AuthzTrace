"""Compile reviewed source evidence into an executable AuthzTrace contract."""
from __future__ import annotations

import re
from typing import Any

from authztrace.scaffold import env_name

from .models import Discovery, RouteEvidence


def _actor_spec(name: str) -> dict[str, Any]:
    if name == "anon":
        return {"auth": {"type": "none"}}
    token_name = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return {"auth": {"type": "bearer", "token": f"${{{token_name}_TOKEN}}"}}


def _endpoint(route: RouteEvidence, allow: list[str]) -> dict[str, Any]:
    path = route.path
    query: dict[str, str] = {}
    if len(route.id_fields) == 1:
        field = route.id_fields[0]
        placeholder = "{id}"
        if route.id_locations[field] == "path":
            path = path.replace("{" + field + "}", placeholder)
        elif route.id_locations[field] == "query":
            query[route.id_request_names.get(field, field)] = placeholder
    else:
        for field in route.id_fields:
            if route.id_locations[field] == "query":
                query[route.id_request_names.get(field, field)] = "{" + field + "}"

    endpoint: dict[str, Any] = {
        "name": route.operation_id or route.handler or route.key,
        "request": f"{route.method} {path}",
        "allow": allow,
    }
    if query:
        endpoint["query"] = query
    return endpoint


def compile_contract(
    discovery: Discovery,
    decisions: dict[str, list[str] | None],
) -> dict[str, Any]:
    """Compile only explicitly reviewed route decisions into the contract schema."""
    missing = [route.key for route in discovery.routes if route.key not in decisions]
    if missing:
        raise ValueError("unresolved authorization policy: " + ", ".join(missing))

    resources: dict[str, dict[str, Any]] = {}
    custom_actors: set[str] = set()
    special = {"owner", "authenticated", "anonymous", "all", "*"}
    for route in discovery.routes:
        allow = decisions[route.key]
        if allow is None:
            continue
        custom_actors.update(item for item in allow if item.lower() not in special)
        resource = resources.get(route.resource)
        if resource is None:
            if len(route.id_fields) == 1:
                resource = {
                    "ids": {
                        owner: env_name(route.resource, owner)
                        for owner in ("alice", "bob")
                    },
                    "endpoints": [],
                }
            else:
                base_resource = route.resource.split("_by_", 1)[0]
                resource = {
                    "target_id": route.target_id,
                    "ids": {
                        owner: {
                            field: env_name(base_resource, owner, field)
                            for field in route.id_fields
                        }
                        for owner in ("alice", "bob")
                    },
                    "endpoints": [],
                }
            resources[route.resource] = resource
        elif len(route.id_fields) > 1:
            first = next(iter(resource["ids"].values()))
            if not isinstance(first, dict) or list(first) != route.id_fields:
                raise ValueError(
                    f"resource {route.resource!r} has incompatible identifier shapes"
                )
        resource["endpoints"].append(_endpoint(route, allow))

    if not resources:
        raise ValueError("all discovered object endpoints were skipped")

    actors = {
        "alice": _actor_spec("alice"),
        "bob": _actor_spec("bob"),
        "anon": _actor_spec("anon"),
    }
    for actor in sorted(custom_actors):
        actors.setdefault(actor, _actor_spec(actor))
    return {
        "base_url": discovery.base_url,
        "actors": actors,
        "resources": resources,
        "policy": {"deny_status": [401, 403, 404]},
    }
