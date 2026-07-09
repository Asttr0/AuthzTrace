"""Load and validate an authztrace.yaml contract, expanding ${ENV_VARS}."""
from __future__ import annotations

import os
import re
from typing import Any

import yaml

from .models import Actor, Check, Contract, Endpoint, Policy, Resource, effective_safe
from .templating import render

_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand(value):
    """Recursively replace ${VAR} with the environment value (empty if unset)."""
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _as_list(value: Any, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _split_request(value: str) -> tuple[str, str]:
    parts = value.strip().split(None, 1)
    if len(parts) != 2:
        raise ValueError(f"invalid request (expected 'METHOD /path'): {value!r}")
    method, path = parts
    return method.upper(), path


def _endpoint(raw: Any, name: str) -> Endpoint:
    """Parse either ``GET /path`` or a structured endpoint object."""
    if isinstance(raw, str):
        method, path = _split_request(raw)
        return Endpoint(name=name, method=method, path=path)

    if not isinstance(raw, dict):
        raise ValueError(f"endpoint {name!r} must be a string or object")

    spec = dict(raw)
    request = spec.pop("request", None)
    if request:
        if not isinstance(request, str):
            raise ValueError(f"endpoint {name!r} request must be 'METHOD /path'")
        method, path = _split_request(request)
    else:
        method = str(spec.pop("method", "")).upper()
        path = str(spec.pop("path", ""))

    if not method or not path:
        raise ValueError(f"endpoint {name!r} must define method/path")

    safe = spec.pop("safe", None)
    if safe is not None and not isinstance(safe, bool):
        raise ValueError(f"endpoint {name!r} safe must be true or false")

    return Endpoint(
        name=str(spec.pop("name", name)),
        method=method,
        path=path,
        query=spec.pop("query", {}) or spec.pop("params", {}) or {},
        headers=spec.pop("headers", {}) or {},
        json=spec.pop("json", None),
        data=spec.pop("data", None),
        allow=_as_list(spec.pop("allow", None), ["owner"]),
        assertions=spec.pop("assertions", {}) or {},
        safe=safe,
    )


def _context(
    resource: Resource | None,
    actor: str,
    owner: str,
    object_id: Any,
) -> dict[str, Any]:
    marker = ""
    if resource and owner:
        marker = resource.markers.get(owner, "")
    return {
        "actor": actor,
        "owner": owner,
        "id": object_id,
        "object_id": object_id,
        "resource": resource.name if resource else "",
        "marker": marker,
    }


def _explicit_check(spec: dict[str, Any], index: int, resources: dict[str, Resource]) -> Check:
    name = str(spec.get("name") or f"contract-{index}")
    actor = str(spec.get("as") or spec.get("actor") or "")
    if not actor:
        raise ValueError(f"contract {name!r} must define 'as' or 'actor'")

    resource_name = str(spec.get("resource") or "")
    resource = resources.get(resource_name) if resource_name else None
    owner = str(spec.get("target_owner") or spec.get("owner") or spec.get("target") or "")

    object_id = spec.get("id", "")
    if object_id == "" and resource and owner:
        object_id = resource.ids.get(owner, "")

    params = spec.get("params") or {}
    ctx = _context(resource, actor, owner, object_id)
    ctx.update(params)

    request = spec.get("request")
    if isinstance(request, str):
        endpoint_spec = {
            "request": request,
            "query": spec.get("query") or spec.get("params") or {},
            "headers": spec.get("headers") or {},
            "json": spec.get("json", None),
            "data": spec.get("data", None),
            "assertions": spec.get("assertions") or {},
            "safe": spec.get("safe", None),
        }
        endpoint = _endpoint(endpoint_spec, name)
    elif isinstance(request, dict):
        endpoint_spec = {
            "query": spec.get("query") or spec.get("params") or {},
            "headers": spec.get("headers") or {},
            "json": spec.get("json", None),
            "data": spec.get("data", None),
            "assertions": spec.get("assertions") or {},
            "safe": spec.get("safe", None),
        }
        endpoint_spec.update(request)
        endpoint = _endpoint(endpoint_spec, name)
    else:
        endpoint = _endpoint(spec, name)

    return Check(
        name=name,
        resource=resource_name,
        actor=actor,
        method=endpoint.method,
        path=render(endpoint.path, ctx),
        path_template=endpoint.path,
        endpoint_name=endpoint.name,
        query=render(endpoint.query, ctx),
        headers=render(endpoint.headers, ctx),
        json=render(endpoint.json, ctx),
        data=render(endpoint.data, ctx),
        target_owner=owner,
        object_id=str(object_id),
        expect=str(spec.get("expect") or "deny"),
        assertions=render(endpoint.assertions | (spec.get("assertions") or {}), ctx),
        safe=effective_safe(endpoint.method, endpoint.safe),
    )


def load_contract(path: str) -> Contract:
    with open(path, encoding="utf-8") as f:
        raw = _expand(yaml.safe_load(f))

    if not raw or "base_url" not in raw:
        raise ValueError("contract must define 'base_url'")

    actors: dict[str, Actor] = {}
    for name, spec in (raw.get("actors") or {}).items():
        auth = (spec or {}).get("auth") or {"type": "none"}
        actors[name] = Actor(name=name, auth=auth)
    if not actors:
        raise ValueError("contract must define at least one actor")

    resources: dict[str, Resource] = {}
    for name, spec in (raw.get("resources") or {}).items():
        spec = spec or {}
        endpoint_specs = spec.get("endpoints") or []
        if not endpoint_specs:
            raise ValueError(f"resource {name!r} must define at least one endpoint")
        ids = spec.get("ids") or {}
        if not isinstance(ids, dict) or not ids:
            raise ValueError(f"resource {name!r} must define ids by owner")
        resources[name] = Resource(
            name=name,
            endpoints=[
                _endpoint(endpoint_spec, f"{name}.{idx}")
                for idx, endpoint_spec in enumerate(endpoint_specs, start=1)
            ],
            ids=ids,
            markers=spec.get("markers", {}) or {},
        )
    if not resources:
        raise ValueError("contract must define at least one resource")

    pol = raw.get("policy") or {}
    policy = Policy(
        default=pol.get("default", "owner-only"),
        deny_status=pol.get("deny_status", [401, 403, 404]),
        allow_status=pol.get("allow_status", []),
    )

    checks = [
        _explicit_check(spec or {}, idx, resources)
        for idx, spec in enumerate(raw.get("contracts") or raw.get("checks") or [], start=1)
    ]
    for chk in checks:
        if chk.actor not in actors:
            raise ValueError(f"contract {chk.name!r} references unknown actor {chk.actor!r}")
        if chk.resource and chk.resource not in resources:
            raise ValueError(f"contract {chk.name!r} references unknown resource {chk.resource!r}")

    return Contract(
        base_url=raw["base_url"].rstrip("/"),
        actors=actors,
        resources=resources,
        policy=policy,
        checks=checks,
    )
