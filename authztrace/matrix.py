"""Expand a contract into the full actor x object test matrix.

This is the part a human bug-hunter does by hand: take every object, and for
every *other* identity try to reach it. AuthzTrace generates that whole cross
product from a few lines of ownership declaration.
"""
from __future__ import annotations

from .models import Check, Contract, Endpoint, effective_safe
from .templating import render


def _is_authenticated(auth: dict) -> bool:
    return (auth or {}).get("type", "none") != "none"


def _is_allowed(contract: Contract, endpoint: Endpoint, actor: str, owner: str) -> bool:
    allow = {item.lower() for item in endpoint.allow}
    if "all" in allow or "*" in allow:
        return True
    if "authenticated" in allow and _is_authenticated(contract.actors[actor].auth):
        return True
    if "anonymous" in allow and not _is_authenticated(contract.actors[actor].auth):
        return True
    if "owner" in allow and actor == owner:
        return True
    return actor.lower() in allow


def _context(resource: str, actor: str, owner: str, object_id: object, marker: object) -> dict:
    return {
        "resource": resource,
        "actor": actor,
        "owner": owner,
        "id": object_id,
        "object_id": object_id,
        "marker": marker,
    }


def generate(contract: Contract) -> list[Check]:
    """For every object and every actor, assert allowed actors pass and others deny."""
    checks: list[Check] = []
    for res in contract.resources.values():
        for endpoint in res.endpoints:
            for owner, object_id in res.ids.items():
                ctx_base = _context(
                    resource=res.name,
                    actor="",
                    owner=owner,
                    object_id=object_id,
                    marker=res.markers.get(owner, ""),
                )
                for actor_name in contract.actors:
                    ctx = dict(ctx_base)
                    ctx["actor"] = actor_name
                    checks.append(
                        Check(
                            name=f"{endpoint.name}: {actor_name} -> {owner}",
                            resource=res.name,
                            actor=actor_name,
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
                            expect=(
                                "allow"
                                if _is_allowed(contract, endpoint, actor_name, owner)
                                else "deny"
                            ),
                            assertions=render(endpoint.assertions, ctx),
                            safe=effective_safe(endpoint.method, endpoint.safe),
                        )
                    )
    return checks + contract.checks
