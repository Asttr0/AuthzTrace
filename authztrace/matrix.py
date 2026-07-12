"""Expand a contract into the full actor x object test matrix.

This is the part a human bug-hunter does by hand: take every object, and for
every *other* identity try to reach it. AuthzTrace generates that whole cross
product from a few lines of ownership declaration.
"""
from __future__ import annotations

from itertools import product
from typing import Any

from .models import Check, Contract, Endpoint, Resource, effective_safe
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


def _context(
    resource: str,
    actor: str,
    owner: str,
    ids: dict[str, Any],
    target_id: str,
    marker: object,
) -> dict[str, Any]:
    context = {
        "resource": resource,
        "actor": actor,
        "owner": owner,
        "id": ids[target_id],
        "object_id": ids[target_id],
        "marker": marker,
    }
    context.update(ids)
    return context


def _variants(resource: Resource):
    owners = list(resource.ids)
    first_fixture = resource.ids[owners[0]]
    if not isinstance(first_fixture, dict):
        for owner, object_id in resource.ids.items():
            yield {"id": object_id}, {"id": owner}, owner, True, ""
        return

    fields = list(first_fixture)
    for source_tuple in product(owners, repeat=len(fields)):
        sources = dict(zip(fields, source_tuple))
        ids = {
            field: resource.ids[source_owner][field]
            for field, source_owner in sources.items()
        }
        target_owner = sources[resource.target_id]
        coherent = len(set(source_tuple)) == 1
        relationship = ",".join(f"{field}={sources[field]}" for field in fields)
        yield ids, sources, target_owner, coherent, relationship


def generate(contract: Contract) -> list[Check]:
    """For every object and every actor, assert allowed actors pass and others deny."""
    checks: list[Check] = []
    for res in contract.resources.values():
        for endpoint in res.endpoints:
            for ids, id_sources, owner, coherent, relationship in _variants(res):
                ctx_base = _context(
                    resource=res.name,
                    actor="",
                    owner=owner,
                    ids=ids,
                    target_id=res.target_id,
                    marker=res.markers.get(owner, ""),
                )
                for actor_name in contract.actors:
                    ctx = dict(ctx_base)
                    ctx["actor"] = actor_name
                    relation_suffix = f" [{relationship}]" if relationship else ""
                    checks.append(
                        Check(
                            name=(
                                f"{endpoint.name}: {actor_name} -> {owner}{relation_suffix}"
                            ),
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
                            object_id=str(ids[res.target_id]),
                            ids=dict(ids),
                            id_sources=dict(id_sources),
                            relationship=relationship,
                            expect=(
                                "allow"
                                if coherent
                                and _is_allowed(contract, endpoint, actor_name, owner)
                                else "deny"
                            ),
                            assertions=render(endpoint.assertions, ctx),
                            safe=effective_safe(endpoint.method, endpoint.safe),
                        )
                    )
    return checks + contract.checks
