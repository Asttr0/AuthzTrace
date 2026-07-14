"""Reconcile source evidence with an OpenAPI route inventory."""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from authztrace.openapi import first_server_url, operation_parameters, read_spec
from authztrace.scaffold import resource_name, template_name

from .models import Discovery, Evidence, RouteEvidence

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PARAMETER = re.compile(r"\{([^{}]+)\}")


def _shape(path: str) -> str:
    return _PARAMETER.sub("{}", path.rstrip("/"))


def _object_route(
    path: str,
    method: str,
    path_item: dict[str, Any],
    operation: dict[str, Any],
) -> RouteEvidence | None:
    raw_path_fields = _PARAMETER.findall(path)
    path_fields = [template_name(item) for item in raw_path_fields]
    locations = {field: "path" for field in path_fields}
    request_names = dict(zip(path_fields, raw_path_fields))
    id_fields = path_fields
    if not id_fields:
        query = [
            (
                template_name(str(parameter.get("name") or "")),
                str(parameter.get("name") or ""),
            )
            for parameter in operation_parameters(path_item, operation)
            if parameter.get("in") == "query"
            and (
                str(parameter.get("name") or "").lower() in {"id", "object_id"}
                or template_name(str(parameter.get("name") or "")).lower().endswith("_id")
            )
        ]
        if query:
            field, request_name = query[0]
            id_fields = [field]
            locations[field] = "query"
            request_names[field] = request_name
    if not id_fields:
        return None

    for field, request_name in request_names.items():
        if locations[field] == "path":
            path = path.replace("{" + request_name + "}", "{" + field + "}")
    target_id = id_fields[-1]
    base_resource = resource_name(path, target_id)
    resource = (
        base_resource
        if len(id_fields) == 1
        else f"{base_resource}_by_{'_'.join(id_fields)}"
    )
    operation_id = str(operation.get("operationId") or f"{method.upper()} {path}")
    return RouteEvidence(
        method=method.upper(),
        path=path,
        handler=operation_id,
        operation_id=operation_id,
        resource=resource,
        id_fields=id_fields,
        target_id=target_id,
        id_locations=locations,
        id_request_names=request_names,
        evidence=[
            Evidence(
                kind="openapi_route",
                state="confirmed",
                message=f"{method.upper()} {path} is declared by OpenAPI",
            )
        ],
    )


def reconcile_openapi(discovery: Discovery, spec_path: str) -> Discovery:
    """Use OpenAPI as route truth while retaining matched source-policy evidence."""
    spec = read_spec(spec_path)
    source_routes = list(discovery.routes)
    used: set[str] = set()
    reconciled: list[RouteEvidence] = []

    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _METHODS or not isinstance(operation, dict):
                continue
            route = _object_route(path, method, path_item, operation)
            if route is None:
                continue
            matches = [
                candidate
                for candidate in source_routes
                if candidate.method == route.method
                and (
                    candidate.operation_id == route.operation_id
                    or candidate.handler == route.operation_id
                    or _shape(route.path).endswith(_shape(candidate.path))
                )
            ]
            if len(matches) == 1:
                source = matches[0]
                used.add(source.key)
                route = replace(
                    source,
                    path=route.path,
                    operation_id=route.operation_id,
                    resource=route.resource,
                    id_fields=route.id_fields,
                    target_id=route.target_id,
                    id_locations=route.id_locations,
                    id_request_names=route.id_request_names,
                    evidence=[*route.evidence, *source.evidence],
                )
            reconciled.append(route)

    reconciled.extend(route for route in source_routes if route.key not in used)
    deduplicated = {route.key: route for route in reconciled}
    if not deduplicated:
        raise ValueError("no object endpoints found in source or OpenAPI spec")
    return replace(
        discovery,
        base_url=(first_server_url(spec) or discovery.base_url).rstrip("/"),
        routes=sorted(deduplicated.values(), key=lambda item: (item.path, item.method)),
    )
