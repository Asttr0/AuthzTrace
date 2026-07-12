"""Generate starter AuthzTrace contracts from OpenAPI specs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PATH_PARAM = re.compile(r"\{([^{}]+)\}")


def _read_spec(path: str) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(text)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("OpenAPI file must contain an object")
    return data


def _resource_name(path: str, param: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    marker = "{" + param + "}"
    if marker in parts:
        idx = parts.index(marker)
        if idx > 0:
            return re.sub(r"(?<!s)s$", "", parts[idx - 1].replace("-", "_")) or "resource"
    return param.removesuffix("_id").removesuffix("Id").replace("-", "_") or "resource"


def _operation_parameters(
    path_item: dict[str, Any],
    operation: dict[str, Any],
) -> list[dict[str, Any]]:
    params: list[dict[str, Any]] = []
    for item in path_item.get("parameters") or []:
        if isinstance(item, dict):
            params.append(item)
    for item in operation.get("parameters") or []:
        if isinstance(item, dict):
            params.append(item)
    return params


def _first_server_url(spec: dict[str, Any]) -> str | None:
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        if isinstance(url, str) and url:
            return url
    return None


def _template_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not name or name[0].isdigit():
        name = "_" + name
    return name


def _env_name(resource: str, owner: str, field: str | None = None) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "_", resource).strip("_").upper() or "RESOURCE"
    if field:
        suffix = re.sub(r"[^A-Za-z0-9]+", "_", field).strip("_").upper()
        return f"${{{owner.upper()}_{safe}_{suffix}}}"
    return f"${{{owner.upper()}_{safe}_ID}}"


def _nested_resource_spec(resource: str, fields: list[str]) -> dict[str, Any]:
    return {
        "target_id": fields[-1],
        "ids": {
            owner: {
                field: _env_name(resource, owner, field)
                for field in fields
            }
            for owner in ("alice", "bob")
        },
        "endpoints": [],
    }


def generate_contract(spec_path: str, base_url: str | None = None) -> dict[str, Any]:
    spec = _read_spec(spec_path)
    resources: dict[str, dict[str, Any]] = {}

    for raw_path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _METHODS or not isinstance(operation, dict):
                continue

            path_params = _PATH_PARAM.findall(raw_path)
            endpoint: dict[str, Any] | None = None
            resource = ""

            if len(path_params) == 1:
                param = path_params[0]
                resource = _resource_name(raw_path, param)
                endpoint = {
                    "name": operation.get("operationId") or f"{method.upper()} {raw_path}",
                    "request": f"{method.upper()} {raw_path.replace('{' + param + '}', '{id}')}",
                }
                resource_spec = resources.setdefault(
                    resource,
                    {
                        "ids": {
                            "alice": _env_name(resource, "alice"),
                            "bob": _env_name(resource, "bob"),
                        },
                        "endpoints": [],
                    },
                )
            elif len(path_params) > 1:
                fields = [_template_name(param) for param in path_params]
                base_resource = _resource_name(raw_path, path_params[-1])
                resource = f"{base_resource}_by_{'_'.join(fields)}"
                rendered_path = raw_path
                for raw_param, field in zip(path_params, fields):
                    rendered_path = rendered_path.replace(
                        "{" + raw_param + "}", "{" + field + "}"
                    )
                endpoint = {
                    "name": operation.get("operationId") or f"{method.upper()} {raw_path}",
                    "request": f"{method.upper()} {rendered_path}",
                }
                resource_spec = resources.setdefault(
                    resource,
                    _nested_resource_spec(base_resource, fields),
                )
            else:
                query_id = None
                for param in _operation_parameters(path_item, operation):
                    name = str(param.get("name") or "")
                    if param.get("in") == "query" and name.lower() in {"id", "object_id"}:
                        query_id = name
                        break
                if query_id:
                    resource = _resource_name(raw_path + "/{" + query_id + "}", query_id)
                    endpoint = {
                        "name": operation.get("operationId") or f"{method.upper()} {raw_path}",
                        "method": method.upper(),
                        "path": raw_path,
                        "query": {query_id: "{id}"},
                    }
                    resource_spec = resources.setdefault(
                        resource,
                        {
                            "ids": {
                                "alice": _env_name(resource, "alice"),
                                "bob": _env_name(resource, "bob"),
                            },
                            "endpoints": [],
                        },
                    )

            if not endpoint or not resource:
                continue
            resource_spec["endpoints"].append(endpoint)

    if not resources:
        raise ValueError("no object endpoints found in OpenAPI spec")

    return {
        "base_url": base_url or _first_server_url(spec) or "http://localhost:3000",
        "actors": {
            "alice": {"auth": {"type": "bearer", "token": "${ALICE_TOKEN}"}},
            "bob": {"auth": {"type": "bearer", "token": "${BOB_TOKEN}"}},
            "anon": {"auth": {"type": "none"}},
        },
        "resources": resources,
        "policy": {"deny_status": [401, 403, 404]},
    }


def write_contract(contract: dict[str, Any], output: str, force: bool = False) -> None:
    path = Path(output)
    if path.exists() and not force:
        raise FileExistsError(f"{output} already exists; pass --force to overwrite")
    path.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")
