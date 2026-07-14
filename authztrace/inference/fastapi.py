"""Static FastAPI source discovery without importing the target application."""
from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from authztrace.scaffold import resource_name, template_name

from .models import Discovery, Evidence, RouteEvidence, SourceSpan

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
}
_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")
_AUTH_WORDS = (
    "admin",
    "auth",
    "current_user",
    "active_user",
    "authenticated_user",
    "principal",
    "permission",
    "require_",
    "role",
    "oauth",
    "api_key",
)
_AUTHORIZATION_WORDS = ("admin", "authorize", "permission", "require_", "role")
_OWNER_FIELDS = {
    "owner_id",
    "user_id",
    "account_id",
    "author_id",
    "created_by",
    "created_by_id",
    "member_id",
    "subject_id",
}
_PRINCIPAL_FIELDS = {"id", "user_id", "account_id", "subject_id"}


@dataclass
class _Router:
    module: str
    name: str
    prefix: str

    @property
    def key(self) -> tuple[str, str]:
        return self.module, self.name


@dataclass
class _RawRoute:
    router: tuple[str, str]
    method: str
    path: str
    handler: ast.FunctionDef | ast.AsyncFunctionDef
    operation_id: str
    module: str
    relative_path: str
    decorator_dependencies: list[str] = field(default_factory=list)


@dataclass
class _Module:
    name: str
    package: str
    relative_path: str
    tree: ast.Module
    aliases: dict[str, str]
    routers: dict[str, _Router]
    routes: list[_RawRoute]
    includes: list[tuple[ast.AST, ast.AST, str]]


def _dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def _join_path(*parts: str) -> str:
    segments = [part.strip("/") for part in parts if part and part != "/"]
    return "/" + "/".join(segment for segment in segments if segment)


def _module_name(root: Path, path: Path) -> tuple[str, str]:
    relative = path.relative_to(root)
    parts = list(relative.with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    module = ".".join(parts)
    package = module if is_package else ".".join(parts[:-1])
    return module, package


def _resolve_from(package: str, module: str | None, level: int) -> str:
    parts = package.split(".") if package else []
    if level:
        remove = max(level - 1, 0)
        if remove:
            parts = parts[:-remove]
    if module:
        parts.extend(module.split("."))
    return ".".join(part for part in parts if part)


def _aliases(tree: ast.Module, package: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".")[0]
                aliases[local] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            parent = _resolve_from(package, node.module, node.level)
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                aliases[local] = ".".join(part for part in (parent, item.name) if part)
    return aliases


def _qualified(name: str, aliases: dict[str, str]) -> str:
    first, dot, rest = name.partition(".")
    resolved = aliases.get(first, first)
    return resolved + (dot + rest if dot else "")


def _router_for_expression(
    node: ast.AST,
    module: _Module,
    modules: dict[str, _Module],
) -> tuple[str, str] | None:
    name = _dotted_name(node)
    if not name:
        return None
    if name in module.routers:
        return module.name, name

    target = _qualified(name, module.aliases)
    for module_name in sorted(modules, key=len, reverse=True):
        prefix = module_name + "."
        if target.startswith(prefix):
            symbol = target[len(prefix):]
            if "." not in symbol and symbol in modules[module_name].routers:
                return module_name, symbol
    return None


def _dependency_names(node: ast.AST | None) -> list[str]:
    names: list[str] = []
    if node is None:
        return names
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        call_name = _dotted_name(child.func).lower()
        if not (call_name.endswith("depends") or call_name.endswith("security")):
            continue
        if child.args:
            target = child.args[0]
            dependency = (
                _dotted_name(target.func) if isinstance(target, ast.Call) else _dotted_name(target)
            )
            if dependency:
                names.append(dependency)
    return names


def _function_defaults(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.AST | None]]:
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(function.args.defaults))
    defaults.extend(function.args.defaults)
    pairs = list(zip(positional, defaults))
    pairs.extend(zip(function.args.kwonlyargs, function.args.kw_defaults))
    return pairs


def _looks_like_auth_dependency(name: str) -> bool:
    lowered = name.lower()
    return any(word in lowered for word in _AUTH_WORDS)


def _principal_and_dependencies(
    route: _RawRoute,
) -> tuple[str, list[str]]:
    dependencies = list(route.decorator_dependencies)
    principal = ""
    for argument, default in _function_defaults(route.handler):
        found = _dependency_names(default)
        dependencies.extend(found)
        if found and any(_looks_like_auth_dependency(name) for name in found):
            principal = principal or argument.arg
    auth_dependencies = sorted(
        {name for name in dependencies if _looks_like_auth_dependency(name)}
    )
    return principal, auth_dependencies


def _attribute_parts(node: ast.AST) -> list[str]:
    name = _dotted_name(node)
    return name.split(".") if name else []


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Name, ast.Attribute)):
        return [_dotted_name(node)]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _model_from_call(call: ast.Call, id_fields: set[str]) -> str:
    call_name = _dotted_name(call.func).lower()
    if call_name.endswith(".get") and len(call.args) >= 2:
        model = _dotted_name(call.args[0])
        identifier = _dotted_name(call.args[1])
        if model and model.rsplit(".", 1)[-1][:1].isupper() and identifier in id_fields:
            return model.rsplit(".", 1)[-1]
    if call_name.endswith(".query") or call_name == "query" or call_name.endswith("select"):
        if call.args:
            model = _dotted_name(call.args[0])
            if model and model.rsplit(".", 1)[-1][:1].isupper():
                return model.rsplit(".", 1)[-1]
    return ""


def _parent_map(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[ast.AST, ast.AST]:
    return {
        child: parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }


def _is_enforcing_comparison(
    node: ast.Compare,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    current: ast.AST = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, ast.Call):
            call_name = _dotted_name(parent.func).lower().rsplit(".", 1)[-1]
            if call_name in {"filter", "filter_by", "having", "where"}:
                return True
        if isinstance(parent, ast.If):
            comparison_is_condition = any(child is node for child in ast.walk(parent.test))
            deny_branch_raises = any(
                isinstance(child, ast.Raise)
                for statement in parent.body
                for child in ast.walk(statement)
            )
            if comparison_is_condition and deny_branch_raises:
                return True
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            break
        current = parent
    return False


def _resource_analysis(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    id_fields: list[str],
    principal: str,
) -> tuple[str, str, str, SourceSpan | None]:
    identifiers = set(id_fields)
    variable_models: dict[str, str] = {}
    resource_model = ""
    parents = _parent_map(function)

    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if not isinstance(value, ast.AST):
                continue
            model = ""
            for child in ast.walk(value):
                if isinstance(child, ast.Call):
                    model = _model_from_call(child, identifiers) or model
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if model:
                resource_model = resource_model or model
                for target in targets:
                    for name in _target_names(target):
                        variable_models[name] = model

        if isinstance(node, ast.Compare):
            values = [node.left, *node.comparators]
            for left, right in zip(values, values[1:]):
                for attribute, identifier in ((left, right), (right, left)):
                    parts = _attribute_parts(attribute)
                    if len(parts) >= 2 and _dotted_name(identifier) in identifiers:
                        base, field = parts[-2], parts[-1]
                        if field == "id" or field in identifiers:
                            if base[:1].isupper():
                                resource_model = resource_model or base
                            elif base in variable_models:
                                resource_model = resource_model or variable_models[base]

    if not principal:
        return resource_model, "", "", None

    for node in ast.walk(function):
        if not isinstance(node, ast.Compare):
            continue
        if not _is_enforcing_comparison(node, parents):
            continue
        values = [node.left, *node.comparators]
        for left, right in zip(values, values[1:]):
            pairs = ((left, right), (right, left))
            for resource_side, principal_side in pairs:
                resource_parts = _attribute_parts(resource_side)
                principal_parts = _attribute_parts(principal_side)
                if len(resource_parts) < 2 or len(principal_parts) < 2:
                    continue
                if principal_parts[0] != principal:
                    continue
                if principal_parts[-1] not in _PRINCIPAL_FIELDS:
                    continue
                if resource_parts[-1] not in _OWNER_FIELDS:
                    continue
                base = resource_parts[-2]
                if base[:1].isupper():
                    resource_model = resource_model or base
                elif base in variable_models:
                    resource_model = resource_model or variable_models[base]
                source = SourceSpan(
                    path="",
                    line=getattr(node, "lineno", function.lineno),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", function.lineno)),
                )
                return (
                    resource_model,
                    ".".join(resource_parts),
                    ".".join(principal_parts),
                    source,
                )
    return resource_model, "", "", None


def _candidate_id_fields(
    route_path: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[str], dict[str, str], dict[str, str]]:
    raw_path_fields = _PATH_PARAMETER.findall(route_path)
    path_fields = [template_name(name) for name in raw_path_fields]
    if path_fields:
        return (
            path_fields,
            {field: "path" for field in path_fields},
            dict(zip(path_fields, raw_path_fields)),
        )

    dependency_args = {
        argument.arg
        for argument, default in _function_defaults(function)
        if _dependency_names(default)
    }
    query_fields = [
        argument.arg
        for argument, _ in _function_defaults(function)
        if argument.arg not in dependency_args
        and (argument.arg in {"id", "object_id"} or argument.arg.endswith("_id"))
    ]
    if not query_fields:
        return [], {}, {}
    field = query_fields[0]
    return [field], {field: "query"}, {field: field}


def _source_span(path: str, node: ast.AST) -> SourceSpan:
    return SourceSpan(
        path=path,
        line=getattr(node, "lineno", 1),
        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
    )


def _parse_module(root: Path, path: Path) -> _Module:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path), type_comments=True)
    module_name, package = _module_name(root, path)
    relative_path = path.relative_to(root).as_posix()
    aliases = _aliases(tree, package)
    routers: dict[str, _Router] = {}

    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        call_name = _qualified(_dotted_name(value.func), aliases)
        if call_name.rsplit(".", 1)[-1] not in {"APIRouter", "FastAPI"}:
            continue
        prefix = _string(_keyword(value, "prefix")) or ""
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                routers[target.id] = _Router(module_name, target.id, prefix)

    module = _Module(module_name, package, relative_path, tree, aliases, routers, [], [])
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                dotted = _dotted_name(decorator.func)
                owner, _, method = dotted.rpartition(".")
                if method.lower() not in _HTTP_METHODS or owner not in routers:
                    continue
                route_path = _string(decorator.args[0] if decorator.args else None)
                route_path = route_path or _string(_keyword(decorator, "path"))
                if route_path is None:
                    continue
                operation_id = _string(_keyword(decorator, "operation_id")) or node.name
                module.routes.append(
                    _RawRoute(
                        router=(module_name, owner),
                        method=method.upper(),
                        path=route_path,
                        handler=node,
                        operation_id=operation_id,
                        module=module_name,
                        relative_path=relative_path,
                        decorator_dependencies=_dependency_names(
                            _keyword(decorator, "dependencies")
                        ),
                    )
                )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        owner, _, method = dotted.rpartition(".")
        if method != "include_router" or not owner or not node.args:
            continue
        module.includes.append(
            (ast.Name(id=owner), node.args[0], _string(_keyword(node, "prefix")) or "")
        )
    return module


def _python_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in _EXCLUDED_DIRS and not name.startswith(".")
        )
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = Path(current, name)
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                continue
            yield path


def _effective_prefixes(
    routers: dict[tuple[str, str], _Router],
    parents: dict[tuple[str, str], list[tuple[tuple[str, str], str]]],
    key: tuple[str, str],
    stack: tuple[tuple[str, str], ...] = (),
) -> list[str]:
    if key in stack:
        return [routers[key].prefix]
    links = parents.get(key) or []
    if not links:
        return [routers[key].prefix]
    prefixes: list[str] = []
    for parent, include_prefix in links:
        for parent_prefix in _effective_prefixes(routers, parents, parent, (*stack, key)):
            prefixes.append(_join_path(parent_prefix, include_prefix, routers[key].prefix))
    return sorted(set(prefixes))


def discover_fastapi(
    root: str,
    base_url: str = "http://localhost:3000",
    *,
    allow_empty: bool = False,
) -> Discovery:
    """Discover object routes and authorization evidence from FastAPI source."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"source root is not a directory: {root}")

    modules: dict[str, _Module] = {}
    diagnostics: list[str] = []
    files = list(_python_files(root_path))
    for path in files:
        try:
            module = _parse_module(root_path, path)
        except SyntaxError as exc:
            relative = path.relative_to(root_path).as_posix()
            diagnostics.append(f"{relative}:{exc.lineno or 1}: {exc.msg}")
            continue
        except (OSError, UnicodeError) as exc:
            relative = path.relative_to(root_path).as_posix()
            diagnostics.append(f"{relative}: {type(exc).__name__}: {exc}")
            continue
        modules[module.name] = module

    routers = {
        router.key: router
        for module in modules.values()
        for router in module.routers.values()
    }
    parents: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    for module in modules.values():
        for parent_node, child_node, prefix in module.includes:
            parent = _router_for_expression(parent_node, module, modules)
            child = _router_for_expression(child_node, module, modules)
            if parent and child:
                parents.setdefault(child, []).append((parent, prefix))

    candidates: list[RouteEvidence] = []
    for module in modules.values():
        for raw in module.routes:
            prefixes = _effective_prefixes(routers, parents, raw.router)
            for prefix in prefixes:
                path = _join_path(prefix, raw.path)
                id_fields, id_locations, id_request_names = _candidate_id_fields(
                    path, raw.handler
                )
                if not id_fields:
                    continue
                for template_field, request_name in id_request_names.items():
                    if id_locations[template_field] == "path":
                        path = path.replace(
                            "{" + request_name + "}", "{" + template_field + "}"
                        )
                target_id = id_fields[-1]
                base_resource = resource_name(path, target_id)
                resource = (
                    base_resource
                    if len(id_fields) == 1
                    else f"{base_resource}_by_{'_'.join(id_fields)}"
                )
                principal, auth_dependencies = _principal_and_dependencies(raw)
                resource_model, owner_field, principal_field, owner_span = _resource_analysis(
                    raw.handler, id_fields, principal
                )
                handler_span = _source_span(raw.relative_path, raw.handler)
                evidence = [
                    Evidence(
                        kind="route",
                        state="confirmed",
                        message=f"{raw.method} {path} is declared by {raw.handler.name}",
                        source=handler_span,
                    )
                ]
                if auth_dependencies:
                    evidence.append(
                        Evidence(
                            kind="authentication",
                            state="confirmed",
                            message="authentication dependencies: "
                            + ", ".join(auth_dependencies),
                            source=handler_span,
                        )
                    )
                authorization_dependencies = [
                    name
                    for name in auth_dependencies
                    if any(word in name.lower() for word in _AUTHORIZATION_WORDS)
                ]
                if authorization_dependencies:
                    evidence.append(
                        Evidence(
                            kind="authorization_guard",
                            state="confirmed",
                            message="authorization dependencies require review: "
                            + ", ".join(authorization_dependencies),
                            source=handler_span,
                        )
                    )
                if resource_model:
                    evidence.append(
                        Evidence(
                            kind="resource_lookup",
                            state="confirmed",
                            message=f"identifier is used to load {resource_model}",
                            source=handler_span,
                        )
                    )
                if owner_field:
                    if owner_span:
                        owner_span = SourceSpan(
                            raw.relative_path, owner_span.line, owner_span.end_line
                        )
                    evidence.append(
                        Evidence(
                            kind="ownership",
                            state="probable",
                            message=f"{owner_field} is compared with {principal_field}",
                            source=owner_span or handler_span,
                        )
                    )
                    policy_state = "probable"
                    suggested_allow = ["owner"]
                else:
                    message = (
                        "authentication was found, but no supported ownership rule was found"
                        if auth_dependencies
                        else "no supported authentication or ownership rule was found"
                    )
                    evidence.append(
                        Evidence(
                            kind="policy",
                            state="unresolved",
                            message=message,
                            source=handler_span,
                        )
                    )
                    policy_state = "unresolved"
                    suggested_allow = None

                candidates.append(
                    RouteEvidence(
                        method=raw.method,
                        path=path,
                        handler=raw.handler.name,
                        operation_id=raw.operation_id,
                        resource=resource,
                        id_fields=id_fields,
                        target_id=target_id,
                        id_locations=id_locations,
                        id_request_names=id_request_names,
                        policy_state=policy_state,
                        suggested_allow=suggested_allow,
                        auth_dependencies=auth_dependencies,
                        principal=principal,
                        resource_model=resource_model,
                        owner_field=owner_field,
                        principal_field=principal_field,
                        evidence=evidence,
                    )
                )

    deduplicated = {route.key: route for route in candidates}
    if not deduplicated and not allow_empty:
        raise ValueError("no FastAPI object endpoints found in source")
    return Discovery(
        framework="fastapi",
        root=".",
        base_url=base_url.rstrip("/"),
        routes=sorted(deduplicated.values(), key=lambda item: (item.path, item.method)),
        files_scanned=len(files),
        diagnostics=diagnostics,
    )
