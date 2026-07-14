"""Framework-neutral evidence produced by source adapters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceSpan:
    """A stable source location relative to the analyzed repository."""

    path: str
    line: int
    end_line: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
        }


@dataclass(frozen=True)
class Evidence:
    """One observed fact or inference supporting a route candidate."""

    kind: str
    state: str
    message: str
    source: SourceSpan | None = None

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "kind": self.kind,
            "state": self.state,
            "message": self.message,
        }
        if self.source:
            item["source"] = self.source.to_dict()
        return item


@dataclass
class RouteEvidence:
    """An object-level API operation and the evidence found for its policy."""

    method: str
    path: str
    handler: str
    operation_id: str
    resource: str
    id_fields: list[str]
    target_id: str
    id_locations: dict[str, str]
    id_request_names: dict[str, str]
    policy_state: str = "unresolved"
    suggested_allow: list[str] | None = None
    auth_dependencies: list[str] = field(default_factory=list)
    principal: str = ""
    resource_model: str = ""
    owner_field: str = ""
    principal_field: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "key": self.key,
            "method": self.method,
            "path": self.path,
            "handler": self.handler,
            "operation_id": self.operation_id,
            "resource": self.resource,
            "id_fields": self.id_fields,
            "target_id": self.target_id,
            "id_locations": self.id_locations,
            "id_request_names": self.id_request_names,
            "policy": {
                "state": self.policy_state,
                "suggested_allow": self.suggested_allow,
            },
            "auth_dependencies": self.auth_dependencies,
            "principal": self.principal or None,
            "resource_model": self.resource_model or None,
            "ownership": None,
            "evidence": [entry.to_dict() for entry in self.evidence],
        }
        if self.owner_field:
            item["ownership"] = {
                "resource_field": self.owner_field,
                "principal_field": self.principal_field,
            }
        return item


@dataclass
class Discovery:
    """The complete deterministic result of a source discovery run."""

    framework: str
    root: str
    base_url: str
    routes: list[RouteEvidence]
    files_scanned: int
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self, decisions: dict[str, list[str] | None] | None = None) -> dict[str, Any]:
        selected = decisions or {}
        return {
            "schema_version": 1,
            "framework": self.framework,
            "root": self.root,
            "base_url": self.base_url,
            "files_scanned": self.files_scanned,
            "summary": {
                "object_routes": len(self.routes),
                "probable_policies": sum(
                    route.policy_state == "probable" for route in self.routes
                ),
                "unresolved_policies": sum(
                    route.policy_state == "unresolved" for route in self.routes
                ),
                "diagnostics": len(self.diagnostics),
            },
            "routes": [
                {
                    **route.to_dict(),
                    "decision": selected.get(route.key, "unresolved"),
                }
                for route in sorted(self.routes, key=lambda item: (item.path, item.method))
            ],
            "diagnostics": sorted(self.diagnostics),
        }
