"""Framework detection and source discovery orchestration."""
from __future__ import annotations

import os
from pathlib import Path

from .fastapi import discover_fastapi
from .models import Discovery
from .openapi import reconcile_openapi


def _detect_framework(root: str) -> str:
    root_path = Path(root).expanduser().resolve()
    excluded = {".git", ".venv", "venv", "site-packages", "node_modules", "__pycache__"}
    for current, dirs, files in os.walk(root_path, followlinks=False):
        dirs[:] = [name for name in dirs if name not in excluded and not name.startswith(".")]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = Path(current, name)
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if "from fastapi" in text or "import fastapi" in text:
                return "fastapi"
    raise ValueError("could not detect a supported API framework; pass --framework fastapi")


def discover_source(
    root: str,
    framework: str = "auto",
    openapi: str | None = None,
    base_url: str | None = None,
) -> Discovery:
    """Discover object routes from source and optionally reconcile an OpenAPI spec."""
    selected = _detect_framework(root) if framework == "auto" else framework
    if selected != "fastapi":
        raise ValueError(f"unsupported source framework: {selected}")
    discovery = discover_fastapi(
        root,
        base_url=base_url or "http://localhost:3000",
        allow_empty=bool(openapi),
    )
    if openapi:
        discovery = reconcile_openapi(discovery, openapi)
    if base_url:
        discovery.base_url = base_url.rstrip("/")
    return discovery
