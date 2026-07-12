"""Serve the packaged Workbench frontend from the FastAPI process."""

from __future__ import annotations

from collections.abc import MutableMapping
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from starlette.responses import FileResponse, Response
from starlette.staticfiles import StaticFiles


class ImmutableAssetFiles(StaticFiles):
    """StaticFiles variant with immutable caching for hashed Vite assets."""

    async def get_response(self, path: str, scope: MutableMapping[str, Any]) -> Response:
        """Add long-lived caching to a successfully resolved hashed asset."""
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


def packaged_frontend_root() -> Path:
    """Return the installed package's frontend asset root."""
    return Path(str(resources.files("app").joinpath("static")))


def mount_packaged_frontend(
    app: FastAPI,
    *,
    frontend_root: Path | None = None,
) -> bool:
    """Mount built assets and an SPA fallback when a packaged frontend exists."""
    root = (frontend_root or packaged_frontend_root()).resolve(strict=False)
    index = root / "index.html"
    if not index.is_file():
        app.state.frontend_mounted = False
        app.state.frontend_root = None
        return False

    assets = root / "assets"
    if assets.is_dir():
        app.mount(
            "/assets",
            ImmutableAssetFiles(directory=assets),
            name="workbench-frontend-assets",
        )

    def serve_index() -> FileResponse:
        return FileResponse(index, headers={"Cache-Control": "no-store"})

    @app.middleware("http")
    async def serve_frontend_fallback(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        if (
            request.method not in {"GET", "HEAD"}
            or response.status_code != 404
            or _is_reserved_server_path(request)
        ):
            return response

        frontend_path = request.url.path.lstrip("/")
        candidate = (root / frontend_path).resolve(strict=False)
        if candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate, headers={"Cache-Control": "no-cache"})
        return serve_index()

    app.add_api_route("/", serve_index, methods=["GET", "HEAD"], include_in_schema=False)
    app.state.frontend_mounted = True
    app.state.frontend_root = root
    return True


def _is_reserved_server_path(request: Request) -> bool:
    """Keep API and framework endpoints out of the SPA fallback."""
    path = request.url.path.rstrip("/") or "/"
    api_prefix = str(getattr(request.app.state.workbench_settings, "API_V1_STR", "/api/v1"))
    normalized_api_prefix = f"/{api_prefix.strip('/')}"
    reserved_prefixes = (
        "/api",
        normalized_api_prefix,
        "/assets",
        "/docs",
        "/redoc",
    )
    if path == "/openapi.json":
        return True
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in reserved_prefixes)
