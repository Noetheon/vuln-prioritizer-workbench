"""Template-aligned FastAPI entrypoint for the Workbench migration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.routing import APIRoute
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response

from app.api.main import api_router
from app.core.config import Settings, settings


def custom_generate_unique_id(route: APIRoute) -> str:
    """Use the official template operation-id convention for generated clients."""
    if route.tags:
        return f"{route.tags[0]}-{route.name}"
    return route.name


def create_app(active_settings: Settings | None = None) -> FastAPI:
    """Create the template-aligned backend shell without legacy side effects."""
    selected_settings = active_settings or settings
    app = FastAPI(
        title=selected_settings.PROJECT_NAME,
        openapi_url=f"{selected_settings.API_V1_STR}/openapi.json",
        generate_unique_id_function=custom_generate_unique_id,
    )
    app.state.template_settings = selected_settings
    if selected_settings.all_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(selected_settings.all_cors_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.middleware("http")(_upload_size_guard)
    app.include_router(api_router, prefix=selected_settings.API_V1_STR)
    return app


async def _upload_size_guard(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.method == "POST" and _is_template_upload_path(request.url.path):
        raw_content_length = request.headers.get("content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                content_length = 0
            active_settings = getattr(request.app.state, "template_settings", None)
            if isinstance(active_settings, Settings):
                multipart_overhead = 64 * 1024
                if content_length > active_settings.max_upload_bytes + multipart_overhead:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Upload exceeds configured limit."},
                    )
    return await call_next(request)


def _is_template_upload_path(path: str) -> bool:
    return path.startswith("/api/v1/projects/") and (
        path.endswith("/imports") or path.endswith("/assets/import")
    )


app = create_app()
