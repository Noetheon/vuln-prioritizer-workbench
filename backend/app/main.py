"""Template-aligned FastAPI entrypoint for the Workbench migration."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute

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
    app.include_router(api_router, prefix=selected_settings.API_V1_STR)
    return app


app = create_app()
