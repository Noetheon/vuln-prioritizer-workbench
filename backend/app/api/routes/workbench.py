"""Workbench routes exposed through the active API namespace."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.core.config import Settings, settings
from app.models import WorkbenchStatus
from vuln_prioritizer import __version__

router = APIRouter(prefix="/workbench", tags=["workbench"])


@router.get("/status")
def template_workbench_status(request: Request) -> WorkbenchStatus:
    """Return active Workbench backend status."""
    active_settings = _request_settings(request)
    return WorkbenchStatus(
        status="ok",
        app=active_settings.PROJECT_NAME,
        core_package="vuln_prioritizer",
        core_version=__version__,
    )


def _request_settings(request: Request) -> Settings:
    active_settings = getattr(request.app.state, "template_settings", settings)
    if isinstance(active_settings, Settings):
        return active_settings
    return settings
