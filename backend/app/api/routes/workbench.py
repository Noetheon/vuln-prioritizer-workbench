"""Workbench adapter routes exposed through the template API namespace."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.core.config import Settings, settings
from app.models import MigrationStatus, WorkbenchStatus
from vuln_prioritizer import __version__

router = APIRouter(prefix="/workbench", tags=["workbench"])


@router.get("/status")
def template_workbench_status(request: Request) -> WorkbenchStatus:
    """Return template-shell status without initializing the legacy Workbench DB."""
    active_settings = _request_settings(request)
    return WorkbenchStatus(
        status="ok",
        app=active_settings.PROJECT_NAME,
        core_package="vuln_prioritizer",
        core_version=__version__,
        legacy_api_prefix=active_settings.LEGACY_API_PREFIX,
        migration=MigrationStatus(
            phase="template-backend-adapter",
            legacy_workbench_mounted=False,
        ),
    )


def _request_settings(request: Request) -> Settings:
    active_settings = getattr(request.app.state, "template_settings", settings)
    if isinstance(active_settings, Settings):
        return active_settings
    return settings
