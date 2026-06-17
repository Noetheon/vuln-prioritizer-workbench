"""Workbench runtime state helpers."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, WebSocket
from sqlalchemy.engine import Engine

from app.core.config import Settings, settings
from app.core.db import engine

WORKBENCH_SETTINGS_STATE_KEY = "workbench_settings"
WORKBENCH_ENGINE_STATE_KEY = "workbench_engine"


def configure_workbench_state(
    app: Any,
    *,
    active_settings: Settings,
    active_engine: Engine,
) -> None:
    """Store active Workbench settings and engine on the FastAPI app state."""
    app.state.workbench_settings = active_settings
    app.state.workbench_engine = active_engine


def workbench_settings(
    request: Request | WebSocket,
    *,
    required: bool = True,
) -> Settings:
    """Return the active Workbench settings for a request."""
    candidate = getattr(request.app.state, WORKBENCH_SETTINGS_STATE_KEY, None)
    if isinstance(candidate, Settings):
        return candidate
    if not required:
        return settings
    raise HTTPException(status_code=500, detail="Workbench settings are not configured.")


def workbench_engine(request: Request) -> Engine:
    """Return the active Workbench database engine for a request."""
    candidate = getattr(request.app.state, WORKBENCH_ENGINE_STATE_KEY, None)
    if isinstance(candidate, Engine):
        return candidate
    raise HTTPException(status_code=500, detail="Workbench database engine is not configured.")


def fallback_workbench_engine(request: Request) -> Engine:
    """Return the active engine or the process-global engine for controlled tests."""
    candidate = getattr(request.app.state, WORKBENCH_ENGINE_STATE_KEY, None)
    if isinstance(candidate, Engine):
        return candidate
    return engine
