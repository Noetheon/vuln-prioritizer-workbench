"""Dependency helpers for the active local Workbench runtime."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Request
from sqlmodel import Session

from app.core.app_state import workbench_engine, workbench_settings
from app.core.local_actor import LocalWorkbenchActor, configured_local_actor


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield a SQLModel session for active API routes."""
    with Session(workbench_engine(request)) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_local_actor(request: Request) -> LocalWorkbenchActor:
    """
    Return the local single-user Workbench principal.

    The current product scope is a local/self-hosted single-user Workbench, so
    API routes should not require login, RBAC, token scopes, or session
    cookies during normal operation.
    """
    return configured_local_actor(workbench_settings(request, required=False))


LocalActor = Annotated[LocalWorkbenchActor, Depends(get_local_actor)]
