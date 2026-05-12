"""Local single-user actor helpers for the Workbench runtime."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.config import Settings, settings

LOCAL_ACTOR_NAMESPACE = uuid.UUID("82a5f27c-a7db-4b44-a860-143b0137e419")


@dataclass(frozen=True, slots=True)
class LocalWorkbenchActor:
    """Small in-memory principal for the local single-user Workbench."""

    id: uuid.UUID
    email: str
    is_active: bool = True
    full_name: str = "Local Workbench"


def local_actor_id(email: str) -> uuid.UUID:
    """Return the stable local actor UUID for a configured email."""
    return uuid.uuid5(LOCAL_ACTOR_NAMESPACE, email.lower())


def configured_local_actor(active_settings: Settings | None = None) -> LocalWorkbenchActor:
    """Return the configured local Workbench actor without touching the database."""
    selected_settings = active_settings or settings
    return LocalWorkbenchActor(
        id=local_actor_id(selected_settings.LOCAL_WORKBENCH_USER_EMAIL),
        email=selected_settings.LOCAL_WORKBENCH_USER_EMAIL,
    )
