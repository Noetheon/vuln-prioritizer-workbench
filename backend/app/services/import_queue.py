"""Shared queuing for uploaded and content-verified replayed import inputs."""

from __future__ import annotations

import uuid

from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.models import AnalysisRun
from app.services.import_execution import execute_project_import_upload
from app.services.import_execution_types import ProjectImportUploadRequest


async def queue_project_import(
    *,
    project_id: uuid.UUID,
    session: Session,
    local_actor: LocalWorkbenchActor,
    settings: Settings,
    upload: ProjectImportUploadRequest,
) -> AnalysisRun:
    """Store inputs and queue the same durable import contract for every entrypoint."""
    return await execute_project_import_upload(
        project_id=project_id,
        session=session,
        local_actor=local_actor,
        settings=settings,
        upload=upload,
        defer_execution=True,
    )
