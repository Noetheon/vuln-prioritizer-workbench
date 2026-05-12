"""Job summary and audit helpers for Workbench import execution."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from sqlmodel import Session

from app.core.local_actor import LocalWorkbenchActor
from app.models.base import get_datetime_utc
from app.services.audit import record_audit_event


def _record_import_audit(
    session: Session,
    *,
    local_actor: LocalWorkbenchActor,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    status: Literal["success", "failure"],
    stage: str,
    input_type: str,
) -> None:
    record_audit_event(
        session,
        action="import.run",
        resource_type="analysis_run",
        resource_id=run_id,
        status=status,
        actor=local_actor,
        project_id=project_id,
        detail={"stage": stage, "input_type": input_type},
    )


def _job_payload(
    *,
    job_id: str,
    status: str,
    status_history: list[dict[str, str]],
    execution_mode: str = "request",
) -> dict[str, Any]:
    timestamp = get_datetime_utc().isoformat()
    return {
        "id": job_id,
        "status": status,
        "execution_mode": execution_mode,
        "updated_at": timestamp,
        "status_history": status_history,
    }


def _job_status_entry(status: str) -> dict[str, str]:
    return {
        "status": status,
        "created_at": get_datetime_utc().isoformat(),
    }
