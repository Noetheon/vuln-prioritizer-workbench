"""Per-project priority thresholds and SLA response targets."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.models import ProjectPolicyPublic, ProjectPolicyUpdate, ProjectPolicyUpdatePublic
from app.models.evaluations import EvaluationCreate
from app.services.project_policy import project_policy_public, save_project_policy
from app.services.reevaluation_execution import ReevaluationConflict, project_evaluation_inputs
from app.services.reevaluation_queue import enqueue_project_reevaluation

router = APIRouter(tags=["projects"])


@router.get("/projects/{project_id}/policy", response_model=ProjectPolicyPublic)
def read_project_policy(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> ProjectPolicyPublic:
    """Return the thresholds and SLA targets new evaluations of this project use."""
    _ = local_actor
    require_project(session, project_id)
    return project_policy_public(session, project_id)


@router.put("/projects/{project_id}/policy", response_model=ProjectPolicyUpdatePublic)
def update_project_policy(
    project_id: uuid.UUID,
    payload: ProjectPolicyUpdate,
    session: SessionDep,
    local_actor: LocalActor,
) -> ProjectPolicyUpdatePublic:
    """Save a new policy version and queue a re-evaluation of existing findings."""
    require_project(session, project_id)
    try:
        changed = save_project_policy(
            session,
            project_id,
            payload,
            actor=local_actor,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=_validation_message(exc)) from exc
    evaluation_run_id: uuid.UUID | None = None
    skipped: str | None = None
    if not payload.reevaluate:
        skipped = "Re-evaluation was not requested."
    elif not changed:
        skipped = "The policy did not change."
    else:
        version = project_policy_public(session, project_id).version
        try:
            project_evaluation_inputs(session, project_id, None)
        except ReevaluationConflict as exc:
            skipped = str(exc)
        else:
            reason = (payload.reason or "").strip()
            run = enqueue_project_reevaluation(
                session,
                project_id,
                EvaluationCreate(
                    reason=f"Policy version {version}" + (f": {reason}" if reason else "")
                ),
            )
            evaluation_run_id = run.id
    session.commit()
    return ProjectPolicyUpdatePublic(
        policy=project_policy_public(session, project_id),
        changed=changed,
        evaluation_run_id=evaluation_run_id,
        evaluation_skipped_reason=skipped,
    )


def _validation_message(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        messages = [str(error.get("msg", "")).removeprefix("Value error, ") for error in errors()]
        return "; ".join(message for message in messages if message) or str(exc)
    return str(exc)
