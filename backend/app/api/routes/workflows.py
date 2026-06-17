"""Durable workflow API routes."""

from __future__ import annotations

import uuid
from asyncio import sleep

from fastapi import APIRouter, HTTPException, WebSocket
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session

from app.api.deps import LocalActor, SessionDep, WebSocketLocalActor
from app.api.routes.workbench_access import require_project
from app.models import (
    WorkflowEventsPublic,
    WorkflowRunPublic,
    WorkflowRunsPublic,
    WorkflowRunStatus,
)
from app.repositories import WorkflowRepository
from app.services.workflows import (
    request_workflow_cancellation,
    workflow_event_public,
    workflow_run_public,
)

router = APIRouter(tags=["workflows"])


@router.get("/projects/{project_id}/workflows", response_model=WorkflowRunsPublic)
def read_project_workflows(
    project_id: uuid.UUID,
    session: SessionDep,
    _local_actor: LocalActor,
    limit: int = 100,
    offset: int = 0,
) -> WorkflowRunsPublic:
    """Return durable workflows for a visible project."""
    require_project(session, project_id)
    repository = WorkflowRepository(session)
    workflows, count = repository.list_project_workflows(
        project_id,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
    )
    return WorkflowRunsPublic(
        data=[
            workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))
            for workflow in workflows
        ],
        count=count,
    )


@router.get("/workflows/{workflow_id}", response_model=WorkflowRunPublic)
def read_workflow(
    workflow_id: uuid.UUID,
    session: SessionDep,
    _local_actor: LocalActor,
) -> WorkflowRunPublic:
    """Return one durable workflow by id."""
    repository = WorkflowRepository(session)
    workflow = repository.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if workflow.project_id is not None:
        require_project(session, workflow.project_id)
    return workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))


@router.post("/workflows/{workflow_id}/cancel", response_model=WorkflowRunPublic)
def cancel_workflow(
    workflow_id: uuid.UUID,
    session: SessionDep,
    _local_actor: LocalActor,
) -> WorkflowRunPublic:
    """Request cooperative cancellation for one workflow."""
    repository = WorkflowRepository(session)
    workflow = repository.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if workflow.project_id is not None:
        require_project(session, workflow.project_id)
    workflow = request_workflow_cancellation(
        session,
        workflow.id,
        message="Cancellation requested by user.",
    )
    session.commit()
    session.refresh(workflow)
    return workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))


@router.post("/workflows/{workflow_id}/retry", response_model=WorkflowRunPublic)
def retry_workflow(
    workflow_id: uuid.UUID,
    session: SessionDep,
    _local_actor: LocalActor,
) -> WorkflowRunPublic:
    """Create a new queued workflow from a previous failed/cancelled workflow payload."""
    repository = WorkflowRepository(session)
    workflow = repository.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if workflow.project_id is not None:
        require_project(session, workflow.project_id)
    if workflow.status not in {WorkflowRunStatus.FAILED, WorkflowRunStatus.CANCELLED}:
        raise HTTPException(status_code=409, detail="Workflow is not retryable.")
    retry = repository.clone_for_manual_retry(workflow.id)
    session.commit()
    session.refresh(retry)
    return workflow_run_public(retry, latest_event=repository.latest_event(retry.id))


@router.get("/workflows/{workflow_id}/events", response_model=WorkflowEventsPublic)
def read_workflow_events(
    workflow_id: uuid.UUID,
    session: SessionDep,
    _local_actor: LocalActor,
    limit: int = 500,
    offset: int = 0,
) -> WorkflowEventsPublic:
    """Return append-only events for one durable workflow."""
    repository = WorkflowRepository(session)
    workflow = repository.get_workflow(workflow_id)
    if workflow is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if workflow.project_id is not None:
        require_project(session, workflow.project_id)
    events, count = repository.list_workflow_events(
        workflow_id,
        limit=max(1, min(limit, 1000)),
        offset=max(0, offset),
    )
    return WorkflowEventsPublic(
        data=[workflow_event_public(event) for event in events],
        count=count,
    )


@router.websocket("/workflows/{workflow_id}/stream")
async def stream_workflow_events(
    websocket: WebSocket,
    workflow_id: uuid.UUID,
    _local_actor: WebSocketLocalActor,
    after_sequence: int = 0,
) -> None:
    """Stream workflow snapshots and events over WebSocket."""
    await websocket.accept()
    active_engine = getattr(websocket.app.state, "workbench_engine", None)
    if active_engine is None:
        await websocket.close(code=1011, reason="Workbench database engine is not configured.")
        return
    last_sequence = max(0, after_sequence)
    while True:
        with Session(active_engine) as session:
            repository = WorkflowRepository(session)
            workflow = repository.get_workflow(workflow_id)
            if workflow is None:
                await websocket.send_json({"type": "error", "detail": "Workflow not found"})
                await websocket.close(code=1008)
                return
            if workflow.project_id is not None:
                try:
                    require_project(session, workflow.project_id)
                except HTTPException as exc:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "detail": str(exc.detail),
                        }
                    )
                    await websocket.close(code=1008)
                    return
            await websocket.send_json(
                {
                    "type": "workflow",
                    "workflow": jsonable_encoder(
                        workflow_run_public(
                            workflow,
                            latest_event=repository.latest_event(workflow.id),
                        )
                    ),
                }
            )
            events, _count = repository.list_workflow_events(workflow.id, limit=1000)
            for event in events:
                if event.sequence <= last_sequence:
                    continue
                last_sequence = event.sequence
                await websocket.send_json(
                    {
                        "type": "event",
                        "event": jsonable_encoder(workflow_event_public(event)),
                    }
                )
            if workflow.status in {
                WorkflowRunStatus.SUCCEEDED,
                WorkflowRunStatus.COMPLETED_WITH_ERRORS,
                WorkflowRunStatus.FAILED,
                WorkflowRunStatus.CANCELLED,
            }:
                await websocket.close(code=1000)
                return
        await sleep(1.0)
