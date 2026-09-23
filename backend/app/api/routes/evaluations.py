"""Native reevaluation workflows and immutable decision revision history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlmodel import col, func, select

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunsPublic,
    Finding,
    FindingCurrentProjection,
    FindingDecisionEvidence,
    ProviderSnapshot,
    WorkflowRunKind,
    WorkflowRunStatus,
)
from app.models.evaluations import DecisionRevisionPublic, DecisionRevisionsPublic, EvaluationCreate
from app.repositories import RunRepository, WorkflowRepository
from app.repositories.evidence_payloads import EvidencePayloadStore
from app.services.reevaluation_execution import (
    ReevaluationConflict,
    load_verified_snapshot,
    project_evaluation_inputs,
)
from app.services.run_workflow_projection import analysis_run_public
from app.services.workflows import latest_analysis_workflow_public

router = APIRouter(tags=["evaluations"])


@router.post("/projects/{project_id}/evaluations", response_model=AnalysisRunPublic)
def create_evaluation(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    body: EvaluationCreate | None = None,
) -> AnalysisRunPublic:
    """Queue evaluation of existing scopes; upload/observation history is retained."""
    require_project(session, project_id)
    payload = body or EvaluationCreate()
    try:
        project_evaluation_inputs(session, project_id, payload.finding_ids)
        if payload.provider_snapshot_id is not None:
            snapshot = session.get(ProviderSnapshot, payload.provider_snapshot_id)
            if snapshot is None:
                raise HTTPException(status_code=404, detail="Provider snapshot not found")
            load_verified_snapshot(snapshot, workbench_settings(request))
    except ReevaluationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    run = RunRepository(session).create_analysis_run(
        project_id=project_id,
        input_type="reevaluation",
        provider_snapshot_id=payload.provider_snapshot_id,
    )
    repository = WorkflowRepository(session)
    workflow = repository.ensure_analysis_workflow(
        kind=WorkflowRunKind.REEVALUATION,
        analysis_run_id=run.id,
        project_id=project_id,
        title="Evaluate existing findings",
        handler="app.services.reevaluation_execution.execute_reevaluation_workflow",
        current_stage="queued",
        status=WorkflowRunStatus.PENDING,
        metadata_json={"reason": payload.reason},
    )
    repository.set_workflow_payload(
        workflow.id,
        payload_json=payload.model_dump(mode="json"),
        queue_name="default",
        max_retries=0,
    )
    session.commit()
    session.refresh(run)
    return analysis_run_public(
        run,
        session=session,
        workflow=latest_analysis_workflow_public(
            session,
            analysis_run_id=run.id,
            kind=WorkflowRunKind.REEVALUATION,
        ),
    )


@router.get("/projects/{project_id}/evaluations", response_model=AnalysisRunsPublic)
def list_evaluations(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AnalysisRunsPublic:
    """List native evaluations, including immediate context/waiver revisions."""
    require_project(session, project_id)
    predicate = (AnalysisRun.project_id == project_id, AnalysisRun.input_type == "reevaluation")
    count = session.exec(select(func.count()).select_from(AnalysisRun).where(*predicate)).one()
    runs = session.exec(
        select(AnalysisRun)
        .where(*predicate)
        .order_by(col(AnalysisRun.started_at).desc(), col(AnalysisRun.id).desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return AnalysisRunsPublic(
        data=[
            analysis_run_public(
                run,
                session=session,
                workflow=latest_analysis_workflow_public(
                    session,
                    analysis_run_id=run.id,
                    kind=WorkflowRunKind.REEVALUATION,
                ),
            )
            for run in runs
        ],
        count=count,
    )


@router.get("/findings/{finding_id}/decision-revisions", response_model=DecisionRevisionsPublic)
def list_decision_revisions(
    finding_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> DecisionRevisionsPublic:
    """Compare immutable decisions to their chronological predecessor."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_project(session, finding.project_id)
    count = session.exec(
        select(func.count())
        .select_from(FindingDecisionEvidence)
        .where(FindingDecisionEvidence.finding_id == finding_id)
    ).one()
    rows = session.exec(
        select(FindingDecisionEvidence)
        .where(FindingDecisionEvidence.finding_id == finding_id)
        .order_by(
            col(FindingDecisionEvidence.created_at).desc(), col(FindingDecisionEvidence.id).desc()
        )
        .offset(offset)
        .limit(limit + 1)
    ).all()
    projection = session.get(FindingCurrentProjection, finding_id)
    payloads = EvidencePayloadStore(session.connection()).load_records(rows)
    data = []
    for index, row in enumerate(rows[:limit]):
        evidence = FindingDecisionEvidenceV2.model_validate(payloads[row.id])
        previous = payloads[rows[index + 1].id] if index + 1 < len(rows) else None
        metadata = evidence.evaluation
        data.append(
            DecisionRevisionPublic(
                id=row.id,
                analysis_run_id=row.analysis_run_id,
                evaluated_at=datetime.fromisoformat(metadata.evaluated_at)
                if metadata
                else row.created_at,
                observed_at=datetime.fromisoformat(metadata.observed_at)
                if metadata and metadata.observed_at
                else None,
                cause=metadata.cause if metadata else "import",
                provider_snapshot_id=uuid.UUID(evidence.provider.provider_snapshot_id)
                if evidence.provider.provider_snapshot_id
                else None,
                engine_version=metadata.engine_version if metadata else None,
                input_sha256=metadata.input_sha256 if metadata else None,
                replay_status="available"
                if evidence.evaluation_input is not None
                else "legacy_unavailable",
                priority=evidence.priority,
                status=evidence.status,
                risk_score=evidence.risk_score,
                operational_rank=evidence.operational_rank,
                rationale=evidence.rationale,
                recommended_action=evidence.recommended_action,
                is_current=projection is not None
                and projection.source_finding_evidence_id == row.id,
                changed_fields=_changed_fields(payloads[row.id], previous),
            )
        )
    return DecisionRevisionsPublic(data=data, count=count)


def _changed_fields(current: dict[str, Any], previous: dict[str, Any] | None) -> list[str]:
    if previous is None:
        return []
    fields = (
        "priority",
        "status",
        "risk_score",
        "operational_rank",
        "rationale",
        "recommended_action",
        "waived",
        "suppressed_by_vex",
        "under_investigation",
        "occurrence_scope",
        "provider",
        "attack",
        "remediation",
        "evaluation_input",
    )
    return [name for name in fields if current.get(name) != previous.get(name)]
