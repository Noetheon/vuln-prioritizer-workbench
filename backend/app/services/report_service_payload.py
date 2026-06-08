"""Payload assembly helpers for Workbench report generation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Session, col, select

from app.decision_core.readmodels import decision_run_view, run_finding_decision_views
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingOccurrence,
    Project,
)
from app.models.base import get_datetime_utc
from app.repositories import WaiverRepository
from app.services.governance_rollups import build_project_governance_rollups_payload
from app.services.report_models import MarkdownReportPayload, ReportGenerationError
from app.services.report_projection import (
    _finding_payload_from_decision_view,
    _provider_snapshot_payload,
)
from app.services.report_service_payload_attack import (
    merge_attack_context,
    run_attack_contexts_by_finding,
)

REPORT_SUPPORTED_RUN_STATUSES = {
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
}


def build_report_payload(
    session: Session,
    *,
    run: AnalysisRun,
    project: Project,
) -> tuple[MarkdownReportPayload, list[Finding], datetime]:
    """Build report payload function."""
    if run.status not in REPORT_SUPPORTED_RUN_STATUSES:
        raise ReportGenerationError(
            f"Analysis run must be completed before reporting; current status is {run.status}."
        )

    generated_at = get_datetime_utc()
    run_view = decision_run_view(run, session=session)
    evidence = run_view.evidence
    if evidence is None:
        raise ReportGenerationError("Analysis evidence v2 is required before reporting.")
    findings = run_findings(session, run)
    run_occurrences = run_occurrences_by_finding(session, run)
    finding_views = sorted(
        run_finding_decision_views(session, run=run, findings=findings),
        key=lambda view: (
            view.operational_rank or 999_999,
            view.priority_rank,
            view.cve_id,
            str(view.finding.id),
        ),
    )
    attack_contexts = run_attack_contexts_by_finding(session, run)
    report_findings = [
        merge_attack_context(
            _finding_payload_from_decision_view(
                view,
                occurrences=run_occurrences.get(view.finding.id, []),
            ),
            attack_contexts.get(view.finding.id),
        )
        for view in finding_views
    ]
    waiver_repository = WaiverRepository(session)
    governance_rollups = build_project_governance_rollups_payload(
        project_id=project.id,
        findings=finding_views,
        waivers=waiver_repository.list_project_waivers(project.id),
        waiver_repository=waiver_repository,
    )
    summary = run_view.summary_payload
    payload = MarkdownReportPayload(
        generated_at=generated_at,
        project_id=str(project.id),
        project_name=project.name,
        run_id=str(run.id),
        run_status=str(run.status),
        input_type=run.input_type,
        filename=run.filename,
        summary=summary,
        findings=tuple(report_findings),
        provider_snapshot=_provider_snapshot_payload(run.provider_snapshot),
        governance_rollups=governance_rollups.model_dump(mode="json"),
        project_description=project.description,
        project_created_at=project.created_at,
        project_updated_at=project.updated_at,
        run_started_at=run.started_at,
        run_finished_at=run.finished_at,
        run_error=run.error_message,
        run_errors=run_view.diagnostics.to_jsonable() if run_view.diagnostics is not None else {},
        input_file_hash=run_view.input_file_hash,
    )

    return payload, findings, generated_at


def run_findings(session: Session, run: AnalysisRun) -> list[Finding]:
    """Run findings function."""
    statement = (
        select(Finding)
        .join(FindingOccurrence)
        .where(FindingOccurrence.analysis_run_id == run.id)
        .order_by(Finding.cve_id, col(Finding.id))
    )
    findings: list[Finding] = []
    seen_ids: set[uuid.UUID] = set()
    for finding in session.exec(statement).all():
        if finding.id in seen_ids:
            continue
        findings.append(finding)
        seen_ids.add(finding.id)
    return findings


def run_occurrences_by_finding(
    session: Session,
    run: AnalysisRun,
) -> dict[uuid.UUID, list[FindingOccurrence]]:
    """Run occurrences by finding function."""
    statement = (
        select(FindingOccurrence)
        .where(FindingOccurrence.analysis_run_id == run.id)
        .order_by(col(FindingOccurrence.id))
    )
    occurrences: dict[uuid.UUID, list[FindingOccurrence]] = {}
    for occurrence in session.exec(statement).all():
        occurrences.setdefault(occurrence.finding_id, []).append(occurrence)
    return occurrences


__all__ = [
    "REPORT_SUPPORTED_RUN_STATUSES",
    "build_report_payload",
    "run_findings",
    "run_occurrences_by_finding",
]
