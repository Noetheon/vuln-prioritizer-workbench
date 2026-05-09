"""Payload assembly helpers for Workbench report generation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Session, col, select

from app.models import AnalysisRun, AnalysisRunStatus, Finding, FindingOccurrence, Project
from app.models.base import get_datetime_utc
from app.repositories import WaiverRepository
from app.services.governance import build_project_governance_rollups_payload
from app.services.report_models import MarkdownReportPayload, ReportGenerationError
from app.services.report_projection import _finding_payload, _provider_snapshot_payload

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
    if run.status not in REPORT_SUPPORTED_RUN_STATUSES:
        raise ReportGenerationError(
            f"Analysis run must be completed before reporting; current status is {run.status}."
        )

    generated_at = get_datetime_utc()
    findings = run_findings(session, run)
    run_occurrences = run_occurrences_by_finding(session, run)
    report_findings = [
        _finding_payload(
            finding,
            occurrences=run_occurrences.get(finding.id, []),
        )
        for finding in findings
    ]
    waiver_repository = WaiverRepository(session)
    governance_rollups = build_project_governance_rollups_payload(
        project_id=project.id,
        findings=findings,
        waivers=waiver_repository.list_project_waivers(project.id),
        waiver_repository=waiver_repository,
    )
    payload = MarkdownReportPayload(
        generated_at=generated_at,
        project_id=str(project.id),
        project_name=project.name,
        run_id=str(run.id),
        run_status=str(run.status),
        input_type=run.input_type,
        filename=run.filename,
        summary=dict(run.summary_json or {}),
        findings=report_findings,
        provider_snapshot=_provider_snapshot_payload(run.provider_snapshot),
        governance_rollups=governance_rollups.model_dump(mode="json"),
        project_description=project.description,
        project_owner_id=str(project.owner_id),
        project_created_at=project.created_at,
        project_updated_at=project.updated_at,
        run_started_at=run.started_at,
        run_finished_at=run.finished_at,
        run_error=run.error_message,
        run_errors=dict(run.error_json or {}),
    )
    return payload, findings, generated_at


def run_findings(session: Session, run: AnalysisRun) -> list[Finding]:
    statement = (
        select(Finding)
        .join(FindingOccurrence)
        .where(FindingOccurrence.analysis_run_id == run.id)
        .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
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
