"""Payload assembly helpers for Workbench report generation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Session, col, select

from app.decision_core.readmodels import decision_run_view, run_finding_decision_views
from app.models import (
    AnalysisEvidence,
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingDecisionEvidence,
    FindingOccurrence,
    Project,
)
from app.models.base import get_datetime_utc
from app.services.report_governance_projection import build_run_governance_rollups
from app.services.report_models import MarkdownReportPayload, ReportGenerationError
from app.services.report_projection import (
    _finding_payload_from_decision_view,
    _provider_snapshot_payload,
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
    generated_at = get_datetime_utc()
    run_view = decision_run_view(run, session=session)
    evidence = run_view.evidence
    if evidence is None:
        raise ReportGenerationError("Analysis evidence v2 is required before reporting.")
    if evidence.analysis_run_id != str(run.id):
        raise ReportGenerationError(
            "Analysis evidence run identity does not match the requested report run."
        )
    if evidence.project_id != str(project.id) or evidence.project_id != str(run.project_id):
        raise ReportGenerationError(
            "Analysis evidence project identity does not match the requested report project."
        )
    if evidence.status not in {str(status) for status in REPORT_SUPPORTED_RUN_STATUSES}:
        raise ReportGenerationError(
            "Analysis run must be completed before reporting; "
            f"evidence status is {evidence.status}."
        )
    findings = run_findings(session, run)
    if len(findings) != evidence.counts.finding_count:
        raise ReportGenerationError(
            "Analysis evidence finding membership is inconsistent: "
            f"expected {evidence.counts.finding_count}, found {len(findings)}."
        )
    finding_views = sorted(
        run_finding_decision_views(session, run=run, findings=findings),
        key=lambda view: (
            view.operational_rank or 999_999,
            view.priority_rank,
            view.cve_id,
            str(view.finding.id),
        ),
    )
    for view in finding_views:
        finding_evidence = view.evidence
        if finding_evidence is None:
            raise ReportGenerationError(
                "Analysis evidence finding membership contains an untyped finding."
            )
        if (
            finding_evidence.analysis_run_id != evidence.analysis_run_id
            or finding_evidence.project_id != evidence.project_id
            or finding_evidence.finding_id != str(view.finding.id)
        ):
            raise ReportGenerationError(
                "Finding decision evidence identity does not match the report evidence envelope."
            )
    run_occurrences = (
        run_occurrences_by_finding(session, run)
        if any(view.evidence is None for view in finding_views)
        else {}
    )
    report_findings = [
        _finding_payload_from_decision_view(
            view,
            occurrences=run_occurrences.get(view.finding.id, []),
        )
        for view in finding_views
    ]
    governance_rollups = build_run_governance_rollups(
        project_id=project.id,
        findings=report_findings,
        generated_at=generated_at,
        evaluated_at=generated_at,
    )
    summary = run_view.summary_payload
    payload = MarkdownReportPayload(
        generated_at=generated_at,
        project_id=evidence.project_id,
        project_name=project.name,
        run_id=evidence.analysis_run_id,
        run_status=evidence.status,
        input_type=evidence.input_type,
        filename=evidence.filename,
        summary=summary,
        findings=tuple(report_findings),
        provider_snapshot=_provider_snapshot_payload(
            run.provider_snapshot,
            evidence=evidence.provider,
            finding_evidence=tuple(
                view.evidence for view in finding_views if view.evidence is not None
            ),
        ),
        governance_rollups=governance_rollups,
        project_description=project.description,
        project_created_at=project.created_at,
        project_updated_at=project.updated_at,
        project_context_source="current_project_projection_at_export",
        run_started_at=None,
        run_finished_at=None,
        run_error=None,
        run_errors=evidence.diagnostics.to_jsonable() if evidence.diagnostics is not None else {},
        input_file_hash=run_view.input_file_hash,
    )

    return payload, findings, generated_at


def run_findings(session: Session, run: AnalysisRun) -> list[Finding]:
    """Return immutable v2 run members, with occurrence lookup only for true legacy runs."""
    has_analysis_evidence = (
        session.exec(
            select(AnalysisEvidence.id).where(AnalysisEvidence.analysis_run_id == run.id).limit(1)
        ).first()
        is not None
    )
    if has_analysis_evidence:
        statement = (
            select(Finding)
            .join(
                FindingDecisionEvidence,
                col(FindingDecisionEvidence.finding_id) == col(Finding.id),
            )
            .where(FindingDecisionEvidence.analysis_run_id == run.id)
            .order_by(FindingDecisionEvidence.cve_id, col(Finding.id))
        )
    else:
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
