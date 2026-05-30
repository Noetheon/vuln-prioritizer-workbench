"""Payload assembly helpers for Workbench report generation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Session, col, select

from app.contracts.decision_evidence import AnalysisEvidenceV2
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingOccurrence,
    Project,
    WorkflowRunKind,
)
from app.models.base import get_datetime_utc
from app.repositories import EvidenceRepository, WaiverRepository
from app.repositories.workflows import WorkflowRepository
from app.services.decision_evidence_builder import build_run_diagnostics
from app.services.governance import build_project_governance_rollups_payload
from app.services.report_models import MarkdownReportPayload, ReportGenerationError
from app.services.report_projection import _finding_payload, _provider_snapshot_payload
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
    evidence_repository = EvidenceRepository(session)
    evidence = evidence_repository.get_analysis_evidence(run.id)
    if evidence is None:
        raise ReportGenerationError("Analysis evidence v2 is required before reporting.")
    findings = run_findings(session, run)
    run_occurrences = run_occurrences_by_finding(session, run)
    run_evidence = evidence_repository.finding_decision_evidence_for_run(run.id)
    attack_contexts = run_attack_contexts_by_finding(session, run)
    report_findings = [
        merge_attack_context(
            _finding_payload(
                finding,
                occurrences=run_occurrences.get(finding.id, []),
                evidence=run_evidence.get(finding.id),
            ),
            attack_contexts.get(finding.id),
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
    workflow = WorkflowRepository(session).get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.IMPORT,
    )
    diagnostics = evidence_repository.get_run_diagnostics(run.id)
    if diagnostics is None and workflow is not None and workflow.diagnostics_json:
        diagnostics = build_run_diagnostics(workflow.diagnostics_json)
    summary = _report_summary_payload(evidence)
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
        run_errors=diagnostics.to_jsonable() if diagnostics is not None else {},
        input_file_hash=_input_file_hash(evidence),
    )

    return payload, findings, generated_at


def run_findings(session: Session, run: AnalysisRun) -> list[Finding]:
    """Run findings function."""
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


def _report_summary_payload(evidence: AnalysisEvidenceV2 | None) -> dict[str, object]:
    if evidence is None:
        return {}
    payload = evidence.to_jsonable()
    provider = dict(payload.get("provider") or {})
    counts = dict(payload.get("counts") or {})
    uploads = dict(payload.get("uploads") or {})
    return {
        **counts,
        **provider,
        "input_upload": uploads.get("input"),
        "asset_context_upload": uploads.get("asset_context"),
        "vex_upload": uploads.get("vex"),
        "input_sha256": payload.get("input_sha256"),
        "warnings": payload.get("warnings") or [],
        "parse_errors": payload.get("parse_errors") or [],
        "analysis_service": payload.get("analysis_service") or {},
        "analysis_semantics": payload.get("analysis_semantics") or {},
        "asset_context": payload.get("asset_context"),
        "vex": payload.get("vex"),
        "dedup_summary": payload.get("dedup_summary"),
    }


def _input_file_hash(evidence: AnalysisEvidenceV2 | None) -> str | None:
    if evidence is None:
        return None
    payload = evidence.to_jsonable()
    if isinstance(payload.get("input_sha256"), str):
        return payload["input_sha256"]
    uploads = dict(payload.get("uploads") or {})
    input_upload = uploads.get("input")
    if isinstance(input_upload, dict) and isinstance(input_upload.get("sha256"), str):
        return input_upload["sha256"]
    return None
