"""Public projections for analysis runs backed by Evidence v2."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import object_session
from sqlmodel import Session

from app.contracts.decision_evidence import (
    AnalysisEvidenceV2,
    RunDiagnosticsV2,
)
from app.models import (
    AnalysisRun,
    AnalysisRunCountsPublic,
    AnalysisRunProviderSnapshotRefPublic,
    AnalysisRunPublic,
    AnalysisRunStatus,
    AnalysisRunSummaryPublic,
    AnalysisRunUploadsPublic,
    WorkflowRunKind,
    WorkflowRunPublic,
)
from app.repositories import EvidenceRepository, WorkflowRepository
from app.services.decision_evidence_builder import build_run_diagnostics
from app.services.run_workflow_metadata import redact_public_payload

SUCCESSFUL_RUN_STATUSES = {
    AnalysisRunStatus.SUCCEEDED,
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
}


def analysis_run_public(
    run: AnalysisRun,
    *,
    session: Session | None = None,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunPublic:
    """Return the public analysis-run response from the v2 evidence source."""
    evidence, diagnostics, raw_result = _evidence_context(run, session=session)
    counts = _counts(evidence, raw_result)
    return AnalysisRunPublic(
        id=run.id,
        project_id=run.project_id,
        provider_snapshot_id=run.provider_snapshot_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error_message=redact_public_payload(run.error_message),
        evidence=evidence,
        diagnostics=diagnostics,
        uploads=_uploads(evidence, raw_result),
        provider_snapshot=_provider_snapshot(run, evidence, raw_result),
        counts=counts,
        warnings=_warnings(evidence, raw_result),
        parse_errors=list(evidence.parse_errors)
        if evidence is not None
        else list(diagnostics.parse_errors)
        if diagnostics is not None
        else [],
        workflow=workflow,
    )


def analysis_run_summary_public(
    run: AnalysisRun,
    *,
    session: Session | None = None,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunSummaryPublic:
    """Return the public run-summary response from Evidence v2."""
    evidence, diagnostics, raw_result = _evidence_context(run, session=session)
    counts = _counts(evidence, raw_result)
    return AnalysisRunSummaryPublic(
        id=run.id,
        project_id=run.project_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_findings=counts.created_findings,
        updated_findings=counts.updated_findings,
        ignored_lines=counts.ignored_lines,
        rows_read=counts.rows_read,
        occurrence_count=counts.occurrence_count,
        finding_count=counts.finding_count,
        counts_by_priority=counts.counts_by_priority,
        kev_hits=counts.kev_hits,
        provider_snapshot_id=run.provider_snapshot_id,
        provider_degraded=_provider_degraded(evidence, raw_result),
        warnings=_warnings(evidence, raw_result),
        parse_errors=list(evidence.parse_errors)
        if evidence is not None
        else list(diagnostics.parse_errors)
        if diagnostics is not None
        else [],
        evidence=evidence,
        diagnostics=diagnostics,
        uploads=_uploads(evidence, raw_result),
        provider_snapshot=_provider_snapshot(run, evidence, raw_result),
        analysis_decision_scope=_analysis_decision_scope(evidence, raw_result),
        persistence_scope=_persistence_scope(evidence, raw_result),
        workflow=workflow,
    )


def _evidence_context(
    run: AnalysisRun,
    *,
    session: Session | None,
) -> tuple[AnalysisEvidenceV2 | None, RunDiagnosticsV2 | None, dict[str, Any]]:
    active_session = session or object_session(run)
    if not isinstance(active_session, Session):
        return None, None, {}
    evidence_repo = EvidenceRepository(active_session)
    evidence = evidence_repo.get_analysis_evidence(run.id)
    diagnostics = evidence_repo.get_run_diagnostics(run.id)
    workflow = WorkflowRepository(active_session).get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.IMPORT,
    )
    raw_result: dict[str, Any] = {}
    if workflow is not None and run.status not in SUCCESSFUL_RUN_STATUSES:
        raw_result = _dict_value(redact_public_payload(workflow.result_json))
    if diagnostics is None and workflow is not None and workflow.diagnostics_json:
        diagnostics = build_run_diagnostics(redact_public_payload(workflow.diagnostics_json))
    return evidence, diagnostics, raw_result


def _uploads(
    evidence: AnalysisEvidenceV2 | None,
    raw_result: dict[str, Any],
) -> AnalysisRunUploadsPublic:
    if evidence is not None:
        return AnalysisRunUploadsPublic(
            input=evidence.uploads.input.to_jsonable() if evidence.uploads.input else None,
            asset_context=evidence.uploads.asset_context.to_jsonable()
            if evidence.uploads.asset_context
            else None,
            vex=evidence.uploads.vex.to_jsonable() if evidence.uploads.vex else None,
        )
    return AnalysisRunUploadsPublic(
        input=_dict_or_none(raw_result.get("input_upload")),
        asset_context=_dict_or_none(raw_result.get("asset_context_upload")),
        vex=_dict_or_none(raw_result.get("vex_upload")),
    )


def _provider_snapshot(
    run: AnalysisRun,
    evidence: AnalysisEvidenceV2 | None,
    raw_result: dict[str, Any],
) -> AnalysisRunProviderSnapshotRefPublic | None:
    if evidence is not None:
        provider = evidence.provider
        if run.provider_snapshot_id is None and provider.provider_snapshot_hash is None:
            return None
        return AnalysisRunProviderSnapshotRefPublic(
            id=run.provider_snapshot_id,
            file=provider.provider_snapshot_file,
            hash=provider.provider_snapshot_hash,
            locked=provider.locked_provider_data,
            degraded=provider.provider_degraded,
        )
    if run.provider_snapshot_id is None and not any(
        raw_result.get(key)
        for key in ("provider_snapshot_file", "provider_snapshot_hash", "locked_provider_data")
    ):
        return None
    return AnalysisRunProviderSnapshotRefPublic(
        id=run.provider_snapshot_id,
        file=_str_value(raw_result.get("provider_snapshot_file")),
        hash=_str_value(raw_result.get("provider_snapshot_hash")),
        locked=_bool_value(raw_result.get("locked_provider_data")),
        degraded=_bool_value(raw_result.get("provider_degraded")),
    )


def _counts(
    evidence: AnalysisEvidenceV2 | None,
    raw_result: dict[str, Any],
) -> AnalysisRunCountsPublic:
    if evidence is not None:
        counts = evidence.counts
        return AnalysisRunCountsPublic(
            created_findings=counts.created_findings,
            updated_findings=counts.updated_findings,
            ignored_lines=counts.ignored_lines,
            rows_read=counts.rows_read,
            occurrence_count=counts.occurrence_count,
            finding_count=counts.finding_count,
            counts_by_priority=dict(counts.counts_by_priority),
            kev_hits=counts.kev_hits,
            suppressed_by_vex=counts.suppressed_by_vex,
            attack_mapped_cves=counts.attack_mapped_cves,
        )
    dedup_summary = _dict_value(raw_result.get("dedup_summary"))
    return AnalysisRunCountsPublic(
        created_findings=_int_value(
            raw_result.get("created_findings", dedup_summary.get("created_findings"))
        ),
        updated_findings=_int_value(
            raw_result.get(
                "updated_findings",
                dedup_summary.get("updated_findings", dedup_summary.get("reused_findings")),
            )
        ),
        ignored_lines=_int_value(raw_result.get("ignored_lines")),
        rows_read=_int_value(raw_result.get("rows_read")),
        occurrence_count=_int_value(raw_result.get("occurrence_count")),
        finding_count=_int_value(raw_result.get("finding_count")),
        counts_by_priority=_priority_counts(raw_result.get("counts_by_priority")),
        kev_hits=_int_value(raw_result.get("kev_hits")),
        suppressed_by_vex=_int_value(raw_result.get("suppressed_by_vex")),
        attack_mapped_cves=_int_value(raw_result.get("attack_mapped_cves")),
    )


def _provider_degraded(evidence: AnalysisEvidenceV2 | None, raw_result: dict[str, Any]) -> bool:
    if evidence is not None:
        return evidence.provider.provider_degraded
    return _bool_value(raw_result.get("provider_degraded"))


def _analysis_decision_scope(
    evidence: AnalysisEvidenceV2 | None,
    raw_result: dict[str, Any],
) -> str | None:
    if evidence is not None:
        return _str_value(evidence.analysis_semantics.get("analysis_decision_scope"))
    return _str_value(raw_result.get("analysis_decision_scope"))


def _persistence_scope(
    evidence: AnalysisEvidenceV2 | None,
    raw_result: dict[str, Any],
) -> str | None:
    if evidence is not None:
        return _str_value(evidence.analysis_semantics.get("persistence_scope"))
    return _str_value(raw_result.get("persistence_scope"))


def _warnings(evidence: AnalysisEvidenceV2 | None, raw_result: dict[str, Any]) -> list[str]:
    if evidence is not None:
        return list(evidence.warnings)
    return _string_list(raw_result.get("warnings"))


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    payload = _dict_value(value)
    return payload or None


def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _priority_counts(value: Any) -> dict[str, int]:
    raw = _dict_value(value)
    return {key: _int_value(raw.get(key)) for key in ("Critical", "High", "Medium", "Low")}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0
