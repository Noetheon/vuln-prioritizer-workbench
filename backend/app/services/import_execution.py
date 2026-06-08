"""Application service for Workbench import upload execution."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.decision_core.producer import (
    DecisionKernelInput,
    DecisionPersistencePlan,
    build_run_result,
)
from app.importers import ImporterParseError, ImporterValidationError
from app.models import AnalysisRun, AnalysisRunStatus, WorkflowRunKind, WorkflowRunStatus
from app.repositories import EvidenceRepository, RunRepository, WorkflowRepository
from app.services.analysis import AnalysisService, WorkbenchAnalysisError
from app.services.import_execution_context import (
    _apply_workbench_asset_context,
    _apply_workbench_vex,
    _parse_errors,
    _parsed_input_from_workbench_occurrences,
)
from app.services.import_execution_failures import (
    raise_analysis_failure as _raise_analysis_failure,
)
from app.services.import_execution_parse_failures import (
    raise_parse_failure as _raise_parse_failure,
)
from app.services.import_execution_parse_failures import (
    raise_sidecar_parse_failure as _raise_sidecar_parse_failure,
)
from app.services.import_execution_parsing import parse_prepared_upload as _parse_prepared_upload
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_summary import (
    _job_payload,
    _job_status_entry,
    _record_import_audit,
)
from app.services.import_execution_types import (
    ImportUploadContent,
    ProjectImportUploadRequest,
)
from app.services.import_execution_uploads import (
    apply_stored_upload_summaries as _apply_stored_upload_summaries,
)
from app.services.import_execution_uploads import (
    mark_import_run_running as _mark_import_run_running,
)
from app.services.import_execution_uploads import (
    prepare_import_upload as _prepare_import_upload,
)
from app.services.import_execution_uploads import (
    resolve_import_run as _resolve_import_run,
)
from app.services.import_execution_uploads import (
    store_prepared_uploads as _store_prepared_uploads,
)
from app.services.import_uploads import sanitize_parser_error_message as _sanitize_error_message
from app.services.workflow_execution import WorkflowExecutionContext

__all__ = [
    "ImportUploadContent",
    "ProjectImportUploadRequest",
    "execute_project_import_upload",
]


@dataclass(frozen=True, slots=True)
class _ImportFailureContext:
    session: Session
    run_repo: RunRepository
    run: AnalysisRun
    local_actor: LocalWorkbenchActor
    project_id: uuid.UUID
    job_id: str
    job_history: list[dict[str, str]]
    ignored_lines: int
    input_type: str


async def execute_project_import_upload(
    *,
    project_id: uuid.UUID,
    session: Session,
    local_actor: LocalWorkbenchActor,
    settings: Settings,
    upload: ProjectImportUploadRequest,
    defer_execution: bool = False,
    existing_run_id: uuid.UUID | None = None,
    workflow_context: WorkflowExecutionContext | None = None,
) -> AnalysisRun:
    """Securely upload, normalize, and persist one Workbench import file."""
    prepared = _prepare_import_upload(upload, settings=settings)
    run_repo = RunRepository(session)
    workflow_repo = WorkflowRepository(session)
    resolved_run = _resolve_import_run(
        run_repo=run_repo,
        project_id=project_id,
        prepared=prepared,
        existing_run_id=existing_run_id,
    )
    run = resolved_run.run
    workflow = workflow_repo.ensure_analysis_workflow(
        kind=WorkflowRunKind.IMPORT,
        analysis_run_id=run.id,
        project_id=project_id,
        title=f"Import {prepared.input_type}",
        handler="app.services.import_execution.execute_project_import_upload",
        status=_workflow_status_for_run(run.status),
        current_stage="queued",
        metadata_json={
            "input_type": prepared.input_type,
            "filename": prepared.stored_filename,
            "locked_provider_data": prepared.locked_provider_data,
        },
    )
    context = workflow_context or WorkflowExecutionContext.for_workflow(workflow_repo, workflow.id)
    if resolved_run.already_finished:
        return run

    artifacts = _store_prepared_uploads(
        settings,
        project_id=project_id,
        run_id=run.id,
        prepared=prepared,
    )
    context.stage(
        "store_uploads",
        "Managed upload artifacts stored.",
        progress_current=1,
        progress_total=6,
        details={
            "input_ref": artifacts.upload_ref,
            "asset_context_ref": artifacts.asset_context_ref,
            "vex_ref": artifacts.vex_ref,
        },
    )
    initial_result_payload = _apply_stored_upload_summaries(
        run,
        resolved_run=resolved_run,
        prepared=prepared,
        artifacts=artifacts,
    )
    context.output(result=initial_result_payload)
    if defer_execution:
        session.commit()
        session.refresh(run)
        return run

    context.start(
        stage="parse_upload",
        message="Parsing primary import upload.",
        progress_current=2,
        progress_total=6,
    )
    job_history = _mark_import_run_running(
        run,
        job_id=resolved_run.job_id,
        job_history=resolved_run.job_history,
    )
    session.flush()
    failure_context = _ImportFailureContext(
        session=session,
        run_repo=run_repo,
        run=run,
        local_actor=local_actor,
        project_id=project_id,
        job_id=resolved_run.job_id,
        job_history=job_history,
        ignored_lines=prepared.ignored_lines,
        input_type=prepared.input_type,
    )

    try:
        parsed_upload = _parse_prepared_upload(prepared)
        occurrences = parsed_upload.occurrences
        context.stage(
            "parse_upload",
            "Primary import upload parsed.",
            progress_current=3,
            progress_total=6,
            details={"occurrence_count": len(occurrences)},
        )
    except (ImporterParseError, ImporterValidationError) as exc:
        parse_errors = _parse_errors(
            exc,
            filename=prepared.stored_filename,
            input_type=prepared.input_type,
        )
        context.fail(
            stage="parse_upload",
            message="Import parsing failed.",
            progress_current=2,
            progress_total=6,
            diagnostics={
                "stage": "parse_upload",
                "message": "Import parsing failed.",
                "error_type": exc.__class__.__name__,
                "parse_errors": parse_errors,
                "ignored_lines": failure_context.ignored_lines,
                "created_findings": 0,
                "updated_findings": 0,
                "import_job": _job_payload(
                    job_id=failure_context.job_id,
                    status="failed",
                    status_history=[
                        *failure_context.job_history,
                        _job_status_entry("failed"),
                    ],
                ),
            },
            terminal_code="parse_failed",
        )
        _raise_parse_failure(
            session=failure_context.session,
            run_repo=failure_context.run_repo,
            run=failure_context.run,
            local_actor=failure_context.local_actor,
            project_id=failure_context.project_id,
            job_id=failure_context.job_id,
            job_history=failure_context.job_history,
            ignored_lines=failure_context.ignored_lines,
            input_type=failure_context.input_type,
            filename=prepared.stored_filename,
            exc=exc,
        )

    asset_context_summary: dict[str, Any] | None = None
    if artifacts.asset_context_path is not None:
        try:
            context.stage(
                "asset_context_parse",
                "Applying asset context sidecar.",
                progress_current=3,
                progress_total=6,
            )
            occurrences, asset_context_summary = _apply_workbench_asset_context(
                occurrences,
                asset_context_path=artifacts.asset_context_path,
            )
        except ValueError as exc:
            sidecar_error = {
                "message": _sanitize_error_message(str(exc)),
                "filename": prepared.asset_context.stored_filename,
                "stage": "asset_context_parse",
                "error_type": exc.__class__.__name__,
            }
            context.fail(
                stage="asset_context_parse",
                message="Asset context parsing failed.",
                progress_current=3,
                progress_total=6,
                diagnostics={
                    "stage": "asset_context_parse",
                    "message": "Asset context parsing failed.",
                    "error_type": exc.__class__.__name__,
                    "asset_context_error": sidecar_error,
                    "ignored_lines": failure_context.ignored_lines,
                    "created_findings": 0,
                    "updated_findings": 0,
                    "import_job": _job_payload(
                        job_id=failure_context.job_id,
                        status="failed",
                        status_history=[
                            *failure_context.job_history,
                            _job_status_entry("failed"),
                        ],
                    ),
                },
                terminal_code="sidecar_parse_failed",
            )
            _raise_sidecar_parse_failure(
                session=failure_context.session,
                run_repo=failure_context.run_repo,
                run=failure_context.run,
                local_actor=failure_context.local_actor,
                project_id=failure_context.project_id,
                job_id=failure_context.job_id,
                job_history=failure_context.job_history,
                ignored_lines=failure_context.ignored_lines,
                input_type=failure_context.input_type,
                error_key="asset_context_error",
                response_message="Asset context parsing failed.",
                filename=prepared.asset_context.stored_filename,
                stage="asset_context_parse",
                exc=exc,
            )

    vex_summary: dict[str, Any] | None = None
    if artifacts.vex_path is not None:
        try:
            context.stage(
                "vex_parse",
                "Applying VEX sidecar.",
                progress_current=3,
                progress_total=6,
            )
            occurrences, vex_summary = _apply_workbench_vex(
                occurrences,
                vex_path=artifacts.vex_path,
            )
        except ValueError as exc:
            sidecar_error = {
                "message": _sanitize_error_message(str(exc)),
                "filename": prepared.vex.stored_filename,
                "stage": "vex_parse",
                "error_type": exc.__class__.__name__,
            }
            context.fail(
                stage="vex_parse",
                message="VEX parsing failed.",
                progress_current=3,
                progress_total=6,
                diagnostics={
                    "stage": "vex_parse",
                    "message": "VEX parsing failed.",
                    "error_type": exc.__class__.__name__,
                    "vex_error": sidecar_error,
                    "ignored_lines": failure_context.ignored_lines,
                    "created_findings": 0,
                    "updated_findings": 0,
                    "import_job": _job_payload(
                        job_id=failure_context.job_id,
                        status="failed",
                        status_history=[
                            *failure_context.job_history,
                            _job_status_entry("failed"),
                        ],
                    ),
                },
                terminal_code="sidecar_parse_failed",
            )
            _raise_sidecar_parse_failure(
                session=failure_context.session,
                run_repo=failure_context.run_repo,
                run=failure_context.run,
                local_actor=failure_context.local_actor,
                project_id=failure_context.project_id,
                job_id=failure_context.job_id,
                job_history=failure_context.job_history,
                ignored_lines=failure_context.ignored_lines,
                input_type=failure_context.input_type,
                error_key="vex_error",
                response_message="VEX parsing failed.",
                filename=prepared.vex.stored_filename,
                stage="vex_parse",
                exc=exc,
            )

    try:
        context.stage(
            "enrich_score_explain",
            "Running provider enrichment, scoring, and explanation.",
            progress_current=4,
            progress_total=6,
            details={"occurrence_count": len(occurrences)},
        )
        parsed_input = _parsed_input_from_workbench_occurrences(
            occurrences,
            input_path=artifacts.upload_path,
            input_type=prepared.input_type,
            base_parsed_input=parsed_upload.parsed_input.parsed_input,
            asset_context_summary=asset_context_summary,
            vex_summary=vex_summary,
        )
        analysis_result = AnalysisService(session, settings).analyze_import(
            input_path=artifacts.upload_path,
            input_type=prepared.input_type,
            asset_context_file=None,
            provider_snapshot_file=prepared.provider_snapshot_path,
            locked_provider_data=prepared.locked_provider_data,
            attack_source=prepared.attack_source,
            attack_mapping_file=prepared.attack_mapping_path,
            attack_technique_metadata_file=prepared.attack_metadata_path,
            vex_files=[],
            parsed_input=parsed_input,
        )
    except ValueError as exc:
        analysis_error = {
            "message": _sanitize_error_message(str(exc)),
            "stage": "enrich_score_explain",
            "error_type": exc.__class__.__name__,
        }
        context.fail(
            stage="enrich_score_explain",
            message="Import analysis failed.",
            progress_current=4,
            progress_total=6,
            diagnostics={
                "stage": "enrich_score_explain",
                "message": "Import analysis failed.",
                "error_type": exc.__class__.__name__,
                "analysis_error": analysis_error,
                "ignored_lines": failure_context.ignored_lines,
                "created_findings": 0,
                "updated_findings": 0,
                "import_job": _job_payload(
                    job_id=failure_context.job_id,
                    status="failed",
                    status_history=[
                        *failure_context.job_history,
                        _job_status_entry("failed"),
                    ],
                ),
            },
            terminal_code="analysis_failed",
        )
        _raise_analysis_failure(
            session=failure_context.session,
            run_repo=failure_context.run_repo,
            run=failure_context.run,
            local_actor=failure_context.local_actor,
            project_id=failure_context.project_id,
            job_id=failure_context.job_id,
            job_history=failure_context.job_history,
            ignored_lines=failure_context.ignored_lines,
            input_type=failure_context.input_type,
            exc=WorkbenchAnalysisError(str(exc)),
        )
    except WorkbenchAnalysisError as exc:
        analysis_error = {
            "message": _sanitize_error_message(str(exc)),
            "stage": "enrich_score_explain",
            "error_type": exc.__class__.__name__,
        }
        context.fail(
            stage="enrich_score_explain",
            message="Import analysis failed.",
            progress_current=4,
            progress_total=6,
            diagnostics={
                "stage": "enrich_score_explain",
                "message": "Import analysis failed.",
                "error_type": exc.__class__.__name__,
                "analysis_error": analysis_error,
                "ignored_lines": failure_context.ignored_lines,
                "created_findings": 0,
                "updated_findings": 0,
                "import_job": _job_payload(
                    job_id=failure_context.job_id,
                    status="failed",
                    status_history=[
                        *failure_context.job_history,
                        _job_status_entry("failed"),
                    ],
                ),
            },
            terminal_code="analysis_failed",
        )
        _raise_analysis_failure(
            session=failure_context.session,
            run_repo=failure_context.run_repo,
            run=failure_context.run,
            local_actor=failure_context.local_actor,
            project_id=failure_context.project_id,
            job_id=failure_context.job_id,
            job_history=failure_context.job_history,
            ignored_lines=failure_context.ignored_lines,
            input_type=failure_context.input_type,
            exc=exc,
        )

    context.stage(
        "persist_findings",
        "Persisting normalized findings and occurrences.",
        progress_current=5,
        progress_total=6,
        details={"occurrence_count": len(occurrences)},
    )
    evidence_repo = EvidenceRepository(session)
    prepared_evidence_record = evidence_repo.prepare_analysis_evidence_record(
        project_id=project_id,
        analysis_run_id=run.id,
        provider_snapshot_id=analysis_result.provider_snapshot_id,
    )
    persist_summary = _persist_workbench_occurrences(
        session=session,
        project_id=project_id,
        run_id=run.id,
        occurrences=occurrences,
        analysis_result=analysis_result,
        analysis_evidence_id=prepared_evidence_record.id,
    )
    run.provider_snapshot_id = analysis_result.provider_snapshot_id
    finished_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.SUCCEEDED,
    )
    persistence_plan = DecisionPersistencePlan.from_summary(
        analysis_evidence_id=prepared_evidence_record.id,
        ignored_lines=prepared.ignored_lines,
        analysis_result=analysis_result,
        summary=persist_summary,
    )
    decision_result = build_run_result(
        kernel_input=DecisionKernelInput(
            project_id=project_id,
            run=finished_run,
            prepared=prepared,
            artifacts=artifacts,
            analysis_result=analysis_result,
            asset_context_summary=asset_context_summary,
            vex_summary=vex_summary,
        ),
        persistence_plan=persistence_plan,
    )
    evidence_record = evidence_repo.upsert_analysis_evidence(
        project_id=project_id,
        analysis_run_id=finished_run.id,
        provider_snapshot_id=analysis_result.provider_snapshot_id,
        evidence=decision_result.analysis_evidence,
    )
    if decision_result.finding_evidence:
        evidence_repo.replace_finding_decision_evidence(
            analysis_evidence_id=evidence_record.id,
            project_id=project_id,
            analysis_run_id=finished_run.id,
            evidence_items=decision_result.finding_evidence,
        )
    context.succeed(
        stage="succeeded",
        message="Import workflow succeeded.",
        progress_current=6,
        progress_total=6,
        result=decision_result.workflow_result.to_jsonable(),
        diagnostics={},
        details=decision_result.workflow_details,
    )
    _record_import_audit(
        session,
        local_actor=local_actor,
        project_id=project_id,
        run_id=finished_run.id,
        status="success",
        stage="succeeded",
        input_type=prepared.input_type,
    )
    session.commit()
    return finished_run


def _workflow_status_for_run(status: AnalysisRunStatus | str) -> WorkflowRunStatus:
    normalized = AnalysisRunStatus(status)
    if normalized == AnalysisRunStatus.FAILED:
        return WorkflowRunStatus.FAILED
    if normalized == AnalysisRunStatus.CANCELLED:
        return WorkflowRunStatus.CANCELLED
    if normalized == AnalysisRunStatus.COMPLETED_WITH_ERRORS:
        return WorkflowRunStatus.COMPLETED_WITH_ERRORS
    if normalized in {AnalysisRunStatus.SUCCEEDED, AnalysisRunStatus.COMPLETED}:
        return WorkflowRunStatus.SUCCEEDED
    if normalized == AnalysisRunStatus.RUNNING:
        return WorkflowRunStatus.RUNNING
    return WorkflowRunStatus.PENDING
