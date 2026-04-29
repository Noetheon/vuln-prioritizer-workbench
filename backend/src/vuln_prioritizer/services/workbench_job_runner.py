"""Execution logic for queued local Workbench jobs."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from sqlalchemy.orm import Session

from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_reports import (
    ReportFormat,
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

ProviderUpdateRunner = Callable[
    [WorkbenchRepository, WorkbenchSettings, dict[str, Any]],
    tuple[Any, list[str]],
]


def execute_queued_workbench_job(
    *,
    repo: WorkbenchRepository,
    session: Session,
    settings: WorkbenchSettings,
    job: Any,
    provider_update_runner: ProviderUpdateRunner,
) -> dict[str, Any]:
    """Run one queued Workbench job and return the persisted result JSON."""
    payload = job.payload_json if isinstance(job.payload_json, dict) else {}
    if job.kind == "create_report":
        analysis_run_id = _queued_job_analysis_run_id(job, payload)
        report_format_value = str(payload.get("format") or "html")
        if report_format_value not in {"json", "markdown", "html", "csv", "sarif"}:
            raise WorkbenchReportError(f"Unsupported report format: {report_format_value}.")
        report_format = cast(ReportFormat, report_format_value)
        report = create_run_report(
            session=session,
            settings=settings,
            analysis_run_id=analysis_run_id,
            report_format=report_format,
        )
        job.project_id = report.project_id
        repo.create_audit_event(
            project_id=report.project_id,
            event_type="report.created",
            target_type="report",
            target_id=report.id,
            message=f"{report_format} report was created.",
            metadata_json={"job_id": job.id, "runner": "api-local-runner"},
        )
        return {
            "report_id": report.id,
            "analysis_run_id": report.analysis_run_id,
            "format": report.format,
        }
    if job.kind == "create_evidence_bundle":
        analysis_run_id = _queued_job_analysis_run_id(job, payload)
        bundle = create_run_evidence_bundle(
            session=session,
            settings=settings,
            analysis_run_id=analysis_run_id,
        )
        job.project_id = bundle.project_id
        repo.create_audit_event(
            project_id=bundle.project_id,
            event_type="evidence_bundle.created",
            target_type="evidence_bundle",
            target_id=bundle.id,
            message="Evidence bundle was created.",
            metadata_json={"job_id": job.id, "runner": "api-local-runner"},
        )
        return {
            "evidence_bundle_id": bundle.id,
            "analysis_run_id": bundle.analysis_run_id,
        }
    if job.kind == "provider_update":
        provider_job, sources = provider_update_runner(repo, settings, payload)
        provider_job.metadata_json = {
            **(provider_job.metadata_json or {}),
            "job_id": job.id,
        }
        repo.create_audit_event(
            project_id=job.project_id,
            event_type="provider_update_job.created",
            target_type="provider_update_job",
            target_id=provider_job.id,
            message="Provider update job was created.",
            metadata_json={
                "status": provider_job.status,
                "sources": sources,
            },
        )
        return {
            "provider_update_job_id": provider_job.id,
            "status": provider_job.status,
            "new_snapshot_id": (provider_job.metadata_json or {}).get("new_snapshot_id"),
        }
    if job.kind == "import_findings":
        if not job.project_id:
            raise WorkbenchAnalysisError("Queued import job is missing project_id.")
        input_paths = [
            _queued_job_artifact_path(value, settings=settings)
            for value in _job_payload_list(payload.get("input_paths") or payload.get("input_path"))
        ]
        input_formats = _job_payload_list(
            payload.get("input_formats") or payload.get("input_format")
        )
        original_filenames = _job_payload_list(
            payload.get("original_filenames") or payload.get("original_filename")
        )
        content_types = cast(
            list[str | None],
            _job_payload_list(payload.get("content_types") or payload.get("content_type")),
        )
        if not input_paths:
            raise WorkbenchAnalysisError("Queued import job is missing input_paths.")
        if len(input_formats) != len(input_paths):
            raise WorkbenchAnalysisError(
                "Queued import job input format count does not match files."
            )
        if not original_filenames:
            original_filenames = [path.name for path in input_paths]
        if len(original_filenames) != len(input_paths):
            raise WorkbenchAnalysisError(
                "Queued import job original filename count does not match files."
            )
        result = run_workbench_import(
            session=session,
            settings=settings,
            project_id=job.project_id,
            input_path=input_paths,
            original_filename=original_filenames,
            input_format=input_formats,
            input_content_type=content_types if content_types else None,
            provider_snapshot_file=_queued_job_optional_artifact_path(
                payload.get("provider_snapshot_file"),
                settings=settings,
            ),
            locked_provider_data=bool(payload.get("locked_provider_data", False)),
            attack_source=str(payload.get("attack_source") or "none"),
            attack_mapping_file=_queued_job_optional_artifact_path(
                payload.get("attack_mapping_file"),
                settings=settings,
            ),
            attack_technique_metadata_file=_queued_job_optional_artifact_path(
                payload.get("attack_technique_metadata_file"),
                settings=settings,
            ),
            asset_context_file=_queued_job_optional_artifact_path(
                payload.get("asset_context_file"),
                settings=settings,
            ),
            vex_file=_queued_job_optional_artifact_path(payload.get("vex_file"), settings=settings),
            waiver_file=_queued_job_optional_artifact_path(
                payload.get("waiver_file"),
                settings=settings,
            ),
            defensive_context_file=_queued_job_optional_artifact_path(
                payload.get("defensive_context_file"),
                settings=settings,
            ),
        )
        result.run.metadata_json = {**result.run.metadata_json, "job_id": job.id}
        return {
            "analysis_run_id": result.run.id,
            "findings_count": result.run.metadata_json.get("findings_count", 0),
        }
    raise WorkbenchAnalysisError(f"Unsupported Workbench job kind: {job.kind}.")


def _queued_job_analysis_run_id(job: Any, payload: dict[str, Any]) -> str:
    raw_value = payload.get("analysis_run_id") or job.target_id
    if not raw_value:
        raise WorkbenchReportError("Queued job is missing analysis_run_id.")
    return str(raw_value)


def _job_payload_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item)]
    return [str(value)]


def _queued_job_optional_artifact_path(
    value: Any,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or value == "":
        return None
    return _queued_job_artifact_path(str(value), settings=settings)


def _queued_job_artifact_path(value: str, *, settings: WorkbenchSettings) -> Path:
    candidate = Path(value).expanduser().resolve(strict=False)
    allowed_roots = (
        settings.upload_dir.resolve(strict=False),
        settings.provider_snapshot_dir.resolve(strict=False),
        settings.provider_cache_dir.resolve(strict=False),
        settings.attack_artifact_dir.resolve(strict=False),
    )
    if not any(candidate.is_relative_to(root) for root in allowed_roots):
        raise WorkbenchAnalysisError("Queued job artifact path is outside Workbench data roots.")
    if not candidate.is_file():
        raise WorkbenchAnalysisError("Queued job artifact no longer exists.")
    return candidate
