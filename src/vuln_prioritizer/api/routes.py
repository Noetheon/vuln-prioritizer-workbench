"""JSON API route facade for the Workbench MVP."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from vuln_prioritizer.api.workbench_artifact_routes import (
    cleanup_project_artifact_retention,
    create_evidence_bundle,
    create_report,
    delete_evidence_bundle,
    delete_report,
    download_evidence_bundle,
    download_report,
    get_project_artifact_retention,
    list_project_artifacts,
    update_project_artifact_retention,
    verify_evidence_bundle_api,
)
from vuln_prioritizer.api.workbench_artifact_routes import (
    router as artifact_router,
)
from vuln_prioritizer.api.workbench_attack_detection_routes import (
    ATTACK_REVIEW_SOURCES,
    create_detection_control,
    delete_detection_control,
    delete_detection_control_attachment,
    download_detection_control_attachment,
    finding_ttps,
    import_detection_controls,
    list_detection_control_attachments,
    list_detection_control_history,
    list_detection_controls,
    project_attack_review_queue,
    project_attack_technique_detail,
    project_coverage_gap_navigator_layer,
    project_coverage_gaps,
    project_governance_rollups,
    project_top_techniques,
    run_attack_navigator_layer,
    update_detection_control,
    update_finding_attack_review,
    upload_detection_control_attachment,
)
from vuln_prioritizer.api.workbench_attack_detection_routes import (
    router as attack_detection_router,
)
from vuln_prioritizer.api.workbench_config_routes import (
    diff_project_config_snapshot,
    export_project_config_snapshot,
    get_project_config,
    get_project_config_defaults,
    list_project_config_history,
    rollback_project_config_snapshot,
    save_project_config,
)
from vuln_prioritizer.api.workbench_config_routes import (
    router as config_router,
)
from vuln_prioritizer.api.workbench_import_routes import (
    explain_finding,
    get_analysis_run,
    get_finding,
    get_run_alias,
    get_run_executive_report,
    get_run_summary,
    import_findings,
    list_findings,
    list_project_runs,
    update_finding_status,
)
from vuln_prioritizer.api.workbench_import_routes import (
    router as import_router,
)
from vuln_prioritizer.api.workbench_integration_routes import (
    export_github_issues,
    export_ticket_sync,
    preview_github_issues,
    preview_ticket_sync,
)
from vuln_prioritizer.api.workbench_integration_routes import (
    router as integration_router,
)
from vuln_prioritizer.api.workbench_jobs import (
    _run_provider_update_job,
    _workbench_job_error_message,
    enqueue_workbench_job,
    execute_queued_workbench_job,
    get_workbench_job,
    job_router,
    list_workbench_jobs,
    retry_workbench_job,
    run_queued_workbench_job,
)
from vuln_prioritizer.api.workbench_project_routes import (
    create_project,
    create_project_waiver,
    delete_project_waiver,
    get_asset,
    get_project,
    list_audit_events,
    list_project_assets,
    list_project_audit_events,
    list_project_waivers,
    list_projects,
    update_asset,
    update_project_waiver,
)
from vuln_prioritizer.api.workbench_project_routes import (
    router as project_router,
)
from vuln_prioritizer.api.workbench_provider_routes import (
    create_provider_update_job,
    list_provider_update_jobs,
    provider_router,
    provider_status,
)
from vuln_prioritizer.api.workbench_route_support import (
    _api_token_hash,
    _artifact_disk_usage,
    _asset_audit_snapshot,
    _collect_config_diff,
    _config_diff_payload,
    _delete_upload_artifact,
    _directory_diagnostics,
    _patched_detection_control_values,
    _resolve_upload_artifact,
    _selected_import_files,
    _selected_import_formats,
    _ticket_sync_preview_items,
    _validate_detection_attachment_filename,
)
from vuln_prioritizer.api.workbench_system_routes import (
    API_TOKEN_PREFIX,
    create_api_token,
    diagnostics,
    health,
    list_api_tokens,
    revoke_api_token,
    version,
)
from vuln_prioritizer.api.workbench_system_routes import (
    router as system_router,
)
from vuln_prioritizer.api.workbench_uploads import (
    _resolve_attack_artifact_path,
    _resolve_provider_snapshot_path,
)
from vuln_prioritizer.services.workbench_job_runner import (
    _job_payload_list,
    _queued_job_analysis_run_id,
    _queued_job_artifact_path,
    _queued_job_optional_artifact_path,
)

api_router = APIRouter(prefix="/api")
api_router.include_router(system_router)
api_router.include_router(project_router)
api_router.include_router(import_router)
api_router.include_router(attack_detection_router)
api_router.include_router(config_router)
api_router.include_router(integration_router)
api_router.include_router(artifact_router)
api_router.include_router(job_router)
api_router.include_router(provider_router)


def _execute_queued_workbench_job(
    *,
    repo: Any,
    session: Any,
    settings: Any,
    job: Any,
) -> dict[str, Any]:
    """Legacy facade for queued job execution with the pre-split signature."""
    return execute_queued_workbench_job(
        repo=repo,
        session=session,
        settings=settings,
        job=job,
        provider_update_runner=_run_provider_update_job,
    )


__all__ = [
    "api_router",
    "API_TOKEN_PREFIX",
    "health",
    "version",
    "diagnostics",
    "create_api_token",
    "list_api_tokens",
    "revoke_api_token",
    "list_projects",
    "create_project",
    "get_project",
    "list_project_audit_events",
    "list_audit_events",
    "list_project_assets",
    "get_asset",
    "update_asset",
    "list_project_waivers",
    "create_project_waiver",
    "update_project_waiver",
    "delete_project_waiver",
    "list_project_runs",
    "import_findings",
    "get_analysis_run",
    "get_run_alias",
    "get_run_summary",
    "get_run_executive_report",
    "list_findings",
    "get_finding",
    "update_finding_status",
    "explain_finding",
    "ATTACK_REVIEW_SOURCES",
    "finding_ttps",
    "project_top_techniques",
    "project_attack_review_queue",
    "update_finding_attack_review",
    "list_detection_controls",
    "create_detection_control",
    "update_detection_control",
    "delete_detection_control",
    "list_detection_control_history",
    "list_detection_control_attachments",
    "upload_detection_control_attachment",
    "download_detection_control_attachment",
    "delete_detection_control_attachment",
    "import_detection_controls",
    "project_coverage_gaps",
    "project_coverage_gap_navigator_layer",
    "project_attack_technique_detail",
    "project_governance_rollups",
    "run_attack_navigator_layer",
    "save_project_config",
    "get_project_config",
    "list_project_config_history",
    "get_project_config_defaults",
    "export_project_config_snapshot",
    "diff_project_config_snapshot",
    "rollback_project_config_snapshot",
    "preview_github_issues",
    "export_github_issues",
    "preview_ticket_sync",
    "export_ticket_sync",
    "create_report",
    "create_evidence_bundle",
    "list_project_artifacts",
    "get_project_artifact_retention",
    "update_project_artifact_retention",
    "cleanup_project_artifact_retention",
    "download_report",
    "delete_report",
    "download_evidence_bundle",
    "delete_evidence_bundle",
    "verify_evidence_bundle_api",
    "enqueue_workbench_job",
    "get_workbench_job",
    "list_workbench_jobs",
    "retry_workbench_job",
    "run_queued_workbench_job",
    "create_provider_update_job",
    "list_provider_update_jobs",
    "provider_status",
    "_api_token_hash",
    "_selected_import_files",
    "_selected_import_formats",
    "_patched_detection_control_values",
    "_config_diff_payload",
    "_collect_config_diff",
    "_ticket_sync_preview_items",
    "_artifact_disk_usage",
    "_directory_diagnostics",
    "_asset_audit_snapshot",
    "_validate_detection_attachment_filename",
    "_resolve_upload_artifact",
    "_delete_upload_artifact",
    "_resolve_attack_artifact_path",
    "_resolve_provider_snapshot_path",
    "_execute_queued_workbench_job",
    "_job_payload_list",
    "_queued_job_analysis_run_id",
    "_queued_job_artifact_path",
    "_queued_job_optional_artifact_path",
    "_workbench_job_error_message",
]
