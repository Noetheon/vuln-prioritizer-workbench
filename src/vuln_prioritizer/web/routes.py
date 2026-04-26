"""Server-rendered Workbench route facade."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.templating import Jinja2Templates

from vuln_prioritizer.web.workbench_common import (
    ATTACK_REVIEW_SOURCES,
    ATTACK_REVIEW_STATUSES,
    TEMPLATE_DIR,
    WEB_API_TOKEN_PREFIX,
    _asset_audit_snapshot,
    _check_csrf,
    _csv_form_values,
    _optional_bool_filter,
    _optional_float_filter,
    _optional_positive_int,
    _project_nav_context,
    _project_path,
    _redacted_database_url,
    _redacted_env_value,
    _runtime_config_from_text,
    _safe_project_path_value,
    _safe_uuid_path_value,
    _selected_import_files,
    _validate_detection_attachment_filename,
    _web_collect_config_diff,
    _web_config_diff,
)
from vuln_prioritizer.web.workbench_governance import (
    assets_page,
    coverage_page,
    create_waiver_form,
    delete_waiver_form,
    finding_detail,
    governance,
    import_detection_controls_form,
    technique_detail_page,
    update_asset_form,
    update_attack_review_form,
    update_detection_control_form,
    update_finding_status_form,
    update_waiver_form,
    upload_detection_control_attachment_form,
    waivers_page,
)
from vuln_prioritizer.web.workbench_governance import router as governance_router
from vuln_prioritizer.web.workbench_projects import (
    create_import_form,
    create_project_form,
    dashboard,
    favicon,
    findings,
    index,
    new_import,
    new_project,
    vulnerability_lookup,
)
from vuln_prioritizer.web.workbench_projects import router as projects_router
from vuln_prioritizer.web.workbench_reports import (
    create_evidence_form,
    create_report_form,
    run_executive_report,
    run_reports,
    verify_evidence_page,
)
from vuln_prioritizer.web.workbench_reports import router as reports_router
from vuln_prioritizer.web.workbench_settings import (
    cleanup_artifacts_form,
    create_api_token_form,
    create_provider_update_job_form,
    export_project_config_form,
    project_settings,
    revoke_api_token_form,
    rollback_project_config_form,
    save_project_config_form,
    update_artifact_retention_form,
)
from vuln_prioritizer.web.workbench_settings import router as settings_router

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
web_router = APIRouter()
web_router.include_router(projects_router)
web_router.include_router(governance_router)
web_router.include_router(settings_router)
web_router.include_router(reports_router)

__all__ = [
    "ATTACK_REVIEW_SOURCES",
    "ATTACK_REVIEW_STATUSES",
    "WEB_API_TOKEN_PREFIX",
    "_asset_audit_snapshot",
    "_check_csrf",
    "_csv_form_values",
    "_optional_bool_filter",
    "_optional_float_filter",
    "_optional_positive_int",
    "_project_nav_context",
    "_project_path",
    "_redacted_database_url",
    "_redacted_env_value",
    "_runtime_config_from_text",
    "_safe_project_path_value",
    "_safe_uuid_path_value",
    "_selected_import_files",
    "_validate_detection_attachment_filename",
    "_web_collect_config_diff",
    "_web_config_diff",
    "assets_page",
    "cleanup_artifacts_form",
    "coverage_page",
    "create_api_token_form",
    "create_evidence_form",
    "create_import_form",
    "create_project_form",
    "create_provider_update_job_form",
    "create_report_form",
    "create_waiver_form",
    "dashboard",
    "delete_waiver_form",
    "export_project_config_form",
    "favicon",
    "finding_detail",
    "findings",
    "governance",
    "import_detection_controls_form",
    "index",
    "new_import",
    "new_project",
    "project_settings",
    "revoke_api_token_form",
    "rollback_project_config_form",
    "run_executive_report",
    "run_reports",
    "save_project_config_form",
    "technique_detail_page",
    "templates",
    "update_artifact_retention_form",
    "update_asset_form",
    "update_attack_review_form",
    "update_detection_control_form",
    "update_finding_status_form",
    "update_waiver_form",
    "upload_detection_control_attachment_form",
    "verify_evidence_page",
    "vulnerability_lookup",
    "waivers_page",
    "web_router",
]
