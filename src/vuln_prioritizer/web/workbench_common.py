"""Shared Workbench web route helpers."""

from __future__ import annotations

# ruff: noqa: F401, I001

import hashlib
import json
import secrets
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import ProviderSourceName, ProviderUpdateJobRequest, WaiverRequest
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.api.workbench_payloads import (
    _attack_review_queue_item_payload,
    _detection_control_attachment_payload,
)
from vuln_prioritizer.api.workbench_support import (
    _cleanup_saved_uploads,
    _count_matching_waiver_findings,
    _coverage_gap_payload,
    _create_provider_update_job_record,
    _detection_control_payload,
    _parse_detection_control_rows,
    _provider_status_payload,
    _provider_update_job_payload,
    _read_bounded_upload,
    _resolve_attack_artifact_path,
    _resolve_provider_snapshot_path,
    _save_optional_context_upload,
    _save_upload,
    _sort_findings,
    _sync_project_waivers,
    _technique_metadata_from_contexts,
    _validated_waiver_values,
    _waiver_payload,
)
from vuln_prioritizer.attack_sources import ATTACK_SOURCE_NONE, WORKBENCH_ALLOWED_MAPPING_SOURCES
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.reporting_executive import render_executive_report_html
from vuln_prioritizer.runtime_config import RuntimeConfigDocument
from vuln_prioritizer.services.workbench_analysis import (
    WorkbenchAnalysisError,
    run_workbench_import,
)
from vuln_prioritizer.services.workbench_artifacts import cleanup_project_artifacts
from vuln_prioritizer.services.workbench_executive_report import (
    WorkbenchExecutiveReportError,
    build_run_executive_report_model,
)
from vuln_prioritizer.services.workbench_governance import build_governance_summary
from vuln_prioritizer.services.workbench_jobs import run_sync_workbench_job
from vuln_prioritizer.services.workbench_reports import (
    ReportFormat,
    WorkbenchReportError,
    create_run_evidence_bundle,
    create_run_report,
    verify_run_evidence_bundle,
)
from vuln_prioritizer.web.view_models import dashboard_model, findings_model, reports_model
from vuln_prioritizer.workbench_config import WorkbenchSettings

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
WEB_API_TOKEN_PREFIX = "vpr_"
ATTACK_REVIEW_SOURCES = set(WORKBENCH_ALLOWED_MAPPING_SOURCES) | {ATTACK_SOURCE_NONE}
ATTACK_REVIEW_STATUSES = {
    "unreviewed",
    "needs_review",
    "source_reviewed",
    "reviewed",
    "rejected",
    "not_applicable",
}

_PROJECT_CHILD_ROUTES = frozenset(
    {
        "assets",
        "coverage",
        "dashboard",
        "findings",
        "governance",
        "imports/new",
        "settings",
        "vulnerabilities",
        "waivers",
    }
)


def _check_csrf(submitted: str, settings: WorkbenchSettings) -> None:
    if not secrets.compare_digest(submitted, settings.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def _project_path(project_id: str, child: str) -> str:
    if child not in _PROJECT_CHILD_ROUTES:
        raise HTTPException(status_code=404, detail="Project route not found.")
    return f"/projects/{_safe_project_path_value(project_id)}/{child}"


def _project_nav_context(
    repo: WorkbenchRepository,
    project: Any,
    context: dict[str, Any],
) -> dict[str, Any]:
    if "latest_run" not in context:
        runs = repo.list_analysis_runs(project.id)
        context["latest_run"] = runs[0] if runs else None
    return context


def _safe_project_path_value(value: str) -> str:
    try:
        return UUID(value).hex
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Project not found.") from exc


def _optional_bool_filter(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise HTTPException(status_code=422, detail="Invalid boolean filter.")


def _optional_float_filter(
    value: str | None,
    *,
    lower: float,
    upper: float,
    label: str,
) -> float | None:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label} filter.") from exc
    if parsed < lower or parsed > upper:
        raise HTTPException(status_code=422, detail=f"Invalid {label} filter.")
    return parsed


def _redacted_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "<set>"


def _safe_uuid_path_value(value: str) -> str:
    try:
        return UUID(value).hex
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Analysis run not found.") from exc


def _redacted_env_value(name: str) -> str:
    import os

    if os.getenv(name):
        return "<set>"
    return "<not set>"


def _runtime_config_from_text(config_text: str) -> RuntimeConfigDocument:
    try:
        raw = yaml.safe_load(config_text) if config_text.strip() else {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid config YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Project config must be a JSON/YAML object.")
    try:
        return RuntimeConfigDocument.model_validate(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid project config: {exc}") from exc


def _optional_positive_int(value: str, label: str) -> int | None:
    if not value.strip():
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{label} must be a number.") from exc
    if parsed <= 0:
        raise HTTPException(status_code=422, detail=f"{label} must be positive.")
    return parsed


def _csv_form_values(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


def _asset_audit_snapshot(asset: Any) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
    }


def _validate_detection_attachment_filename(filename: str) -> None:
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise HTTPException(status_code=422, detail="Invalid attachment filename.")
    if Path(filename).suffix.lower() not in {
        ".txt",
        ".md",
        ".json",
        ".csv",
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
    }:
        raise HTTPException(status_code=422, detail="Unsupported attachment file type.")


def _web_config_diff(*, base: Any | None, target: Any) -> dict[str, Any]:
    before = base.config_json if base is not None and isinstance(base.config_json, dict) else {}
    after = target.config_json if isinstance(target.config_json, dict) else {}
    changed: dict[str, dict[str, Any]] = {}
    _web_collect_config_diff(before=before, after=after, prefix="", changed=changed)
    return {
        "base": base,
        "target": target,
        "changed": changed,
    }


def _web_collect_config_diff(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str,
    changed: dict[str, dict[str, Any]],
) -> None:
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in before:
            changed[path] = {"before": None, "after": after[key]}
        elif key not in after:
            changed[path] = {"before": before[key], "after": None}
        elif isinstance(before[key], dict) and isinstance(after[key], dict):
            _web_collect_config_diff(
                before=before[key],
                after=after[key],
                prefix=path,
                changed=changed,
            )
        elif before[key] != after[key]:
            changed[path] = {"before": before[key], "after": after[key]}


def _selected_import_files(
    *,
    file: UploadFile | None,
    files: list[UploadFile] | None,
) -> list[UploadFile]:
    selected = [item for item in (files or []) if item.filename]
    if file is not None and file.filename:
        selected.insert(0, file)
    if not selected:
        raise HTTPException(status_code=422, detail="At least one import file is required.")
    return selected


__all__ = [
    "ATTACK_REVIEW_SOURCES",
    "ATTACK_REVIEW_STATUSES",
    "Annotated",
    "Any",
    "Depends",
    "File",
    "Form",
    "HTMLResponse",
    "HTTPException",
    "Path",
    "ProviderSourceName",
    "ProviderUpdateJobRequest",
    "Query",
    "RedirectResponse",
    "ReportFormat",
    "Request",
    "Response",
    "RuntimeConfigDocument",
    "Session",
    "TEMPLATE_DIR",
    "UploadFile",
    "WEB_API_TOKEN_PREFIX",
    "WaiverRequest",
    "WorkbenchAnalysisError",
    "WorkbenchExecutiveReportError",
    "WorkbenchReportError",
    "WorkbenchRepository",
    "WorkbenchSettings",
    "_asset_audit_snapshot",
    "_attack_review_queue_item_payload",
    "_check_csrf",
    "_cleanup_saved_uploads",
    "_count_matching_waiver_findings",
    "_coverage_gap_payload",
    "_create_provider_update_job_record",
    "_csv_form_values",
    "_detection_control_attachment_payload",
    "_detection_control_payload",
    "_optional_bool_filter",
    "_optional_float_filter",
    "_optional_positive_int",
    "_parse_detection_control_rows",
    "_project_nav_context",
    "_project_path",
    "_provider_status_payload",
    "_provider_update_job_payload",
    "_read_bounded_upload",
    "_redacted_database_url",
    "_redacted_env_value",
    "_resolve_attack_artifact_path",
    "_resolve_provider_snapshot_path",
    "_runtime_config_from_text",
    "_safe_uuid_path_value",
    "_save_optional_context_upload",
    "_save_upload",
    "_selected_import_files",
    "_sort_findings",
    "_sync_project_waivers",
    "_technique_metadata_from_contexts",
    "_validated_waiver_values",
    "_validate_detection_attachment_filename",
    "_waiver_payload",
    "_web_config_diff",
    "api_token_digest",
    "build_governance_summary",
    "build_run_executive_report_model",
    "cast",
    "cleanup_project_artifacts",
    "create_run_evidence_bundle",
    "create_run_report",
    "dashboard_model",
    "findings_model",
    "get_db_session",
    "get_workbench_settings",
    "hashlib",
    "json",
    "render_executive_report_html",
    "reports_model",
    "run_sync_workbench_job",
    "run_workbench_import",
    "secrets",
    "templates",
    "verify_run_evidence_bundle",
]
