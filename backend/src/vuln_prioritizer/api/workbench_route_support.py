"""Shared helpers for Workbench API route modules."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi import HTTPException, UploadFile

from vuln_prioritizer.api.schemas import (
    DetectionControlPatchRequest,
    TicketSyncPreviewRequest,
)
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.api.workbench_detection import (
    _detection_control_values,
)
from vuln_prioritizer.api.workbench_findings import _filter_findings, _sort_findings
from vuln_prioritizer.api.workbench_tickets import (
    _ticket_preview_payload,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.workbench_config import WorkbenchSettings


def _api_token_hash(token_value: str) -> str:
    return api_token_digest(token_value)


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


def _selected_import_formats(
    *,
    input_format: str,
    input_formats: list[str] | None,
    file_count: int,
) -> list[str]:
    selected = [item for item in (input_formats or []) if item]
    if not selected:
        selected = [input_format]
    if len(selected) == 1 and file_count > 1:
        return selected * file_count
    if len(selected) != file_count:
        raise HTTPException(
            status_code=422,
            detail="input_formats must contain one format per uploaded file.",
        )
    return selected


def _patched_detection_control_values(
    control: Any,
    payload: DetectionControlPatchRequest,
) -> dict[str, Any]:
    values = {
        "control_id": control.control_id,
        "name": control.name,
        "technique_id": control.technique_id,
        "technique_name": control.technique_name,
        "source_type": control.source_type,
        "coverage_level": control.coverage_level,
        "environment": control.environment,
        "owner": control.owner,
        "evidence_ref": control.evidence_ref,
        "evidence_refs": list(control.evidence_refs_json or []),
        "review_status": control.review_status,
        "notes": control.notes,
        "last_verified_at": control.last_verified_at,
    }
    for field_name in payload.model_fields_set:
        values[field_name] = getattr(payload, field_name)
    return _detection_control_values(values, index=1)


def _config_diff_payload(*, base: Any | None, target: Any) -> dict[str, Any]:
    before = base.config_json if base is not None and isinstance(base.config_json, dict) else {}
    after = target.config_json if isinstance(target.config_json, dict) else {}
    added: dict[str, Any] = {}
    removed: dict[str, Any] = {}
    changed: dict[str, dict[str, Any]] = {}
    _collect_config_diff(
        before=before,
        after=after,
        prefix="",
        added=added,
        removed=removed,
        changed=changed,
    )
    return {
        "base_id": base.id if base is not None else None,
        "target_id": target.id,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _collect_config_diff(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str,
    added: dict[str, Any],
    removed: dict[str, Any],
    changed: dict[str, dict[str, Any]],
) -> None:
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in before:
            added[path] = after[key]
        elif key not in after:
            removed[path] = before[key]
        elif isinstance(before[key], dict) and isinstance(after[key], dict):
            _collect_config_diff(
                before=before[key],
                after=after[key],
                prefix=path,
                added=added,
                removed=removed,
                changed=changed,
            )
        elif before[key] != after[key]:
            changed[path] = {"before": before[key], "after": after[key]}


def _ticket_sync_preview_items(
    repo: WorkbenchRepository,
    project_id: str,
    payload: TicketSyncPreviewRequest,
) -> list[dict[str, Any]]:
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    preview_items: list[dict[str, Any]] = []
    duplicate_keys: set[str] = set()
    for finding in findings:
        item = _ticket_preview_payload(finding, payload=payload)
        if item["duplicate_key"] in duplicate_keys:
            continue
        duplicate_keys.add(item["duplicate_key"])
        preview_items.append(item)
        if len(preview_items) >= payload.limit:
            break
    return preview_items


def _artifact_disk_usage(paths: list[str]) -> int:
    total = 0
    for raw_path in paths:
        path = Path(raw_path)
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def _directory_diagnostics(path: Path) -> dict[str, Any]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".vuln-prioritizer-write-check"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        writable = True
    except OSError:
        writable = False
    return {
        "path": str(path),
        "exists": path.exists(),
        "writable": writable,
    }


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


def _resolve_upload_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
    missing_detail: str,
) -> Path:
    resolved = Path(value).resolve(strict=False)
    upload_root = settings.upload_dir.resolve(strict=False)
    if not resolved.is_relative_to(upload_root) or not resolved.is_file():
        raise HTTPException(status_code=404, detail=missing_detail)
    actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Attachment checksum mismatch.")
    return resolved


def _delete_upload_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
) -> bool:
    resolved = Path(value).resolve(strict=False)
    upload_root = settings.upload_dir.resolve(strict=False)
    if not resolved.is_relative_to(upload_root):
        raise HTTPException(status_code=422, detail="Attachment path is outside the upload root.")
    if not resolved.is_file():
        return False
    actual_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Attachment checksum mismatch.")
    resolved.unlink()
    return True
