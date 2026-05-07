"""Upload validation and storage helpers for Workbench imports."""

from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Protocol

from app.core.config import Settings
from app.importers import UnsupportedInputTypeError, build_importer_registry
from app.services.import_errors import ImportServiceError

ALLOWED_UPLOAD_SUFFIXES = {
    "cve-list": {".txt", ".csv"},
    "generic-occurrence-csv": {".csv"},
    "trivy-json": {".json"},
    "grype-json": {".json"},
    "cyclonedx-json": {".json"},
    "spdx-json": {".json"},
    "dependency-check-json": {".json"},
    "github-alerts-json": {".json"},
    "nessus-xml": {".nessus", ".xml"},
    "openvas-xml": {".xml"},
}
ALLOWED_UPLOAD_MIME_HINTS = {
    "cve-list": {"text/plain", "text/csv", "application/vnd.ms-excel"},
    "generic-occurrence-csv": {"text/csv", "text/plain", "application/vnd.ms-excel"},
    "trivy-json": {"application/json", "text/json"},
    "grype-json": {"application/json", "text/json"},
    "cyclonedx-json": {"application/json", "text/json"},
    "spdx-json": {"application/json", "text/json"},
    "dependency-check-json": {"application/json", "text/json"},
    "github-alerts-json": {"application/json", "text/json"},
    "nessus-xml": {"application/xml", "text/xml"},
    "openvas-xml": {"application/xml", "text/xml"},
}


class ReadableUpload(Protocol):
    """Async readable upload-like stream used at the HTTP boundary."""

    async def read(self, size: int = -1) -> bytes:
        raise NotImplementedError


async def read_bounded_upload(
    file: ReadableUpload,
    *,
    settings: Settings,
    max_bytes: int | None = None,
) -> bytes:
    limit = (
        settings.max_upload_bytes
        if max_bytes is None
        else min(settings.max_upload_bytes, max_bytes)
    )
    total = 0
    chunks: list[bytes] = []
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise ImportServiceError(
                status_code=413,
                detail="Upload exceeds configured limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def validate_aggregate_upload_size(
    *,
    settings: Settings,
    payloads: list[bytes | None],
) -> None:
    if sum(len(payload) for payload in payloads if payload is not None) > settings.max_upload_bytes:
        raise ImportServiceError(
            status_code=413,
            detail="Upload exceeds configured limit.",
        )


def has_optional_upload(filename: str | None) -> bool:
    return bool(filename and filename.strip())


def validate_asset_context_upload(filename: str, content_type: str | None) -> None:
    if Path(filename).suffix.lower() != ".csv":
        raise ImportServiceError(status_code=422, detail="Asset context file must be a CSV.")
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in {"text/csv", "text/plain", "application/vnd.ms-excel"}:
        raise ImportServiceError(
            status_code=422,
            detail="Asset context content type must be text/csv.",
        )


def validate_vex_upload(filename: str, content_type: str | None) -> None:
    if Path(filename).suffix.lower() != ".json":
        raise ImportServiceError(status_code=422, detail="VEX file must be a JSON document.")
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in {"application/json", "text/json"}:
        raise ImportServiceError(
            status_code=422,
            detail="VEX content type must be application/json.",
        )


def sanitize_context_filename(filename: str, *, reserved_filename: str) -> str:
    sanitized = sanitize_filename(filename)
    if sanitized == reserved_filename:
        return f"asset_context_{sanitized}"
    return sanitized


def sanitize_vex_filename(
    filename: str,
    *,
    reserved_filenames: set[str | None],
) -> str:
    sanitized = sanitize_filename(filename)
    if sanitized in {value for value in reserved_filenames if value}:
        return f"vex_{sanitized}"
    return sanitized


def optional_upload_summary(
    *,
    input_type: str,
    original_filename: str | None,
    stored_filename: str | None,
    content_type: str | None,
    size_bytes: int | None,
    sha256: str | None,
    path: str | None,
) -> dict[str, Any] | None:
    if original_filename is None or stored_filename is None or size_bytes is None or sha256 is None:
        return None
    return upload_summary(
        input_type=input_type,
        original_filename=original_filename,
        stored_filename=stored_filename,
        content_type=content_type,
        size_bytes=size_bytes,
        sha256=sha256,
        path=path,
    )


def upload_summary_with_path(value: Any, *, path: str | None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {**value, "path": path, "storage_ref": path}


def upload_storage_ref(
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    filename: str,
) -> str:
    """Return the public managed upload reference without exposing server roots."""
    return f"{project_id}/{run_id}/{sanitize_filename(filename)}"


def store_upload(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    filename: str,
    content: bytes,
) -> Path:
    upload_root = settings.import_upload_dir_path.resolve(strict=False)
    target_dir = upload_root / str(project_id) / str(run_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = (target_dir / filename).resolve(strict=False)
    if not target_path.is_relative_to(upload_root):
        raise ImportServiceError(status_code=422, detail="Upload path is not allowed.")
    try:
        with target_path.open("wb") as output:
            output.write(content)
    except Exception:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise
    return target_path


def upload_summary(
    *,
    input_type: str,
    original_filename: str,
    stored_filename: str,
    content_type: str | None,
    size_bytes: int,
    sha256: str,
    path: str | None,
) -> dict[str, Any]:
    return {
        "input_type": input_type,
        "original_filename": original_filename,
        "stored_filename": stored_filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "path": path,
        "storage_ref": path,
    }


def sanitize_parser_error_message(message: str) -> str:
    """Remove local filesystem paths from parser-facing error text."""
    unix_path = r"(?:/(?:Users|home|private|tmp|var|Volumes)/[^\s`'\"<>:;,)]*)"
    windows_path = r"(?:[A-Za-z]:\\[^\s`'\"<>:;,)]*)"
    return re.sub(f"{unix_path}|{windows_path}", "uploaded file", message)


def ignored_line_count(input_type: str, payload: bytes) -> int:
    if input_type not in {"cve-list", "generic-occurrence-csv"}:
        return 0
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    return sum(1 for line in text.splitlines() if _is_ignored_text_line(line))


def validate_input_type(input_type: str) -> None:
    try:
        build_importer_registry().get(input_type)
    except UnsupportedInputTypeError as exc:
        raise ImportServiceError(status_code=422, detail=str(exc)) from exc


def validate_upload_suffix(filename: str, *, input_type: str) -> None:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES.get(input_type, set()):
        raise ImportServiceError(
            status_code=422,
            detail="File extension does not match input type.",
        )


def validate_mime_hint(content_type: str | None, *, input_type: str) -> None:
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in ALLOWED_UPLOAD_MIME_HINTS.get(input_type, set()):
        raise ImportServiceError(
            status_code=422, detail="Upload content type does not match input type."
        )


def reject_unsafe_upload_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise ImportServiceError(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise ImportServiceError(status_code=422, detail="Upload filename is not allowed.")


def sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip() or "upload"
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return sanitized or "upload"


def normalize_input_type(input_type: str) -> str:
    normalized = input_type.strip().lower()
    if not normalized:
        raise ImportServiceError(status_code=422, detail="input_type is required.")
    return normalized


def _is_ignored_text_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")
