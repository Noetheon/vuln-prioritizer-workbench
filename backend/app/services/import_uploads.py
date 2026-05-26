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
from app.services.workbench_capabilities import (
    SIDE_CAR_UPLOAD_CAPABILITIES,
    allowed_upload_mime_hints,
    allowed_upload_suffixes,
)

ALLOWED_UPLOAD_SUFFIXES = allowed_upload_suffixes()
ALLOWED_UPLOAD_MIME_HINTS = allowed_upload_mime_hints()
SIDE_CAR_UPLOADS_BY_ID = {item.id: item for item in SIDE_CAR_UPLOAD_CAPABILITIES}


class ReadableUpload(Protocol):
    """Async readable upload-like stream used at the HTTP boundary."""

    async def read(self, size: int = -1) -> bytes:
        """Read method for ReadableUpload."""
        raise TypeError("Protocol declaration only")


async def read_bounded_upload(
    file: ReadableUpload,
    *,
    settings: Settings,
    max_bytes: int | None = None,
) -> bytes:
    """Read bounded upload function."""
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
    """Validate aggregate upload size function."""
    if sum(len(payload) for payload in payloads if payload is not None) > settings.max_upload_bytes:
        raise ImportServiceError(
            status_code=413,
            detail="Upload exceeds configured limit.",
        )


def has_optional_upload(filename: str | None) -> bool:
    """Has optional upload function."""
    return bool(filename and filename.strip())


def validate_asset_context_upload(filename: str, content_type: str | None) -> None:
    """Validate asset context upload function."""
    _validate_sidecar_upload(
        "asset-context",
        filename,
        content_type,
        extension_detail="Asset context file must be a CSV.",
        mime_detail="Asset context content type must be text/csv.",
    )


def validate_vex_upload(filename: str, content_type: str | None) -> None:
    """Validate vex upload function."""
    _validate_sidecar_upload(
        "vex",
        filename,
        content_type,
        extension_detail="VEX file must be a JSON document.",
        mime_detail="VEX content type must be application/json.",
    )


def sanitize_context_filename(filename: str, *, reserved_filename: str) -> str:
    """Sanitize context filename function."""
    sanitized = sanitize_filename(filename)
    if sanitized == reserved_filename:
        return f"asset_context_{sanitized}"
    return sanitized


def sanitize_vex_filename(
    filename: str,
    *,
    reserved_filenames: set[str | None],
) -> str:
    """Sanitize vex filename function."""
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
    """Optional upload summary function."""
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
    """Upload summary with path function."""
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
    """Store upload function."""
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
    """Upload summary function."""
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
    """Ignored line count function."""
    if input_type not in {"cve-list", "generic-occurrence-csv"}:
        return 0
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    return sum(1 for line in text.splitlines() if _is_ignored_text_line(line))


def validate_input_type(input_type: str) -> None:
    """Validate input type function."""
    try:
        build_importer_registry().get(input_type)
    except UnsupportedInputTypeError as exc:
        raise ImportServiceError(status_code=422, detail=str(exc)) from exc


def validate_upload_suffix(filename: str, *, input_type: str) -> None:
    """Validate upload suffix function."""
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES.get(input_type, set()):
        raise ImportServiceError(
            status_code=422,
            detail="File extension does not match input type.",
        )


def validate_mime_hint(content_type: str | None, *, input_type: str) -> None:
    """Validate mime hint function."""
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in ALLOWED_UPLOAD_MIME_HINTS.get(input_type, set()):
        raise ImportServiceError(
            status_code=422, detail="Upload content type does not match input type."
        )


def reject_unsafe_upload_filename(filename: str) -> None:
    """Reject unsafe upload filename function."""
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise ImportServiceError(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise ImportServiceError(status_code=422, detail="Upload filename is not allowed.")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename function."""
    name = Path(filename).name.strip() or "upload"
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return sanitized or "upload"


def normalize_input_type(input_type: str) -> str:
    """Normalize input type function."""
    normalized = input_type.strip().lower()
    if not normalized:
        raise ImportServiceError(status_code=422, detail="input_type is required.")
    return normalized


def _validate_sidecar_upload(
    capability_id: str,
    filename: str,
    content_type: str | None,
    *,
    extension_detail: str,
    mime_detail: str,
) -> None:
    capability = SIDE_CAR_UPLOADS_BY_ID[capability_id]
    if Path(filename).suffix.lower() not in set(capability.extensions):
        raise ImportServiceError(status_code=422, detail=extension_detail)
    normalized = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in set(capability.accepted_mime_types):
        raise ImportServiceError(status_code=422, detail=mime_detail)


def _is_ignored_text_line(line: str) -> bool:
    """Is ignored text line function."""
    stripped = line.strip()
    return not stripped or stripped.startswith("#")
