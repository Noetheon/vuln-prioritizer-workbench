"""Upload and artifact helpers for Workbench API and web routes."""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from fastapi import HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from vuln_prioritizer.services.workbench_analysis import SUPPORTED_WORKBENCH_INPUT_FORMATS
from vuln_prioritizer.workbench_config import WorkbenchSettings

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
ALLOWED_CONTEXT_UPLOAD_SUFFIXES = {
    "asset-context": {".csv"},
    "vex": {".json"},
    "waiver": {".yml", ".yaml"},
    "defensive-context": {".json"},
}
SAFE_SNAPSHOT_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*[.]json$")
SAFE_ATTACK_FILENAME_RE = SAFE_SNAPSHOT_FILENAME_RE


async def _read_bounded_upload(file: UploadFile, *, settings: WorkbenchSettings) -> bytes:
    total = 0
    chunks: list[bytes] = []
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
        chunks.append(chunk)
    return b"".join(chunks)


async def _save_upload(
    file: UploadFile,
    *,
    input_format: str,
    settings: WorkbenchSettings,
) -> Path:
    if input_format not in SUPPORTED_WORKBENCH_INPUT_FORMATS:
        raise HTTPException(status_code=422, detail="Unsupported Workbench input format.")
    original_filename = file.filename or "upload"
    _reject_unsafe_upload_filename(original_filename)
    sanitized = _sanitize_filename(original_filename)
    suffix = Path(sanitized).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES[input_format]:
        raise HTTPException(status_code=422, detail="File extension does not match input format.")

    target_dir = settings.upload_dir / uuid4().hex
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitized
    total = 0
    with target_path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
            output.write(chunk)
    return target_path


async def _save_optional_context_upload(
    file: UploadFile | None,
    *,
    kind: str,
    settings: WorkbenchSettings,
) -> Path | None:
    if file is None or not file.filename:
        return None
    try:
        allowed_suffixes = ALLOWED_CONTEXT_UPLOAD_SUFFIXES[kind]
    except KeyError as exc:
        raise HTTPException(status_code=422, detail="Unsupported context upload kind.") from exc

    _reject_unsafe_upload_filename(file.filename)
    sanitized = _sanitize_filename(file.filename)
    suffix = Path(sanitized).suffix.lower()
    if suffix not in allowed_suffixes:
        raise HTTPException(status_code=422, detail=f"{kind} file extension is not allowed.")

    target_dir = settings.upload_dir / uuid4().hex / "context"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / sanitized
    total = 0
    with target_path.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                shutil.rmtree(target_dir.parent, ignore_errors=True)
                raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
            output.write(chunk)
    return target_path


def _sanitize_filename(filename: str) -> str:
    name = Path(filename).name.strip() or "upload"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _reject_unsafe_upload_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")


def _artifact_response(path: Path, *, media_type: str) -> StreamingResponse:
    filename = _sanitize_filename(path.name)
    return StreamingResponse(
        _iter_file(path),
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


def _iter_file(path: Path) -> Iterator[bytes]:
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            yield chunk


def _resolve_download_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
    missing_detail: str,
) -> Path:
    resolved = Path(value).resolve(strict=False)
    report_root = settings.report_dir.resolve(strict=False)
    if not resolved.is_relative_to(report_root) or not resolved.is_file():
        raise HTTPException(status_code=404, detail=missing_detail)
    actual_sha256 = _sha256_file(resolved)
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Artifact checksum mismatch.")
    return resolved


def _delete_download_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
) -> bool:
    resolved = Path(value).resolve(strict=False)
    report_root = settings.report_dir.resolve(strict=False)
    if not resolved.is_relative_to(report_root):
        raise HTTPException(status_code=422, detail="Artifact path is outside the report root.")
    if not resolved.is_file():
        return False
    actual_sha256 = _sha256_file(resolved)
    if actual_sha256 != expected_sha256:
        raise HTTPException(status_code=409, detail="Artifact checksum mismatch.")
    resolved.unlink()
    return True


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _cleanup_saved_uploads(*paths: Path | None) -> None:
    for path in paths:
        if path is None:
            continue
        root = path.parent.parent if path.parent.name == "context" else path.parent
        shutil.rmtree(root, ignore_errors=True)


def _resolve_provider_snapshot_path(
    value: str | None,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or not value.strip():
        return None

    filename = value.strip()
    if (
        not SAFE_SNAPSHOT_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise HTTPException(status_code=422, detail="Provider snapshot path is not allowed.")

    allowed_roots = (
        settings.provider_snapshot_dir.resolve(strict=False),
        settings.provider_cache_dir.resolve(strict=False),
    )
    for root in allowed_roots:
        resolved = _resolve_allowed_root_file(root, filename)
        if resolved is not None:
            return resolved

    raise HTTPException(status_code=422, detail="Provider snapshot file does not exist.")


def _resolve_attack_artifact_path(
    value: str | None,
    *,
    settings: WorkbenchSettings,
) -> Path | None:
    if value is None or not value.strip():
        return None

    filename = value.strip()
    if (
        not SAFE_ATTACK_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise HTTPException(status_code=422, detail="ATT&CK artifact path is not allowed.")

    root = settings.attack_artifact_dir.resolve(strict=False)
    resolved = _resolve_allowed_root_file(root, filename)
    if resolved is not None:
        return resolved

    raise HTTPException(status_code=422, detail="ATT&CK artifact file does not exist.")


def _resolve_allowed_root_file(root: Path, filename: str) -> Path | None:
    if not root.is_dir():
        return None
    candidate = root / filename
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root.resolve(strict=True)):
        return None
    return resolved
