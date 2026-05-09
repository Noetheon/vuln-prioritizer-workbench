"""Deterministic evidence bundle archive helpers."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from app.services.report_contracts import (
    DETERMINISTIC_ZIP_FILE_MODE,
    DETERMINISTIC_ZIP_TIMESTAMP,
)
from app.services.report_formatting import dict_value as _dict_value
from app.services.report_models import MarkdownReportPayload


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _bundle_file_entry(*, path: str, content: bytes, kind: str) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _bundle_input_hashes(payload: MarkdownReportPayload) -> list[dict[str, Any]]:
    upload = _dict_value(payload.summary.get("input_upload"))
    input_sha256 = upload.get("sha256") or payload.summary.get("input_sha256")
    if not isinstance(input_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", input_sha256):
        return []
    filename = (
        upload.get("stored_filename")
        or upload.get("original_filename")
        or payload.filename
        or "uploaded-input"
    )
    size_bytes = upload.get("size_bytes")
    return [
        {
            "path": _safe_bundle_filename(filename),
            "size_bytes": int(size_bytes) if isinstance(size_bytes, int | float) else 0,
            "sha256": input_sha256,
        }
    ]


def _safe_bundle_filename(value: object) -> str:
    filename = Path(str(value)).name.strip() if value is not None else ""
    return filename or "uploaded-input"


def _write_deterministic_zip_member(
    archive: zipfile.ZipFile,
    path: str,
    content: bytes,
) -> None:
    info = zipfile.ZipInfo(filename=path, date_time=DETERMINISTIC_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = DETERMINISTIC_ZIP_FILE_MODE
    archive.writestr(info, content)


__all__ = [
    "_bundle_file_entry",
    "_bundle_input_hashes",
    "_json_bytes",
    "_safe_bundle_filename",
    "_write_deterministic_zip_member",
]
