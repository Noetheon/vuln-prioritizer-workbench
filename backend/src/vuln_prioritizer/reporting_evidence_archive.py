"""Archive and file helpers for CLI evidence bundles."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from vuln_prioritizer.models import EvidenceBundleFile
from vuln_prioritizer.security_redaction import redact_text, redact_value

DETERMINISTIC_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
DETERMINISTIC_ZIP_FILE_MODE = 0o644 << 16


def redacted_file_bytes(path: Path) -> tuple[bytes, bool]:
    """Return file bytes with text secrets redacted when content is UTF-8 or JSON."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw, False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        redacted_text = redact_text(text)
        return redacted_text.encode("utf-8"), redacted_text != text
    redacted_payload, redaction_paths = redact_value(payload)
    redacted_text = json.dumps(redacted_payload, indent=2, sort_keys=True)
    return redacted_text.encode("utf-8"), bool(redaction_paths)


def write_deterministic_zip_member(
    archive: zipfile.ZipFile,
    path: str,
    content: bytes,
) -> None:
    info = zipfile.ZipInfo(filename=path, date_time=DETERMINISTIC_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = DETERMINISTIC_ZIP_FILE_MODE
    archive.writestr(info, content)


def bundle_file_entry(*, path: str, content: bytes, kind: str) -> EvidenceBundleFile:
    return EvidenceBundleFile(
        path=path,
        kind=kind,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


__all__ = [
    "DETERMINISTIC_ZIP_FILE_MODE",
    "DETERMINISTIC_ZIP_TIMESTAMP",
    "bundle_file_entry",
    "redacted_file_bytes",
    "write_deterministic_zip_member",
]
