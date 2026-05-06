from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

from app.core.config import Settings
from app.models import Report
from app.services.report_artifacts import (
    ReportArtifactChecksumError,
    ReportArtifactNotFoundError,
    build_report_public,
    validated_report_path,
)


def test_report_artifact_public_dto_redacts_server_path_and_secret_metadata(
    tmp_path: Path,
) -> None:
    settings = Settings(REPORT_DIR=str(tmp_path))
    artifact = tmp_path / "report.md"
    artifact.write_text("report", encoding="utf-8")
    report = _report(artifact, metadata_json={"token": "secret", "count": 2})

    public = build_report_public(report, settings)

    assert public.download_url == f"/api/v1/reports/{report.id}/download"
    assert "path" not in public.model_dump()
    assert public.metadata_json["token"] == "[REDACTED]"
    assert public.metadata_json["count"] == 2


def test_report_artifact_validation_rejects_outside_root_and_checksum_mismatch(
    tmp_path: Path,
) -> None:
    settings = Settings(REPORT_DIR=str(tmp_path / "reports"))
    outside = tmp_path / "outside.md"
    outside.write_text("report", encoding="utf-8")

    with pytest.raises(ReportArtifactNotFoundError):
        validated_report_path(_report(outside), settings)

    inside = tmp_path / "reports" / "report.md"
    inside.parent.mkdir()
    inside.write_text("changed", encoding="utf-8")
    report = _report(inside, sha256="0" * 64)

    with pytest.raises(ReportArtifactChecksumError):
        validated_report_path(report, settings)


def test_report_artifact_validation_returns_existing_rooted_file(tmp_path: Path) -> None:
    settings = Settings(REPORT_DIR=str(tmp_path))
    artifact = tmp_path / "report.md"
    artifact.write_text("report", encoding="utf-8")

    assert validated_report_path(_report(artifact), settings) == artifact.resolve()


def _report(
    path: Path,
    *,
    metadata_json: dict[str, object] | None = None,
    sha256: str | None = None,
) -> Report:
    content = path.read_bytes() if path.exists() else b""
    return Report(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        analysis_run_id=uuid.uuid4(),
        kind="technical-markdown",
        format="markdown",
        filename=path.name,
        content_type="text/markdown; charset=utf-8",
        sha256=sha256 or hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        metadata_json=metadata_json or {},
        path=str(path),
    )
