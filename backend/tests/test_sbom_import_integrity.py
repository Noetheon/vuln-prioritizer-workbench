from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.contracts.sbom import SbomAssessmentV1
from app.core.config import Settings
from app.importers import ImporterParseError
from app.services import sbom_import
from app.services.import_execution_types import ImportUploadContent, ProjectImportUploadRequest
from app.services.import_execution_upload_prepare import prepare_import_upload
from app.services.import_execution_upload_storage import store_prepared_uploads
from app.services.sbom_scanner import SbomScannerResult


def _prepared(tmp_path):
    settings = Settings(IMPORT_UPLOAD_DIR=str(tmp_path), PROVIDER_CACHE_DIR=str(tmp_path / "cache"))
    content = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "demo", "purl": "pkg:npm/demo@1.0"}],
        }
    ).encode()
    prepared = prepare_import_upload(
        ProjectImportUploadRequest(
            input_type="cyclonedx-json",
            sbom_scanner="grype",
            file=ImportUploadContent(
                filename="sbom.json", content_type="application/json", content=content
            ),
        ),
        settings=settings,
    )
    artifacts = store_prepared_uploads(
        settings, project_id=uuid.uuid4(), run_id=uuid.uuid4(), prepared=prepared
    )
    context = SimpleNamespace(stage=lambda *args, **kwargs: None, checkpoint=lambda: None)
    return settings, prepared, artifacts, context


def _result(input_sha256: str, report: dict | None = None) -> SbomScannerResult:
    if report is None:
        report = {"matches": [], "descriptor": {"name": "grype", "version": "0.110.0"}}
    content = json.dumps(report).encode()
    return SbomScannerResult(
        report=report,
        report_bytes=content,
        evidence=SbomAssessmentV1(
            scanner_version="0.110.0",
            input_format="cyclonedx-json",
            target_ref="demo",
            scanned_at=datetime.now(UTC).isoformat(),
            input_sha256=input_sha256,
            output_sha256=hashlib.sha256(content).hexdigest(),
            component_count=1,
            identified_component_count=1,
            version_missing_count=0,
            scanner_match_count=0,
            prioritized_match_count=0,
            unassigned_match_count=0,
        ),
    )


def test_scan_cannot_publish_evidence_for_changed_upload(tmp_path, monkeypatch) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path)
    monkeypatch.setattr(sbom_import, "scan_sbom", lambda *args, **kwargs: _result("a" * 64))
    with pytest.raises(ImporterParseError, match="changed"):
        sbom_import.scan_prepared_sbom(
            prepared, artifacts, settings=settings, context=context, observed_at=datetime.now(UTC)
        )
    assert not (artifacts.upload_path.parent / "sbom-assessments").exists()


def test_scan_observation_time_preserves_the_instant_for_aware_datetimes(
    tmp_path, monkeypatch
) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path)
    monkeypatch.setattr(
        sbom_import, "scan_sbom", lambda *args, **kwargs: _result(prepared.upload_sha256)
    )
    observed = datetime(2026, 9, 19, 10, 30, tzinfo=timezone(timedelta(hours=2)))
    _parsed, assessment = sbom_import.scan_prepared_sbom(
        prepared, artifacts, settings=settings, context=context, observed_at=observed
    )
    assert datetime.fromisoformat(assessment.observed_at) == observed


def test_scan_cannot_publish_evidence_with_mismatched_input_format(tmp_path, monkeypatch) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path)
    result = _result(prepared.upload_sha256)
    result.evidence.input_format = "spdx-json"
    monkeypatch.setattr(sbom_import, "scan_sbom", lambda *args, **kwargs: result)
    with pytest.raises(ImporterParseError, match="input type does not match"):
        sbom_import.scan_prepared_sbom(
            prepared, artifacts, settings=settings, context=context, observed_at=datetime.now(UTC)
        )
    assert not (artifacts.upload_path.parent / "sbom-assessments").exists()


def test_scanner_warnings_are_sanitized_and_bounded_without_modifying_raw_report(
    tmp_path, monkeypatch
) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path)
    report = {
        "matches": [{"vulnerability": {"id": f"GHSA-{number}"}} for number in range(1000)],
        "descriptor": {"name": "grype", "version": "0.110.0"},
    }
    result = _result(prepared.upload_sha256, report)
    result.evidence.warnings = ["Could not read /private/tmp/secret/grype.yaml " + "x" * 4000]
    monkeypatch.setattr(sbom_import, "scan_sbom", lambda *args, **kwargs: result)
    parsed, assessment = sbom_import.scan_prepared_sbom(
        prepared, artifacts, settings=settings, context=context, observed_at=datetime.now(UTC)
    )
    assert len(assessment.warnings) == 21
    assert all(len(warning) <= 1000 for warning in assessment.warnings)
    assert "/private/tmp/secret" not in assessment.model_dump_json()
    assert "981 additional warning(s) omitted" in assessment.warnings[-1]
    assert parsed.parsed_input.parsed_input.warnings == assessment.warnings
    assert assessment.status == "partial"
    raw_path = settings.import_upload_dir_path / assessment.artifact_refs["report"]
    assert raw_path.read_bytes() == result.report_bytes


def test_missing_scanner_package_evidence_marks_assessment_partial(tmp_path, monkeypatch) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path)
    result = _result(
        prepared.upload_sha256,
        {"matches": [{"vulnerability": {"id": "CVE-2021-44228"}}]},
    )
    monkeypatch.setattr(sbom_import, "scan_sbom", lambda *args, **kwargs: result)
    _parsed, assessment = sbom_import.scan_prepared_sbom(
        prepared, artifacts, settings=settings, context=context, observed_at=datetime.now(UTC)
    )
    assert assessment.status == "partial"
    assert any("missing an artifact object" in warning for warning in assessment.warnings)


@pytest.mark.parametrize("root_style", ["symlink", "relative"])
def test_scan_artifact_refs_support_resolved_upload_roots(
    tmp_path, monkeypatch, root_style
) -> None:
    settings, prepared, artifacts, context = _prepared(tmp_path / "actual")
    if root_style == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path / "actual", target_is_directory=True)
        settings = replace(settings, IMPORT_UPLOAD_DIR=str(alias))
    else:
        monkeypatch.chdir(tmp_path)
        settings = replace(settings, IMPORT_UPLOAD_DIR="actual")
    monkeypatch.setattr(
        sbom_import, "scan_sbom", lambda *args, **kwargs: _result(prepared.upload_sha256)
    )
    _parsed, assessment = sbom_import.scan_prepared_sbom(
        prepared, artifacts, settings=settings, context=context, observed_at=datetime.now(UTC)
    )
    for name in ("report", "manifest"):
        reference = assessment.artifact_refs[name]
        assert (settings.import_upload_dir_path / reference).is_file()
        assert reference.startswith(artifacts.upload_ref.rsplit("/", 1)[0] + "/")
