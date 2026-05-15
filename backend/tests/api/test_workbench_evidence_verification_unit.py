from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from app.services import report_bundle_archive_verification as bundle_verification
from app.services import report_sarif_validation as sarif_validation
from app.services.report_bundle_archive_verification import (
    describe_evidence_bundle_mismatch,
    validate_evidence_manifest_structure,
    verify_evidence_bundle,
)
from app.services.report_sarif_validation import (
    load_sarif_payload,
    validate_sarif_file,
    validate_sarif_payload,
)
from vuln_prioritizer.models import EvidenceBundleFile, EvidenceBundleManifest


def test_verify_evidence_bundle_reports_missing_manifest(tmp_path: Path) -> None:
    bundle_path = tmp_path / "missing-manifest.zip"
    _write_zip(bundle_path, {"analysis.json": b'{"schema":"analysis-result.v1"}\n'})

    metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert metadata.bundle_path == str(bundle_path)
    assert summary.ok is False
    assert summary.manifest_errors == 1
    assert summary.missing_files == 1
    assert items[0].path == "manifest.json"
    assert items[0].status == "missing"


def test_verify_evidence_bundle_reports_missing_modified_and_unexpected_members(
    tmp_path: Path,
) -> None:
    expected_analysis = b'{"schema":"analysis-result.v1","ok":true}\n'
    manifest = _manifest(
        [
            _bundle_file("analysis.json", "analysis-json", expected_analysis),
            _bundle_file("technical.md", "technical-markdown", b"# Technical\n"),
        ]
    )
    bundle_path = tmp_path / "tampered.zip"
    _write_zip(
        bundle_path,
        {
            "manifest.json": json.dumps(manifest).encode(),
            "analysis.json": b'{"schema":"analysis-result.v1","tampered":true}\n',
            "extra.txt": b"not declared\n",
        },
    )

    _metadata, summary, items = verify_evidence_bundle(bundle_path)
    by_status = {item.status: item for item in items}

    assert summary.ok is False
    assert summary.expected_files == 2
    assert summary.modified_files == 1
    assert summary.missing_files == 1
    assert summary.unexpected_files == 1
    assert by_status["modified"].path == "analysis.json"
    assert "sha256 mismatch" in by_status["modified"].detail
    assert by_status["missing"].path == "technical.md"
    assert by_status["unexpected"].path == "extra.txt"
    assert by_status["unexpected"].actual_sha256 == _sha256(b"not declared\n")


@pytest.mark.parametrize(
    ("manifest_bytes", "expected_detail"),
    [
        (b"{not json", "Manifest is not valid JSON"),
        (b"[]", "Manifest must decode to a JSON object."),
    ],
)
def test_verify_evidence_bundle_reports_invalid_manifest_payloads(
    tmp_path: Path,
    manifest_bytes: bytes,
    expected_detail: str,
) -> None:
    bundle_path = tmp_path / "invalid-manifest.zip"
    _write_zip(bundle_path, {"manifest.json": manifest_bytes})

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.manifest_errors == 1
    assert items[0].path == "manifest.json"
    assert expected_detail in items[0].detail


def test_verify_evidence_bundle_rejects_bad_zip(tmp_path: Path) -> None:
    bundle_path = tmp_path / "not-a-zip.zip"
    bundle_path.write_text("not a zip", encoding="utf-8")

    with pytest.raises(ValueError, match="is not a valid ZIP archive"):
        verify_evidence_bundle(bundle_path)


def test_verify_evidence_bundle_rejects_archive_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path = tmp_path / "too-many-members.zip"
    _write_zip(bundle_path, {"manifest.json": b"{}", "a.txt": b"a"})
    monkeypatch.setattr(bundle_verification, "MAX_EVIDENCE_BUNDLE_MEMBERS", 1)

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.manifest_errors == 1
    assert items[0].path == "*"
    assert "member verifier limit" in items[0].detail


def test_verify_evidence_bundle_rejects_manifest_and_total_size_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_path = tmp_path / "oversized.zip"
    _write_zip(bundle_path, {"manifest.json": b"{}" * 4, "a.txt": b"abc"})
    monkeypatch.setattr(bundle_verification, "MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES", 3)
    monkeypatch.setattr(bundle_verification, "MAX_EVIDENCE_BUNDLE_TOTAL_BYTES", 5)

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.manifest_errors == 2
    assert {item.path for item in items} == {"*", "manifest.json"}
    assert any("uncompressed size" in item.detail for item in items)
    assert any("Manifest exceeds verifier size limit" in item.detail for item in items)


def test_verify_evidence_bundle_rejects_oversized_declared_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"too large"
    manifest = _manifest([_bundle_file("analysis.json", "analysis-json", content)])
    bundle_path = tmp_path / "oversized-member.zip"
    _write_zip(
        bundle_path,
        {"manifest.json": json.dumps(manifest).encode(), "analysis.json": content},
    )
    monkeypatch.setattr(bundle_verification, "MAX_EVIDENCE_BUNDLE_MEMBER_BYTES", 1)

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.modified_files == 1
    assert items[0].path == "analysis.json"
    assert items[0].status == "error"
    assert "was not decompressed" in items[0].detail


def test_verify_evidence_bundle_reports_hash_limit_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"hash me"
    manifest = _manifest([_bundle_file("analysis.json", "analysis-json", content)])
    bundle_path = tmp_path / "hash-limit.zip"
    _write_zip(
        bundle_path,
        {"manifest.json": json.dumps(manifest).encode(), "analysis.json": content},
    )

    def fail_hash(_archive: zipfile.ZipFile, path: str) -> tuple[int, str]:
        raise ValueError(f"{path} exceeds verifier size limit.")

    monkeypatch.setattr(bundle_verification, "_hash_limited_member", fail_hash)

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.modified_files == 1
    assert items[0].status == "error"
    assert "exceeds verifier size limit" in items[0].detail


def test_verify_evidence_bundle_reports_unexpected_large_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest([])
    bundle_path = tmp_path / "unexpected-large.zip"
    _write_zip(
        bundle_path,
        {"manifest.json": json.dumps(manifest).encode(), "unexpected.bin": b"large"},
    )
    monkeypatch.setattr(bundle_verification, "MAX_EVIDENCE_BUNDLE_MEMBER_BYTES", 1)

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.unexpected_files == 1
    assert items[0].path == "unexpected.bin"
    assert items[0].status == "unexpected"
    assert "was not decompressed" in items[0].detail
    assert items[0].actual_sha256 is None


def test_verify_evidence_bundle_reports_manifest_schema_errors(tmp_path: Path) -> None:
    bundle_path = tmp_path / "schema-error.zip"
    _write_zip(
        bundle_path,
        {"manifest.json": json.dumps({"schema_version": "1.1.0", "files": [{}]}).encode()},
    )

    _metadata, summary, items = verify_evidence_bundle(bundle_path)

    assert summary.ok is False
    assert summary.manifest_errors == 1
    assert items[0].path == "manifest.json"
    assert "Manifest failed validation at" in items[0].detail


def test_validate_evidence_manifest_structure_rejects_reserved_and_duplicate_paths() -> None:
    manifest = EvidenceBundleManifest(
        generated_at="2026-05-15T00:00:00Z",
        source_analysis_path="analysis.json",
        files=[
            EvidenceBundleFile(
                path="manifest.json",
                kind="manifest-copy",
                size_bytes=2,
                sha256=_sha256(b"{}"),
            ),
            EvidenceBundleFile(
                path="analysis.json",
                kind="analysis-json",
                size_bytes=2,
                sha256=_sha256(b"{}"),
            ),
            EvidenceBundleFile(
                path="analysis.json",
                kind="analysis-json",
                size_bytes=2,
                sha256=_sha256(b"{}"),
            ),
        ],
    )

    errors = validate_evidence_manifest_structure(manifest)

    assert [error.path for error in errors] == ["manifest.json", "analysis.json"]
    assert "must not declare manifest.json" in errors[0].detail
    assert "more than once" in errors[1].detail


def test_describe_evidence_bundle_mismatch_uses_generic_detail_when_values_match() -> None:
    expected = EvidenceBundleFile(
        path="analysis.json",
        kind="analysis-json",
        size_bytes=2,
        sha256=_sha256(b"{}"),
    )

    assert (
        describe_evidence_bundle_mismatch(
            expected=expected,
            actual_size=2,
            actual_sha256=_sha256(b"{}"),
        )
        == "Archive member does not match the manifest."
    )


def test_sarif_validation_reports_rule_and_vulnerability_contract_errors() -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer-workbench",
                        "rules": [{"id": "declared-rule"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "missing-rule",
                        "level": "error",
                        "message": {"text": "Missing CVE metadata"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "input.csv"}}}
                        ],
                        "partialFingerprints": {"primary": "fingerprint"},
                        "properties": {
                            "cve": "not-a-cve",
                            "references": ["ftp://example.invalid/advisory"],
                        },
                    }
                ],
            }
        ],
    }

    errors = validate_sarif_payload(payload)

    assert any("missing-rule" in error and "not declared" in error for error in errors)
    assert any("properties.cve" in error for error in errors)
    assert any("reference must be an HTTP(S) URL" in error for error in errors)


def test_load_sarif_payload_rejects_non_object_json(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a JSON object"):
        load_sarif_payload(sarif_path)


def test_load_sarif_payload_rejects_invalid_json(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="is not valid JSON"):
        load_sarif_payload(sarif_path)


def test_validate_sarif_payload_reports_schema_errors_and_skips_non_objects() -> None:
    payload = {
        "version": "2.0.0",
        "runs": [
            "not-a-run",
            {
                "tool": {"driver": {"name": "not-vuln-prioritizer", "rules": []}},
                "results": ["not-a-result"],
            },
        ],
    }

    errors = validate_sarif_payload(payload)

    assert any("version: '2.1.0' was expected" in error for error in errors)
    assert any("runs.0" in error and "not of type 'object'" in error for error in errors)
    assert any("runs.1.results.0" in error and "not of type 'object'" in error for error in errors)
    assert not any("properties.cve" in error for error in errors)


def test_validate_sarif_file_accepts_valid_payload(tmp_path: Path) -> None:
    payload = _valid_sarif_payload()
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded, errors = validate_sarif_file(sarif_path)

    assert loaded == payload
    assert errors == []


def test_validate_sarif_payload_detects_missing_vulnerability_references() -> None:
    payload = _valid_sarif_payload()
    payload["runs"][0]["results"][0]["properties"]["references"] = []

    errors = sarif_validation.validate_sarif_payload(payload)

    assert any("properties.references" in error for error in errors)


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member_path, content in members.items():
            archive.writestr(member_path, content)


def _bundle_file(path: str, kind: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "kind": kind,
        "size_bytes": len(content),
        "sha256": _sha256(content),
    }


def _manifest(files: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "1.1.0",
        "bundle_kind": "evidence-bundle",
        "generated_at": "2026-05-15T00:00:00Z",
        "source_analysis_path": "analysis.json",
        "files": files,
    }


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _valid_sarif_payload() -> dict[str, object]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer-workbench",
                        "rules": [{"id": "critical-vulnerability"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "critical-vulnerability",
                        "level": "error",
                        "message": {"text": "Critical vulnerability"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "input.csv"}}}
                        ],
                        "partialFingerprints": {"primary": "fingerprint"},
                        "properties": {
                            "cve": "CVE-2024-3094",
                            "references": ["https://example.test/CVE-2024-3094"],
                        },
                    }
                ],
            }
        ],
    }
