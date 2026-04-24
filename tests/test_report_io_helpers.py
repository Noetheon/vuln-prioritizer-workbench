from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import typer
from pydantic import ValidationError

from vuln_prioritizer.cli_support.report_io import (
    analysis_input_paths,
    attack_navigator_layer_from_summary,
    bundle_file_entry,
    describe_evidence_bundle_mismatch,
    format_evidence_manifest_validation_error,
    input_hash_entry,
    load_analysis_report_payload,
    provider_snapshot_manifest_entry,
    resolve_analysis_input_path,
    source_input_bundle_path,
    validate_evidence_manifest_structure,
    verify_evidence_bundle,
    write_evidence_bundle,
)
from vuln_prioritizer.models import EvidenceBundleFile, EvidenceBundleManifest


def test_load_analysis_report_payload_rejects_non_analysis_json(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{broken", encoding="utf-8")
    with pytest.raises(typer.Exit) as invalid_exc:
        load_analysis_report_payload(invalid_json)
    assert invalid_exc.value.exit_code == 2

    scalar_json = tmp_path / "scalar.json"
    scalar_json.write_text("[]", encoding="utf-8")
    with pytest.raises(typer.Exit) as scalar_exc:
        load_analysis_report_payload(scalar_json)
    assert scalar_exc.value.exit_code == 2

    incomplete_json = tmp_path / "incomplete.json"
    incomplete_json.write_text('{"metadata": {}}', encoding="utf-8")
    with pytest.raises(typer.Exit) as incomplete_exc:
        load_analysis_report_payload(incomplete_json)
    assert incomplete_exc.value.exit_code == 2


def test_verify_evidence_bundle_reports_manifest_decode_and_schema_errors(
    tmp_path: Path,
) -> None:
    missing_manifest = tmp_path / "missing-manifest.zip"
    _write_zip(missing_manifest, {"analysis.json": b"{}"})
    _, missing_summary, missing_items = verify_evidence_bundle(missing_manifest)
    assert missing_summary.manifest_errors == 1
    assert missing_summary.missing_files == 1
    assert missing_items[0].status == "missing"

    invalid_manifest = tmp_path / "invalid-manifest.zip"
    _write_zip(invalid_manifest, {"manifest.json": b"{broken"})
    _, invalid_summary, invalid_items = verify_evidence_bundle(invalid_manifest)
    assert invalid_summary.manifest_errors == 1
    assert invalid_items[0].status == "error"
    assert "not valid JSON" in invalid_items[0].detail

    scalar_manifest = tmp_path / "scalar-manifest.zip"
    _write_zip(scalar_manifest, {"manifest.json": b"[]"})
    _, scalar_summary, scalar_items = verify_evidence_bundle(scalar_manifest)
    assert scalar_summary.manifest_errors == 1
    assert scalar_items[0].detail == "Manifest must decode to a JSON object."

    schema_manifest = tmp_path / "schema-manifest.zip"
    _write_zip(schema_manifest, {"manifest.json": b'{"files": []}'})
    _, schema_summary, schema_items = verify_evidence_bundle(schema_manifest)
    assert schema_summary.manifest_errors == 1
    assert "Manifest failed validation at generated_at" in schema_items[0].detail


def test_verify_evidence_bundle_reports_manifest_structure_errors(tmp_path: Path) -> None:
    manifest_payload = {
        "generated_at": "2026-04-24T10:00:00Z",
        "source_analysis_path": "analysis.json",
        "files": [
            {
                "path": "manifest.json",
                "kind": "manifest",
                "size_bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
            {
                "path": "analysis.json",
                "kind": "analysis-json",
                "size_bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
            {
                "path": "analysis.json",
                "kind": "analysis-json",
                "size_bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
        ],
    }
    bundle = tmp_path / "structure-errors.zip"
    _write_zip(bundle, {"manifest.json": json.dumps(manifest_payload).encode("utf-8")})

    metadata, summary, items = verify_evidence_bundle(bundle)

    assert metadata.manifest_schema_version == "1.1.0"
    assert summary.ok is False
    assert summary.expected_files == 3
    assert summary.manifest_errors == 2
    assert {item.path for item in items} == {"manifest.json", "analysis.json"}
    assert any("must not declare manifest.json" in item.detail for item in items)
    assert any("same bundle member path" in item.detail for item in items)


def test_verify_evidence_bundle_rejects_bad_zip(tmp_path: Path) -> None:
    bad_zip = tmp_path / "bad.zip"
    bad_zip.write_text("not a zip", encoding="utf-8")

    with pytest.raises(typer.Exit) as exc:
        verify_evidence_bundle(bad_zip)
    assert exc.value.exit_code == 2


def test_evidence_bundle_helper_functions_cover_manifest_and_path_edges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_file = tmp_path / "input.txt"
    analysis_file = tmp_path / "analysis.json"
    snapshot_file = tmp_path / "snapshot.json"
    input_file.write_text("CVE-2024-0001\n", encoding="utf-8")
    analysis_file.write_text("{}", encoding="utf-8")
    snapshot_file.write_text('{"metadata": {}}', encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    assert analysis_input_paths({"input_paths": [" input.txt ", "", 1]}) == ["input.txt"]
    assert analysis_input_paths({"input_path": " input.txt "}) == ["input.txt"]
    assert analysis_input_paths({}) == []
    assert analysis_input_paths("not metadata") == []
    assert resolve_analysis_input_path("input.txt", analysis_file) == input_file.resolve()
    assert resolve_analysis_input_path("", analysis_file) is None
    assert resolve_analysis_input_path(42, analysis_file) is None
    assert source_input_bundle_path(input_file, index=2, multiple=True) == "input/002-input.txt"
    assert source_input_bundle_path(input_file, index=1, multiple=False) == "input/input.txt"
    expected_input_hash = hashlib.sha256(input_file.read_bytes()).hexdigest()
    assert input_hash_entry(input_file).sha256 == expected_input_hash
    analysis_entry = bundle_file_entry(path="analysis.json", content=b"{}", kind="analysis-json")
    assert analysis_entry.size_bytes == 2
    assert provider_snapshot_manifest_entry("not metadata", analysis_path=analysis_file) == {}
    assert provider_snapshot_manifest_entry(
        {
            "provider_snapshot_id": "snapshot-1",
            "provider_snapshot_file": "snapshot.json",
            "provider_snapshot_sources": ["nvd"],
        },
        analysis_path=analysis_file,
    ) == {
        "id": "snapshot-1",
        "sha256": hashlib.sha256(snapshot_file.read_bytes()).hexdigest(),
        "path": "snapshot.json",
        "sources": ["nvd"],
    }
    assert provider_snapshot_manifest_entry(
        {
            "provider_snapshot_id": "snapshot-2",
            "provider_snapshot_hash": "c" * 64,
            "provider_snapshot_file": "missing.json",
        },
        analysis_path=analysis_file,
    ) == {"id": "snapshot-2", "sha256": "c" * 64, "path": "missing.json"}


def test_attack_navigator_layer_from_summary_filters_invalid_distribution_entries() -> None:
    assert attack_navigator_layer_from_summary("not summary") is None
    assert attack_navigator_layer_from_summary({"technique_distribution": {}}) is None
    assert attack_navigator_layer_from_summary(
        {"technique_distribution": {"": 3, "T1190": 2, "T1059": 0, "T1110": -1}}
    )["techniques"] == [
        {
            "techniqueID": "T1190",
            "score": 2,
            "comment": "Observed in 2 mapped CVE(s).",
        }
    ]


def test_write_evidence_bundle_handles_missing_input_copy_and_navigator_layer(
    tmp_path: Path,
) -> None:
    analysis_file = tmp_path / "analysis.json"
    output_file = tmp_path / "evidence.zip"
    payload = {
        "metadata": {
            "input_path": "missing-input.txt",
            "findings_count": 1,
            "kev_hits": 0,
            "waived_count": 0,
        },
        "attack_summary": {
            "mapped_cves": 1,
            "unmapped_cves": 0,
            "technique_distribution": {"T1190": 1},
            "tactic_distribution": {"initial-access": 1},
            "mapping_type_distribution": {"exploitation_technique": 1},
        },
        "findings": [],
    }
    analysis_file.write_text(json.dumps(payload), encoding="utf-8")

    manifest = write_evidence_bundle(
        analysis_path=analysis_file,
        output_path=output_file,
        payload=payload,
        include_input_copy=True,
    )

    assert manifest.included_input_copy is False
    assert manifest.source_input_paths == ["missing-input.txt"]
    assert manifest.attack_mapped_cves == 1
    with zipfile.ZipFile(output_file) as archive:
        names = set(archive.namelist())
        assert "attack-navigator-layer.json" in names
        assert not any(name.startswith("input/") for name in names)


def test_manifest_validation_error_format_and_mismatch_descriptions() -> None:
    try:
        EvidenceBundleManifest.model_validate({"files": []})
    except ValidationError as exc:
        detail = format_evidence_manifest_validation_error(exc)
    else:  # pragma: no cover - the model is expected to reject this payload.
        raise AssertionError("Expected manifest validation to fail")

    expected = EvidenceBundleFile(
        path="report.html",
        kind="html-report",
        size_bytes=10,
        sha256="a" * 64,
    )

    assert "generated_at" in detail
    assert (
        describe_evidence_bundle_mismatch(
            expected=expected,
            actual_size=10,
            actual_sha256="a" * 64,
        )
        == "Archive member does not match the manifest."
    )
    assert (
        describe_evidence_bundle_mismatch(
            expected=expected,
            actual_size=11,
            actual_sha256="b" * 64,
        )
        == "Archive member does not match the manifest: size 11 != manifest 10, sha256 mismatch."
    )


def test_validate_evidence_manifest_structure_accepts_clean_manifest() -> None:
    manifest = EvidenceBundleManifest(
        generated_at="2026-04-24T10:00:00Z",
        source_analysis_path="analysis.json",
        files=[
            EvidenceBundleFile(
                path="analysis.json",
                kind="analysis-json",
                size_bytes=2,
                sha256=hashlib.sha256(b"{}").hexdigest(),
            )
        ],
    )

    assert validate_evidence_manifest_structure(manifest) == []


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
