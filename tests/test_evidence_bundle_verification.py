from __future__ import annotations

import json
import zipfile
from pathlib import Path

from test_cli import _install_fake_providers, _write_input_file, runner

from vuln_prioritizer.cli import app


def test_cli_verify_evidence_bundle_succeeds_for_clean_bundle(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle_file = _build_evidence_bundle(monkeypatch, tmp_path)
    verification_file = tmp_path / "verification.json"

    result = runner.invoke(
        app,
        [
            "report",
            "verify-evidence-bundle",
            "--input",
            str(bundle_file),
            "--format",
            "json",
            "--output",
            str(verification_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(verification_file.read_text(encoding="utf-8"))
    assert payload["summary"]["ok"] is True
    assert payload["summary"]["verified_files"] == 4
    assert payload["summary"]["missing_files"] == 0
    assert payload["summary"]["modified_files"] == 0
    assert payload["summary"]["unexpected_files"] == 0
    assert payload["summary"]["manifest_errors"] == 0
    assert {item["path"] for item in payload["items"]} == {
        "analysis.json",
        "report.html",
        "summary.md",
        "input/cves.txt",
    }


def test_cli_verify_evidence_bundle_detects_modified_member(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle_file = _build_evidence_bundle(monkeypatch, tmp_path)
    verification_file = tmp_path / "modified.json"
    members = _read_bundle_members(bundle_file)
    members["report.html"] = b"<html><body>tampered</body></html>"
    _write_bundle_members(bundle_file, members)

    result = runner.invoke(
        app,
        [
            "report",
            "verify-evidence-bundle",
            "--input",
            str(bundle_file),
            "--format",
            "json",
            "--output",
            str(verification_file),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(verification_file.read_text(encoding="utf-8"))
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["modified_files"] == 1
    modified_item = next(item for item in payload["items"] if item["path"] == "report.html")
    assert modified_item["status"] == "modified"
    assert "sha256 mismatch" in modified_item["detail"]


def test_cli_verify_evidence_bundle_detects_missing_member(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle_file = _build_evidence_bundle(monkeypatch, tmp_path)
    verification_file = tmp_path / "missing.json"
    members = _read_bundle_members(bundle_file)
    members.pop("summary.md")
    _write_bundle_members(bundle_file, members)

    result = runner.invoke(
        app,
        [
            "report",
            "verify-evidence-bundle",
            "--input",
            str(bundle_file),
            "--format",
            "json",
            "--output",
            str(verification_file),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(verification_file.read_text(encoding="utf-8"))
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["missing_files"] == 1
    missing_item = next(item for item in payload["items"] if item["path"] == "summary.md")
    assert missing_item["status"] == "missing"


def test_cli_verify_evidence_bundle_detects_unexpected_member(
    monkeypatch,
    tmp_path: Path,
) -> None:
    bundle_file = _build_evidence_bundle(monkeypatch, tmp_path)
    verification_file = tmp_path / "unexpected.json"
    members = _read_bundle_members(bundle_file)
    members["extra.txt"] = b"surprise"
    _write_bundle_members(bundle_file, members)

    result = runner.invoke(
        app,
        [
            "report",
            "verify-evidence-bundle",
            "--input",
            str(bundle_file),
            "--format",
            "json",
            "--output",
            str(verification_file),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(verification_file.read_text(encoding="utf-8"))
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["unexpected_files"] == 1
    unexpected_item = next(item for item in payload["items"] if item["path"] == "extra.txt")
    assert unexpected_item["status"] == "unexpected"


def _build_evidence_bundle(monkeypatch, tmp_path: Path) -> Path:
    input_file = _write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    bundle_file = tmp_path / "evidence.zip"
    _install_fake_providers(monkeypatch)

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )
    assert analyze_result.exit_code == 0

    bundle_result = runner.invoke(
        app,
        [
            "report",
            "evidence-bundle",
            "--input",
            str(analysis_file),
            "--output",
            str(bundle_file),
        ],
    )
    assert bundle_result.exit_code == 0
    return bundle_file


def _read_bundle_members(bundle_file: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(bundle_file, "r") as archive:
        return {
            info.filename: archive.read(info.filename)
            for info in archive.infolist()
            if not info.is_dir()
        }


def _write_bundle_members(bundle_file: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(bundle_file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(members.items()):
            archive.writestr(path, content)
