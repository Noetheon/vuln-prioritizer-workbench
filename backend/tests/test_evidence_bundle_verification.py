from __future__ import annotations

import json
import zipfile
from pathlib import Path

from _cli_helpers import (
    install_fake_providers as _install_fake_providers,
)
from _cli_helpers import (
    runner,
)
from _cli_helpers import (
    write_input_file as _write_input_file,
)

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import EpssData, KevData, NvdData
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider
from vuln_prioritizer.reporting_evidence import (
    resolve_provider_snapshot_path,
    write_evidence_bundle,
)


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


def test_cli_evidence_bundle_includes_all_multi_input_sources(
    monkeypatch,
    tmp_path: Path,
) -> None:
    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    analysis_file = tmp_path / "analysis.json"
    bundle_file = tmp_path / "evidence.zip"
    first_input.write_text("CVE-2021-44228\n", encoding="utf-8")
    second_input.write_text("CVE-2023-44487\n", encoding="utf-8")
    _install_fake_providers(monkeypatch)

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(first_input),
            "--input",
            str(second_input),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )
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

    assert analyze_result.exit_code == 0
    assert bundle_result.exit_code == 0
    with zipfile.ZipFile(bundle_file) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))

    assert manifest["source_input_paths"] == ["input/001-cves-a.txt", "input/002-cves-b.txt"]
    assert manifest["source_input_path"] == "input/001-cves-a.txt"
    assert {"input/001-cves-a.txt", "input/002-cves-b.txt"} <= names


def test_cli_evidence_bundle_includes_provider_snapshot_and_replays_offline(
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    snapshot_file = tmp_path / "provider-snapshot.json"
    analysis_file = tmp_path / "analysis.json"
    bundle_file = tmp_path / "evidence.zip"

    def fake_nvd_fetch_many(
        self: NvdProvider,  # noqa: ARG001
        cve_ids: list[str],
        *,
        refresh: bool = False,  # noqa: ARG001
    ) -> tuple[dict[str, NvdData], list[str]]:
        return (
            {
                cve_id: NvdData(
                    cve_id=cve_id,
                    description=f"{cve_id} snapshot description",
                    cvss_base_score=9.0,
                    cvss_severity="CRITICAL",
                    cvss_version="3.1",
                )
                for cve_id in cve_ids
            },
            [],
        )

    def fake_epss_fetch_many(
        self: EpssProvider,  # noqa: ARG001
        cve_ids: list[str],
        *,
        refresh: bool = False,  # noqa: ARG001
    ) -> tuple[dict[str, EpssData], list[str]]:
        return (
            {
                cve_id: EpssData(cve_id=cve_id, epss=0.5, percentile=0.9, date="2026-04-29")
                for cve_id in cve_ids
            },
            [],
        )

    def fake_kev_fetch_many(
        self: KevProvider,  # noqa: ARG001
        cve_ids: list[str],
        offline_file: Path | None = None,  # noqa: ARG001
        *,
        refresh: bool = False,  # noqa: ARG001
    ) -> tuple[dict[str, KevData], list[str]]:
        return ({cve_id: KevData(cve_id=cve_id, in_kev=False) for cve_id in cve_ids}, [])

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)

    export_result = runner.invoke(
        app,
        [
            "data",
            "export-provider-snapshot",
            "--input",
            str(input_file),
            "--output",
            str(snapshot_file),
            "--cache-dir",
            str(tmp_path / "cache"),
        ],
    )
    assert export_result.exit_code == 0

    def fail_fetch_many(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("live provider should not be called during locked replay")

    monkeypatch.setattr(NvdProvider, "fetch_many", fail_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fail_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fail_fetch_many)

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
            "--provider-snapshot-file",
            str(snapshot_file),
            "--locked-provider-data",
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

    with zipfile.ZipFile(bundle_file) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        bundled_snapshot = json.loads(archive.read("provider/provider-snapshot.json"))

    assert "provider/provider-snapshot.json" in names
    assert bundled_snapshot["metadata"]["snapshot_format"] == "provider-snapshot.v1.json"
    assert manifest["provider_snapshot"]["bundle_path"] == "provider/provider-snapshot.json"
    assert (
        manifest["provider_snapshot"]["sha256"]
        == manifest["artifact_hashes"]["provider/provider-snapshot.json"]
    )
    assert any(
        item["path"] == "provider/provider-snapshot.json" and item["kind"] == "provider-snapshot"
        for item in manifest["files"]
    )


def test_evidence_bundle_resolves_repo_relative_provider_snapshot(
    monkeypatch,
    tmp_path: Path,
) -> None:
    analysis_file = tmp_path / "build" / "analysis.json"
    analysis_file.parent.mkdir()
    analysis_file.write_text("{}", encoding="utf-8")
    snapshot_file = tmp_path / "data" / "demo_provider_snapshot.json"
    snapshot_file.parent.mkdir()
    snapshot_file.write_text(
        json.dumps(
            {
                "items": [],
                "metadata": {
                    "artifact_kind": "provider-snapshot",
                    "generated_at": "2026-04-21T12:00:00+00:00",
                    "selected_sources": ["nvd", "epss", "kev"],
                    "snapshot_format": "provider-snapshot.v1.json",
                    "snapshot_id": "test-provider-snapshot",
                },
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=local-secret\n", encoding="utf-8")
    secret_json = tmp_path / "secrets" / "export.json"
    secret_json.parent.mkdir()
    secret_json.write_text('{"SECRET_KEY": "local-secret"}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert (
        resolve_provider_snapshot_path("data/demo_provider_snapshot.json", analysis_file)
        == snapshot_file
    )
    assert resolve_provider_snapshot_path("../private/provider.json", analysis_file) is None
    assert resolve_provider_snapshot_path(str(snapshot_file), analysis_file) is None
    assert resolve_provider_snapshot_path(".env", analysis_file) is None
    assert resolve_provider_snapshot_path("secrets/export.json", analysis_file) is None


def test_evidence_bundle_redacts_secret_like_text_in_copied_artifacts(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    analysis_file = tmp_path / "analysis.json"
    bundle_file = tmp_path / "evidence.zip"
    input_file.write_text(
        "\n".join(
            [
                "CVE-2026-0711",
                "NVD_API_KEY=super-secret-token",
                "source=/Users/Alice/My Project/secret-cves.txt",
                'container="/app/workbench-import-uploads/private input/cves.txt"',
                r"mirror=C:\Users\Alice\My Project\secret-cves.txt",
            ]
        ),
        encoding="utf-8",
    )
    analysis_file.write_text(
        json.dumps(
            {
                "metadata": {
                    "input_path": str(input_file),
                    "input_paths": [str(input_file)],
                    "findings_count": 0,
                    "kev_hits": 0,
                    "waived_count": 0,
                    "token": "super-secret-token",
                },
                "findings": [],
                "warnings": [
                    "Bearer super-secret-token",
                    "Parser failed at /app/workbench-reports/private report.json",
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = write_evidence_bundle(
        analysis_path=analysis_file,
        output_path=bundle_file,
        payload=json.loads(analysis_file.read_text(encoding="utf-8")),
        include_input_copy=True,
    )

    with zipfile.ZipFile(bundle_file) as archive:
        combined = "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in archive.namelist()
            if name.endswith((".json", ".md", ".html", ".txt"))
        )

    assert manifest.redaction["enabled"] is True
    assert "super-secret-token" not in combined
    assert str(tmp_path) not in combined
    assert "/Users/Alice" not in combined
    assert "/app/workbench-" not in combined
    assert r"C:\Users\Alice" not in combined
    assert "My Project" not in combined
    assert "private report.json" not in combined
    assert "NVD_API_KEY=<redacted>" in combined
    assert "[REDACTED-PATH]" in combined


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
