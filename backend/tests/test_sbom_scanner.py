from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from app.services.sbom_scanner import SbomScannerError, inspect_sbom, scan_sbom


def _sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "example", "version": "1.0"}},
        "components": [{"name": "example", "purl": "pkg:pypi/example@1.0"}],
    }


def _report(matches: list | None = None) -> dict:
    return {
        "matches": matches or [],
        "descriptor": {
            "name": "grype",
            "version": "0.110.0",
            "db": {
                "built": "2026-09-19T00:00:00Z",
                "schemaVersion": "6.0.0",
                "checksum": "sha256:" + "a" * 64,
                "valid": True,
            },
        },
    }


def _input(tmp_path: Path, data: dict | None = None) -> Path:
    path = tmp_path / "upload.json"
    path.write_text(json.dumps(data or _sbom()))
    return path


def _scanner(tmp_path: Path, report: dict | None = None, *, body: str | None = None) -> Path:
    binary = tmp_path / "scanner"
    payload = body if body is not None else f"print({json.dumps(report or _report())!r})"
    binary.write_text(
        f"#!{Path(sys.executable).resolve()}\nimport json, os, sys, time\n{payload}\n"
    )
    binary.chmod(0o755)
    return binary


def test_inventory_identity_versions_and_partial_identification() -> None:
    data = _sbom()
    data["components"] += [
        {"name": "unknown", "version": "2"},
        {"name": "no-version", "purl": "pkg:pypi/no-version"},
    ]
    inventory = inspect_sbom(json.dumps(data).encode())
    assert inventory.target_ref == "example@1.0"
    assert inventory.component_count == 3
    assert inventory.identified_component_count == 1
    assert inventory.version_missing_count == 1
    assert inventory.warnings
    assert (
        inspect_sbom(json.dumps(data).encode(), target_ref="my-service").target_ref == "my-service"
    )


def test_spdx_package_urls_and_described_root() -> None:
    data = {
        "spdxVersion": "SPDX-2.3",
        "documentDescribes": ["SPDXRef-App"],
        "packages": [
            {
                "SPDXID": "SPDXRef-App",
                "name": "app",
                "versionInfo": "1",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/app@1"}],
            }
        ],
    }
    inventory = inspect_sbom(json.dumps(data).encode())
    assert inventory.input_format == "spdx-json"
    assert inventory.target_ref == "pkg:npm/app@1"
    assert inventory.identified_component_count == 1


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"spdxVersion": "SPDX-3.0", "packages": [{"name": "a"}]},
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [None]},
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "a", "components": {}}],
        },
    ],
)
def test_preflight_rejects_non_inventory_or_invalid_structure(data: object) -> None:
    with pytest.raises(SbomScannerError):
        inspect_sbom(json.dumps(data).encode())


def test_zero_matches_succeeds_and_keeps_exact_hashes(tmp_path: Path) -> None:
    path = _input(tmp_path)
    result = scan_sbom(path, executable=_scanner(tmp_path), cache_dir=tmp_path / "db")
    assert result.report["matches"] == []
    assert result.evidence.scanner_match_count == 0
    assert result.evidence.status == "complete"
    assert result.evidence.database_sha256 == "a" * 64
    assert result.evidence.input_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.evidence.output_sha256 == hashlib.sha256(result.report_bytes).hexdigest()
    renamed = tmp_path / "different-upload-name.json"
    renamed.write_bytes(path.read_bytes())
    assert (
        scan_sbom(
            renamed, executable=tmp_path / "scanner", cache_dir=tmp_path / "db"
        ).evidence.target_ref
        == result.evidence.target_ref
    )


def test_alias_and_unassigned_advisory_counts_preserve_original_report(tmp_path: Path) -> None:
    matches = [
        {"vulnerability": {"id": "GHSA-one"}, "relatedVulnerabilities": [{"id": "CVE-2024-12345"}]},
        {"vulnerability": {"id": "CVE-2024-54321"}},
        {"vulnerability": {"id": "GHSA-without-cve"}},
    ]
    result = scan_sbom(
        _input(tmp_path), executable=_scanner(tmp_path, _report(matches)), cache_dir=tmp_path / "db"
    )
    assert result.report["matches"] == matches
    assert result.evidence.scanner_match_count == 3
    assert result.evidence.prioritized_match_count == 2
    assert result.evidence.unassigned_match_count == 1
    assert result.evidence.status == "partial"


def test_config_and_environment_are_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRYPE_ONLY_FIXED", "true")
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "true")
    monkeypatch.setenv("GRYPE_CONFIG", "/unexpected/config")
    monkeypatch.setenv("SYFT_REGISTRY_AUTH_PASSWORD", "not-for-the-scanner")
    monkeypatch.setenv("UNRELATED_TOKEN", "not-for-the-scanner")
    captured = tmp_path / "capture.json"
    body = (
        "config = json.load(open(sys.argv[sys.argv.index('--config') + 1]))\n"
        f"open({str(captured)!r}, 'w').write(json.dumps("
        "{'env': dict(os.environ), 'config': config, "
        "'cwd': os.getcwd(), 'args': sys.argv}))\n"
        f"print({json.dumps(_report())!r})"
    )
    scan_sbom(_input(tmp_path), executable=_scanner(tmp_path, body=body), cache_dir=tmp_path / "db")
    actual = json.loads(captured.read_text())
    assert not any(k.startswith(("GRYPE_", "SYFT_")) for k in actual["env"])
    assert "UNRELATED_TOKEN" not in actual["env"]
    assert actual["config"]["db"]["auto-update"] is False
    assert actual["config"]["external-sources"]["enable"] is False
    assert actual["config"]["check-for-app-update"] is False
    assert actual["config"]["ignore"] == []
    assert any(arg.startswith("sbom:") for arg in actual["args"])
    assert not Path(actual["cwd"]).exists()


def test_database_file_hash_is_only_read_from_managed_cache(tmp_path: Path) -> None:
    cache = tmp_path / "db"
    cache.mkdir()
    db = cache / "vulnerability.db"
    db.write_bytes(b"database content")
    report = _report()
    report["descriptor"]["db"]["path"] = str(db)
    result = scan_sbom(_input(tmp_path), executable=_scanner(tmp_path, report), cache_dir=cache)
    assert result.evidence.database_sha256 == hashlib.sha256(db.read_bytes()).hexdigest()
    outside = tmp_path / "secret"
    outside.write_bytes(b"not scanner input")
    report["descriptor"]["db"] = {"path": str(outside)}
    result = scan_sbom(_input(tmp_path), executable=_scanner(tmp_path, report), cache_dir=cache)
    assert result.evidence.database_sha256 is None
    assert result.evidence.status == "partial"


@pytest.mark.parametrize("nested_status", [False, True])
def test_explicitly_invalid_database_cannot_be_published_as_clean(
    tmp_path: Path, nested_status: bool
) -> None:
    report = _report()
    status = report["descriptor"]["db"]
    status["valid"] = False
    if nested_status:
        report["descriptor"]["db"] = {"status": status}
    # A zero-exit process and complete provenance cannot override failed DB validation.
    with pytest.raises(SbomScannerError, match="invalid vulnerability database"):
        scan_sbom(
            _input(tmp_path),
            executable=_scanner(tmp_path, report),
            cache_dir=tmp_path / "db",
        )


@pytest.mark.parametrize(
    "body, message",
    [
        ("print('invalid json')", "not valid JSON"),
        ("print('{}')", "matches array"),
        ("sys.stderr.write('database unavailable'); sys.exit(2)", "database unavailable"),
        ("time.sleep(10)", "time limit"),
        ("sys.stdout.write('x' * 100000)", "output size limit"),
        ("sys.stderr.write('x' * 100000)", "output size limit"),
    ],
)
def test_scanner_failures_are_bounded(tmp_path: Path, body: str, message: str) -> None:
    started = time.monotonic()
    with pytest.raises(SbomScannerError, match=message):
        scan_sbom(
            _input(tmp_path),
            executable=_scanner(tmp_path, body=body),
            cache_dir=tmp_path / "db",
            timeout_seconds=2 if message == "time limit" else 5,
            max_output_bytes=2048,
        )
    assert time.monotonic() - started < 8


def test_cancellation_preserves_workflow_exception_and_reaps_process(tmp_path: Path) -> None:
    class Cancelled(Exception):
        pass

    calls = 0

    def checkpoint() -> None:
        nonlocal calls
        calls += 1
        if calls >= 2 and pid_path.exists():
            raise Cancelled("lease cancelled")

    pid_path = tmp_path / "pid"
    binary = _scanner(
        tmp_path, body=f"open({str(pid_path)!r}, 'w').write(str(os.getpid()))\ntime.sleep(10)"
    )
    with pytest.raises(Cancelled, match="lease cancelled"):
        scan_sbom(
            _input(tmp_path), executable=binary, cache_dir=tmp_path / "db", checkpoint=checkpoint
        )
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_path.read_text()), 0)


def test_missing_executable_is_an_actionable_failure(tmp_path: Path) -> None:
    with pytest.raises(SbomScannerError, match="installed, executable Grype"):
        scan_sbom(_input(tmp_path), executable=tmp_path / "missing", cache_dir=tmp_path / "db")


def test_executable_can_be_resolved_from_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scanner(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    result = scan_sbom(_input(tmp_path), executable="scanner", cache_dir=tmp_path / "db")
    assert result.evidence.scanner_version == "0.110.0"


@pytest.mark.skipif(os.name != "posix", reason="Process groups are a POSIX facility")
def test_timeout_cleans_descendants_after_immediate_child_exits(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    code = (
        "import signal\n"
        "child = os.fork()\n"
        "if child:\n"
        "    sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(pid_path)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)"
    )
    with pytest.raises(SbomScannerError, match="time limit"):
        scan_sbom(
            _input(tmp_path),
            executable=_scanner(tmp_path, body=code),
            cache_dir=tmp_path / "db",
            timeout_seconds=2,
        )
    pid = int(pid_path.read_text())
    # The descendant is reaped by init, which can take a short scheduling interval.
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("Scanner descendant was left running after timeout")
