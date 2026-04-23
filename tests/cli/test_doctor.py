from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vuln_prioritizer.cli import app


def test_cli_doctor_fails_cleanly_for_missing_runtime_config(
    compact_output,
    runner,
    tmp_path: Path,
) -> None:
    missing_config = tmp_path / "missing-runtime-config.yml"

    result = runner.invoke(
        app,
        [
            "--config",
            str(missing_config),
            "doctor",
        ],
    )

    assert result.exit_code == 2
    assert "Input validation failed:" in result.stdout
    assert missing_config.name in compact_output(result.stdout)
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.stdout


def test_cli_doctor_json_reports_healthy_local_state(runner, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor.json"

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["schema_version"] == "1.2.0"
    assert payload["summary"]["overall_status"] == "ok"
    assert checks["runtime.python"]["status"] == "ok"
    assert checks["runtime.python"]["category"] == "runtime"
    assert checks["runtime.config"]["status"] == "ok"
    assert checks["cache.nvd"]["status"] == "ok"
    assert checks["cache.epss"]["status"] == "ok"
    assert checks["cache.kev"]["status"] == "ok"


def test_cli_doctor_reports_missing_files_as_degraded(runner, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor.json"
    missing_mapping = tmp_path / "missing-mapping.json"

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--attack-mapping-file",
            str(missing_mapping),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "error"
    assert checks["path.attack_mapping_file"]["status"] == "error"
    assert checks["attack.validation"]["status"] == "error"


def test_cli_doctor_reports_waiver_health(
    runner,
    tmp_path: Path,
    write_waiver_file,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-waivers.json"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Needs formal review.",
        expires_on="2026-04-25",
        review_on="2026-04-20",
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["path.waiver_file"]["status"] == "ok"
    assert checks["waiver.health"]["status"] == "degraded"
    assert "review due" in checks["waiver.health"]["detail"]


def test_cli_doctor_marks_dirty_cache_namespaces_as_degraded(
    runner,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-cache.json"
    expired_cache = cache_dir / "nvd" / "expired.json"
    expired_cache.parent.mkdir(parents=True, exist_ok=True)
    expired_cache.write_text(
        json.dumps(
            {
                "key": "CVE-2026-0001",
                "cached_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                "payload": {"value": 1},
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--cache-ttl-hours",
            "1",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["cache.nvd"]["status"] == "degraded"
    assert "expired" in checks["cache.nvd"]["detail"]


def test_cli_doctor_rejects_invalid_discovered_runtime_config(
    compact_output,
    runner,
    monkeypatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (tmp_path / "vuln-prioritizer.yml").write_text("version: [broken\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
        ],
    )

    assert result.exit_code == 2
    assert "Input validation failed:" in result.stdout
    assert "vuln-prioritizer.yml" in compact_output(result.stdout)


def test_cli_doctor_live_mode_runs_reachability_probes(
    runner,
    monkeypatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-live.json"

    class _FakeResponse:
        def __init__(self, status_code: int = 200) -> None:
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

    def fake_get(url, params=None, timeout=5):  # noqa: ANN001
        return _FakeResponse()

    monkeypatch.setattr("vuln_prioritizer.cli_support.doctor_support.requests.get", fake_get)
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--live",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "ok"
    assert checks["auth.nvd_api_key"]["status"] == "ok"
    assert checks["live.nvd_api"]["status"] == "ok"
    assert checks["live.epss_api"]["status"] == "ok"
    assert checks["live.kev_feed"]["status"] == "ok"


def test_cli_doctor_live_mode_warns_when_nvd_api_key_is_missing(
    runner,
    monkeypatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-live-warn.json"

    class _FakeResponse:
        def __init__(self, status_code: int = 200) -> None:
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

    def fake_get(url, params=None, timeout=5):  # noqa: ANN001
        return _FakeResponse()

    monkeypatch.setattr("vuln_prioritizer.cli_support.doctor_support.requests.get", fake_get)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--live",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["auth.nvd_api_key"]["status"] == "degraded"
    assert "anonymous rate limits" in checks["auth.nvd_api_key"]["detail"]
