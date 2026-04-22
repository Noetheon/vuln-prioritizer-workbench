from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
PYTHON = sys.executable


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(SRC_PATH)
        if not existing_pythonpath
        else os.pathsep.join([str(SRC_PATH), existing_pythonpath])
    )
    return subprocess.run(
        [PYTHON, "-m", "vuln_prioritizer.cli", *args],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _assert_ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_module_entrypoint_report_evidence_bundle_round_trip(tmp_path: Path) -> None:
    analysis_file = PROJECT_ROOT / "data" / "benchmarks" / "rollup_remediation_analysis.json"
    html_file = tmp_path / "report.html"
    bundle_file = tmp_path / "evidence.zip"
    verification_file = tmp_path / "verification.json"

    html_result = _run_cli(
        "report",
        "html",
        "--input",
        str(analysis_file),
        "--output",
        str(html_file),
    )
    _assert_ok(html_result)

    bundle_result = _run_cli(
        "report",
        "evidence-bundle",
        "--input",
        str(analysis_file),
        "--output",
        str(bundle_file),
    )
    _assert_ok(bundle_result)

    verification_result = _run_cli(
        "report",
        "verify-evidence-bundle",
        "--input",
        str(bundle_file),
        "--output",
        str(verification_file),
        "--format",
        "json",
    )
    _assert_ok(verification_result)

    assert "<h1>vuln-prioritizer Executive Report</h1>" in html_file.read_text(encoding="utf-8")
    verification_payload = json.loads(verification_file.read_text(encoding="utf-8"))
    assert verification_payload["summary"]["ok"] is True
    assert verification_payload["summary"]["modified_files"] == 0
    assert verification_payload["summary"]["missing_files"] == 0


def test_module_entrypoint_attack_commands_work_offline(tmp_path: Path) -> None:
    attack_root = PROJECT_ROOT / "data" / "attack"
    mapping_file = attack_root / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
    metadata_file = attack_root / "attack_techniques_enterprise_16.1_subset.json"
    coverage_file = tmp_path / "coverage.json"
    validate_file = tmp_path / "validate.json"
    navigator_file = tmp_path / "navigator.json"

    validate_result = _run_cli(
        "attack",
        "validate",
        "--attack-mapping-file",
        str(mapping_file),
        "--attack-technique-metadata-file",
        str(metadata_file),
        "--output",
        str(validate_file),
        "--format",
        "json",
    )
    _assert_ok(validate_result)

    coverage_result = _run_cli(
        "attack",
        "coverage",
        "--input",
        str(PROJECT_ROOT / "data" / "sample_cves_mixed.txt"),
        "--attack-mapping-file",
        str(mapping_file),
        "--attack-technique-metadata-file",
        str(metadata_file),
        "--output",
        str(coverage_file),
        "--format",
        "json",
    )
    _assert_ok(coverage_result)

    navigator_result = _run_cli(
        "attack",
        "navigator-layer",
        "--input",
        str(PROJECT_ROOT / "data" / "sample_cves_attack.txt"),
        "--attack-mapping-file",
        str(mapping_file),
        "--attack-technique-metadata-file",
        str(metadata_file),
        "--output",
        str(navigator_file),
    )
    _assert_ok(navigator_result)

    validate_payload = json.loads(validate_file.read_text(encoding="utf-8"))
    coverage_payload = json.loads(coverage_file.read_text(encoding="utf-8"))
    navigator_payload = json.loads(navigator_file.read_text(encoding="utf-8"))
    assert validate_payload["source"] == "ctid-mappings-explorer"
    assert coverage_payload["summary"]["mapped_cves"] == 3
    assert coverage_payload["summary"]["unmapped_cves"] == 2
    assert navigator_payload["domain"] == "enterprise-attack"
    assert navigator_payload["techniques"]


def test_module_entrypoint_snapshot_and_state_round_trip(tmp_path: Path) -> None:
    before_file = PROJECT_ROOT / "data" / "benchmarks" / "snapshots" / "lifecycle_before.json"
    after_file = PROJECT_ROOT / "data" / "benchmarks" / "snapshots" / "lifecycle_after.json"
    diff_file = tmp_path / "diff.json"
    db_path = tmp_path / "state.db"
    import_file = tmp_path / "import.json"
    history_file = tmp_path / "history.json"
    top_services_file = tmp_path / "top-services.json"

    diff_result = _run_cli(
        "snapshot",
        "diff",
        "--before",
        str(before_file),
        "--after",
        str(after_file),
        "--output",
        str(diff_file),
        "--format",
        "json",
    )
    _assert_ok(diff_result)

    init_result = _run_cli("state", "init", "--db", str(db_path))
    _assert_ok(init_result)

    import_result = _run_cli(
        "state",
        "import-snapshot",
        "--db",
        str(db_path),
        "--input",
        str(after_file),
        "--output",
        str(import_file),
        "--format",
        "json",
    )
    _assert_ok(import_result)

    history_result = _run_cli(
        "state",
        "history",
        "--db",
        str(db_path),
        "--cve",
        "CVE-2024-2002",
        "--output",
        str(history_file),
        "--format",
        "json",
    )
    _assert_ok(history_result)

    top_services_result = _run_cli(
        "state",
        "top-services",
        "--db",
        str(db_path),
        "--days",
        "3650",
        "--output",
        str(top_services_file),
        "--format",
        "json",
    )
    _assert_ok(top_services_result)

    diff_payload = json.loads(diff_file.read_text(encoding="utf-8"))
    import_payload = json.loads(import_file.read_text(encoding="utf-8"))
    history_payload = json.loads(history_file.read_text(encoding="utf-8"))
    top_services_payload = json.loads(top_services_file.read_text(encoding="utf-8"))
    assert diff_payload["summary"]["added"] == 1
    assert diff_payload["summary"]["removed"] == 1
    assert import_payload["summary"]["imported"] is True
    assert history_payload["metadata"]["cve_id"] == "CVE-2024-2002"
    assert history_payload["items"][0]["priority_label"] == "Critical"
    assert {item["service"] for item in top_services_payload["items"]} >= {"edge-api", "payments"}
