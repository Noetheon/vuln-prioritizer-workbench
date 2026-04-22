from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import generate_provider_snapshot_json

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


def _write_provider_snapshot(snapshot_file: Path, input_file: Path) -> None:
    snapshot_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    generated_at="2026-04-22T12:00:00Z",
                    input_path=str(input_file),
                    input_paths=[str(input_file)],
                    input_format="cve-list",
                    selected_sources=["nvd", "epss", "kev"],
                    requested_cves=2,
                    output_path=str(snapshot_file),
                    cache_enabled=False,
                ),
                items=[
                    ProviderSnapshotItem(
                        cve_id="CVE-2021-44228",
                        nvd=NvdData(
                            cve_id="CVE-2021-44228",
                            description="Log4Shell",
                            cvss_base_score=10.0,
                            cvss_severity="CRITICAL",
                            cvss_version="3.1",
                        ),
                        epss=EpssData(
                            cve_id="CVE-2021-44228",
                            epss=0.97,
                            percentile=0.999,
                            date="2026-04-20",
                        ),
                        kev=KevData(cve_id="CVE-2021-44228", in_kev=True),
                    ),
                    ProviderSnapshotItem(
                        cve_id="CVE-2023-44487",
                        nvd=NvdData(
                            cve_id="CVE-2023-44487",
                            description="HTTP/2 Rapid Reset",
                            cvss_base_score=7.5,
                            cvss_severity="HIGH",
                            cvss_version="3.1",
                        ),
                        epss=EpssData(
                            cve_id="CVE-2023-44487",
                            epss=0.42,
                            percentile=0.91,
                            date="2026-04-20",
                        ),
                        kev=KevData(cve_id="CVE-2023-44487", in_kev=False),
                    ),
                ],
            )
        ),
        encoding="utf-8",
    )


def _write_p2_provider_snapshot(snapshot_file: Path) -> None:
    snapshot_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    generated_at="2026-04-22T12:00:00Z",
                    input_path="github_alerts_export.json",
                    input_paths=["github_alerts_export.json"],
                    input_format="github-alerts-json",
                    selected_sources=["nvd", "epss", "kev"],
                    requested_cves=1,
                    output_path=str(snapshot_file),
                    cache_enabled=False,
                ),
                items=[
                    ProviderSnapshotItem(
                        cve_id="CVE-2023-34362",
                        nvd=NvdData(
                            cve_id="CVE-2023-34362",
                            description="MOVEit Transfer SQL injection",
                            cvss_base_score=9.8,
                            cvss_severity="CRITICAL",
                            cvss_version="3.1",
                        ),
                        epss=EpssData(
                            cve_id="CVE-2023-34362",
                            epss=0.943,
                            percentile=0.999,
                            date="2026-04-20",
                        ),
                        kev=KevData(
                            cve_id="CVE-2023-34362",
                            in_kev=True,
                            vendor_project="Progress",
                            product="MOVEit Transfer",
                        ),
                    )
                ],
            )
        ),
        encoding="utf-8",
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


def test_module_entrypoint_locked_provider_snapshot_round_trip(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")
    snapshot_file = tmp_path / "provider-snapshot.json"
    _write_provider_snapshot(snapshot_file, input_file)

    analysis_file = tmp_path / "analysis.json"
    compare_file = tmp_path / "compare.json"
    explain_file = tmp_path / "explain.json"
    snapshot_output_file = tmp_path / "snapshot.json"

    analysis_result = _run_cli(
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
    )
    _assert_ok(analysis_result)

    compare_result = _run_cli(
        "compare",
        "--input",
        str(input_file),
        "--output",
        str(compare_file),
        "--format",
        "json",
        "--provider-snapshot-file",
        str(snapshot_file),
        "--locked-provider-data",
    )
    _assert_ok(compare_result)

    explain_result = _run_cli(
        "explain",
        "--cve",
        "CVE-2021-44228",
        "--output",
        str(explain_file),
        "--format",
        "json",
        "--provider-snapshot-file",
        str(snapshot_file),
        "--locked-provider-data",
    )
    _assert_ok(explain_result)

    snapshot_result = _run_cli(
        "snapshot",
        "create",
        "--input",
        str(input_file),
        "--output",
        str(snapshot_output_file),
        "--format",
        "json",
        "--provider-snapshot-file",
        str(snapshot_file),
        "--locked-provider-data",
    )
    _assert_ok(snapshot_result)

    analysis_payload = json.loads(analysis_file.read_text(encoding="utf-8"))
    compare_payload = json.loads(compare_file.read_text(encoding="utf-8"))
    explain_payload = json.loads(explain_file.read_text(encoding="utf-8"))
    snapshot_payload = json.loads(snapshot_output_file.read_text(encoding="utf-8"))

    assert analysis_payload["metadata"]["locked_provider_data"] is True
    assert analysis_payload["metadata"]["provider_snapshot_sources"] == ["nvd", "epss", "kev"]
    assert len(analysis_payload["findings"]) == 2

    assert compare_payload["metadata"]["locked_provider_data"] is True
    assert compare_payload["metadata"]["provider_snapshot_sources"] == ["nvd", "epss", "kev"]
    assert len(compare_payload["comparisons"]) == 2

    assert explain_payload["metadata"]["locked_provider_data"] is True
    assert explain_payload["metadata"]["provider_snapshot_sources"] == ["nvd", "epss", "kev"]
    assert explain_payload["finding"]["cve_id"] == "CVE-2021-44228"

    assert snapshot_payload["metadata"]["locked_provider_data"] is True
    assert snapshot_payload["metadata"]["provider_snapshot_sources"] == ["nvd", "epss", "kev"]
    assert len(snapshot_payload["findings"]) == 2


def test_module_entrypoint_p2_context_round_trip(tmp_path: Path) -> None:
    input_file = PROJECT_ROOT / "data" / "input_fixtures" / "github_alerts_export.json"
    asset_context_file = tmp_path / "asset-context.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence,criticality,owner,business_service",
                "glob-rule,repository,*requirements.txt,asset-glob,glob,10,medium,team-platform,identity",
                "exact-rule,repository,backend/requirements.txt,asset-exact,exact,10,critical,team-platform,identity",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    vex_file = tmp_path / "vex.json"
    vex_file.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2023-34362"},
                        "status": "under_investigation",
                        "products": [
                            {
                                "subcomponents": [
                                    {"kind": "repository", "name": "backend/requirements.txt"}
                                ]
                            }
                        ],
                    },
                    {
                        "vulnerability": {"name": "CVE-2023-34362"},
                        "status": "fixed",
                        "products": [
                            {
                                "subcomponents": [
                                    {"kind": "repository", "name": "backend/requirements.txt"}
                                ]
                            }
                        ],
                    },
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    snapshot_file = tmp_path / "provider-snapshot.json"
    _write_p2_provider_snapshot(snapshot_file)

    analysis_file = tmp_path / "analysis.json"
    compare_file = tmp_path / "compare.json"
    explain_file = tmp_path / "explain.json"
    snapshot_output_file = tmp_path / "snapshot.json"
    rollup_file = tmp_path / "rollup.json"

    common_args = [
        "--asset-context",
        str(asset_context_file),
        "--vex-file",
        str(vex_file),
        "--provider-snapshot-file",
        str(snapshot_file),
        "--locked-provider-data",
    ]

    analysis_result = _run_cli(
        "analyze",
        "--input",
        str(input_file),
        "--input-format",
        "github-alerts-json",
        *common_args,
        "--output",
        str(analysis_file),
        "--format",
        "json",
    )
    _assert_ok(analysis_result)

    compare_result = _run_cli(
        "compare",
        "--input",
        str(input_file),
        "--input-format",
        "github-alerts-json",
        *common_args,
        "--output",
        str(compare_file),
        "--format",
        "json",
    )
    _assert_ok(compare_result)

    explain_result = _run_cli(
        "explain",
        "--cve",
        "CVE-2023-34362",
        *common_args,
        "--target-kind",
        "repository",
        "--target-ref",
        "backend/requirements.txt",
        "--output",
        str(explain_file),
        "--format",
        "json",
    )
    _assert_ok(explain_result)

    snapshot_result = _run_cli(
        "snapshot",
        "create",
        "--input",
        str(input_file),
        "--input-format",
        "github-alerts-json",
        *common_args,
        "--output",
        str(snapshot_output_file),
        "--format",
        "json",
    )
    _assert_ok(snapshot_result)

    rollup_result = _run_cli(
        "rollup",
        "--input",
        str(snapshot_output_file),
        "--by",
        "asset",
        "--output",
        str(rollup_file),
        "--format",
        "json",
    )
    _assert_ok(rollup_result)

    analysis_payload = json.loads(analysis_file.read_text(encoding="utf-8"))
    compare_payload = json.loads(compare_file.read_text(encoding="utf-8"))
    explain_payload = json.loads(explain_file.read_text(encoding="utf-8"))
    snapshot_payload = json.loads(snapshot_output_file.read_text(encoding="utf-8"))
    rollup_payload = json.loads(rollup_file.read_text(encoding="utf-8"))

    finding = analysis_payload["findings"][0]
    occurrence = next(
        item
        for item in finding["provenance"]["occurrences"]
        if item["target_ref"] == "backend/requirements.txt"
    )
    assert analysis_payload["metadata"]["asset_match_conflict_count"] == 1
    assert analysis_payload["metadata"]["vex_conflict_count"] == 1
    assert finding["remediation"]["strategy"] == "upgrade"
    assert finding["remediation"]["components"][0]["fixed_versions"] == ["2023.0.2"]
    assert occurrence["asset_id"] == "asset-exact"
    assert occurrence["asset_match_rule_id"] == "exact-rule"
    assert occurrence["vex_status"] == "under_investigation"
    assert occurrence["vex_match_type"] == "target"

    assert compare_payload["comparisons"][0]["under_investigation"] is True
    assert compare_payload["metadata"]["vex_conflict_count"] == 1

    assert any(
        "Asset context resolved" in warning for warning in explain_payload["metadata"]["warnings"]
    )
    assert any("VEX resolved" in warning for warning in explain_payload["metadata"]["warnings"])
    explain_occurrence = explain_payload["finding"]["provenance"]["occurrences"][0]
    assert explain_occurrence["asset_match_rule_id"] == "exact-rule"
    assert explain_occurrence["vex_status"] == "under_investigation"

    assert snapshot_payload["metadata"]["snapshot_kind"] == "snapshot"
    assert snapshot_payload["findings"][0]["remediation"]["strategy"] == "upgrade"

    assert rollup_payload["metadata"]["dimension"] == "asset"
    assert rollup_payload["buckets"][0]["bucket"] == "asset-exact"
    assert rollup_payload["buckets"][0]["top_candidates"][0]["remediation"]["strategy"] == "upgrade"
