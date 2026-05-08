from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import typer
from typer.testing import CliRunner

from vuln_prioritizer.cli import app
from vuln_prioritizer.cli_support import snapshot_rollup

runner = CliRunner()
BENCHMARK_ROOT = Path(__file__).resolve().parents[2] / "data" / "benchmarks"
SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "docs" / "schemas"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def test_rollup_remediation_fixture_covers_ordering_and_multi_bucket_findings(
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "rollup.json"

    result = runner.invoke(
        app,
        [
            "rollup",
            "--input",
            str(BENCHMARK_ROOT / "rollup_remediation_analysis.json"),
            "--by",
            "service",
            "--top",
            "2",
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("rollup-report.schema.json"))

    assert payload["metadata"]["schema_version"] == "1.2.0"
    assert payload["metadata"]["top"] == 2
    assert [bucket["bucket"] for bucket in payload["buckets"]] == [
        "shared",
        "identity",
        "Unmapped",
        "payments",
    ]
    assert [bucket["remediation_rank"] for bucket in payload["buckets"]] == [1, 2, 3, 4]

    buckets = {bucket["bucket"]: bucket for bucket in payload["buckets"]}
    assert buckets["shared"]["top_cves"] == ["CVE-2025-1000", "CVE-2025-2000"]
    assert buckets["identity"]["top_cves"] == ["CVE-2025-1000"]
    assert buckets["Unmapped"]["top_cves"] == ["CVE-2025-4000"]
    assert buckets["payments"]["actionable_count"] == 0
    assert "risk-review" in buckets["payments"]["owners"]
    assert any(hint.startswith("waiver owners:") for hint in buckets["payments"]["context_hints"])
    assert buckets["payments"]["top_candidates"][0]["waived"] is True
    assert buckets["shared"]["top_candidates"][0]["cve_id"] == "CVE-2025-1000"
    assert buckets["identity"]["top_candidates"][0]["cve_id"] == "CVE-2025-1000"


def test_rollup_supports_owner_exposure_environment_and_component_dimensions(
    tmp_path: Path,
) -> None:
    source_payload = json.loads(
        (BENCHMARK_ROOT / "rollup_remediation_analysis.json").read_text(encoding="utf-8")
    )
    source_payload["findings"][0]["provenance"]["components"] = ["django", "openssl"]
    input_file = tmp_path / "analysis-with-components.json"
    input_file.write_text(json.dumps(source_payload, indent=2) + "\n", encoding="utf-8")

    expected_buckets = {
        "owner": {"team-identity", "team-shared", "team-payments", "risk-review", "Unmapped"},
        "exposure": {"internet-facing", "internal", "Unmapped"},
        "environment": {"prod", "stage", "Unmapped"},
        "component": {"django", "openssl", "Unmapped"},
    }

    for dimension, expected in expected_buckets.items():
        output_file = tmp_path / f"rollup-{dimension}.json"
        result = runner.invoke(
            app,
            [
                "rollup",
                "--input",
                str(input_file),
                "--by",
                dimension,
                "--format",
                "json",
                "--output",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(output_file.read_text(encoding="utf-8"))
        assert payload["metadata"]["dimension"] == dimension
        assert {bucket["bucket"] for bucket in payload["buckets"]} == expected


def test_rollup_support_helpers_validate_payload_and_json_edges(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{bad", encoding="utf-8")
    with pytest.raises(typer.Exit) as invalid_json_exit:
        snapshot_rollup.load_json_document_or_exit(invalid_json)
    assert invalid_json_exit.value.exit_code == 2

    top_level_list = tmp_path / "list.json"
    top_level_list.write_text("[]", encoding="utf-8")
    with pytest.raises(typer.Exit) as list_exit:
        snapshot_rollup.load_json_document_or_exit(top_level_list)
    assert list_exit.value.exit_code == 2

    bad_snapshot = tmp_path / "bad-snapshot.json"
    bad_snapshot.write_text(json.dumps({"metadata": {}, "findings": []}), encoding="utf-8")
    with pytest.raises(typer.Exit) as snapshot_exit:
        snapshot_rollup.load_snapshot_payload(bad_snapshot)
    assert snapshot_exit.value.exit_code == 2

    bad_rollup = tmp_path / "bad-rollup.json"
    bad_rollup.write_text(json.dumps({"metadata": {}}), encoding="utf-8")
    with pytest.raises(typer.Exit) as rollup_exit:
        snapshot_rollup.load_rollup_payload(bad_rollup)
    assert rollup_exit.value.exit_code == 2

    snapshot_payload = json.loads(
        (BENCHMARK_ROOT / "snapshots" / "lifecycle_before.json").read_text(encoding="utf-8")
    )
    snapshot_payload["findings"][0] = "not-an-object"
    with pytest.raises(ValueError, match="Snapshot finding #1"):
        snapshot_rollup.validate_snapshot_payload(snapshot_payload)


def test_rollup_helpers_cover_unmapped_and_contextual_reason_edges() -> None:
    finding = {
        "cve_id": "CVE-2025-0001",
        "priority_label": "High",
        "priority_rank": 2,
        "in_kev": True,
        "under_investigation": True,
        "waiver_status": "review_due",
        "provenance": {
            "occurrences": [
                {
                    "asset_owner": "team-platform",
                    "asset_exposure": "internet-facing",
                    "asset_environment": "production",
                }
            ]
        },
        "recommended_action": "",
    }
    expired = {
        **finding,
        "cve_id": "CVE-2025-0002",
        "in_kev": False,
        "under_investigation": False,
        "waiver_status": "expired",
        "waived": False,
        "provenance": {"occurrences": []},
    }
    waived = {
        **finding,
        "cve_id": "CVE-2025-0003",
        "in_kev": False,
        "under_investigation": False,
        "waiver_status": "accepted",
        "waived": True,
        "waiver_owner": "risk-review",
        "provenance": {"occurrences": []},
    }

    assert snapshot_rollup.rollup_bucket_names(finding, dimension="unknown") == ["Unmapped"]
    assert snapshot_rollup.finding_top_actions([finding], top=3) == []
    assert snapshot_rollup.finding_exposures(finding) == ["internet-facing"]
    assert snapshot_rollup.finding_environments(finding) == ["production"]
    assert snapshot_rollup.string_or_none(None) is None
    assert snapshot_rollup.string_or_none("   ") is None
    assert snapshot_rollup.string_or_none(" Prod ", lowercase=True) == "prod"

    hints = snapshot_rollup.rollup_bucket_context_hints([finding, expired, waived])
    assert "1 under investigation" in hints
    assert "1 waiver review due" in hints
    assert "1 waiver expired" in hints
    assert "waiver owners: risk-review" in hints

    assert snapshot_rollup.rollup_bucket_rank_reason(
        findings=[waived],
        actionable_findings=[],
        highest_priority="High",
    ).startswith("No actionable findings remain")
    assert "expired waiver(s)" in snapshot_rollup.rollup_bucket_rank_reason(
        findings=[finding, expired],
        actionable_findings=[finding],
        highest_priority="High",
    )
    assert snapshot_rollup.rollup_candidate_reason(finding).endswith("waiver review due")
    assert snapshot_rollup.rollup_candidate_reason(expired).endswith("waiver expired")
    assert snapshot_rollup.rollup_candidate_reason(waived).endswith("waived by risk-review")
