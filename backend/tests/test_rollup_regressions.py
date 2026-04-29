from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from vuln_prioritizer.cli import app

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
