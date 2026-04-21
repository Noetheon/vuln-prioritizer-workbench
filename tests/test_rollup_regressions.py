from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from vuln_prioritizer.cli import app

runner = CliRunner()
BENCHMARK_ROOT = Path(__file__).resolve().parents[1] / "data" / "benchmarks"
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "docs" / "schemas"


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
