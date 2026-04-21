from __future__ import annotations

import json
import zipfile
from pathlib import Path

import jsonschema
import yaml
from test_cli import _install_fake_providers, _write_input_file
from typer.testing import CliRunner

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import (
    DoctorCheck,
    DoctorReport,
    PrioritizedFinding,
    RollupBucket,
    RollupCandidate,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    SnapshotMetadata,
)
from vuln_prioritizer.reporter import (
    build_snapshot_report_payload,
    generate_doctor_json,
    generate_rollup_json,
    generate_snapshot_diff_json,
)

runner = CliRunner()
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "docs" / "schemas"
ACTION_FILE = Path(__file__).resolve().parents[1] / "action.yml"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def _sample_finding() -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id="CVE-2024-0001",
        priority_label="High",
        priority_rank=2,
        rationale="High EPSS with a visible remediation path.",
        recommended_action="Patch immediately.",
        waived=True,
        waiver_reason="Approved until the next maintenance window.",
        waiver_owner="risk-review",
        waiver_expires_on="2027-12-31",
        waiver_scope="global",
    )


def test_summary_markdown_sidecar_is_emitted(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    summary_file = tmp_path / "summary.md"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--summary-output",
            str(summary_file),
        ],
    )

    assert result.exit_code == 0
    summary = summary_file.read_text(encoding="utf-8")
    assert "# Vulnerability Prioritization Summary" in summary
    assert "- Findings shown: 4" in summary
    assert "- ATT&CK mapped CVEs: 0" in summary


def test_doctor_json_matches_published_schema() -> None:
    report = DoctorReport(
        generated_at="2026-04-21T12:00:00Z",
        live=True,
        config_file="/tmp/vuln-prioritizer.yml",
        checks=[DoctorCheck(name="runtime_config", status="ok", detail="discovered")],
    )

    payload = json.loads(generate_doctor_json(report))
    jsonschema.validate(payload, _load_schema("doctor-report.schema.json"))


def test_snapshot_json_matches_published_schema() -> None:
    metadata = SnapshotMetadata(
        input_path="data/sample_cves_mixed.txt",
        output_format="json",
        generated_at="2026-04-21T12:00:00Z",
        config_file="/tmp/vuln-prioritizer.yml",
    )
    payload = build_snapshot_report_payload([_sample_finding()], metadata)

    jsonschema.validate(payload, _load_schema("snapshot-report.schema.json"))


def test_snapshot_diff_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_snapshot_diff_json(
            [
                SnapshotDiffItem(
                    cve_id="CVE-2024-0001",
                    category="context_changed",
                    before_priority="Medium",
                    after_priority="High",
                    before_rank=3,
                    after_rank=2,
                    before_targets=["host:old"],
                    after_targets=["host:new"],
                    before_asset_ids=["asset-1"],
                    after_asset_ids=["asset-2"],
                    before_services=["service-a"],
                    after_services=["service-b"],
                    context_change_fields=["targets", "asset_ids"],
                )
            ],
            SnapshotDiffSummary(
                added=0,
                removed=0,
                priority_up=1,
                priority_down=0,
                context_changed=1,
                unchanged=0,
            ),
            SnapshotDiffMetadata(
                generated_at="2026-04-21T12:00:00Z",
                before_path="before.json",
                after_path="after.json",
                include_unchanged=True,
            ),
        )
    )

    jsonschema.validate(payload, _load_schema("snapshot-diff-report.schema.json"))


def test_rollup_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_rollup_json(
            [
                RollupBucket(
                    bucket="host:app-01",
                    dimension="asset",
                    remediation_rank=1,
                    finding_count=2,
                    actionable_count=1,
                    critical_count=1,
                    high_count=1,
                    kev_count=1,
                    attack_mapped_count=1,
                    waived_count=1,
                    internet_facing_count=1,
                    production_count=1,
                    highest_priority="Critical",
                    rank_reason="Ranked by highest actionable priority Critical and 1 KEV finding.",
                    context_hints=["1 KEV", "1 internet-facing"],
                    owners=["team-platform"],
                    top_cves=["CVE-2021-44228", "CVE-2024-0001"],
                    recommended_actions=["Patch immediately."],
                    top_candidates=[
                        RollupCandidate(
                            cve_id="CVE-2021-44228",
                            priority_label="Critical",
                            waived=False,
                            in_kev=True,
                            highest_asset_criticality="Critical",
                            highest_asset_exposure="internet-facing",
                            asset_ids=["host:app-01"],
                            services=["identity"],
                            owners=["team-platform"],
                            recommended_action="Patch immediately.",
                            rank_reason="Critical, KEV, internet-facing, Critical criticality",
                        )
                    ],
                )
            ],
            RollupMetadata(
                generated_at="2026-04-21T12:00:00Z",
                input_path="analysis.json",
                input_kind="analysis",
                dimension="asset",
                bucket_count=1,
                top=5,
            ),
        )
    )

    jsonschema.validate(payload, _load_schema("rollup-report.schema.json"))


def test_evidence_bundle_manifest_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
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
    with zipfile.ZipFile(bundle_file) as archive:
        names = set(archive.namelist())
        assert {"analysis.json", "report.html", "summary.md", "manifest.json"} <= names
        assert any(name.startswith("input/") for name in names)
        manifest = json.loads(archive.read("manifest.json"))

    jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
    assert manifest["included_input_copy"] is True


def test_action_contract_exposes_summary_and_config_wiring() -> None:
    payload = yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))
    inputs = payload["inputs"]
    outputs = payload["outputs"]
    run_step = next(
        step for step in payload["runs"]["steps"] if step.get("name") == "Run vuln-prioritizer"
    )
    run_block = run_step["run"]

    assert "config-file" in inputs
    assert "no-config" in inputs
    assert "summary-output-path" in inputs
    assert "summary-path" in outputs
    assert "github-step-summary" in inputs
    assert "--config" in run_block
    assert "--no-config" in run_block
    assert "--summary-output" in run_block
    assert "$GITHUB_STEP_SUMMARY" in run_block
