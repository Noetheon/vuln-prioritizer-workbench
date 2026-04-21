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
    DoctorSummary,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
    PrioritizedFinding,
    RollupBucket,
    RollupCandidate,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    SnapshotMetadata,
    StateHistoryEntry,
    StateHistoryMetadata,
    StateHistoryReport,
    StateImportMetadata,
    StateImportReport,
    StateImportSummary,
    StateInitMetadata,
    StateInitReport,
    StateInitSummary,
    StateTopServiceEntry,
    StateTopServicesMetadata,
    StateTopServicesReport,
    StateWaiverEntry,
    StateWaiverMetadata,
    StateWaiverReport,
)
from vuln_prioritizer.reporter import (
    build_snapshot_report_payload,
    generate_doctor_json,
    generate_evidence_bundle_verification_json,
    generate_rollup_json,
    generate_snapshot_diff_json,
    generate_state_history_json,
    generate_state_import_json,
    generate_state_init_json,
    generate_state_top_services_json,
    generate_state_waivers_json,
)

runner = CliRunner()
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "docs" / "schemas"
ACTION_FILE = Path(__file__).resolve().parents[1] / "action.yml"
RELEASE_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
TESTPYPI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "testpypi.yml"


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
        summary=DoctorSummary(
            overall_status="degraded",
            ok_count=1,
            degraded_count=1,
            error_count=0,
        ),
        checks=[
            DoctorCheck(
                check_id="runtime.config",
                name="runtime_config",
                scope="local",
                category="config",
                status="ok",
                detail="discovered",
            ),
            DoctorCheck(
                check_id="auth.nvd_api_key",
                name="nvd_api_key",
                scope="live",
                category="auth",
                status="degraded",
                detail="NVD_API_KEY missing.",
                hint="Set NVD_API_KEY for higher rate limits.",
            ),
        ],
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


def test_evidence_bundle_verification_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_evidence_bundle_verification_json(
            [
                EvidenceBundleVerificationItem(
                    path="report.html",
                    kind="html-report",
                    status="modified",
                    detail="Archive member does not match the manifest: sha256 mismatch.",
                    expected_size_bytes=120,
                    actual_size_bytes=121,
                    expected_sha256="a" * 64,
                    actual_sha256="b" * 64,
                )
            ],
            EvidenceBundleVerificationSummary(
                ok=False,
                total_members=5,
                expected_files=4,
                verified_files=3,
                missing_files=0,
                modified_files=1,
                unexpected_files=0,
                manifest_errors=0,
            ),
            EvidenceBundleVerificationMetadata(
                generated_at="2026-04-21T12:00:00Z",
                bundle_path="/tmp/evidence.zip",
                manifest_schema_version="1.1.0",
                bundle_kind="evidence-bundle",
            ),
        )
    )

    jsonschema.validate(payload, _load_schema("evidence-bundle-verification-report.schema.json"))


def test_state_init_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_state_init_json(
            StateInitReport(
                metadata=StateInitMetadata(
                    generated_at="2026-04-21T12:00:00Z",
                    db_path="/tmp/state.db",
                ),
                summary=StateInitSummary(initialized=True, snapshot_count=2),
            )
        )
    )

    jsonschema.validate(payload, _load_schema("state-init-report.schema.json"))


def test_state_import_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_state_import_json(
            StateImportReport(
                metadata=StateImportMetadata(
                    generated_at="2026-04-21T12:00:00Z",
                    db_path="/tmp/state.db",
                    input_path="/tmp/snapshot.json",
                ),
                summary=StateImportSummary(
                    imported=False,
                    snapshot_id=4,
                    snapshot_generated_at="2026-04-20T09:00:00Z",
                    finding_count=3,
                    snapshot_count=4,
                ),
            )
        )
    )

    jsonschema.validate(payload, _load_schema("state-import-report.schema.json"))


def test_state_history_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_state_history_json(
            StateHistoryReport(
                metadata=StateHistoryMetadata(
                    generated_at="2026-04-21T12:00:00Z",
                    db_path="/tmp/state.db",
                    cve_id="CVE-2024-0001",
                    entry_count=1,
                ),
                items=[
                    StateHistoryEntry(
                        snapshot_generated_at="2026-04-20T09:00:00Z",
                        snapshot_path="/tmp/after.json",
                        input_path="/tmp/input.txt",
                        priority_label="Critical",
                        priority_rank=1,
                        in_kev=True,
                        waived=False,
                        waiver_status=None,
                        waiver_owner=None,
                        services=["identity"],
                        asset_ids=["asset-01"],
                    )
                ],
            )
        )
    )

    jsonschema.validate(payload, _load_schema("state-history-report.schema.json"))


def test_state_waivers_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_state_waivers_json(
            StateWaiverReport(
                metadata=StateWaiverMetadata(
                    generated_at="2026-04-21T12:00:00Z",
                    db_path="/tmp/state.db",
                    status_filter="review_due",
                    latest_only=True,
                    entry_count=1,
                ),
                items=[
                    StateWaiverEntry(
                        snapshot_generated_at="2026-04-20T09:00:00Z",
                        snapshot_path="/tmp/latest.json",
                        cve_id="CVE-2024-0001",
                        priority_label="High",
                        waiver_status="review_due",
                        waiver_owner="risk-review",
                        waiver_expires_on="2026-05-01",
                        waiver_review_on="2026-04-15",
                        waiver_days_remaining=10,
                    )
                ],
            )
        )
    )

    jsonschema.validate(payload, _load_schema("state-waivers-report.schema.json"))


def test_state_top_services_json_matches_published_schema() -> None:
    payload = json.loads(
        generate_state_top_services_json(
            StateTopServicesReport(
                metadata=StateTopServicesMetadata(
                    generated_at="2026-04-21T12:00:00Z",
                    db_path="/tmp/state.db",
                    days=30,
                    priority_filter="critical",
                    limit=5,
                    entry_count=1,
                ),
                items=[
                    StateTopServiceEntry(
                        service="identity",
                        occurrence_count=3,
                        distinct_cves=2,
                        snapshot_count=2,
                        kev_count=1,
                        latest_seen="2026-04-20T09:00:00Z",
                    )
                ],
            )
        )
    )

    jsonschema.validate(payload, _load_schema("state-top-services-report.schema.json"))


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
    assert "summary-template" in inputs
    assert "summary-path" in outputs
    assert "github-step-summary" in inputs
    assert "--config" in run_block
    assert "--no-config" in run_block
    assert "--summary-output" in run_block
    assert "render_compact_summary" in run_block
    assert "$RUNNER_TEMP/vuln-prioritizer-summary.md" in run_block
    assert "$GITHUB_STEP_SUMMARY" in run_block


def test_release_workflow_is_tag_bound_and_verifies_pypi_install() -> None:
    payload = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    jobs = payload["jobs"]
    build_steps = jobs["build-and-release"]["steps"]
    github_release_steps = [
        step for step in build_steps if step.get("uses") == "softprops/action-gh-release@v3"
    ]

    assert github_release_steps
    assert all(
        "startsWith(github.ref, 'refs/tags/v')" in step["if"] for step in github_release_steps
    )
    assert "startsWith(github.ref, 'refs/tags/v')" in jobs["publish-pypi"]["if"]
    assert "PYPI_PUBLISH_ENABLED" in jobs["publish-pypi"]["if"]

    verify_job = jobs["verify-pypi-install"]
    assert verify_job["needs"] == "publish-pypi"
    assert "startsWith(github.ref, 'refs/tags/v')" in verify_job["if"]
    verify_run = verify_job["steps"][-1]["run"]
    assert 'version="${GITHUB_REF_NAME#v}"' in verify_run
    assert 'python -m pip install --force-reinstall "vuln-prioritizer==${version}"' in verify_run
    assert "vuln-prioritizer --help" in verify_run
    assert "vuln-prioritizer doctor --format json --output doctor.json" in verify_run


def test_testpypi_workflow_exposes_version_output_and_hosted_index_verification() -> None:
    payload = yaml.safe_load(TESTPYPI_WORKFLOW.read_text(encoding="utf-8"))
    jobs = payload["jobs"]

    assert (
        jobs["build"]["outputs"]["package_version"]
        == "${{ steps.package_version.outputs.version }}"
    )
    build_steps = jobs["build"]["steps"]
    version_step = next(step for step in build_steps if step.get("id") == "package_version")
    assert "payload['project']['version']" in version_step["run"]

    verify_job = jobs["verify-testpypi-install"]
    assert verify_job["needs"] == ["build", "publish-testpypi"]
    assert "TEST_PYPI_PUBLISH_ENABLED" in verify_job["if"]
    verify_run = verify_job["steps"][-1]["run"]
    assert "needs.build.outputs.package_version" in verify_run
    assert "--index-url https://test.pypi.org/simple/" in verify_run
    assert "--extra-index-url https://pypi.org/simple/" in verify_run
    assert "python -m pip install --force-reinstall \\" in verify_run
    assert "vuln-prioritizer --help" in verify_run
    assert "vuln-prioritizer doctor --format json --output doctor.json" in verify_run
