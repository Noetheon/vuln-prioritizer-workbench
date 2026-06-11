from __future__ import annotations

import json
import uuid
import zipfile
from collections import Counter
from dataclasses import replace
from datetime import timedelta
from io import BytesIO
from pathlib import Path
from typing import Any

from sqlmodel import Session, col, select
from utils.workbench_env import WorkbenchApiEnv, local_api_headers

from app.domain.engine.providers.curated_attack_mappings import CuratedAttackMappingProvider
from app.models.base import get_datetime_utc
from app.services.demo_workspace import _demo_data_dir

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEMO_PROJECT_NAME = "Online Shop Demo Workspace"
EXPECTED_REPORT_FILENAMES = {
    "technical-report.md",
    "executive-report.html",
    "analysis-result.v2.json",
    "findings.csv",
    "attack-navigator-layer.json",
    "results.sarif",
    "evidence-bundle.zip",
}


def test_demo_workspace_status_is_disabled_by_default(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)

    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)
    seed_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is False
    assert status_response.json()["seeded"] is False
    assert seed_response.status_code == 403


def test_demo_workspace_fixture_root_follows_attack_artifact_parent(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    mounted_data = tmp_path / "mounted-data"
    input_fixtures = mounted_data / "input_fixtures"
    input_fixtures.mkdir(parents=True)
    (mounted_data / "attack").mkdir()
    (input_fixtures / "demo_workspace_occurrences.csv").write_text("cve_id\n", encoding="utf-8")
    (input_fixtures / "demo_workspace_openvex.json").write_text("{}", encoding="utf-8")

    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        ATTACK_ARTIFACT_DIR=str(mounted_data / "attack"),
    )

    assert _demo_data_dir(active_settings) == mounted_data


def test_demo_attack_mapping_fixture_stays_reviewed_defensive_context_only() -> None:
    mapping_path = PROJECT_ROOT / "data" / "attack" / "local_curated_demo_mappings.yml"
    text = mapping_path.read_text(encoding="utf-8").lower()

    for forbidden in ("exploit", "exploitation", "payload", "proof-of-concept", "poc"):
        assert forbidden not in text

    bundle = CuratedAttackMappingProvider().load(mapping_path)
    mappings = [mapping for group in bundle.mappings_by_cve.values() for mapping in group]

    assert mappings
    assert {mapping.mapping_type for mapping in mappings} == {"detection_context"}
    assert {mapping.review_status for mapping in mappings} == {"reviewed"}
    assert all(mapping.source == "local-curated" for mapping in mappings)


def test_demo_workspace_can_be_seeded_reset_and_removed(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)

    first_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert first_response.status_code == 200
    payload = first_response.json()
    project_id = payload["project"]["id"]
    first_run_id = payload["latest_run"]["id"]
    assert payload["enabled"] is True
    assert payload["seeded"] is True
    assert payload["project"]["name"] == "Online Shop Demo Workspace"
    assert payload["finding_count"] == 24
    assert payload["asset_count"] == 21
    assert payload["waiver_count"] == 4
    assert payload["report_count"] == 7
    assert "result" not in payload["latest_run"]
    assert payload["latest_run"]["evidence"]["schema_version"] == "analysis-evidence.v2"
    assert payload["latest_run"]["workflow"]["kind"] == "import"
    assert payload["latest_run"]["workflow"]["status"] == "succeeded"
    assert "summary_json" not in payload["latest_run"]
    assert "error_json" not in payload["latest_run"]
    assert {report["filename"] for report in payload["reports"]} >= {
        "technical-report.md",
        "executive-report.html",
        "analysis-result.v2.json",
        "findings.csv",
        "attack-navigator-layer.json",
        "results.sarif",
        "evidence-bundle.zip",
    }
    assert all(report["workflow"]["kind"] == "report_generation" for report in payload["reports"])
    assert all(report["workflow"]["status"] == "succeeded" for report in payload["reports"])

    projects_response = workbench_api_env.client.get("/api/v1/projects/", headers=headers)
    findings_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/findings/?limit=100",
        headers=headers,
    )
    assets_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/assets/",
        headers=headers,
    )
    waivers_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/waivers/",
        headers=headers,
    )
    reports_response = workbench_api_env.client.get(
        f"/api/v1/runs/{first_run_id}/reports",
        headers=headers,
    )
    dashboard_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/dashboard",
        headers=headers,
    )
    governance_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/governance/rollups/?limit=20",
        headers=headers,
    )
    attack_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/attack/summary",
        headers=headers,
    )

    assert projects_response.status_code == 200
    assert projects_response.json()["count"] == 1
    assert findings_response.status_code == 200
    assert findings_response.json()["count"] == 24
    findings = findings_response.json()["data"]
    assert sum(1 for finding in findings if finding["waived"]) == 4
    assert sum(1 for finding in findings if finding["suppressed_by_vex"]) == 2
    assert {finding["status"] for finding in findings} >= {
        "accepted",
        "fixed",
        "open",
        "suppressed",
    }
    assert assets_response.status_code == 200
    assert assets_response.json()["count"] == 21
    assert waivers_response.status_code == 200
    assert waivers_response.json()["count"] == 4
    assert governance_response.status_code == 200
    waiver_debt = governance_response.json()["waiver_debt"]
    assert waiver_debt["waiver_count"] == 4
    assert waiver_debt["active_count"] == 3
    assert waiver_debt["review_due_count"] == 1
    assert waiver_debt["expired_count"] == 0
    assert waiver_debt["expiring_soon_count"] == 1
    assert waiver_debt["accepted_finding_count"] == 4
    assert reports_response.status_code == 200
    assert reports_response.json()["count"] == 7
    assert all(
        report["workflow"]["latest_event"]["event_type"] == "succeeded"
        for report in reports_response.json()["data"]
    )
    assert dashboard_response.status_code == 200
    assert attack_response.status_code == 200
    _assert_demo_totals_are_coherent(
        dashboard=dashboard_response.json(),
        findings=findings,
        assets=assets_response.json()["data"],
        waivers=waivers_response.json()["data"],
        reports=reports_response.json()["data"],
        governance=governance_response.json(),
        attack=attack_response.json(),
    )
    _assert_demo_report_downloads(
        workbench_api_env,
        headers=headers,
        reports=reports_response.json()["data"],
    )
    assert attack_response.json()["mapped_finding_count"] == 21
    assert attack_response.json()["mapped_coverage_percent"] == 87.5
    assert (tmp_path / "uploads" / project_id).exists()
    assert (tmp_path / "reports" / project_id).exists()

    existing_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )
    assert existing_response.status_code == 200
    assert existing_response.json()["project"]["id"] == project_id
    assert existing_response.json()["latest_run"]["id"] == first_run_id

    reset_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )
    assert reset_response.status_code == 200
    assert reset_response.json()["project"]["id"] == project_id
    assert reset_response.json()["latest_run"]["id"] != first_run_id
    assert reset_response.json()["finding_count"] == 24
    assert reset_response.json()["asset_count"] == 21
    assert reset_response.json()["waiver_count"] == 4
    assert reset_response.json()["report_count"] == 7

    delete_response = workbench_api_env.client.delete("/api/v1/workbench/demo", headers=headers)
    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)

    assert delete_response.status_code == 204
    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is True
    assert status_response.json()["seeded"] is False
    assert not (tmp_path / "uploads" / project_id).exists()
    assert not (tmp_path / "reports" / project_id).exists()

    recreated_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )
    assert recreated_response.status_code == 200
    assert recreated_response.json()["project"]["id"] == project_id
    assert recreated_response.json()["finding_count"] == 24
    assert recreated_response.json()["asset_count"] == 21
    assert recreated_response.json()["waiver_count"] == 4
    assert recreated_response.json()["report_count"] == 7


def test_demo_workspace_load_self_heals_mutated_state(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)

    first_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )
    assert first_response.status_code == 200
    first_payload = first_response.json()
    project_id = first_payload["project"]["id"]
    first_run_id = first_payload["latest_run"]["id"]

    _corrupt_demo_workspace_without_changing_counts(workbench_api_env, project_id)

    repaired_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )

    assert repaired_response.status_code == 200
    repaired_payload = repaired_response.json()
    assert repaired_payload["project"]["id"] == project_id
    assert repaired_payload["project"]["name"] == DEMO_PROJECT_NAME
    assert repaired_payload["latest_run"]["id"] != first_run_id
    assert repaired_payload["finding_count"] == 24
    assert repaired_payload["asset_count"] == 21
    assert repaired_payload["waiver_count"] == 4
    assert repaired_payload["report_count"] == 7

    governance_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/governance/rollups/?limit=20",
        headers=headers,
    )
    assert governance_response.status_code == 200
    waiver_debt = governance_response.json()["waiver_debt"]
    assert waiver_debt["active_count"] == 3
    assert waiver_debt["review_due_count"] == 1
    assert waiver_debt["expired_count"] == 0


def test_demo_workspace_load_repairs_missing_report_artifact(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)

    first_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )
    assert first_response.status_code == 200
    first_payload = first_response.json()
    project_id = first_payload["project"]["id"]
    first_run_id = first_payload["latest_run"]["id"]

    deleted_artifact = _delete_one_demo_report_artifact(
        workbench_api_env,
        project_id=project_id,
        run_id=first_run_id,
    )
    assert not deleted_artifact.exists()

    repaired_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )

    assert repaired_response.status_code == 200
    repaired_payload = repaired_response.json()
    assert repaired_payload["project"]["id"] == project_id
    assert repaired_payload["latest_run"]["id"] != first_run_id
    assert repaired_payload["finding_count"] == 24
    assert repaired_payload["asset_count"] == 21
    assert repaired_payload["waiver_count"] == 4
    assert repaired_payload["report_count"] == 7
    assert _all_demo_report_artifacts_exist(
        workbench_api_env,
        project_id=project_id,
        run_id=repaired_payload["latest_run"]["id"],
    )


def test_demo_workspace_load_repairs_missing_decision_evidence(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)

    first_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )
    assert first_response.status_code == 200
    first_payload = first_response.json()
    project_id = first_payload["project"]["id"]
    first_run_id = first_payload["latest_run"]["id"]

    _delete_demo_decision_evidence(workbench_api_env, project_id)

    repaired_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": False},
    )

    assert repaired_response.status_code == 200
    repaired_payload = repaired_response.json()
    assert repaired_payload["project"]["id"] == project_id
    assert repaired_payload["latest_run"]["id"] != first_run_id
    assert repaired_payload["latest_run"]["evidence"]["schema_version"] == "analysis-evidence.v2"
    assert repaired_payload["latest_run"]["workflow"]["status"] == "succeeded"
    assert repaired_payload["finding_count"] == 24


def test_demo_workspace_seed_stays_disabled_outside_local(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _enable_demo_workspace(workbench_api_env, tmp_path, environment="production")
    headers = local_api_headers(workbench_api_env.client)

    status_response = workbench_api_env.client.get("/api/v1/workbench/demo", headers=headers)
    seed_response = workbench_api_env.client.post(
        "/api/v1/workbench/demo",
        headers=headers,
        json={"reset": True},
    )

    assert status_response.status_code == 200
    assert status_response.json()["enabled"] is False
    assert seed_response.status_code == 403


def _enable_demo_workspace(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    *,
    environment: str = "local",
) -> None:
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        ATTACK_ARTIFACT_DIR=str(PROJECT_ROOT / "data" / "attack"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
        DEMO_WORKSPACE_ENABLED=True,
        ENVIRONMENT=environment,
        FRONTEND_HOST="https://workbench.example.com"
        if environment != "local"
        else "http://localhost:5173",
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        REPORT_DIR=str(tmp_path / "reports"),
        SECRET_KEY="workbench-demo-test-secret-0123456789",
    )
    workbench_api_env.client.app.state.workbench_settings = active_settings


def _corrupt_demo_workspace_without_changing_counts(
    workbench_api_env: WorkbenchApiEnv,
    project_id: str,
) -> None:
    project_uuid = uuid.UUID(project_id)
    models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        project = session.get(models.Project, project_uuid)
        assert project is not None
        project.name = "Mutated Demo Project"
        project.description = "corrupted by local demo exploration"

        waiver = session.exec(
            select(models.Waiver).where(models.Waiver.project_id == project_uuid)
        ).first()
        assert waiver is not None
        expired_at = get_datetime_utc().date() - timedelta(days=1)
        waiver.expires_at = expired_at
        waiver.review_at = expired_at

        session.add(project)
        session.add(waiver)
        session.commit()


def _delete_one_demo_report_artifact(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: str,
    run_id: str,
) -> Path:
    project_uuid = uuid.UUID(project_id)
    run_uuid = uuid.UUID(run_id)
    models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        report = session.exec(
            select(models.Report)
            .where(models.Report.project_id == project_uuid)
            .where(models.Report.analysis_run_id == run_uuid)
        ).first()
        assert report is not None
        artifact_path = Path(report.path)
    assert artifact_path.is_file()
    artifact_path.unlink()
    return artifact_path


def _delete_demo_decision_evidence(
    workbench_api_env: WorkbenchApiEnv,
    project_id: str,
) -> None:
    project_uuid = uuid.UUID(project_id)
    models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        workflow_ids = [
            workflow.id
            for workflow in session.exec(
                select(models.WorkflowRun).where(models.WorkflowRun.project_id == project_uuid)
            ).all()
        ]
        if workflow_ids:
            events = session.exec(
                select(models.WorkflowEvent).where(
                    col(models.WorkflowEvent.workflow_run_id).in_(workflow_ids)
                )
            ).all()
            for event in events:
                session.delete(event)
        for model in (
            models.FindingDecisionEvidence,
            models.AnalysisEvidence,
            models.WorkflowRun,
        ):
            rows = session.exec(select(model).where(model.project_id == project_uuid)).all()
            for row in rows:
                session.delete(row)
        session.commit()


def _all_demo_report_artifacts_exist(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: str,
    run_id: str,
) -> bool:
    project_uuid = uuid.UUID(project_id)
    run_uuid = uuid.UUID(run_id)
    models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        reports = session.exec(
            select(models.Report)
            .where(models.Report.project_id == project_uuid)
            .where(models.Report.analysis_run_id == run_uuid)
        ).all()
    return len(reports) == 7 and all(Path(report.path).is_file() for report in reports)


def _assert_demo_totals_are_coherent(
    *,
    dashboard: dict[str, Any],
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    waivers: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    governance: dict[str, Any],
    attack: dict[str, Any],
) -> None:
    summary = dashboard["summary"]
    signal_counts = dashboard["findings"]["signal_counts"]

    assert summary["finding_count"] == len(findings) == 24
    assert summary["open_finding_count"] == sum(
        1 for finding in findings if finding["status"] in {"open", "in_review", "remediating"}
    )
    assert summary["counts_by_status"] == _expected_count_map(
        Counter(finding["status"] for finding in findings),
        summary["counts_by_status"],
    )
    assert summary["counts_by_priority"] == _expected_count_map(
        Counter(str(finding["priority"]).title() for finding in findings),
        summary["counts_by_priority"],
    )
    assert sum(summary["counts_by_status"].values()) == summary["finding_count"]
    assert sum(summary["counts_by_priority"].values()) == summary["finding_count"]

    assert len({asset["asset_key"] for asset in assets}) == 21
    assert sum(asset["finding_count"] for asset in assets) == summary["finding_count"]
    assert len(waivers) == 4
    assert {report["filename"] for report in reports} == EXPECTED_REPORT_FILENAMES

    epss_bucket_counts = {
        "low": sum(1 for finding in findings if _epss_in_range(finding, 0, 0.25)),
        "medium": sum(1 for finding in findings if _epss_in_range(finding, 0.25, 0.5)),
        "high": sum(1 for finding in findings if _epss_in_range(finding, 0.5, 0.7)),
        "critical": sum(1 for finding in findings if _epss_in_range(finding, 0.7, None)),
    }
    assert signal_counts["epss_buckets"] == epss_bucket_counts
    assert signal_counts["high_epss"] == epss_bucket_counts["critical"]
    assert sum(signal_counts["epss_buckets"].values()) == summary["epss_hits"]
    assert signal_counts["internet_facing_criticals"] == sum(
        1
        for finding in findings
        if finding["priority"] == "critical" and finding["exposure"] == "internet-facing"
    )

    waiver_debt = governance["waiver_debt"]
    assert waiver_debt["waiver_count"] == (
        waiver_debt["active_count"] + waiver_debt["review_due_count"] + waiver_debt["expired_count"]
    )
    assert waiver_debt["accepted_finding_count"] == sum(
        1 for finding in findings if finding["status"] == "accepted" or finding["waived"]
    )
    assert attack["mapped_finding_count"] + attack["unmapped_finding_count"] == len(findings)

    assert sum(service["finding_count"] for service in governance["services"]) == len(findings)
    for rollup_group in (
        governance["owners"],
        governance["services"],
        governance["environments"],
        governance["assets"],
        governance["top_services_by_risk"],
        governance["top_assets_by_risk"],
    ):
        for rollup in rollup_group:
            _assert_rollup_counts_are_coherent(rollup)


def _assert_demo_report_downloads(
    workbench_api_env: WorkbenchApiEnv,
    *,
    headers: dict[str, str],
    reports: list[dict[str, Any]],
) -> None:
    reports_by_filename = {report["filename"]: report for report in reports}
    assert set(reports_by_filename) == EXPECTED_REPORT_FILENAMES

    for filename, report in reports_by_filename.items():
        download = workbench_api_env.client.get(report["download_url"], headers=headers)

        assert download.status_code == 200, filename
        assert download.headers["cache-control"] == "no-store"
        assert "attachment" in download.headers["content-disposition"]
        assert filename in download.headers["content-disposition"]
        assert len(download.content) > 500

        if filename == "technical-report.md":
            assert "# Technical Vulnerability Report" in download.text
        elif filename == "executive-report.html":
            assert "<!doctype html>" in download.text
            assert "Executive Summary" not in download.text
            assert "Decision Brief" in download.text
            assert "Top Remediation Campaigns" in download.text
            assert "CVE-2021-44228 / Log4Shell" in download.text
            assert "CVE-2022-22965 / Spring4Shell" in download.text
            assert "Decision Ready Recommendations" in download.text
        elif filename == "analysis-result.v2.json":
            payload = download.json()
            assert payload["schema"] == "analysis-result.v2"
            assert payload["project"]["name"] == DEMO_PROJECT_NAME
        elif filename == "findings.csv":
            assert "cve_id" in download.text
            assert "CVE-" in download.text
        elif filename == "attack-navigator-layer.json":
            payload = download.json()
            assert payload["version"] == "4.5"
            assert payload["domain"] == "enterprise-attack"
            assert payload["techniques"]
        elif filename == "results.sarif":
            payload = download.json()
            assert payload["version"] == "2.1.0"
            assert payload["runs"]
        elif filename == "evidence-bundle.zip":
            with zipfile.ZipFile(BytesIO(download.content)) as archive:
                names = set(archive.namelist())
                expected_bundle_files = {
                    "analysis.json",
                    "executive.html",
                    "manifest.json",
                    "technical.md",
                }
                assert expected_bundle_files.issubset(names)
                manifest = json.loads(archive.read("manifest.json"))
                assert manifest["bundle_kind"] == "evidence-bundle"


def _assert_rollup_counts_are_coherent(rollup: dict[str, Any]) -> None:
    assert sum(rollup["priority_counts"].values()) == rollup["finding_count"]
    assert sum(rollup["status_counts"].values()) == rollup["finding_count"]
    assert rollup["open_count"] == sum(
        rollup["status_counts"].get(status, 0) for status in ("open", "in_review", "remediating")
    )
    assert rollup["accepted_count"] >= rollup["status_counts"].get("accepted", 0)
    assert rollup["fixed_count"] == rollup["status_counts"].get("fixed", 0)
    assert rollup["suppressed_count"] == rollup["status_counts"].get("suppressed", 0)


def _expected_count_map(
    actual_counts: Counter[str],
    expected_shape: dict[str, int],
) -> dict[str, int]:
    return {key: actual_counts.get(key, 0) for key in expected_shape}


def _epss_in_range(
    finding: dict[str, Any],
    minimum: float,
    maximum: float | None,
) -> bool:
    value = finding.get("epss")
    if not isinstance(value, (int, float)) or value < minimum:
        return False
    return maximum is None or value < maximum
