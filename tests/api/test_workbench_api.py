from __future__ import annotations

import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app, get_engine
from vuln_prioritizer.db import (
    ApiToken,
    Finding,
    Vulnerability,
    WorkbenchRepository,
    create_session_factory,
)
from vuln_prioritizer.workbench_config import WorkbenchSettings

ROOT = Path(__file__).resolve().parents[2]
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
TRIVY_REPORT = ROOT / "data" / "input_fixtures" / "trivy_report.json"
GRYPE_REPORT = ROOT / "data" / "input_fixtures" / "grype_report.json"
CYCLONEDX_BOM = ROOT / "data" / "input_fixtures" / "cyclonedx_bom.json"
SPDX_BOM = ROOT / "data" / "input_fixtures" / "spdx_bom.json"
DEPENDENCY_CHECK_REPORT = ROOT / "data" / "input_fixtures" / "dependency_check_report.json"
GITHUB_ALERTS_EXPORT = ROOT / "data" / "input_fixtures" / "github_alerts_export.json"
NESSUS_REPORT = ROOT / "data" / "input_fixtures" / "nessus_report.nessus"
OPENVAS_REPORT = ROOT / "data" / "input_fixtures" / "openvas_report.xml"
ASSET_CONTEXT = ROOT / "data" / "input_fixtures" / "example_asset_context.csv"
OPENVEX = ROOT / "data" / "input_fixtures" / "openvex_statements.json"
ATTACK_MAPPING = ROOT / "data" / "attack" / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
ATTACK_METADATA = ROOT / "data" / "attack" / "attack_techniques_enterprise_16.1_subset.json"
EXPECTED_SAMPLE_CVES = {
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-44487",
    "CVE-2024-3094",
}


def _client(tmp_path: Path) -> TestClient:
    snapshot_dir = _provider_snapshot_dir(tmp_path)
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=snapshot_dir,
        attack_artifact_dir=ROOT / "data" / "attack",
    )
    return TestClient(create_app(settings=settings))


def _client_and_settings(tmp_path: Path) -> tuple[TestClient, WorkbenchSettings]:
    snapshot_dir = _provider_snapshot_dir(tmp_path)
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=snapshot_dir,
        attack_artifact_dir=ROOT / "data" / "attack",
    )
    return TestClient(create_app(settings=settings)), settings


def _provider_snapshot_dir(tmp_path: Path) -> Path:
    snapshot_dir = tmp_path / "provider-snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DEMO_PROVIDER_SNAPSHOT, snapshot_dir / DEMO_PROVIDER_SNAPSHOT.name)
    return snapshot_dir


def _create_project(client: TestClient) -> dict[str, Any]:
    response = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert response.status_code == 200
    return response.json()


def _import_sample(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _import_payload(
    client: TestClient,
    project_id: str,
    *,
    input_format: str,
    filename: str,
    content: bytes,
    content_type: str,
) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": input_format,
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={"file": (filename, content, content_type)},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_workbench_health_and_project_crud(tmp_path: Path) -> None:
    client = _client(tmp_path)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert "object-src 'none'" in health.headers["content-security-policy"]

    bad_host = client.get("/api/health", headers={"host": "evil.example"})
    assert bad_host.status_code == 400

    version = client.get("/api/version")
    assert version.status_code == 200
    assert version.json()["app"] == "Vuln Prioritizer Workbench"

    project = _create_project(client)
    assert project["name"] == "online-shop-demo"
    project_detail = client.get(f"/api/projects/{project['id']}")
    assert project_detail.status_code == 200
    assert project_detail.json()["name"] == "online-shop-demo"

    projects = client.get("/api/projects")
    assert projects.status_code == 200
    assert projects.json()["items"][0]["id"] == project["id"]

    duplicate = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert duplicate.status_code == 409
    duplicate_payload = duplicate.json()
    assert duplicate_payload["detail"] == "Project already exists."
    assert duplicate_payload["error"]["code"] == "conflict"


def test_workbench_import_findings_reports_and_evidence(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    run = _import_sample(client, project["id"])

    assert run["status"] == "completed"
    assert run["input_type"] == "cve-list"
    assert run["input_filename"] == "sample.txt"
    assert run["finished_at"] is not None
    assert run["job_id"]
    assert run["summary"]["findings_count"] == len(EXPECTED_SAMPLE_CVES)
    assert run["summary"]["kev_hits"] >= 1
    assert run["summary"]["counts_by_priority"]
    assert run["provider_snapshot_id"]
    assert run["summary"]["provider_snapshot_id"] == run["provider_snapshot_id"]

    provider_status = client.get("/api/providers/status")
    assert provider_status.status_code == 200
    status_payload = provider_status.json()
    assert status_payload["status"] == "ok"
    assert status_payload["snapshot"]["content_hash"]
    assert status_payload["snapshot"]["selected_sources"] == ["nvd", "epss", "kev"]
    assert {source["name"] for source in status_payload["sources"]} == {"nvd", "epss", "kev"}

    project_runs = client.get(f"/api/projects/{project['id']}/runs")
    assert project_runs.status_code == 200
    assert [item["id"] for item in project_runs.json()["items"]] == [run["id"]]

    run_alias = client.get(f"/api/runs/{run['id']}")
    assert run_alias.status_code == 200
    assert run_alias.json()["id"] == run["id"]

    run_summary = client.get(f"/api/runs/{run['id']}/summary")
    assert run_summary.status_code == 200
    assert run_summary.json()["findings_count"] == len(EXPECTED_SAMPLE_CVES)

    executive_report = client.get(f"/api/analysis-runs/{run['id']}/executive-report")
    assert executive_report.status_code == 200
    executive_payload = executive_report.json()
    assert executive_payload["title"] == project["name"]
    assert executive_payload["nav"][0]["label"] == "Executive Security Overview"
    assert executive_payload["workspace_nav"]["groups"][0]["label"] == "Analyze"
    assert any(
        link["label"] == "Executive Report" and link["active"]
        for group in executive_payload["workspace_nav"]["groups"]
        for link in group["links"]
    )
    assert any(item["label"] == "KEV" for item in executive_payload["kpis"])
    assert executive_payload["priority_findings"][0]["cve"].startswith("CVE-")
    assert set(executive_payload) >= {
        "overview_metrics",
        "provider_cards",
        "severity_signal_rows",
        "asset_risk_rows",
        "priority_kpis",
        "attack",
        "remediation",
        "evidence",
    }
    assert executive_payload["attack"]["technique_strip"] is not None
    assert executive_payload["remediation"]["next_steps"]
    assert executive_payload["evidence"]["provider_rows"]

    findings = client.get(f"/api/projects/{project['id']}/findings")
    assert findings.status_code == 200
    items = findings.json()["items"]
    assert {item["cve_id"] for item in items} == EXPECTED_SAMPLE_CVES
    assert {item["status"] for item in items} == {"open"}
    assert [item["operational_rank"] for item in items] == sorted(
        item["operational_rank"] for item in items
    )

    filtered = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"q": "CVE-2024-3094"},
    )
    assert filtered.status_code == 200
    assert [item["cve_id"] for item in filtered.json()["items"]] == ["CVE-2024-3094"]
    assert filtered.json()["total"] == 1
    assert filtered.json()["limit"] == 100
    assert filtered.json()["offset"] == 0

    paged = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"limit": 2, "offset": 1, "sort": "cve"},
    )
    assert paged.status_code == 200
    paged_payload = paged.json()
    assert paged_payload["total"] == len(EXPECTED_SAMPLE_CVES)
    assert paged_payload["limit"] == 2
    assert [item["cve_id"] for item in paged_payload["items"]] == sorted(EXPECTED_SAMPLE_CVES)[1:3]

    kev_findings = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"kev": "true", "sort": "epss"},
    )
    assert kev_findings.status_code == 200
    assert kev_findings.json()["total"] >= 1
    assert all(item["in_kev"] for item in kev_findings.json()["items"])

    bad_sort = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"sort": "unsupported"},
    )
    assert bad_sort.status_code == 422
    assert bad_sort.json()["error"]["code"] == "validation_error"

    log4shell = next(item for item in items if item["cve_id"] == "CVE-2021-44228")
    detail = client.get(f"/api/findings/{log4shell['id']}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["finding"]["cve_id"] == "CVE-2021-44228"
    assert detail_payload["finding"]["provider_evidence"]["nvd"]["cve_id"] == "CVE-2021-44228"
    assert detail_payload["occurrences"][0]["source_format"] == "cve-list"
    assert detail_payload["occurrences"][0]["source_record_id"] == "line:1"

    explanation = client.get(f"/api/findings/{log4shell['id']}/explain")
    assert explanation.status_code == 200
    assert explanation.json()["cve_id"] == "CVE-2021-44228"
    assert explanation.json()["explanation"]["cve_id"] == "CVE-2021-44228"

    report_expectations = {
        "json": ("analysis-json", b'"locked_provider_data": true'),
        "markdown": ("markdown-summary", b"# Vulnerability Prioritization Summary"),
        "html": ("html-report", b"Vulnerability"),
        "csv": ("findings-csv", b"cve_id,priority,status"),
        "sarif": ("sarif-results", b'"version": "2.1.0"'),
    }
    created_reports: list[dict[str, Any]] = []
    for report_format, (expected_kind, expected_content) in report_expectations.items():
        report = client.post(
            f"/api/analysis-runs/{run['id']}/reports",
            json={"format": report_format},
        )
        assert report.status_code == 200
        report_payload = report.json()
        created_reports.append(report_payload)
        assert report_payload["format"] == report_format
        assert report_payload["kind"] == expected_kind
        assert len(report_payload["sha256"]) == 64

        report_download = client.get(report_payload["download_url"])
        assert report_download.status_code == 200
        assert report_download.headers["content-disposition"].startswith("attachment;")
        assert report_download.headers["cache-control"] == "no-store"
        assert hashlib.sha256(report_download.content).hexdigest() == report_payload["sha256"]
        assert expected_content in report_download.content
        assert b"CVE-2021-44228" in report_download.content

        if report_format == "json":
            analysis_payload = json.loads(report_download.text)
            assert analysis_payload["metadata"]["input_format"] == "cve-list"
            assert analysis_payload["metadata"]["locked_provider_data"] is True
            assert {
                finding["cve_id"] for finding in analysis_payload["findings"]
            } == EXPECTED_SAMPLE_CVES
        if report_format == "sarif":
            sarif_payload = json.loads(report_download.text)
            assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == (
                "vuln-prioritizer-workbench"
            )
            assert any(
                result["properties"]["cve"] == "CVE-2021-44228"
                for result in sarif_payload["runs"][0]["results"]
            )

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_payload = bundle.json()
    assert len(bundle_payload["sha256"]) == 64
    bundle_download = client.get(bundle_payload["download_url"])
    assert bundle_download.status_code == 200
    assert hashlib.sha256(bundle_download.content).hexdigest() == bundle_payload["sha256"]
    assert bundle_download.content.startswith(b"PK")

    with zipfile.ZipFile(io.BytesIO(bundle_download.content)) as archive:
        names = set(archive.namelist())
        assert {"analysis.json", "report.html", "summary.md", "manifest.json"} <= names
        assert "input/sample.txt" in names

        analysis_payload = json.loads(archive.read("analysis.json"))
        assert analysis_payload["metadata"]["input_format"] == "cve-list"
        assert {
            finding["cve_id"] for finding in analysis_payload["findings"]
        } == EXPECTED_SAMPLE_CVES

        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["bundle_kind"] == "evidence-bundle"
        assert manifest["findings_count"] == len(EXPECTED_SAMPLE_CVES)
        assert manifest["included_input_copy"] is True
        assert manifest["source_analysis_sha256"]
        assert manifest["source_input_hashes"][0]["path"].endswith("sample.txt")
        assert (
            manifest["provider_snapshot"]["sha256"]
            == analysis_payload["metadata"]["provider_snapshot_hash"]
        )
        manifest_files = {item["path"]: item for item in manifest["files"]}
        for artifact_name in ["analysis.json", "report.html", "summary.md", "input/sample.txt"]:
            assert artifact_name in manifest_files
            assert (
                manifest_files[artifact_name]["sha256"]
                == hashlib.sha256(archive.read(artifact_name)).hexdigest()
            )
            assert (
                manifest["artifact_hashes"][artifact_name]
                == manifest_files[artifact_name]["sha256"]
            )

    assert bundle_payload["verify_url"] == f"/api/evidence-bundles/{bundle_payload['id']}/verify"
    verification = client.get(bundle_payload["verify_url"])
    assert verification.status_code == 200
    assert verification.json()["summary"]["ok"] is True

    jobs = client.get("/api/jobs", params={"project_id": project["id"]})
    assert jobs.status_code == 200
    job_items = jobs.json()["items"]
    job_kinds = {item["kind"] for item in job_items}
    assert {"import_findings", "create_report", "create_evidence_bundle"} <= job_kinds
    assert all(
        item["status"] == "completed"
        for item in job_items
        if item["kind"] in {"import_findings", "create_report", "create_evidence_bundle"}
    )
    import_job = client.get(f"/api/jobs/{run['job_id']}")
    assert import_job.status_code == 200
    assert import_job.json()["result"]["analysis_run_id"] == run["id"]

    manual_job = client.post(
        "/api/jobs",
        json={
            "kind": "create_report",
            "project_id": project["id"],
            "target_type": "analysis_run",
            "target_id": run["id"],
            "payload": {"analysis_run_id": run["id"], "format": "html"},
            "idempotency_key": "manual-report-job",
        },
    )
    assert manual_job.status_code == 200, manual_job.text
    duplicate_job = client.post(
        "/api/jobs",
        json={
            "kind": "create_report",
            "project_id": project["id"],
            "target_type": "analysis_run",
            "target_id": run["id"],
            "payload": {"analysis_run_id": run["id"], "format": "html"},
            "idempotency_key": "manual-report-job",
        },
    )
    assert duplicate_job.status_code == 200, duplicate_job.text
    assert duplicate_job.json()["id"] == manual_job.json()["id"]
    manual_run = client.post(f"/api/jobs/{manual_job.json()['id']}/run")
    assert manual_run.status_code == 200, manual_run.text
    assert manual_run.json()["status"] == "completed"
    assert manual_run.json()["result"]["analysis_run_id"] == run["id"]
    assert manual_run.json()["result"]["format"] == "html"

    retry_job = next(item for item in job_items if item["kind"] == "create_report")
    retry = client.post(f"/api/jobs/{retry_job['id']}/retry")
    assert retry.status_code == 200
    assert retry.json()["status"] == "queued"

    default_retention = client.get(f"/api/projects/{project['id']}/artifacts/retention")
    assert default_retention.status_code == 200
    assert default_retention.json()["report_retention_days"] is None
    retention = client.patch(
        f"/api/projects/{project['id']}/artifacts/retention",
        json={
            "report_retention_days": 30,
            "evidence_retention_days": 90,
            "max_disk_usage_mb": 512,
        },
    )
    assert retention.status_code == 200, retention.text
    assert retention.json()["report_retention_days"] == 30
    cleanup = client.post(
        f"/api/projects/{project['id']}/artifacts/cleanup",
        params={"dry_run": "true"},
    )
    assert cleanup.status_code == 200
    assert cleanup.json()["dry_run"] is True

    artifacts = client.get(f"/api/projects/{project['id']}/artifacts")
    assert artifacts.status_code == 200
    assert len(artifacts.json()["reports"]) == len(created_reports) + 1
    assert len(artifacts.json()["evidence_bundles"]) == 1
    assert artifacts.json()["disk_usage_bytes"] > 0

    deleted_report = client.delete(f"/api/reports/{created_reports[0]['id']}")
    assert deleted_report.status_code == 200
    assert deleted_report.json()["artifact_removed"] is True
    assert client.get(created_reports[0]["download_url"]).status_code == 404

    deleted_bundle = client.delete(f"/api/evidence-bundles/{bundle_payload['id']}")
    assert deleted_bundle.status_code == 200
    assert deleted_bundle.json()["artifact_removed"] is True
    assert client.get(bundle_payload["download_url"]).status_code == 404


def test_project_artifact_cleanup_is_scoped_and_enforces_disk_cap(tmp_path: Path) -> None:
    client, settings = _client_and_settings(tmp_path)
    first = client.post("/api/projects", json={"name": "first"}).json()
    second = client.post("/api/projects", json={"name": "second"}).json()
    session_factory = create_session_factory(get_engine(client.app))
    first_run_id = ""
    second_file = settings.report_dir / "second-run" / "analysis.json"
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        first_run = repo.create_analysis_run(
            project_id=first["id"],
            input_type="cve-list",
            input_filename="first.txt",
            status="completed",
        )
        second_run = repo.create_analysis_run(
            project_id=second["id"],
            input_type="cve-list",
            input_filename="second.txt",
            status="completed",
        )
        first_run_id = first_run.id
        first_dir = settings.report_dir / first_run.id
        first_dir.mkdir(parents=True)
        first_old = first_dir / "old.json"
        first_new = first_dir / "new.json"
        first_orphan = first_dir / "orphan.tmp"
        first_old.write_text("x" * (1024 * 1024 + 10), encoding="utf-8")
        first_new.write_text("fresh", encoding="utf-8")
        first_orphan.write_text("orphan", encoding="utf-8")
        second_file.parent.mkdir(parents=True)
        second_file.write_text("do-not-delete", encoding="utf-8")
        repo.add_report(
            project_id=first["id"],
            analysis_run_id=first_run.id,
            kind="analysis-json",
            format="json",
            path=str(first_old),
            sha256=hashlib.sha256(first_old.read_bytes()).hexdigest(),
        )
        repo.add_report(
            project_id=first["id"],
            analysis_run_id=first_run.id,
            kind="analysis-json",
            format="json",
            path=str(first_new),
            sha256=hashlib.sha256(first_new.read_bytes()).hexdigest(),
        )
        repo.add_report(
            project_id=second["id"],
            analysis_run_id=second_run.id,
            kind="analysis-json",
            format="json",
            path=str(second_file),
            sha256=hashlib.sha256(second_file.read_bytes()).hexdigest(),
        )
        repo.upsert_project_artifact_retention(
            project_id=first["id"],
            max_disk_usage_mb=1,
        )
        session.commit()

    cleanup = client.post(
        f"/api/projects/{first['id']}/artifacts/cleanup",
        params={"dry_run": "false"},
    )

    assert cleanup.status_code == 200, cleanup.text
    deleted = set(cleanup.json()["deleted_files"])
    assert str(settings.report_dir / first_run_id / "orphan.tmp") in deleted
    assert not (settings.report_dir / first_run_id / "old.json").exists()
    assert not (settings.report_dir / first_run_id / "orphan.tmp").exists()
    assert second_file.exists()


def test_workbench_finding_lifecycle_audit_and_exports(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    run = _import_sample(client, project["id"])
    findings = client.get(f"/api/projects/{project['id']}/findings").json()["items"]
    finding = next(item for item in findings if item["cve_id"] == "CVE-2021-44228")

    update = client.patch(
        f"/api/findings/{finding['id']}",
        json={"status": "in_review", "actor": "analyst", "reason": "triage started"},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "in_review"
    history = update.json()["status_history"]
    assert history[-1]["previous_status"] == "open"
    assert history[-1]["new_status"] == "in_review"
    assert history[-1]["actor"] == "analyst"

    detail = client.get(f"/api/findings/{finding['id']}")
    assert detail.status_code == 200
    assert detail.json()["status_history"][-1]["reason"] == "triage started"

    reimport = _import_sample(client, project["id"])
    assert reimport["status"] == "completed"
    after_reimport = client.get(f"/api/findings/{finding['id']}")
    assert after_reimport.status_code == 200
    assert after_reimport.json()["status"] == "in_review"
    assert after_reimport.json()["status_history"][-1]["reason"] == "triage started"

    audit = client.get(f"/api/projects/{project['id']}/audit-events")
    assert audit.status_code == 200
    event_types = [event["event_type"] for event in audit.json()["items"]]
    assert "finding.status_changed" in event_types
    assert "analysis_run.imported" in event_types
    assert "project.created" in event_types

    json_report = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "json"},
    ).json()
    json_download = client.get(json_report["download_url"])
    payload = json.loads(json_download.text)
    exported = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2021-44228")
    assert exported["status"] == "in_review"
    assert exported["status_history"][-1]["actor"] == "analyst"

    csv_report = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "csv"},
    ).json()
    csv_download = client.get(csv_report["download_url"])
    assert "CVE-2021-44228,Critical,in_review" in csv_download.text

    sarif_report = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "sarif"},
    ).json()
    sarif_payload = client.get(sarif_report["download_url"]).json()
    result = next(
        item
        for item in sarif_payload["runs"][0]["results"]
        if item["properties"]["cve"] == "CVE-2021-44228"
    )
    assert result["properties"]["status"] == "in_review"
    assert result["partialFingerprints"]["vuln-prioritizer-workbench/v1"]
    assert sarif_payload["runs"][0]["tool"]["driver"]["rules"]


def test_workbench_imports_all_mvp_formats(tmp_path: Path) -> None:
    client = _client(tmp_path)
    cases = [
        (
            "generic-occurrence-csv",
            "generic.csv",
            (
                b"cve,component,version,purl,fix_version,target_kind,target_ref,"
                b"asset_id,criticality,exposure,environment,owner,business_service\n"
                b"CVE-2024-3094,xz,5.6.0-r0,pkg:apk/alpine/xz@5.6.0-r0,5.6.1-r2,"
                b"image,ghcr.io/acme/demo-app:1.0.0,api-gateway,critical,"
                b"internet-facing,prod,platform-team,customer-login\n"
            ),
            "text/csv",
            {"CVE-2024-3094"},
        ),
        (
            "trivy-json",
            "trivy.json",
            TRIVY_REPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094", "CVE-2024-4577"},
        ),
        (
            "grype-json",
            "grype.json",
            GRYPE_REPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094"},
        ),
        (
            "cyclonedx-json",
            "cyclonedx.json",
            CYCLONEDX_BOM.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094"},
        ),
        (
            "spdx-json",
            "spdx.json",
            SPDX_BOM.read_bytes(),
            "application/json",
            {"CVE-2024-3094", "CVE-2024-4577"},
        ),
        (
            "dependency-check-json",
            "dependency-check.json",
            DEPENDENCY_CHECK_REPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362", "CVE-2024-3094"},
        ),
        (
            "github-alerts-json",
            "github-alerts.json",
            GITHUB_ALERTS_EXPORT.read_bytes(),
            "application/json",
            {"CVE-2023-34362"},
        ),
        (
            "nessus-xml",
            "nessus-report.nessus",
            NESSUS_REPORT.read_bytes(),
            "application/xml",
            {"CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3094"},
        ),
        (
            "openvas-xml",
            "openvas-report.xml",
            OPENVAS_REPORT.read_bytes(),
            "application/xml",
            {"CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3094"},
        ),
    ]

    for index, (input_format, filename, content, content_type, expected_cves) in enumerate(cases):
        project = client.post("/api/projects", json={"name": f"format-{index}"}).json()
        run = _import_payload(
            client,
            project["id"],
            input_format=input_format,
            filename=filename,
            content=content,
            content_type=content_type,
        )
        assert run["status"] == "completed"
        assert run["input_type"] == input_format

        findings = client.get(f"/api/projects/{project['id']}/findings")
        assert findings.status_code == 200
        assert {item["cve_id"] for item in findings.json()["items"]} == expected_cves


def test_workbench_multi_file_import_preserves_inputs_and_evidence(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "input_formats": ["trivy-json", "spdx-json"],
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files=[
            ("files", ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")),
            ("files", ("spdx.json", SPDX_BOM.read_bytes(), "application/json")),
        ],
    )
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["input_type"] == "mixed"
    assert run["input_filename"] == "trivy.json, spdx.json"

    findings = client.get(f"/api/projects/{project['id']}/findings", params={"sort": "cve"})
    assert findings.status_code == 200
    assert {item["cve_id"] for item in findings.json()["items"]} == {
        "CVE-2023-34362",
        "CVE-2024-3094",
        "CVE-2024-4577",
    }

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_download = client.get(bundle.json()["download_url"])
    with zipfile.ZipFile(io.BytesIO(bundle_download.content)) as archive:
        names = set(archive.namelist())
        assert "input/001-trivy.json" in names
        assert "input/002-spdx.json" in names
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["included_input_copy"] is True
        assert len(manifest["source_input_hashes"]) == 2


def test_workbench_import_accepts_defensive_context_overlay(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    context_payload = {
        "items": [
            {
                "cve_id": "CVE-2021-44228",
                "source": "ghsa",
                "source_id": "GHSA-log4shell",
                "severity": "critical",
                "summary": "GitHub Advisory context.",
            }
        ]
    }

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={
            "file": ("sample.txt", SAMPLE_CVES.read_bytes(), "text/plain"),
            "defensive_context_file": (
                "context.json",
                json.dumps(context_payload).encode("utf-8"),
                "application/json",
            ),
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["summary"]["defensive_context_sources"] == ["ghsa"]
    findings = client.get(f"/api/projects/{project['id']}/findings").json()["items"]
    finding = next(item for item in findings if item["cve_id"] == "CVE-2021-44228")
    assert finding["defensive_contexts"][0]["source"] == "ghsa"


def test_failed_sync_jobs_are_persisted(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post("/api/analysis-runs/missing-run/reports", json={"format": "json"})

    assert response.status_code == 422
    jobs = client.get("/api/jobs", params={"kind": "create_report"}).json()["items"]
    assert jobs
    assert jobs[0]["status"] == "failed"
    assert "Analysis run not found" in jobs[0]["error_message"]


def test_workbench_attack_import_exposes_ttp_context_and_navigator(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
            "attack_source": "ctid-json",
            "attack_mapping_file": ATTACK_MAPPING.name,
            "attack_technique_metadata_file": ATTACK_METADATA.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["summary"]["attack_enabled"] is True
    assert run["summary"]["attack_source"] == "ctid-mappings-explorer"
    assert run["summary"]["attack_mapped_cves"] >= 1
    assert (
        run["summary"]["attack_mapping_file_sha256"]
        == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
    )
    assert (
        run["summary"]["attack_technique_metadata_file_sha256"]
        == hashlib.sha256(ATTACK_METADATA.read_bytes()).hexdigest()
    )
    assert run["summary"]["attack_metadata_format"] == "vuln-prioritizer-technique-json"

    findings = client.get(f"/api/projects/{project['id']}/findings", params={"sort": "cve"})
    assert findings.status_code == 200
    mapped = [item for item in findings.json()["items"] if item["attack_mapped"]]
    assert mapped
    assert all(item["threat_context_rank"] is not None for item in mapped)

    moveit = next(item for item in mapped if item["cve_id"] == "CVE-2023-34362")
    ttps = client.get(f"/api/findings/{moveit['id']}/ttps")
    assert ttps.status_code == 200
    ttp_payload = ttps.json()
    assert ttp_payload["source"] == "ctid"
    assert ttp_payload["review_status"] == "source_reviewed"
    assert ttp_payload["mapped"] is True
    assert ttp_payload["source_hash"] == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
    assert ttp_payload["metadata_hash"] == hashlib.sha256(ATTACK_METADATA.read_bytes()).hexdigest()
    assert ttp_payload["source_path"].endswith(ATTACK_MAPPING.name)
    assert ttp_payload["metadata_path"].endswith(ATTACK_METADATA.name)
    assert {technique["attack_object_id"] for technique in ttp_payload["techniques"]} >= {"T1190"}

    top_techniques = client.get(f"/api/projects/{project['id']}/attack/top-techniques")
    assert top_techniques.status_code == 200
    assert any(item["technique_id"] == "T1190" for item in top_techniques.json()["items"])

    review_queue = client.get(
        f"/api/projects/{project['id']}/attack/review-queue",
        params={"source": "ctid", "mapped": "true", "technique_id": "T1190"},
    )
    assert review_queue.status_code == 200, review_queue.text
    review_items = review_queue.json()["items"]
    assert any(item["cve_id"] == "CVE-2023-34362" for item in review_items)
    assert all(item["source"] == "ctid" for item in review_items)
    assert all("T1190" in item["technique_ids"] for item in review_items)

    review_update = client.patch(
        f"/api/findings/{moveit['id']}/ttps/review",
        json={
            "review_status": "needs_review",
            "actor": "threat-review",
            "reason": "mapping source inventory check",
        },
    )
    assert review_update.status_code == 200, review_update.text
    assert review_update.json()["review_status"] == "needs_review"
    review_audit = client.get(f"/api/projects/{project['id']}/audit-events")
    assert review_audit.status_code == 200
    assert "attack_context.review_updated" in {
        event["event_type"] for event in review_audit.json()["items"]
    }

    unsupported_review_source = client.get(
        f"/api/projects/{project['id']}/attack/review-queue",
        params={"source": "heuristic"},
    )
    assert unsupported_review_source.status_code == 422

    navigator = client.get(f"/api/analysis-runs/{run['id']}/attack/navigator-layer")
    assert navigator.status_code == 200
    assert any(item["techniqueID"] == "T1190" for item in navigator.json()["techniques"])

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_download = client.get(bundle.json()["download_url"])
    with zipfile.ZipFile(io.BytesIO(bundle_download.content)) as archive:
        names = set(archive.namelist())
        assert "attack-navigator-layer.json" in names
        manifest = json.loads(archive.read("manifest.json"))
        manifest_files = {item["path"]: item for item in manifest["files"]}
        analysis_payload = json.loads(archive.read("analysis.json"))
        assert (
            analysis_payload["metadata"]["attack_mapping_file_sha256"]
            == hashlib.sha256(ATTACK_MAPPING.read_bytes()).hexdigest()
        )
        assert analysis_payload["metadata"]["attack_technique_metadata_file_sha256"]
        assert "attack-navigator-layer.json" in manifest_files
        assert (
            manifest_files["attack-navigator-layer.json"]["sha256"]
            == hashlib.sha256(archive.read("attack-navigator-layer.json")).hexdigest()
        )


def test_workbench_import_accepts_context_vex_and_waiver_uploads(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    waiver = "\n".join(
        [
            "waivers:",
            "  - id: review-due-xz",
            "    cve_id: CVE-2024-3094",
            "    owner: risk-review",
            "    reason: Temporary acceptance for coordinated rollout.",
            "    expires_on: 2099-12-31",
            "    review_on: 2000-01-01",
            "    services: [customer-login]",
        ]
    ).encode()

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={
            "file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json"),
            "asset_context_file": ("asset-context.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
            "vex_file": ("openvex.json", OPENVEX.read_bytes(), "application/json"),
            "waiver_file": ("waivers.yml", waiver, "text/yaml"),
        },
    )
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["summary"]["findings_count"] == 3

    findings = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"sort": "cve"},
    )
    assert findings.status_code == 200
    by_cve = {item["cve_id"]: item for item in findings.json()["items"]}
    assert by_cve["CVE-2023-34362"]["suppressed_by_vex"] is True
    assert by_cve["CVE-2023-34362"]["status"] == "suppressed"
    assert by_cve["CVE-2023-34362"]["vex_statuses"] == {"not_affected": 1}
    assert by_cve["CVE-2024-4577"]["under_investigation"] is True
    assert by_cve["CVE-2024-3094"]["waived"] is True
    assert by_cve["CVE-2024-3094"]["waiver_status"] == "review_due"
    assert by_cve["CVE-2024-3094"]["waiver_owner"] == "risk-review"
    assert by_cve["CVE-2024-3094"]["owner"] == "platform-team"
    assert by_cve["CVE-2024-3094"]["service"] == "customer-login"

    governance = client.get(f"/api/projects/{project['id']}/governance/rollups")
    assert governance.status_code == 200
    payload = governance.json()
    assert payload["total_findings"] == 3
    assert payload["waiver_summary"]["review_due_count"] == 1
    assert payload["vex_summary"]["suppressed_findings"] == 1
    assert payload["vex_summary"]["under_investigation_findings"] == 1
    assert payload["vex_summary"]["status_counts"]["not_affected"] == 1
    owner_labels = {item["label"] for item in payload["owners"]}
    service_labels = {item["label"] for item in payload["services"]}
    assert "platform-team" in owner_labels
    assert "customer-login" in service_labels

    markdown = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "markdown"},
    )
    assert markdown.status_code == 200
    markdown_download = client.get(markdown.json()["download_url"])
    assert markdown_download.status_code == 200
    assert "## Governance" in markdown_download.text
    assert "Top owners: platform-team" in markdown_download.text


def test_workbench_assets_and_persisted_waivers_update_current_findings(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={
            "file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json"),
            "asset_context_file": ("asset-context.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
        },
    )
    assert response.status_code == 200, response.text

    assets = client.get(f"/api/projects/{project['id']}/assets")
    assert assets.status_code == 200
    [asset] = assets.json()["items"]
    assert asset["asset_id"] == "api-gateway"
    assert asset["owner"] == "platform-team"
    assert asset["finding_count"] == 1
    asset_detail = client.get(f"/api/assets/{asset['id']}")
    assert asset_detail.status_code == 200
    assert asset_detail.json()["asset_id"] == "api-gateway"

    updated_asset = client.patch(
        f"/api/assets/{asset['id']}",
        json={
            "asset_id": "edge-gateway",
            "owner": "platform-risk",
            "business_service": "checkout",
            "environment": "prod",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    )
    assert updated_asset.status_code == 200, updated_asset.text
    assert updated_asset.json()["asset_id"] == "edge-gateway"

    owner_only_update = client.patch(
        f"/api/assets/{asset['id']}",
        json={"owner": "platform-risk-review"},
    )
    assert owner_only_update.status_code == 200, owner_only_update.text
    owner_only_payload = owner_only_update.json()
    assert owner_only_payload["asset_id"] == "edge-gateway"
    assert owner_only_payload["owner"] == "platform-risk-review"
    assert owner_only_payload["business_service"] == "checkout"
    assert owner_only_payload["environment"] == "prod"
    assert owner_only_payload["exposure"] == "internet-facing"
    assert owner_only_payload["criticality"] == "critical"

    findings = client.get(f"/api/projects/{project['id']}/findings", params={"q": "CVE-2024-3094"})
    assert findings.status_code == 200
    xz_finding = findings.json()["items"][0]
    assert xz_finding["asset"] == "edge-gateway"
    assert xz_finding["owner"] == "platform-risk-review"
    assert xz_finding["service"] == "checkout"

    waiver = client.post(
        f"/api/projects/{project['id']}/waivers",
        json={
            "cve_id": "CVE-2024-3094",
            "asset_id": "edge-gateway",
            "owner": "risk-owner",
            "reason": "Temporary residual risk acceptance for staged remediation.",
            "expires_on": "2099-12-31",
            "review_on": "2000-01-01",
            "approval_ref": "CAB-42",
        },
    )
    assert waiver.status_code == 200, waiver.text
    waiver_payload = waiver.json()
    assert waiver_payload["status"] == "review_due"
    assert waiver_payload["matched_findings"] == 1

    updated_waiver = client.patch(
        f"/api/waivers/{waiver_payload['id']}",
        json={
            "cve_id": "CVE-2024-3094",
            "asset_id": "edge-gateway",
            "owner": "risk-owner-updated",
            "reason": "Residual risk accepted with compensating controls.",
            "expires_on": "2099-12-31",
            "review_on": "2099-12-01",
            "approval_ref": "CAB-43",
        },
    )
    assert updated_waiver.status_code == 200, updated_waiver.text
    waiver_payload = updated_waiver.json()
    assert waiver_payload["owner"] == "risk-owner-updated"
    assert waiver_payload["status"] == "active"

    waived_findings = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"q": "CVE-2024-3094"},
    )
    assert waived_findings.status_code == 200
    waived = waived_findings.json()["items"][0]
    assert waived["waived"] is True
    assert waived["waiver_status"] == "active"
    assert waived["waiver_id"] == f"api:{waiver_payload['id']}"
    assert waived["waiver_owner"] == "risk-owner-updated"

    listed = client.get(f"/api/projects/{project['id']}/waivers")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["matched_findings"] == 1

    deleted = client.delete(f"/api/waivers/{waiver_payload['id']}")
    assert deleted.status_code == 200
    refreshed = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"q": "CVE-2024-3094"},
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["items"][0]["waiver_id"] is None
    assert refreshed.json()["items"][0]["waived"] is False


def test_workbench_detection_controls_coverage_gaps_and_technique_detail(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "trivy-json",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
            "attack_source": "ctid-json",
            "attack_mapping_file": ATTACK_MAPPING.name,
            "attack_technique_metadata_file": ATTACK_METADATA.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )
    assert response.status_code == 200, response.text

    controls_csv = (
        b"control_id,name,technique_id,technique_name,coverage_level,owner,"
        b"evidence_ref,notes,last_verified_at\n"
        b"edge-waf,WAF exploit-public-app rule,T1190,Exploit Public-Facing Application,"
        b"partial,secops,https://example.invalid/evidence,"
        b"Needs production tuning,2026-04-01\n"
        b"shell-telemetry,Shell command telemetry,T9999,Synthetic Technique,"
        b"not_covered,secops,,Needs owner review,2026-04-02\n"
    )
    imported = client.post(
        f"/api/projects/{project['id']}/detection-controls/import",
        files={"file": ("controls.csv", controls_csv, "text/csv")},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["imported"] == 2
    assert imported.json()["items"][0]["coverage_level"] == "partial"

    controls = client.get(f"/api/projects/{project['id']}/detection-controls")
    assert controls.status_code == 200
    assert controls.json()["items"][0]["control_id"] == "edge-waf"

    created_control = client.post(
        f"/api/projects/{project['id']}/detection-controls",
        json={
            "control_id": "edr-shell",
            "name": "EDR shell telemetry",
            "technique_id": "T1059",
            "coverage_level": "covered",
            "owner": "detection-team",
            "evidence_ref": "case-123",
            "evidence_refs": ["case-123", "runbook-7"],
            "review_status": "needs_review",
        },
    )
    assert created_control.status_code == 200, created_control.text
    assert created_control.json()["review_status"] == "needs_review"
    assert created_control.json()["evidence_refs"] == ["case-123", "runbook-7"]
    patched_control = client.patch(
        f"/api/detection-controls/{created_control.json()['id']}",
        json={
            "coverage_level": "partial",
            "notes": "needs Linux tuning",
            "review_status": "reviewed",
            "evidence_refs": ["case-456"],
        },
    )
    assert patched_control.status_code == 200
    assert patched_control.json()["coverage_level"] == "partial"
    assert patched_control.json()["notes"] == "needs Linux tuning"
    assert patched_control.json()["review_status"] == "reviewed"
    assert patched_control.json()["history_count"] >= 2

    bad_attachment = client.post(
        f"/api/detection-controls/{created_control.json()['id']}/attachments",
        files={"file": ("tool.exe", b"not allowed", "application/octet-stream")},
    )
    assert bad_attachment.status_code == 422

    attachment = client.post(
        f"/api/detection-controls/{created_control.json()['id']}/attachments",
        files={"file": ("evidence.md", b"# Evidence\nCovered by EDR.", "text/markdown")},
    )
    assert attachment.status_code == 200, attachment.text
    attachment_payload = attachment.json()
    assert attachment_payload["filename"] == "evidence.md"
    assert (
        attachment_payload["sha256"] == hashlib.sha256(b"# Evidence\nCovered by EDR.").hexdigest()
    )

    attachments = client.get(f"/api/detection-controls/{created_control.json()['id']}/attachments")
    assert attachments.status_code == 200
    assert [item["id"] for item in attachments.json()["items"]] == [attachment_payload["id"]]

    attachment_download = client.get(
        f"/api/detection-control-attachments/{attachment_payload['id']}/download"
    )
    assert attachment_download.status_code == 200
    assert attachment_download.content == b"# Evidence\nCovered by EDR."

    deleted_attachment = client.delete(
        f"/api/detection-control-attachments/{attachment_payload['id']}"
    )
    assert deleted_attachment.status_code == 200
    assert deleted_attachment.json()["artifact_removed"] is True

    history = client.get(f"/api/detection-controls/{created_control.json()['id']}/history")
    assert history.status_code == 200
    history_events = {item["event_type"] for item in history.json()["items"]}
    assert {"created", "updated", "attachment_added", "attachment_deleted"} <= history_events

    deleted_control = client.delete(f"/api/detection-controls/{created_control.json()['id']}")
    assert deleted_control.status_code == 200

    gaps = client.get(f"/api/projects/{project['id']}/attack/coverage-gaps")
    assert gaps.status_code == 200
    t1190 = next(item for item in gaps.json()["items"] if item["technique_id"] == "T1190")
    assert t1190["coverage_level"] == "partial"
    assert t1190["owner"] == "secops"
    assert "compensating telemetry" in t1190["recommended_action"]
    t9999 = next(item for item in gaps.json()["items"] if item["technique_id"] == "T9999")
    assert t9999["finding_count"] == 0
    assert t9999["coverage_level"] == "not_covered"

    navigator = client.get(f"/api/projects/{project['id']}/attack/coverage-gap-navigator-layer")
    assert navigator.status_code == 200
    navigator_techniques = navigator.json()["techniques"]
    assert any(
        item["techniqueID"] == "T1190" and item["score"] == 60 for item in navigator_techniques
    )
    assert all("offensive" not in item["comment"].lower() for item in navigator_techniques)

    detail = client.get(f"/api/projects/{project['id']}/attack/techniques/T1190")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["technique_id"] == "T1190"
    assert detail_payload["coverage"]["coverage_level"] == "partial"
    assert detail_payload["controls"][0]["owner"] == "secops"
    assert detail_payload["findings"]

    controls_only_detail = client.get(f"/api/projects/{project['id']}/attack/techniques/T9999")
    assert controls_only_detail.status_code == 200
    assert controls_only_detail.json()["coverage"]["control_count"] == 1
    assert controls_only_detail.json()["coverage"]["finding_count"] == 0


def test_workbench_new_api_error_paths_and_detection_import_validation(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)

    empty_token_name = client.post("/api/tokens", json={"name": "   "})
    assert empty_token_name.status_code == 422

    missing_project_routes = [
        ("get", "/api/projects/missing"),
        ("get", "/api/projects/missing/assets"),
        ("get", "/api/projects/missing/waivers"),
        ("get", "/api/projects/missing/runs"),
        ("get", "/api/projects/missing/findings"),
        ("get", "/api/projects/missing/attack/top-techniques"),
        ("get", "/api/projects/missing/detection-controls"),
        ("get", "/api/projects/missing/attack/coverage-gaps"),
        ("get", "/api/projects/missing/attack/coverage-gap-navigator-layer"),
        ("get", "/api/projects/missing/attack/techniques/T1190"),
    ]
    for method, path in missing_project_routes:
        response = getattr(client, method)(path)
        assert response.status_code == 404, path

    assert client.get("/api/assets/missing").status_code == 404
    assert client.patch("/api/assets/missing", json={"owner": "nobody"}).status_code == 404
    assert client.get("/api/analysis-runs/missing").status_code == 404
    assert client.get("/api/runs/missing/summary").status_code == 404
    assert client.get("/api/findings/missing").status_code == 404
    assert client.get("/api/findings/missing/explain").status_code == 404
    assert client.get("/api/findings/missing/ttps").status_code == 404
    missing_waiver_response = client.delete("/api/waivers/missing")
    assert missing_waiver_response.status_code == 404
    assert (
        client.patch(
            "/api/waivers/missing",
            json={
                "cve_id": "CVE-2024-3094",
                "owner": "risk",
                "reason": "Missing waiver update.",
                "expires_on": "2099-12-31",
            },
        ).status_code
        == 404
    )

    project = _create_project(client)
    no_scope = client.post(
        f"/api/projects/{project['id']}/waivers",
        json={
            "owner": "risk",
            "reason": "No scope.",
            "expires_on": "2099-12-31",
        },
    )
    assert no_scope.status_code == 422

    bad_cve = client.post(
        f"/api/projects/{project['id']}/waivers",
        json={
            "cve_id": "not-a-cve",
            "owner": "risk",
            "reason": "Invalid CVE.",
            "expires_on": "2099-12-31",
        },
    )
    assert bad_cve.status_code == 422

    bad_finding = client.post(
        f"/api/projects/{project['id']}/waivers",
        json={
            "finding_id": "missing",
            "owner": "risk",
            "reason": "Invalid finding.",
            "expires_on": "2099-12-31",
        },
    )
    assert bad_finding.status_code == 422

    bad_review = client.post(
        f"/api/projects/{project['id']}/waivers",
        json={
            "cve_id": "CVE-2024-3094",
            "owner": "risk",
            "reason": "Bad review date.",
            "expires_on": "2099-01-01",
            "review_on": "2099-02-01",
        },
    )
    assert bad_review.status_code == 422

    yaml_controls = b"""
controls:
  - control_id: edge-waf
    name: WAF exploit-public-app rule
    technique_id: T1190
    coverage_level: partial
    owner: secops
"""
    yaml_import = client.post(
        f"/api/projects/{project['id']}/detection-controls/import",
        files={"file": ("controls.yaml", yaml_controls, "text/yaml")},
    )
    assert yaml_import.status_code == 200, yaml_import.text
    assert yaml_import.json()["items"][0]["technique_id"] == "T1190"

    invalid_detection_uploads = [
        ("controls.txt", b"technique_id,coverage_level\nT1190,partial\n"),
        ("controls.csv", b""),
        ("controls.csv", b"technique_id,coverage_level\nbad,partial\n"),
        ("controls.csv", b"technique_id,coverage_level\nT1190,unsupported\n"),
        ("controls.yaml", b"controls: {}\n"),
    ]
    for filename, content in invalid_detection_uploads:
        response = client.post(
            f"/api/projects/{project['id']}/detection-controls/import",
            files={"file": (filename, content, "text/plain")},
        )
        assert response.status_code == 422, filename


def test_workbench_api_tokens_config_provider_jobs_and_github_preview(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    client = _client(tmp_path)

    token_response = client.post("/api/tokens", json={"name": "local automation"})
    assert token_response.status_code == 200, token_response.text
    token_payload = token_response.json()
    assert token_payload["token"].startswith("vpr_")
    assert token_payload["token"] not in token_payload["id"]

    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        token_record = session.get(ApiToken, token_payload["id"])
        assert token_record is not None
        assert token_record.token_hash != token_payload["token"]
        assert len(token_record.token_hash) == 64

    assert client.get("/api/diagnostics").status_code == 403
    assert client.get("/api/tokens").status_code == 403

    headers = {"X-API-Token": token_payload["token"]}
    listed_tokens = client.get("/api/tokens", headers=headers)
    assert listed_tokens.status_code == 200
    assert listed_tokens.json()["items"][0]["id"] == token_payload["id"]
    assert "token" not in listed_tokens.json()["items"][0]

    diagnostics = client.get("/api/diagnostics", headers=headers)
    assert diagnostics.status_code == 200
    assert diagnostics.json()["api_tokens_active"] is True

    token_audit = client.get("/api/audit-events", headers=headers)
    assert token_audit.status_code == 200
    assert "api_token.created" in {event["event_type"] for event in token_audit.json()["items"]}

    second_token = client.post(
        "/api/tokens",
        json={"name": "backup automation"},
        headers=headers,
    )
    assert second_token.status_code == 200, second_token.text
    second_headers = {"X-API-Token": second_token.json()["token"]}

    blocked = client.post("/api/projects", json={"name": "blocked-without-token"})
    assert blocked.status_code == 403

    bad_token = client.post(
        "/api/projects",
        json={"name": "blocked-with-bad-token"},
        headers={"X-API-Token": "wrong"},
    )
    assert bad_token.status_code == 403

    project_response = client.post(
        "/api/projects",
        json={"name": "token-gated-project"},
        headers=headers,
    )
    assert project_response.status_code == 200, project_response.text
    project = project_response.json()

    with session_factory() as session:
        token_record = session.get(ApiToken, token_payload["id"])
        assert token_record is not None
        assert token_record.last_used_at is not None

    imported = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
        headers=headers,
    )
    assert imported.status_code == 200, imported.text

    job = client.post(
        "/api/providers/update-jobs",
        json={"sources": ["nvd", "epss", "kev"], "cache_only": True},
        headers=headers,
    )
    assert job.status_code == 200, job.text
    job_payload = job.json()
    assert job_payload["status"] == "completed"
    assert job_payload["metadata"]["snapshot_preserved"] is True
    assert job_payload["metadata"]["snapshot_created"] is True
    assert job_payload["metadata"]["new_snapshot_id"]
    assert job_payload["metadata"]["new_snapshot_hash"]
    assert Path(job_payload["metadata"]["snapshot_path"]).is_file()

    provider_status = client.get("/api/providers/status")
    assert provider_status.status_code == 200
    assert (
        provider_status.json()["snapshot"]["content_hash"]
        == job_payload["metadata"]["new_snapshot_hash"]
    )

    saved_config = client.post(
        f"/api/projects/{project['id']}/settings/config",
        json={
            "config": {
                "version": 1,
                "defaults": {"locked_provider_data": True},
                "commands": {"analyze": {"format": "json", "sort_by": "operational"}},
            }
        },
        headers=headers,
    )
    assert saved_config.status_code == 200, saved_config.text
    assert saved_config.json()["config"]["defaults"]["locked_provider_data"] is True

    invalid_config = client.post(
        f"/api/projects/{project['id']}/settings/config",
        json={"config": {"unknown": True}},
        headers=headers,
    )
    assert invalid_config.status_code == 422

    loaded_config = client.get(f"/api/projects/{project['id']}/settings/config")
    assert loaded_config.status_code == 200
    assert loaded_config.json()["item"]["id"] == saved_config.json()["id"]

    updated_config = client.post(
        f"/api/projects/{project['id']}/settings/config",
        json={
            "config": {
                "version": 1,
                "defaults": {"locked_provider_data": True},
                "commands": {"analyze": {"format": "json", "sort_by": "epss"}},
            }
        },
        headers=headers,
    )
    assert updated_config.status_code == 200, updated_config.text
    history = client.get(
        f"/api/projects/{project['id']}/settings/config/history",
        headers=headers,
    )
    assert history.status_code == 200
    assert [item["id"] for item in history.json()["items"]][:2] == [
        updated_config.json()["id"],
        saved_config.json()["id"],
    ]
    diff = client.get(
        f"/api/projects/{project['id']}/settings/config/{updated_config.json()['id']}/diff",
        params={"base_id": saved_config.json()["id"]},
        headers=headers,
    )
    assert diff.status_code == 200
    assert diff.json()["changed"]["commands.analyze.sort_by"] == {
        "before": "operational",
        "after": "epss",
    }
    defaults = client.get(
        f"/api/projects/{project['id']}/settings/config/defaults",
        headers=headers,
    )
    assert defaults.status_code == 200
    assert defaults.json()["config"]["version"] == 1
    exported_config = client.get(
        f"/api/projects/{project['id']}/settings/config/{updated_config.json()['id']}/export",
        headers=headers,
    )
    assert exported_config.status_code == 200
    assert exported_config.headers["content-disposition"].startswith("attachment;")
    assert exported_config.json()["commands"]["analyze"]["sort_by"] == "epss"
    rollback = client.post(
        f"/api/projects/{project['id']}/settings/config/{saved_config.json()['id']}/rollback",
        headers=headers,
    )
    assert rollback.status_code == 200
    assert rollback.json()["source"] == f"rollback:{saved_config.json()['id']}"
    assert rollback.json()["config"]["commands"]["analyze"]["sort_by"] == "operational"

    preview = client.post(
        f"/api/projects/{project['id']}/github/issues/preview",
        json={"limit": 4, "priority": "Critical", "milestone": "v1.2"},
        headers=headers,
    )
    assert preview.status_code == 200, preview.text
    preview_payload = preview.json()
    assert preview_payload["dry_run"] is True
    assert preview_payload["items"]
    duplicate_keys = [item["duplicate_key"] for item in preview_payload["items"]]
    assert len(duplicate_keys) == len(set(duplicate_keys))
    assert all(item["milestone"] == "v1.2" for item in preview_payload["items"])

    dry_run_export = client.post(
        f"/api/projects/{project['id']}/github/issues/export",
        json={
            "repository": "acme/workbench-triage",
            "limit": 1,
            "priority": "Critical",
            "dry_run": True,
        },
        headers=headers,
    )
    assert dry_run_export.status_code == 200, dry_run_export.text
    assert dry_run_export.json()["items"][0]["status"] == "preview"

    posted_payloads: list[dict[str, Any]] = []

    class FakeGitHubResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {"html_url": "https://github.com/acme/workbench-triage/issues/7", "number": 7}

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        assert args == ("https://api.github.com/repos/acme/workbench-triage/issues",)
        assert kwargs["headers"]["Authorization"] == "Bearer ghp_test"
        assert "ghp_test" not in kwargs["json"]["body"]
        assert "vuln-prioritizer duplicate_key" in kwargs["json"]["body"]
        posted_payloads.append(kwargs["json"])
        return FakeGitHubResponse()

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setattr("vuln_prioritizer.api.workbench_github.requests.post", fake_post)
    exported = client.post(
        f"/api/projects/{project['id']}/github/issues/export",
        json={
            "repository": "acme/workbench-triage",
            "limit": 1,
            "priority": "Critical",
            "dry_run": False,
        },
        headers=headers,
    )
    assert exported.status_code == 200, exported.text
    exported_payload = exported.json()
    assert exported_payload["created_count"] == 1
    assert exported_payload["items"][0]["status"] == "created"
    assert exported_payload["items"][0]["issue_url"].endswith("/issues/7")
    assert len(posted_payloads) == 1

    duplicate_export = client.post(
        f"/api/projects/{project['id']}/github/issues/export",
        json={
            "repository": "acme/workbench-triage",
            "limit": 1,
            "priority": "Critical",
            "dry_run": False,
        },
        headers=headers,
    )
    assert duplicate_export.status_code == 200, duplicate_export.text
    assert duplicate_export.json()["created_count"] == 0
    assert duplicate_export.json()["skipped_count"] == 1
    assert duplicate_export.json()["items"][0]["status"] == "skipped_duplicate"
    assert len(posted_payloads) == 1

    ticket_preview = client.post(
        f"/api/projects/{project['id']}/tickets/preview",
        json={"provider": "jira", "priority": "Critical", "limit": 1},
        headers=headers,
    )
    assert ticket_preview.status_code == 200, ticket_preview.text
    ticket_item = ticket_preview.json()["items"][0]
    assert ticket_item["provider"] == "jira"
    assert ticket_item["status"] == "preview"
    assert ticket_item["idempotency_key"].startswith("vuln-prioritizer:")

    ticket_posts: list[dict[str, Any]] = []

    class FakeTicketResponse:
        status_code = 201

        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_ticket_post(*args: Any, **kwargs: Any) -> FakeTicketResponse:
        url = args[0]
        assert kwargs["headers"]["Authorization"].startswith("Bearer ")
        assert kwargs["headers"]["Idempotency-Key"].startswith("vuln-prioritizer:")
        assert "jira_test" not in json.dumps(kwargs["json"])
        assert "snow_test" not in json.dumps(kwargs["json"])
        ticket_posts.append({"url": url, "json": kwargs["json"]})
        if url == "https://jira.example.invalid/rest/api/3/issue":
            return FakeTicketResponse({"key": "SEC-7", "id": "10007"})
        if url == "https://snow.example.invalid/api/now/table/incident":
            return FakeTicketResponse(
                {
                    "result": {
                        "number": "INC0007",
                        "sys_id": "abc123",
                        "link": "https://snow.example.invalid/nav_to.do?uri=incident.do?sys_id=abc123",
                    }
                }
            )
        raise AssertionError(url)

    monkeypatch.setattr("vuln_prioritizer.api.workbench_tickets.requests.post", fake_ticket_post)
    monkeypatch.setenv("JIRA_TOKEN", "jira_test")
    monkeypatch.setenv(
        "VULN_PRIORITIZER_TICKET_BASE_URL_ALLOWLIST",
        "https://jira.example.invalid,https://snow.example.invalid",
    )
    jira_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "jira",
            "priority": "Critical",
            "limit": 1,
            "dry_run": False,
            "base_url": "https://jira.example.invalid",
            "token_env": "JIRA_TOKEN",
            "jira_project_key": "SEC",
        },
        headers=headers,
    )
    assert jira_export.status_code == 200, jira_export.text
    assert jira_export.json()["created_count"] == 1
    assert (
        jira_export.json()["items"][0]["ticket_url"] == "https://jira.example.invalid/browse/SEC-7"
    )
    duplicate_jira_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "jira",
            "priority": "Critical",
            "limit": 1,
            "dry_run": False,
            "base_url": "https://jira.example.invalid",
            "token_env": "JIRA_TOKEN",
            "jira_project_key": "SEC",
        },
        headers=headers,
    )
    assert duplicate_jira_export.status_code == 200, duplicate_jira_export.text
    assert duplicate_jira_export.json()["created_count"] == 0
    assert duplicate_jira_export.json()["skipped_count"] == 1
    assert duplicate_jira_export.json()["items"][0]["status"] == "skipped_duplicate"
    assert len(ticket_posts) == 1

    monkeypatch.setenv("SERVICENOW_TOKEN", "snow_test")
    custom_table_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "servicenow",
            "priority": "Critical",
            "limit": 1,
            "dry_run": False,
            "base_url": "https://snow.example.invalid",
            "token_env": "SERVICENOW_TOKEN",
            "servicenow_table": "change_request",
        },
        headers=headers,
    )
    assert custom_table_export.status_code == 422
    servicenow_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "servicenow",
            "priority": "Critical",
            "limit": 1,
            "dry_run": False,
            "base_url": "https://snow.example.invalid",
            "token_env": "SERVICENOW_TOKEN",
            "servicenow_table": "incident",
        },
        headers=headers,
    )
    assert servicenow_export.status_code == 200, servicenow_export.text
    assert servicenow_export.json()["created_count"] == 1
    assert servicenow_export.json()["items"][0]["external_id"] == "INC0007"
    assert len(ticket_posts) == 2

    unsafe_ticket_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "jira",
            "dry_run": False,
            "base_url": "http://jira.example.invalid",
            "token_env": "JIRA_TOKEN",
            "jira_project_key": "SEC",
        },
        headers=headers,
    )
    assert unsafe_ticket_export.status_code == 422
    loopback_ticket_export = client.post(
        f"/api/projects/{project['id']}/tickets/export",
        json={
            "provider": "jira",
            "dry_run": False,
            "base_url": "https://127.0.0.1",
            "token_env": "JIRA_TOKEN",
            "jira_project_key": "SEC",
        },
        headers=headers,
    )
    assert loopback_ticket_export.status_code == 422

    revoke = client.delete(f"/api/tokens/{token_payload['id']}", headers=headers)
    assert revoke.status_code == 200
    assert revoke.json()["active"] is False
    revoked_write = client.post(
        "/api/projects",
        json={"name": "blocked-revoked-token"},
        headers=headers,
    )
    assert revoked_write.status_code == 403
    listed_after_revoke = client.get("/api/tokens", headers=second_headers)
    assert listed_after_revoke.status_code == 200
    token_states = {item["id"]: item["active"] for item in listed_after_revoke.json()["items"]}
    assert token_states[token_payload["id"]] is False


def test_workbench_csv_report_escapes_spreadsheet_formulas(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    content = (
        b"cve,component,version,target_ref,asset_id,owner,business_service\n"
        b'CVE-2024-3094,"=HYPERLINK(""https://example.invalid"")",5.6.0,'
        b"repo:demo,asset-1,+owner,@service\n"
    )
    run = _import_payload(
        client,
        project["id"],
        input_format="generic-occurrence-csv",
        filename="generic.csv",
        content=content,
        content_type="text/csv",
    )
    report = client.post(
        f"/api/analysis-runs/{run['id']}/reports",
        json={"format": "csv"},
    )
    assert report.status_code == 200
    csv_report = client.get(report.json()["download_url"])
    assert csv_report.status_code == 200
    assert "'=HYPERLINK" in csv_report.text
    assert ",+owner," not in csv_report.text
    assert ",'+owner," in csv_report.text
    assert ",'@service," in csv_report.text


def test_workbench_rejects_unsupported_and_oversized_uploads(tmp_path: Path) -> None:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        max_upload_mb=1,
    )
    client = TestClient(create_app(settings=settings))
    project = _create_project(client)

    bad_format = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "nessus-xml"},
        files={"file": ("scan.xml", b"<xml />", "application/xml")},
    )
    assert bad_format.status_code == 422

    path_traversal = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "trivy-json"},
        files={"file": ("../../trivy.json", b"{}", "application/json")},
    )
    assert path_traversal.status_code == 422
    assert "Upload filename is not allowed" in path_traversal.text
    assert not (tmp_path / "trivy.json").exists()

    context_path_traversal = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "cve-list"},
        files={
            "file": ("sample.txt", b"CVE-2024-3094\n", "text/plain"),
            "asset_context_file": ("../asset.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
        },
    )
    assert context_path_traversal.status_code == 422
    assert "Upload filename is not allowed" in context_path_traversal.text
    assert not any(settings.upload_dir.rglob("*"))

    oversized = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "cve-list"},
        files={"file": ("large.txt", b"A" * (2 * 1024 * 1024), "text/plain")},
    )
    assert oversized.status_code == 413


def test_workbench_rejects_untrusted_provider_snapshot_path(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)

    response = client.post(
        f"/api/projects/{project['id']}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": str(tmp_path / "private-snapshot.json"),
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Provider snapshot path is not allowed" in response.text


def test_workbench_downloads_reject_tampered_artifact_paths(tmp_path: Path) -> None:
    client, settings = _client_and_settings(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project(name="artifact-tamper")
        run = repo.create_analysis_run(project_id=project.id, input_type="cve-list")
        report = repo.add_report(
            project_id=project.id,
            analysis_run_id=run.id,
            kind="analysis-json",
            format="json",
            path=str(outside),
            sha256=hashlib.sha256(outside.read_bytes()).hexdigest(),
        )
        session.commit()
        report_id = report.id

    response = client.get(f"/api/reports/{report_id}/download")
    assert response.status_code == 404

    valid_path = settings.report_dir / "run" / "analysis.json"
    valid_path.parent.mkdir(parents=True)
    valid_path.write_text("{}", encoding="utf-8")
    original_sha = hashlib.sha256(valid_path.read_bytes()).hexdigest()
    valid_path.write_text('{"tampered": true}', encoding="utf-8")

    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.get_project_by_name("artifact-tamper")
        assert project is not None
        run = repo.list_analysis_runs(project.id)[0]
        checksum_report = repo.add_report(
            project_id=project.id,
            analysis_run_id=run.id,
            kind="analysis-json",
            format="json",
            path=str(valid_path),
            sha256=original_sha,
        )
        session.commit()
        checksum_report_id = checksum_report.id

    response = client.get(f"/api/reports/{checksum_report_id}/download")
    assert response.status_code == 409


def test_workbench_findings_api_handles_10k_pagination_smoke(tmp_path: Path) -> None:
    client = _client(tmp_path)
    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        project = repo.create_project(name="ten-k-smoke")
        vulnerabilities = [
            Vulnerability(id=f"vuln-{index}", cve_id=f"CVE-2099-{index:05d}")
            for index in range(10_000)
        ]
        session.add_all(vulnerabilities)
        session.flush()
        session.add_all(
            [
                Finding(
                    id=f"finding-{index}",
                    project_id=project.id,
                    vulnerability_id=f"vuln-{index}",
                    cve_id=f"CVE-2099-{index:05d}",
                    status="open",
                    priority="Low",
                    priority_rank=4,
                    operational_rank=index + 1,
                    finding_json={},
                    explanation_json={},
                )
                for index in range(10_000)
            ]
        )
        session.commit()
        project_id = project.id

    response = client.get(
        f"/api/projects/{project_id}/findings",
        params={"sort": "cve", "limit": 100, "offset": 9900},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 10_000
    assert payload["limit"] == 100
    assert len(payload["items"]) == 100
    assert payload["items"][0]["cve_id"] == "CVE-2099-09900"
