from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app, get_engine
from vuln_prioritizer.db import WorkbenchRepository, create_session_factory
from vuln_prioritizer.workbench_config import WorkbenchSettings

ROOT = Path(__file__).resolve().parents[2]
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
TRIVY_REPORT = ROOT / "data" / "input_fixtures" / "trivy_report.json"
GRYPE_REPORT = ROOT / "data" / "input_fixtures" / "grype_report.json"
EXPECTED_SAMPLE_CVES = {
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-44487",
    "CVE-2024-3094",
}


def _client(tmp_path: Path) -> TestClient:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
    )
    return TestClient(create_app(settings=settings))


def _client_and_settings(tmp_path: Path) -> tuple[TestClient, WorkbenchSettings]:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
    )
    return TestClient(create_app(settings=settings)), settings


def _create_project(client: TestClient) -> dict[str, Any]:
    response = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert response.status_code == 200
    return response.json()


def _import_sample(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": str(DEMO_PROVIDER_SNAPSHOT),
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
            "provider_snapshot_file": str(DEMO_PROVIDER_SNAPSHOT),
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

    version = client.get("/api/version")
    assert version.status_code == 200
    assert version.json()["app"] == "Vuln Prioritizer Workbench"

    project = _create_project(client)
    assert project["name"] == "online-shop-demo"

    projects = client.get("/api/projects")
    assert projects.status_code == 200
    assert projects.json()["items"][0]["id"] == project["id"]

    duplicate = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert duplicate.status_code == 409


def test_workbench_import_findings_reports_and_evidence(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    run = _import_sample(client, project["id"])

    assert run["status"] == "completed"
    assert run["input_type"] == "cve-list"
    assert run["input_filename"] == "sample.txt"
    assert run["finished_at"] is not None
    assert run["summary"]["findings_count"] == len(EXPECTED_SAMPLE_CVES)
    assert run["summary"]["kev_hits"] >= 1
    assert run["summary"]["counts_by_priority"]

    project_runs = client.get(f"/api/projects/{project['id']}/runs")
    assert project_runs.status_code == 200
    assert [item["id"] for item in project_runs.json()["items"]] == [run["id"]]

    run_alias = client.get(f"/api/runs/{run['id']}")
    assert run_alias.status_code == 200
    assert run_alias.json()["id"] == run["id"]

    run_summary = client.get(f"/api/runs/{run['id']}/summary")
    assert run_summary.status_code == 200
    assert run_summary.json()["findings_count"] == len(EXPECTED_SAMPLE_CVES)

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
    }
    for report_format, (expected_kind, expected_content) in report_expectations.items():
        report = client.post(
            f"/api/analysis-runs/{run['id']}/reports",
            json={"format": report_format},
        )
        assert report.status_code == 200
        report_payload = report.json()
        assert report_payload["format"] == report_format
        assert report_payload["kind"] == expected_kind
        assert len(report_payload["sha256"]) == 64

        report_download = client.get(report_payload["download_url"])
        assert report_download.status_code == 200
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
        manifest_files = {item["path"]: item for item in manifest["files"]}
        for artifact_name in ["analysis.json", "report.html", "summary.md", "input/sample.txt"]:
            assert artifact_name in manifest_files
            assert (
                manifest_files[artifact_name]["sha256"]
                == hashlib.sha256(archive.read(artifact_name)).hexdigest()
            )


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
    assert not (tmp_path / "trivy.json").exists()

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
