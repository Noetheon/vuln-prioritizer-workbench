from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app
from vuln_prioritizer.workbench_config import WorkbenchSettings


def _client(tmp_path: Path) -> TestClient:
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
    )
    return TestClient(create_app(settings=settings))


def _create_project(client: TestClient) -> dict[str, Any]:
    response = client.post("/api/projects", json={"name": "online-shop-demo"})
    assert response.status_code == 200
    return response.json()


def _import_sample(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": "data/demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", Path("data/sample_cves.txt").read_bytes(), "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_workbench_health_and_project_crud(tmp_path: Path) -> None:
    client = _client(tmp_path)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    project = _create_project(client)
    assert project["name"] == "online-shop-demo"

    projects = client.get("/api/projects")
    assert projects.status_code == 200
    assert projects.json()["items"][0]["id"] == project["id"]


def test_workbench_import_findings_reports_and_evidence(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = _create_project(client)
    run = _import_sample(client, project["id"])

    assert run["status"] == "completed"
    assert run["summary"]["findings_count"] >= 1

    findings = client.get(f"/api/projects/{project['id']}/findings")
    assert findings.status_code == 200
    items = findings.json()["items"]
    assert {item["cve_id"] for item in items} >= {"CVE-2021-44228", "CVE-2024-3094"}

    detail = client.get(f"/api/findings/{items[0]['id']}")
    assert detail.status_code == 200
    assert "finding" in detail.json()

    report = client.post(f"/api/analysis-runs/{run['id']}/reports", json={"format": "html"})
    assert report.status_code == 200
    report_download = client.get(report.json()["download_url"])
    assert report_download.status_code == 200
    assert b"Vulnerability" in report_download.content

    bundle = client.post(f"/api/analysis-runs/{run['id']}/evidence-bundle")
    assert bundle.status_code == 200
    bundle_download = client.get(bundle.json()["download_url"])
    assert bundle_download.status_code == 200
    assert bundle_download.content.startswith(b"PK")


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
    assert path_traversal.status_code in {200, 422}

    oversized = client.post(
        f"/api/projects/{project['id']}/imports",
        data={"input_format": "cve-list"},
        files={"file": ("large.txt", b"A" * (2 * 1024 * 1024), "text/plain")},
    )
    assert oversized.status_code == 413
