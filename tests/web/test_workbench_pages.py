from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup
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


def test_project_setup_dashboard_and_empty_findings_pages(tmp_path: Path) -> None:
    client = _client(tmp_path)

    setup = client.get("/projects/new")
    assert setup.status_code == 200
    soup = BeautifulSoup(setup.text, "html.parser")
    token = soup.select_one("input[name=csrf_token]")
    assert token is not None

    created = client.post(
        "/projects",
        data={"name": "online-shop-demo", "description": "", "csrf_token": token["value"]},
        follow_redirects=False,
    )
    assert created.status_code == 303
    dashboard_path = created.headers["location"]

    dashboard = client.get(dashboard_path)
    assert dashboard.status_code == 200
    assert "online-shop-demo" in dashboard.text

    project_id = dashboard_path.split("/")[2]
    findings = client.get(f"/projects/{project_id}/findings")
    assert findings.status_code == 200
    assert "No findings imported." in findings.text


def test_web_import_report_page_and_finding_detail(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = client.post("/api/projects", json={"name": "web-demo"}).json()
    import_page = client.get(f"/projects/{project['id']}/imports/new")
    soup = BeautifulSoup(import_page.text, "html.parser")
    token = soup.select_one("input[name=csrf_token]")
    assert token is not None

    imported = client.post(
        f"/web/projects/{project['id']}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": "data/demo_provider_snapshot.json",
            "locked_provider_data": "true",
            "csrf_token": token["value"],
        },
        files={"file": ("sample.txt", Path("data/sample_cves.txt").read_bytes(), "text/plain")},
        follow_redirects=False,
    )
    assert imported.status_code == 303
    reports = client.get(imported.headers["location"])
    assert reports.status_code == 200
    assert "Run artifacts" in reports.text

    findings = client.get(f"/projects/{project['id']}/findings")
    assert findings.status_code == 200
    detail_link = BeautifulSoup(findings.text, "html.parser").select_one("td a")
    assert detail_link is not None
    detail = client.get(str(detail_link["href"]))
    assert detail.status_code == 200
    assert "Why this priority?" in detail.text
