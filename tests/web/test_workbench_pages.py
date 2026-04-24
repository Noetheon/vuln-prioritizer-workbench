from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app
from vuln_prioritizer.workbench_config import WorkbenchSettings

ROOT = Path(__file__).resolve().parents[2]
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
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
        provider_snapshot_dir=ROOT / "data",
    )
    return TestClient(create_app(settings=settings))


def _csrf_token(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    token = soup.select_one("input[name=csrf_token]")
    assert token is not None
    return str(token["value"])


def _create_project_via_web(client: TestClient, *, name: str) -> tuple[str, str]:
    setup = client.get("/projects/new")
    assert setup.status_code == 200
    token = _csrf_token(setup.text)

    created = client.post(
        "/projects",
        data={"name": name, "description": "Workbench happy path", "csrf_token": token},
        follow_redirects=False,
    )
    assert created.status_code == 303
    dashboard_path = created.headers["location"]
    project_id = dashboard_path.split("/")[2]
    return project_id, dashboard_path


def test_project_setup_dashboard_and_empty_findings_pages(tmp_path: Path) -> None:
    client = _client(tmp_path)

    setup = client.get("/projects/new")
    assert setup.status_code == 200
    token = _csrf_token(setup.text)

    created = client.post(
        "/projects",
        data={"name": "online-shop-demo", "description": "", "csrf_token": token},
        follow_redirects=False,
    )
    assert created.status_code == 303
    dashboard_path = created.headers["location"]

    dashboard = client.get(dashboard_path)
    assert dashboard.status_code == 200
    assert "online-shop-demo" in dashboard.text

    duplicate = client.post(
        "/projects",
        data={"name": "online-shop-demo", "description": "", "csrf_token": token},
    )
    assert duplicate.status_code == 409

    project_id = dashboard_path.split("/")[2]
    findings = client.get(f"/projects/{project_id}/findings")
    assert findings.status_code == 200
    assert "No findings imported." in findings.text


def test_web_import_report_page_and_finding_detail(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project_id, dashboard_path = _create_project_via_web(client, name="web-demo")

    import_page = client.get(f"/projects/{project_id}/imports/new")
    assert import_page.status_code == 200
    assert "web-demo" in import_page.text
    token = _csrf_token(import_page.text)

    imported = client.post(
        f"/web/projects/{project_id}/imports",
        data={
            "input_format": "cve-list",
            "provider_snapshot_file": DEMO_PROVIDER_SNAPSHOT.name,
            "locked_provider_data": "true",
            "csrf_token": token,
        },
        files={"file": ("sample.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
        follow_redirects=False,
    )
    assert imported.status_code == 303
    reports_path = imported.headers["location"]
    run_id = reports_path.split("/")[2]

    dashboard = client.get(dashboard_path)
    assert dashboard.status_code == 200
    assert "CVE-2021-44228" in dashboard.text
    assert "completed" in dashboard.text

    reports = client.get(reports_path)
    assert reports.status_code == 200
    assert "Run artifacts" in reports.text
    assert "No reports generated." in reports.text
    assert "No evidence bundles generated." in reports.text

    findings = client.get(f"/projects/{project_id}/findings")
    assert findings.status_code == 200
    for cve_id in EXPECTED_SAMPLE_CVES:
        assert cve_id in findings.text
    detail_link = BeautifulSoup(findings.text, "html.parser").select_one("td a")
    assert detail_link is not None
    detail = client.get(str(detail_link["href"]))
    assert detail.status_code == 200
    assert "Why this priority?" in detail.text

    report_token = _csrf_token(reports.text)
    created_report = client.post(
        f"/web/analysis-runs/{run_id}/reports",
        data={"report_format": "html", "csrf_token": report_token},
        follow_redirects=False,
    )
    assert created_report.status_code == 303
    assert created_report.headers["location"] == reports_path

    reports = client.get(reports_path)
    assert reports.status_code == 200
    soup = BeautifulSoup(reports.text, "html.parser")
    report_link = soup.select_one('a[href^="/api/reports/"]')
    assert report_link is not None
    assert "html-report" in report_link.text

    report_download = client.get(str(report_link["href"]))
    assert report_download.status_code == 200
    assert b"CVE-2021-44228" in report_download.content

    bundle_token = _csrf_token(reports.text)
    created_bundle = client.post(
        f"/web/analysis-runs/{run_id}/evidence-bundle",
        data={"csrf_token": bundle_token},
        follow_redirects=False,
    )
    assert created_bundle.status_code == 303
    assert created_bundle.headers["location"] == reports_path

    reports = client.get(reports_path)
    assert reports.status_code == 200
    bundle_link = BeautifulSoup(reports.text, "html.parser").select_one(
        'a[href^="/api/evidence-bundles/"]'
    )
    assert bundle_link is not None
    assert "Evidence ZIP" in bundle_link.text

    bundle_download = client.get(str(bundle_link["href"]))
    assert bundle_download.status_code == 200
    assert bundle_download.content.startswith(b"PK")
