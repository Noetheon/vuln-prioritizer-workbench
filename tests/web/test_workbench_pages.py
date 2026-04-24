from __future__ import annotations

from pathlib import Path

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app, get_engine
from vuln_prioritizer.db import WorkbenchRepository, create_session_factory
from vuln_prioritizer.web.routes import _redacted_database_url
from vuln_prioritizer.workbench_config import WorkbenchSettings

ROOT = Path(__file__).resolve().parents[2]
DEMO_PROVIDER_SNAPSHOT = ROOT / "data" / "demo_provider_snapshot.json"
SAMPLE_CVES = ROOT / "data" / "sample_cves.txt"
TRIVY_REPORT = ROOT / "data" / "input_fixtures" / "trivy_report.json"
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
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=ROOT / "data",
        attack_artifact_dir=ROOT / "data" / "attack",
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


def test_web_settings_redacts_database_password() -> None:
    redacted = _redacted_database_url("postgresql://workbench:secret-api-key@db.internal/app")

    assert "secret-api-key" not in redacted
    assert "***" in redacted


def test_web_import_report_page_and_finding_detail(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project_id, dashboard_path = _create_project_via_web(client, name="web-demo")

    import_page = client.get(f"/projects/{project_id}/imports/new")
    assert import_page.status_code == 200
    assert "web-demo" in import_page.text
    assert 'name="asset_context_file"' in import_page.text
    assert 'name="vex_file"' in import_page.text
    assert 'name="waiver_file"' in import_page.text
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
    assert "Freshness" in dashboard.text
    assert "EPSS" in dashboard.text

    reports = client.get(reports_path)
    assert reports.status_code == 200
    assert "Run artifacts" in reports.text
    assert "No reports generated." in reports.text
    assert "No evidence bundles generated." in reports.text

    findings = client.get(f"/projects/{project_id}/findings")
    assert findings.status_code == 200
    for cve_id in EXPECTED_SAMPLE_CVES:
        assert cve_id in findings.text
    filtered = client.get(
        f"/projects/{project_id}/findings",
        params={"q": "CVE-2024-3094", "kev": "", "sort": "cve"},
    )
    assert filtered.status_code == 200
    assert "CVE-2024-3094" in filtered.text
    assert "Showing 1-1 of 1 findings." in filtered.text
    detail_link = BeautifulSoup(findings.text, "html.parser").select_one("td a")
    assert detail_link is not None
    detail = client.get(str(detail_link["href"]))
    assert detail.status_code == 200
    assert "Why this priority?" in detail.text

    intelligence = client.get(
        f"/projects/{project_id}/vulnerabilities",
        params={"q": "CVE-2021-44228"},
    )
    assert intelligence.status_code == 200
    assert "Stored provider data" in intelligence.text
    assert "CVE-2021-44228" in intelligence.text

    settings = client.get(f"/projects/{project_id}/settings")
    assert settings.status_code == 200
    assert "Provider sources" in settings.text
    assert "NVD API key value" in settings.text
    assert "secret-api-key" not in settings.text

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
    verify_link = BeautifulSoup(reports.text, "html.parser").select_one(
        'a[href^="/evidence-bundles/"]'
    )
    assert bundle_link is not None
    assert verify_link is not None
    assert "Evidence ZIP" in bundle_link.text

    bundle_download = client.get(str(bundle_link["href"]))
    assert bundle_download.status_code == 200
    assert bundle_download.content.startswith(b"PK")

    verification = client.get(str(verify_link["href"]))
    assert verification.status_code == 200
    assert "Bundle verification" in verification.text
    assert "Passed" in verification.text


def test_web_governance_page_surfaces_uploaded_context_vex_and_waivers(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = client.post("/api/projects", json={"name": "governance-web-demo"}).json()
    waiver = "\n".join(
        [
            "waivers:",
            "  - id: review-due-xz",
            "    cve_id: CVE-2024-3094",
            "    owner: risk-review",
            "    reason: Temporary acceptance for coordinated rollout.",
            "    expires_on: 2099-12-31",
            "    review_on: 2000-01-01",
            '    ticket_url: "javascript:alert(1)"',
            "    services: [customer-login]",
        ]
    ).encode()
    imported = client.post(
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
    assert imported.status_code == 200, imported.text

    governance = client.get(f"/projects/{project['id']}/governance")
    assert governance.status_code == 200
    assert "Governance" in governance.text
    assert "platform-team" in governance.text
    assert "customer-login" in governance.text
    assert "VEX suppressed" in governance.text
    assert "Review due" in governance.text

    dashboard = client.get(f"/projects/{project['id']}/dashboard")
    assert dashboard.status_code == 200
    assert "VEX suppressed" in dashboard.text
    assert "Waiver review due" in dashboard.text

    api_findings = client.get(f"/api/projects/{project['id']}/findings")
    xz = next(item for item in api_findings.json()["items"] if item["cve_id"] == "CVE-2024-3094")
    detail = client.get(f"/findings/{xz['id']}")
    assert detail.status_code == 200
    assert 'href="javascript:alert(1)"' not in detail.text
    assert "javascript:alert(1)" in detail.text


def test_web_attack_dashboard_and_finding_ttp_context(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = client.post("/api/projects", json={"name": "attack-web-demo"}).json()
    imported = client.post(
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
    assert imported.status_code == 200, imported.text

    dashboard = client.get(f"/projects/{project['id']}/dashboard")
    assert dashboard.status_code == 200
    assert "Top techniques" in dashboard.text
    assert "T1190" in dashboard.text

    findings = client.get(f"/api/projects/{project['id']}/findings")
    mapped = next(item for item in findings.json()["items"] if item["attack_mapped"])
    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        contexts = repo.list_finding_attack_contexts(mapped["id"])
        assert contexts
        techniques = [dict(item) for item in contexts[0].techniques_json]
        techniques[0]["url"] = "javascript:alert(1)"
        techniques[0]["name"] = "Malicious ATT&CK link"
        contexts[0].techniques_json = techniques
        session.commit()

    detail = client.get(f"/findings/{mapped['id']}")
    assert detail.status_code == 200
    assert "ATT&amp;CK TTPs" in detail.text
    assert "Threat context" in detail.text
    assert "source_reviewed" in detail.text
    assert "Malicious ATT&amp;CK link" in detail.text
    assert 'href="javascript:alert(1)"' not in detail.text
