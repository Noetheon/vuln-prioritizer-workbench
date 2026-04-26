from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi import HTTPException
from fastapi.testclient import TestClient

from vuln_prioritizer.api.app import create_app, get_engine
from vuln_prioritizer.db import WorkbenchRepository, create_session_factory
from vuln_prioritizer.web.routes import _project_path, _redacted_database_url
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
    snapshot_dir = tmp_path / "provider-snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DEMO_PROVIDER_SNAPSHOT, snapshot_dir / DEMO_PROVIDER_SNAPSHOT.name)
    settings = WorkbenchSettings(
        database_url=f"sqlite:///{tmp_path / 'workbench.db'}",
        upload_dir=tmp_path / "uploads",
        report_dir=tmp_path / "reports",
        provider_cache_dir=tmp_path / "cache",
        provider_snapshot_dir=snapshot_dir,
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


def test_web_route_error_paths_and_local_redirects(tmp_path: Path) -> None:
    client = _client(tmp_path)

    root = client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/projects/new"

    favicon = client.get("/favicon.ico")
    assert favicon.status_code == 204

    setup = client.get("/projects/new")
    token = _csrf_token(setup.text)
    empty_project = client.post(
        "/projects",
        data={"name": "   ", "description": "", "csrf_token": token},
    )
    assert empty_project.status_code == 422

    created = client.post(
        "/projects",
        data={"name": "error-path-demo", "description": "", "csrf_token": token},
        follow_redirects=False,
    )
    assert created.status_code == 303
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"].endswith("/dashboard")

    duplicate = client.post(
        "/projects",
        data={"name": "error-path-demo", "description": "", "csrf_token": token},
    )
    assert duplicate.status_code == 409

    missing_gets = [
        "/projects/missing/dashboard",
        "/projects/missing/imports/new",
        "/projects/missing/assets",
        "/projects/missing/waivers",
        "/projects/missing/coverage",
        "/projects/missing/attack/techniques/T1190",
        "/findings/missing",
    ]
    for path in missing_gets:
        response = client.get(path)
        assert response.status_code == 404, path

    assert (
        client.post(
            "/web/assets/missing",
            data={
                "asset_id": "missing",
                "owner": "",
                "business_service": "",
                "environment": "",
                "exposure": "",
                "criticality": "",
                "csrf_token": token,
            },
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/web/waivers/missing/delete",
            data={"csrf_token": token},
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/web/projects/missing/coverage/import",
            data={"csrf_token": token},
            files={
                "file": (
                    "controls.csv",
                    b"technique_id,coverage_level\nT1190,partial\n",
                    "text/csv",
                )
            },
        ).status_code
        == 404
    )


def test_project_redirect_paths_are_local_and_validated() -> None:
    project_id = "1" * 32

    assert _project_path(project_id, "waivers") == f"/projects/{project_id}/waivers"
    assert _project_path(project_id, "coverage") == f"/projects/{project_id}/coverage"

    with pytest.raises(HTTPException):
        _project_path("//example.invalid", "waivers")
    with pytest.raises(HTTPException):
        _project_path(project_id, "//example.invalid")


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
    dashboard_soup = BeautifulSoup(dashboard.text, "html.parser")
    assert (
        dashboard_soup.select_one(f'a[href="/analysis-runs/{run_id}/executive-report"]') is not None
    )
    assert dashboard_soup.select_one(f'a[href="/analysis-runs/{run_id}/reports"]') is not None

    reports = client.get(reports_path)
    assert reports.status_code == 200
    assert "Run artifacts" in reports.text
    assert "Open executive report" in reports.text
    assert "No reports generated." in reports.text
    assert "No evidence bundles generated." in reports.text
    reports_soup = BeautifulSoup(reports.text, "html.parser")
    sidebar = reports_soup.select_one(".app-sidebar")
    assert sidebar is not None
    assert [
        group.get_text(" ", strip=True).split()[0] for group in sidebar.select(".side-nav-group")
    ]
    assert sidebar.select_one('a[aria-current="page"][href$="/reports"]') is not None
    assert sidebar.select_one('a[href$="/executive-report"]') is not None

    executive_report = client.get(f"/analysis-runs/{run_id}/executive-report")
    assert executive_report.status_code == 200
    assert "Executive Security Overview" in executive_report.text
    assert "Risk Posture and Source Signals" in executive_report.text
    assert "Evidence, Data Quality and Methodology" in executive_report.text
    assert "Finding Dossiers" in executive_report.text
    assert "Input and preservation" in executive_report.text
    assert "Provider transparency" in executive_report.text
    assert "Governance state" in executive_report.text
    assert "How to Read This Report" in executive_report.text
    assert "Findings by Severity and Signal" in executive_report.text
    assert "Provider Signals" in executive_report.text
    assert "Top ATT&amp;CK-Mapped Findings" in executive_report.text
    assert "Next 30 Days" in executive_report.text
    assert "Evidence Bundle Contents" in executive_report.text
    assert "Mapping Confidence" in executive_report.text
    executive_soup = BeautifulSoup(executive_report.text, "html.parser")
    assert executive_soup.select_one(".er-app-header") is not None
    assert executive_soup.select_one(".er-workspace-sidebar") is not None
    assert executive_soup.select_one(".er-workspace-sidebar [data-sidebar-toggle]") is not None
    assert executive_soup.select_one(".er-workspace-sidebar .nav-icon") is not None
    assert (
        executive_soup.select_one('.er-workspace-nav a[aria-current="page"]').get_text(strip=True)
        == "Executive Report"
    )
    assert "/static/executive-report.css" in executive_report.text
    assert "/static/workbench.js" in executive_report.text

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
    assert "Provider updates" in settings.text
    assert "NVD API key value" in settings.text
    assert "secret-api-key" not in settings.text
    settings_token = _csrf_token(settings.text)
    provider_job = client.post(
        f"/web/projects/{project_id}/providers/update-jobs",
        data={
            "sources": ["nvd", "epss", "kev"],
            "max_cves": "1",
            "cache_only": "true",
            "csrf_token": settings_token,
        },
        follow_redirects=False,
    )
    assert provider_job.status_code == 303
    settings = client.get(f"/projects/{project_id}/settings")
    assert "completed" in settings.text

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


def test_web_assets_waivers_and_coverage_pages(tmp_path: Path) -> None:
    client = _client(tmp_path)
    project = client.post("/api/projects", json={"name": "governance-editor-web-demo"}).json()
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
        files={
            "file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json"),
            "asset_context_file": ("asset-context.csv", ASSET_CONTEXT.read_bytes(), "text/csv"),
        },
    )
    assert imported.status_code == 200, imported.text

    assets = client.get(f"/projects/{project['id']}/assets")
    assert assets.status_code == 200
    assert "api-gateway" in assets.text
    assert "platform-team" in assets.text
    asset_token = _csrf_token(assets.text)
    asset_payload = client.get(f"/api/projects/{project['id']}/assets").json()["items"][0]
    updated_asset = client.post(
        f"/web/assets/{asset_payload['id']}",
        data={
            "asset_id": "edge-gateway",
            "owner": "risk-ui",
            "business_service": "checkout",
            "environment": "prod",
            "exposure": "internet-facing",
            "criticality": "critical",
            "target_ref": asset_payload["target_ref"],
            "csrf_token": asset_token,
        },
        follow_redirects=False,
    )
    assert updated_asset.status_code == 303
    assert updated_asset.headers["location"] == f"/projects/{project['id']}/assets"

    waivers = client.get(f"/projects/{project['id']}/waivers")
    assert waivers.status_code == 200
    assert "Create waiver" in waivers.text
    waiver_token = _csrf_token(waivers.text)
    findings_payload = client.get(
        f"/api/projects/{project['id']}/findings",
        params={"q": "CVE-2024-3094"},
    ).json()["items"]
    detail = client.get(f"/findings/{findings_payload[0]['id']}")
    assert detail.status_code == 200
    assert "Accept residual risk" in detail.text
    assert "Create waiver" in detail.text
    created_waiver = client.post(
        f"/web/projects/{project['id']}/waivers",
        data={
            "cve_id": "CVE-2024-3094",
            "asset_id": "edge-gateway",
            "owner": "risk-ui",
            "reason": "Temporary residual risk acceptance from the web editor.",
            "expires_on": "2099-12-31",
            "review_on": "2000-01-01",
            "approval_ref": "CAB-UI",
            "csrf_token": waiver_token,
        },
        follow_redirects=False,
    )
    assert created_waiver.status_code == 303
    waivers = client.get(f"/projects/{project['id']}/waivers")
    assert "risk-ui" in waivers.text
    assert "review_due" in waivers.text
    assert "badge review_due" in waivers.text
    assert "Save review" in waivers.text
    waiver_payload = client.get(f"/api/projects/{project['id']}/waivers").json()["items"][0]
    waiver_update = client.post(
        f"/web/waivers/{waiver_payload['id']}",
        data={
            "cve_id": "CVE-2024-3094",
            "asset_id": "edge-gateway",
            "owner": "risk-ui-reviewed",
            "reason": "Residual risk reviewed and still accepted.",
            "expires_on": "2099-12-31",
            "review_on": "2099-12-01",
            "approval_ref": "CAB-UI-2",
            "csrf_token": waiver_token,
        },
        follow_redirects=False,
    )
    assert waiver_update.status_code == 303
    waivers = client.get(f"/projects/{project['id']}/waivers")
    assert "risk-ui-reviewed" in waivers.text
    assert "active" in waivers.text

    coverage = client.get(f"/projects/{project['id']}/coverage")
    assert coverage.status_code == 200
    assert "Detection coverage" in coverage.text
    assert "Mapping review queue" in coverage.text
    assert "T1190" in coverage.text
    coverage_token = _csrf_token(coverage.text)
    mapped_finding = next(
        item
        for item in client.get(f"/api/projects/{project['id']}/findings").json()["items"]
        if item["attack_mapped"]
    )
    updated_attack_review = client.post(
        f"/web/findings/{mapped_finding['id']}/attack-review",
        data={
            "review_status": "needs_review",
            "actor": "web-review",
            "reason": "web review queue",
            "csrf_token": coverage_token,
        },
        follow_redirects=False,
    )
    assert updated_attack_review.status_code == 303
    assert updated_attack_review.headers["location"] == f"/projects/{project['id']}/coverage"
    assert client.get(f"/api/findings/{mapped_finding['id']}/ttps").json()["review_status"] == (
        "needs_review"
    )
    controls_csv = (
        b"control_id,name,technique_id,coverage_level,owner,evidence_ref,notes\n"
        b"edge-waf,WAF exploit-public-app rule,T1190,partial,secops,"
        b"https://example.invalid/evidence,Needs production tuning\n"
        b"shell-telemetry,Shell command telemetry,T9999,not_covered,secops,,Needs owner review\n"
    )
    imported_controls = client.post(
        f"/web/projects/{project['id']}/coverage/import",
        data={"csrf_token": coverage_token},
        files={"file": ("controls.csv", controls_csv, "text/csv")},
        follow_redirects=False,
    )
    assert imported_controls.status_code == 303
    assert imported_controls.headers["location"] == f"/projects/{project['id']}/coverage"

    coverage = client.get(f"/projects/{project['id']}/coverage")
    assert "WAF exploit-public-app rule" in coverage.text
    assert "Shell command telemetry" in coverage.text
    assert "partial" in coverage.text

    session_factory = create_session_factory(get_engine(client.app))
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        context = next(
            ctx
            for ctx in repo.list_project_attack_contexts(project["id"])
            if any(
                isinstance(technique, dict) and technique.get("attack_object_id") == "T1190"
                for technique in ctx.techniques_json
            )
        )
        context.techniques_json = [
            {
                **technique,
                "deprecated": True,
                "revoked": True,
            }
            if isinstance(technique, dict) and technique.get("attack_object_id") == "T1190"
            else technique
            for technique in context.techniques_json
        ]
        session.commit()

    technique = client.get(f"/projects/{project['id']}/attack/techniques/T1190")
    assert technique.status_code == 200
    assert "Technique detail" in technique.text
    assert "Deprecated" in technique.text
    assert "Revoked" in technique.text
    assert "WAF exploit-public-app rule" in technique.text
    assert "CVE-" in technique.text

    controls_only_technique = client.get(f"/projects/{project['id']}/attack/techniques/T9999")
    assert controls_only_technique.status_code == 200
    assert "Shell command telemetry" in controls_only_technique.text
    assert "Mapped findings" in controls_only_technique.text


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
