from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlmodel import Session
from utils.template_workbench import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    TemplateApiEnv,
    auth_headers,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    seed_foreign_project_graph,
)

from app.main import app
from app.services import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    render_markdown_report,
)


def test_vpw048_openapi_exposes_markdown_report_contract() -> None:
    response = TestClient(app).get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    assert "/api/v1/runs/{run_id}/reports" in payload["paths"]
    assert "/api/v1/reports/{report_id}/download" in payload["paths"]
    assert {"ReportCreate", "ReportPublic", "ReportsPublic"}.issubset(
        payload["components"]["schemas"]
    )


def test_vpw048_markdown_report_create_downloads_for_completed_run(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    run_id = _seed_reportable_run(template_api_env, uuid.UUID(project["id"]))

    response = template_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "markdown"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "markdown"
    assert payload["kind"] == "technical-markdown"
    assert payload["filename"] == "technical-report.md"
    assert len(payload["sha256"]) == 64
    assert payload["download_url"] == f"/api/v1/reports/{payload['id']}/download"

    with Session(template_api_env.engine) as session:
        report = session.get(template_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.metadata_json["finding_count"] == 2

    download = template_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert "attachment" in download.headers["content-disposition"]
    assert "technical-report.md" in download.headers["content-disposition"]
    body = download.text
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]
    assert "# Technical Vulnerability Report" in body
    assert "## Summary" in body
    assert "## Top Findings" in body
    assert "## Reasons" in body
    assert "## Data Quality" in body
    assert "## Provider Snapshot" in body
    assert body.index(DEMO_CVE_XZ) < body.index(DEMO_CVE_LOG4SHELL)
    assert "sha256:vpw048-snapshot" in body
    assert "Yes" in body
    assert "<script>" not in body
    assert "<img" not in body
    assert "[open](" not in body
    assert "&lt;script&gt;" in body


def test_vpw048_report_auth_project_visibility_and_invalid_run_state(
    restricted_template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(restricted_template_api_env, tmp_path)
    headers = auth_headers(restricted_template_api_env.client)
    foreign = seed_foreign_project_graph(
        restricted_template_api_env.engine,
        restricted_template_api_env.app_models,
        restricted_template_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")
    pending_run_id = _seed_status_run(restricted_template_api_env, "pending")
    failed_run_id = _seed_status_run(restricted_template_api_env, "failed")
    foreign_report_id = _seed_foreign_report(restricted_template_api_env, foreign)

    assert (
        restricted_template_api_env.client.post(
            f"/api/v1/runs/{missing_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 404
    )
    assert (
        restricted_template_api_env.client.post(
            f"/api/v1/runs/{foreign['run_id']}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 403
    )
    assert (
        restricted_template_api_env.client.get(
            f"/api/v1/reports/{foreign_report_id}/download",
            headers=headers,
        ).status_code
        == 403
    )
    for run_id in (pending_run_id, failed_run_id):
        response = restricted_template_api_env.client.post(
            f"/api/v1/runs/{run_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        )
        assert response.status_code == 422
        assert "completed" in response.json()["detail"]


def test_vpw048_download_rejects_path_escape_and_checksum_mismatch(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    run_id = _seed_reportable_run(template_api_env, uuid.UUID(project["id"]))
    created = template_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "markdown"},
    ).json()
    report_id = uuid.UUID(created["id"])

    with Session(template_api_env.engine) as session:
        report = session.get(template_api_env.app_models.Report, report_id)
        assert report is not None
        report_path = Path(report.path)
    report_path.write_text("tampered report\n", encoding="utf-8")

    tampered = template_api_env.client.get(created["download_url"], headers=headers)
    assert tampered.status_code == 409
    assert tampered.json()["detail"] == "Report artifact checksum mismatch"

    outside_path = tmp_path / "outside-report.md"
    outside_path.write_text("outside root\n", encoding="utf-8")
    with Session(template_api_env.engine) as session:
        report = session.get(template_api_env.app_models.Report, report_id)
        assert report is not None
        report.path = str(outside_path)
        session.add(report)
        session.commit()

    escaped = template_api_env.client.get(created["download_url"], headers=headers)
    assert escaped.status_code == 404
    assert escaped.json()["detail"] == "Report artifact not found"


def test_vpw048_markdown_report_snapshot_is_stable() -> None:
    payload = MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000048",
        project_name="Snapshot Project <script>alert(1)</script>",
        run_id="00000000-0000-4000-8000-000000000049",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.txt",
        summary={"finding_count": 2},
        findings=[
            MarkdownReportFinding(
                operational_rank=1,
                cve_id=DEMO_CVE_XZ,
                priority="critical",
                status="open",
                risk_score=100.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                asset="Payments API",
                component="xz 5.6.0-r0",
                rationale="Internet-facing production asset with critical score.",
                recommended_action="Patch [open](javascript:alert(1)) now.",
                data_quality_confidence="high",
                data_quality_flags=[],
            ),
            MarkdownReportFinding(
                operational_rank=2,
                cve_id=DEMO_CVE_LOG4SHELL,
                priority="high",
                status="in_review",
                risk_score=94.2,
                epss=0.944,
                cvss_base_score=10.0,
                in_kev=True,
                asset="Ops API",
                component="log4j-core 2.14.1",
                rationale="CISA KEV listing and vulnerable component evidence.",
                recommended_action="Patch via vendor upgrade.",
                data_quality_confidence="medium",
                data_quality_flags=["missing_asset_owner - Owner is not set"],
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000050",
            content_hash="sha256:vpw048-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes={"provider_snapshot": "sha256:vpw048-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        ),
    )
    snapshot_path = Path(__file__).resolve().parent / "snapshots" / "vpw_048_technical_report.md"

    assert render_markdown_report(payload) == snapshot_path.read_text(encoding="utf-8")


def _configure_report_dir(template_api_env: TemplateApiEnv, tmp_path: Path) -> Path:
    report_dir = (tmp_path / "template-reports").resolve(strict=False)
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        REPORT_DIR=str(report_dir),
    )
    return report_dir


def _seed_reportable_run(template_api_env: TemplateApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = template_api_env.app_models
    repositories = template_api_env.repositories
    with Session(template_api_env.engine) as session:
        run_repo = repositories.RunRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:vpw048-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes_json={"provider_snapshot": "sha256:vpw048-snapshot"},
            source_metadata_json={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        )
        run = run_repo.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="cve-list",
            filename="known-cves.txt",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={
                "finding_count": 2,
                "counts_by_priority": {"Critical": 1, "High": 1},
                "locked_provider_data": True,
            },
        )
        first = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_LOG4SHELL,
            asset_key="ops-api",
            asset_name="Ops <img src=x onerror=alert(1)> API",
            component_name="log4j-core",
            component_version="2.14.1",
            priority=app_models.FindingPriority.HIGH,
            priority_rank=2,
            operational_rank=2,
            risk_score=94.2,
            epss=0.944,
            cvss=10.0,
            in_kev=True,
            rationale="KEV-listed issue with <script>alert(1)</script> evidence.",
            action="Patch via vendor upgrade.",
            confidence="medium",
            flags=[{"code": "missing_asset_owner", "message": "Owner missing <img>"}],
        )
        second = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_XZ,
            asset_key="payments-api",
            asset_name="Payments <script>alert(1)</script> API",
            component_name="xz",
            component_version="5.6.0-r0",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            risk_score=100.0,
            epss=0.846,
            cvss=10.0,
            in_kev=False,
            rationale="Internet-facing production asset with critical score.",
            action="Patch [open](javascript:alert(1)) now.",
            confidence="high",
            flags=[],
        )
        run_repo.add_finding_occurrence(
            finding_id=first.id,
            analysis_run_id=run.id,
            source="cve-list",
            raw_reference=DEMO_CVE_LOG4SHELL,
        )
        run_repo.add_finding_occurrence(
            finding_id=second.id,
            analysis_run_id=run.id,
            source="cve-list",
            raw_reference=DEMO_CVE_XZ,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_finding(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    cve_id: str,
    asset_key: str,
    asset_name: str,
    component_name: str,
    component_version: str,
    priority: Any,
    priority_rank: int,
    operational_rank: int,
    risk_score: float,
    epss: float,
    cvss: float,
    in_kev: bool,
    rationale: str,
    action: str,
    confidence: str,
    flags: list[dict[str, str]],
) -> Any:
    asset = create_asset(
        session,
        app_models,
        repositories,
        project_id=project_id,
        asset_key=asset_key,
        name=asset_name,
    )
    component = create_component(
        session,
        repositories,
        name=component_name,
        version=component_version,
    )
    vulnerability = create_vulnerability(session, repositories, cve_id=cve_id, cvss_score=cvss)
    finding = create_finding(
        session,
        app_models,
        repositories,
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        component_id=component.id,
        asset_id=asset.id,
        cve_id=cve_id,
        priority=priority,
        priority_rank=priority_rank,
        operational_rank=operational_rank,
    )
    finding.risk_score = risk_score
    finding.epss = epss
    finding.cvss_base_score = cvss
    finding.in_kev = in_kev
    finding.rationale = rationale
    finding.recommended_action = action
    finding.data_quality_json = {"confidence": confidence, "flags": flags}
    finding.explanation_json = {"data_quality_confidence": confidence, "data_quality_flags": flags}
    session.flush()
    return finding


def _seed_status_run(template_api_env: TemplateApiEnv, status: str) -> uuid.UUID:
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    with Session(template_api_env.engine) as session:
        run = template_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename=f"{status}.txt",
            status=status,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_foreign_report(
    template_api_env: TemplateApiEnv,
    foreign: dict[str, uuid.UUID],
) -> uuid.UUID:
    report_id = uuid.uuid4()
    with Session(template_api_env.engine) as session:
        template_api_env.repositories.ReportRepository(session).create_report(
            report_id=report_id,
            project_id=foreign["project_id"],
            analysis_run_id=foreign["run_id"],
            kind="technical-markdown",
            format="markdown",
            filename="technical-report.md",
            content_type="text/markdown; charset=utf-8",
            path="data/template-reports/foreign/technical-report.md",
            sha256="0" * 64,
            size_bytes=0,
            metadata_json={},
        )
        session.commit()
    return report_id
