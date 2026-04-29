from __future__ import annotations

import csv
import hashlib
import json
import uuid
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
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
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
)

CSV_FINDINGS_COLUMNS = [
    "cve_id",
    "priority",
    "status",
    "kev",
    "epss",
    "cvss",
    "data_quality_confidence",
    "data_quality_flags",
    "component",
    "asset",
    "owner",
    "service",
    "vex_statuses",
    "suppressed_by_vex",
    "under_investigation",
    "waived",
    "waiver_status",
    "waiver_owner",
    "waiver_expires_on",
    "waiver_review_on",
    "attack_mapped",
    "attack_techniques",
    "defensive_context_sources",
    "decision_template",
    "decision_sla",
    "decision_statement",
    "business_impact",
    "recommended_action",
]


def test_vpw049_openapi_exposes_report_format_contract() -> None:
    response = TestClient(app).get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    assert "/api/v1/runs/{run_id}/reports" in payload["paths"]
    assert "/api/v1/reports/{report_id}/download" in payload["paths"]
    assert {"ReportCreate", "ReportPublic", "ReportsPublic"}.issubset(
        payload["components"]["schemas"]
    )
    assert payload["components"]["schemas"]["ReportCreate"]["properties"]["format"]["enum"] == [
        "markdown",
        "html",
        "json",
        "csv",
        "zip",
    ]


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


def test_vpw049_html_report_create_downloads_executive_report(
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
        json={"format": "html"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "html"
    assert payload["kind"] == "executive-html"
    assert payload["filename"] == "executive-report.html"
    assert payload["content_type"] == "text/html; charset=utf-8"
    assert len(payload["sha256"]) == 64
    assert payload["metadata_json"]["finding_count"] == 2
    assert payload["metadata_json"]["format"] == "html"
    assert payload["download_url"] == f"/api/v1/reports/{payload['id']}/download"

    with Session(template_api_env.engine) as session:
        report = session.get(template_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("executive-report.html")

    download = template_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in download.headers["content-disposition"]
    assert "executive-report.html" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("text/html")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    body = download.text
    assert "<!doctype html>" in body
    assert "Executive Summary" in body
    assert "Business Impact" in body
    assert "Top Risks" in body
    assert "Recommendations" in body
    assert "Provider Freshness" in body
    assert "Decision Statement" in body
    assert "Emergency / 24h" in body
    assert "sha256:vpw048-snapshot" in body
    assert body.index(DEMO_CVE_XZ) < body.index(DEMO_CVE_LOG4SHELL)
    assert "<script" not in body.lower()
    assert "<img" not in body.lower()
    assert 'href="javascript:' not in body.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


def test_vpw050_analysis_json_export_create_downloads_schema_valid_result(
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
        json={"format": "json"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "json"
    assert payload["kind"] == "analysis-result-json"
    assert payload["filename"] == "analysis-result.v1.json"
    assert payload["content_type"] == "application/json; charset=utf-8"
    assert payload["metadata_json"]["finding_count"] == 2

    with Session(template_api_env.engine) as session:
        report = session.get(template_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("analysis-result.v1.json")

    download = template_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "analysis-result.v1.json" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("application/json")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    body = download.json()
    jsonschema.validate(body, _load_schema("analysis-result.v1.schema.json"))
    assert body["schema"] == "analysis-result.v1"
    assert body["schema_version"] == "1.0.0"
    assert body["project"]["id"] == project["id"]
    assert body["analysis_run"]["id"] == str(run_id)
    assert body["provider_snapshot"]["content_hash"] == "sha256:vpw048-snapshot"
    assert [finding["cve_id"] for finding in body["findings"]] == [
        DEMO_CVE_XZ,
        DEMO_CVE_LOG4SHELL,
    ]
    first = body["findings"][0]
    assert first["recommendation"]["decision_statement"].startswith("Decision Statement:")
    assert first["data_quality"]["raw"]["confidence"] == "high"
    assert first["explanation"]["decision_guidance"]["sla"]["target_hours"] == 24
    assert first["occurrences"][0]["analysis_run_id"] == str(run_id)
    assert set(body["explanations"]) == {DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL}


def test_vpw050_findings_csv_export_create_downloads_stable_columns(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    run_id = _seed_reportable_run(template_api_env, uuid.UUID(project["id"]))

    response = template_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "csv"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "csv"
    assert payload["kind"] == "findings-csv"
    assert payload["filename"] == "findings.csv"
    assert payload["content_type"] == "text/csv; charset=utf-8"

    download = template_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "findings.csv" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("text/csv")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    reader = csv.DictReader(StringIO(download.text))
    assert reader.fieldnames == CSV_FINDINGS_COLUMNS
    rows = list(reader)
    assert [row["cve_id"] for row in rows] == [DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL]
    assert rows[0]["priority"] == "Critical"
    assert rows[0]["kev"] == "no"
    assert rows[0]["epss"] == "0.846"
    assert rows[0]["cvss"] == "10"
    assert rows[0]["asset"] == "payments-api"
    assert rows[0]["decision_sla"] == "Emergency / 24h"
    assert rows[0]["decision_statement"].startswith("Decision Statement:")
    assert rows[1]["data_quality_flags"] == "missing_asset_owner - Owner missing <img>"


def test_vpw050_csv_export_escapes_spreadsheet_formula_cells(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    run_id = _seed_formula_run(template_api_env, uuid.UUID(project["id"]))

    created = template_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "csv"},
    )

    assert created.status_code == 200, created.text
    csv_report = template_api_env.client.get(created.json()["download_url"], headers=headers)
    assert csv_report.status_code == 200
    text = csv_report.text
    assert "'=HYPERLINK" in text
    assert ",'=asset-key," in text
    assert ",'+owner," in text
    assert ",'@service," in text
    assert "'\tformula_flag - flag" in text
    assert "'-Patch now" in text
    assert ",=asset-key," not in text
    assert ",+owner," not in text
    assert ",@service," not in text


def test_vpw050_analysis_schema_rejects_contract_drift() -> None:
    schema = _load_schema("analysis-result.v1.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    valid = json.loads(
        (_repo_root() / "docs" / "evidence" / "vpw-050-analysis-result.v1.json").read_text(
            encoding="utf-8"
        )
    )

    jsonschema.validate(valid, schema)

    missing_required = dict(valid)
    missing_required.pop("findings")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(missing_required, schema)

    unexpected_top_level = dict(valid)
    unexpected_top_level["unexpected_top_level"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(unexpected_top_level, schema)

    malformed_finding = json.loads(json.dumps(valid))
    malformed_finding["findings"][0].pop("recommendation")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(malformed_finding, schema)


def test_vpw050_committed_evidence_artifacts_are_contract_valid() -> None:
    evidence_dir = _repo_root() / "docs" / "evidence"
    schema = _load_schema("analysis-result.v1.schema.json")
    analysis_json = json.loads(
        (evidence_dir / "vpw-050-analysis-result.v1.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(analysis_json, schema)
    assert analysis_json["schema"] == "analysis-result.v1"
    assert analysis_json["analysis_run"]["id"] == "00000000-0000-4000-8000-000000000050"
    assert [finding["cve_id"] for finding in analysis_json["findings"]] == [
        DEMO_CVE_XZ,
        DEMO_CVE_LOG4SHELL,
    ]

    findings_csv = (evidence_dir / "vpw-050-findings.csv").read_text(encoding="utf-8")
    reader = csv.DictReader(StringIO(findings_csv))
    assert reader.fieldnames == CSV_FINDINGS_COLUMNS
    rows = list(reader)
    assert [row["cve_id"] for row in rows] == [DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL]
    assert rows[0]["decision_sla"] == "Emergency / 24h"
    assert rows[1]["attack_techniques"] == "T1190"


def test_vpw051_evidence_bundle_zip_create_downloads_manifest_integrity(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    run_id = _seed_reportable_run(template_api_env, uuid.UUID(project["id"]))
    input_metadata = _add_vpw051_bundle_metadata(template_api_env, run_id, tmp_path)

    response = template_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "zip"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "zip"
    assert payload["kind"] == "evidence-bundle"
    assert payload["filename"] == "evidence-bundle.zip"
    assert payload["content_type"] == "application/zip"

    download = template_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "evidence-bundle.zip" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("application/zip")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    with zipfile.ZipFile(BytesIO(download.content)) as archive:
        names = sorted(archive.namelist())
        assert names == [
            "analysis.json",
            "executive.html",
            "manifest.json",
            "provider-snapshot.json",
            "technical.md",
        ]
        manifest = json.loads(archive.read("manifest.json"))
        jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
        assert manifest["bundle_kind"] == "evidence-bundle"
        assert manifest["source_analysis_path"] == "analysis.json"
        assert manifest["source_input_hashes"] == [input_metadata]
        assert manifest["included_input_copy"] is False
        assert manifest["provider_snapshot"]["bundle_path"] == "provider-snapshot.json"
        assert manifest["redaction"]["enabled"] is True
        assert "manifest.json" not in {item["path"] for item in manifest["files"]}
        for item in manifest["files"]:
            content = archive.read(item["path"])
            assert item["size_bytes"] == len(content)
            assert item["sha256"] == hashlib.sha256(content).hexdigest()
            assert manifest["artifact_hashes"][item["path"]] == item["sha256"]

        bundle_text = "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in names
            if name.endswith((".json", ".md", ".html"))
        )
        assert "super-secret-token" not in bundle_text
        assert "provider-secret-key" not in bundle_text
        assert str(tmp_path) not in bundle_text
        assert "[REDACTED]" in bundle_text


def test_vpw051_evidence_bundle_renderer_snapshot_is_stable() -> None:
    payload = _vpw051_snapshot_payload()
    bundle, manifest = render_evidence_bundle_zip(payload)

    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        assert sorted(archive.namelist()) == [
            "analysis.json",
            "executive.html",
            "manifest.json",
            "provider-snapshot.json",
            "technical.md",
        ]
        stored_manifest = json.loads(archive.read("manifest.json"))
        assert manifest == stored_manifest
        assert (
            archive.read("analysis.json")
            == (_repo_root() / "docs" / "evidence" / "vpw-051-analysis.json").read_bytes()
        )
        assert (
            archive.read("manifest.json")
            == (_repo_root() / "docs" / "evidence" / "vpw-051-manifest.json").read_bytes()
        )
        for item in manifest["files"]:
            assert item["sha256"] == hashlib.sha256(archive.read(item["path"])).hexdigest()


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


def test_vpw049_html_report_snapshot_is_stable() -> None:
    payload = MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000049",
        project_name="Executive Snapshot <script>alert(1)</script>",
        run_id="00000000-0000-4000-8000-000000000155",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.html",
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
                decision_statement=(
                    "Decision Statement: patch CVE-2024-3094 on Payments API "
                    "within the emergency SLA."
                ),
                business_impact=(
                    "Customer payment traffic depends on the affected production API; "
                    "delay increases outage and fraud exposure."
                ),
                decision_sla="Emergency / 24h",
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
                decision_statement=(
                    "Decision Statement: patch CVE-2021-44228 after owner "
                    "validation and compensating control review."
                ),
                business_impact="Operational tooling exposure requires management visibility.",
                decision_sla="Emergency / 24h",
                data_quality_flags=["missing_asset_owner - Owner is not set"],
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000051",
            content_hash="sha256:vpw049-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes={"provider_snapshot": "sha256:vpw049-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
                "source_path": "demo_provider_snapshot.json",
                "item_count": 2,
            },
        ),
    )
    snapshot_path = Path(__file__).resolve().parent / "snapshots" / "vpw_049_executive_report.html"

    assert render_html_executive_report(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw050_analysis_json_export_snapshot_is_stable() -> None:
    payload = _vpw050_snapshot_payload()
    snapshot_path = (
        Path(__file__).resolve().parent / "snapshots" / "vpw_050_analysis_result.v1.json"
    )

    assert render_analysis_result_json(payload) == snapshot_path.read_text(encoding="utf-8")


def test_vpw050_findings_csv_export_snapshot_is_stable() -> None:
    payload = _vpw050_snapshot_payload()
    snapshot_path = Path(__file__).resolve().parent / "snapshots" / "vpw_050_findings.csv"

    assert render_findings_csv(payload) == snapshot_path.read_text(encoding="utf-8")


def _configure_report_dir(template_api_env: TemplateApiEnv, tmp_path: Path) -> Path:
    report_dir = (tmp_path / "template-reports").resolve(strict=False)
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        REPORT_DIR=str(report_dir),
    )
    return report_dir


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_schema(filename: str) -> dict[str, Any]:
    schema_path = _repo_root() / "docs" / "schemas" / filename
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _vpw050_snapshot_payload() -> MarkdownReportPayload:
    return MarkdownReportPayload(
        generated_at=datetime(2026, 4, 29, 12, 0, tzinfo=UTC),
        project_id="00000000-0000-4000-8000-000000000156",
        project_name="VPW-050 Snapshot",
        run_id="00000000-0000-4000-8000-000000000050",
        run_status="completed",
        input_type="cve-list",
        filename="known-cves.txt",
        summary={"finding_count": 2, "counts_by_priority": {"Critical": 1, "High": 1}},
        findings=[
            MarkdownReportFinding(
                id="00000000-0000-4000-8000-000000000501",
                dedup_key="vpw050-xz",
                operational_rank=1,
                cve_id=DEMO_CVE_XZ,
                priority="critical",
                priority_rank=1,
                status="open",
                risk_score=100.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                attack_mapped=False,
                asset="Payments API",
                asset_key="payments-api",
                owner="platform-team",
                business_service="checkout",
                environment="prod",
                exposure="internet-facing",
                criticality="critical",
                component="xz 5.6.0-r0",
                component_purl="pkg:apk/alpine/xz@5.6.0-r0",
                vulnerability={"severity": "CRITICAL", "provider": {"nvd": "locked"}},
                rationale="Internet-facing production asset with critical score.",
                recommended_action="Patch [open](javascript:alert(1)) now.",
                data_quality_confidence="high",
                decision_statement=(
                    "Decision Statement: patch CVE-2024-3094 on Payments API "
                    "within the emergency SLA."
                ),
                business_impact="Checkout traffic depends on the affected service.",
                decision_sla="Emergency / 24h",
                explanation={
                    "decision_guidance": {
                        "template_label": "Patch",
                        "decision_statement": (
                            "Decision Statement: patch CVE-2024-3094 on Payments API "
                            "within the emergency SLA."
                        ),
                    }
                },
                data_quality={"confidence": "high", "flags": []},
                evidence={"source": "snapshot"},
                occurrences=[
                    {
                        "id": "00000000-0000-4000-8000-000000000601",
                        "analysis_run_id": "00000000-0000-4000-8000-000000000050",
                        "source": "cve-list",
                        "raw_reference": DEMO_CVE_XZ,
                        "evidence": {"line": 1},
                    }
                ],
                data_quality_flags=[],
                first_seen_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                last_seen_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
                created_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                updated_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
            ),
            MarkdownReportFinding(
                id="00000000-0000-4000-8000-000000000502",
                dedup_key="vpw050-log4shell",
                operational_rank=2,
                cve_id=DEMO_CVE_LOG4SHELL,
                priority="high",
                priority_rank=2,
                status="in_review",
                risk_score=94.2,
                epss=0.944,
                cvss_base_score=10.0,
                in_kev=True,
                attack_mapped=True,
                asset="Ops API",
                asset_key="ops-api",
                owner="secops",
                business_service="operations",
                environment="prod",
                exposure="internal",
                criticality="high",
                component="log4j-core 2.14.1",
                component_purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                vulnerability={"severity": "CRITICAL", "provider": {"kev": True}},
                rationale="CISA KEV listing and vulnerable component evidence.",
                recommended_action="Patch via vendor upgrade.",
                data_quality_confidence="medium",
                decision_statement="Decision Statement: patch after owner validation.",
                business_impact="Operational tooling exposure requires management visibility.",
                decision_sla="Emergency / 24h",
                explanation={
                    "decision_guidance": {
                        "template_label": "Patch",
                        "decision_statement": "Decision Statement: patch after owner validation.",
                    },
                    "attack_techniques": ["T1190"],
                },
                data_quality={
                    "confidence": "medium",
                    "flags": [{"code": "missing_asset_owner", "message": "Owner is not set"}],
                },
                evidence={"source": "snapshot"},
                occurrences=[
                    {
                        "id": "00000000-0000-4000-8000-000000000602",
                        "analysis_run_id": "00000000-0000-4000-8000-000000000050",
                        "source": "cve-list",
                        "raw_reference": DEMO_CVE_LOG4SHELL,
                        "evidence": {"line": 2},
                    }
                ],
                data_quality_flags=["missing_asset_owner - Owner is not set"],
                first_seen_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                last_seen_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
                created_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
                updated_at=datetime(2026, 4, 29, 11, 30, tzinfo=UTC),
            ),
        ],
        provider_snapshot=MarkdownProviderSnapshot(
            id="00000000-0000-4000-8000-000000000650",
            content_hash="sha256:vpw050-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            created_at="2026-04-28T10:20:00Z",
            source_hashes={"provider_snapshot": "sha256:vpw050-snapshot"},
            source_metadata={
                "locked_provider_data": True,
                "selected_sources": ["nvd", "epss", "kev"],
            },
        ),
        project_description="Snapshot project for VPW-050 exports.",
        project_owner_id="00000000-0000-4000-8000-000000000011",
        project_created_at=datetime(2026, 4, 29, 10, 0, tzinfo=UTC),
        project_updated_at=datetime(2026, 4, 29, 10, 30, tzinfo=UTC),
        run_started_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
        run_finished_at=datetime(2026, 4, 29, 11, 45, tzinfo=UTC),
        run_errors={},
    )


def _vpw051_snapshot_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    input_sha256 = "a" * 64
    first_finding = replace(
        payload.findings[0],
        recommended_action="Patch after using super-secret-token in the approval system.",
        rationale="Review local evidence from /tmp/pytest/vpw-051-input.txt.",
        evidence={
            "source": "snapshot",
            "authorization": "Bearer super-secret-token",
            "upload_path": "/tmp/pytest/vpw-051-input.txt",
        },
    )
    provider_snapshot = None
    if payload.provider_snapshot is not None:
        provider_snapshot = replace(
            payload.provider_snapshot,
            source_metadata={
                **payload.provider_snapshot.source_metadata,
                "source_path": "/Users/umut/private/provider-snapshot.json",
                "api_key": "provider-secret-key",
                "cache_dir": "/Users/umut/private/cache",
            },
        )
    return replace(
        payload,
        summary={
            **payload.summary,
            "input_sha256": input_sha256,
            "input_upload": {
                "original_filename": "known-cves.txt",
                "stored_filename": "known-cves.txt",
                "size_bytes": 29,
                "sha256": input_sha256,
                "path": "/Users/umut/private/vpw-051-input.txt",
                "token": "super-secret-token",
            },
        },
        run_error="Bearer super-secret-token",
        run_errors={"authorization": "Bearer super-secret-token"},
        findings=[first_finding, *payload.findings[1:]],
        provider_snapshot=provider_snapshot,
    )


def _add_vpw051_bundle_metadata(
    template_api_env: TemplateApiEnv,
    run_id: uuid.UUID,
    tmp_path: Path,
) -> dict[str, Any]:
    app_models = template_api_env.app_models
    upload_path = tmp_path / "private" / "known-cves.txt"
    upload_content = f"{DEMO_CVE_XZ}\n{DEMO_CVE_LOG4SHELL}\n".encode()
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    upload_path.write_bytes(upload_content)
    input_metadata = {
        "path": upload_path.name,
        "size_bytes": len(upload_content),
        "sha256": hashlib.sha256(upload_content).hexdigest(),
    }
    with Session(template_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, run_id)
        assert run is not None
        run.summary_json = {
            **dict(run.summary_json or {}),
            "input_sha256": input_metadata["sha256"],
            "input_upload": {
                "original_filename": upload_path.name,
                "stored_filename": upload_path.name,
                "size_bytes": input_metadata["size_bytes"],
                "sha256": input_metadata["sha256"],
                "path": str(upload_path),
                "token": "super-secret-token",
            },
        }
        run.error_json = {"authorization": "Bearer super-secret-token"}
        if run.provider_snapshot is not None:
            run.provider_snapshot.source_metadata_json = {
                **dict(run.provider_snapshot.source_metadata_json or {}),
                "source_path": str(tmp_path / "private" / "provider-snapshot.json"),
                "api_key": "provider-secret-key",
                "cache_dir": str(tmp_path / "private" / "cache"),
            }
            session.add(run.provider_snapshot)
        finding = session.exec(
            select(app_models.Finding)
            .where(app_models.Finding.project_id == run.project_id)
            .where(app_models.Finding.cve_id == DEMO_CVE_XZ)
        ).first()
        assert finding is not None
        finding.recommended_action = "Patch after using super-secret-token in the approval system."
        finding.rationale = f"Review local evidence from {tmp_path}/private/vpw-051-input.txt."
        finding.evidence_json = {
            "source": "snapshot",
            "authorization": "Bearer super-secret-token",
            "upload_path": str(upload_path),
        }
        session.add(finding)
        session.add(run)
        session.commit()
    return input_metadata


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


def _seed_formula_run(template_api_env: TemplateApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = template_api_env.app_models
    repositories = template_api_env.repositories
    with Session(template_api_env.engine) as session:
        run_repo = repositories.RunRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:vpw050-formula-snapshot",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
        )
        run = run_repo.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="generic-occurrence-csv",
            filename="formula-cells.csv",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={"finding_count": 1},
        )
        finding = _seed_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            cve_id=DEMO_CVE_XZ,
            asset_key="=asset-key",
            asset_name="=asset-name",
            asset_owner="+owner",
            asset_business_service="@service",
            component_name='=HYPERLINK("https://example.invalid")',
            component_version="5.6.0",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            risk_score=100.0,
            epss=0.846,
            cvss=10.0,
            in_kev=False,
            rationale="\tTabbed rationale",
            action="-Patch now",
            confidence="high",
            flags=[{"code": "\tformula_flag", "message": "flag"}],
        )
        run_repo.add_finding_occurrence(
            finding_id=finding.id,
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
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
    asset_owner: str | None = None,
    asset_business_service: str | None = None,
) -> Any:
    asset = create_asset(
        session,
        app_models,
        repositories,
        project_id=project_id,
        asset_key=asset_key,
        name=asset_name,
    )
    if asset_owner is not None:
        asset.owner = asset_owner
    if asset_business_service is not None:
        asset.business_service = asset_business_service
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
    finding.explanation_json = {
        "data_quality_confidence": confidence,
        "data_quality_flags": flags,
        "decision_guidance": {
            "decision_statement": (
                f"Decision Statement: remediate {cve_id} on {asset_name} with the "
                "assigned owner before the emergency SLA expires."
            ),
            "business_impact": {
                "text": (
                    f"Executive attention is warranted for {asset_name} because the "
                    f"finding combines {priority} priority with provider-backed risk signals."
                ),
            },
            "sla": {"label": "Emergency", "target_hours": 24},
        },
    }
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
