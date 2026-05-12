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
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    local_api_headers,
    seed_secondary_project_graph,
)

from app import models as app_models
from app.main import app
from app.services import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    build_attack_navigator_layer_payload,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
    render_sarif_report,
)
from app.services.report_contracts import CSV_FINDINGS_COLUMNS
from app.services.report_sarif_validation import validate_sarif_payload
from vuln_prioritizer.sarif_contract import (
    SARIF_FINGERPRINT_KEY,
    SARIF_WORKBENCH_FINGERPRINT_KEY,
)

VPW054_DEMO_ARTIFACTS = {
    "markdown": Path("docs/examples/vpw-054-workbench-technical-report.md"),
    "html": Path("docs/examples/vpw-054-workbench-executive-report.html"),
    "json": Path("docs/examples/vpw-054-workbench-analysis-result.v1.json"),
}
VPW054_HTML_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_054_executive_report.normalized.html")
VPW068_MARKDOWN_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_068_governance_report.md")
VPW068_HTML_SNAPSHOT = Path("backend/tests/api/snapshots/vpw_068_governance_report.normalized.html")
VPW054_SECRET_MARKERS = (
    "super-secret-token",
    "provider-secret-key",
    "bearer ",
    "api_key",
    "authorization",
    "/users/",
    "/tmp/",
    ".env",
)


def test_vpw049_openapi_exposes_report_format_contract() -> None:
    response = TestClient(app).get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    assert "/api/v1/runs/{run_id}/reports" in payload["paths"]
    assert "/api/v1/reports/{report_id}/download" in payload["paths"]
    assert "/api/v1/reports/{report_id}/verify" in payload["paths"]
    download_response = payload["paths"]["/api/v1/reports/{report_id}/download"]["get"][
        "responses"
    ]["200"]
    assert download_response["content"]["application/octet-stream"]["schema"] == {
        "format": "binary",
        "type": "string",
    }
    assert {"ReportCreate", "ReportPublic", "ReportVerificationPublic", "ReportsPublic"}.issubset(
        payload["components"]["schemas"]
    )
    report_create = payload["components"]["schemas"]["ReportCreate"]["properties"]
    assert report_create["format"]["enum"] == [
        "markdown",
        "html",
        "json",
        "csv",
        "zip",
        "attack-navigator",
        "sarif",
    ]
    assert report_create["attack_filter"]["enum"] == [
        "all",
        "critical-high",
        "kev",
        "no-coverage",
    ]


def test_vpw048_markdown_report_create_downloads_for_completed_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
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

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.metadata_json["finding_count"] == 2

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert "attachment" in download.headers["content-disposition"]
    assert "technical-report.md" in download.headers["content-disposition"]
    body = download.text
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]
    assert "# Technical Vulnerability Report" in body
    assert "## Summary" in body
    assert "## Top Findings" in body
    assert "## Governance Rollups" in body
    assert "### Top Services by Risk" in body
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
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
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

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("executive-report.html")

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert download.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in download.headers["content-security-policy"]
    assert "attachment" in download.headers["content-disposition"]
    assert "executive-report.html" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("text/html")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    body = download.text
    assert "<!doctype html>" in body
    assert "Executive Summary" in body
    assert "Service Risk, Accepted Risk, and VEX" in body
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


def test_vpw070_html_report_escapes_malicious_external_text() -> None:
    payload = _vpw050_snapshot_payload()
    malicious_finding = replace(
        payload.findings[0],
        asset='Payments <img src=x onerror="window.__vpwXss=1"> API',
        component="xz <script>window.__vpwXss=1</script>",
        decision_statement="Decision <svg onload=window.__vpwXss=1> statement",
        business_impact='Impact <img src=x onerror="window.__vpwXss=1">',
        recommended_action="Patch <script>window.__vpwXss=1</script> now.",
    )
    assert payload.provider_snapshot is not None
    provider_snapshot = replace(
        payload.provider_snapshot,
        source_hashes={
            "provider <script>window.__vpwXss=1</script>": "sha256:vpw070",
        },
        source_metadata={
            **payload.provider_snapshot.source_metadata,
            "selected_sources": ["nvd", "<img src=x onerror=window.__vpwXss=1>"],
            "validation_error": 'provider <svg onload="window.__vpwXss=1">',
        },
    )

    body = render_html_executive_report(
        replace(
            payload,
            project_name="VPW-070 <script>window.__vpwXss=1</script>",
            filename='known-cves"><img src=x onerror=window.__vpwXss=1>.txt',
            findings=[malicious_finding, *payload.findings[1:]],
            provider_snapshot=provider_snapshot,
        )
    )

    lowered = body.lower()
    assert "<script" not in lowered
    assert "<img" not in lowered
    assert "<svg" not in lowered
    assert 'href="javascript:' not in lowered
    assert "&lt;script&gt;window.__vpwXss=1&lt;/script&gt;" in body
    assert "&lt;img src=x onerror=&quot;window.__vpwXss=1&quot;&gt;" in body
    assert "provider &lt;svg onload=&quot;window.__vpwXss=1&quot;&gt;" in body
    assert "Source Hash: provider &lt;script&gt;window.__vpwXss=1&lt;/script&gt;" in body


def test_vpw050_analysis_json_export_create_downloads_schema_valid_result(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
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

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("analysis-result.v1.json")

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

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
    assert body["governance_rollups"]["top_services_by_risk"][0]["label"] == "Unassigned"
    assert body["governance_rollups"]["top_services_by_risk"][0]["finding_count"] == 2
    assert body["governance_rollups"]["top_assets_by_risk"][0]["label"] == "payments-api"
    assert body["governance_rollups"]["top_assets_by_risk"][0]["finding_count"] == 1
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
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
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

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

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


def test_vpw080_sarif_report_create_downloads_valid_results(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "sarif"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "sarif"
    assert payload["kind"] == "sarif-results"
    assert payload["filename"] == "results.sarif"
    assert payload["content_type"] == "application/sarif+json; charset=utf-8"
    assert payload["metadata_json"]["sarif_version"] == "2.1.0"
    assert payload["metadata_json"]["rule_count"] == 2
    assert payload["metadata_json"]["result_count"] == 2

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("results.sarif")

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "results.sarif" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("application/sarif+json")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    sarif = download.json()
    assert validate_sarif_payload(sarif) == []
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert run["tool"]["driver"]["name"] == "vuln-prioritizer-workbench"
    assert [rule["id"] for rule in rules] == [
        "vuln-prioritizer/cve-2024-3094",
        "vuln-prioritizer/cve-2021-44228",
    ]
    assert [result["ruleId"] for result in results] == [rule["id"] for rule in rules]
    assert [result["level"] for result in results] == ["error", "error"]
    assert [rule["defaultConfiguration"]["level"] for rule in rules] == ["error", "error"]
    assert [rule["properties"]["security-severity"] for rule in rules] == ["10.0", "10.0"]

    first = results[0]
    assert first["properties"]["cve"] == DEMO_CVE_XZ
    assert first["properties"]["references"][0] == f"https://nvd.nist.gov/vuln/detail/{DEMO_CVE_XZ}"
    assert all(
        reference.startswith(("http://", "https://"))
        for result in results
        for reference in result["properties"]["references"]
    )
    assert first["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    assert first["partialFingerprints"][SARIF_WORKBENCH_FINGERPRINT_KEY]
    assert (
        first["partialFingerprints"][SARIF_FINGERPRINT_KEY]
        == first["partialFingerprints"][SARIF_WORKBENCH_FINGERPRINT_KEY]
    )
    assert (
        first["partialFingerprints"][SARIF_FINGERPRINT_KEY]
        != results[1]["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    )


def test_vpw103_workbench_sarif_uses_stable_fingerprint_contract() -> None:
    artifact_uri = "service:payments-api"
    component_purl = "pkg:deb/debian/xz@5.6.0-1"
    cve_id = DEMO_CVE_XZ
    generated_at = datetime(2026, 1, 1, tzinfo=UTC)
    api_payload = MarkdownReportPayload(
        generated_at=generated_at,
        project_id="project-1",
        project_name="Payments",
        run_id="run-1",
        run_status="completed",
        input_type="generic-occurrence-csv",
        filename="findings.csv",
        summary={},
        provider_snapshot=None,
        findings=[
            MarkdownReportFinding(
                operational_rank=1,
                cve_id=cve_id,
                priority="Critical",
                status="open",
                risk_score=98.0,
                epss=0.846,
                cvss_base_score=10.0,
                in_kev=False,
                asset="Payments API",
                asset_key="payments-api",
                component="xz 5.6.0",
                component_purl=component_purl,
                rationale="Representative SARIF contract fixture.",
                recommended_action="Patch xz.",
                data_quality_confidence="high",
                occurrences=[
                    {
                        "evidence": {
                            "target_kind": "service",
                            "target_ref": "payments-api",
                            "purl": component_purl,
                        }
                    }
                ],
            )
        ],
    )

    api_sarif = render_sarif_report(api_payload)

    assert validate_sarif_payload(api_sarif) == []
    api_result = api_sarif["runs"][0]["results"][0]
    api_rule = api_sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert api_result["ruleId"] == f"vuln-prioritizer/{cve_id.lower()}"
    assert api_result["level"] == "error"
    assert api_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == artifact_uri
    assert api_rule["properties"]["security-severity"] == "10.0"
    assert (
        api_result["partialFingerprints"][SARIF_WORKBENCH_FINGERPRINT_KEY]
        == api_result["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    )


def test_vpw060_attack_navigator_report_create_downloads_filtered_layer(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    _add_vpw060_attack_contexts(workbench_api_env, run_id)

    response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "attack-navigator", "attack_filter": "all"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["format"] == "attack-navigator"
    assert payload["kind"] == "attack-navigator-layer"
    assert payload["filename"] == "attack-navigator-layer.json"
    assert payload["content_type"] == "application/json; charset=utf-8"
    assert payload["metadata_json"]["attack_filter"] == "all"
    assert payload["metadata_json"]["technique_count"] == 2

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("attack-navigator-layer.json")

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "attack-navigator-layer.json" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("application/json")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    layer = download.json()
    assert layer["version"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert [item["techniqueID"] for item in layer["techniques"]] == ["T1059", "T1190"]
    assert layer["techniques"][0]["score"] == 100.0
    assert "CVE-2024-3094" in layer["techniques"][0]["comment"]
    assert "Coverage: not assessed" in layer["techniques"][0]["comment"]
    assert "payload" not in json.dumps(layer).lower()
    assert _layer_metadata(layer, "Unmapped findings omitted") == "0"

    kev_response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "attack-navigator", "attack_filter": "kev"},
    )
    assert kev_response.status_code == 200, kev_response.text
    kev_layer = workbench_api_env.client.get(
        kev_response.json()["download_url"],
        headers=headers,
    ).json()
    assert [item["techniqueID"] for item in kev_layer["techniques"]] == ["T1190"]
    assert _layer_metadata(kev_layer, "Filter") == "kev"
    assert "KEV: 1 finding(s)" in kev_layer["techniques"][0]["comment"]

    no_coverage_response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "attack-navigator", "attack_filter": "no-coverage"},
    )
    assert no_coverage_response.status_code == 200, no_coverage_response.text
    no_coverage_layer = workbench_api_env.client.get(
        no_coverage_response.json()["download_url"],
        headers=headers,
    ).json()
    assert _layer_metadata(no_coverage_layer, "Filter") == "no-coverage"
    assert all(
        _technique_metadata(item, "Coverage") == "not assessed"
        for item in no_coverage_layer["techniques"]
    )


def test_vpw050_csv_export_escapes_spreadsheet_formula_cells(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_formula_run(workbench_api_env, uuid.UUID(project["id"]))

    created = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "csv"},
    )

    assert created.status_code == 200, created.text
    csv_report = workbench_api_env.client.get(created.json()["download_url"], headers=headers)
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
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    input_metadata = _add_vpw051_bundle_metadata(workbench_api_env, run_id, tmp_path)

    response = workbench_api_env.client.post(
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

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

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
            "governance/asset-context.json",
            "governance/rollups.json",
            "governance/vex-summary.json",
            "governance/waivers.json",
            "manifest.json",
            "provider-snapshot.json",
            "technical.md",
        ]
        manifest = json.loads(archive.read("manifest.json"))
        analysis = json.loads(archive.read("analysis.json"))
        governance_rollups = json.loads(archive.read("governance/rollups.json"))
        governance_waivers = json.loads(archive.read("governance/waivers.json"))
        governance_vex = json.loads(archive.read("governance/vex-summary.json"))
        governance_asset_context = json.loads(archive.read("governance/asset-context.json"))
        technical_report = archive.read("technical.md").decode("utf-8")
        executive_report = archive.read("executive.html").decode("utf-8")
        jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
        jsonschema.validate(analysis, _load_schema("analysis-result.v1.schema.json"))
        assert manifest["bundle_kind"] == "evidence-bundle"
        assert manifest["source_analysis_path"] == "analysis.json"
        assert manifest["source_input_hashes"] == [input_metadata]
        assert manifest["included_input_copy"] is False
        assert manifest["provider_snapshot"]["bundle_path"] == "provider-snapshot.json"
        assert manifest["redaction"]["enabled"] is True
        assert analysis["governance_rollups"]["top_services_by_risk"][0]["label"] == "Unassigned"
        assert manifest["governance_artifacts"] == [
            {
                "bundle_path": "governance/rollups.json",
                "kind": "governance-rollups",
                "sha256": manifest["artifact_hashes"]["governance/rollups.json"],
            },
            {
                "bundle_path": "governance/waivers.json",
                "kind": "governance-waivers",
                "sha256": manifest["artifact_hashes"]["governance/waivers.json"],
            },
            {
                "bundle_path": "governance/vex-summary.json",
                "kind": "governance-vex-summary",
                "sha256": manifest["artifact_hashes"]["governance/vex-summary.json"],
            },
            {
                "bundle_path": "governance/asset-context.json",
                "kind": "governance-asset-context",
                "sha256": manifest["artifact_hashes"]["governance/asset-context.json"],
            },
        ]
        assert governance_rollups["schema"] == "governance-rollups.v1"
        assert governance_waivers["schema"] == "governance-waivers.v1"
        assert governance_vex["schema"] == "governance-vex-summary.v1"
        assert governance_asset_context["schema"] == "governance-asset-context.v1"
        assert {item["asset_key"] for item in governance_asset_context["assets"]} == {
            "ops-api",
            "payments-api",
        }
        assert sum(item["finding_count"] for item in governance_asset_context["assets"]) == 2
        assert "Governance Rollups" in technical_report
        assert "Top Assets by Risk" in technical_report
        assert "Accepted Risk and Expiring Waivers" in technical_report
        assert "VEX Summary" in technical_report
        assert "Service Risk, Accepted Risk, and VEX" in executive_report
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


def test_vpw068_reports_and_evidence_bundle_export_governance_context() -> None:
    payload = _vpw068_governance_payload()

    markdown = render_markdown_report(payload)
    assert markdown == (_repo_root() / VPW068_MARKDOWN_SNAPSHOT).read_text(encoding="utf-8")
    assert "### Top Assets by Risk" in markdown
    assert "### Accepted Risk and Expiring Waivers" in markdown
    assert "### VEX Summary" in markdown
    assert (
        "| service:checkout | risk-team | review\\_due | 2026-05-07 | 2026-04-30 | 2 |" in markdown
    )
    assert "| Suppressed by VEX | 1 |" in markdown

    html = render_html_executive_report(payload)
    assert _normalize_html_snapshot(html) == (_repo_root() / VPW068_HTML_SNAPSHOT).read_text(
        encoding="utf-8"
    )
    assert "Service Risk, Accepted Risk, and VEX" in html
    assert "Accepted Risk and Expiring Waivers" in html
    assert "Expiring Soon" in html
    assert "service:checkout" in html

    analysis = json.loads(render_analysis_result_json(payload))
    jsonschema.validate(analysis, _load_schema("analysis-result.v1.schema.json"))
    assert analysis["governance_rollups"]["top_assets_by_risk"][0]["label"] == "payments-api"
    assert analysis["governance_rollups"]["waiver_debt"]["expiring_soon_count"] == 1

    bundle, manifest = render_evidence_bundle_zip(payload)
    jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        assert {
            "governance/asset-context.json",
            "governance/rollups.json",
            "governance/vex-summary.json",
            "governance/waivers.json",
        }.issubset(set(archive.namelist()))
        waivers = json.loads(archive.read("governance/waivers.json"))
        vex = json.loads(archive.read("governance/vex-summary.json"))
        asset_context = json.loads(archive.read("governance/asset-context.json"))

    assert [item["kind"] for item in manifest["governance_artifacts"]] == [
        "governance-rollups",
        "governance-waivers",
        "governance-vex-summary",
        "governance-asset-context",
    ]
    assert waivers["accepted_findings"][0]["waiver_status"] == "review_due"
    assert (
        "Accepted-risk governance remains visible"
        in waivers["accepted_findings"][0]["decision_statement"]
    )
    assert vex["summary"]["suppressed_by_vex_count"] == 1
    assert vex["summary"]["status_counts"] == {"not_affected": 1}
    assert vex["findings"][0]["vex_statuses"] == "not_affected:1"
    assert asset_context["top_assets_by_risk"][0]["label"] == "payments-api"


def test_evidence_bundle_redacts_sensitive_governance_map_keys(tmp_path: Path) -> None:
    payload = _vpw068_governance_payload()
    governance_rollups = json.loads(json.dumps(payload.governance_rollups))
    governance_rollups["waiver_debt"]["owner_counts"] = {"token=ghp_super_secret_value": 1}
    governance_rollups["waiver_debt"]["service_counts"] = {str(tmp_path / "prod-db"): 1}
    redaction_payload = replace(payload, governance_rollups=governance_rollups)

    bundle, manifest = render_evidence_bundle_zip(redaction_payload)

    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        bundle_text = "\n".join(
            archive.read(name).decode("utf-8", errors="replace")
            for name in archive.namelist()
            if name.endswith((".json", ".md", ".html"))
        )

    assert "ghp_super_secret_value" not in bundle_text
    assert str(tmp_path) not in bundle_text
    assert "[REDACTED-KEY]" in bundle_text
    assert not any(
        "ghp_super_secret_value" in key for key in manifest["redaction"]["redacted_keys"]
    )
    assert not any(str(tmp_path) in key for key in manifest["redaction"]["redacted_keys"])


def test_vpw079_workbench_evidence_bundle_includes_detection_coverage_export() -> None:
    payload = replace(
        _vpw068_governance_payload(),
        detection_coverage={
            "summary": {
                "covered": 0,
                "partial": 1,
                "not_covered": 1,
                "unknown": 0,
                "not_applicable": 0,
            },
            "items": [
                {
                    "technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic_ids": ["TA0001"],
                    "finding_count": 2,
                    "critical_finding_count": 1,
                    "kev_finding_count": 1,
                    "coverage_level": "partial",
                    "control_count": 1,
                    "owner": "secops",
                    "evidence_refs": ["siem-rule-123"],
                    "recommended_action": (
                        "Review partial coverage and add compensating telemetry or analytics."
                    ),
                },
                {
                    "technique_id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "tactic_ids": ["TA0002"],
                    "finding_count": 1,
                    "critical_finding_count": 0,
                    "kev_finding_count": 0,
                    "coverage_level": "not_covered",
                    "control_count": 0,
                    "owner": None,
                    "evidence_refs": [],
                    "recommended_action": (
                        "Prioritize defensive coverage or document compensating controls."
                    ),
                },
            ],
            "controls": [
                {
                    "control_id": "edge-waf",
                    "name": "WAF exploit-public-app rule",
                    "technique_id": "T1190",
                    "coverage_level": "partial",
                    "owner": "secops",
                    "evidence_ref": "siem-rule-123",
                }
            ],
        },
    )

    markdown = render_markdown_report(payload)
    assert "## Detection Coverage" in markdown
    assert "| Partial | 1 |" in markdown
    analysis = json.loads(render_analysis_result_json(payload))
    jsonschema.validate(analysis, _load_schema("analysis-result.v1.schema.json"))
    assert analysis["detection_coverage"]["summary"]["not_covered"] == 1

    bundle, manifest = render_evidence_bundle_zip(payload)
    jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
    with zipfile.ZipFile(BytesIO(bundle)) as archive:
        assert "governance/detection-coverage.json" in archive.namelist()
        detection_bytes = archive.read("governance/detection-coverage.json")
        detection_coverage = json.loads(detection_bytes)

    assert detection_coverage["schema"] == "detection-coverage.v1"
    assert detection_coverage["summary"]["partial"] == 1
    assert detection_coverage["items"][0]["coverage_level"] == "partial"
    assert "not proof" in detection_coverage["limitations"][0]
    assert {
        "bundle_path": "governance/detection-coverage.json",
        "kind": "governance-detection-coverage",
        "sha256": manifest["artifact_hashes"]["governance/detection-coverage.json"],
    } in manifest["governance_artifacts"]
    assert (
        manifest["artifact_hashes"]["governance/detection-coverage.json"]
        == hashlib.sha256(detection_bytes).hexdigest()
    )


def test_vpw060_evidence_bundle_includes_attack_navigator_layer_when_mapped(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    _add_vpw060_attack_contexts(workbench_api_env, run_id)

    response = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "zip"},
    )

    assert response.status_code == 200, response.text
    download = workbench_api_env.client.get(response.json()["download_url"], headers=headers)
    assert download.status_code == 200

    with zipfile.ZipFile(BytesIO(download.content)) as archive:
        names = sorted(archive.namelist())
        assert "attack-navigator-layer.json" in names
        manifest = json.loads(archive.read("manifest.json"))
        layer = json.loads(archive.read("attack-navigator-layer.json"))
        layer_entry = next(
            item for item in manifest["files"] if item["path"] == "attack-navigator-layer.json"
        )
        assert manifest["attack_navigator_layer"] == {
            "bundle_path": "attack-navigator-layer.json",
            "sha256": layer_entry["sha256"],
        }
        assert layer_entry["kind"] == "attack-navigator-layer"
        assert (
            layer_entry["sha256"]
            == hashlib.sha256(archive.read("attack-navigator-layer.json")).hexdigest()
        )
        assert [item["techniqueID"] for item in layer["techniques"]] == ["T1059", "T1190"]


def test_vpw052_evidence_bundle_verify_api_reports_clean_bundle(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    created = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "zip"},
    )
    assert created.status_code == 200, created.text

    verified = workbench_api_env.client.post(
        f"/api/v1/reports/{created.json()['id']}/verify",
        headers=headers,
    )

    assert verified.status_code == 200, verified.text
    payload = verified.json()
    jsonschema.validate(payload, _load_schema("evidence-bundle-verification-report.schema.json"))
    assert payload["metadata"]["bundle_path"] == "evidence-bundle.zip"
    assert payload["metadata"]["bundle_kind"] == "evidence-bundle"
    assert payload["metadata"]["manifest_schema_version"] == "1.1.0"
    assert payload["summary"] == {
        "ok": True,
        "total_members": 9,
        "expected_files": 8,
        "verified_files": 8,
        "missing_files": 0,
        "modified_files": 0,
        "unexpected_files": 0,
        "manifest_errors": 0,
    }
    assert {item["status"] for item in payload["items"]} == {"ok"}
    assert str(tmp_path) not in json.dumps(payload)


def test_vpw052_evidence_bundle_verify_api_reports_modified_member(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    created = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "zip"},
    )
    assert created.status_code == 200, created.text
    report_id = uuid.UUID(created.json()["id"])

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report_path = Path(report.path)
    tampered_bundle = _replace_zip_member(
        report_path.read_bytes(),
        "analysis.json",
        b'{"schema":"analysis-result.v1","tampered":true}\n',
    )
    report_path.write_bytes(tampered_bundle)
    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report.sha256 = hashlib.sha256(tampered_bundle).hexdigest()
        report.size_bytes = len(tampered_bundle)
        session.add(report)
        session.commit()

    verified = workbench_api_env.client.post(
        f"/api/v1/reports/{report_id}/verify",
        headers=headers,
    )

    assert verified.status_code == 200, verified.text
    payload = verified.json()
    jsonschema.validate(payload, _load_schema("evidence-bundle-verification-report.schema.json"))
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["modified_files"] == 1
    assert payload["summary"]["verified_files"] == 7
    modified_items = [item for item in payload["items"] if item["status"] == "modified"]
    assert len(modified_items) == 1
    assert modified_items[0]["path"] == "analysis.json"
    assert modified_items[0]["kind"] == "analysis-json"
    assert "sha256 mismatch" in modified_items[0]["detail"]
    assert modified_items[0]["expected_sha256"] != modified_items[0]["actual_sha256"]


def test_vpw052_verify_api_rejects_non_bundle_reports(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    created = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "markdown"},
    )
    assert created.status_code == 200, created.text

    response = workbench_api_env.client.post(
        f"/api/v1/reports/{created.json()['id']}/verify",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Report is not an evidence bundle"


def test_vpw052_committed_verification_evidence_is_contract_valid() -> None:
    schema = _load_schema("evidence-bundle-verification-report.schema.json")
    evidence_dir = _repo_root() / "docs" / "evidence"
    positive = json.loads(
        (evidence_dir / "vpw-052-positive-verification.json").read_text(encoding="utf-8")
    )
    tampered = json.loads(
        (evidence_dir / "vpw-052-tampered-verification.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(positive, schema)
    assert positive["summary"]["ok"] is True
    assert positive["summary"]["verified_files"] == 4
    assert {item["status"] for item in positive["items"]} == {"ok"}

    jsonschema.validate(tampered, schema)
    assert tampered["summary"]["ok"] is False
    assert tampered["summary"]["modified_files"] == 1
    assert [item["path"] for item in tampered["items"] if item["status"] == "modified"] == [
        "analysis.json"
    ]


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


def test_vpw060_attack_navigator_layer_snapshot_is_stable() -> None:
    layer = _vpw060_snapshot_layer()

    assert layer == json.loads(
        (_repo_root() / "docs" / "evidence" / "vpw-060-attack-navigator-layer.json").read_text(
            encoding="utf-8"
        )
    )


def test_vpw048_report_local_project_visibility_and_invalid_run_state(
    secondary_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(secondary_workbench_api_env, tmp_path)
    headers = local_api_headers(secondary_workbench_api_env.client)
    secondary_project = seed_secondary_project_graph(
        secondary_workbench_api_env.engine,
        secondary_workbench_api_env.app_models,
        secondary_workbench_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")
    pending_run_id = _seed_status_run(secondary_workbench_api_env, "pending")
    failed_run_id = _seed_status_run(secondary_workbench_api_env, "failed")
    secondary_report_id = _seed_secondary_project_report(
        secondary_workbench_api_env, secondary_project
    )

    assert (
        secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{missing_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 404
    )
    assert (
        secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{secondary_project['run_id']}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 200
    )
    assert (
        secondary_workbench_api_env.client.get(
            f"/api/v1/reports/{secondary_report_id}/download",
            headers=headers,
        ).status_code
        == 404
    )
    for run_id in (pending_run_id, failed_run_id):
        response = secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{run_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        )
        assert response.status_code == 422
        assert "completed" in response.json()["detail"]
    with Session(secondary_workbench_api_env.engine) as session:
        failure_events = session.exec(
            select(secondary_workbench_api_env.app_models.AuditEvent).where(
                secondary_workbench_api_env.app_models.AuditEvent.action == "report.create",
                secondary_workbench_api_env.app_models.AuditEvent.status == "failure",
            )
        ).all()
    assert {event.resource_id for event in failure_events} == {
        str(pending_run_id),
        str(failed_run_id),
    }
    assert {event.resource_type for event in failure_events} == {"analysis_run"}
    assert all(event.detail_json["format"] == "markdown" for event in failure_events)


def test_vpw048_download_rejects_path_escape_and_checksum_mismatch(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    created = workbench_api_env.client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=headers,
        json={"format": "markdown"},
    ).json()
    report_id = uuid.UUID(created["id"])

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report_path = Path(report.path)
    report_path.write_text("tampered report\n", encoding="utf-8")

    tampered = workbench_api_env.client.get(created["download_url"], headers=headers)
    assert tampered.status_code == 409
    assert tampered.json()["detail"] == "Report artifact checksum mismatch"

    outside_path = tmp_path / "outside-report.md"
    outside_path.write_text("outside root\n", encoding="utf-8")
    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report.path = str(outside_path)
        session.add(report)
        session.commit()

    escaped = workbench_api_env.client.get(created["download_url"], headers=headers)
    assert escaped.status_code == 404
    assert escaped.json()["detail"] == "Report artifact not found"


def test_report_generation_rejects_artifacts_over_configured_size_limit(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    previous_settings = workbench_api_env.client.app.state.workbench_settings
    try:
        report_dir = _configure_report_dir(workbench_api_env, tmp_path, MAX_REPORT_MB=0)
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

        response = workbench_api_env.client.post(
            f"/api/v1/runs/{run_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        )

        assert response.status_code == 422
        assert "configured report size limit" in response.text
        with Session(workbench_api_env.engine) as session:
            reports = workbench_api_env.repositories.ReportRepository(session).list_run_reports(
                run_id
            )
        assert reports == []
        assert not report_dir.exists()
    finally:
        workbench_api_env.client.app.state.workbench_settings = previous_settings


def test_report_generation_prunes_oldest_reports_for_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    previous_settings = workbench_api_env.client.app.state.workbench_settings
    try:
        report_dir = _configure_report_dir(
            workbench_api_env,
            tmp_path,
            MAX_REPORT_MB=50,
            MAX_REPORTS_PER_RUN=2,
        )
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

        created = []
        for _ in range(3):
            response = workbench_api_env.client.post(
                f"/api/v1/runs/{run_id}/reports",
                headers=headers,
                json={"format": "markdown"},
            )
            assert response.status_code == 200, response.text
            created.append(response.json())

        with Session(workbench_api_env.engine) as session:
            reports = workbench_api_env.repositories.ReportRepository(session).list_run_reports(
                run_id
            )
            remaining_ids = {str(report.id) for report in reports}
            retention_event = session.exec(
                select(app_models.AuditEvent).where(
                    app_models.AuditEvent.action == "report.retention.delete"
                )
            ).one()

        assert len(reports) == 2
        assert remaining_ids == {created[1]["id"], created[2]["id"]}
        assert retention_event.resource_id == created[0]["id"]
        assert retention_event.project_id == uuid.UUID(project["id"])
        assert retention_event.detail_json == {
            "analysis_run_id": str(run_id),
            "retained_report_id": created[2]["id"],
            "format": "markdown",
            "kind": "technical-markdown",
            "filename": "technical-report.md",
            "artifact_deleted": True,
            "max_reports_per_run": 2,
        }
        assert not (report_dir / project["id"] / str(run_id) / created[0]["id"]).exists()
        assert (report_dir / project["id"] / str(run_id) / created[1]["id"]).exists()
        assert (report_dir / project["id"] / str(run_id) / created[2]["id"]).exists()
    finally:
        workbench_api_env.client.app.state.workbench_settings = previous_settings


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


def test_vpw054_demo_report_artifacts_match_current_renderers() -> None:
    payload = _vpw054_demo_payload()
    repo_root = _repo_root()
    rendered = {
        "markdown": render_markdown_report(payload),
        "html": render_html_executive_report(payload),
        "json": render_analysis_result_json(payload),
    }

    for artifact_type, relative_path in VPW054_DEMO_ARTIFACTS.items():
        artifact_path = repo_root / relative_path
        assert artifact_path.read_text(encoding="utf-8") == rendered[artifact_type]

    jsonschema.validate(
        json.loads(rendered["json"]),
        _load_schema("analysis-result.v1.schema.json"),
    )


def test_vpw054_normalized_html_report_snapshot_is_stable() -> None:
    payload = _vpw054_demo_payload()
    snapshot_path = _repo_root() / VPW054_HTML_SNAPSHOT

    assert _normalize_html_snapshot(
        render_html_executive_report(payload)
    ) == snapshot_path.read_text(encoding="utf-8")


def test_vpw054_demo_report_artifacts_are_linked_and_secret_free() -> None:
    repo_root = _repo_root()
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    evidence = (repo_root / "docs" / "evidence" / "vpw-054-report-snapshots.md").read_text(
        encoding="utf-8"
    )
    combined_artifacts: list[str] = []

    for relative_path in VPW054_DEMO_ARTIFACTS.values():
        artifact_link = relative_path.as_posix()
        assert artifact_link in readme
        assert artifact_link in evidence
        combined_artifacts.append((repo_root / relative_path).read_text(encoding="utf-8"))

    combined_text = "\n".join(combined_artifacts).lower()
    for marker in VPW054_SECRET_MARKERS:
        assert marker not in combined_text


def _layer_metadata(layer: dict[str, Any], key: str) -> str | None:
    for item in layer.get("metadata", []):
        if item.get("name") == key:
            return item.get("value")
    return None


def _technique_metadata(technique: dict[str, Any], key: str) -> str | None:
    for item in technique.get("metadata", []):
        if item.get("name") == key:
            return item.get("value")
    return None


def _configure_report_dir(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    **settings_overrides: Any,
) -> Path:
    report_dir = (tmp_path / "workbench-reports").resolve(strict=False)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    overrides = {"MAX_REPORT_MB": 50, "MAX_REPORTS_PER_RUN": 20, **settings_overrides}
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        REPORT_DIR=str(report_dir),
        **overrides,
    )
    return report_dir


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_schema(filename: str) -> dict[str, Any]:
    schema_path = _repo_root() / "docs" / "schemas" / filename
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _normalize_html_snapshot(value: str) -> str:
    lines = [line.rstrip() for line in value.replace("\r\n", "\n").splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


def _replace_zip_member(bundle: bytes, member_path: str, replacement: bytes) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(BytesIO(bundle), "r") as source:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for source_info in source.infolist():
                content = (
                    replacement
                    if source_info.filename == member_path
                    else source.read(source_info.filename)
                )
                target_info = zipfile.ZipInfo(
                    filename=source_info.filename,
                    date_time=source_info.date_time,
                )
                target_info.compress_type = source_info.compress_type
                target_info.create_system = source_info.create_system
                target_info.external_attr = source_info.external_attr
                target.writestr(target_info, content)
    return output.getvalue()


def _vpw060_snapshot_layer() -> dict[str, Any]:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000060")
    run_id = uuid.UUID("00000000-0000-4000-8000-000000000061")
    finding_id = uuid.UUID("00000000-0000-4000-8000-000000000062")
    vulnerability_id = uuid.UUID("00000000-0000-4000-8000-000000000063")
    generated_at = datetime(2026, 4, 29, 12, 0, tzinfo=UTC)
    finding = app_models.Finding(
        id=finding_id,
        project_id=project_id,
        vulnerability_id=vulnerability_id,
        cve_id=DEMO_CVE_LOG4SHELL,
        dedup_key="vpw060-log4shell",
        priority=app_models.FindingPriority.HIGH,
        priority_rank=2,
        operational_rank=1,
        risk_score=94.2,
        in_kev=True,
        attack_mapped=True,
    )
    unmapped = app_models.Finding(
        id=uuid.UUID("00000000-0000-4000-8000-000000000064"),
        project_id=project_id,
        vulnerability_id=uuid.UUID("00000000-0000-4000-8000-000000000065"),
        cve_id=DEMO_CVE_XZ,
        dedup_key="vpw060-xz",
        priority=app_models.FindingPriority.CRITICAL,
        priority_rank=1,
        operational_rank=2,
        risk_score=100.0,
        in_kev=False,
        attack_mapped=False,
    )
    context = app_models.FindingAttackContext(
        id=uuid.UUID("00000000-0000-4000-8000-000000000066"),
        finding_id=finding.id,
        analysis_run_id=run_id,
        cve_id=finding.cve_id,
        mapped=True,
        source="local-curated",
        review_status="needs_review",
        defensive_note="Defensive triage context only.",
        rationale="Reviewed local mapping for defensive prioritization.",
        technique_ids_json=["T1190"],
        tactic_ids_json=["initial-access"],
        mappings_json=[
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "attack_object_id": "T1190",
                "attack_object_name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "confidence": "low",
                "review_status": "needs_review",
                "source": "local-curated",
                "mapping_type": "exploitation",
                "defensive_note": "Use for defensive triage and coverage review.",
                "rationale": "Reviewed local mapping; no procedural detail included.",
            }
        ],
        created_at=generated_at,
        updated_at=generated_at,
    )
    return build_attack_navigator_layer_payload(
        project_id=project_id,
        project_name="VPW-060 Snapshot",
        run_id=run_id,
        findings=[finding, unmapped],
        attack_contexts=[context],
        filter_value="all",
        generated_at=generated_at,
    )


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
                        "recommendation_label": "Patch",
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
                        "recommendation_label": "Patch",
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
        project_created_at=datetime(2026, 4, 29, 10, 0, tzinfo=UTC),
        project_updated_at=datetime(2026, 4, 29, 10, 30, tzinfo=UTC),
        run_started_at=datetime(2026, 4, 29, 11, 0, tzinfo=UTC),
        run_finished_at=datetime(2026, 4, 29, 11, 45, tzinfo=UTC),
        run_errors={},
    )


def _vpw054_demo_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    return replace(
        payload,
        project_id="00000000-0000-4000-8000-000000000054",
        project_name="VPW-054 Demo Reports",
        project_description="Committed demo artifacts for VPW-054 report snapshot coverage.",
        run_id="00000000-0000-4000-8000-000000000540",
        filename="vpw-054-known-cves.txt",
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


def _vpw068_governance_payload() -> MarkdownReportPayload:
    payload = _vpw050_snapshot_payload()
    waiver = {
        "source": "workbench-api",
        "waiver_id": "00000000-0000-4000-8000-000000000681",
        "waiver_status": "review_due",
        "waiver_owner": "risk-team",
        "waiver_expires_on": "2026-05-07",
        "waiver_review_on": "2026-04-30",
        "waiver_scope": "service:checkout",
        "waiver_approval_ref": "CAB-068",
    }
    accepted = replace(
        payload.findings[0],
        status="accepted",
        waived=True,
        explanation={
            **payload.findings[0].explanation,
            "waiver": waiver,
            "waiver_status": "review_due",
            "waiver_owner": "risk-team",
            "waiver_expires_on": "2026-05-07",
            "waiver_review_on": "2026-04-30",
        },
        decision_statement=(
            "Decision Statement: maintain accepted risk for CVE-2024-3094 until "
            "owner review completes. Accepted-risk governance remains visible "
            "(owner risk-team; status review_due; review 2026-04-30; expires 2026-05-07)."
        ),
    )
    vex_suppressed = replace(
        payload.findings[1],
        status="suppressed",
        suppressed_by_vex=True,
        explanation={
            **payload.findings[1].explanation,
            "provenance": {
                "vex_statuses": {"not_affected": 1},
                "occurrences": [
                    {
                        "vex_status": "not_affected",
                        "source_format": "openvex",
                        "source_record_id": "VEX-068-1",
                    }
                ],
            },
            "vex_justification": "component_not_present",
            "vex_action_statement": "Reopen if the affected package is redeployed.",
            "vex_source_format": "openvex",
            "vex_source_record_id": "VEX-068-1",
        },
        decision_statement=(
            "Decision Statement: monitor VEX-suppressed CVE-2021-44228. "
            "VEX governance applies (status not_affected; source openvex; record VEX-068-1)."
        ),
    )
    return replace(
        payload,
        findings=[accepted, vex_suppressed],
        governance_rollups={
            "project_id": payload.project_id,
            "generated_at": "2026-04-29T12:00:00Z",
            "owners": [
                _vpw068_rollup(
                    "owner",
                    "platform-team",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "owner",
                    "secops",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "services": [
                _vpw068_rollup(
                    "service",
                    "checkout",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "service",
                    "operations",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "assets": [
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                ),
                _vpw068_rollup(
                    "asset",
                    "ops-api",
                    finding_count=1,
                    high_count=1,
                    suppressed_count=1,
                    suppressed_by_vex_count=1,
                    risk_score_total=94.2,
                    top_cves=[DEMO_CVE_LOG4SHELL],
                ),
            ],
            "environments": [
                _vpw068_rollup(
                    "environment",
                    "prod",
                    finding_count=2,
                    critical_count=1,
                    high_count=1,
                    accepted_count=1,
                    suppressed_count=1,
                    waived_count=1,
                    suppressed_by_vex_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=194.2,
                    top_cves=[DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL],
                )
            ],
            "top_services_by_risk": [
                _vpw068_rollup(
                    "service",
                    "checkout",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                )
            ],
            "top_assets_by_risk": [
                _vpw068_rollup(
                    "asset",
                    "payments-api",
                    finding_count=1,
                    critical_count=1,
                    accepted_count=1,
                    waived_count=1,
                    review_due_waiver_count=1,
                    risk_score_total=100.0,
                    top_cves=[DEMO_CVE_XZ],
                )
            ],
            "waiver_debt": {
                "waiver_count": 1,
                "active_count": 0,
                "review_due_count": 1,
                "expired_count": 0,
                "expiring_soon_count": 1,
                "matched_finding_count": 2,
                "accepted_finding_count": 1,
                "expired_finding_count": 0,
                "review_due_finding_count": 1,
                "owner_counts": {"risk-team": 1},
                "service_counts": {"checkout": 1},
                "items": [
                    {
                        "id": "00000000-0000-4000-8000-000000000681",
                        "owner": "risk-team",
                        "scope": "service:checkout",
                        "status": "review_due",
                        "days_remaining": 7,
                        "expires_at": "2026-05-07",
                        "review_at": "2026-04-30",
                        "matched_findings": 2,
                        "cve_id": None,
                        "service": "checkout",
                        "asset_key": None,
                        "finding_id": None,
                    }
                ],
            },
        },
    )


def _vpw068_rollup(
    dimension: str,
    label: str,
    *,
    finding_count: int,
    risk_score_total: float,
    top_cves: list[str],
    open_count: int = 0,
    accepted_count: int = 0,
    fixed_count: int = 0,
    suppressed_count: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
    kev_count: int = 0,
    attack_mapped_count: int = 0,
    suppressed_by_vex_count: int = 0,
    under_investigation_count: int = 0,
    waived_count: int = 0,
    expired_waiver_count: int = 0,
    review_due_waiver_count: int = 0,
) -> dict[str, Any]:
    return {
        "dimension": dimension,
        "label": label,
        "finding_count": finding_count,
        "open_count": open_count,
        "accepted_count": accepted_count,
        "fixed_count": fixed_count,
        "suppressed_count": suppressed_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "kev_count": kev_count,
        "attack_mapped_count": attack_mapped_count,
        "suppressed_by_vex_count": suppressed_by_vex_count,
        "under_investigation_count": under_investigation_count,
        "waived_count": waived_count,
        "expired_waiver_count": expired_waiver_count,
        "review_due_waiver_count": review_due_waiver_count,
        "risk_score_total": risk_score_total,
        "risk_score_max": risk_score_total,
        "highest_priority": "Critical" if critical_count else "High" if high_count else None,
        "priority_counts": {
            "Critical": critical_count,
            "High": high_count,
            "Medium": 0,
            "Low": 0,
        },
        "status_counts": {
            "open": open_count,
            "in_review": 0,
            "remediating": 0,
            "fixed": fixed_count,
            "accepted": accepted_count,
            "suppressed": suppressed_count,
        },
        "top_cves": top_cves,
    }


def _add_vpw051_bundle_metadata(
    workbench_api_env: WorkbenchApiEnv,
    run_id: uuid.UUID,
    tmp_path: Path,
) -> dict[str, Any]:
    app_models = workbench_api_env.app_models
    upload_path = tmp_path / "private" / "known-cves.txt"
    upload_content = f"{DEMO_CVE_XZ}\n{DEMO_CVE_LOG4SHELL}\n".encode()
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    upload_path.write_bytes(upload_content)
    input_metadata = {
        "path": upload_path.name,
        "size_bytes": len(upload_content),
        "sha256": hashlib.sha256(upload_content).hexdigest(),
    }
    with Session(workbench_api_env.engine) as session:
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


def _add_vpw060_attack_contexts(
    workbench_api_env: WorkbenchApiEnv,
    run_id: uuid.UUID,
) -> None:
    app_models_for_env = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models_for_env.AnalysisRun, run_id)
        assert run is not None
        findings = {
            finding.cve_id: finding
            for finding in session.exec(
                select(app_models_for_env.Finding).where(
                    app_models_for_env.Finding.project_id == run.project_id
                )
            ).all()
        }
        log4shell = findings[DEMO_CVE_LOG4SHELL]
        xz = findings[DEMO_CVE_XZ]
        for finding, technique_id, technique_name, tactic, confidence, review_status in (
            (
                log4shell,
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
                "medium",
                "reviewed",
            ),
            (
                xz,
                "T1059",
                "Command and Scripting Interpreter",
                "execution",
                "low",
                "needs_review",
            ),
        ):
            finding.attack_mapped = True
            finding.explanation_json = {
                **dict(finding.explanation_json or {}),
                "attack_techniques": [technique_id],
            }
            session.add(finding)
            session.add(
                app_models_for_env.FindingAttackContext(
                    finding_id=finding.id,
                    analysis_run_id=run.id,
                    cve_id=finding.cve_id,
                    mapped=True,
                    source="local-curated",
                    review_status=review_status,
                    defensive_note="Defensive triage context only; validate before action.",
                    rationale="Reviewed local ATT&CK mapping for defensive prioritization.",
                    technique_ids_json=[technique_id],
                    tactic_ids_json=[tactic],
                    mappings_json=[
                        {
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "attack_object_id": technique_id,
                            "attack_object_name": technique_name,
                            "tactics": [tactic],
                            "confidence": confidence,
                            "review_status": review_status,
                            "source": "local-curated",
                            "mapping_type": "exploitation",
                            "defensive_note": "Use for defensive triage and coverage review.",
                            "rationale": "Reviewed local mapping; no procedural detail included.",
                        }
                    ],
                )
            )
        session.commit()


def _seed_reportable_run(workbench_api_env: WorkbenchApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
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


def _seed_formula_run(workbench_api_env: WorkbenchApiEnv, project_id: uuid.UUID) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    with Session(workbench_api_env.engine) as session:
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


def _seed_status_run(workbench_api_env: WorkbenchApiEnv, status: str) -> uuid.UUID:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename=f"{status}.txt",
            status=status,
        )
        run_id = run.id
        session.commit()
        return run_id


def _seed_secondary_project_report(
    workbench_api_env: WorkbenchApiEnv,
    secondary_project: dict[str, uuid.UUID],
) -> uuid.UUID:
    report_id = uuid.uuid4()
    with Session(workbench_api_env.engine) as session:
        workbench_api_env.repositories.ReportRepository(session).create_report(
            report_id=report_id,
            project_id=secondary_project["project_id"],
            analysis_run_id=secondary_project["run_id"],
            kind="technical-markdown",
            format="markdown",
            filename="technical-report.md",
            content_type="text/markdown; charset=utf-8",
            path="data/workbench-reports/secondary_project/technical-report.md",
            sha256="0" * 64,
            size_bytes=0,
            metadata_json={},
        )
        session.commit()
    return report_id
