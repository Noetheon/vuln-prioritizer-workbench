from __future__ import annotations

import csv
import hashlib
import json
import uuid
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import jsonschema
from fastapi.testclient import TestClient
from sqlmodel import Session
from utils.report_contract_fixtures import (
    _vpw050_snapshot_payload,
    replace,
)
from utils.workbench_contracts import (
    _configure_report_dir,
    _create_report_via_worker,
    _layer_metadata,
    _load_schema,
    _seed_formula_run,
    _seed_reportable_run,
    _technique_metadata,
)
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app.core.config import Settings
from app.domain.engine.sarif_contract import (
    SARIF_FINGERPRINT_KEY,
    SARIF_WORKBENCH_FINGERPRINT_KEY,
)
from app.main import app
from app.models.reports import REPORT_FORMAT_VALUES
from app.services import (
    MarkdownReportFinding,
    MarkdownReportPayload,
    render_html_executive_report,
    render_sarif_report,
)
from app.services.report_contracts import (
    CSV_FINDINGS_COLUMNS,
    REPORT_CONTENT_TYPE_CSV,
    REPORT_CONTENT_TYPE_HTML,
    REPORT_CONTENT_TYPE_JSON,
    REPORT_CONTENT_TYPE_MARKDOWN,
    REPORT_CONTENT_TYPE_SARIF,
    REPORT_CONTENT_TYPE_ZIP,
    REPORT_FILENAME_ANALYSIS_JSON,
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_EVIDENCE_BUNDLE,
    REPORT_FILENAME_EXECUTIVE_HTML,
    REPORT_FILENAME_FINDINGS_CSV,
    REPORT_FILENAME_SARIF_RESULTS,
    REPORT_FILENAME_TECHNICAL_MARKDOWN,
    REPORT_KIND_ANALYSIS_JSON,
    REPORT_KIND_ATTACK_NAVIGATOR,
    REPORT_KIND_EVIDENCE_BUNDLE,
    REPORT_KIND_EXECUTIVE_HTML,
    REPORT_KIND_FINDINGS_CSV,
    REPORT_KIND_SARIF_RESULTS,
    REPORT_KIND_TECHNICAL_MARKDOWN,
)
from app.services.report_sarif_validation import validate_sarif_payload
from app.services.workbench_capabilities import build_workbench_capabilities


def test_vpw049_openapi_exposes_report_format_contract() -> None:
    client = TestClient(app)
    try:
        response = client.get("/api/v1/openapi.json")
    finally:
        client.close()

    assert response.status_code == 200
    payload = response.json()
    assert "/api/v1/runs/{run_id}/report-jobs" in payload["paths"]
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


def test_workbench_report_capabilities_match_report_create_and_artifact_contracts() -> None:
    expected_contracts = {
        "markdown": (
            REPORT_KIND_TECHNICAL_MARKDOWN,
            REPORT_FILENAME_TECHNICAL_MARKDOWN,
            REPORT_CONTENT_TYPE_MARKDOWN,
        ),
        "html": (
            REPORT_KIND_EXECUTIVE_HTML,
            REPORT_FILENAME_EXECUTIVE_HTML,
            REPORT_CONTENT_TYPE_HTML,
        ),
        "json": (
            REPORT_KIND_ANALYSIS_JSON,
            REPORT_FILENAME_ANALYSIS_JSON,
            REPORT_CONTENT_TYPE_JSON,
        ),
        "csv": (REPORT_KIND_FINDINGS_CSV, REPORT_FILENAME_FINDINGS_CSV, REPORT_CONTENT_TYPE_CSV),
        "zip": (
            REPORT_KIND_EVIDENCE_BUNDLE,
            REPORT_FILENAME_EVIDENCE_BUNDLE,
            REPORT_CONTENT_TYPE_ZIP,
        ),
        "attack-navigator": (
            REPORT_KIND_ATTACK_NAVIGATOR,
            REPORT_FILENAME_ATTACK_NAVIGATOR,
            REPORT_CONTENT_TYPE_JSON,
        ),
        "sarif": (
            REPORT_KIND_SARIF_RESULTS,
            REPORT_FILENAME_SARIF_RESULTS,
            REPORT_CONTENT_TYPE_SARIF,
        ),
    }
    capabilities = build_workbench_capabilities(Settings())

    assert [capability.format for capability in capabilities.report_formats] == list(
        REPORT_FORMAT_VALUES
    )
    assert {
        capability.format: (capability.kind, capability.filename, capability.content_type)
        for capability in capabilities.report_formats
    } == expected_contracts


def test_vpw048_markdown_report_create_downloads_for_completed_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    report_dir = _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "markdown"},
    )

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

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "html"},
    )

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
    assert "Executive Summary" not in body
    assert "Decision Brief" in body
    assert "Governance Exceptions" in body
    assert "Business Services at Risk" in body
    assert "Top Remediation Campaigns" in body
    assert "Recommendations" in body
    assert "Evidence Confidence and Provider Freshness" in body
    assert "Decision Statement" in body
    assert "Emergency / 24h" in body
    assert "sha256:vpw048-snapshot" in body
    assert body.index(DEMO_CVE_LOG4SHELL) < body.index(DEMO_CVE_XZ)
    assert "<script" not in body.lower()
    assert "<img" not in body.lower()
    assert 'href="javascript:' not in body.lower()


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
    assert "<svg onload" not in lowered
    assert 'href="javascript:' not in lowered
    assert '<svg class="risk-projection-svg"' in body
    assert "&lt;script&gt;window.__vpwXss=1&lt;/script&gt;" in body
    assert "known-cves&quot;&gt;&lt;img src=x onerror=window.__vpwXss=1&gt;.txt" in body
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

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "json"},
    )

    assert payload["format"] == "json"
    assert payload["kind"] == "analysis-result-json"
    assert payload["filename"] == "analysis-result.v2.json"
    assert payload["content_type"] == "application/json; charset=utf-8"
    assert payload["metadata_json"]["finding_count"] == 2

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, uuid.UUID(payload["id"]))
        assert report is not None
        assert Path(report.path).resolve(strict=True).is_relative_to(report_dir)
        assert report.path.endswith("analysis-result.v2.json")

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)

    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "analysis-result.v2.json" in download.headers["content-disposition"]
    assert download.headers["content-type"].startswith("application/json")
    assert hashlib.sha256(download.content).hexdigest() == payload["sha256"]

    body = download.json()
    jsonschema.validate(body, _load_schema("analysis-result.v2.schema.json"))
    assert body["schema"] == "analysis-result.v2"
    assert body["schema_version"] == "2.0.0"
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
    assert first["recommendation"]["decision_sla"] == "Emergency / 24h"
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

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "csv"},
    )

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

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "sarif"},
    )

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
        "vuln-prioritizer-workbench/cve-2024-3094",
        "vuln-prioritizer-workbench/cve-2021-44228",
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

    assert api_result["ruleId"] == f"vuln-prioritizer-workbench/{cve_id.lower()}"
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
    run_id = _seed_reportable_run(
        workbench_api_env,
        uuid.UUID(project["id"]),
        with_attack_contexts=True,
    )

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "attack-navigator", "attack_filter": "all"},
    )

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

    kev_payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "attack-navigator", "attack_filter": "kev"},
    )
    kev_layer = workbench_api_env.client.get(
        kev_payload["download_url"],
        headers=headers,
    ).json()
    assert [item["techniqueID"] for item in kev_layer["techniques"]] == ["T1190"]
    assert _layer_metadata(kev_layer, "Filter") == "kev"
    assert "KEV: 1 finding(s)" in kev_layer["techniques"][0]["comment"]

    no_coverage_payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "attack-navigator", "attack_filter": "no-coverage"},
    )
    no_coverage_layer = workbench_api_env.client.get(
        no_coverage_payload["download_url"],
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

    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "csv"},
    )

    csv_report = workbench_api_env.client.get(created["download_url"], headers=headers)
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
