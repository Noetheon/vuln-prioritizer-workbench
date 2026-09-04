from __future__ import annotations

import csv
import hashlib
import json
import uuid
import zipfile
from datetime import UTC, date, datetime
from io import BytesIO, StringIO
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload, configure_upload_dir
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
from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.readmodels import DecisionFindingView, run_finding_decision_views
from app.domain.engine.sarif_contract import (
    SARIF_FINGERPRINT_KEY,
    SARIF_WORKBENCH_FINGERPRINT_KEY,
)
from app.main import app
from app.models.reports import REPORT_FORMAT_VALUES
from app.services import (
    MarkdownReportFinding,
    MarkdownReportPayload,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
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
from app.services.report_governance_projection import build_run_governance_rollups
from app.services.report_models import ReportGenerationError
from app.services.report_projection import _report_occurrences
from app.services.report_sarif_validation import validate_sarif_payload
from app.services.report_service_attack import attack_navigator_layer, run_attack_contexts
from app.services.report_service_payload import build_report_payload, run_findings
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
    # This synthetic v2 fixture deliberately has no typed occurrence evidence;
    # relational occurrence rows must not leak into a historical export.
    assert first["occurrences"] == []
    assert set(body["explanations"]) == {DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL}


def test_historical_report_uses_only_immutable_run_evidence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project_payload = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project_payload["id"])
    run_id = _seed_reportable_run(
        workbench_api_env,
        project_id,
        with_attack_contexts=True,
    )
    mutable_noise_project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Mutable occurrence noise",
    )
    mutable_noise_project_id = uuid.UUID(mutable_noise_project["id"])
    mutable_noise_run_id = _seed_reportable_run(
        workbench_api_env,
        mutable_noise_project_id,
        with_attack_contexts=True,
    )

    def report_payload() -> MarkdownReportPayload:
        with Session(workbench_api_env.engine) as session:
            run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
            project = session.get(workbench_api_env.app_models.Project, project_id)
            assert run is not None
            assert project is not None
            return build_report_payload(session, run=run, project=project)[0]

    def navigator_payload() -> dict[str, object]:
        with Session(workbench_api_env.engine) as session:
            run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
            project = session.get(workbench_api_env.app_models.Project, project_id)
            assert run is not None
            assert project is not None
            findings = run_findings(session, run)
            finding_views = run_finding_decision_views(session, run=run, findings=findings)
            layer = attack_navigator_layer(
                run=run,
                project=project,
                findings=finding_views,
                attack_contexts=run_attack_contexts(
                    session,
                    run,
                    findings=finding_views,
                ),
                generated_at=run.finished_at,
                filter_value="all",
                include_empty=True,
            )
            assert layer is not None
            return layer

    def bundle_projection(
        payload: MarkdownReportPayload,
        navigator: dict[str, object],
    ) -> dict[str, object]:
        bundle, manifest = render_evidence_bundle_zip(
            payload,
            attack_navigator_layer=navigator,
        )
        with zipfile.ZipFile(BytesIO(bundle)) as archive:
            analysis = json.loads(archive.read("analysis.json"))
            bundled_navigator = json.loads(archive.read("attack-navigator-layer.json"))
        return {
            "manifest_finding_count": manifest["findings_count"],
            "analysis_cves": [finding["cve_id"] for finding in analysis["findings"]],
            "navigator_techniques": bundled_navigator["techniques"],
        }

    before = report_payload()
    navigator_before = navigator_payload()
    bundle_before = bundle_projection(before, navigator_before)
    finding_before = next(
        finding for finding in before.findings if finding.cve_id == DEMO_CVE_LOG4SHELL
    )
    assert before.provider_snapshot is not None
    assert before.provider_snapshot.source_metadata["run_subset_provider_evidence"] == {
        "scope": "selected_run_findings",
        "derivation": "immutable_finding_decision_evidence",
        "finding_evidence_count": 2,
        "nvd_last_modified_max": None,
        "latest_epss_date": None,
        "kev_date_added_max": None,
    }

    with Session(workbench_api_env.engine) as session:
        asset = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project_id,
                workbench_api_env.app_models.Asset.asset_key == "ops-api",
            )
        ).one()
        asset.name = "RENAMED-LATER"
        asset.owner = "later-owner"
        asset.business_service = "later-service"
        asset.criticality = workbench_api_env.app_models.AssetCriticality.LOW
        session.add(asset)

        vulnerability = session.exec(
            select(workbench_api_env.app_models.Vulnerability).where(
                workbench_api_env.app_models.Vulnerability.cve_id == DEMO_CVE_LOG4SHELL
            )
        ).one()
        vulnerability.description = "MUTATED-LATER"
        vulnerability.cvss_score = 1.0
        vulnerability.provider_json = {"reference_urls": ["https://later.invalid"]}
        session.add(vulnerability)

        attack_context = session.exec(
            select(workbench_api_env.app_models.FindingAttackContext).where(
                workbench_api_env.app_models.FindingAttackContext.analysis_run_id == run_id,
                workbench_api_env.app_models.FindingAttackContext.cve_id == DEMO_CVE_LOG4SHELL,
            )
        ).one()
        attack_context.source = "mutated-later"
        attack_context.review_status = "stale"
        attack_context.technique_ids_json = ["T9999"]
        attack_context.tactic_ids_json = []
        attack_context.mappings_json = [
            {
                "technique_id": "T9999",
                "technique_name": "MUTATED-LATER",
                "confidence": "low",
            }
        ]
        session.add(attack_context)

        waiver_repository = workbench_api_env.repositories.WaiverRepository(session)
        waiver_repository.create_project_waiver(
            project_id=project_id,
            waiver_in=workbench_api_env.app_models.WaiverCreate(
                cve_id=DEMO_CVE_LOG4SHELL,
                owner="later-owner",
                reason="Created after the selected analysis run.",
                expires_at=date(2099, 1, 1),
            ),
        )

        snapshot = workbench_api_env.repositories.RunRepository(
            session
        ).get_or_create_provider_snapshot(
            content_hash=before.provider_snapshot.content_hash or "",
            nvd_last_sync="2099-01-01T00:00:00Z",
            epss_date="2099-01-01",
            kev_catalog_version="later-version",
            source_hashes_json={"nvd": "later-hash"},
            source_metadata_json={"later": True},
        )
        assert str(snapshot.id) == before.provider_snapshot.id

        primary_occurrences = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.analysis_run_id == run_id
            )
        ).all()
        primary_occurrences_by_cve = {}
        for occurrence in primary_occurrences:
            finding = session.get(workbench_api_env.app_models.Finding, occurrence.finding_id)
            assert finding is not None
            primary_occurrences_by_cve[finding.cve_id] = occurrence
        mutable_noise_occurrence = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.analysis_run_id
                == mutable_noise_run_id
            )
        ).first()
        assert mutable_noise_occurrence is not None
        session.delete(primary_occurrences_by_cve[DEMO_CVE_LOG4SHELL])
        primary_occurrences_by_cve[DEMO_CVE_XZ].analysis_run_id = mutable_noise_run_id
        mutable_noise_occurrence.analysis_run_id = run_id
        session.add(primary_occurrences_by_cve[DEMO_CVE_XZ])
        session.add(mutable_noise_occurrence)
        session.commit()

    after = report_payload()
    navigator_after = navigator_payload()
    bundle_after = bundle_projection(after, navigator_after)
    finding_after = next(
        finding for finding in after.findings if finding.cve_id == DEMO_CVE_LOG4SHELL
    )
    assert finding_after == finding_before
    assert after.provider_snapshot == before.provider_snapshot
    assert navigator_after == navigator_before
    assert bundle_after == bundle_before
    assert [finding.cve_id for finding in after.findings] == [
        finding.cve_id for finding in before.findings
    ]
    assert set(bundle_after["analysis_cves"]) == {DEMO_CVE_XZ, DEMO_CVE_LOG4SHELL}
    assert finding_after.asset == "Ops <img src=x onerror=alert(1)> API"
    assert finding_after.owner is None
    assert finding_after.business_service is None
    assert finding_after.criticality is None
    assert finding_after.vulnerability is not None
    assert finding_after.vulnerability.cvss_score == 10.0
    assert finding_after.vulnerability.description is None
    assert "later.invalid" not in json.dumps(finding_after.model_dump(mode="json"))
    assert before.governance_rollups["waiver_debt"]["waiver_count"] == 0
    assert after.governance_rollups["waiver_debt"]["waiver_count"] == 0
    assert {
        key: value for key, value in after.governance_rollups.items() if key != "generated_at"
    } == {key: value for key, value in before.governance_rollups.items() if key != "generated_at"}

    with Session(workbench_api_env.engine) as session:
        run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
        assert run is not None
        finding_views = run_finding_decision_views(
            session,
            run=run,
            findings=run_findings(session, run),
        )
        typed_view = next(view for view in finding_views if view.cve_id == DEMO_CVE_LOG4SHELL)
        legacy_view = next(view for view in finding_views if view.cve_id == DEMO_CVE_XZ)
        hybrid_contexts = run_attack_contexts(
            session,
            run,
            findings=[
                typed_view,
                DecisionFindingView(finding=legacy_view.finding),
            ],
        )
        contexts_by_cve = {context.cve_id: context for context in hybrid_contexts}
        assert typed_view.evidence is not None
        assert contexts_by_cve[DEMO_CVE_LOG4SHELL].source == typed_view.evidence.attack.source
        assert contexts_by_cve[DEMO_CVE_XZ].source == "local-curated"

    with Session(workbench_api_env.engine) as session:
        relational_occurrence = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.analysis_run_id == run_id,
            )
        ).first()
        assert relational_occurrence is not None
    empty_typed_occurrences = FindingDecisionEvidenceV2.model_validate(
        finding_before.evidence
    ).model_copy(update={"occurrences": []})
    assert (
        _report_occurrences(
            evidence=empty_typed_occurrences,
            occurrences=[relational_occurrence],
        )
        == ()
    )

    with Session(workbench_api_env.engine) as session:
        decision_evidence = session.exec(
            select(workbench_api_env.app_models.FindingDecisionEvidence).where(
                workbench_api_env.app_models.FindingDecisionEvidence.analysis_run_id == run_id
            )
        ).first()
        assert decision_evidence is not None
        session.delete(decision_evidence)
        session.commit()
    with pytest.raises(ReportGenerationError, match="finding membership is inconsistent"):
        report_payload()


def test_historical_report_header_and_provider_subset_are_evidence_bound(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project_payload = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Immutable report source",
    )
    project_id = uuid.UUID(project_payload["id"])
    configure_upload_dir(workbench_api_env, tmp_path)
    _configure_report_dir(workbench_api_env, tmp_path)
    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={
            "file": (
                "original.txt",
                f"{DEMO_CVE_LOG4SHELL}\n{DEMO_CVE_XZ}\n".encode(),
                "text/plain",
            )
        },
    )
    completed = completed_run_payload(workbench_api_env, response, headers=headers)
    run_id = uuid.UUID(completed["id"])

    def payload() -> MarkdownReportPayload:
        with Session(workbench_api_env.engine) as session:
            run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
            project = session.get(workbench_api_env.app_models.Project, project_id)
            assert run is not None
            assert project is not None
            return build_report_payload(session, run=run, project=project)[0]

    before = payload()
    assert before.run_status == "succeeded"
    assert before.input_type == "cve-list"
    assert before.filename == "original.txt"
    assert before.run_started_at is None
    assert before.run_finished_at is None
    assert before.run_error is None
    assert before.run_errors == {}
    assert before.provider_snapshot is not None
    assert before.provider_snapshot.nvd_last_sync is None
    assert before.provider_snapshot.epss_date is None
    assert before.provider_snapshot.kev_catalog_version is None
    assert before.provider_snapshot.source_metadata["run_subset_provider_evidence"] == {
        "scope": "selected_run_findings",
        "derivation": "immutable_finding_decision_evidence",
        "finding_evidence_count": 2,
        "nvd_last_modified_max": "2026-02-20T16:15:59.363",
        "latest_epss_date": "2026-04-23",
        "kev_date_added_max": "2021-12-10",
    }
    assert before.project_context_source == "current_project_projection_at_export"
    immutable_provider_snapshot_id = before.provider_snapshot.id
    assert immutable_provider_snapshot_id is not None

    with Session(workbench_api_env.engine) as session:
        run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
        project = session.get(workbench_api_env.app_models.Project, project_id)
        assert run is not None
        assert project is not None
        snapshot = run.provider_snapshot
        assert snapshot is not None
        run.status = workbench_api_env.app_models.AnalysisRunStatus.FAILED
        run.input_type = "cyclonedx-json"
        run.filename = "MUTATED-LATER.json"
        run.error_message = "MUTATED-LATER"
        run.started_at = datetime(2099, 1, 1, tzinfo=UTC)
        run.finished_at = datetime(2099, 1, 2, tzinfo=UTC)
        run.provider_snapshot_id = None
        snapshot.nvd_last_sync = "2099-01-01T00:00:00Z"
        snapshot.epss_date = "2099-01-01"
        snapshot.kev_catalog_version = "later-version"
        snapshot.source_metadata_json = {"later": True}
        project.name = "Renamed current project context"
        project.description = "Description changed after the selected run."
        session.add(run)
        session.add(snapshot)
        session.add(project)
        session.commit()

    after = payload()
    assert after.run_status == before.run_status
    assert after.input_type == before.input_type
    assert after.filename == before.filename
    assert after.run_started_at is None
    assert after.run_finished_at is None
    assert after.run_error is None
    assert after.run_errors == {}
    assert after.provider_snapshot == before.provider_snapshot
    assert after.project_name == "Renamed current project context"
    assert after.project_description == "Description changed after the selected run."
    assert after.project_context_source == "current_project_projection_at_export"

    analysis = json.loads(render_analysis_result_json(after))
    assert analysis["project"]["context_source"] == "current_project_projection_at_export"
    assert analysis["analysis_run"]["status"] == "succeeded"
    assert analysis["analysis_run"]["started_at"] is None
    assert analysis["analysis_run"]["finished_at"] is None
    assert analysis["analysis_run"]["error_message"] is None
    assert "Current project projection at export time" in render_markdown_report(after)
    assert "not immutable run evidence" in render_html_executive_report(after)

    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "json"},
    )
    download = workbench_api_env.client.get(created["download_url"], headers=headers)
    assert download.status_code == 200
    assert download.json()["analysis_run"]["status"] == "succeeded"
    assert download.json()["analysis_run"]["filename"] == "original.txt"
    assert created["metadata_json"]["provider_snapshot_id"] == immutable_provider_snapshot_id


def test_historical_report_fails_closed_on_mutable_run_project_drift(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    original_project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Immutable evidence project",
    )
    other_project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Mutable run project",
    )
    run_id = _seed_reportable_run(
        workbench_api_env,
        uuid.UUID(original_project["id"]),
    )

    with Session(workbench_api_env.engine) as session:
        run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
        project = session.get(
            workbench_api_env.app_models.Project,
            uuid.UUID(other_project["id"]),
        )
        assert run is not None
        assert project is not None
        run.project_id = project.id
        session.add(run)
        session.commit()

        with pytest.raises(ReportGenerationError, match="project identity"):
            build_report_payload(session, run=run, project=project)


def test_historical_report_derives_component_label_from_immutable_purl(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project_payload = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project_payload["id"])
    csv_payload = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,source",
            f"{DEMO_CVE_LOG4SHELL},repo-a,,,pkg:pypi/django@3.0.0,test",
            "",
        ]
    ).encode()
    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("purl-only.csv", csv_payload, "text/csv")},
    )
    completed = completed_run_payload(workbench_api_env, response, headers=headers)
    run_id = uuid.UUID(completed["id"])

    with Session(workbench_api_env.engine) as session:
        run = session.get(workbench_api_env.app_models.AnalysisRun, run_id)
        project = session.get(workbench_api_env.app_models.Project, project_id)
        assert run is not None
        assert project is not None
        payload = build_report_payload(session, run=run, project=project)[0]

    assert len(payload.findings) == 1
    assert payload.findings[0].component == "django 3.0.0"
    assert payload.findings[0].component_purl == "pkg:pypi/django@3.0.0"
    analysis = json.loads(render_analysis_result_json(payload))
    assert analysis["findings"][0]["component"] == {
        "label": "django 3.0.0",
        "purl": "pkg:pypi/django@3.0.0",
    }
    csv_row = next(csv.DictReader(StringIO(render_findings_csv(payload))))
    assert csv_row["component"] == "django 3.0.0"


def test_run_governance_rollups_preserve_and_deduplicate_typed_waiver_evidence() -> None:
    payload = _vpw050_snapshot_payload()
    waiver = {
        "waiver_id": "00000000-0000-4000-8000-000000000681",
        "waiver_status": "review_due",
        "waiver_owner": "risk-team",
        "waiver_scope": "service:checkout",
        "waiver_expires_on": "2026-05-07",
        "waiver_review_on": "2026-04-30",
        "waiver_days_remaining": 7,
        "waiver_reason": "Temporary compensating control.",
        "waiver_approval_ref": "CAB-068",
        "waiver_ticket_url": "https://tickets.example/068",
    }
    findings = tuple(
        finding.model_copy(
            update={
                "status": "accepted",
                "waived": True,
                "business_service": "checkout",
                "explanation": {"waiver": waiver, "cve_id": finding.cve_id},
                "evidence": {
                    "priority_evidence": {
                        "raw": {
                            "waiver": waiver,
                            "cve_id": finding.cve_id,
                            "operational_score": finding.risk_score,
                        }
                    },
                    "governance": {"waiver": waiver},
                },
            }
        )
        for finding in payload.findings
    )

    rollups = build_run_governance_rollups(
        project_id=uuid.UUID(payload.project_id),
        findings=findings,
        generated_at=datetime(2026, 5, 1, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 30, tzinfo=UTC),
    )

    debt = rollups["waiver_debt"]
    assert debt["waiver_count"] == 1
    assert debt["review_due_count"] == 1
    assert debt["matched_finding_count"] == 2
    assert debt["service_counts"] == {"checkout": 1}
    assert debt["items"] == [
        {
            "id": waiver["waiver_id"],
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
            "reason": "Temporary compensating control.",
            "approval_ref": "CAB-068",
            "ticket_url": "https://tickets.example/068",
        }
    ]
    analysis_result = json.loads(
        render_analysis_result_json(
            payload.model_copy(
                update={"findings": findings, "governance_rollups": rollups},
            )
        )
    )
    jsonschema.validate(analysis_result, _load_schema("analysis-result.v2.schema.json"))
    exported_debt = analysis_result["governance_rollups"]["waiver_debt"]
    assert exported_debt["items"][0]["reason"] == waiver["waiver_reason"]
    assert exported_debt["items"][0]["approval_ref"] == waiver["waiver_approval_ref"]
    assert exported_debt["items"][0]["ticket_url"] == waiver["waiver_ticket_url"]


def test_run_governance_rollups_keep_idless_waivers_distinct_per_cve() -> None:
    payload = _vpw050_snapshot_payload()
    idless_waiver = {
        "waiver_status": "active",
        "waiver_owner": "risk-team",
        "waiver_scope": "global",
        "waiver_expires_on": "2026-05-30",
        "waiver_review_on": "2026-05-15",
        "waiver_days_remaining": 29,
        "waiver_reason": "Imported policy rule without a stable identifier.",
    }
    findings = tuple(
        finding.model_copy(
            update={
                "status": "accepted",
                "waived": True,
                "explanation": {"waiver": idless_waiver},
                "evidence": {
                    "priority_evidence": {"raw": {"waiver": idless_waiver}},
                    "governance": {"waiver": idless_waiver},
                },
            }
        )
        for finding in payload.findings
    )

    rollups = build_run_governance_rollups(
        project_id=uuid.UUID(payload.project_id),
        findings=findings,
        generated_at=datetime(2026, 5, 1, tzinfo=UTC),
        evaluated_at=datetime(2026, 5, 1, tzinfo=UTC),
    )

    debt = rollups["waiver_debt"]
    assert debt["waiver_count"] == 2
    assert debt["active_count"] == 2
    assert debt["matched_finding_count"] == 2
    assert {item["cve_id"] for item in debt["items"]} == {
        DEMO_CVE_XZ,
        DEMO_CVE_LOG4SHELL,
    }
    assert {item["matched_findings"] for item in debt["items"]} == {1}
    assert len({item["id"] for item in debt["items"]}) == 2


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
    assert "'\tformula_flag - flag" in text
    assert "'-Patch now" in text
    assert ",=asset-key," not in text
    # Owner/service exist only in the mutable fixture relation, not in this run's
    # typed evidence, so a historical report must not project either value.
    assert "+owner" not in text
    assert "@service" not in text
    assert ",+owner," not in text
    assert ",@service," not in text
