from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

import jsonschema
import pytest
from utils.import_contract_fixtures import ATTACK_MAPPING, OPENVEX, SAMPLE_CVES, TRIVY_REPORT
from utils.workbench_contracts import _load_schema
from utils.workbench_env import WorkbenchApiEnv
from utils.workbench_workflow_contracts import (
    assert_no_workflow_path_leak,
    assert_same_run_contract,
    configure_workflow_context,
    create_report,
    downloaded_json,
    downloaded_text,
    downloaded_zip_members,
    finding_by_cve,
    finding_items,
    list_reports,
    post_import,
    project_findings,
    report_response,
    run_summary,
    sha256_bytes,
    verify_report,
)

from app.services.report_contracts import CSV_FINDINGS_COLUMNS


def test_cve_list_import_flows_to_summary_findings_and_core_reports(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    for env_name in ("NVD_API_KEY", "FIRST_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)
    for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(proxy_name, "http://127.0.0.1:9")

    context = configure_workflow_context(workbench_api_env, tmp_path)
    content = SAMPLE_CVES.read_bytes()
    import_payload = post_import(
        workbench_api_env,
        context,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample_cves.txt", content, "text/plain")},
    )
    run_id = import_payload["id"]

    summary = run_summary(workbench_api_env, context, run_id)
    findings = project_findings(workbench_api_env, context)
    assert_same_run_contract(
        import_payload=import_payload,
        summary=summary,
        findings=findings,
        context=context,
    )
    assert import_payload["input_type"] == "cve-list"
    assert import_payload["status"] == "succeeded"
    assert summary["input_upload"]["sha256"] == sha256_bytes(content)
    assert import_payload["locked_provider_data"] is True
    assert import_payload["provider_snapshot_file"] == "demo_provider_snapshot.json"
    assert summary["provider_snapshot_id"] == import_payload["provider_snapshot_id"]
    assert summary["provider_snapshot_id"]
    assert summary["finding_count"] > 0
    assert summary["kev_hits"] > 0

    finding_cves = {finding["cve_id"] for finding in finding_items(findings)}
    assert {"CVE-2024-3094", "CVE-2021-44228"} <= finding_cves

    markdown_report = create_report(workbench_api_env, context, run_id, "markdown")
    assert markdown_report["filename"] == "technical-report.md"
    assert markdown_report["kind"] == "technical-markdown"
    markdown_text = downloaded_text(workbench_api_env, context, markdown_report)
    assert "# Technical Vulnerability Report" in markdown_text
    assert "CVE-2024-3094" in markdown_text
    assert "## Provider Snapshot" in markdown_text
    assert_no_workflow_path_leak(markdown_text, context)

    json_report = create_report(workbench_api_env, context, run_id, "json")
    assert json_report["filename"] == "analysis-result.v1.json"
    assert json_report["kind"] == "analysis-result-json"
    analysis_json = downloaded_json(workbench_api_env, context, json_report)
    jsonschema.validate(analysis_json, _load_schema("analysis-result.v1.schema.json"))
    assert analysis_json["schema"] == "analysis-result.v1"
    assert analysis_json["project"]["id"] == context.project_id
    assert analysis_json["analysis_run"]["id"] == run_id
    assert analysis_json["analysis_run"]["project_id"] == context.project_id
    assert analysis_json["analysis_run"]["input_type"] == "cve-list"
    assert (
        analysis_json["analysis_run"]["summary"]["provider_snapshot_id"]
        == (summary["provider_snapshot_id"])
    )
    assert analysis_json["provider_snapshot"]["id"] == summary["provider_snapshot_id"]
    assert {finding["cve_id"] for finding in analysis_json["findings"]} == finding_cves
    assert {
        occurrence["analysis_run_id"]
        for finding in analysis_json["findings"]
        for occurrence in finding["occurrences"]
    } == {run_id}
    assert_no_workflow_path_leak(analysis_json, context)


def test_asset_context_import_flows_to_finding_context_and_csv_html_reports(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    context = configure_workflow_context(workbench_api_env, tmp_path)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,web-tier,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()
    asset_context_csv = "\n".join(
        [
            (
                "target_kind,target_ref,asset_id,owner,business_service,"
                "criticality,exposure,environment"
            ),
            "generic,web-tier,asset-web-1,team-platform,payments,critical,public,prod",
            "",
        ]
    ).encode()

    import_payload = post_import(
        workbench_api_env,
        context,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "asset_context_file": ("asset-context.csv", asset_context_csv, "text/csv"),
        },
    )
    run_id = import_payload["id"]
    summary = run_summary(workbench_api_env, context, run_id)
    findings = project_findings(workbench_api_env, context)
    detail = finding_by_cve(workbench_api_env, context, "CVE-2024-3094")

    assert_same_run_contract(
        import_payload=import_payload,
        summary=summary,
        findings=findings,
        context=context,
    )
    assert summary["input_type"] == "generic-occurrence-csv"
    assert import_payload["asset_context"]["matched_occurrences"] == 1
    assert detail["asset_key"] == "asset-web-1"
    assert detail["owner"] == "team-platform"
    assert detail["business_service"] == "payments"
    assert detail["asset_environment"] == "production"
    assert detail["exposure"] == "internet-facing"
    assert detail["explanation_json"]["provenance"]["asset_owners"] == ["team-platform"]
    assert detail["explanation_json"]["provenance"]["asset_business_services"] == ["payments"]

    csv_report = create_report(workbench_api_env, context, run_id, "csv")
    assert csv_report["filename"] == "findings.csv"
    csv_text = downloaded_text(workbench_api_env, context, csv_report)
    reader = csv.DictReader(StringIO(csv_text))
    assert reader.fieldnames == CSV_FINDINGS_COLUMNS
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2024-3094"
    assert rows[0]["asset"] == "asset-web-1"
    assert rows[0]["owner"] == "team-platform"
    assert rows[0]["service"] == "payments"
    assert rows[0]["component"] == "xz 5.6.0"
    assert_no_workflow_path_leak(csv_text, context)

    html_report = create_report(workbench_api_env, context, run_id, "html")
    assert html_report["filename"] == "executive-report.html"
    html = downloaded_text(workbench_api_env, context, html_report)
    assert "team-platform" in html
    assert "payments" in html
    assert_no_workflow_path_leak(html, context)


def test_openvex_import_flows_to_fixed_status_and_json_markdown_reports(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    context = configure_workflow_context(workbench_api_env, tmp_path)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            (
                "CVE-2021-44228,log4j-service,log4j-core,2.14.1,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,CRITICAL"
            ),
            "",
        ]
    ).encode()
    vex_bytes = OPENVEX.read_bytes()

    import_payload = post_import(
        workbench_api_env,
        context,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "vex_file": ("openvex.json", vex_bytes, "application/json"),
        },
    )
    run_id = import_payload["id"]
    summary = run_summary(workbench_api_env, context, run_id)
    findings = project_findings(workbench_api_env, context)
    detail = finding_by_cve(workbench_api_env, context, "CVE-2021-44228")

    assert_same_run_contract(
        import_payload=import_payload,
        summary=summary,
        findings=findings,
        context=context,
    )
    assert import_payload["vex"]["matched_occurrences"] == 1
    assert import_payload["suppressed_by_vex"] == 1
    assert detail["status"] == "fixed"
    assert detail["suppressed_by_vex"] is True
    assert detail["explanation_json"]["provenance"]["vex_statuses"] == {"fixed": 1}
    occurrence = detail["occurrences"][0]
    assert occurrence["analysis_run_id"] == run_id
    assert occurrence["vex_status"] == "fixed"
    assert occurrence["vex_source_format"] == "openvex-json"
    assert occurrence["vex_source_path"] == "openvex.json"

    json_report = create_report(workbench_api_env, context, run_id, "json")
    analysis_json = downloaded_json(workbench_api_env, context, json_report)
    finding = analysis_json["findings"][0]
    assert finding["cve_id"] == "CVE-2021-44228"
    assert finding["status"] == "fixed"
    assert finding["suppressed_by_vex"] is True
    assert finding["explanation"]["provenance"]["vex_statuses"] == {"fixed": 1}
    assert finding["occurrences"][0]["analysis_run_id"] == run_id
    assert finding["occurrences"][0]["evidence"]["vex_status"] == "fixed"
    assert_no_workflow_path_leak(analysis_json, context)

    markdown_report = create_report(workbench_api_env, context, run_id, "markdown")
    markdown = downloaded_text(workbench_api_env, context, markdown_report)
    assert "CVE-2021-44228" in markdown
    assert "fixed" in markdown.lower()
    assert_no_workflow_path_leak(markdown, context)


def test_attack_import_flows_to_navigator_and_evidence_bundle(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    context = configure_workflow_context(workbench_api_env, tmp_path)
    trivy_bytes = TRIVY_REPORT.read_bytes()
    import_payload = post_import(
        workbench_api_env,
        context,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", trivy_bytes, "application/json")},
    )
    run_id = import_payload["id"]
    summary = run_summary(workbench_api_env, context, run_id)
    findings = project_findings(workbench_api_env, context)
    mapped = finding_by_cve(workbench_api_env, context, "CVE-2023-34362")
    unmapped = finding_by_cve(workbench_api_env, context, "CVE-2024-3094")

    assert_same_run_contract(
        import_payload=import_payload,
        summary=summary,
        findings=findings,
        context=context,
    )
    assert summary["input_type"] == "trivy-json"
    assert import_payload["attack_mapped_cves"] == 1
    assert summary["input_upload"]["sha256"] == sha256_bytes(trivy_bytes)
    assert mapped["attack_context"]["mapped"] is True
    assert mapped["attack_context"]["source"] == "local-curated"
    assert mapped["attack_context"]["mappings"][0]["technique_id"] == "T1190"
    assert "payload" not in mapped["attack_context"]["mappings"][0]["rationale"].lower()
    assert unmapped["attack_context"]["mapped"] is False
    assert unmapped["attack_context"]["mappings"] == []

    layer_report = create_report(
        workbench_api_env,
        context,
        run_id,
        "attack-navigator",
        payload_overrides={"attack_filter": "all"},
    )
    assert layer_report["filename"] == "attack-navigator-layer.json"
    layer = downloaded_json(workbench_api_env, context, layer_report)
    t1190 = next(item for item in layer["techniques"] if item["techniqueID"] == "T1190")
    assert "CVE-2023-34362" in t1190["comment"]
    assert "payload" not in t1190["comment"].lower()
    assert_no_workflow_path_leak(layer, context)

    bundle_report = create_report(workbench_api_env, context, run_id, "zip")
    assert bundle_report["filename"] == "evidence-bundle.zip"
    members = downloaded_zip_members(workbench_api_env, context, bundle_report)
    assert {
        "analysis.json",
        "attack-navigator-layer.json",
        "findings.csv",
        "manifest.json",
        "technical.md",
    } <= set(members)

    manifest = json.loads(members["manifest.json"])
    analysis = json.loads(members["analysis.json"])
    bundle_layer = json.loads(members["attack-navigator-layer.json"])
    jsonschema.validate(manifest, _load_schema("evidence-bundle-manifest.schema.json"))
    assert manifest["bundle_kind"] == "evidence-bundle"
    assert manifest["source_analysis_path"] == "analysis.json"
    assert manifest["artifact_hashes"]["analysis.json"]
    assert manifest["artifact_hashes"]["attack-navigator-layer.json"]
    assert any(
        item["sha256"] == sha256_bytes(trivy_bytes) for item in manifest["source_input_hashes"]
    )
    assert manifest["attack_navigator_layer"]["bundle_path"] == "attack-navigator-layer.json"
    assert analysis["analysis_run"]["id"] == run_id
    assert analysis["project"]["id"] == context.project_id
    assert {item["techniqueID"] for item in bundle_layer["techniques"]} == {"T1190"}

    verified = verify_report(workbench_api_env, context, bundle_report["id"])
    jsonschema.validate(verified, _load_schema("evidence-bundle-verification-report.schema.json"))
    assert verified["summary"]["ok"] is True
    assert verified["summary"]["missing_files"] == 0
    assert verified["summary"]["modified_files"] == 0
    assert_no_workflow_path_leak(manifest, context)
    assert_no_workflow_path_leak(analysis, context)


def test_failed_import_persists_diagnostics_and_rejects_report_creation(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    context = configure_workflow_context(workbench_api_env, tmp_path)
    content = b"CVE-2024-3094\nnot-a-cve\n"
    failure = post_import(
        workbench_api_env,
        context,
        data={"input_type": "cve-list"},
        files={"file": ("bad.txt", content, "text/plain")},
        expected_status=422,
    )["detail"]
    run_id = failure["analysis_run_id"]

    summary = run_summary(workbench_api_env, context, run_id)
    findings = project_findings(workbench_api_env, context)
    assert failure["message"] == "Import parsing failed."
    assert failure["parse_errors"][0]["line"] == 2
    assert failure["parse_errors"][0]["value"] == "not-a-cve"
    assert summary["id"] == run_id
    assert summary["project_id"] == context.project_id
    assert summary["status"] == "failed"
    assert summary["created_findings"] == 0
    assert summary["updated_findings"] == 0
    assert summary["finding_count"] == 0
    assert summary["input_upload"]["sha256"] == sha256_bytes(content)
    assert summary["parse_errors"] == failure["parse_errors"]
    assert findings["count"] == 0
    assert_no_workflow_path_leak(failure, context)
    assert_no_workflow_path_leak(summary, context)

    rejected = report_response(
        workbench_api_env,
        context,
        run_id,
        report_format="markdown",
        expected_status=422,
    )
    assert "completed" in rejected.json()["detail"]
    assert list_reports(workbench_api_env, context, run_id)["count"] == 0
    assert not list(context.report_dir.rglob("*"))
