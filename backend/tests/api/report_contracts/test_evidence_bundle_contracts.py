from __future__ import annotations

import hashlib
import json
import uuid
import zipfile
from io import BytesIO
from pathlib import Path

import jsonschema
from sqlmodel import Session
from utils.report_contract_fixtures import (
    VPW068_HTML_SNAPSHOT,
    VPW068_MARKDOWN_SNAPSHOT,
    _vpw068_governance_payload,
    replace,
)
from utils.workbench_contracts import (
    _add_vpw051_bundle_metadata,
    _add_vpw060_attack_contexts,
    _configure_report_dir,
    _create_report_via_worker,
    _load_schema,
    _normalize_html_snapshot,
    _replace_zip_member,
    _repo_root,
    _seed_reportable_run,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app.services import (
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_html_executive_report,
    render_markdown_report,
)


def test_vpw051_evidence_bundle_zip_create_downloads_manifest_integrity(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    input_metadata = _add_vpw051_bundle_metadata(workbench_api_env, run_id, tmp_path)

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "zip"},
    )

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
            "findings.csv",
            "governance/asset-context.json",
            "governance/rollups.json",
            "governance/vex-summary.json",
            "governance/waivers.json",
            "manifest.json",
            "provider-snapshot.json",
            "results.sarif",
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
        jsonschema.validate(analysis, _load_schema("analysis-result.v2.schema.json"))
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
        assert "Governance Exceptions" in executive_report
        assert (
            "Hash recorded in final manifest.json after this HTML is rendered." in executive_report
        )
        assert manifest["artifact_hashes"]["analysis.json"] in executive_report
        assert manifest["artifact_hashes"]["technical.md"] in executive_report
        assert "Expected when Evidence ZIP is generated." not in executive_report
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
    assert "Governance Exceptions" in html
    assert "Accepted Risk and Waiver Review" in html
    assert "Expiring Soon" in html
    assert "service:checkout" in html

    analysis = json.loads(render_analysis_result_json(payload))
    jsonschema.validate(analysis, _load_schema("analysis-result.v2.schema.json"))
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
    jsonschema.validate(analysis, _load_schema("analysis-result.v2.schema.json"))
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

    payload = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "zip"},
    )

    download = workbench_api_env.client.get(payload["download_url"], headers=headers)
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

    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "zip"},
    )

    verified = workbench_api_env.client.post(
        f"/api/v1/reports/{created['id']}/verify",
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
        "total_members": 11,
        "expected_files": 10,
        "verified_files": 10,
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
    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "zip"},
    )
    report_id = uuid.UUID(created["id"])

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report_path = Path(report.path)
    tampered_bundle = _replace_zip_member(
        report_path.read_bytes(),
        "analysis.json",
        b'{"schema":"analysis-result.v2","tampered":true}\n',
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
    assert payload["summary"]["verified_files"] == 9
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
    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "markdown"},
    )

    response = workbench_api_env.client.post(
        f"/api/v1/reports/{created['id']}/verify",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Report is not an evidence bundle"
