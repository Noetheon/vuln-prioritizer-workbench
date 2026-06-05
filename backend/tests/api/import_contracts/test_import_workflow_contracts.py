from __future__ import annotations

import json
import uuid
from pathlib import Path

from sqlmodel import Session
from utils.import_contracts import (
    completed_run_payload as _completed_run_payload,
)
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.import_contracts import (
    decision_state as _decision_state,
)
from utils.import_contracts import (
    finding_state as _finding_state,
)
from utils.import_contracts import (
    public_run_aliases as _public_run_aliases,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)
from utils.workbench_workflow_contracts import workflow_metadata

from app import models as app_models


def test_decision_api_endpoints_expose_explain_summary_and_cvss_comparison(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = b"CVE-2021-44228\nCVE-2024-3094\n"

    import_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("decision-api.txt", content, "text/plain")},
    )
    assert import_response.status_code == 200
    run_payload = _completed_run_payload(workbench_api_env, import_response, headers=headers)
    assert not Path(run_payload["input_upload"]["path"]).is_absolute()

    findings_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings_response.status_code == 200
    findings_payload = findings_response.json()
    assert findings_payload["count"] == 2
    finding_id = findings_payload["data"][0]["id"]

    explain_response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}/explain",
        headers=headers,
    )
    assert explain_response.status_code == 200
    explain_payload = explain_response.json()
    assert explain_payload["finding_id"] == finding_id
    assert explain_payload["project_id"] == project["id"]
    assert explain_payload["priority"] == "critical"
    assert explain_payload["decision_explanation"]["reason_codes"]
    assert explain_payload["decision_guidance"]["decision_statement"]
    assert explain_payload["provider_evidence"]["nvd"]
    assert explain_payload["data_quality_confidence"] in {"high", "medium", "low"}

    project_summary_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/summary",
        headers=headers,
    )
    assert project_summary_response.status_code == 200
    project_summary = project_summary_response.json()
    assert project_summary["project_id"] == project["id"]
    assert project_summary["finding_count"] == 2
    assert project_summary["open_finding_count"] == 2
    assert project_summary["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert project_summary["counts_by_status"] == {
        "open": 2,
        "in_review": 0,
        "remediating": 0,
        "fixed": 0,
        "accepted": 0,
        "suppressed": 0,
    }
    assert project_summary["kev_hits"] >= 1
    assert project_summary["epss_hits"] == 2
    assert project_summary["cvss_known_count"] == 2
    assert project_summary["latest_run_id"] == run_payload["id"]
    assert project_summary["latest_run_status"] == "succeeded"

    comparison_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/compare/cvss-only",
        headers=headers,
        params={"include_comparisons": True},
    )
    assert comparison_response.status_code == 200
    comparison_payload = comparison_response.json()
    assert comparison_payload["project_id"] == project["id"]
    assert comparison_payload["methodology"]["baseline"] == "cvss-only"
    assert comparison_payload["summary"]["total"] == 2
    assert comparison_payload["counts"]["enriched"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert {item["cve_id"] for item in comparison_payload["comparisons"]} == {
        "CVE-2021-44228",
        "CVE-2024-3094",
    }


def test_double_import_deduplicates_findings_and_appends_occurrences(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity,owner,business_service,exposure",
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public"
            ),
            (
                "CVE-2024-4577,web-tier,php-cgi,8.3.7,"
                "pkg:deb/debian/php-cgi@8.3.7,HIGH,team-web,checkout,internal"
            ),
            "",
        ]
    ).encode()

    first = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert first.status_code == 200, first.text
    first_payload = _completed_run_payload(workbench_api_env, first, headers=headers)
    assert first_payload["dedup_summary"]["created_findings"] == 2
    assert first_payload["dedup_summary"]["reused_findings"] == 0
    assert {item["action"] for item in first_payload["dedup_summary"]["decisions"]} == {"created"}

    first_findings, first_occurrence_count = _finding_state(workbench_api_env, project_id)
    first_decisions = _decision_state(first_findings)
    first_seen = {finding.cve_id: finding.first_seen_at for finding in first_findings}
    first_last_seen = {finding.cve_id: finding.last_seen_at for finding in first_findings}
    first_dedup_keys = {finding.cve_id: finding.dedup_key for finding in first_findings}

    second = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert second.status_code == 200, second.text
    second_payload = _completed_run_payload(workbench_api_env, second, headers=headers)
    dedup_summary = second_payload["dedup_summary"]
    assert second_payload["occurrence_count"] == 2
    assert second_payload["finding_count"] == 2
    assert second_payload["created_findings"] == 0
    assert second_payload["updated_findings"] == 2
    assert dedup_summary["created_findings"] == 0
    assert dedup_summary["updated_findings"] == 2
    assert dedup_summary["reused_findings"] == 2
    assert dedup_summary["decision_count"] == 2
    assert {item["action"] for item in dedup_summary["decisions"]} == {"reused"}
    assert all(item["dedup_key"].startswith("vpw019:") for item in dedup_summary["decisions"])
    assert all(
        item["target_ref"] in {"build-host-1", "web-tier"} for item in dedup_summary["decisions"]
    )

    second_findings, second_occurrence_count = _finding_state(workbench_api_env, project_id)
    second_decisions = _decision_state(second_findings)
    assert len(first_findings) == 2
    assert first_occurrence_count == 2
    assert len(second_findings) == 2
    assert second_occurrence_count == 4
    assert second_decisions == first_decisions
    assert {finding.cve_id: finding.first_seen_at for finding in second_findings} == first_seen
    assert {finding.cve_id: finding.dedup_key for finding in second_findings} == first_dedup_keys
    assert all(
        finding.last_seen_at > first_last_seen[finding.cve_id] for finding in second_findings
    )
    findings_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings_response.status_code == 200, findings_response.text
    findings_by_cve = {item["cve_id"]: item for item in findings_response.json()["data"]}
    assert findings_by_cve["CVE-2024-3094"]["component_name"] == "xz"
    assert findings_by_cve["CVE-2024-3094"]["component_version"] == "5.6.0"
    assert findings_by_cve["CVE-2024-3094"]["asset_key"] == "build-host-1"
    assert findings_by_cve["CVE-2024-3094"]["owner"] == "team-platform"
    assert findings_by_cve["CVE-2024-3094"]["business_service"] == "payments"
    assert findings_by_cve["CVE-2024-3094"]["exposure"] == "internet-facing"
    assert findings_by_cve["CVE-2024-4577"]["owner"] == "team-web"
    assert findings_by_cve["CVE-2024-4577"]["business_service"] == "checkout"
    assert findings_by_cve["CVE-2024-4577"]["exposure"] == "internal"

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 2

    summary = workbench_api_env.client.get(
        f"/api/v1/runs/{second_payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = _public_run_aliases(summary.json())
    assert summary_payload["created_findings"] == 0
    assert summary_payload["updated_findings"] == 2
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["dedup_summary"]["reused_findings"] == 2
    assert {item["action"] for item in summary_payload["dedup_summary"]["decisions"]} == {"reused"}
    assert summary_payload["counts_by_priority"] == second_payload["counts_by_priority"]


def test_asset_rescore_marks_and_clears_decision_evidence_v2(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity,owner,business_service,exposure",
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,team-platform,payments,public"
            ),
            "",
        ]
    ).encode()

    import_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("asset-rescore.csv", content, "text/csv")},
    )
    assert import_response.status_code == 200, import_response.text
    _completed_run_payload(workbench_api_env, import_response, headers=headers)

    assets_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert assets_response.status_code == 200, assets_response.text
    asset = next(
        item for item in assets_response.json()["data"] if item["asset_key"] == "build-host-1"
    )
    assert asset["rescore_needed"] is False

    update_response = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset['id']}",
        headers=headers,
        json={"owner": "team-platform-updated"},
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["rescore_needed"] is True

    finding_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert finding_response.status_code == 200, finding_response.text
    finding = next(
        item for item in finding_response.json()["data"] if item["cve_id"] == "CVE-2024-3094"
    )
    detail_response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding['id']}",
        headers=headers,
    )
    assert detail_response.status_code == 200, detail_response.text
    flags = detail_response.json()["evidence"]["priority_evidence"]["data_quality_flags"]
    assert [flag["code"] for flag in flags] == ["asset_context_rescore_needed"]
    assert flags[0]["changed_fields"] == ["owner"]

    recalculate_response = workbench_api_env.client.post(
        f"/api/v1/assets/{asset['id']}/recalculate",
        headers=headers,
    )
    assert recalculate_response.status_code == 200, recalculate_response.text
    recalculated = recalculate_response.json()
    assert recalculated["cleared_rescore_flags"] == 1
    assert recalculated["rescore_needed"] is False

    cleared_detail_response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding['id']}",
        headers=headers,
    )
    assert cleared_detail_response.status_code == 200, cleared_detail_response.text
    cleared_flags = cleared_detail_response.json()["evidence"]["priority_evidence"][
        "data_quality_flags"
    ]
    assert not any(flag["code"] == "asset_context_rescore_needed" for flag in cleared_flags)


def test_generic_import_persists_multi_fix_versions(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,fix_versions",
            'CVE-2024-3094,build-host-1,xz,5.6.0,"5.6.1-r2|5.6.2"',
            "",
        ]
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert payload["occurrence_count"] == 1
    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["fix_version"] == "5.6.1-r2"
    assert occurrence["fix_versions"] == ["5.6.1-r2", "5.6.2"]


def test_same_batch_duplicate_bulk_import_reuses_finding_and_appends_occurrences(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    duplicate_rows = [
        "CVE-2024-3094,duplicate-host,CRITICAL,team-platform,payments,public" for _ in range(1000)
    ]
    content = "\n".join(
        [
            "cve_id,target_ref,raw_severity,owner,business_service,exposure",
            *duplicate_rows,
            "",
        ]
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("duplicate-occurrences.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    dedup_summary = payload["dedup_summary"]
    assert payload["occurrence_count"] == 1000
    assert payload["finding_count"] == 1
    assert payload["created_findings"] == 1
    assert payload["updated_findings"] == 999
    assert dedup_summary["created_findings"] == 1
    assert dedup_summary["updated_findings"] == 999
    assert dedup_summary["reused_findings"] == 999
    assert dedup_summary["decision_count"] == 1000
    assert dedup_summary["omitted_decisions"] == 500
    assert {item["action"] for item in dedup_summary["decisions"]} == {
        "created",
        "reused",
    }
    assert len({item["dedup_key"] for item in dedup_summary["decisions"]}) == 1

    findings, occurrence_count = _finding_state(workbench_api_env, project_id)
    assert len(findings) == 1
    assert occurrence_count == 1000
    assert findings[0].cve_id == "CVE-2024-3094"
    assert findings[0].asset_id is not None
    with Session(workbench_api_env.engine) as session:
        asset = session.get(app_models.Asset, findings[0].asset_id)
    assert asset is not None
    assert asset.asset_key == "duplicate-host"


def test_same_cve_on_different_assets_creates_distinct_findings(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity",
            "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "CVE-2024-3094,build-host-2,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("same-cve-assets.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert payload["finding_count"] == 2
    metadata_payload = workflow_metadata(workbench_api_env, payload["id"], headers=headers)
    assert metadata_payload["summary"]["analysis_semantics"] == {
        "analysis_decision_scope": "cve_baseline_with_occurrence_overlays",
        "persistence_scope": "asset_component_occurrence",
        "occurrence_overlay_fields": [
            "asset_context",
            "component_identity",
            "source_identity",
            "vex_status",
        ],
        "finding_dedup_key_version": "vpw019-v1",
        "cve_count": 1,
        "occurrence_count": 2,
        "finding_count": 2,
        "same_cve_can_create_distinct_asset_findings": True,
    }
    assert payload["dedup_summary"]["created_findings"] == 2
    assert {item["target_ref"] for item in payload["dedup_summary"]["decisions"]} == {
        "build-host-1",
        "build-host-2",
    }

    findings, occurrence_count = _finding_state(workbench_api_env, project_id)
    assert len(findings) == 2
    assert occurrence_count == 2
    assert len({finding.dedup_key for finding in findings}) == 2


def test_same_cve_vex_status_remains_occurrence_scoped(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity",
            (
                "CVE-2021-44228,log4j-fixed,log4j-core,2.14.1,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1,CRITICAL"
            ),
            (
                "CVE-2021-44228,log4j-open,log4j-core,2.13.0,"
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0,CRITICAL"
            ),
            "",
        ]
    ).encode()
    vex = json.dumps(
        {
            "statements": [
                {
                    "action_statement": "Upgrade completed for the scoped component.",
                    "products": [
                        {
                            "identifiers": {
                                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                            },
                        },
                    ],
                    "status": "fixed",
                    "vulnerability": {"name": "CVE-2021-44228"},
                }
            ]
        }
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("same-cve-vex.csv", content, "text/csv"),
            "vex_file": ("same-cve-vex.json", vex, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    _completed_run_payload(workbench_api_env, response, headers=headers)
    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    by_asset = {item["asset_key"]: item for item in findings.json()["data"]}

    assert by_asset["log4j-fixed"]["status"] == "fixed"
    assert by_asset["log4j-fixed"]["suppressed_by_vex"] is True
    assert by_asset["log4j-fixed"]["evidence"]["governance"]["vex_statuses"] == {"fixed": 1}
    assert by_asset["log4j-fixed"]["evidence"]["occurrence_scope"]["target_ref"] == ("log4j-fixed")
    assert by_asset["log4j-open"]["status"] == "open"
    assert by_asset["log4j-open"]["suppressed_by_vex"] is False
    assert by_asset["log4j-open"]["evidence"]["governance"]["vex_statuses"] == {}
    assert by_asset["log4j-open"]["evidence"]["occurrence_scope"]["target_ref"] == ("log4j-open")
