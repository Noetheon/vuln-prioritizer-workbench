from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contract_fixtures import (
    ATTACK_MAPPING,
    CYCLONEDX_VEX,
    OPENVEX,
    SAMPLE_CVES,
    TRIVY_REPORT,
)
from utils.import_contracts import (
    assert_no_sensitive_path_leak as _assert_no_sensitive_path_leak,
)
from utils.import_contracts import (
    completed_run_payload as _completed_run_payload,
)
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)
from utils.workbench_workflow_contracts import workflow_metadata

from app import models as app_models


def test_workbench_import_uses_demo_snapshot_without_network_or_keys(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    for env_name in ("NVD_API_KEY", "FIRST_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)
    for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(proxy_name, "http://127.0.0.1:9")
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample_cves.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    summary = payload
    assert payload["status"] == "succeeded"
    assert summary["locked_provider_data"] is True
    assert summary["provider_snapshot_file"] == "demo_provider_snapshot.json"
    assert summary["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary["finding_count"] > 0
    assert summary["kev_hits"] > 0
    with Session(workbench_api_env.engine) as session:
        snapshot = session.get(
            app_models.ProviderSnapshot,
            uuid.UUID(payload["provider_snapshot_id"]),
        )
        assert snapshot is not None
        assert snapshot.content_hash
        assert set(snapshot.source_hashes_json) == {"provider_snapshot"}


def test_attack_import_exposes_workbench_finding_ttp_context(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )

    assert response.status_code == 200, response.text
    run_payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert run_payload["attack_mapped_cves"] == 1
    assert run_payload["attack_source"] == "local-curated"

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"sort": "cve"},
    )
    assert findings.status_code == 200
    finding_items = findings.json()["data"]
    mapped = next(item for item in finding_items if item["cve_id"] == "CVE-2023-34362")
    unmapped = next(item for item in finding_items if item["cve_id"] == "CVE-2024-3094")

    mapped_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{mapped['id']}",
        headers=headers,
    )
    assert mapped_detail.status_code == 200
    attack_context = mapped_detail.json()["attack_context"]
    assert attack_context["mapped"] is True
    assert attack_context["source"] == "local-curated"
    assert attack_context["confidence"] == "low"
    assert attack_context["low_confidence"] is True
    assert attack_context["review_status"] == "needs_review"
    assert attack_context["mappings"][0]["technique_id"] == "T1190"
    assert "reviewed" in attack_context["mappings"][0]["rationale"].lower()
    assert "payload" not in attack_context["mappings"][0]["rationale"].lower()
    assert attack_context["techniques"][0]["technique_id"] == "T1190"
    assert "initial-access" in attack_context["tactics"]
    assert "defensive triage" in attack_context["defensive_note"]

    unmapped_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{unmapped['id']}",
        headers=headers,
    )
    assert unmapped_detail.status_code == 200
    empty_context = unmapped_detail.json()["attack_context"]
    assert empty_context["mapped"] is False
    assert empty_context["mappings"] == []
    assert empty_context["techniques"] == []


def test_attack_summary_api_rolls_up_top_techniques_and_confidence(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    import_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={
            "input_type": "trivy-json",
            "attack_source": "local-curated",
            "attack_mapping_file": ATTACK_MAPPING.name,
        },
        files={"file": ("trivy.json", TRIVY_REPORT.read_bytes(), "application/json")},
    )
    assert import_response.status_code == 200, import_response.text
    _completed_run_payload(workbench_api_env, import_response, headers=headers)

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/attack/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["finding_count"] == 3
    assert payload["mapped_finding_count"] == 1
    assert payload["unmapped_finding_count"] == 2
    assert payload["mapped_coverage_percent"] == 33.3
    assert payload["confidence_distribution"] == {
        "high": 0,
        "medium": 0,
        "low": 1,
        "unknown": 0,
    }
    assert payload["review_status_counts"]["needs_review"] == 1
    assert payload["source_counts"] == {"local-curated": 1}
    assert payload["top_techniques"][0]["technique_id"] == "T1190"
    assert payload["top_techniques"][0]["name"] == "Exploit Public-Facing Application"
    assert payload["top_techniques"][0]["finding_count"] == 1
    assert payload["top_techniques"][0]["confidence_counts"]["low"] == 1
    assert "initial-access" in payload["top_techniques"][0]["tactics"]
    assert payload["top_tactics"][0]["tactic"] == "initial-access"
    assert "defensive triage context only" in payload["defensive_note"]


def test_import_upload_applies_asset_context_sidecar_to_workbench_findings(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
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
    expected_sidecar_sha256 = hashlib.sha256(asset_context_csv).hexdigest()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "asset_context_file": ("asset-context.csv", asset_context_csv, "text/csv"),
        },
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    sidecar_upload = payload["asset_context_upload"]
    assert sidecar_upload["sha256"] == expected_sidecar_sha256
    assert sidecar_upload["stored_filename"] == "asset-context.csv"
    assert not Path(sidecar_upload["path"]).is_absolute()
    assert (upload_dir / sidecar_upload["path"]).read_bytes() == asset_context_csv
    assert payload["asset_context"]["loaded_rows"] == 1
    assert payload["asset_context"]["matched_occurrences"] == 1
    assert payload["dedup_summary"]["decisions"][0]["asset_ref"] == "asset-web-1"

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["asset_key"] == "asset-web-1"
    assert finding["owner"] == "team-platform"
    assert finding["business_service"] == "payments"
    assert finding["asset_environment"] == "production"
    assert finding["asset_criticality"] == "critical"
    assert finding["exposure"] == "internet-facing"
    assert finding["risk_score"] == 100.0

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200
    explanation = detail.json()["explanation_json"]
    assert explanation["operational_score"] == 100
    assert "internet-facing asset context: +8" in explanation["operational_score_reasons"]
    assert "production asset context: +5" in explanation["operational_score_reasons"]
    assert "critical asset criticality: +7" in explanation["operational_score_reasons"]
    assert explanation["highest_asset_criticality"] == "critical"
    assert explanation["provenance"]["asset_ids"] == ["asset-web-1"]
    assert explanation["provenance"]["highest_asset_exposure"] == "internet-facing"
    assert explanation["provenance"]["asset_owners"] == ["team-platform"]
    assert explanation["provenance"]["asset_business_services"] == ["payments"]
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["asset_ref"] == "asset-web-1"
    assert occurrence["target_ref"] == "web-tier"
    assert occurrence["asset_owner"] == "team-platform"
    assert occurrence["asset_business_service"] == "payments"
    assert occurrence["asset_exposure"] == "internet-facing"


def test_generic_import_persists_core_canonical_asset_context_aliases(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            ("cve_id,asset_ref,component,version,purl,severity,criticality,exposure,environment"),
            (
                "CVE-2024-3094,build-host-1,xz,5.6.0,"
                "pkg:apk/alpine/xz@5.6.0-r0,CRITICAL,crit,private,qa"
            ),
            "",
        ]
    ).encode()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("asset-aliases.csv", occurrence_csv, "text/csv")},
    )

    assert response.status_code == 200, response.text
    _completed_run_payload(workbench_api_env, response, headers=headers)
    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["asset_key"] == "build-host-1"
    assert finding["asset_environment"] == "test"
    assert finding["asset_criticality"] == "critical"
    assert finding["exposure"] == "internal"

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    explanation = detail.json()["explanation_json"]
    assert explanation["highest_asset_criticality"] == "critical"
    assert explanation["provenance"]["highest_asset_exposure"] == "internal"
    assert explanation["provenance"]["asset_environments"] == ["test"]
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["asset_exposure"] == "internal"

    with Session(workbench_api_env.engine) as session:
        asset = session.exec(
            select(app_models.Asset).where(app_models.Asset.project_id == project_id)
        ).one()
        assert asset.environment == app_models.AssetEnvironment.TEST
        assert asset.exposure == app_models.AssetExposure.INTERNAL
        assert asset.criticality == app_models.AssetCriticality.CRITICAL


def test_import_upload_applies_openvex_sidecar_to_workbench_findings(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
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
    expected_vex_sha256 = hashlib.sha256(vex_bytes).hexdigest()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "vex_file": ("openvex.json", vex_bytes, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    vex_upload = payload["vex_upload"]
    assert vex_upload["sha256"] == expected_vex_sha256
    assert vex_upload["stored_filename"] == "openvex.json"
    assert not Path(vex_upload["path"]).is_absolute()
    assert (upload_dir / vex_upload["path"]).read_bytes() == vex_bytes
    assert payload["vex"]["statement_count"] == 4
    assert payload["vex"]["matched_occurrences"] == 1
    assert payload["suppressed_by_vex"] == 1
    metadata_payload = workflow_metadata(workbench_api_env, payload["id"], headers=headers)
    assert metadata_payload["summary"]["vex_conflict_count"] == 0

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    finding = findings.json()["data"][0]
    assert finding["status"] == "fixed"
    assert finding["suppressed_by_vex"] is True
    assert finding["explanation_json"]["priority_state"] == "Fixed"
    assert finding["explanation_json"]["provenance"]["vex_statuses"] == {"fixed": 1}
    vex_reason = next(
        reason
        for reason in finding["explanation_json"]["explanation"]["reasons"]
        if reason["code"] == "governance.vex_status"
    )
    assert "fixed: 1" in vex_reason["message"]
    assert "Upgrade completed for the scoped component." in vex_reason["message"]

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding['id']}", headers=headers)
    assert detail.status_code == 200
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["vex_status"] == "fixed"
    assert occurrence["vex_match_type"] == "purl"
    assert occurrence["vex_source_format"] == "openvex-json"
    assert occurrence["vex_source_path"] == "openvex.json"
    assert occurrence["vex_action_statement"] == "Upgrade completed for the scoped component."
    _assert_no_sensitive_path_leak(occurrence, tmp_path, upload_dir)


def test_import_upload_applies_cyclonedx_vex_sidecar_to_workbench_findings(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    occurrence_csv = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            (
                "CVE-2023-34362,moveit-service,moveit-transfer,2023.0.0,"
                "pkg:pypi/moveit-transfer@2023.0.0,HIGH"
            ),
            ("CVE-2024-4577,php-service,php-cgi,8.1.28,pkg:generic/php-cgi@8.1.28,HIGH"),
            "",
        ]
    ).encode()
    vex_bytes = CYCLONEDX_VEX.read_bytes()

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("occurrences.csv", occurrence_csv, "text/csv"),
            "vex_file": ("cyclonedx-vex.json", vex_bytes, "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    vex_upload = payload["vex_upload"]
    assert vex_upload["input_type"] == "vex-json"
    assert vex_upload["stored_filename"] == "cyclonedx-vex.json"
    assert not Path(vex_upload["path"]).is_absolute()
    assert payload["vex"]["statement_count"] == 3
    assert payload["vex"]["matched_occurrences"] == 2
    assert payload["suppressed_by_vex"] == 2

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    by_cve = {finding["cve_id"]: finding for finding in findings.json()["data"]}
    assert by_cve["CVE-2023-34362"]["status"] == "suppressed"
    assert by_cve["CVE-2023-34362"]["suppressed_by_vex"] is True
    assert by_cve["CVE-2023-34362"]["explanation_json"]["provenance"]["vex_statuses"] == {
        "not_affected": 1
    }
    assert by_cve["CVE-2024-4577"]["status"] == "fixed"
    assert by_cve["CVE-2024-4577"]["explanation_json"]["priority_state"] == "Fixed"

    detail = workbench_api_env.client.get(
        f"/api/v1/findings/{by_cve['CVE-2023-34362']['id']}",
        headers=headers,
    )
    assert detail.status_code == 200
    occurrence = detail.json()["occurrences"][0]
    assert occurrence["vex_status"] == "not_affected"
    assert occurrence["vex_match_type"] == "purl"
    assert occurrence["vex_source_format"] == "cyclonedx-vex-json"
    assert occurrence["vex_justification"] == "vulnerable_code_not_present"


def test_import_upload_rejects_invalid_vex_sidecar_with_clear_error(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": (
                "occurrences.csv",
                b"cve_id,asset_ref\nCVE-2024-3094,web-tier\n",
                "text/csv",
            ),
            "vex_file": ("bad-openvex.json", b'{"statements": {}}', "application/json"),
        },
    )

    assert response.status_code == 200, response.text
    run_payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert run_payload["status"] == "failed"
    detail = {**run_payload["diagnostics"], "analysis_run_id": run_payload["id"]}
    assert detail["message"] == "VEX parsing failed."
    assert detail["analysis_run_id"]
    assert detail["vex_error"]["stage"] == "vex_parse"
    assert "OpenVEX JSON `statements`" in detail["vex_error"]["message"]
    assert "uploaded file" in detail["vex_error"]["message"]
    _assert_no_sensitive_path_leak(detail["vex_error"], tmp_path, upload_dir)

    assert run_payload["vex_error"]["stage"] == "vex_parse"
    assert run_payload["workflow_error"]["vex_error"]["stage"] == "vex_parse"
    _assert_no_sensitive_path_leak(run_payload["workflow_error"]["vex_error"], tmp_path, upload_dir)
    _assert_no_sensitive_path_leak(run_payload["vex_error"], tmp_path, upload_dir)
    assert run_payload["created_findings"] == 0
    assert run_payload["updated_findings"] == 0

    metadata_payload = workflow_metadata(
        workbench_api_env,
        detail["analysis_run_id"],
        headers=headers,
    )
    assert metadata_payload["status"] == "failed"
    assert metadata_payload["summary"]["vex_error"]["stage"] == "vex_parse"
    assert metadata_payload["error"]["vex_error"]["stage"] == "vex_parse"
    assert metadata_payload["summary"]["created_findings"] == 0
    assert metadata_payload["summary"]["updated_findings"] == 0
    _assert_no_sensitive_path_leak(metadata_payload, tmp_path, upload_dir)

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_import_upload_rejects_invalid_asset_context_sidecar_with_clear_error(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": (
                "occurrences.csv",
                b"cve_id,asset_ref\nCVE-2024-3094,web-tier\n",
                "text/csv",
            ),
            "asset_context_file": (
                "bad-asset-context.csv",
                b"target_kind,target_ref\nhost,web-tier\n",
                "text/csv",
            ),
        },
    )

    assert response.status_code == 200, response.text
    run_payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert run_payload["status"] == "failed"
    detail = {**run_payload["diagnostics"], "analysis_run_id": run_payload["id"]}
    assert detail["message"] == "Asset context parsing failed."
    assert detail["analysis_run_id"]
    assert detail["asset_context_error"]["stage"] == "asset_context_parse"
    assert "asset_id" in detail["asset_context_error"]["message"]
    _assert_no_sensitive_path_leak(detail["asset_context_error"], tmp_path, upload_dir)

    assert run_payload["asset_context_error"]["stage"] == "asset_context_parse"
    assert run_payload["workflow_error"]["asset_context_error"]["stage"] == "asset_context_parse"
    _assert_no_sensitive_path_leak(
        run_payload["workflow_error"]["asset_context_error"],
        tmp_path,
        upload_dir,
    )
    _assert_no_sensitive_path_leak(
        run_payload["asset_context_error"],
        tmp_path,
        upload_dir,
    )
    assert run_payload["created_findings"] == 0
    assert run_payload["updated_findings"] == 0

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0


def test_import_upload_rejects_unsafe_asset_context_regex_sidecar(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": (
                "occurrences.csv",
                b"cve_id,asset_ref\nCVE-2024-3094,aaaaaaaaaaaaaaaaaaaaX\n",
                "text/csv",
            ),
            "asset_context_file": (
                "bad-asset-context.csv",
                b"target_kind,target_ref,asset_id,match_mode\ngeneric,^(a+)+$,asset-redos,regex\n",
                "text/csv",
            ),
        },
    )

    assert response.status_code == 200, response.text
    run_payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert run_payload["status"] == "failed"
    assert "regex at row 1 is unsafe" in str(run_payload["diagnostics"])
