from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app.decision_core.identity import FINDING_SCOPE_KEY_PREFIX
from app.decision_core.ledger import canonical_payload_sha256
from app.services.import_execution_persistence_queries import _legacy_finding_identity_lookup

_ASSET_ID = "asset-web-canonical"
_OCCURRENCE_CSV = "\n".join(
    [
        "cve_id,target_ref,component_name,component_version,purl,raw_severity",
        "CVE-2024-3094,web-tier,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
        "",
    ]
).encode()
_NORMALIZED_SCOPE_OCCURRENCE_CSV = "\n".join(
    [
        "cve_id,target_ref,component_name,component_version,purl,raw_severity",
        ("CVE-2024-3094,Caf\u00e9-tier,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL"),
        "",
    ]
).encode()


def test_raw_sidecar_raw_reimport_hydrates_stable_context_before_analysis_and_vex(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    sidecar = _asset_context_csv(
        asset_id=_ASSET_ID,
        owner="team-platform",
        service="payments",
        criticality="critical",
        exposure="public",
        environment="prod",
    )

    _run_import(workbench_api_env, project["id"], headers=headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=sidecar,
    )
    sidecar_finding = _only_finding(workbench_api_env, project["id"], headers=headers)

    _run_import(workbench_api_env, project["id"], headers=headers)
    hydrated_finding = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert hydrated_finding["id"] == sidecar_finding["id"]
    assert hydrated_finding["risk_score"] == sidecar_finding["risk_score"]
    assert (
        hydrated_finding["evidence"]["priority_evidence"]["operational_score_reasons"]
        == sidecar_finding["evidence"]["priority_evidence"]["operational_score_reasons"]
    )
    assert (
        hydrated_finding["evidence"]["occurrence_scope"]
        == sidecar_finding["evidence"]["occurrence_scope"]
    )
    import_evidence = hydrated_finding["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence["asset_context_source"] == "persisted-project"
    assert set(import_evidence["asset_context_hydrated_fields"]) == {
        "asset_id",
        "owner",
        "business_service",
        "environment",
        "exposure",
        "criticality",
    }
    assert import_evidence["asset_context_persisted_finding_id"] == hydrated_finding["id"]

    vex = json.dumps(
        {
            "statements": [
                {
                    "justification": "vulnerable_code_not_present",
                    "products": [
                        {
                            "subcomponents": [
                                {
                                    "kind": "generic",
                                    "name": _ASSET_ID,
                                }
                            ]
                        }
                    ],
                    "status": "not_affected",
                    "vulnerability": {"name": "CVE-2024-3094"},
                }
            ]
        },
        sort_keys=True,
    ).encode()
    vex_run = _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        vex=vex,
    )
    assert vex_run["vex"]["matched_occurrences"] == 1
    vex_finding = _only_finding(workbench_api_env, project["id"], headers=headers)
    assert vex_finding["suppressed_by_vex"] is True
    assert vex_finding["evidence"]["occurrence_scope"]["asset_id"] == _ASSET_ID
    assert vex_finding["evidence"]["occurrence_scope"]["vex_match_type"] == "target"


def test_new_scope_with_explicit_asset_id_inherits_safe_relational_context_before_analysis(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="shared-asset",
            owner="team-platform",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    initial = _only_finding(workbench_api_env, project["id"], headers=headers)

    new_scope_csv = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity",
            ("CVE-2024-4577,web-tier,php,8.1.0,pkg:deb/debian/php@8.1.0,CRITICAL"),
            "",
        ]
    ).encode()
    identity_only_sidecar = "\n".join(
        [
            "target_kind,target_ref,asset_id",
            "generic,web-tier,shared-asset",
            "",
        ]
    ).encode()
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=new_scope_csv,
        asset_context=identity_only_sidecar,
    )

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    findings = {item["cve_id"]: item for item in response.json()["data"]}
    assert set(findings) == {"CVE-2024-3094", "CVE-2024-4577"}
    new_scope = findings["CVE-2024-4577"]
    assert new_scope["asset_id"] == initial["asset_id"]
    assert new_scope["asset_key"] == "shared-asset"
    assert new_scope["owner"] == "team-platform"
    assert new_scope["business_service"] == "payments"
    assert new_scope["asset_environment"] == "production"
    assert new_scope["asset_criticality"] == "critical"
    assert new_scope["exposure"] == "internet-facing"
    occurrence_scope = new_scope["evidence"]["occurrence_scope"]
    assert occurrence_scope["asset_id"] == "shared-asset"
    assert occurrence_scope["asset_owner"] == "team-platform"
    assert occurrence_scope["asset_business_service"] == "payments"
    assert occurrence_scope["asset_environment"] == "production"
    assert occurrence_scope["asset_criticality"] == "critical"
    assert occurrence_scope["asset_exposure"] == "internet-facing"
    reasons = new_scope["evidence"]["priority_evidence"]["operational_score_reasons"]
    assert "internet-facing asset context: +8" in reasons
    assert "production asset context: +4" in reasons
    assert "critical asset criticality: +7" in reasons
    import_evidence = new_scope["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence["asset_context_source"] == "persisted-project"
    assert set(import_evidence["asset_context_hydrated_fields"]) == {
        "owner",
        "business_service",
        "environment",
        "exposure",
        "criticality",
    }
    assert import_evidence["asset_context_persisted_asset_row_id"] == initial["asset_id"]


def test_new_scope_does_not_hydrate_from_manually_renamed_conflicting_asset(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="original-explicit-id",
            owner="team-original",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    rename = workbench_api_env.client.patch(
        f"/api/v1/assets/{original['asset_id']}",
        headers=headers,
        json={"asset_key": "claimed-new-id"},
    )
    assert rename.status_code == 200, rename.text

    new_scope_csv = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity",
            ("CVE-2024-4577,web-tier,php,8.1.0,pkg:deb/debian/php@8.1.0,CRITICAL"),
            "",
        ]
    ).encode()
    identity_only_sidecar = "\n".join(
        [
            "target_kind,target_ref,asset_id",
            "generic,web-tier,claimed-new-id",
            "",
        ]
    ).encode()
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=new_scope_csv,
        asset_context=identity_only_sidecar,
    )

    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    findings = {item["cve_id"]: item for item in response.json()["data"]}
    new_scope = findings["CVE-2024-4577"]
    assert new_scope["asset_id"] != original["asset_id"]
    assert new_scope["asset_key"] != "claimed-new-id"
    assert new_scope["owner"] is None
    assert new_scope["business_service"] is None
    assert new_scope["asset_environment"] == "unknown"
    assert new_scope["asset_criticality"] == "unknown"
    assert new_scope["exposure"] == "unknown"
    occurrence_scope = new_scope["evidence"]["occurrence_scope"]
    assert occurrence_scope["asset_id"] == "claimed-new-id"
    assert occurrence_scope["asset_owner"] is None
    assert occurrence_scope["asset_business_service"] is None
    assert occurrence_scope["asset_environment"] is None
    assert occurrence_scope["asset_criticality"] is None
    assert occurrence_scope["asset_exposure"] is None
    import_evidence = new_scope["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence.get("asset_context_source") != "persisted-project"


def test_partial_import_marks_untouched_shared_asset_finding_stale_until_recalculated(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    initial_occurrences = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,purl,raw_severity",
            "CVE-2024-3094,web-tier,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            ("CVE-2024-4577,web-tier,php,8.1.0,pkg:deb/debian/php@8.1.0,CRITICAL"),
            "",
        ]
    ).encode()
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=initial_occurrences,
        asset_context=_asset_context_csv(
            asset_id="shared-asset",
            owner="team-a",
            service="payments",
            criticality="low",
            exposure="internal",
            environment="dev",
        ),
    )
    initial_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert initial_response.status_code == 200, initial_response.text
    initial_findings = {item["cve_id"]: item for item in initial_response.json()["data"]}
    untouched_initial = initial_findings["CVE-2024-4577"]

    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="shared-asset",
            owner="team-b",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    current_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert current_response.status_code == 200, current_response.text
    current_findings = {item["cve_id"]: item for item in current_response.json()["data"]}
    touched = current_findings["CVE-2024-3094"]
    untouched = current_findings["CVE-2024-4577"]

    assert touched["asset_criticality"] == "critical"
    assert touched["evidence"]["occurrence_scope"]["asset_criticality"] == "critical"
    assert not _has_asset_rescore_flag(touched)
    assert untouched["asset_id"] == touched["asset_id"]
    assert untouched["asset_criticality"] == "critical"
    assert untouched["evidence"]["occurrence_scope"]["asset_criticality"] == "low"
    assert untouched["risk_score"] == untouched_initial["risk_score"]
    assert _has_asset_rescore_flag(untouched)

    assets_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert assets_response.status_code == 200, assets_response.text
    assets = assets_response.json()["data"]
    assert len(assets) == 1
    assert assets[0]["id"] == touched["asset_id"]
    assert assets[0]["rescore_needed"] is True

    recalculate = workbench_api_env.client.post(
        f"/api/v1/assets/{touched['asset_id']}/recalculate",
        headers=headers,
    )
    assert recalculate.status_code == 200, recalculate.text
    refreshed_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert refreshed_response.status_code == 200, refreshed_response.text
    refreshed = {item["cve_id"]: item for item in refreshed_response.json()["data"]}[
        "CVE-2024-4577"
    ]
    assert refreshed["evidence"]["occurrence_scope"]["asset_criticality"] == "critical"
    assert refreshed["risk_score"] > untouched["risk_score"]
    assert not _has_asset_rescore_flag(refreshed)


def test_raw_reimport_normalizes_legacy_projected_asset_id_to_nfc(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    composed_asset_id = "Caf\u00e9-asset"
    legacy_projected_asset_id = "  Cafe\u0301-asset  "

    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id=composed_asset_id,
            owner="team-unicode",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    with Session(workbench_api_env.engine) as session:
        projection = session.get(
            workbench_api_env.app_models.FindingCurrentProjection,
            uuid.UUID(original["id"]),
        )
        assert projection is not None
        assert projection.source_finding_evidence_id is not None
        source = session.get(
            workbench_api_env.app_models.FindingDecisionEvidence,
            projection.source_finding_evidence_id,
        )
        assert source is not None
        payload = json.loads(json.dumps(source.payload_json))
        occurrence_scope = dict(payload["occurrence_scope"])
        occurrence_scope.pop("asset_id", None)
        payload["occurrence_scope"] = occurrence_scope
        occurrences = [dict(item) for item in payload["occurrences"]]
        for occurrence in occurrences:
            occurrence.pop("asset_id", None)
            import_evidence = dict(occurrence["import_evidence"])
            import_evidence["asset_id"] = legacy_projected_asset_id
            occurrence["import_evidence"] = import_evidence
        payload["occurrences"] = occurrences
        payload_hash = canonical_payload_sha256(payload)
        source.payload_json = payload
        projection.source_payload_sha256 = payload_hash
        projection.projection_payload_sha256 = payload_hash
        session.add(source)
        session.add(projection)
        session.commit()

    vex = json.dumps(
        {
            "statements": [
                {
                    "justification": "vulnerable_code_not_present",
                    "products": [
                        {
                            "subcomponents": [
                                {
                                    "kind": "generic",
                                    "name": composed_asset_id,
                                }
                            ]
                        }
                    ],
                    "status": "not_affected",
                    "vulnerability": {"name": "CVE-2024-3094"},
                }
            ]
        },
        sort_keys=True,
    ).encode()
    reimport = _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        vex=vex,
    )
    current = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert reimport["vex"]["matched_occurrences"] == 1
    assert current["id"] == original["id"]
    assert current["asset_id"] == original["asset_id"]
    assert current["asset_key"] == composed_asset_id
    assert current["evidence"]["occurrence_scope"]["asset_id"] == composed_asset_id
    assert current["suppressed_by_vex"] is True
    import_evidence = current["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence["asset_context_source"] == "persisted-project"
    assert "asset_id" in import_evidence["asset_context_hydrated_fields"]


def test_current_sidecar_asset_remap_wins_over_persisted_projection(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="asset-old",
            owner="team-old",
            service="legacy",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="asset-new",
            owner="team-new",
            service="next-generation",
            criticality="low",
            exposure="internal",
            environment="dev",
        ),
    )
    remapped = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert remapped["id"] == original["id"]
    assert remapped["asset_key"] == "asset-new"
    assert remapped["owner"] == "team-new"
    assert remapped["business_service"] == "next-generation"
    assert remapped["asset_environment"] == "development"
    assert remapped["asset_criticality"] == "low"
    assert remapped["exposure"] == "internal"
    assert remapped["risk_score"] < original["risk_score"]
    assert remapped["evidence"]["occurrence_scope"]["asset_id"] == "asset-new"


def test_partial_asset_remap_does_not_inherit_context_from_previous_asset(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="asset-old",
            owner="team-old",
            service="legacy",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="asset-new",
            owner="",
            service="",
            criticality="",
            exposure="",
            environment="",
        ),
    )
    remapped = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert remapped["asset_key"] == "asset-new"
    assert remapped["owner"] is None
    assert remapped["business_service"] is None
    assert remapped["asset_environment"] == "unknown"
    assert remapped["asset_criticality"] == "unknown"
    assert remapped["exposure"] == "unknown"
    occurrence = remapped["evidence"]["occurrences"][0]
    assert occurrence["asset_id"] == "asset-new"
    assert occurrence["import_evidence"].get("asset_context_source") != "persisted-project"


def test_raw_reimport_never_promotes_readable_implicit_asset_key_to_asset_id(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    _run_import(workbench_api_env, project["id"], headers=headers)
    _run_import(workbench_api_env, project["id"], headers=headers)
    finding = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert finding["asset_key"] == "web-tier"
    assert finding["evidence"]["occurrence_scope"]["asset_id"] is None
    occurrence = finding["evidence"]["occurrences"][0]
    assert occurrence["asset_id"] is None
    assert occurrence["import_evidence"].get("asset_id") is None
    assert occurrence["import_evidence"]["asset_context_source"] == "persisted-project"
    assert "asset_id" not in occurrence["import_evidence"]["asset_context_hydrated_fields"]
    detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding['id']}",
        headers=headers,
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["occurrences"][0]["asset_id"] is None


def test_raw_reimport_preserves_manually_renamed_link_instead_of_rebinding(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id="asset-old",
            owner="team-original",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    original_asset_id = original["asset_id"]

    rename = workbench_api_env.client.patch(
        f"/api/v1/assets/{original_asset_id}",
        headers=headers,
        json={"asset_key": "manually-renamed"},
    )
    assert rename.status_code == 200, rename.text
    replacement = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": "asset-old",
            "name": "Unrelated replacement",
            "environment": "unknown",
            "exposure": "unknown",
            "criticality": "unknown",
        },
    )
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["id"] != original_asset_id

    _run_import(workbench_api_env, project["id"], headers=headers)
    reimported = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert reimported["id"] == original["id"]
    assert reimported["asset_id"] == original_asset_id
    assert reimported["asset_key"] == "manually-renamed"
    assert reimported["owner"] == "team-original"


def test_legacy_finding_context_is_hydrated_before_vex_and_converges_to_v2(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id=_ASSET_ID,
            owner="team-platform",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    legacy_source_id, legacy_payload = _rewrite_current_finding_as_legacy(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:legacy-context-before-vex",
    )

    vex_run = _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        vex=_not_affected_vex(_ASSET_ID),
    )
    current = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert vex_run["vex"]["matched_occurrences"] == 1
    assert current["id"] == original["id"]
    assert current["owner"] == "team-platform"
    assert current["business_service"] == "payments"
    assert current["suppressed_by_vex"] is True
    assert current["evidence"]["dedup_key"].startswith(FINDING_SCOPE_KEY_PREFIX)
    assert current["evidence"]["occurrence_scope"]["asset_id"] == _ASSET_ID
    import_evidence = current["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence["asset_context_source"] == "persisted-project"
    assert import_evidence["asset_context_persisted_finding_id"] == original["id"]

    with Session(workbench_api_env.engine) as session:
        finding = session.get(workbench_api_env.app_models.Finding, uuid.UUID(original["id"]))
        legacy_source = session.get(
            workbench_api_env.app_models.FindingDecisionEvidence,
            legacy_source_id,
        )
        assert finding is not None
        assert finding.dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)
        assert legacy_source is not None
        assert legacy_source.dedup_key == "vpw019:legacy-context-before-vex"
        assert legacy_source.payload_json == legacy_payload


def test_legacy_scope_reimport_normalizes_nfc_and_converges_to_v2(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=_NORMALIZED_SCOPE_OCCURRENCE_CSV,
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    _rewrite_current_finding_as_legacy(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:unicode-scope",
        legacy_target_kind="  GENERIC  ",
        legacy_target_ref="Cafe\u0301-tier",
    )

    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=_NORMALIZED_SCOPE_OCCURRENCE_CSV,
    )
    current = _only_finding(workbench_api_env, project["id"], headers=headers)

    assert current["id"] == original["id"]
    assert current["evidence"]["dedup_key"].startswith(FINDING_SCOPE_KEY_PREFIX)
    import_evidence = current["evidence"]["occurrences"][0]["import_evidence"]
    assert import_evidence["asset_context_source"] == "persisted-project"


def test_legacy_scope_lookup_normalizes_target_kind_whitespace(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        occurrence_csv=_NORMALIZED_SCOPE_OCCURRENCE_CSV,
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    _rewrite_current_finding_as_legacy(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:target-kind-whitespace",
        legacy_target_kind="  Kubernetes   Pod  ",
        legacy_target_ref="Cafe\u0301-tier",
    )

    with Session(workbench_api_env.engine) as session:
        finding = session.get(
            workbench_api_env.app_models.Finding,
            uuid.UUID(original["id"]),
        )
        assert finding is not None
        lookup = _legacy_finding_identity_lookup(
            session=session,
            project_id=uuid.UUID(project["id"]),
            cves=[finding.cve_id],
        )
        identity = (
            finding.vulnerability_id,
            finding.component_id,
            "kubernetes pod",
            "Caf\u00e9-tier",
        )

        assert lookup.matches[identity].id == finding.id


def test_equivalent_legacy_aliases_select_oldest_and_preserve_losing_history(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    composed_asset_id = "Caf\u00e9-asset"
    decomposed_asset_id = "Cafe\u0301-asset"
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id=composed_asset_id,
            owner="team-platform",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    _rewrite_current_finding_as_legacy(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:normalized-asset-alias-a",
    )
    with Session(workbench_api_env.engine) as session:
        original_occurrence = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.finding_id
                == uuid.UUID(original["id"])
            )
        ).one()
        original_evidence = dict(original_occurrence.evidence_json)
        original_evidence["asset_id"] = decomposed_asset_id
        original_occurrence.evidence_json = original_evidence
        session.add(original_occurrence)
        session.commit()
    duplicate_id = _clone_legacy_finding(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:normalized-asset-alias-b",
    )
    with Session(workbench_api_env.engine) as session:
        duplicate_occurrence = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.finding_id == duplicate_id
            )
        ).one()
        duplicate_evidence = dict(duplicate_occurrence.evidence_json)
        duplicate_evidence["asset_id"] = composed_asset_id
        duplicate_occurrence.evidence_json = duplicate_evidence
        session.add(duplicate_occurrence)
        session.commit()

    first_reimport = _run_import(workbench_api_env, project["id"], headers=headers)
    second_reimport = _run_import(workbench_api_env, project["id"], headers=headers)

    assert first_reimport["created_findings"] == 0
    assert first_reimport["updated_findings"] == 1
    assert second_reimport["created_findings"] == 0
    assert second_reimport["updated_findings"] == 1
    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == uuid.UUID(project["id"])
                )
            ).all()
        )
    findings_by_id = {finding.id: finding for finding in findings}
    assert len(findings) == 2
    assert findings_by_id[uuid.UUID(original["id"])].dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)
    assert findings_by_id[duplicate_id].dedup_key == "vpw019:normalized-asset-alias-b"


def test_ambiguous_legacy_scope_fails_once_without_partial_decision_writes(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(
        workbench_api_env,
        project["id"],
        headers=headers,
        asset_context=_asset_context_csv(
            asset_id=_ASSET_ID,
            owner="team-platform",
            service="payments",
            criticality="critical",
            exposure="public",
            environment="prod",
        ),
    )
    original = _only_finding(workbench_api_env, project["id"], headers=headers)
    _rewrite_current_finding_as_legacy(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:ambiguous-a",
    )
    duplicate_id = _clone_legacy_finding(
        workbench_api_env,
        finding_id=original["id"],
        legacy_key="vpw019:ambiguous-b",
    )
    with Session(workbench_api_env.engine) as session:
        duplicate = session.get(workbench_api_env.app_models.Finding, duplicate_id)
        assert duplicate is not None
        duplicate.asset_id = None
        session.add(duplicate)
        session.commit()

    failed = _run_failed_raw_import(
        workbench_api_env,
        project["id"],
        headers=headers,
    )

    _assert_terminal_persisted_context_failure(workbench_api_env, failed)
    assert failed["diagnostics"]["error_type"] == "PersistedAssetContextInvariantError"
    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == uuid.UUID(project["id"])
                )
            ).all()
        )
        assert len(findings) == 2
        assert all(
            not finding.dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX) for finding in findings
        )


def test_missing_projection_source_fails_once_and_finishes_analysis_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(workbench_api_env, project["id"], headers=headers)
    finding = _only_finding(workbench_api_env, project["id"], headers=headers)
    with Session(workbench_api_env.engine) as session:
        projection = session.get(
            workbench_api_env.app_models.FindingCurrentProjection,
            uuid.UUID(finding["id"]),
        )
        assert projection is not None
        projection.source_finding_evidence_id = None
        session.add(projection)
        session.commit()

    failed = _run_failed_raw_import(
        workbench_api_env,
        project["id"],
        headers=headers,
    )

    _assert_terminal_persisted_context_failure(workbench_api_env, failed)
    assert failed["diagnostics"]["error_type"] == "DecisionLedgerInvariantError"


def test_invalid_projection_source_contract_fails_once_without_retry(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    _run_import(workbench_api_env, project["id"], headers=headers)
    finding = _only_finding(workbench_api_env, project["id"], headers=headers)
    with Session(workbench_api_env.engine) as session:
        projection = session.get(
            workbench_api_env.app_models.FindingCurrentProjection,
            uuid.UUID(finding["id"]),
        )
        assert projection is not None
        assert projection.source_finding_evidence_id is not None
        source = session.get(
            workbench_api_env.app_models.FindingDecisionEvidence,
            projection.source_finding_evidence_id,
        )
        assert source is not None
        invalid_payload = dict(source.payload_json)
        invalid_payload.pop("cve_id")
        invalid_hash = canonical_payload_sha256(invalid_payload)
        source.payload_json = invalid_payload
        projection.source_payload_sha256 = invalid_hash
        projection.projection_payload_sha256 = invalid_hash
        session.add(source)
        session.add(projection)
        session.commit()

    failed = _run_failed_raw_import(
        workbench_api_env,
        project["id"],
        headers=headers,
    )

    _assert_terminal_persisted_context_failure(workbench_api_env, failed)
    assert failed["diagnostics"]["error_type"] == "PersistedAssetContextInvariantError"


def _rewrite_current_finding_as_legacy(
    workbench_api_env: WorkbenchApiEnv,
    *,
    finding_id: str,
    legacy_key: str,
    legacy_target_kind: str | None = None,
    legacy_target_ref: str | None = None,
) -> tuple[uuid.UUID, dict[str, Any]]:
    persisted_finding_id = uuid.UUID(finding_id)
    with Session(workbench_api_env.engine) as session:
        finding = session.get(workbench_api_env.app_models.Finding, persisted_finding_id)
        projection = session.get(
            workbench_api_env.app_models.FindingCurrentProjection,
            persisted_finding_id,
        )
        assert finding is not None
        assert projection is not None
        assert projection.source_finding_evidence_id is not None
        assert projection.lifecycle_overlay_json == {}
        source = session.get(
            workbench_api_env.app_models.FindingDecisionEvidence,
            projection.source_finding_evidence_id,
        )
        assert source is not None

        payload = dict(source.payload_json)
        payload["dedup_key"] = legacy_key
        legacy_occurrences: list[dict[str, Any]] = []
        for item in payload.get("occurrences", []):
            occurrence_payload = dict(item)
            dedup = dict(occurrence_payload.get("dedup", {}))
            dedup["key"] = legacy_key
            occurrence_payload["dedup"] = dedup
            legacy_occurrences.append(occurrence_payload)
        payload["occurrences"] = legacy_occurrences
        payload_hash = canonical_payload_sha256(payload)

        finding.dedup_key = legacy_key
        source.dedup_key = legacy_key
        source.payload_json = payload
        projection.dedup_key = legacy_key
        projection.source_payload_sha256 = payload_hash
        projection.projection_payload_sha256 = payload_hash
        session.add(finding)
        session.add(source)
        session.add(projection)
        for occurrence in session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.finding_id == persisted_finding_id
            )
        ).all():
            occurrence_evidence = dict(occurrence.evidence_json)
            occurrence_evidence["dedup_key"] = legacy_key
            if legacy_target_kind is not None:
                occurrence_evidence["target_kind"] = legacy_target_kind
            if legacy_target_ref is not None:
                occurrence_evidence["target_ref"] = legacy_target_ref
            occurrence.evidence_json = occurrence_evidence
            session.add(occurrence)
        session.commit()
        return source.id, json.loads(json.dumps(payload))


def _clone_legacy_finding(
    workbench_api_env: WorkbenchApiEnv,
    *,
    finding_id: str,
    legacy_key: str,
) -> uuid.UUID:
    persisted_finding_id = uuid.UUID(finding_id)
    with Session(workbench_api_env.engine) as session:
        original = session.get(workbench_api_env.app_models.Finding, persisted_finding_id)
        assert original is not None
        original_occurrence = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.finding_id == persisted_finding_id
            )
        ).first()
        assert original_occurrence is not None
        duplicate = workbench_api_env.app_models.Finding(
            project_id=original.project_id,
            vulnerability_id=original.vulnerability_id,
            component_id=original.component_id,
            asset_id=original.asset_id,
            cve_id=original.cve_id,
            dedup_key=legacy_key,
            status=original.status,
        )
        session.add(duplicate)
        session.flush()
        session.add(
            workbench_api_env.app_models.FindingOccurrence(
                finding_id=duplicate.id,
                analysis_run_id=original_occurrence.analysis_run_id,
                source=original_occurrence.source,
                scanner=original_occurrence.scanner,
                raw_reference=original_occurrence.raw_reference,
                fix_version=original_occurrence.fix_version,
                evidence_json=dict(original_occurrence.evidence_json),
            )
        )
        session.commit()
        return duplicate.id


def _run_failed_raw_import(
    workbench_api_env: WorkbenchApiEnv,
    project_id: str,
    *,
    headers: dict[str, str],
) -> dict[str, Any]:
    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", _OCCURRENCE_CSV, "text/csv")},
    )
    assert response.status_code == 200, response.text
    return completed_run_payload(workbench_api_env, response, headers=headers)


def _assert_terminal_persisted_context_failure(
    workbench_api_env: WorkbenchApiEnv,
    failed: dict[str, Any],
) -> None:
    public_message = "Persisted project decision context is inconsistent."
    assert failed["status"] == "failed"
    assert failed["error_message"] == public_message
    assert failed["finished_at"] is not None
    assert failed["diagnostics"]["stage"] == "persisted_asset_context"
    assert failed["diagnostics"]["message"] == public_message
    assert failed["diagnostics"]["asset_context_error"]["message"] == public_message

    run_id = uuid.UUID(failed["id"])
    with Session(workbench_api_env.engine) as session:
        workflow = session.exec(
            select(workbench_api_env.app_models.WorkflowRun).where(
                workbench_api_env.app_models.WorkflowRun.analysis_run_id == run_id
            )
        ).one()
        assert workflow.status == "failed"
        assert workflow.attempt_count == 1
        assert workflow.retry_count == 0
        assert workflow.terminal_code == "persisted_context_invariant"
        assert (
            session.exec(
                select(func.count())
                .select_from(workbench_api_env.app_models.FindingOccurrence)
                .where(workbench_api_env.app_models.FindingOccurrence.analysis_run_id == run_id)
            ).one()
            == 0
        )
        assert (
            session.exec(
                select(func.count())
                .select_from(workbench_api_env.app_models.FindingDecisionEvidence)
                .where(
                    workbench_api_env.app_models.FindingDecisionEvidence.analysis_run_id == run_id
                )
            ).one()
            == 0
        )
        assert (
            session.exec(
                select(func.count())
                .select_from(workbench_api_env.app_models.AnalysisEvidence)
                .where(workbench_api_env.app_models.AnalysisEvidence.analysis_run_id == run_id)
            ).one()
            == 0
        )


def _not_affected_vex(asset_id: str) -> bytes:
    return json.dumps(
        {
            "statements": [
                {
                    "justification": "vulnerable_code_not_present",
                    "products": [
                        {
                            "subcomponents": [
                                {
                                    "kind": "generic",
                                    "name": asset_id,
                                }
                            ]
                        }
                    ],
                    "status": "not_affected",
                    "vulnerability": {"name": "CVE-2024-3094"},
                }
            ]
        },
        sort_keys=True,
    ).encode()


def _run_import(
    workbench_api_env: WorkbenchApiEnv,
    project_id: str,
    *,
    headers: dict[str, str],
    asset_context: bytes | None = None,
    vex: bytes | None = None,
    occurrence_csv: bytes = _OCCURRENCE_CSV,
) -> dict[str, Any]:
    files: dict[str, tuple[str, bytes, str]] = {
        "file": ("occurrences.csv", occurrence_csv, "text/csv"),
    }
    if asset_context is not None:
        files["asset_context_file"] = ("asset-context.csv", asset_context, "text/csv")
    if vex is not None:
        files["vex_file"] = ("openvex.json", vex, "application/json")
    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files=files,
    )
    assert response.status_code == 200, response.text
    run = completed_run_payload(workbench_api_env, response, headers=headers)
    assert run["status"] == "succeeded", run.get("diagnostics")
    return run


def _only_finding(
    workbench_api_env: WorkbenchApiEnv,
    project_id: str,
    *,
    headers: dict[str, str],
) -> dict[str, Any]:
    response = workbench_api_env.client.get(
        f"/api/v1/projects/{project_id}/findings/",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["count"] == 1
    return payload["data"][0]


def _asset_context_csv(
    *,
    asset_id: str,
    owner: str,
    service: str,
    criticality: str,
    exposure: str,
    environment: str,
) -> bytes:
    return "\n".join(
        [
            (
                "target_kind,target_ref,asset_id,owner,business_service,"
                "criticality,exposure,environment"
            ),
            (
                f"generic,web-tier,{asset_id},{owner},{service},"
                f"{criticality},{exposure},{environment}"
            ),
            "",
        ]
    ).encode()


def _has_asset_rescore_flag(finding: dict[str, Any]) -> bool:
    flags = finding["evidence"]["priority_evidence"]["data_quality_flags"]
    return any(flag.get("code") == "asset_context_rescore_needed" for flag in flags)
