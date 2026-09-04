from __future__ import annotations

import uuid
from copy import deepcopy
from typing import Any

import pytest
from sqlmodel import Session, select
from utils.import_contracts import completed_run_payload, configure_upload_dir
from utils.workbench_contracts import (
    _create_report_via_worker,
    _seed_analysis_evidence,
    _seed_finding_evidence,
)
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

from app.decision_core.contracts import OccurrenceEvidenceV2
from app.decision_core.ledger import canonical_payload_sha256
from app.repositories.waivers import _projection_scope_sort_key, _recompute_projection_decision


def test_vpw064_workbench_waiver_lifecycle_and_report_visibility(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_update = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "business_service": "checkout",
            "owner": "risk-team",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    )
    assert asset_update.status_code == 200, asset_update.text

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk-owner",
            "reason": "Temporary accepted risk while compensating controls are verified.",
            "expires_at": "2099-12-31",
            "review_at": "2099-12-01",
            "approval_ref": "CAB-064",
        },
    )
    assert created.status_code == 200, created.text
    waiver = created.json()
    assert waiver["status"] == "active"
    assert waiver["matched_findings"] == 1

    accepted_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert accepted_detail.status_code == 200
    accepted = accepted_detail.json()
    assert accepted["status"] == "accepted"
    assert accepted["waived"] is True
    assert "explanation_json" not in accepted

    run_id = _seed_report_run(
        workbench_api_env,
        project_id=uuid.UUID(project["id"]),
        finding_id=finding_id,
    )
    report = _create_report_via_worker(
        workbench_api_env,
        uuid.UUID(run_id),
        headers=headers,
        payload={"format": "csv"},
    )
    csv_download = workbench_api_env.client.get(report["download_url"], headers=headers)
    assert csv_download.status_code == 200
    assert "accepted" in csv_download.text
    assert "Accepted-risk governance remains visible" in csv_download.text

    updated = workbench_api_env.client.patch(
        f"/api/v1/waivers/{waiver['id']}",
        headers=headers,
        json={
            "service": "checkout",
            "owner": "service-risk",
            "reason": "Service-scoped accepted risk reviewed by the owner.",
            "expires_at": "2099-12-31",
            "review_at": "2099-12-01",
            "approval_ref": "CAB-065",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["service"] == "checkout"
    assert updated.json()["matched_findings"] == 2

    expired = workbench_api_env.client.post(
        f"/api/v1/waivers/{waiver['id']}/expire",
        headers=headers,
    )
    assert expired.status_code == 200, expired.text
    assert expired.json()["status"] == "expired"
    assert expired.json()["matched_findings"] == 2

    expired_detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert expired_detail.status_code == 200
    expired_finding = expired_detail.json()
    assert expired_finding["status"] == "open"
    assert expired_finding["waived"] is False
    assert "explanation_json" not in expired_finding


def test_workbench_waiver_mutations_recompute_scores_guidance_and_global_ranks(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    finding_ids = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )["finding_ids"]
    stronger_id, weaker_id = finding_ids

    with Session(workbench_api_env.engine) as session:
        historical_rows = list(
            session.exec(
                select(workbench_api_env.app_models.FindingDecisionEvidence).where(
                    workbench_api_env.app_models.FindingDecisionEvidence.project_id == project_id
                )
            ).all()
        )
        immutable_payloads = {row.finding_id: deepcopy(row.payload_json) for row in historical_rows}

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "finding_id": str(stronger_id),
            "owner": "risk-owner",
            "reason": "Temporarily accept the stronger finding.",
            "expires_at": "2099-12-31",
            "approval_ref": "CAB-RANK-CREATE",
        },
    )
    assert created.status_code == 200, created.text
    waiver_id = created.json()["id"]

    with Session(workbench_api_env.engine) as session:
        current = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).evidence_for_findings(finding_ids)
        stronger = current[stronger_id]
        weaker = current[weaker_id]
        assert stronger.status == "accepted"
        assert stronger.waived is True
        assert stronger.priority_evidence.priority_state == "Accepted"
        assert stronger.priority_evidence.operational_score == stronger.risk_score
        assert "active accepted-risk waiver: -20" in (
            stronger.priority_evidence.operational_score_reasons
        )
        assert stronger.priority_evidence.explanation.operational_score == stronger.risk_score
        assert stronger.remediation.recommendation == "waiver"
        assert stronger.remediation.recommendation_label == "Waiver"
        assert weaker.status == "open"
        assert weaker.priority_evidence.priority_state == "High"
        assert weaker.operational_rank == 1
        assert stronger.operational_rank == 2

    updated = workbench_api_env.client.patch(
        f"/api/v1/waivers/{waiver_id}",
        headers=headers,
        json={
            "finding_id": str(weaker_id),
            "owner": "risk-owner",
            "reason": "Move accepted risk to the weaker finding.",
            "expires_at": "2099-12-31",
            "review_at": "2099-12-01",
            "approval_ref": "CAB-RANK-UPDATE",
            "ticket_url": "https://tickets.example.test/CAB-RANK-UPDATE",
        },
    )
    assert updated.status_code == 200, updated.text

    with Session(workbench_api_env.engine) as session:
        current = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).evidence_for_findings(finding_ids)
        stronger = current[stronger_id]
        weaker = current[weaker_id]
        assert stronger.status == "open"
        assert stronger.waived is False
        assert stronger.priority_evidence.priority_state == "Critical"
        assert stronger.remediation.recommendation == "mitigate"
        assert weaker.status == "accepted"
        assert weaker.waived is True
        assert weaker.priority_evidence.priority_state == "Accepted"
        assert weaker.remediation.recommendation == "waiver"
        assert stronger.operational_rank == 1
        assert weaker.operational_rank == 2

    deleted = workbench_api_env.client.delete(
        f"/api/v1/waivers/{waiver_id}",
        headers=headers,
    )
    assert deleted.status_code == 204, deleted.text

    with Session(workbench_api_env.engine) as session:
        current = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).evidence_for_findings(finding_ids)
        assert current[stronger_id].status == "open"
        assert current[weaker_id].status == "open"
        assert current[stronger_id].waived is False
        assert current[weaker_id].waived is False
        assert current[stronger_id].operational_rank == 1
        assert current[weaker_id].operational_rank == 2
        remaining_waivers = workbench_api_env.repositories.WaiverRepository(
            session
        ).list_project_waivers(project_id)
        assert remaining_waivers == []
        historical_rows = list(
            session.exec(
                select(workbench_api_env.app_models.FindingDecisionEvidence).where(
                    workbench_api_env.app_models.FindingDecisionEvidence.project_id == project_id
                )
            ).all()
        )
        assert {row.finding_id: row.payload_json for row in historical_rows} == immutable_payloads
        delete_audit = session.exec(
            select(workbench_api_env.app_models.AuditEvent).where(
                workbench_api_env.app_models.AuditEvent.action == "waiver.delete",
                workbench_api_env.app_models.AuditEvent.resource_id == str(waiver_id),
            )
        ).one()
        snapshot = delete_audit.detail_json["deleted_waiver"]
        assert snapshot["id"] == waiver_id
        assert snapshot["project_id"] == str(project_id)
        assert snapshot["finding_id"] == str(weaker_id)
        assert snapshot["owner"] == "risk-owner"
        assert snapshot["reason"] == "Move accepted risk to the weaker finding."
        assert snapshot["expires_at"] == "2099-12-31"
        assert snapshot["review_at"] == "2099-12-01"
        assert snapshot["approval_ref"] == "CAB-RANK-UPDATE"
        assert snapshot["ticket_url"] == "https://tickets.example.test/CAB-RANK-UPDATE"
        assert snapshot["created_at"]
        assert snapshot["updated_at"]


def test_forced_waiver_sync_preserves_scope_first_tie_break_order(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            "cve_id,target_kind,target_ref,raw_severity",
            f"{DEMO_CVE_LOG4SHELL},host,a-target,critical",
            f"{DEMO_CVE_LOG4SHELL},host,b-target,critical",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("stable-scope-ranks.csv", occurrence_csv, "text/csv")},
    )
    run_payload = completed_run_payload(workbench_api_env, imported, headers=headers)
    assert run_payload["status"] == "succeeded"

    monkeypatch.setattr("app.repositories.waivers._PROJECTION_SYNC_BATCH_SIZE", 1)
    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        finding_ids = [finding.id for finding in findings]
        projection_repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        )

        before_evidence = projection_repository.evidence_for_findings(finding_ids)
        before = {
            evidence.occurrence_scope.target_ref: evidence.operational_rank
            for evidence in before_evidence.values()
        }
        assert before == {"a-target": 1, "b-target": 2}

        workbench_api_env.repositories.WaiverRepository(session).sync_project_waivers(
            project_id,
            force=True,
        )
        session.flush()

        after_evidence = projection_repository.evidence_for_findings(finding_ids)
        after = {
            evidence.occurrence_scope.target_ref: evidence.operational_rank
            for evidence in after_evidence.values()
        }
        assert after == before


def test_forced_waiver_sync_preserves_package_type_component_scopes(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,package_type,raw_severity",
            f"{DEMO_CVE_LOG4SHELL},shared-target,openssl,1.0,deb,critical",
            f"{DEMO_CVE_LOG4SHELL},shared-target,openssl,1.0,rpm,critical",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("package-type-scopes.csv", occurrence_csv, "text/csv")},
    )
    run_payload = completed_run_payload(workbench_api_env, imported, headers=headers)
    assert run_payload["status"] == "succeeded"

    monkeypatch.setattr("app.repositories.waivers._PROJECTION_SYNC_BATCH_SIZE", 1)
    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        finding_ids = [finding.id for finding in findings]
        projection_repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        )
        before_evidence = projection_repository.evidence_for_findings(finding_ids)
        by_package_type = {
            evidence.occurrence_scope.package_type: evidence
            for evidence in before_evidence.values()
        }
        assert set(by_package_type) == {"deb", "rpm"}
        assert {
            package_type: evidence.operational_rank
            for package_type, evidence in by_package_type.items()
        } == {"deb": 1, "rpm": 2}

        legacy_scope_keys = {}
        for package_type, evidence in by_package_type.items():
            legacy = evidence.model_copy(
                update={
                    "occurrence_scope": evidence.occurrence_scope.model_copy(
                        update={"package_type": None}
                    ),
                    "occurrences": [
                        item.model_copy(update={"package_type": None})
                        for item in evidence.occurrences
                    ],
                }
            )
            legacy_scope_keys[package_type] = _projection_scope_sort_key(legacy)
        assert legacy_scope_keys["deb"] != legacy_scope_keys["rpm"]

        before = {
            package_type: evidence.operational_rank
            for package_type, evidence in by_package_type.items()
        }
        workbench_api_env.repositories.WaiverRepository(session).sync_project_waivers(
            project_id,
            force=True,
        )
        session.flush()
        after_evidence = projection_repository.evidence_for_findings(finding_ids)
        after = {
            evidence.occurrence_scope.package_type: evidence.operational_rank
            for evidence in after_evidence.values()
        }
        assert after == before


@pytest.mark.parametrize(
    ("vex_status", "expected_priority_state"),
    [("fixed", "Fixed"), ("not_affected", "Suppressed")],
)
def test_waiver_recompute_preserves_compact_vex_status_counts(
    workbench_api_env: WorkbenchApiEnv,
    vex_status: str,
    expected_priority_state: str,
) -> None:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    project_id = uuid.UUID(project["id"])
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )["finding_ids"][0]
    with Session(workbench_api_env.engine) as session:
        evidence = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).get_evidence(finding_id)
        assert evidence is not None

    compact = evidence.model_copy(
        update={
            "status": "fixed" if vex_status == "fixed" else "suppressed",
            "suppressed_by_vex": True,
            "occurrences": [],
            "occurrence_scope": evidence.occurrence_scope.model_copy(update={"vex_status": None}),
            "governance": evidence.governance.model_copy(
                update={
                    "suppressed_by_vex": True,
                    "vex_statuses": {vex_status: 1},
                }
            ),
        }
    )

    recomputed = _recompute_projection_decision(compact.to_jsonable())

    assert recomputed.suppressed_by_vex is True
    assert recomputed.priority_state == expected_priority_state
    assert recomputed.operational_score == 0
    assert recomputed.provenance.vex_statuses == {vex_status: 1}
    assert recomputed.provenance.occurrence_count == 1
    assert recomputed.provenance.suppressed_occurrence_count == 1


def test_waiver_recompute_does_not_infer_suppression_from_partial_compact_vex_counts(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    evidence = _current_seed_evidence(workbench_api_env)
    compact = evidence.model_copy(
        update={
            "status": "open",
            "suppressed_by_vex": False,
            "occurrences": [],
            "occurrence_scope": evidence.occurrence_scope.model_copy(update={"vex_status": None}),
            "governance": evidence.governance.model_copy(
                update={
                    "suppressed_by_vex": False,
                    "vex_statuses": {"fixed": 1},
                }
            ),
        }
    )

    recomputed = _recompute_projection_decision(compact.to_jsonable())

    assert recomputed.suppressed_by_vex is False
    assert recomputed.priority_state not in {"Fixed", "Suppressed"}
    assert recomputed.operational_score > 0
    assert recomputed.provenance.vex_statuses == {"fixed": 1}
    assert recomputed.provenance.occurrence_count == 2
    assert recomputed.provenance.active_occurrence_count == 1
    assert recomputed.provenance.suppressed_occurrence_count == 1


def test_waiver_recompute_accumulates_normalized_compact_vex_status_keys(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    evidence = _current_seed_evidence(workbench_api_env)
    compact = evidence.model_copy(
        update={
            "status": "fixed",
            "suppressed_by_vex": True,
            "occurrences": [],
            "occurrence_scope": evidence.occurrence_scope.model_copy(update={"vex_status": None}),
            "governance": evidence.governance.model_copy(
                update={
                    "suppressed_by_vex": True,
                    "vex_statuses": {"Fixed": 1, " fixed ": 2},
                }
            ),
        }
    )

    recomputed = _recompute_projection_decision(compact.to_jsonable())

    assert recomputed.priority_state == "Fixed"
    assert recomputed.provenance.vex_statuses == {"fixed": 3}
    assert recomputed.provenance.occurrence_count == 3
    assert recomputed.provenance.suppressed_occurrence_count == 3


def test_waiver_recompute_preserves_compact_investigation_flag_with_partial_counts(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    evidence = _current_seed_evidence(workbench_api_env)
    compact = evidence.model_copy(
        update={
            "status": "open",
            "suppressed_by_vex": False,
            "under_investigation": True,
            "occurrences": [],
            "occurrence_scope": evidence.occurrence_scope.model_copy(update={"vex_status": None}),
            "governance": evidence.governance.model_copy(
                update={
                    "suppressed_by_vex": False,
                    "under_investigation": True,
                    "vex_statuses": {"affected": 1},
                }
            ),
        }
    )

    recomputed = _recompute_projection_decision(compact.to_jsonable())

    assert recomputed.suppressed_by_vex is False
    assert recomputed.under_investigation is True
    assert recomputed.operational_score > 0
    assert recomputed.provenance.vex_statuses == {"affected": 1}


def _current_seed_evidence(workbench_api_env: WorkbenchApiEnv) -> Any:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    with Session(workbench_api_env.engine) as session:
        evidence = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).get_evidence(finding_id)
        assert evidence is not None
        return evidence


def test_vpw064_workbench_waiver_scopes_match_finding_cve_asset_and_service(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "business_service": "checkout",
        },
    )

    scoped_payloads: tuple[tuple[dict[str, Any], int], ...] = (
        ({"finding_id": finding_id, "owner": "finding-risk"}, 1),
        ({"cve_id": DEMO_CVE_LOG4SHELL, "owner": "cve-risk"}, 1),
        ({"asset_key": "payments-api", "owner": "asset-risk"}, 2),
        ({"service": "checkout", "owner": "service-risk"}, 2),
    )
    for payload, expected_matches in scoped_payloads:
        response = workbench_api_env.client.post(
            f"/api/v1/projects/{project['id']}/waivers/",
            headers=headers,
            json={
                **payload,
                "reason": f"Scope validation for {next(iter(payload))}.",
                "expires_at": "2099-12-31",
                "approval_ref": "CAB-SCOPE",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["matched_findings"] == expected_matches

    listed = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["count"] == 4


def test_specific_active_waiver_outranks_broad_review_due_waiver(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-04-21T12:00:00+00:00")
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    finding = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    ).json()

    broad = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "portfolio-risk",
            "reason": "The broad acceptance needs review.",
            "expires_at": "2026-04-25",
            "review_at": "2026-04-20",
        },
    )
    assert broad.status_code == 200, broad.text
    assert broad.json()["status"] == "review_due"

    specific = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "asset_key": finding["asset_key"],
            "owner": "asset-risk",
            "reason": "The asset-specific acceptance remains active.",
            "expires_at": "2026-06-30",
        },
    )
    assert specific.status_code == 200, specific.text
    assert specific.json()["status"] == "active"

    refreshed = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert refreshed.status_code == 200, refreshed.text
    waiver = refreshed.json()["evidence"]["governance"]["waiver"]
    assert waiver["waiver_id"] == specific.json()["id"]
    assert waiver["waiver_status"] == "active"
    assert waiver["waiver_owner"] == "asset-risk"


def test_exact_finding_waiver_outranks_multi_field_scope(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    finding_response = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert finding_response.status_code == 200, finding_response.text
    finding = finding_response.json()

    broad = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "asset_key": finding["asset_key"],
            "service": finding["business_service"],
            "owner": "multi-field-owner",
            "reason": "Broad multi-field acceptance.",
            "expires_at": "2099-12-31",
        },
    )
    assert broad.status_code == 200, broad.text

    exact = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "finding_id": str(finding_id),
            "owner": "exact-finding-owner",
            "reason": "Acceptance for this exact finding.",
            "expires_at": "2099-12-31",
        },
    )
    assert exact.status_code == 200, exact.text

    refreshed = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert refreshed.status_code == 200, refreshed.text
    waiver = refreshed.json()["evidence"]["governance"]["waiver"]
    assert waiver["waiver_id"] == exact.json()["id"]
    assert waiver["waiver_owner"] == "exact-finding-owner"


def test_waiver_match_count_uses_same_unicode_semantics_as_effective_state(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    finding = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    ).json()
    updated = workbench_api_env.client.patch(
        f"/api/v1/assets/{finding['asset_id']}",
        headers=headers,
        json={"asset_key": "Straße"},
    )
    assert updated.status_code == 200, updated.text

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "asset_key": "STRASSE",
            "owner": "unicode-risk-owner",
            "reason": "Exercise Unicode-equivalent asset scope matching.",
            "expires_at": "2099-12-31",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["matched_findings"] == 2

    listed = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["data"][0]["matched_findings"] == 2


@pytest.mark.parametrize(
    ("waiver_scope", "asset_update"),
    [
        ({"service": "checkout", "owner": "service-risk"}, {"business_service": "identity"}),
        ({"asset_key": "payments-api", "owner": "asset-risk"}, {"asset_key": "renamed-api"}),
    ],
)
def test_workbench_asset_context_changes_resync_waiver_state(
    workbench_api_env: WorkbenchApiEnv,
    waiver_scope: dict[str, str],
    asset_update: dict[str, str],
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_seed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"asset_key": "payments-api", "business_service": "checkout"},
    )
    assert asset_seed.status_code == 200, asset_seed.text

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            **waiver_scope,
            "reason": "Scope should clear when asset context no longer matches.",
            "expires_at": "2099-12-31",
            "approval_ref": "CAB-ASSET-SYNC",
        },
    )
    assert created.status_code == 200, created.text
    assert (
        workbench_api_env.client.get(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
        ).json()["waived"]
        is True
    )

    changed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json=asset_update,
    )

    assert changed.status_code == 200, changed.text
    refreshed = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert refreshed.status_code == 200
    finding_payload = refreshed.json()
    assert finding_payload["status"] == "open"
    assert finding_payload["waived"] is False
    assert "evidence_json" not in finding_payload


def test_workbench_asset_context_import_resyncs_waiver_state(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])
    finding = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    asset_id = finding["asset_id"]
    asset_seed = workbench_api_env.client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers,
        json={"asset_key": "payments-api", "business_service": "checkout"},
    )
    assert asset_seed.status_code == 200, asset_seed.text
    waiver = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "service": "checkout",
            "owner": "service-risk",
            "reason": "Import should clear this service scope.",
            "expires_at": "2099-12-31",
            "approval_ref": "CAB-ASSET-IMPORT-SYNC",
        },
    )
    assert waiver.status_code == 200, waiver.text

    context_csv = "\n".join(
        [
            "target_kind,target_ref,asset_id,business_service",
            "host,payments-api,payments-api,identity",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/import",
        headers=headers,
        files={"asset_context_file": ("asset-context.csv", context_csv, "text/csv")},
    )

    assert imported.status_code == 200, imported.text
    refreshed = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["status"] == "open"
    assert refreshed.json()["waived"] is False


def test_workbench_expired_waiver_sync_updates_v2_evidence_with_string_status(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    occurrence_csv = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,business_service",
            f"{DEMO_CVE_LOG4SHELL},identity-api,log4j,2.14.1,checkout",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("waiver-evidence.csv", occurrence_csv, "text/csv")},
    )
    run_payload = completed_run_payload(workbench_api_env, imported, headers=headers)
    assert run_payload["evidence"]["analysis_evidence_id"]

    with Session(workbench_api_env.engine) as session:
        finding = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project_id,
                workbench_api_env.app_models.Finding.cve_id == DEMO_CVE_LOG4SHELL,
            )
        ).one()
        finding_id = finding.id
        finding.status = "open"
        session.add(finding)
        session.commit()

    expired = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "legacy-risk",
            "reason": "Expired waiver should still update typed evidence.",
            "expires_at": "2020-01-01",
            "review_at": "2019-12-31",
            "approval_ref": "CAB-STRING-STATUS",
        },
    )
    assert expired.status_code == 200, expired.text
    assert expired.json()["matched_findings"] == 1

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "open"
    assert detail.json()["waived"] is False
    with Session(workbench_api_env.engine) as session:
        historical_evidence = workbench_api_env.repositories.EvidenceRepository(
            session
        ).latest_finding_decision_evidence(finding_id)
        current_evidence = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).get_evidence(finding_id)
        assert historical_evidence is not None
        assert current_evidence is not None
        assert historical_evidence.governance.waiver == {}
        assert current_evidence.status == "open"
        assert current_evidence.governance.waived is False
        waiver_record = {
            **current_evidence.governance.waiver,
            **dict(current_evidence.priority_evidence.raw.get("waiver") or {}),
        }
        assert waiver_record["waiver_status"] == "expired"


def test_waiver_recompute_preserves_asset_context_from_pre_typed_v2_evidence(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Any,
) -> None:
    configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    occurrence_csv = "\n".join(
        [
            "cve_id,target_ref,component_name,component_version,raw_severity",
            "CVE-2024-3094,prod-api,xz,5.6.0,CRITICAL",
            "",
        ]
    ).encode()
    asset_context_csv = "\n".join(
        [
            "target_kind,target_ref,asset_id,criticality,exposure,environment",
            "generic,prod-api,asset-prod,critical,public,prod",
            "",
        ]
    ).encode()
    imported = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={
            "file": ("legacy-v2.csv", occurrence_csv, "text/csv"),
            "asset_context_file": ("asset-context.csv", asset_context_csv, "text/csv"),
        },
    )
    run_payload = completed_run_payload(workbench_api_env, imported, headers=headers)
    assert run_payload["status"] == "succeeded"
    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    ).json()["data"]
    assert len(findings) == 1
    original = findings[0]
    original_reasons = original["evidence"]["priority_evidence"]["operational_score_reasons"]

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
        legacy_payload = deepcopy(source.payload_json)
        for occurrence in legacy_payload["occurrences"]:
            occurrence.pop("target_kind", None)
            occurrence.pop("asset_id", None)
            occurrence.pop("asset_environment", None)
            occurrence.pop("asset_criticality", None)
            assert occurrence["import_evidence"]["asset_id"] == "asset-prod"
            assert occurrence["import_evidence"]["target_kind"] == "generic"
            assert occurrence["import_evidence"]["asset_environment"] == "prod"
            assert occurrence["import_evidence"]["asset_criticality"] == "critical"
        legacy_hash = canonical_payload_sha256(legacy_payload)
        source.payload_json = legacy_payload
        projection.source_payload_sha256 = legacy_hash
        projection.projection_payload_sha256 = legacy_hash
        session.add(source)
        session.add(projection)
        session.commit()

    expired = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": "CVE-2024-3094",
            "owner": "legacy-risk",
            "reason": "Exercise an upgrade-safe legacy evidence recompute.",
            "expires_at": "2020-01-01",
        },
    )
    assert expired.status_code == 200, expired.text

    current = workbench_api_env.client.get(
        f"/api/v1/findings/{original['id']}",
        headers=headers,
    )
    assert current.status_code == 200, current.text
    current_payload = current.json()
    assert current_payload["risk_score"] == original["risk_score"]
    assert (
        current_payload["evidence"]["priority_evidence"]["operational_score_reasons"]
        == original_reasons
    )
    assert current_payload["asset_criticality"] == "critical"
    assert current_payload["asset_environment"] == "production"
    with Session(workbench_api_env.engine) as session:
        source = session.exec(
            select(workbench_api_env.app_models.FindingDecisionEvidence).where(
                workbench_api_env.app_models.FindingDecisionEvidence.finding_id
                == uuid.UUID(original["id"])
            )
        ).one()
        assert source.payload_json == legacy_payload


def test_vpw064_workbench_waiver_validation_errors(workbench_api_env: WorkbenchApiEnv) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    missing_scope = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "owner": "risk",
            "reason": "No scope.",
            "expires_at": "2099-12-31",
        },
    )
    assert missing_scope.status_code == 422

    missing_expiry = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk",
            "reason": "Missing expiry.",
        },
    )
    assert missing_expiry.status_code == 422

    review_after_expiry = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk",
            "reason": "Bad review date.",
            "expires_at": "2099-01-01",
            "review_at": "2099-02-01",
        },
    )
    assert review_after_expiry.status_code == 422


def _seed_report_run(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: uuid.UUID,
    finding_id: str,
) -> str:
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="waiver-report.csv",
            status=workbench_api_env.app_models.AnalysisRunStatus.COMPLETED,
            result_ref_json={"parsed": 1, "findings": 1},
        )
        finding = session.get(workbench_api_env.app_models.Finding, uuid.UUID(finding_id))
        assert finding is not None
        occurrence = run_repo.add_finding_occurrence(
            finding_id=uuid.UUID(finding_id),
            analysis_run_id=run.id,
            source="generic-occurrence-csv",
            raw_reference=DEMO_CVE_LOG4SHELL,
        )
        evidence_repo = workbench_api_env.repositories.EvidenceRepository(session)
        latest_evidence = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).get_evidence(uuid.UUID(finding_id))
        assert latest_evidence is not None
        finding_evidence = _seed_finding_evidence(
            finding=finding,
            analysis_run_id=run.id,
            project_id=project_id,
            asset_key=finding.asset.asset_key if finding.asset is not None else "payments-api",
            asset_name=finding.asset.name if finding.asset is not None else "Payments API",
            component_name=finding.component.name
            if finding.component is not None
            else "log4j-core",
            component_version=finding.component.version
            if finding.component is not None
            else "2.14.1",
            component_purl=finding.component.purl if finding.component is not None else None,
            component_package_type=(
                finding.component.package_type or finding.component.ecosystem
                if finding.component is not None
                else None
            ),
            priority=latest_evidence.priority,
            priority_rank=latest_evidence.priority_rank,
            risk_score=latest_evidence.risk_score or 0.0,
            operational_rank=latest_evidence.operational_rank,
            epss=latest_evidence.epss or 0.0,
            cvss=latest_evidence.cvss_base_score or 0.0,
            in_kev=latest_evidence.in_kev,
            rationale=latest_evidence.rationale or "Accepted risk report seed.",
            action=latest_evidence.recommended_action or "Review accepted risk.",
            confidence="high",
            flags=[],
        ).model_copy(
            update={
                "status": latest_evidence.status,
                "waived": latest_evidence.waived,
                "governance": latest_evidence.governance,
                "priority_evidence": latest_evidence.priority_evidence,
            }
        )
        finding_evidence.occurrences.append(
            OccurrenceEvidenceV2(
                occurrence_id=str(occurrence.id),
                analysis_run_id=str(run.id),
                source="generic-occurrence-csv",
                raw_reference=DEMO_CVE_LOG4SHELL,
            )
        )
        analysis_evidence = evidence_repo.upsert_analysis_evidence(
            project_id=project_id,
            analysis_run_id=run.id,
            provider_snapshot_id=run.provider_snapshot_id,
            evidence=_seed_analysis_evidence(
                project_id=project_id,
                run=run,
                provider_snapshot_id=run.provider_snapshot_id,
                provider_snapshot_hash=None,
                finding_count=1,
                counts_by_priority={finding_evidence.priority_evidence.priority_label: 1},
                locked_provider_data=False,
                findings=[finding_evidence],
            ),
        )
        evidence_repo.replace_finding_decision_evidence(
            analysis_evidence_id=analysis_evidence.id,
            project_id=project_id,
            analysis_run_id=run.id,
            evidence_items=[finding_evidence],
        )
        session.commit()
        return str(run.id)
