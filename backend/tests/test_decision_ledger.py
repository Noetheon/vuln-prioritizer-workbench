from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlmodel import Session, select
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    local_api_headers,
    seed_finding_pair,
)

from app.decision_core.ledger import DecisionLedgerInvariantError
from app.models import FindingCurrentProjection, FindingDecisionEvidence
from app.services.risk_reduction import project_risk_index, project_risk_index_from_projection


def test_decision_ledger_dual_write_links_current_state_to_immutable_history(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_ids = _seed_decision_ledger(workbench_api_env)

    with Session(workbench_api_env.engine) as session:
        history = list(session.exec(select(FindingDecisionEvidence)).all())
        projections = list(session.exec(select(FindingCurrentProjection)).all())
        parity = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).verify_source_parity(projections)

    assert {row.finding_id for row in history} == set(finding_ids)
    assert {row.finding_id for row in projections} == set(finding_ids)
    assert all(row.source_finding_evidence_id is not None for row in projections)
    assert all(row.lifecycle_revision == 0 for row in projections)
    assert all(row.lifecycle_overlay_json == {} for row in projections)
    assert parity.checked == 2
    assert parity.matches is True


def test_decision_ledger_rejects_history_rewrite_but_allows_current_lifecycle_update(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        evidence_repository = workbench_api_env.repositories.EvidenceRepository(session)
        source = evidence_repository.latest_finding_decision_evidence_record(finding_id)
        assert source is not None
        original_payload = dict(source.payload_json)
        contract = evidence_repository.latest_finding_decision_evidence(finding_id)
        assert contract is not None

        with pytest.raises(DecisionLedgerInvariantError, match="immutable"):
            evidence_repository.replace_finding_decision_evidence(
                analysis_evidence_id=source.analysis_evidence_id,
                project_id=source.project_id,
                analysis_run_id=source.analysis_run_id,
                evidence_items=[contract.model_copy(update={"status": "in_review"})],
            )

        projection_repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        )
        projection_repository.update_current_payload(
            finding_id,
            contract.model_copy(update={"status": "in_review"}).to_jsonable(),
        )
        session.commit()

        session.refresh(source)
        current = projection_repository.get_evidence(finding_id)
        projection = projection_repository.get_record(finding_id)

    assert source.payload_json == original_payload
    assert current is not None
    assert current.status == "in_review"
    assert projection is not None
    assert projection.lifecycle_revision == 1
    assert projection.lifecycle_overlay_json == {"status": "in_review"}


def test_decision_ledger_rejects_denormalized_history_column_drift(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.EvidenceRepository(session)
        source = repository.latest_finding_decision_evidence_record(finding_id)
        contract = repository.latest_finding_decision_evidence(finding_id)
        assert source is not None
        assert contract is not None
        source.priority = "low"
        session.add(source)
        session.flush()

        with pytest.raises(DecisionLedgerInvariantError, match="immutable"):
            repository.replace_finding_decision_evidence(
                analysis_evidence_id=source.analysis_evidence_id,
                project_id=source.project_id,
                analysis_run_id=source.analysis_run_id,
                evidence_items=[contract],
            )


def test_decision_ledger_rejects_cross_envelope_contract_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.EvidenceRepository(session)
        source = repository.latest_finding_decision_evidence_record(finding_id)
        contract = repository.latest_finding_decision_evidence(finding_id)
        assert source is not None
        assert contract is not None

        with pytest.raises(DecisionLedgerInvariantError, match="persistence envelope"):
            repository.replace_finding_decision_evidence(
                analysis_evidence_id=source.analysis_evidence_id,
                project_id=source.project_id,
                analysis_run_id=source.analysis_run_id,
                evidence_items=[contract.model_copy(update={"project_id": str(uuid.uuid4())})],
            )


def test_decision_ledger_backfill_restores_missing_current_rows_idempotently(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_ids = _seed_decision_ledger(workbench_api_env)

    with Session(workbench_api_env.engine) as session:
        projections = list(session.exec(select(FindingCurrentProjection)).all())
        for projection in projections:
            session.delete(projection)
        session.commit()

        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        missing = repository.verify_all_source_parity(batch_size=1)
        assert repository.backfill_missing(batch_size=1) == 2
        assert repository.backfill_missing(batch_size=1) == 0
        restored = repository.records_for_findings(finding_ids)
        parity = repository.verify_all_source_parity(batch_size=1)

    assert missing.checked == 0
    assert missing.mismatches == ("coverage:history=2,projection=0",)
    assert len(restored) == 2
    assert parity.checked == 2
    assert parity.matches is True


def test_decision_ledger_shadow_parity_detects_source_hash_drift(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        projection = session.exec(
            select(FindingCurrentProjection).where(
                FindingCurrentProjection.finding_id == finding_id
            )
        ).one()
        projection.source_payload_sha256 = "0" * 64
        session.add(projection)
        session.flush()
        result = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).verify_source_parity([projection])

    assert result.checked == 1
    assert result.matches is False
    assert result.mismatches == (f"{finding_id}:source-hash",)


def test_decision_ledger_shadow_parity_detects_source_timestamp_drift(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        projection = session.get(FindingCurrentProjection, finding_id)
        assert projection is not None
        projection.source_created_at += timedelta(seconds=1)
        session.add(projection)
        session.flush()
        result = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).verify_source_parity([projection])

    assert result.checked == 1
    assert result.mismatches == (f"{finding_id}:source-created-at",)


def test_decision_ledger_shadow_parity_detects_projection_payload_and_column_drift(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        projection = session.get(FindingCurrentProjection, finding_id)
        assert projection is not None
        projection.lifecycle_overlay_json = {"status": "in_review"}
        projection.priority = "critical"
        session.add(projection)
        session.flush()
        result = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        ).verify_source_parity([projection])

    assert result.checked == 1
    assert result.matches is False
    assert result.mismatches == (
        f"{finding_id}:projection-hash",
        f"{finding_id}:source-projection-hash",
        f"{finding_id}:materialized-columns",
    )


def test_projection_risk_index_preserves_zero_score_findings_without_history(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )
    with Session(workbench_api_env.engine) as session:
        asset = create_asset(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
            asset_key="pending-evidence-api",
            name="Pending Evidence API",
        )
        component = create_component(
            session,
            workbench_api_env.repositories,
            name="pending-evidence-component",
        )
        vulnerability = create_vulnerability(
            session,
            workbench_api_env.repositories,
            cve_id="CVE-2024-9998",
        )
        create_finding(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id="CVE-2024-9998",
        )
        session.commit()
        findings = workbench_api_env.repositories.FindingRepository(session).list_project_findings(
            project_id
        )

        expected = project_risk_index(findings)
        projected = project_risk_index_from_projection(session, project_id)

    assert expected == 57.0
    assert projected == expected


def _seed_decision_ledger(workbench_api_env: WorkbenchApiEnv) -> list[uuid.UUID]:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    return [uuid.UUID(str(value)) for value in seeded["finding_ids"]]
