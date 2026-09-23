from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import date, timedelta

import pytest
from pydantic import ValidationError
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

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.ledger import DecisionLedgerInvariantError, canonical_payload_sha256
from app.models import FindingCurrentProjection, FindingDecisionEvidence
from app.repositories.current_projections import (
    _apply_top_level_overlay,
    _effective_projection_payload,
)
from app.repositories.evidence_payloads import EvidencePayloadStore
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


def test_decision_ledger_nested_overlay_preserves_nulls_and_isolates_history_and_callers(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        source = session.get(FindingDecisionEvidence, projection.source_finding_evidence_id)
        assert source is not None
        original_source = deepcopy(source.payload_json)
        original_hash = projection.source_payload_sha256
        payload = repository.current_payload(finding_id)
        assert payload is not None
        replacement = {"nested": {"replacement": [None, {"value": "new"}]}}
        assert payload["priority_evidence"]["raw"] != replacement
        payload["priority_evidence"]["raw"] = deepcopy(replacement)
        expected = deepcopy(payload)

        repository.update_current_payload(finding_id, payload)
        payload["priority_evidence"]["raw"]["nested"]["replacement"][1]["value"] = "caller mutation"

        assert projection.lifecycle_overlay_json["priority_evidence"]["raw"] == replacement
        assert projection.source_payload_sha256 == original_hash
        assert projection.projection_payload_sha256 == canonical_payload_sha256(expected)
        assert source.payload_json == original_source
        session.commit()
        session.refresh(source)
        session.refresh(projection)
        current = repository.current_payload(finding_id)
        assert current == expected
        current["priority_evidence"]["raw"]["nested"]["replacement"][1]["value"] = "read mutation"
        assert repository.current_payload(finding_id) == expected
        assert source.payload_json == original_source
        assert repository.verify_source_parity([projection]).matches


@pytest.mark.parametrize("clear_mode", ["remove", "explicit_null"])
def test_decision_ledger_rejects_unrepresentable_top_level_deletion(
    workbench_api_env: WorkbenchApiEnv, clear_mode: str
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        before = deepcopy(projection.model_dump())
        payload = repository.current_payload(finding_id)
        assert payload is not None
        original = deepcopy(payload)
        assert payload["risk_score"] is not None
        if clear_mode == "remove":
            payload.pop("risk_score")
        else:
            payload["risk_score"] = None

        # Normalization omits optional nulls. A sparse replacement overlay must
        # reject deleting a source key instead of silently keeping its old value.
        with pytest.raises(DecisionLedgerInvariantError, match="could not reproduce"):
            repository.update_current_payload(finding_id, payload)

        assert projection.model_dump() == before
        assert repository.current_payload(finding_id) == original
        assert repository.verify_source_parity([projection]).matches


def test_decision_ledger_overlay_reader_copies_nested_values_and_replaces_top_level_nulls() -> None:
    source = {"unchanged": {"items": [1]}, "replaced": {"old": [2]}, "cleared": {"old": 3}}
    overlay = {"replaced": {"new": [None]}, "cleared": None}
    original_source = deepcopy(source)
    original_overlay = deepcopy(overlay)

    current = _apply_top_level_overlay(source, overlay)

    assert current == {"unchanged": {"items": [1]}, "replaced": {"new": [None]}, "cleared": None}
    current["unchanged"]["items"].append(4)
    current["replaced"]["new"].append(5)
    assert source == original_source
    assert overlay == original_overlay


def test_decision_ledger_contract_reader_preserves_json_values_and_isolates_nested_graphs(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        source = session.get(FindingDecisionEvidence, projection.source_finding_evidence_id)
        assert source is not None
        payload = EvidencePayloadStore(session.connection()).load(source)
        payload["remediation"]["raw"] = {"source": {"items": [None, "Größe, 東京, 🛡️\u0000"]}}
        payload["evaluation_input"] = {
            "cve_id": source.cve_id,
            "observations": [{"cve_id": source.cve_id, "fix_versions": ["2.0"]}],
            "provider_evidence": {
                name: {"cve_id": source.cve_id} for name in ("nvd", "epss", "kev")
            },
            "attack_data": {"cve_id": source.cve_id},
            "evaluation_date": "2026-09-19",
        }
        source.payload_json = FindingDecisionEvidenceV2.model_validate(payload).to_jsonable()
        projection.lifecycle_overlay_json = {
            "rationale": "Current decision rationale",
            "priority_evidence": source.payload_json["priority_evidence"]
            | {"raw": {"overlay": {"items": [None, 2**256, 0.12345678912345678]}}},
        }
        original_source = deepcopy(source.payload_json)
        original_overlay = deepcopy(projection.lifecycle_overlay_json)
        expected = FindingDecisionEvidenceV2.model_validate(
            _effective_projection_payload(projection, source, source.payload_json)
        )
        projection.source_payload_sha256 = canonical_payload_sha256(source.payload_json)
        projection.projection_payload_sha256 = canonical_payload_sha256(expected.to_jsonable())
        projection.rationale = expected.rationale
        projection.lifecycle_revision = 1
        projection.revision += 1
        assert repository.verify_source_parity([projection]).matches

        current = repository.evidence_for_records([projection], source_records={source.id: source})[
            finding_id
        ]

        assert current.model_dump() == expected.model_dump()
        assert current.rationale == "Current decision rationale"
        assert current.priority_evidence.raw == original_overlay["priority_evidence"]["raw"]
        assert current.evaluation_input is not None
        assert current.evaluation_input.evaluation_date == date(2026, 9, 19)
        current.evaluation_input.observations[0].fix_versions.append("3.0")
        current.remediation.raw["source"]["items"].append("source mutation")
        current.priority_evidence.raw["overlay"]["items"].append("overlay mutation")

        again = repository.evidence_for_records([projection], source_records={source.id: source})[
            finding_id
        ]
        assert again.model_dump() == expected.model_dump()
        assert source.payload_json == original_source
        assert projection.lifecycle_overlay_json == original_overlay


def test_decision_ledger_contract_reader_retains_deep_persistable_raw_evidence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        source = session.get(FindingDecisionEvidence, projection.source_finding_evidence_id)
        assert source is not None
        nested: dict[str, object] = {"items": [None, "deep evidence"]}
        for _ in range(199):
            nested = {"nested": nested}
        payload = EvidencePayloadStore(session.connection()).load(source)
        payload["priority_evidence"]["raw"] = nested
        persisted = FindingDecisionEvidenceV2.model_validate(payload).to_jsonable()
        source.payload_json = persisted
        original_hash = canonical_payload_sha256(source.payload_json)
        projection.source_payload_sha256 = original_hash
        projection.projection_payload_sha256 = original_hash
        session.add(source)
        session.add(projection)
        session.flush()
        session.refresh(source)
        session.refresh(projection)
        assert source.payload_json == persisted
        assert repository.verify_source_parity([projection]).matches

        current = repository.evidence_for_records([projection], source_records={source.id: source})[
            finding_id
        ]

        assert current.to_jsonable() == persisted
        current.priority_evidence.raw["nested"]["reader mutation"] = True
        assert canonical_payload_sha256(source.payload_json) == original_hash


@pytest.mark.parametrize("invalid_field", ["risk_score", "unknown_field"])
def test_decision_ledger_contract_reader_still_rejects_invalid_overlay_fields(
    workbench_api_env: WorkbenchApiEnv, invalid_field: str
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        source = session.get(FindingDecisionEvidence, projection.source_finding_evidence_id)
        assert source is not None
        projection.lifecycle_overlay_json = {invalid_field: {"invalid": [None]}}

        with pytest.raises(ValidationError) as old_error:
            FindingDecisionEvidenceV2.model_validate(
                _effective_projection_payload(
                    projection, source, EvidencePayloadStore(session.connection()).load(source)
                )
            )
        with pytest.raises(ValidationError) as current_error:
            repository.evidence_for_records([projection], source_records={source.id: source})

        assert current_error.value.errors() == old_error.value.errors()


@pytest.mark.parametrize("identity", ["finding_id", "project_id", "analysis_run_id"])
def test_decision_ledger_both_readers_reject_mismatched_source_identity(
    workbench_api_env: WorkbenchApiEnv, identity: str
) -> None:
    finding_id = _seed_decision_ledger(workbench_api_env)[0]

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(session)
        projection = repository.get_record(finding_id)
        assert projection is not None
        source = session.get(FindingDecisionEvidence, projection.source_finding_evidence_id)
        assert source is not None
        setattr(source, identity, uuid.uuid4())

        with pytest.raises(ValueError, match="identity mismatch"):
            _effective_projection_payload(projection, source, {})
        with pytest.raises(ValueError, match="identity mismatch"):
            repository.evidence_for_records([projection], source_records={source.id: source})


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
