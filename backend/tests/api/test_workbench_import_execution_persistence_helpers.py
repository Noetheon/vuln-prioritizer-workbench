from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

from sqlalchemy import event
from sqlmodel import Session, select
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.decision_core.identity import (
    FINDING_SCOPE_KEY_PREFIX,
    OBSERVATION_KEY_PREFIX,
    component_scope_identity,
    finding_scope_identity,
    finding_scope_key,
    observation_identity,
    observation_key,
)
from app.domain.engine.models import AnalysisContext, PrioritizedFinding
from app.importers.contracts import NormalizedOccurrence
from app.repositories.findings import normalize_component_persistence_identity
from app.services import WorkbenchAnalysisResult
from app.services.import_execution_dedup import (
    _dedup_key_parts,
    _finding_dedup_key,
    _observation_key,
    _preferred_asset_storage_key,
)
from app.services.import_execution_persistence import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _attack_context_defensive_note,
    _attack_context_review_status,
    _canonical_component_projection,
    _chunks,
    _chunks_any,
    _decision_payload_for_occurrence,
    _finding_status_for_occurrence,
    _jsonable_model,
    _persist_workbench_occurrences,
    _priority_state_for_occurrence,
    _suppressed_by_vex_for_occurrence,
    _technique_ids_from_context,
    _valid_attack_tactic_ids,
)
from app.services.import_execution_persistence_bulk import (
    _persist_workbench_occurrences_bulk_insert,
)
from app.services.import_execution_persistence_payloads import (
    _canonical_vulnerability_source_id,
    _scope_projection_payload,
)


def _decision(**overrides: object) -> PrioritizedFinding:
    values = {
        "cve_id": "CVE-2024-3094",
        "priority_label": "High",
        "priority_rank": 2,
        "priority_state": "Open",
        "operational_score": 87,
        "rationale": "Remote code execution risk.",
        "recommended_action": "Patch affected systems.",
    }
    values.update(overrides)
    return PrioritizedFinding(**values)


def _occurrence(**overrides: object) -> NormalizedOccurrence:
    values = {
        "cve_id": "CVE-2024-3094",
        "component_name": "xz-utils",
        "component_version": "5.6.0",
        "target_ref": "build-host-1",
        "source": "generic-occurrence-csv",
        "raw_evidence": {
            "source_id": "scanner-a",
            "source_record_id": "finding-1",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "rpm",
            "environment": "Production",
            "exposure": "internet",
            "criticality": "critical",
        },
    }
    values.update(overrides)
    return NormalizedOccurrence(**values)


def test_import_persistence_dedup_key_uses_cve_component_asset_scope() -> None:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    parts = _dedup_key_parts(project_id, _occurrence(target_ref=" build-host-1 "))

    assert parts == {
        "project_id": str(project_id),
        "cve_id": "CVE-2024-3094",
        "component_identity": component_scope_identity(
            component_name="xz-utils",
            component_version="5.6.0",
            purl="pkg:rpm/xz-utils@5.6.0",
        ),
        "target_kind": "generic",
        "target_ref": "build-host-1",
        "source_id": "scanner-a",
    }
    assert _finding_dedup_key(parts).startswith(FINDING_SCOPE_KEY_PREFIX)
    assert _finding_dedup_key(parts) == _finding_dedup_key(dict(reversed(parts.items())))


def test_import_persistence_dedup_key_falls_back_to_component_identity() -> None:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    parts = _dedup_key_parts(
        project_id,
        _occurrence(raw_evidence={"source_id": "scanner-a", "package_type": "deb"}),
    )

    assert parts["component_identity"] == component_scope_identity(
        component_name="xz-utils",
        component_version="5.6.0",
        package_type="deb",
    )


def test_bulk_insert_fast_path_rejects_purl_only_component_identity() -> None:
    occurrence = NormalizedOccurrence(
        cve_id="CVE-2024-3094",
        component_name=None,
        target_ref="build-host-1",
        raw_evidence={"purl": "pkg:rpm/xz-utils@5.6.0"},
    )

    result = _persist_workbench_occurrences_bulk_insert(
        session=cast(Session, SimpleNamespace()),
        project_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        occurrences=[occurrence] * 1000,
        analysis_result=cast(WorkbenchAnalysisResult, SimpleNamespace()),
    )

    assert result is None


def test_observation_identity_includes_source_record_source_id_and_cve_alias() -> None:
    first = observation_identity(
        source=" Grype-JSON ",
        source_record_id="match:1",
        source_id="GHSA-1111-2222-3333",
        cve_id="cve-2024-0001",
    )
    second_alias = observation_identity(
        source="grype-json",
        source_record_id="match:1",
        source_id="GHSA-1111-2222-3333",
        cve_id="CVE-2024-0002",
    )

    assert first.parts() == {
        "source": "grype-json",
        "source_record_id": "match:1",
        "cve_id": "CVE-2024-0001",
        "source_id": "GHSA-1111-2222-3333",
    }
    assert observation_key(first).startswith(OBSERVATION_KEY_PREFIX)
    assert observation_key(first) != observation_key(second_alias)


def test_finding_scope_key_is_source_independent_cve_consistent_and_stable() -> None:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    first_occurrence = _occurrence(
        cve_id="CVE-2024-0001",
        source="grype-json",
        raw_evidence={
            "source_id": "GHSA-1111-2222-3333",
            "source_record_id": "match:1",
            "purl": " PKG:PYPI/Django@5.6.0 ",
        },
    )
    repeated_from_another_source = _occurrence(
        cve_id="CVE-2024-0001",
        source="trivy-json",
        raw_evidence={
            "source_id": "scanner-b",
            "source_record_id": "result:99",
            "purl": "pkg:pypi/django@5.6.0",
        },
    )
    second_cve_alias = _occurrence(
        cve_id="CVE-2024-0002",
        source="grype-json",
        raw_evidence={
            "source_id": "GHSA-1111-2222-3333",
            "source_record_id": "match:1",
            "purl": "pkg:pypi/django@5.6.0",
        },
    )

    first_parts = _dedup_key_parts(project_id, first_occurrence)
    repeated_parts = _dedup_key_parts(project_id, repeated_from_another_source)
    alias_parts = _dedup_key_parts(project_id, second_cve_alias)

    assert first_parts["source_id"] != repeated_parts["source_id"]
    assert _finding_dedup_key(first_parts) == _finding_dedup_key(repeated_parts)
    assert _finding_dedup_key(first_parts) != _finding_dedup_key(alias_parts)
    assert _observation_key(first_occurrence) != _observation_key(second_cve_alias)

    explicit_scope = finding_scope_identity(
        project_id=project_id,
        cve_id="cve-2024-0001",
        component_name=" Django ",
        component_version="5.6.0",
        purl=" PKG:PYPI/Django@5.6.0 ",
        target_ref=" build-host-1 ",
    )
    assert explicit_scope.parts() == {
        "project_id": str(project_id),
        "cve_id": "CVE-2024-0001",
        "component_identity": component_scope_identity(
            component_name="django",
            component_version="5.6.0",
            purl="pkg:pypi/django@5.6.0",
        ),
        "target_kind": "generic",
        "target_ref": "build-host-1",
    }
    assert finding_scope_key(explicit_scope) == _finding_dedup_key(first_parts)


def test_vulnerability_source_alias_is_only_projected_when_observations_agree() -> None:
    zulu = _occurrence(raw_evidence={"source_id": "Z-ALIAS"})
    alpha = _occurrence(raw_evidence={"source_id": "A-ALIAS"})
    repeated = _occurrence(raw_evidence={"source_id": "Z-ALIAS"})

    assert _canonical_vulnerability_source_id([zulu, alpha]) is None
    assert _canonical_vulnerability_source_id([alpha, zulu]) is None
    assert _canonical_vulnerability_source_id([zulu, repeated]) == "Z-ALIAS"


def test_import_persistence_uses_final_scope_decision_without_vex_overlay() -> None:
    suppressed_decision = _decision(suppressed_by_vex=True, priority_state="Suppressed")
    open_occurrence = _occurrence(raw_evidence={})
    fixed_occurrence = _occurrence(raw_evidence={"vex_status": "fixed"})
    not_affected_occurrence = _occurrence(raw_evidence={"vex_status": "not_affected"})

    assert (
        _finding_status_for_occurrence(suppressed_decision, open_occurrence).value == "suppressed"
    )
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, open_occurrence) is True
    assert (
        _priority_state_for_occurrence(
            suppressed_decision,
            open_occurrence,
            base_priority_state=suppressed_decision.priority_state,
        )
        == "Suppressed"
    )
    assert (
        _finding_status_for_occurrence(suppressed_decision, fixed_occurrence).value == "suppressed"
    )
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, fixed_occurrence) is True
    assert (
        _finding_status_for_occurrence(suppressed_decision, not_affected_occurrence).value
        == "suppressed"
    )
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, not_affected_occurrence) is True


def test_import_persistence_payload_is_canonical_and_scope_metadata_is_separate() -> None:
    occurrence = _occurrence(raw_evidence={"source_id": "scanner-a", "vex_status": "fixed"})
    decision = _decision(priority_state="Open")
    result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="import.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=uuid.UUID("00000000-0000-4000-8000-000000000456"),
        provider_snapshot_hash="snapshot-hash",
        provider_snapshot_file="provider-snapshot.json",
        locked_provider_data=True,
    )

    compact_payload = _decision_payload_for_occurrence(decision, occurrence, compact=True)
    normal_payload = _decision_payload_for_occurrence(decision, occurrence, compact=False)
    evidence = _analysis_evidence_for_occurrence(
        result,
        decision,
        occurrence,
        priority_state=compact_payload["priority_state"],
    )

    assert compact_payload == normal_payload
    assert "occurrence_scope" not in compact_payload
    assert compact_payload["priority_state"] == "Open"
    assert "remediation" in compact_payload
    assert "decision_guidance" in compact_payload
    restored = PrioritizedFinding.model_validate(compact_payload)
    assert restored.operational_score == decision.operational_score
    assert restored.provenance.occurrences == []
    assert evidence["occurrence_scope"]["source_id"] == "scanner-a"
    assert evidence["provider_snapshot_hash"] == "snapshot-hash"
    assert evidence["occurrence_vex_status"] == "fixed"
    assert evidence["priority_state"] == "Open"


def test_scope_projection_keeps_only_field_level_unanimous_provenance() -> None:
    shared_evidence = {
        "source_id": "scanner-a",
        "purl": "pkg:rpm/xz-utils@5.6.0",
        "vex_status": "fixed",
        "vex_match_type": "exact",
    }
    projection = _scope_projection_payload(
        _decision(),
        [
            _occurrence(
                source="grype-json",
                raw_evidence={
                    **shared_evidence,
                    "source_record_id": "match:1",
                    "vex_source_path": "/vex/a.json",
                },
            ),
            _occurrence(
                source="grype-json",
                raw_evidence={
                    **shared_evidence,
                    "source_record_id": "match:2",
                    "vex_source_path": "/vex/b.json",
                },
            ),
        ],
    )

    assert projection["source"] == "grype-json"
    assert projection["source_id"] == "scanner-a"
    assert projection["source_record_id"] is None
    assert projection["vex_status"] == "fixed"
    assert projection["vex_match_type"] == "exact"
    assert projection["vex_source_path"] is None


def test_scope_projection_retains_the_only_explicit_asset_id() -> None:
    projection = _scope_projection_payload(
        _decision(),
        [
            _occurrence(asset_id=None),
            _occurrence(asset_id="asset-prod"),
        ],
    )

    assert projection["asset_id"] == "asset-prod"


def test_import_persistence_summary_and_chunk_helpers_are_stable() -> None:
    occurrences = [_occurrence(), _occurrence(cve_id="CVE-2021-44228")]

    assert (
        _analysis_semantics_summary(occurrences=occurrences, finding_count=2)[
            "same_cve_can_create_distinct_asset_findings"
        ]
        is True
    )
    assert _chunks(["a", "b", "c"], size=2) == [["a", "b"], ["c"]]
    assert _chunks_any([{"a": 1}, {"b": 2}, {"c": 3}], size=2) == [
        [{"a": 1}, {"b": 2}],
        [{"c": 3}],
    ]


def test_import_persistence_attack_context_helpers_prioritize_review_states() -> None:
    assert _valid_attack_tactic_ids(["TA0001", "T1059", "TA0040"]) == ["TA0001", "TA0040"]
    assert _attack_context_defensive_note(True).startswith("Use this ATT&CK context")
    assert _attack_context_defensive_note(False).startswith("No reviewed ATT&CK mapping")
    assert (
        _attack_context_review_status(
            "reviewed",
            mapped=True,
            mappings=[{"review_status": "stale"}, {"review_status": "reviewed"}],
        )
        == "stale"
    )
    assert _technique_ids_from_context(
        techniques=[{"attack_object_id": "T1059"}],
        mappings=[{"attack_object_id": "T1190"}],
        technique_models=[SimpleNamespace(attack_object_id="T1566")],
    ) == ["T1059", "T1190", "T1566"]


def test_import_persistence_jsonable_model_recurses_through_model_lists() -> None:
    model = _decision()

    assert _jsonable_model(model)["cve_id"] == "CVE-2024-3094"
    assert _jsonable_model((model,)) == [_jsonable_model(model)]


def test_import_persistence_preserves_manual_workflow_status_until_evidence_changes(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Workflow status")
    project_id = uuid.UUID(project["id"])
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories
    decision = _decision()
    occurrence = _occurrence()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="occurrences.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )

    with Session(workbench_api_env.engine) as session:
        run_repo = repositories.RunRepository(session)
        first_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="first.csv",
        )
        first_summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=first_run.id,
            occurrences=[occurrence],
            analysis_result=analysis_result,
        )
        finding_id = uuid.UUID(first_summary["dedup_summary"]["decisions"][0]["finding_id"])
        finding = session.get(app_models.Finding, finding_id)
        assert finding is not None
        assert finding.status == app_models.FindingStatus.OPEN

        finding.status = app_models.FindingStatus.REMEDIATING
        session.add(finding)
        second_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="second.csv",
        )
        second_summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=second_run.id,
            occurrences=[occurrence],
            analysis_result=analysis_result,
        )
        session.refresh(finding)
        assert second_summary["updated_findings"] == 1
        assert finding.status == app_models.FindingStatus.REMEDIATING
        assert second_summary["finding_evidence"][0].status == "remediating"

        fixed_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="fixed.csv",
        )
        fixed_decision = _decision(priority_state="Fixed")
        fixed_analysis_result = WorkbenchAnalysisResult(
            findings_by_cve={fixed_decision.cve_id: fixed_decision},
            context=analysis_result.context,
            provider_snapshot_id=None,
            provider_snapshot_hash=None,
            provider_snapshot_file=None,
            locked_provider_data=False,
        )
        fixed_summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=fixed_run.id,
            occurrences=[
                _occurrence(
                    raw_evidence={**occurrence.raw_evidence, "vex_status": "fixed"},
                )
            ],
            analysis_result=fixed_analysis_result,
        )
        session.refresh(finding)
        assert finding.status == app_models.FindingStatus.FIXED
        assert fixed_summary["finding_evidence"][0].status == "fixed"


def test_import_persistence_bulk_insert_fast_path_persists_large_new_import(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with workbench_api_env.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1

    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Bulk import")
    project_id = uuid.UUID(project["id"])
    app_models = workbench_api_env.app_models

    occurrences: list[NormalizedOccurrence] = []
    decisions: dict[str, PrioritizedFinding] = {}
    for index in range(1000):
        cve = f"CVE-2099-{index + 1000:04d}"
        occurrences.append(
            NormalizedOccurrence(
                cve_id=cve,
                target_ref=f"host-{index}",
                source="bulk-test",
                fix_version="2.0.0",
                raw_evidence={
                    "source_id": f"scanner-{index}",
                    "source_record_id": f"row-{index}",
                    "owner": "platform",
                    "business_service": "identity",
                    "environment": "Production",
                    "exposure": "internet",
                    "criticality": "critical",
                },
            )
        )
        decisions[cve] = _decision(
            cve_id=cve,
            priority_label="High",
            priority_rank=2,
            operational_rank=index + 1,
            cvss_base_score=8.8,
            cvss_severity="HIGH",
            epss=0.72,
        )
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve=decisions,
        context=AnalysisContext(
            input_path="bulk.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )

    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="bulk.csv",
        )
        analysis_evidence = app_models.AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=run.id,
        )
        session.add(analysis_evidence)
        session.flush()
        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=analysis_result,
            analysis_evidence_id=analysis_evidence.id,
        )
        session.commit()

    assert summary["occurrence_count"] == 1000
    assert summary["finding_count"] == 1000
    assert summary["created_findings"] == 1000
    assert summary["updated_findings"] == 0
    assert summary["dedup_summary"]["omitted_decisions"] == 500

    with Session(workbench_api_env.engine) as session:
        findings = session.exec(select(app_models.Finding)).all()
        assets = session.exec(select(app_models.Asset)).all()
        vulnerabilities = session.exec(select(app_models.Vulnerability)).all()
        occurrence_rows = session.exec(select(app_models.FindingOccurrence)).all()
        first_evidence = session.exec(
            select(app_models.FindingDecisionEvidence).where(
                app_models.FindingDecisionEvidence.cve_id == "CVE-2099-1000"
            )
        ).one()

    with workbench_api_env.engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []

    assert len(findings) == 1000
    assert len(assets) == 1000
    assert len(vulnerabilities) == 1000
    assert len(occurrence_rows) == 1000
    first_finding = next(finding for finding in findings if finding.cve_id == "CVE-2099-1000")
    assert first_finding.component_id is None
    assert summary["finding_evidence"] == []
    first_payload = first_evidence.payload_json
    assert first_payload["occurrences"][0]["dedup"]["action"] == "created"
    observation_key = first_payload["occurrences"][0]["dedup"]["observation_key"]
    assert observation_key.startswith(OBSERVATION_KEY_PREFIX)
    assert first_payload["occurrences"][0]["dedup"]["observation_key_version"] == "observation-v1"
    assert first_payload["occurrence_scope"]["target_ref"] == "host-0"


def test_bulk_asset_projection_matches_normal_path_for_conflicting_ordered_contexts(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Bulk asset projection parity",
    )
    project_id = uuid.UUID(project["id"])
    app_models = workbench_api_env.app_models

    def occurrence(
        cve_id: str,
        *,
        source_record_id: str,
        raw_evidence: dict[str, str] | None = None,
    ) -> NormalizedOccurrence:
        return NormalizedOccurrence(
            cve_id=cve_id,
            target_kind="host",
            target_ref="shared-asset",
            source="asset-projection-test",
            raw_evidence={
                "source_id": source_record_id,
                "source_record_id": source_record_id,
                **(raw_evidence or {}),
            },
        )

    low = occurrence(
        "CVE-2110-1000",
        source_record_id="low-z",
        raw_evidence={
            "asset_owner": "team-z",
            "asset_business_service": "service-z",
            "asset_environment": "development",
            "asset_exposure": "internal",
            "asset_criticality": "low",
        },
    )
    critical = occurrence(
        "CVE-2110-1001",
        source_record_id="critical-a",
        raw_evidence={
            "asset_owner": "team-a",
            "asset_business_service": "service-a",
            "asset_environment": "production",
            "asset_exposure": "internet-facing",
            "asset_criticality": "critical",
        },
    )
    fillers = [
        occurrence(
            f"CVE-2110-{index + 1002:04d}",
            source_record_id=f"filler-{index:04d}",
        )
        for index in range(998)
    ]

    def persisted_asset_snapshot(
        scoped_occurrences: list[NormalizedOccurrence],
        *,
        bulk: bool,
    ) -> dict[str, Any]:
        decisions = {item.cve_id: _decision(cve_id=item.cve_id) for item in scoped_occurrences}
        analysis_result = WorkbenchAnalysisResult(
            findings_by_cve=decisions,
            context=AnalysisContext(
                input_path="asset-projection.csv",
                output_format="json",
                generated_at="2026-09-04T00:00:00Z",
            ),
            provider_snapshot_id=None,
            provider_snapshot_hash=None,
            provider_snapshot_file=None,
            locked_provider_data=False,
        )
        with Session(workbench_api_env.engine) as session:
            run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename="asset-projection.csv",
            )
            if bulk:
                summary = _persist_workbench_occurrences_bulk_insert(
                    session=session,
                    project_id=project_id,
                    run_id=run.id,
                    occurrences=scoped_occurrences,
                    analysis_result=analysis_result,
                )
                assert summary is not None
            else:
                summary = _persist_workbench_occurrences(
                    session=session,
                    project_id=project_id,
                    run_id=run.id,
                    occurrences=scoped_occurrences,
                    analysis_result=analysis_result,
                )
            session.flush()
            assets = list(
                session.exec(
                    select(app_models.Asset).where(app_models.Asset.project_id == project_id)
                ).all()
            )
            findings = list(
                session.exec(
                    select(app_models.Finding).where(app_models.Finding.project_id == project_id)
                ).all()
            )
            assert summary["finding_count"] == len(scoped_occurrences)
            assert len(assets) == 1
            assert {finding.asset_id for finding in findings} == {assets[0].id}
            asset = assets[0]
            return {
                "asset_key": asset.asset_key,
                "name": asset.name,
                "target_ref": asset.target_ref,
                "owner": asset.owner,
                "business_service": asset.business_service,
                "environment": str(asset.environment),
                "exposure": str(asset.exposure),
                "criticality": str(asset.criticality),
            }

    normal_forward = persisted_asset_snapshot([low, critical], bulk=False)
    normal_reverse = persisted_asset_snapshot([critical, low], bulk=False)
    bulk_forward = persisted_asset_snapshot([low, critical, *fillers], bulk=True)
    bulk_reverse = persisted_asset_snapshot(
        list(reversed([low, critical, *fillers])),
        bulk=True,
    )

    assert normal_forward == normal_reverse == bulk_forward == bulk_reverse
    assert bulk_forward == {
        "asset_key": _preferred_asset_storage_key(low),
        "name": "shared-asset",
        "target_ref": "shared-asset",
        "owner": "team-a",
        "business_service": "service-a",
        "environment": "production",
        "exposure": "internet-facing",
        "criticality": "critical",
    }


def test_import_persistence_converges_legacy_key_on_exact_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Legacy convergence")
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    occurrence = _occurrence()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="legacy.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )

    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        first_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="legacy-first.csv",
        )
        first = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=first_run.id,
            occurrences=[occurrence],
            analysis_result=analysis_result,
        )
        finding_id = uuid.UUID(first["dedup_summary"]["decisions"][0]["finding_id"])
        finding = session.get(workbench_api_env.app_models.Finding, finding_id)
        assert finding is not None
        finding.dedup_key = "vpw019:legacy-source-sensitive-key"
        session.add(finding)
        session.commit()

        second_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="legacy-second.csv",
        )
        second = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=second_run.id,
            occurrences=[occurrence],
            analysis_result=analysis_result,
        )
        session.flush()
        session.refresh(finding)

    assert second["created_findings"] == 0
    assert second["updated_findings"] == 1
    assert second["dedup_summary"]["decisions"][0]["finding_id"] == str(finding_id)
    assert finding.dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)


def test_raw_sidecar_upgrade_raw_reuses_finding_and_promotes_asset_in_place(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Asset upgrade")
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="asset-upgrade.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    raw = _occurrence(
        target_kind="host",
        target_ref="prod-app",
        asset_id=None,
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "raw-first",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "rpm",
            "target_kind": "host",
            "target_ref": "prod-app",
        },
    )
    enriched = _occurrence(
        target_kind="host",
        target_ref="prod-app",
        asset_id="asset-prod",
        raw_evidence={
            **dict(raw.raw_evidence),
            "source_record_id": "with-sidecar",
            "asset_id": "asset-prod",
            "asset_owner": "team-platform",
            "asset_environment": "prod",
            "asset_criticality": "critical",
        },
    )
    raw_again = _occurrence(
        target_kind="host",
        target_ref="prod-app",
        raw_evidence={
            **dict(raw.raw_evidence),
            "source_record_id": "raw-again",
        },
    )

    summaries: list[dict[str, Any]] = []
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        for index, occurrence in enumerate((raw, enriched, raw_again), start=1):
            run = run_repo.create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename=f"asset-upgrade-{index}.csv",
            )
            summaries.append(
                _persist_workbench_occurrences(
                    session=session,
                    project_id=project_id,
                    run_id=run.id,
                    occurrences=[occurrence],
                    analysis_result=analysis_result,
                )
            )
            session.flush()

        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )
        persisted_occurrences = list(
            session.exec(select(workbench_api_env.app_models.FindingOccurrence)).all()
        )

    finding_ids = [summary["dedup_summary"]["decisions"][0]["finding_id"] for summary in summaries]
    assert len(set(finding_ids)) == 1
    assert [summary["created_findings"] for summary in summaries] == [1, 0, 0]
    assert [summary["updated_findings"] for summary in summaries] == [0, 1, 1]
    assert len(findings) == 1
    assert len(assets) == 1
    assert assets[0].asset_key == "asset-prod"
    assert findings[0].asset_id == assets[0].id
    assert len(persisted_occurrences) == 3
    assert {item.evidence_json["target_ref"] for item in persisted_occurrences} == {"prod-app"}


def test_sidecar_identity_change_does_not_rename_shared_implicit_asset(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Shared implicit asset identity change",
    )
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="shared-implicit-asset.csv",
            output_format="json",
            generated_at="2026-09-04T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    first_scope = _occurrence(
        component_name="component-a",
        component_version="1",
        target_kind="host",
        target_ref="shared-host",
        asset_id=None,
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "first-scope",
            "purl": "pkg:generic/component-a@1",
            "package_type": "generic",
            "target_kind": "host",
            "target_ref": "shared-host",
        },
    )
    second_scope = _occurrence(
        component_name="component-b",
        component_version="1",
        target_kind="host",
        target_ref="shared-host",
        asset_id=None,
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "second-scope",
            "purl": "pkg:generic/component-b@1",
            "package_type": "generic",
            "target_kind": "host",
            "target_ref": "shared-host",
        },
    )
    remapped_first_scope = _occurrence(
        component_name="component-a",
        component_version="1",
        target_kind="host",
        target_ref="shared-host",
        asset_id="canonical-a",
        raw_evidence={
            **dict(first_scope.raw_evidence),
            "source_record_id": "first-scope-remapped",
            "asset_id": "canonical-a",
        },
    )

    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        initial_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="shared-implicit-asset-initial.csv",
        )
        initial = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=initial_run.id,
            occurrences=[first_scope, second_scope],
            analysis_result=analysis_result,
        )
        session.flush()

        components_by_id = {
            component.id: component.name
            for component in session.exec(select(workbench_api_env.app_models.Component)).all()
        }
        initial_findings_by_component = {
            components_by_id[finding.component_id]: finding
            for finding in session.exec(select(workbench_api_env.app_models.Finding)).all()
        }
        initial_first = initial_findings_by_component["component-a"]
        initial_second = initial_findings_by_component["component-b"]
        initial_first_snapshot = (initial_first.id, initial_first.dedup_key)
        initial_second_snapshot = (
            initial_second.id,
            initial_second.asset_id,
            initial_second.dedup_key,
            initial_second.status,
            initial_second.last_seen_at,
        )
        shared_asset_id = initial_second.asset_id
        assert shared_asset_id is not None
        assert initial_first.asset_id == shared_asset_id

        remap_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="shared-implicit-asset-remap.csv",
        )
        remapped = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=remap_run.id,
            occurrences=[remapped_first_scope],
            analysis_result=analysis_result,
        )
        session.flush()

        assets = list(session.exec(select(workbench_api_env.app_models.Asset)).all())
        assets_by_id = {asset.id: asset for asset in assets}
        persisted_findings_by_component = {
            components_by_id[finding.component_id]: finding
            for finding in session.exec(select(workbench_api_env.app_models.Finding)).all()
        }
        persisted_first = persisted_findings_by_component["component-a"]
        persisted_second = persisted_findings_by_component["component-b"]

    assert initial["created_findings"] == 2
    assert initial["updated_findings"] == 0
    assert remapped["created_findings"] == 0
    assert remapped["updated_findings"] == 1
    assert remapped["dedup_summary"]["decisions"][0]["finding_id"] == str(initial_first_snapshot[0])
    assert (persisted_first.id, persisted_first.dedup_key) == initial_first_snapshot
    assert persisted_first.asset_id is not None
    assert persisted_first.asset_id != shared_asset_id
    assert assets_by_id[persisted_first.asset_id].asset_key == "canonical-a"
    assert (
        persisted_second.id,
        persisted_second.asset_id,
        persisted_second.dedup_key,
        persisted_second.status,
        persisted_second.last_seen_at,
    ) == initial_second_snapshot
    assert assets_by_id[shared_asset_id].asset_key == "host:shared-host"
    assert {asset.asset_key for asset in assets} == {"host:shared-host", "canonical-a"}


def test_sidecar_identity_change_does_not_rename_shared_explicit_asset(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(
        workbench_api_env.client,
        headers,
        name="Shared asset identity change",
    )
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="shared-asset.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    first_scope = _occurrence(
        target_kind="host",
        target_ref="prod-app-a",
        asset_id="old-id",
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "first-scope",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "rpm",
            "target_kind": "host",
            "target_ref": "prod-app-a",
            "asset_id": "old-id",
        },
    )
    second_scope = _occurrence(
        target_kind="host",
        target_ref="prod-app-b",
        asset_id="old-id",
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "second-scope",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "rpm",
            "target_kind": "host",
            "target_ref": "prod-app-b",
            "asset_id": "old-id",
        },
    )
    remapped_first_scope = _occurrence(
        target_kind="host",
        target_ref="prod-app-a",
        asset_id="new-id",
        raw_evidence={
            **dict(first_scope.raw_evidence),
            "source_record_id": "first-scope-remapped",
            "asset_id": "new-id",
        },
    )

    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        initial_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="shared-asset-initial.csv",
        )
        initial = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=initial_run.id,
            occurrences=[first_scope, second_scope],
            analysis_result=analysis_result,
        )
        remap_run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="shared-asset-remap.csv",
        )
        remapped = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=remap_run.id,
            occurrences=[remapped_first_scope],
            analysis_result=analysis_result,
        )
        session.flush()

        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )

    initial_ids = {item["finding_id"] for item in initial["dedup_summary"]["decisions"]}
    assert remapped["dedup_summary"]["decisions"][0]["finding_id"] in initial_ids
    assert remapped["created_findings"] == 0
    assert remapped["updated_findings"] == 1
    assert {asset.asset_key for asset in assets} == {"old-id", "new-id"}
    assets_by_id = {asset.id: asset for asset in assets}
    finding_asset_keys = {assets_by_id[finding.asset_id].asset_key for finding in findings}
    assert finding_asset_keys == {"old-id", "new-id"}


def test_component_repository_and_import_cache_share_canonical_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        legacy_purl_identity = normalize_component_persistence_identity(
            name="Legacy Django",
            version="3.0.0",
            purl=" PKG:PYPI/Django@3.0.0 ",
            ecosystem="PYPI",
            package_type="PYPI",
        )
        legacy_purl = workbench_api_env.app_models.Component(
            name="Legacy Django",
            version="3.0.0",
            purl=" PKG:PYPI/Django@3.0.0 ",
            ecosystem="PYPI",
            package_type="PYPI",
            identity_key=legacy_purl_identity.storage_key,
            identity_material=legacy_purl_identity.scope_key,
        )
        legacy_name_identity = normalize_component_persistence_identity(
            name=" Lib XML ",
            version=" 2.0.0 ",
            ecosystem=" RPM ",
            package_type=" RPM ",
        )
        legacy_name = workbench_api_env.app_models.Component(
            name=" Lib XML ",
            version=" 2.0.0 ",
            purl=None,
            ecosystem=" RPM ",
            package_type=" RPM ",
            identity_key=legacy_name_identity.storage_key,
            identity_material=legacy_name_identity.scope_key,
        )
        session.add(legacy_purl)
        session.add(legacy_name)
        session.flush()

        purl_match = repository.upsert_component(
            name="django",
            version="3.0.0",
            purl="pkg:pypi/django@3.0.0",
            ecosystem="pypi",
            package_type="pypi",
        )
        name_match = repository.upsert_component(
            name="lib xml",
            version="2.0.0",
            ecosystem="rpm",
            package_type="rpm",
        )

        assert purl_match.id == legacy_purl.id
        assert purl_match.name == "django"
        assert purl_match.version == "3.0.0"
        assert purl_match.purl == "pkg:pypi/django@3.0.0"
        assert purl_match.ecosystem == "pypi"
        assert purl_match.package_type == "pypi"
        assert name_match.id == legacy_name.id
        assert name_match.name == "lib xml"
        assert name_match.version == "2.0.0"
        assert name_match.ecosystem == "rpm"
        assert name_match.package_type == "rpm"
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 2


def test_shared_component_projection_is_stable_across_finding_scope_order() -> None:
    zulu = _occurrence(
        component_name="Zulu Component",
        target_kind="host",
        target_ref="host-z",
    )
    alpha = _occurrence(
        component_name="Alpha Component",
        target_kind="host",
        target_ref="host-a",
    )

    forward = _canonical_component_projection([zulu, alpha])
    reverse = _canonical_component_projection([alpha, zulu])

    assert forward == reverse
    assert forward.name == "Alpha Component"
    assert forward.purl == "pkg:rpm/xz-utils@5.6.0"


def test_purl_only_scopes_persist_distinct_canonical_components(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="PURL-only scopes")
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="purl-only.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    occurrences = [
        _occurrence(
            component_name=None,
            component_version=None,
            raw_evidence={
                "source_id": "scanner-a",
                "source_record_id": "record-a",
                "purl": " PKG:PYPI/LIB-A@1 ",
                "package_type": " PYPI ",
            },
        ),
        _occurrence(
            component_name=None,
            component_version=None,
            raw_evidence={
                "source_id": "scanner-b",
                "source_record_id": "record-b",
                "purl": "pkg:pypi/lib-a@1",
                "package_type": "pypi",
            },
        ),
        _occurrence(
            component_name=None,
            component_version=None,
            raw_evidence={
                "source_id": "scanner-c",
                "source_record_id": "record-c",
                "purl": "pkg:pypi/lib-b@1",
                "package_type": "pypi",
            },
        ),
    ]

    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="purl-only.csv",
        )
        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=analysis_result,
        )
        session.flush()
        findings = list(session.exec(select(workbench_api_env.app_models.Finding)).all())
        components = list(session.exec(select(workbench_api_env.app_models.Component)).all())

    assert summary["occurrence_count"] == 3
    assert summary["finding_count"] == 2
    assert summary["created_findings"] == 2
    assert summary["updated_findings"] == 0
    decision_ids = [item["finding_id"] for item in summary["dedup_summary"]["decisions"]]
    assert decision_ids[0] == decision_ids[1]
    assert decision_ids[2] != decision_ids[0]
    assert len(findings) == 2
    assert len({finding.component_id for finding in findings}) == 2
    assert {component.purl for component in components} == {
        "pkg:pypi/lib-a@1",
        "pkg:pypi/lib-b@1",
    }
    assert {component.name for component in components} == {"lib-a", "lib-b"}


def test_scope_projection_and_unique_run_counts_are_input_order_independent(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Stable scope")
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="stable-scope.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    low = _occurrence(
        component_name="Zulu Component",
        component_version="5.6.9",
        source="scanner-z-format",
        raw_evidence={
            "source_id": "scanner-z",
            "source_record_id": "record-z",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "deb",
            "asset_criticality": "low",
            "asset_exposure": "internal",
            "asset_environment": "dev",
            "asset_owner": "team-z",
            "asset_business_service": "service-z",
            "vex_status": "fixed",
            "vex_match_type": "exact-z",
            "vex_source_path": "/vex/z.json",
        },
    )
    critical = _occurrence(
        component_name="Alpha Component",
        component_version="5.6.0",
        source="scanner-a-format",
        raw_evidence={
            "source_id": "scanner-a",
            "source_record_id": "record-a",
            "purl": "pkg:rpm/xz-utils@5.6.0",
            "package_type": "rpm",
            "asset_criticality": "critical",
            "asset_exposure": "internet-facing",
            "asset_environment": "prod",
            "asset_owner": "team-a",
            "asset_business_service": "service-a",
            "vex_status": "under_investigation",
            "vex_match_type": "exact-a",
            "vex_source_path": "/vex/a.json",
        },
    )

    summaries: list[dict[str, Any]] = []
    asset_snapshots: list[dict[str, Any]] = []
    component_snapshots: list[dict[str, Any]] = []
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        for index, scoped_occurrences in enumerate(
            ([low, critical], [critical, low]),
            start=1,
        ):
            run = run_repo.create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename=f"stable-scope-{index}.csv",
            )
            summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=run.id,
                occurrences=scoped_occurrences,
                analysis_result=analysis_result,
            )
            session.flush()
            finding_id = uuid.UUID(summary["dedup_summary"]["decisions"][0]["finding_id"])
            finding = session.get(workbench_api_env.app_models.Finding, finding_id)
            assert (
                finding is not None
                and finding.asset_id is not None
                and finding.component_id is not None
            )
            asset = session.get(workbench_api_env.app_models.Asset, finding.asset_id)
            component = session.get(
                workbench_api_env.app_models.Component,
                finding.component_id,
            )
            assert asset is not None
            assert component is not None
            summaries.append(summary)
            asset_snapshots.append(
                {
                    "owner": asset.owner,
                    "business_service": asset.business_service,
                    "environment": str(asset.environment),
                    "exposure": str(asset.exposure),
                    "criticality": str(asset.criticality),
                }
            )
            component_snapshots.append(
                {
                    "name": component.name,
                    "version": component.version,
                    "purl": component.purl,
                    "ecosystem": component.ecosystem,
                    "package_type": component.package_type,
                }
            )

    assert summaries[0]["created_findings"] == 1
    assert summaries[0]["updated_findings"] == 0
    assert summaries[1]["created_findings"] == 0
    assert summaries[1]["updated_findings"] == 1
    assert all(
        summary["created_findings"] + summary["updated_findings"] == summary["finding_count"]
        for summary in summaries
    )
    assert summaries[1]["dedup_summary"]["reused_findings"] == 1
    first_scope = summaries[0]["finding_evidence"][0].occurrence_scope.model_dump()
    second_scope = summaries[1]["finding_evidence"][0].occurrence_scope.model_dump()
    assert first_scope == second_scope
    assert first_scope["source"] is None
    assert first_scope["source_id"] is None
    assert first_scope["source_record_id"] is None
    assert first_scope["vex_status"] is None
    assert first_scope["vex_match_type"] is None
    assert first_scope["vex_source_path"] is None
    assert first_scope["asset_owner"] == "team-a"
    assert first_scope["asset_business_service"] == "service-a"
    assert first_scope["asset_environment"] == "production"
    assert first_scope["asset_exposure"] == "internet-facing"
    assert first_scope["asset_criticality"] == "critical"
    assert asset_snapshots == [
        {
            "owner": "team-a",
            "business_service": "service-a",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
        {
            "owner": "team-a",
            "business_service": "service-a",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    ]
    assert component_snapshots[0] == component_snapshots[1]
    assert component_snapshots[0] == {
        "name": first_scope["component_name"],
        "version": first_scope["component_version"],
        "purl": str(first_scope["purl"]).casefold(),
        "ecosystem": "rpm",
        "package_type": "rpm",
    }
    occurrence_evidence = summaries[0]["finding_evidence"][0].occurrences
    assert {item.source for item in occurrence_evidence} == {
        "scanner-a-format",
        "scanner-z-format",
    }
    assert {item.source_id for item in occurrence_evidence} == {"scanner-a", "scanner-z"}
    assert {item.source_record_id for item in occurrence_evidence} == {
        "record-a",
        "record-z",
    }
    assert {item.vex_status for item in occurrence_evidence} == {
        "fixed",
        "under_investigation",
    }
    assert {item.vex_match_type for item in occurrence_evidence} == {"exact-a", "exact-z"}
    assert {item.vex_source_path for item in occurrence_evidence} == {
        "/vex/a.json",
        "/vex/z.json",
    }


def test_new_scope_import_batches_legacy_identity_lookup(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers, name="Batch lookup")
    project_id = uuid.UUID(project["id"])
    decision = _decision()
    analysis_result = WorkbenchAnalysisResult(
        findings_by_cve={decision.cve_id: decision},
        context=AnalysisContext(
            input_path="batch.csv",
            output_format="json",
            generated_at="2026-05-08T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )
    occurrences = [_occurrence(target_ref=f"host-{index}") for index in range(25)]
    finding_selects: list[str] = []

    def count_finding_selects(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        normalized_statement = " ".join(statement.lower().split())
        if normalized_statement.startswith("select") and " from finding" in normalized_statement:
            finding_selects.append(statement)

    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="batch.csv",
        )
        event.listen(
            workbench_api_env.engine,
            "before_cursor_execute",
            count_finding_selects,
        )
        try:
            summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=run.id,
                occurrences=occurrences,
                analysis_result=analysis_result,
            )
        finally:
            event.remove(
                workbench_api_env.engine,
                "before_cursor_execute",
                count_finding_selects,
            )

    assert summary["finding_count"] == 25
    assert 1 <= len(finding_selects) <= 2


def test_reimport_select_count_stays_bounded_when_rows_double(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    """Guard the complete persistence path against row-wise re-import reads."""

    def measure_reimport(row_count: int) -> tuple[int, list[str]]:
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(
            workbench_api_env.client,
            headers,
            name=f"Bounded re-import {row_count}",
        )
        project_id = uuid.UUID(project["id"])
        occurrences = [
            _occurrence(
                cve_id=f"CVE-2026-{row_count * 1000 + index}",
                component_name=f"component-{row_count}-{index}",
                component_version="1.0.0",
                target_ref=f"host-{row_count}-{index}",
                raw_evidence={
                    "source_id": f"scanner-{row_count}",
                    "source_record_id": f"finding-{row_count}-{index}",
                    "purl": f"pkg:generic/component-{row_count}-{index}@1.0.0",
                    "package_type": "generic",
                    "environment": "production",
                    "exposure": "internet-facing",
                    "criticality": "high",
                },
            )
            for index in range(row_count)
        ]
        decisions = {
            occurrence.cve_id: _decision(cve_id=occurrence.cve_id) for occurrence in occurrences
        }
        analysis_result = WorkbenchAnalysisResult(
            findings_by_cve=decisions,
            context=AnalysisContext(
                input_path=f"bounded-{row_count}.csv",
                output_format="json",
                generated_at="2026-09-04T00:00:00Z",
            ),
            provider_snapshot_id=None,
            provider_snapshot_hash=None,
            provider_snapshot_file=None,
            locked_provider_data=False,
        )

        with Session(workbench_api_env.engine) as session:
            run_repo = workbench_api_env.repositories.RunRepository(session)
            evidence_repo = workbench_api_env.repositories.EvidenceRepository(session)
            initial_run = run_repo.create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename=f"initial-{row_count}.csv",
            )
            initial_analysis_evidence = evidence_repo.prepare_analysis_evidence_record(
                project_id=project_id,
                analysis_run_id=initial_run.id,
                provider_snapshot_id=None,
            )
            initial_summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=initial_run.id,
                occurrences=occurrences,
                analysis_result=analysis_result,
                analysis_evidence_id=initial_analysis_evidence.id,
            )
            evidence_repo.replace_finding_decision_evidence(
                analysis_evidence_id=initial_analysis_evidence.id,
                project_id=project_id,
                analysis_run_id=initial_run.id,
                evidence_items=initial_summary["finding_evidence"],
            )
            session.commit()

        with Session(workbench_api_env.engine) as session:
            run_repo = workbench_api_env.repositories.RunRepository(session)
            evidence_repo = workbench_api_env.repositories.EvidenceRepository(session)
            reimport_run = run_repo.create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename=f"reimport-{row_count}.csv",
            )
            reimport_analysis_evidence = evidence_repo.prepare_analysis_evidence_record(
                project_id=project_id,
                analysis_run_id=reimport_run.id,
                provider_snapshot_id=None,
            )
            reimport_run_id = reimport_run.id
            reimport_analysis_evidence_id = reimport_analysis_evidence.id
            session.commit()

        select_statements: list[str] = []

        def collect_selects(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: object,
        ) -> None:
            if statement.lstrip().lower().startswith("select"):
                select_statements.append(" ".join(statement.lower().split()))

        with Session(workbench_api_env.engine) as session:
            event.listen(workbench_api_env.engine, "before_cursor_execute", collect_selects)
            try:
                summary = _persist_workbench_occurrences(
                    session=session,
                    project_id=project_id,
                    run_id=reimport_run_id,
                    occurrences=occurrences,
                    analysis_result=analysis_result,
                    analysis_evidence_id=reimport_analysis_evidence_id,
                )
                workbench_api_env.repositories.EvidenceRepository(
                    session
                ).replace_finding_decision_evidence(
                    analysis_evidence_id=reimport_analysis_evidence_id,
                    project_id=project_id,
                    analysis_run_id=reimport_run_id,
                    evidence_items=summary["finding_evidence"],
                )
                session.commit()
            finally:
                event.remove(workbench_api_env.engine, "before_cursor_execute", collect_selects)

        assert summary["created_findings"] == 0
        assert summary["updated_findings"] == row_count
        return len(select_statements), select_statements

    count_25, statements_25 = measure_reimport(25)
    count_50, statements_50 = measure_reimport(50)

    assert count_25 <= 10, statements_25
    assert count_50 <= count_25 + 1, statements_50
