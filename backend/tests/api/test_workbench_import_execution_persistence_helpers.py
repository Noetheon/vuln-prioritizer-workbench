from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlmodel import Session, select
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.importers.contracts import NormalizedOccurrence
from app.services import WorkbenchAnalysisResult
from app.services.import_execution_dedup import _dedup_key_parts, _finding_dedup_key
from app.services.import_execution_persistence import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _attack_context_defensive_note,
    _attack_context_review_status,
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
from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding


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
        "cve": "CVE-2024-3094",
        "component": "xz-utils",
        "version": "5.6.0",
        "asset_ref": "build-host-1",
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


def test_import_persistence_dedup_key_uses_source_component_asset_scope() -> None:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    parts = _dedup_key_parts(project_id, _occurrence(asset_ref=" build-host-1 "))

    assert parts == {
        "project_id": str(project_id),
        "source_id": "scanner-a",
        "component_identity": "pkg:rpm/xz-utils@5.6.0",
        "asset_ref": "build-host-1",
    }
    assert _finding_dedup_key(parts).startswith("vpw019:")
    assert _finding_dedup_key(parts) == _finding_dedup_key(dict(reversed(parts.items())))


def test_import_persistence_dedup_key_falls_back_to_component_identity() -> None:
    project_id = uuid.UUID("00000000-0000-4000-8000-000000000123")
    parts = _dedup_key_parts(
        project_id,
        _occurrence(raw_evidence={"source_id": "scanner-a", "package_type": "deb"}),
    )

    assert parts["component_identity"] == "component|xz-utils|5.6.0|deb"


def test_import_persistence_vex_status_overlays_decision_state() -> None:
    suppressed_decision = _decision(suppressed_by_vex=True, priority_state="Suppressed")
    open_occurrence = _occurrence(raw_evidence={})
    fixed_occurrence = _occurrence(raw_evidence={"vex_status": "fixed"})
    not_affected_occurrence = _occurrence(raw_evidence={"vex_status": "not_affected"})

    assert _finding_status_for_occurrence(suppressed_decision, open_occurrence).value == "open"
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, open_occurrence) is False
    assert (
        _priority_state_for_occurrence(
            suppressed_decision,
            open_occurrence,
            base_priority_state=suppressed_decision.priority_state,
        )
        == "Open"
    )
    assert _finding_status_for_occurrence(suppressed_decision, fixed_occurrence).value == "fixed"
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, fixed_occurrence) is True
    assert (
        _finding_status_for_occurrence(suppressed_decision, not_affected_occurrence).value
        == "suppressed"
    )
    assert _suppressed_by_vex_for_occurrence(suppressed_decision, not_affected_occurrence) is True


def test_import_persistence_payload_helpers_include_occurrence_scope_and_evidence() -> None:
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

    decision_payload = _decision_payload_for_occurrence(decision, occurrence, compact=True)
    evidence = _analysis_evidence_for_occurrence(
        result,
        decision,
        occurrence,
        priority_state=decision_payload["priority_state"],
    )

    assert decision_payload["occurrence_scope"]["source_id"] == "scanner-a"
    assert decision_payload["priority_state"] == "Fixed"
    assert evidence["provider_snapshot_hash"] == "snapshot-hash"
    assert evidence["occurrence_vex_status"] == "fixed"
    assert evidence["priority_state"] == "Fixed"


def test_import_persistence_summary_and_chunk_helpers_are_stable() -> None:
    occurrences = [_occurrence(), _occurrence(cve="CVE-2021-44228")]

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


def test_import_persistence_bulk_insert_fast_path_persists_large_new_import(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
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
                cve=cve,
                asset_ref=f"asset-{index}",
                source="bulk-test",
                fix_version="2.0.0",
                raw_evidence={
                    "source_id": f"scanner-{index}",
                    "source_record_id": f"row-{index}",
                    "target_ref": f"host-{index}",
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
        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=analysis_result,
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

    assert len(findings) == 1000
    assert len(assets) == 1000
    assert len(vulnerabilities) == 1000
    assert len(occurrence_rows) == 1000
    first_finding = next(finding for finding in findings if finding.cve_id == "CVE-2099-1000")
    assert first_finding.component_id is None
    assert first_finding.evidence_json["dedup"]["action"] == "created"
    assert first_finding.explanation_json["occurrence_scope"]["target_ref"] == "host-0"
