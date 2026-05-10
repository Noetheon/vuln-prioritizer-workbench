"""Persistence orchestration facade for Workbench imports."""

from __future__ import annotations

# ruff: noqa: F401
import uuid
from typing import Any

from sqlmodel import Session

from app.domain.import_asset_context import (
    asset_criticality_from_evidence as _asset_criticality,
)
from app.domain.import_asset_context import (
    asset_environment_from_evidence as _asset_environment,
)
from app.domain.import_asset_context import asset_exposure_from_evidence as _asset_exposure
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.repositories import AssetRepository, FindingRepository, RunRepository
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_dedup import _dedup_key_parts, _finding_dedup_key
from app.services.import_execution_persistence_attack import (
    _attack_context_defensive_note,
    _attack_context_enabled,
    _attack_context_review_status,
    _persist_workbench_finding_attack_context,
    _technique_ids_from_context,
    _valid_attack_tactic_ids,
)
from app.services.import_execution_persistence_bulk import (
    _persist_workbench_occurrences_bulk_insert,
)
from app.services.import_execution_persistence_common import DEDUP_DECISION_SAMPLE_LIMIT
from app.services.import_execution_persistence_payloads import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _decision_cvss_vector,
    _decision_cwe,
    _decision_data_quality_json,
    _decision_for_occurrence,
    _decision_modified,
    _decision_payload_for_occurrence,
    _decision_priority,
    _decision_provider_json,
    _decision_published,
    _finding_status_for_occurrence,
    _jsonable_model,
    _occurrence_scope_payload,
    _priority_state_for_occurrence,
    _suppressed_by_vex_for_occurrence,
)
from app.services.import_execution_persistence_queries import (
    _chunks,
    _chunks_any,
    _existing_findings_by_dedup_key,
)


def _persist_workbench_occurrences(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: WorkbenchAnalysisResult,
) -> dict[str, Any]:
    bulk_summary = _persist_workbench_occurrences_bulk_insert(
        session=session,
        project_id=project_id,
        run_id=run_id,
        occurrences=occurrences,
        analysis_result=analysis_result,
    )
    if bulk_summary is not None:
        return bulk_summary

    asset_repo = AssetRepository(session)
    finding_repo = FindingRepository(session)
    run_repo = RunRepository(session)
    decisions: list[dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    touched_finding_ids: set[str] = set()
    attack_context_finding_ids: set[uuid.UUID] = set()
    dedup_keys = [
        _finding_dedup_key(_dedup_key_parts(project_id, occurrence)) for occurrence in occurrences
    ]
    findings_by_dedup_key = _existing_findings_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=dedup_keys,
    )
    assets_by_key: dict[str, Any] = {}
    components_by_key: dict[tuple[str, str, str, str], Any] = {}
    vulnerabilities_by_cve: dict[str, Any] = {}
    data_quality_by_cve: dict[str, dict[str, Any]] = {}
    with session.no_autoflush:
        for index, occurrence in enumerate(occurrences, start=1):
            decision = _decision_for_occurrence(analysis_result, occurrence)
            occurrence_scope = _occurrence_scope_payload(occurrence)
            decision_payload = _decision_payload_for_occurrence(
                decision,
                occurrence,
                occurrence_scope=occurrence_scope,
            )
            data_quality_payload = data_quality_by_cve.get(occurrence.cve)
            if data_quality_payload is None:
                data_quality_payload = _decision_data_quality_json(decision)
                data_quality_by_cve[occurrence.cve] = data_quality_payload
            dedup_parts = _dedup_key_parts(project_id, occurrence)
            dedup_key = _finding_dedup_key(dedup_parts)
            asset = None
            if occurrence.asset_ref:
                asset = assets_by_key.get(occurrence.asset_ref)
                if asset is None:
                    asset = asset_repo.upsert_asset(
                        project_id=project_id,
                        asset_key=occurrence.asset_ref,
                        name=occurrence.asset_ref,
                        target_ref=_string_evidence(occurrence.raw_evidence, "target_ref"),
                        owner=_string_evidence(occurrence.raw_evidence, "owner"),
                        business_service=_string_evidence(
                            occurrence.raw_evidence,
                            "business_service",
                        ),
                        environment=_asset_environment(occurrence.raw_evidence),
                        exposure=_asset_exposure(occurrence.raw_evidence),
                        criticality=_asset_criticality(occurrence.raw_evidence),
                        flush=False,
                    )
                    assets_by_key[occurrence.asset_ref] = asset
            component = None
            if occurrence.component:
                component_key = (
                    occurrence.component,
                    occurrence.version or "",
                    _string_evidence(occurrence.raw_evidence, "purl") or "",
                    _string_evidence(occurrence.raw_evidence, "package_type") or "",
                )
                component = components_by_key.get(component_key)
                if component is None:
                    component = finding_repo.upsert_component(
                        name=occurrence.component,
                        version=occurrence.version,
                        purl=_string_evidence(occurrence.raw_evidence, "purl"),
                        ecosystem=_string_evidence(occurrence.raw_evidence, "package_type"),
                        package_type=_string_evidence(occurrence.raw_evidence, "package_type"),
                        flush=False,
                    )
                    components_by_key[component_key] = component
            vulnerability = vulnerabilities_by_cve.get(occurrence.cve)
            if vulnerability is None:
                vulnerability = finding_repo.upsert_vulnerability(
                    cve_id=occurrence.cve,
                    source_id=dedup_parts["source_id"],
                    title=occurrence.cve,
                    description=decision.description,
                    cvss_score=decision.cvss_base_score,
                    cvss_vector=_decision_cvss_vector(decision),
                    severity=(
                        decision.cvss_severity
                        or _string_evidence(occurrence.raw_evidence, "severity")
                    ),
                    cwe=_decision_cwe(decision),
                    published_at=_decision_published(decision),
                    modified_at=_decision_modified(decision),
                    provider_json=_decision_provider_json(decision),
                    flush=False,
                )
                vulnerabilities_by_cve[occurrence.cve] = vulnerability
            existing_finding = findings_by_dedup_key.get(dedup_key)
            action = "reused" if existing_finding is not None else "created"
            finding = finding_repo.create_or_update_finding(
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                cve_id=occurrence.cve,
                dedup_key=dedup_key,
                component_id=component.id if component else None,
                asset_id=asset.id if asset else None,
                status=_finding_status_for_occurrence(decision, occurrence),
                priority=_decision_priority(decision),
                priority_rank=decision.priority_rank,
                risk_score=float(decision.operational_score),
                operational_rank=decision.operational_rank or index,
                in_kev=decision.in_kev,
                epss=decision.epss,
                cvss_base_score=decision.cvss_base_score,
                attack_mapped=decision.attack_mapped,
                suppressed_by_vex=_suppressed_by_vex_for_occurrence(decision, occurrence),
                under_investigation=decision.under_investigation,
                waived=decision.waived,
                recommended_action=decision.recommended_action,
                rationale=decision.rationale,
                explanation_json=decision_payload,
                data_quality_json=data_quality_payload,
                evidence_json={
                    "import": dict(occurrence.raw_evidence),
                    "analysis": _analysis_evidence_for_occurrence(
                        analysis_result,
                        decision,
                        occurrence,
                        priority_state=decision_payload.get("priority_state"),
                        occurrence_scope=occurrence_scope,
                    ),
                    "dedup": {
                        "key": dedup_key,
                        "key_version": "vpw019-v1",
                        "action": action,
                        "parts": dedup_parts,
                    },
                },
                existing_finding=existing_finding,
                lookup_existing=False,
                flush=False,
            )
            findings_by_dedup_key[dedup_key] = finding
            if finding.id not in attack_context_finding_ids and _attack_context_enabled(
                analysis_result,
                decision,
            ):
                _persist_workbench_finding_attack_context(
                    session=session,
                    run_id=run_id,
                    finding_id=finding.id,
                    decision=decision,
                )
                attack_context_finding_ids.add(finding.id)
            if action == "created":
                created_count += 1
            else:
                reused_count += 1
            touched_finding_ids.add(str(finding.id))
            run_repo.add_finding_occurrence(
                finding_id=finding.id,
                analysis_run_id=run_id,
                source=occurrence.source,
                raw_reference=_string_evidence(occurrence.raw_evidence, "source_record_id"),
                fix_version=occurrence.fix_version,
                evidence_json={
                    **dict(occurrence.raw_evidence),
                    "dedup_key": dedup_key,
                    "dedup_action": action,
                },
                flush=False,
            )
            if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
                decisions.append(
                    {
                        "action": action,
                        "dedup_key": dedup_key,
                        "finding_id": str(finding.id),
                        "cve": occurrence.cve,
                        "source_id": dedup_parts["source_id"],
                        "component_identity": dedup_parts["component_identity"],
                        "asset_ref": dedup_parts["asset_ref"],
                    }
                )
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": created_count,
        "updated_findings": reused_count,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=len(touched_finding_ids),
        ),
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": created_count,
            "updated_findings": reused_count,
            "reused_findings": reused_count,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
    }
