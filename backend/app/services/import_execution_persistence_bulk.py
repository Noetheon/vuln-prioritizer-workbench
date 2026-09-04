"""Bulk insert fast path for large Workbench imports."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import insert
from sqlmodel import Session

from app.decision_core.builders import (
    build_finding_decision_evidence,
    build_occurrence_evidence,
)
from app.decision_core.contracts import (
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
    FindingDecisionEvidenceV2,
)
from app.decision_core.identity import (
    FINDING_SCOPE_KEY_VERSION,
    OBSERVATION_KEY_VERSION,
)
from app.domain.asset_identity import is_reserved_asset_storage_key
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import (
    Asset,
    Finding,
    FindingCurrentProjection,
    FindingDecisionEvidence,
    FindingOccurrence,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories.current_projections import projection_insert_values
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_dedup import (
    _asset_persistence_key,
    _asset_storage_keys_by_identity,
    _dedup_key_parts,
    _finding_dedup_key,
    _legacy_asset_persistence_keys,
    _observation_key,
    _persistence_order_key,
)
from app.services.import_execution_persistence_attack import _attack_context_enabled
from app.services.import_execution_persistence_common import DEDUP_DECISION_SAMPLE_LIMIT
from app.services.import_execution_persistence_payloads import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _asset_projection_payload,
    _canonical_vulnerability_source_id,
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
    _occurrence_scope_payload,
    _scoped_operational_score_for_occurrence,
    _suppressed_by_vex_for_occurrence,
)
from app.services.import_execution_persistence_queries import (
    _chunks_any,
    _existing_assets_by_key,
    _existing_findings_by_dedup_key,
    _existing_vulnerabilities_by_cve,
)


def _persist_workbench_occurrences_bulk_insert(
    *,
    session: Session,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    occurrences: list[NormalizedOccurrence],
    analysis_result: WorkbenchAnalysisResult,
    analysis_evidence_id: uuid.UUID | None = None,
) -> dict[str, Any] | None:
    """Fast path for large all-new occurrence imports with no component rows."""
    if len(occurrences) < 1000:
        return None
    if any(
        occurrence.component_name or _string_evidence(occurrence.raw_evidence, "purl")
        for occurrence in occurrences
    ):
        return None
    if any(
        _attack_context_enabled(analysis_result, _decision_for_occurrence(analysis_result, item))
        for item in occurrences
    ):
        return None
    if any(
        occurrence.asset_id is not None and is_reserved_asset_storage_key(occurrence.asset_id)
        for occurrence in occurrences
    ):
        # Reserved IDs may only be reconciled against evidence-proven pre-v2
        # rows by the normal path; the all-new bulk path must never create one.
        return None

    dedup_keys = [
        _finding_dedup_key(_dedup_key_parts(project_id, occurrence)) for occurrence in occurrences
    ]
    if len(set(dedup_keys)) != len(dedup_keys):
        return None
    if _existing_findings_by_dedup_key(
        session=session,
        project_id=project_id,
        dedup_keys=dedup_keys,
    ):
        return None

    now = get_datetime_utc()
    asset_occurrences_by_key: dict[str, list[NormalizedOccurrence]] = {}
    for occurrence in occurrences:
        asset_key = _asset_persistence_key(occurrence)
        if asset_key is not None:
            asset_occurrences_by_key.setdefault(asset_key, []).append(occurrence)
    asset_storage_key_by_identity = _asset_storage_keys_by_identity(asset_occurrences_by_key)
    asset_keys = sorted(set(asset_storage_key_by_identity.values()).union(asset_occurrences_by_key))
    existing_assets = _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=asset_keys,
    )
    if existing_assets:
        return None
    legacy_asset_keys = sorted(
        {
            legacy_key
            for occurrence in occurrences
            for legacy_key in _legacy_asset_persistence_keys(occurrence)
        }
    )
    if _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=legacy_asset_keys,
    ):
        # The normal path can inspect occurrence evidence before deciding
        # whether an old unnamespaced asset may be promoted safely.
        return None
    asset_rows: list[dict[str, Any]] = []
    asset_ids_by_key: dict[str, uuid.UUID] = {}
    for asset_identity_key, asset_occurrences in sorted(asset_occurrences_by_key.items()):
        asset_key = asset_storage_key_by_identity[asset_identity_key]
        asset_projection = _asset_projection_payload(asset_occurrences)
        asset_id = uuid.uuid4()
        asset_ids_by_key[asset_identity_key] = asset_id
        asset_rows.append(
            {
                "id": asset_id,
                "project_id": project_id,
                "asset_key": asset_key,
                # Match the normal path: the namespaced persistence key is an
                # internal collision guard, not the operator-facing label.
                "name": (
                    asset_occurrences[0].asset_id or asset_occurrences[0].target_ref or asset_key
                ),
                "target_ref": asset_projection["target_ref"],
                "owner": asset_projection["owner"],
                "business_service": asset_projection["business_service"],
                "environment": asset_projection["environment"],
                "exposure": asset_projection["exposure"],
                "criticality": asset_projection["criticality"],
                "created_at": now,
                "updated_at": now,
            }
        )

    occurrences_by_cve: dict[str, list[NormalizedOccurrence]] = {}
    for occurrence in occurrences:
        occurrences_by_cve.setdefault(occurrence.cve_id, []).append(occurrence)
    cves = sorted(occurrences_by_cve)
    vulnerabilities_by_cve = _existing_vulnerabilities_by_cve(session=session, cves=cves)
    if vulnerabilities_by_cve:
        return None
    vulnerability_rows: list[dict[str, Any]] = []
    vulnerability_ids_by_cve = {
        cve: vulnerability.id for cve, vulnerability in vulnerabilities_by_cve.items()
    }
    for cve in cves:
        if cve in vulnerability_ids_by_cve:
            continue
        cve_occurrences = occurrences_by_cve[cve]
        source_occurrence = min(
            cve_occurrences,
            key=lambda item: _persistence_order_key(project_id, item),
        )
        decision = _decision_for_occurrence(analysis_result, source_occurrence)
        vulnerability_id = uuid.uuid4()
        vulnerability_ids_by_cve[cve] = vulnerability_id
        vulnerability_rows.append(
            {
                "id": vulnerability_id,
                "cve_id": cve,
                "source_id": _canonical_vulnerability_source_id(cve_occurrences),
                "title": cve,
                "description": decision.description,
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "severity": decision.cvss_severity
                or _string_evidence(source_occurrence.raw_evidence, "severity"),
                "cwe": _decision_cwe(decision),
                "published_at": _decision_published(decision),
                "modified_at": _decision_modified(decision),
                "provider_json": _decision_provider_json(decision),
                "created_at": now,
                "updated_at": now,
            }
        )

    if asset_rows:
        for chunk in _chunks_any(asset_rows, size=500):
            session.execute(insert(Asset), chunk)
    if vulnerability_rows:
        session.execute(insert(Vulnerability), vulnerability_rows)

    data_quality_by_cve: dict[str, dict[str, Any]] = {}
    finding_batch: list[dict[str, Any]] = []
    occurrence_batch: list[dict[str, Any]] = []
    evidence_batch: list[dict[str, Any]] = []
    projection_batch: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    finding_evidence: list[FindingDecisionEvidenceV2] = []
    created_count = len(occurrences)
    for index, (occurrence, dedup_key) in enumerate(
        zip(occurrences, dedup_keys, strict=True),
        start=1,
    ):
        dedup_parts = _dedup_key_parts(project_id, occurrence)
        decision = _decision_for_occurrence(analysis_result, occurrence)
        occurrence_scope = _occurrence_scope_payload(occurrence)
        scoped_score = _scoped_operational_score_for_occurrence(decision, occurrence)
        decision_payload = _decision_payload_for_occurrence(
            decision,
            occurrence,
            compact=True,
            occurrence_scope=occurrence_scope,
            scoped_score=scoped_score,
        )
        data_quality_payload = data_quality_by_cve.get(occurrence.cve_id)
        if data_quality_payload is None:
            data_quality_payload = _decision_data_quality_json(decision)
            data_quality_by_cve[occurrence.cve_id] = data_quality_payload

        finding_id = uuid.uuid4()
        occurrence_id = uuid.uuid4()
        occurrence_asset_identity_key = _asset_persistence_key(occurrence)
        finding_asset_id = (
            asset_ids_by_key.get(occurrence_asset_identity_key)
            if occurrence_asset_identity_key is not None
            else None
        )
        observation_key = _observation_key(occurrence)
        evidence_payload = {
            "import": dict(occurrence.raw_evidence),
            "analysis": _analysis_evidence_for_occurrence(
                analysis_result,
                decision,
                occurrence,
                priority_state=decision_payload.get("priority_state"),
                occurrence_scope=occurrence_scope,
                operational_score=scoped_score[0],
            ),
            "dedup": {
                "key": dedup_key,
                "key_version": FINDING_SCOPE_KEY_VERSION,
                "observation_key": observation_key,
                "observation_key_version": OBSERVATION_KEY_VERSION,
                "action": "created",
                "parts": dedup_parts,
            },
        }
        finding_batch.append(
            {
                "id": finding_id,
                "project_id": project_id,
                "vulnerability_id": vulnerability_ids_by_cve[occurrence.cve_id],
                "component_id": None,
                "asset_id": finding_asset_id,
                "cve_id": occurrence.cve_id,
                "dedup_key": dedup_key,
                "status": _finding_status_for_occurrence(decision, occurrence).value,
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
                "updated_at": now,
            }
        )
        occurrence_batch.append(
            {
                "id": occurrence_id,
                "finding_id": finding_id,
                "analysis_run_id": run_id,
                "source": occurrence.source,
                "scanner": None,
                "raw_reference": _string_evidence(occurrence.raw_evidence, "source_record_id"),
                "fix_version": occurrence.fix_version,
                "evidence_json": {
                    **dict(occurrence.raw_evidence),
                    "target_kind": occurrence.target_kind,
                    "target_ref": occurrence.target_ref,
                    "asset_id": occurrence.asset_id,
                    "dedup_key": dedup_key,
                    "dedup_action": "created",
                    "observation_key": observation_key,
                    "observation_key_version": OBSERVATION_KEY_VERSION,
                },
            }
        )
        occurrence_evidence = build_occurrence_evidence(
            analysis_run_id=run_id,
            occurrence_id=occurrence_id,
            source=occurrence.source,
            scanner=None,
            raw_reference=_string_evidence(occurrence.raw_evidence, "source_record_id"),
            fix_version=occurrence.fix_version,
            raw_evidence={
                **dict(occurrence.raw_evidence),
                "component_name": occurrence.component_name,
                "component_version": occurrence.component_version,
                "target_kind": occurrence.target_kind,
                "target_ref": occurrence.target_ref,
                "asset_id": occurrence.asset_id,
            },
            dedup=evidence_payload["dedup"],
        )
        evidence_item = build_finding_decision_evidence(
            project_id=project_id,
            run_id=run_id,
            finding_id=finding_id,
            cve_id=occurrence.cve_id,
            dedup_key=dedup_key,
            status=_finding_status_for_occurrence(decision, occurrence).value,
            priority=_decision_priority(decision).value,
            priority_rank=decision.priority_rank,
            risk_score=float(scoped_score[0]),
            operational_rank=decision.operational_rank or index,
            in_kev=decision.in_kev,
            epss=decision.epss,
            cvss_base_score=decision.cvss_base_score,
            attack_mapped=decision.attack_mapped,
            suppressed_by_vex=_suppressed_by_vex_for_occurrence(decision, occurrence),
            under_investigation=decision.under_investigation,
            waived=decision.waived,
            rationale=decision.rationale,
            recommended_action=decision.recommended_action,
            decision_payload=decision_payload,
            data_quality_payload=data_quality_payload,
            provider_payload=_decision_provider_json(decision),
            occurrence_scope=occurrence_scope,
            occurrence_evidence=[occurrence_evidence],
        )
        if analysis_evidence_id is None:
            finding_evidence.append(evidence_item)
        else:
            evidence_record_id = uuid.uuid4()
            source_payload = evidence_item.to_jsonable()
            evidence_batch.append(
                {
                    "id": evidence_record_id,
                    "analysis_evidence_id": analysis_evidence_id,
                    "project_id": project_id,
                    "analysis_run_id": run_id,
                    "finding_id": finding_id,
                    "schema_version": FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
                    "cve_id": evidence_item.cve_id,
                    "dedup_key": evidence_item.dedup_key,
                    "priority": evidence_item.priority,
                    "status": evidence_item.status,
                    "payload_json": source_payload,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            projection_batch.append(
                projection_insert_values(
                    source_record_id=evidence_record_id,
                    source_created_at=now,
                    evidence=evidence_item,
                    source_payload=source_payload,
                )
            )
        if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
            decisions.append(
                {
                    "action": "created",
                    "dedup_key": dedup_key,
                    "finding_id": str(finding_id),
                    "cve_id": occurrence.cve_id,
                    "source_id": dedup_parts["source_id"],
                    "component_identity": dedup_parts["component_identity"],
                    "target_kind": dedup_parts["target_kind"],
                    "target_ref": dedup_parts["target_ref"],
                }
            )
        if len(evidence_batch) >= 100:
            if finding_batch:
                session.execute(insert(Finding), finding_batch)
                finding_batch.clear()
            if occurrence_batch:
                session.execute(insert(FindingOccurrence), occurrence_batch)
                occurrence_batch.clear()
            session.execute(insert(FindingDecisionEvidence), evidence_batch)
            session.execute(insert(FindingCurrentProjection), projection_batch)
            evidence_batch.clear()
            projection_batch.clear()
        else:
            if len(finding_batch) >= 250:
                session.execute(insert(Finding), finding_batch)
                finding_batch.clear()
            if len(occurrence_batch) >= 500:
                session.execute(insert(FindingOccurrence), occurrence_batch)
                occurrence_batch.clear()

    if finding_batch:
        session.execute(insert(Finding), finding_batch)
    if occurrence_batch:
        session.execute(insert(FindingOccurrence), occurrence_batch)
    if evidence_batch:
        session.execute(insert(FindingDecisionEvidence), evidence_batch)
        session.execute(insert(FindingCurrentProjection), projection_batch)
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": created_count,
        "created_findings": created_count,
        "updated_findings": 0,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=created_count,
            analysis_result=analysis_result,
        ),
        "dedup_summary": {
            "key_version": FINDING_SCOPE_KEY_VERSION,
            "created_findings": created_count,
            "updated_findings": 0,
            "reused_findings": 0,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
        "finding_evidence": finding_evidence,
    }
