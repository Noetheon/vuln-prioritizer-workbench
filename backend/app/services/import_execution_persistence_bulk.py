"""Bulk insert fast path for large Workbench imports."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import insert
from sqlmodel import Session

from app.contracts.decision_evidence import (
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
    FindingDecisionEvidenceV2,
)
from app.domain.import_asset_context import (
    asset_criticality_from_evidence as _asset_criticality,
)
from app.domain.import_asset_context import (
    asset_environment_from_evidence as _asset_environment,
)
from app.domain.import_asset_context import asset_exposure_from_evidence as _asset_exposure
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import Asset, Finding, FindingDecisionEvidence, FindingOccurrence, Vulnerability
from app.models.base import get_datetime_utc
from app.services.analysis import WorkbenchAnalysisResult
from app.services.decision_evidence_builder import (
    build_finding_decision_evidence,
    build_occurrence_evidence,
)
from app.services.import_execution_dedup import _dedup_key_parts, _finding_dedup_key
from app.services.import_execution_persistence_attack import _attack_context_enabled
from app.services.import_execution_persistence_common import DEDUP_DECISION_SAMPLE_LIMIT
from app.services.import_execution_persistence_payloads import (
    _analysis_evidence_for_occurrence,
    _analysis_semantics_summary,
    _compact_decision_payload,
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
    if any(occurrence.component_name for occurrence in occurrences):
        return None
    if any(
        _attack_context_enabled(analysis_result, _decision_for_occurrence(analysis_result, item))
        for item in occurrences
    ):
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
    asset_keys = sorted(
        {occurrence.target_ref for occurrence in occurrences if occurrence.target_ref}
    )
    existing_assets = _existing_assets_by_key(
        session=session,
        project_id=project_id,
        asset_keys=asset_keys,
    )
    if existing_assets:
        return None
    asset_rows: list[dict[str, Any]] = []
    asset_ids_by_key: dict[str, uuid.UUID] = {
        asset_key: asset.id for asset_key, asset in existing_assets.items()
    }
    for occurrence in occurrences:
        asset_key = occurrence.target_ref
        if not asset_key or asset_key in asset_ids_by_key:
            continue
        asset_id = uuid.uuid4()
        asset_ids_by_key[asset_key] = asset_id
        asset_rows.append(
            {
                "id": asset_id,
                "project_id": project_id,
                "asset_key": asset_key,
                "name": asset_key,
                "target_ref": _string_evidence(occurrence.raw_evidence, "target_ref"),
                "owner": _string_evidence(occurrence.raw_evidence, "owner"),
                "business_service": _string_evidence(
                    occurrence.raw_evidence,
                    "business_service",
                ),
                "environment": _asset_environment(occurrence.raw_evidence).value,
                "exposure": _asset_exposure(occurrence.raw_evidence).value,
                "criticality": _asset_criticality(occurrence.raw_evidence).value,
                "created_at": now,
                "updated_at": now,
            }
        )

    cves = sorted({occurrence.cve_id for occurrence in occurrences})
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
        decision = analysis_result.findings_by_cve[cve]
        source_occurrence = next(
            occurrence for occurrence in occurrences if occurrence.cve_id == cve
        )
        dedup_parts = _dedup_key_parts(project_id, source_occurrence)
        vulnerability_id = uuid.uuid4()
        vulnerability_ids_by_cve[cve] = vulnerability_id
        vulnerability_rows.append(
            {
                "id": vulnerability_id,
                "cve_id": cve,
                "source_id": dedup_parts["source_id"],
                "title": cve,
                "description": decision.description,
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "severity": decision.cvss_severity,
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
    compact_payload_by_cve: dict[str, dict[str, Any]] = {}
    finding_batch: list[dict[str, Any]] = []
    occurrence_batch: list[dict[str, Any]] = []
    evidence_batch: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    finding_evidence: list[FindingDecisionEvidenceV2] = []
    created_count = len(occurrences)
    for index, (occurrence, dedup_key) in enumerate(
        zip(occurrences, dedup_keys, strict=True),
        start=1,
    ):
        dedup_parts = _dedup_key_parts(project_id, occurrence)
        decision = analysis_result.findings_by_cve[occurrence.cve_id]
        compact_payload = compact_payload_by_cve.get(occurrence.cve_id)
        if compact_payload is None:
            compact_payload = _compact_decision_payload(decision)
            compact_payload_by_cve[occurrence.cve_id] = compact_payload
        occurrence_scope = _occurrence_scope_payload(occurrence)
        decision_payload = _decision_payload_for_occurrence(
            decision,
            occurrence,
            compact=True,
            base_payload=compact_payload,
            occurrence_scope=occurrence_scope,
        )
        data_quality_payload = data_quality_by_cve.get(occurrence.cve_id)
        if data_quality_payload is None:
            data_quality_payload = _decision_data_quality_json(decision)
            data_quality_by_cve[occurrence.cve_id] = data_quality_payload

        finding_id = uuid.uuid4()
        occurrence_id = uuid.uuid4()
        finding_asset_id: uuid.UUID | None = (
            asset_ids_by_key.get(occurrence.target_ref) if occurrence.target_ref else None
        )
        evidence_payload = {
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
                    "dedup_key": dedup_key,
                    "dedup_action": "created",
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
                "target_ref": occurrence.target_ref,
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
            risk_score=float(decision.operational_score),
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
            evidence_batch.append(
                {
                    "id": uuid.uuid4(),
                    "analysis_evidence_id": analysis_evidence_id,
                    "project_id": project_id,
                    "analysis_run_id": run_id,
                    "finding_id": finding_id,
                    "schema_version": FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
                    "cve_id": evidence_item.cve_id,
                    "dedup_key": evidence_item.dedup_key,
                    "priority": evidence_item.priority,
                    "status": evidence_item.status,
                    "payload_json": evidence_item.to_jsonable(),
                    "created_at": now,
                    "updated_at": now,
                }
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
                    "target_ref": dedup_parts["target_ref"],
                }
            )
        if len(finding_batch) >= 250:
            session.execute(insert(Finding), finding_batch)
            finding_batch.clear()
        if len(occurrence_batch) >= 500:
            session.execute(insert(FindingOccurrence), occurrence_batch)
            occurrence_batch.clear()
        if len(evidence_batch) >= 100:
            session.execute(insert(FindingDecisionEvidence), evidence_batch)
            evidence_batch.clear()

    if finding_batch:
        session.execute(insert(Finding), finding_batch)
    if occurrence_batch:
        session.execute(insert(FindingOccurrence), occurrence_batch)
    if evidence_batch:
        session.execute(insert(FindingDecisionEvidence), evidence_batch)
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": created_count,
        "created_findings": created_count,
        "updated_findings": 0,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=created_count,
        ),
        "dedup_summary": {
            "key_version": "vpw019-v1",
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
