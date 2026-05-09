"""Bulk insert fast path for large Workbench imports."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import insert
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
from app.models import Asset, Finding, FindingOccurrence, Vulnerability
from app.models.base import get_datetime_utc
from app.services import WorkbenchAnalysisResult
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
) -> dict[str, Any] | None:
    """Fast path for large all-new occurrence imports with no component rows."""
    if len(occurrences) < 1000:
        return None
    if any(occurrence.component for occurrence in occurrences):
        return None
    if any(
        _attack_context_enabled(analysis_result, _decision_for_occurrence(analysis_result, item))
        for item in occurrences
    ):
        return None

    dedup_parts_by_index = [_dedup_key_parts(project_id, occurrence) for occurrence in occurrences]
    dedup_keys = [_finding_dedup_key(parts) for parts in dedup_parts_by_index]
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
        {occurrence.asset_ref for occurrence in occurrences if occurrence.asset_ref}
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
    first_occurrence_by_asset = {
        occurrence.asset_ref: occurrence
        for occurrence in occurrences
        if occurrence.asset_ref and occurrence.asset_ref not in existing_assets
    }
    for asset_key, occurrence in first_occurrence_by_asset.items():
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

    cves = sorted({occurrence.cve for occurrence in occurrences})
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
        dedup_parts = dedup_parts_by_index[
            next(index for index, occurrence in enumerate(occurrences) if occurrence.cve == cve)
        ]
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
    decisions: list[dict[str, Any]] = []
    touched_finding_ids: set[str] = set()
    for index, (occurrence, dedup_parts, dedup_key) in enumerate(
        zip(occurrences, dedup_parts_by_index, dedup_keys, strict=True),
        start=1,
    ):
        decision = analysis_result.findings_by_cve[occurrence.cve]
        compact_payload = compact_payload_by_cve.get(occurrence.cve)
        if compact_payload is None:
            compact_payload = _compact_decision_payload(decision)
            compact_payload_by_cve[occurrence.cve] = compact_payload
        occurrence_scope = _occurrence_scope_payload(occurrence)
        decision_payload = _decision_payload_for_occurrence(
            decision,
            occurrence,
            compact=True,
            base_payload=compact_payload,
            occurrence_scope=occurrence_scope,
        )
        data_quality_payload = data_quality_by_cve.get(occurrence.cve)
        if data_quality_payload is None:
            data_quality_payload = _decision_data_quality_json(decision)
            data_quality_by_cve[occurrence.cve] = data_quality_payload

        finding_id = uuid.uuid4()
        finding_asset_id: uuid.UUID | None = (
            asset_ids_by_key.get(occurrence.asset_ref) if occurrence.asset_ref else None
        )
        finding_batch.append(
            {
                "id": finding_id,
                "project_id": project_id,
                "vulnerability_id": vulnerability_ids_by_cve[occurrence.cve],
                "component_id": None,
                "asset_id": finding_asset_id,
                "cve_id": occurrence.cve,
                "dedup_key": dedup_key,
                "status": _finding_status_for_occurrence(decision, occurrence).value,
                "priority": _decision_priority(decision).value,
                "priority_rank": decision.priority_rank,
                "risk_score": float(decision.operational_score),
                "operational_rank": decision.operational_rank or index,
                "in_kev": decision.in_kev,
                "epss": decision.epss,
                "cvss_base_score": decision.cvss_base_score,
                "attack_mapped": decision.attack_mapped,
                "suppressed_by_vex": _suppressed_by_vex_for_occurrence(
                    decision,
                    occurrence,
                ),
                "under_investigation": decision.under_investigation,
                "waived": decision.waived,
                "recommended_action": decision.recommended_action,
                "rationale": decision.rationale,
                "explanation_json": decision_payload,
                "data_quality_json": data_quality_payload,
                "evidence_json": {
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
                },
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
                "updated_at": now,
            }
        )
        occurrence_batch.append(
            {
                "id": uuid.uuid4(),
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
        touched_finding_ids.add(str(finding_id))
        if len(decisions) < DEDUP_DECISION_SAMPLE_LIMIT:
            decisions.append(
                {
                    "action": "created",
                    "dedup_key": dedup_key,
                    "finding_id": str(finding_id),
                    "cve": occurrence.cve,
                    "source_id": dedup_parts["source_id"],
                    "component_identity": dedup_parts["component_identity"],
                    "asset_ref": dedup_parts["asset_ref"],
                }
            )
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
    session.flush()

    return {
        "occurrence_count": len(occurrences),
        "finding_count": len(touched_finding_ids),
        "created_findings": len(touched_finding_ids),
        "updated_findings": 0,
        "analysis_semantics": _analysis_semantics_summary(
            occurrences=occurrences,
            finding_count=len(touched_finding_ids),
        ),
        "dedup_summary": {
            "key_version": "vpw019-v1",
            "created_findings": len(touched_finding_ids),
            "updated_findings": 0,
            "reused_findings": 0,
            "decision_count": len(occurrences),
            "decisions": decisions,
            "decision_sample_limit": DEDUP_DECISION_SAMPLE_LIMIT,
            "omitted_decisions": max(0, len(occurrences) - len(decisions)),
        },
    }
