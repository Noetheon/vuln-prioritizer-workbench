"""Persistence, deduplication, and finding shaping for Workbench imports."""

from __future__ import annotations

import re
import uuid
from copy import deepcopy
from typing import Any

from sqlalchemy import insert
from sqlmodel import Session, col, select

from app.domain.import_asset_context import (
    asset_criticality_from_evidence as _asset_criticality,
)
from app.domain.import_asset_context import (
    asset_environment_from_evidence as _asset_environment,
)
from app.domain.import_asset_context import asset_exposure_from_evidence as _asset_exposure
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import (
    Asset,
    Finding,
    FindingAttackContext,
    FindingOccurrence,
    FindingPriority,
    FindingStatus,
    Vulnerability,
)
from app.models.base import get_datetime_utc
from app.repositories import AssetRepository, FindingRepository, RunRepository
from app.services import WorkbenchAnalysisError, WorkbenchAnalysisResult
from app.services.import_execution_dedup import _dedup_key_parts, _finding_dedup_key
from vuln_prioritizer.models import PrioritizedFinding

DEDUP_DECISION_SAMPLE_LIMIT = 500


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


def _attack_context_enabled(
    analysis_result: WorkbenchAnalysisResult,
    decision: PrioritizedFinding,
) -> bool:
    return analysis_result.context.attack_source != "none" or decision.attack_context.mapped


def _analysis_semantics_summary(
    *,
    occurrences: list[NormalizedOccurrence],
    finding_count: int,
) -> dict[str, Any]:
    return {
        "analysis_decision_scope": "cve_baseline_with_occurrence_overlays",
        "persistence_scope": "asset_component_occurrence",
        "occurrence_overlay_fields": [
            "asset_context",
            "component_identity",
            "source_identity",
            "vex_status",
        ],
        "finding_dedup_key_version": "vpw019-v1",
        "cve_count": len({occurrence.cve for occurrence in occurrences}),
        "occurrence_count": len(occurrences),
        "finding_count": finding_count,
        "same_cve_can_create_distinct_asset_findings": True,
    }


def _decision_payload_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    compact: bool = False,
    base_payload: dict[str, Any] | None = None,
    occurrence_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if base_payload is not None:
        payload = deepcopy(base_payload)
    else:
        payload = _compact_decision_payload(decision) if compact else decision.model_dump()
    occurrence_scope = occurrence_scope or _occurrence_scope_payload(occurrence)
    payload["occurrence_scope"] = occurrence_scope
    payload["suppressed_by_vex"] = _suppressed_by_vex_for_occurrence(decision, occurrence)
    payload["priority_state"] = _priority_state_for_occurrence(
        decision,
        occurrence,
        base_priority_state=payload.get("priority_state"),
    )
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        provenance["occurrence_scope"] = occurrence_scope
        vex_status = _occurrence_vex_status(occurrence)
        provenance["vex_statuses"] = {vex_status: 1} if vex_status else {}
    return payload


def _analysis_evidence_for_occurrence(
    analysis_result: WorkbenchAnalysisResult,
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    priority_state: str | None = None,
    occurrence_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    occurrence_scope = occurrence_scope or _occurrence_scope_payload(occurrence)
    return {
        "decision_scope": "cve_baseline_with_occurrence_overlays",
        "priority_state": priority_state
        or _priority_state_for_occurrence(
            decision,
            occurrence,
            base_priority_state=decision.priority_state,
        ),
        "operational_score": decision.operational_score,
        "provider_snapshot_id": str(analysis_result.provider_snapshot_id)
        if analysis_result.provider_snapshot_id is not None
        else None,
        "provider_snapshot_hash": analysis_result.provider_snapshot_hash,
        "occurrence_scope": occurrence_scope,
        "occurrence_vex_status": _occurrence_vex_status(occurrence),
    }


def _priority_state_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    base_priority_state: str | None,
) -> str | None:
    status = _finding_status_for_occurrence(decision, occurrence)
    if status in {FindingStatus.FIXED, FindingStatus.SUPPRESSED}:
        return status.value.title()
    if decision.suppressed_by_vex and _occurrence_vex_status(occurrence) is None:
        return "Open"
    return base_priority_state


def _occurrence_scope_payload(occurrence: NormalizedOccurrence) -> dict[str, Any]:
    return {
        "source": occurrence.source,
        "source_id": _string_evidence(occurrence.raw_evidence, "source_id"),
        "source_record_id": _string_evidence(occurrence.raw_evidence, "source_record_id"),
        "component": occurrence.component,
        "version": occurrence.version,
        "purl": _string_evidence(occurrence.raw_evidence, "purl"),
        "asset_ref": occurrence.asset_ref,
        "target_ref": _string_evidence(occurrence.raw_evidence, "target_ref"),
        "asset_owner": _string_evidence(occurrence.raw_evidence, "owner"),
        "asset_business_service": _string_evidence(
            occurrence.raw_evidence,
            "business_service",
        ),
        "asset_exposure": _string_evidence(occurrence.raw_evidence, "exposure"),
        "asset_environment": _string_evidence(occurrence.raw_evidence, "environment"),
        "asset_criticality": _string_evidence(occurrence.raw_evidence, "criticality"),
        "vex_status": _occurrence_vex_status(occurrence),
        "vex_match_type": _string_evidence(occurrence.raw_evidence, "vex_match_type"),
        "vex_source_path": _string_evidence(occurrence.raw_evidence, "vex_source_path"),
    }


def _compact_decision_payload(decision: PrioritizedFinding) -> dict[str, Any]:
    """Return the explain/score fields needed for large bulk imports without provider bloat."""
    explanation = _jsonable_model(getattr(decision, "explanation", None)) or {}
    guidance = _jsonable_model(getattr(decision, "decision_guidance", None)) or {}
    provenance = _jsonable_model(getattr(decision, "provenance", None)) or {}
    payload: dict[str, Any] = {
        "cve_id": decision.cve_id,
        "priority_label": decision.priority_label,
        "priority_rank": decision.priority_rank,
        "priority_state": decision.priority_state,
        "operational_score": decision.operational_score,
        "operational_score_reasons": list(decision.operational_score_reasons),
        "recommended_action": decision.recommended_action,
        "rationale": decision.rationale,
        "explanation": {
            "summary": explanation.get("summary"),
            "reasons": explanation.get("reasons", []),
        },
        "decision_guidance": {
            "decision_statement": guidance.get("decision_statement"),
            "recommended_next_steps": guidance.get("recommended_next_steps", []),
        },
        "provenance": {
            "vex_statuses": provenance.get("vex_statuses", {}),
            "provider_snapshot_hash": provenance.get("provider_snapshot_hash"),
        },
        "data_quality_flags": [_jsonable_model(item) for item in decision.data_quality_flags],
        "data_quality_confidence": decision.data_quality_confidence,
    }
    if decision.provider_evidence is not None:
        payload["provider_evidence"] = {
            "nvd": {
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "published": _decision_published(decision),
                "last_modified": _decision_modified(decision),
                "cwes": _decision_cwes(decision),
            },
            "epss": {"score": decision.epss},
            "kev": {"known_exploited": decision.in_kev},
        }
    return {key: value for key, value in payload.items() if value is not None}


def _jsonable_model(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [_jsonable_model(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable_model(item) for item in value]
    return value


def _existing_findings_by_dedup_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    dedup_keys: list[str],
) -> dict[str, Finding]:
    """Load existing project findings for a bulk import without per-row lookups."""
    if not dedup_keys:
        return {}
    findings: dict[str, Finding] = {}
    for chunk in _chunks(sorted(set(dedup_keys)), size=500):
        statement = select(Finding).where(
            Finding.project_id == project_id,
            col(Finding.dedup_key).in_(chunk),
        )
        for finding in session.exec(statement).all():
            findings[finding.dedup_key] = finding
    return findings


def _existing_assets_by_key(
    *,
    session: Session,
    project_id: uuid.UUID,
    asset_keys: list[str],
) -> dict[str, Asset]:
    if not asset_keys:
        return {}
    assets: dict[str, Asset] = {}
    for chunk in _chunks(sorted(set(asset_keys)), size=500):
        statement = select(Asset).where(
            Asset.project_id == project_id,
            col(Asset.asset_key).in_(chunk),
        )
        for asset in session.exec(statement).all():
            assets[asset.asset_key] = asset
    return assets


def _existing_vulnerabilities_by_cve(
    *,
    session: Session,
    cves: list[str],
) -> dict[str, Vulnerability]:
    if not cves:
        return {}
    vulnerabilities: dict[str, Vulnerability] = {}
    for chunk in _chunks(sorted(set(cves)), size=500):
        statement = select(Vulnerability).where(col(Vulnerability.cve_id).in_(chunk))
        for vulnerability in session.exec(statement).all():
            vulnerabilities[vulnerability.cve_id] = vulnerability
    return vulnerabilities


def _chunks(values: list[str], *, size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _chunks_any(values: list[dict[str, Any]], *, size: int) -> list[list[dict[str, Any]]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _persist_workbench_finding_attack_context(
    *,
    session: Session,
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    decision: PrioritizedFinding,
) -> None:
    context = decision.attack_context
    mappings = _attack_mapping_payloads(context.mappings, context.techniques)
    techniques = [technique.model_dump() for technique in context.techniques]
    technique_ids = _technique_ids_from_context(techniques, mappings, context.techniques)
    session.add(
        FindingAttackContext(
            finding_id=finding_id,
            analysis_run_id=run_id,
            cve_id=decision.cve_id,
            mapped=context.mapped,
            source=context.source or "none",
            review_status=_attack_context_review_status(
                getattr(context, "review_status", None),
                context.mapped,
                mappings,
            ),
            defensive_note=_attack_context_defensive_note(context.mapped),
            rationale=context.rationale,
            technique_ids_json=technique_ids,
            tactic_ids_json=_valid_attack_tactic_ids(context.tactics),
            mappings_json=mappings,
        )
    )


def _attack_mapping_payloads(mappings: list[Any], techniques: list[Any]) -> list[dict[str, Any]]:
    techniques_by_id = {
        technique.attack_object_id: technique.model_dump()
        for technique in techniques
        if getattr(technique, "attack_object_id", None)
    }
    payloads: list[dict[str, Any]] = []
    for mapping in mappings:
        payload = mapping.model_dump()
        technique = techniques_by_id.get(payload.get("attack_object_id"))
        if technique:
            payload["technique"] = technique
            payload["tactics"] = technique.get("tactics", [])
            payload["technique_url"] = technique.get("url")
        payloads.append(payload)
    return payloads


def _technique_ids_from_context(
    techniques: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    technique_models: list[Any],
) -> list[str]:
    ids: list[str] = []
    for technique in techniques:
        candidate = _string_evidence(technique, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for mapping in mappings:
        candidate = _string_evidence(mapping, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for technique in technique_models:
        candidate = getattr(technique, "attack_object_id", None)
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    return ids


def _valid_attack_tactic_ids(values: list[str]) -> list[str]:
    return [value for value in values if re.fullmatch(r"TA\d{4}", value)]


def _attack_context_review_status(
    review_status: str | None,
    mapped: bool,
    mappings: list[dict[str, Any]],
) -> str:
    mapping_statuses = {
        status
        for mapping in mappings
        if isinstance(status := mapping.get("review_status"), str)
        and status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}
    }
    for status in ("needs_review", "stale", "rejected", "unreviewed"):
        if status in mapping_statuses:
            return status
    if review_status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}:
        return review_status
    return "reviewed" if mapped else "unreviewed"


def _attack_context_defensive_note(mapped: bool) -> str:
    if mapped:
        return (
            "Use this ATT&CK context only for defensive triage, detection coverage, "
            "and mitigation review."
        )
    return "No reviewed ATT&CK mapping is stored for this finding."


def _decision_for_occurrence(
    analysis_result: WorkbenchAnalysisResult,
    occurrence: NormalizedOccurrence,
) -> PrioritizedFinding:
    decision = analysis_result.findings_by_cve.get(occurrence.cve)
    if decision is None:
        raise WorkbenchAnalysisError(f"Decision analysis did not produce {occurrence.cve}.")
    return decision


def _decision_priority(decision: PrioritizedFinding) -> FindingPriority:
    return FindingPriority(decision.priority_label.lower())


def _decision_status(decision: PrioritizedFinding) -> FindingStatus:
    if decision.priority_state == "Fixed":
        return FindingStatus.FIXED
    if decision.suppressed_by_vex:
        return FindingStatus.SUPPRESSED
    if decision.waived:
        return FindingStatus.ACCEPTED
    return FindingStatus.OPEN


def _finding_status_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> FindingStatus:
    vex_status = _occurrence_vex_status(occurrence)
    if vex_status == "fixed":
        return FindingStatus.FIXED
    if vex_status == "not_affected":
        return FindingStatus.SUPPRESSED
    if vex_status is None and decision.suppressed_by_vex:
        return FindingStatus.OPEN
    return _decision_status(decision)


def _suppressed_by_vex_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> bool:
    vex_status = _occurrence_vex_status(occurrence)
    if vex_status in {"fixed", "not_affected"}:
        return True
    if vex_status is None:
        return False
    return decision.suppressed_by_vex


def _occurrence_vex_status(occurrence: NormalizedOccurrence) -> str | None:
    return _string_evidence(occurrence.raw_evidence, "vex_status")


def _decision_provider_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return decision.provider_evidence.model_dump() if decision.provider_evidence else {}


def _decision_cvss_vector(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.cvss_vector


def _decision_cwe(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None or not decision.provider_evidence.nvd.cwes:
        return None
    return ", ".join(decision.provider_evidence.nvd.cwes)


def _decision_cwes(decision: PrioritizedFinding) -> list[str]:
    if decision.provider_evidence is None:
        return []
    return list(decision.provider_evidence.nvd.cwes)


def _decision_published(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.published


def _decision_modified(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.last_modified


def _decision_data_quality_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return {
        "flags": [item.model_dump() for item in decision.data_quality_flags],
        "confidence": decision.data_quality_confidence,
    }
