"""Projection helpers for Workbench report payloads."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.models import Finding, FindingOccurrence, ProviderSnapshot
from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_models import MarkdownProviderSnapshot, MarkdownReportFinding
from app.services.report_renderer_common import (
    _boolish_signal,
    _decision_guidance_from_payload,
    _priority_label,
    _string_from_mapping,
    _vex_statuses_label_from_explanation,
)


def _analysis_provider_snapshot(snapshot: MarkdownProviderSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {
        "id": snapshot.id,
        "created_at": snapshot.created_at,
        "content_hash": snapshot.content_hash,
        "nvd_last_sync": snapshot.nvd_last_sync,
        "epss_date": snapshot.epss_date,
        "kev_catalog_version": snapshot.kev_catalog_version,
        "source_hashes": snapshot.source_hashes,
        "source_metadata": snapshot.source_metadata,
    }


def _analysis_finding(finding: MarkdownReportFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "cve_id": finding.cve_id,
        "status": finding.status,
        "priority": _priority_label(finding.priority),
        "priority_raw": finding.priority,
        "priority_rank": finding.priority_rank,
        "operational_rank": finding.operational_rank,
        "dedup_key": finding.dedup_key,
        "risk_score": finding.risk_score,
        "epss": finding.epss,
        "cvss_base_score": finding.cvss_base_score,
        "in_kev": finding.in_kev,
        "attack_mapped": _boolish_signal(finding, "attack_mapped"),
        "suppressed_by_vex": _boolish_signal(finding, "suppressed_by_vex"),
        "under_investigation": _boolish_signal(finding, "under_investigation"),
        "waived": _boolish_signal(finding, "waived"),
        "asset": {
            "label": finding.asset,
            "asset_key": finding.asset_key,
            "owner": finding.owner,
            "business_service": finding.business_service,
            "environment": finding.environment,
            "exposure": finding.exposure,
            "criticality": finding.criticality,
        },
        "component": {
            "label": finding.component,
            "purl": finding.component_purl,
        },
        "vulnerability": finding.vulnerability,
        "recommendation": {
            "rationale": finding.rationale,
            "recommended_action": finding.recommended_action,
            "decision_guidance": _decision_guidance_from_payload(finding),
            "decision_statement": finding.decision_statement,
            "decision_sla": finding.decision_sla,
            "business_impact": finding.business_impact,
        },
        "data_quality": {
            "confidence": finding.data_quality_confidence,
            "flags": finding.data_quality_flags,
            "raw": finding.data_quality,
        },
        "explanation": finding.explanation,
        "evidence": finding.evidence,
        "occurrences": finding.occurrences,
        "first_seen_at": _iso_datetime(finding.first_seen_at) if finding.first_seen_at else None,
        "last_seen_at": _iso_datetime(finding.last_seen_at) if finding.last_seen_at else None,
        "created_at": _iso_datetime(finding.created_at) if finding.created_at else None,
        "updated_at": _iso_datetime(finding.updated_at) if finding.updated_at else None,
    }


def _finding_payload(
    finding: Finding,
    *,
    occurrences: list[FindingOccurrence],
) -> MarkdownReportFinding:
    decision_guidance = _decision_guidance(finding)
    explanation = _dict_value(finding.explanation_json)
    base_decision_statement = _decision_text(
        decision_guidance,
        "decision_statement",
        fallback=finding.recommended_action,
    )
    return MarkdownReportFinding(
        id=str(finding.id),
        dedup_key=finding.dedup_key,
        operational_rank=finding.operational_rank,
        cve_id=finding.cve_id,
        priority=str(finding.priority),
        status=str(finding.status),
        priority_rank=finding.priority_rank,
        risk_score=finding.risk_score,
        epss=finding.epss,
        cvss_base_score=finding.cvss_base_score,
        in_kev=finding.in_kev,
        asset=_asset_label(finding),
        asset_key=finding.asset.asset_key if finding.asset is not None else None,
        owner=finding.asset.owner if finding.asset is not None else None,
        business_service=finding.asset.business_service if finding.asset is not None else None,
        environment=str(finding.asset.environment) if finding.asset is not None else None,
        exposure=str(finding.asset.exposure) if finding.asset is not None else None,
        criticality=str(finding.asset.criticality) if finding.asset is not None else None,
        component=_component_label(finding),
        component_purl=finding.component.purl if finding.component is not None else None,
        attack_mapped=finding.attack_mapped,
        suppressed_by_vex=finding.suppressed_by_vex,
        under_investigation=finding.under_investigation,
        waived=finding.waived,
        vulnerability=_vulnerability_payload(finding),
        rationale=finding.rationale,
        recommended_action=finding.recommended_action,
        explanation=explanation,
        data_quality=_dict_value(finding.data_quality_json),
        evidence=_dict_value(finding.evidence_json),
        occurrences=[_occurrence_payload(occurrence) for occurrence in occurrences],
        data_quality_confidence=_data_quality_confidence(finding),
        decision_statement=_governance_decision_statement(
            finding=finding,
            explanation=explanation,
            base_statement=base_decision_statement,
        ),
        business_impact=_decision_text(decision_guidance, "business_impact"),
        decision_sla=_decision_sla(decision_guidance),
        data_quality_flags=_data_quality_flags(finding),
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


def _governance_decision_statement(
    *,
    finding: Finding,
    explanation: dict[str, Any],
    base_statement: str | None,
) -> str | None:
    statement = base_statement
    additions: list[str] = []
    waiver = _dict_value(explanation.get("waiver"))
    waiver_status = _string_from_mapping(waiver, "waiver_status") or _string_from_mapping(
        explanation, "waiver_status"
    )
    if finding.waived or waiver_status:
        additions.append(
            "Accepted-risk governance remains visible"
            + _governance_detail_clause(
                (
                    (
                        "owner",
                        _string_from_mapping(waiver, "waiver_owner")
                        or _string_from_mapping(explanation, "waiver_owner"),
                    ),
                    ("status", waiver_status),
                    (
                        "review",
                        _string_from_mapping(waiver, "waiver_review_on")
                        or _string_from_mapping(explanation, "waiver_review_on"),
                    ),
                    (
                        "expires",
                        _string_from_mapping(waiver, "waiver_expires_on")
                        or _string_from_mapping(explanation, "waiver_expires_on"),
                    ),
                )
            )
            + "."
        )
    if finding.suppressed_by_vex or finding.under_investigation:
        vex_statuses = _vex_statuses_label_from_explanation(explanation)
        additions.append(
            "VEX governance applies"
            + _governance_detail_clause(
                (
                    ("status", vex_statuses),
                    ("source", _string_from_mapping(explanation, "vex_source_format")),
                    ("record", _string_from_mapping(explanation, "vex_source_record_id")),
                )
            )
            + "."
        )
    if not additions:
        return statement
    prefix = statement.rstrip() if statement else "Decision Statement: review finding governance."
    return f"{prefix} {' '.join(additions)}"


def _governance_detail_clause(items: Sequence[tuple[str, str | None]]) -> str:
    details = [f"{label} {value}" for label, value in items if value]
    return f" ({'; '.join(details)})" if details else ""


def _provider_snapshot_payload(
    snapshot: ProviderSnapshot | None,
) -> MarkdownProviderSnapshot | None:
    if snapshot is None:
        return None
    return MarkdownProviderSnapshot(
        id=str(snapshot.id),
        content_hash=snapshot.content_hash,
        nvd_last_sync=snapshot.nvd_last_sync,
        epss_date=snapshot.epss_date,
        kev_catalog_version=snapshot.kev_catalog_version,
        created_at=_iso_datetime(snapshot.created_at),
        source_hashes=dict(snapshot.source_hashes_json or {}),
        source_metadata=dict(snapshot.source_metadata_json or {}),
    )


def _asset_label(finding: Finding) -> str | None:
    if finding.asset is None:
        return None
    return finding.asset.name or finding.asset.asset_key


def _component_label(finding: Finding) -> str | None:
    if finding.component is None:
        return None
    if finding.component.version:
        return f"{finding.component.name} {finding.component.version}"
    return finding.component.name


def _vulnerability_payload(finding: Finding) -> dict[str, Any]:
    vulnerability = finding.vulnerability
    if vulnerability is None:
        return {}
    return {
        "id": str(vulnerability.id),
        "source_id": vulnerability.source_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "cvss_score": vulnerability.cvss_score,
        "cvss_vector": vulnerability.cvss_vector,
        "severity": vulnerability.severity,
        "cwe": vulnerability.cwe,
        "published_at": vulnerability.published_at,
        "modified_at": vulnerability.modified_at,
        "provider": dict(vulnerability.provider_json or {}),
    }


def _occurrence_payload(occurrence: FindingOccurrence) -> dict[str, Any]:
    evidence = _dict_value(occurrence.evidence_json)
    return {
        "id": str(occurrence.id),
        "analysis_run_id": str(occurrence.analysis_run_id),
        "source": occurrence.source,
        "scanner": occurrence.scanner,
        "raw_reference": occurrence.raw_reference,
        "fix_version": occurrence.fix_version,
        "evidence": evidence,
    }


def _data_quality_confidence(finding: Finding) -> str | None:
    explanation_json = _dict_value(finding.explanation_json)
    data_quality_json = _dict_value(finding.data_quality_json)
    value = explanation_json.get("data_quality_confidence") or data_quality_json.get("confidence")
    return str(value) if value else None


def _data_quality_flags(finding: Finding) -> list[str]:
    explanation_json = _dict_value(finding.explanation_json)
    data_quality_json = _dict_value(finding.data_quality_json)
    flags = _flag_items(explanation_json.get("data_quality_flags"))
    flags.extend(_flag_items(data_quality_json.get("flags")))
    deduped: list[str] = []
    for flag in flags:
        if flag not in deduped:
            deduped.append(flag)
    return deduped


def _decision_guidance(finding: Finding) -> dict[str, Any]:
    explanation_json = _dict_value(finding.explanation_json)
    return _dict_value(explanation_json.get("decision_guidance"))


def _decision_text(
    decision_guidance: dict[str, Any],
    key: str,
    *,
    fallback: str | None = None,
) -> str | None:
    value = decision_guidance.get(key)
    if isinstance(value, str):
        return value if value.strip() else fallback
    if isinstance(value, dict):
        for candidate_key in ("text", "summary", "statement", "label"):
            candidate = value.get(candidate_key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate
    return fallback


def _decision_sla(decision_guidance: dict[str, Any]) -> str | None:
    sla = decision_guidance.get("sla")
    if isinstance(sla, str):
        return sla if sla.strip() else None
    if not isinstance(sla, dict):
        return None

    label = str(sla.get("label")).strip() if sla.get("label") else None
    target = sla.get("target_hours") or sla.get("hours")
    if target is None:
        target_days = sla.get("target_days") or sla.get("days")
        if target_days is not None:
            target = f"{target_days}d"
    elif isinstance(target, int | float) and float(target).is_integer():
        target = f"{int(target)}h"
    else:
        target = f"{target}h"

    parts = [part for part in (label, str(target).strip() if target else None) if part]
    return " / ".join(parts) if parts else None


def _flag_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    flags: list[str] = []
    for item in value:
        if isinstance(item, dict):
            parts = [
                str(item[key]) for key in ("code", "label", "message", "detail") if item.get(key)
            ]
            if parts:
                flags.append(" - ".join(parts))
        elif item:
            flags.append(str(item))
    return flags


__all__ = [
    "_analysis_finding",
    "_analysis_provider_snapshot",
    "_asset_label",
    "_component_label",
    "_data_quality_confidence",
    "_data_quality_flags",
    "_decision_guidance",
    "_decision_sla",
    "_decision_text",
    "_finding_payload",
    "_flag_items",
    "_governance_decision_statement",
    "_governance_detail_clause",
    "_occurrence_payload",
    "_provider_snapshot_payload",
    "_vulnerability_payload",
]
