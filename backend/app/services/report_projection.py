"""Projection helpers for Workbench report payloads."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.decision_core.contracts import FindingDecisionEvidenceV2, ProviderEvidenceV2
from app.decision_core.readmodels import DecisionFindingView, decision_finding_view
from app.models import Finding, FindingOccurrence, ProviderSnapshot
from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_models import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    ReportOccurrence,
    ReportVulnerability,
)
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
        "vulnerability": _vulnerability_export(finding.vulnerability),
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
        "occurrences": [
            occurrence.model_dump(mode="json", exclude_unset=True)
            for occurrence in finding.occurrences
        ],
        "first_seen_at": _iso_datetime(finding.first_seen_at) if finding.first_seen_at else None,
        "last_seen_at": _iso_datetime(finding.last_seen_at) if finding.last_seen_at else None,
        "created_at": _iso_datetime(finding.created_at) if finding.created_at else None,
        "updated_at": _iso_datetime(finding.updated_at) if finding.updated_at else None,
    }


def _finding_payload(
    finding: Finding,
    *,
    occurrences: list[FindingOccurrence],
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> MarkdownReportFinding:
    view = decision_finding_view(finding, evidence=evidence)
    return _finding_payload_from_decision_view(view, occurrences=occurrences)


def _finding_payload_from_decision_view(
    view: DecisionFindingView,
    *,
    occurrences: list[FindingOccurrence],
) -> MarkdownReportFinding:
    finding = view.finding
    evidence = view.evidence
    asset = _report_asset_projection(finding, evidence=evidence)
    component_label, component_purl = _report_component_projection(view)
    decision_guidance = _decision_guidance(finding, evidence=evidence)
    explanation = _finding_explanation(finding, evidence=evidence)
    recommended_action = view.recommended_action
    rationale = view.rationale
    base_decision_statement = _decision_text(
        decision_guidance,
        "decision_statement",
        fallback=recommended_action,
    )
    return MarkdownReportFinding(
        id=evidence.finding_id if evidence is not None else str(finding.id),
        dedup_key=view.dedup_key,
        operational_rank=view.operational_rank,
        cve_id=view.cve_id,
        priority=evidence.priority if evidence is not None else str(view.priority),
        status=evidence.status if evidence is not None else str(view.status),
        priority_rank=view.priority_rank,
        risk_score=view.risk_score,
        epss=view.epss,
        cvss_base_score=view.cvss_base_score,
        in_kev=view.in_kev,
        asset=asset["label"],
        asset_key=asset["asset_key"],
        owner=asset["owner"],
        business_service=asset["business_service"],
        environment=asset["environment"],
        exposure=asset["exposure"],
        criticality=asset["criticality"],
        component=component_label,
        component_purl=component_purl,
        attack_mapped=evidence.attack.mapped if evidence is not None else view.attack_mapped,
        suppressed_by_vex=view.suppressed_by_vex,
        under_investigation=view.under_investigation,
        waived=view.waived,
        vulnerability=_vulnerability_payload(finding, evidence=evidence),
        rationale=rationale,
        recommended_action=recommended_action,
        explanation=explanation,
        data_quality=_finding_data_quality(finding, evidence=evidence),
        evidence=evidence.to_jsonable() if evidence is not None else {},
        occurrences=_report_occurrences(evidence=evidence, occurrences=occurrences),
        data_quality_confidence=_data_quality_confidence(finding, evidence=evidence),
        decision_statement=_governance_decision_statement(
            finding=finding,
            explanation=explanation,
            base_statement=base_decision_statement,
            waived=view.waived,
            suppressed_by_vex=view.suppressed_by_vex,
            under_investigation=view.under_investigation,
        ),
        business_impact=_decision_text(decision_guidance, "business_impact"),
        decision_sla=_decision_sla(decision_guidance),
        data_quality_flags=tuple(_data_quality_flags(finding, evidence=evidence)),
        first_seen_at=finding.first_seen_at if evidence is None else None,
        last_seen_at=finding.last_seen_at if evidence is None else None,
        created_at=finding.created_at if evidence is None else None,
        updated_at=finding.updated_at if evidence is None else None,
    )


def _governance_decision_statement(
    *,
    finding: Finding,
    explanation: dict[str, Any],
    base_statement: str | None,
    waived: bool | None = None,
    suppressed_by_vex: bool | None = None,
    under_investigation: bool | None = None,
) -> str | None:
    statement = base_statement
    additions: list[str] = []
    waiver = _dict_value(explanation.get("waiver"))
    waiver_status = _string_from_mapping(waiver, "waiver_status") or _string_from_mapping(
        explanation, "waiver_status"
    )
    if bool(waived) or waiver_status:
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
    has_vex_governance = bool(suppressed_by_vex) or bool(under_investigation)
    if has_vex_governance:
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
    *,
    evidence: ProviderEvidenceV2 | None = None,
    finding_evidence: Sequence[FindingDecisionEvidenceV2] = (),
) -> MarkdownProviderSnapshot | None:
    if evidence is not None:
        if evidence.provider_snapshot_id is None and evidence.provider_snapshot_hash is None:
            return None
        source_hashes = (
            {"provider_snapshot": evidence.provider_snapshot_hash}
            if evidence.provider_snapshot_hash is not None
            else {}
        )
        return MarkdownProviderSnapshot(
            id=evidence.provider_snapshot_id,
            content_hash=evidence.provider_snapshot_hash,
            nvd_last_sync=None,
            epss_date=None,
            kev_catalog_version=None,
            created_at=None,
            source_hashes=source_hashes,
            source_metadata={
                "provider_snapshot_file": evidence.provider_snapshot_file,
                "locked_provider_data": evidence.locked_provider_data,
                "provider_degraded": evidence.provider_degraded,
                "provider_data_quality_flags": {
                    source: [flag.to_jsonable() for flag in flags]
                    for source, flags in evidence.provider_data_quality_flags.items()
                },
                "nvd_hits": evidence.nvd_hits,
                "epss_hits": evidence.epss_hits,
                "kev_hits": evidence.kev_hits,
                "run_subset_provider_evidence": _run_subset_provider_evidence(finding_evidence),
            },
        )
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


def _run_subset_provider_evidence(
    evidence_items: Sequence[FindingDecisionEvidenceV2],
) -> dict[str, Any]:
    """Summarize immutable provider dates without claiming snapshot-wide freshness."""
    nvd_last_modified: list[str] = []
    epss_dates: list[str] = []
    kev_dates_added: list[str] = []
    for finding_evidence in evidence_items:
        provider = dict(finding_evidence.provider.provider_evidence)
        nvd = _dict_value(provider.get("nvd"))
        epss = _dict_value(provider.get("epss"))
        kev = _dict_value(provider.get("kev"))
        if value := _clean_string(nvd.get("last_modified")):
            nvd_last_modified.append(value)
        if value := _clean_string(epss.get("date")):
            epss_dates.append(value)
        if value := _clean_string(kev.get("date_added")):
            kev_dates_added.append(value)
    return {
        "scope": "selected_run_findings",
        "derivation": "immutable_finding_decision_evidence",
        "finding_evidence_count": len(evidence_items),
        "nvd_last_modified_max": max(nvd_last_modified, default=None),
        "latest_epss_date": max(epss_dates, default=None),
        "kev_date_added_max": max(kev_dates_added, default=None),
    }


def _asset_label(finding: Finding) -> str | None:
    if finding.asset is None:
        return None
    return finding.asset.name or finding.asset.asset_key


def _report_asset_projection(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None,
) -> dict[str, str | None]:
    """Project asset presentation from the selected run evidence when available."""
    if evidence is None:
        asset = finding.asset
        return {
            "label": _asset_label(finding),
            "asset_key": asset.asset_key if asset is not None else None,
            "owner": asset.owner if asset is not None else None,
            "business_service": asset.business_service if asset is not None else None,
            "environment": str(asset.environment) if asset is not None else None,
            "exposure": str(asset.exposure) if asset is not None else None,
            "criticality": str(asset.criticality) if asset is not None else None,
        }

    scope = evidence.occurrence_scope
    asset_key = (
        _clean_string(scope.asset_id)
        or _clean_string(scope.target_ref)
        or _single_occurrence_value(evidence, "asset_id")
        or _single_occurrence_value(evidence, "target_ref")
        or _single_raw_list_value(evidence, "asset_ids")
    )
    asset_name = _single_raw_list_value(evidence, "asset_names")
    return {
        "label": asset_name or asset_key,
        "asset_key": asset_key,
        "owner": _clean_string(scope.asset_owner)
        or _single_occurrence_value(evidence, "asset_owner"),
        "business_service": _clean_string(scope.asset_business_service)
        or _single_occurrence_value(evidence, "asset_business_service"),
        "environment": _clean_string(scope.asset_environment)
        or _single_occurrence_value(evidence, "asset_environment"),
        "exposure": _clean_string(scope.asset_exposure)
        or _single_occurrence_value(evidence, "asset_exposure"),
        "criticality": _clean_string(scope.asset_criticality)
        or _single_occurrence_value(evidence, "asset_criticality"),
    }


def _component_label(finding: Finding) -> str | None:
    if finding.component is None:
        return None
    if finding.component.version:
        return f"{finding.component.name} {finding.component.version}"
    return finding.component.name


def _report_component_projection(
    view: DecisionFindingView,
) -> tuple[str | None, str | None]:
    """Project the same evidence-bound component identity as the decision read model."""
    evidence = view.evidence
    if evidence is None:
        return view.component_label, view.component_purl

    scope = evidence.occurrence_scope
    name = (
        _clean_string(scope.component_name)
        or _single_occurrence_value(evidence, "component_name")
        or _single_raw_list_value(evidence, "components")
        or view.component_name
    )
    version = (
        _clean_string(scope.component_version)
        or _single_occurrence_value(evidence, "component_version")
        or _single_raw_list_value(evidence, "versions")
        or view.component_version
    )
    label = f"{name} {version}" if name and version else name
    return label, view.component_purl


def _vulnerability_payload(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> ReportVulnerability | None:
    if evidence is not None:
        return _evidence_vulnerability_payload(evidence)
    vulnerability = finding.vulnerability
    if vulnerability is None:
        return None
    return ReportVulnerability(
        id=str(vulnerability.id),
        source_id=vulnerability.source_id,
        title=vulnerability.title,
        description=vulnerability.description,
        cvss_score=vulnerability.cvss_score,
        cvss_vector=vulnerability.cvss_vector,
        severity=vulnerability.severity,
        cwe=vulnerability.cwe,
        published_at=vulnerability.published_at,
        modified_at=vulnerability.modified_at,
        provider=dict(vulnerability.provider_json or {}),
    )


def _evidence_vulnerability_payload(
    evidence: FindingDecisionEvidenceV2,
) -> ReportVulnerability:
    provider = dict(evidence.provider.provider_evidence)
    nvd = _dict_value(provider.get("nvd"))
    kev = _dict_value(provider.get("kev"))
    cwes = _string_values(nvd.get("cwes"))
    references = tuple(_string_values(nvd.get("references")))
    source_id = (
        _clean_string(evidence.occurrence_scope.source_id)
        or _single_occurrence_value(evidence, "source_id")
        or _clean_string(nvd.get("cve_id"))
        or evidence.cve_id
    )
    return ReportVulnerability(
        id=None,
        source_id=source_id,
        title=_clean_string(nvd.get("title"))
        or _clean_string(kev.get("vulnerability_name"))
        or evidence.cve_id,
        description=_clean_string(nvd.get("description"))
        or _clean_string(provider.get("description"))
        or _clean_string(kev.get("short_description")),
        cvss_score=evidence.cvss_base_score,
        cvss_vector=_clean_string(nvd.get("cvss_vector"))
        or _clean_string(provider.get("cvss_vector")),
        severity=_clean_string(nvd.get("cvss_severity")) or _clean_string(provider.get("severity")),
        cwe=", ".join(cwes) if cwes else None,
        published_at=_clean_string(nvd.get("published"))
        or _clean_string(provider.get("published")),
        modified_at=_clean_string(nvd.get("last_modified"))
        or _clean_string(provider.get("last_modified")),
        provider=provider,
        references=references,
    )


def _single_occurrence_value(
    evidence: FindingDecisionEvidenceV2,
    field_name: str,
) -> str | None:
    values = {
        value
        for occurrence in evidence.occurrences
        if (value := _clean_string(getattr(occurrence, field_name, None))) is not None
    }
    return next(iter(values)) if len(values) == 1 else None


def _single_raw_list_value(
    evidence: FindingDecisionEvidenceV2,
    field_name: str,
) -> str | None:
    provenance = _dict_value(evidence.priority_evidence.raw.get("provenance"))
    values = set(_string_values(provenance.get(field_name)))
    return next(iter(values)) if len(values) == 1 else None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [cleaned for item in value if (cleaned := _clean_string(item)) is not None]


def _clean_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _vulnerability_export(vulnerability: ReportVulnerability | None) -> dict[str, Any]:
    if vulnerability is None:
        return {}
    return vulnerability.model_dump(mode="json", exclude_unset=True)


def _occurrence_payload(occurrence: FindingOccurrence) -> ReportOccurrence:
    evidence = _dict_value(occurrence.evidence_json)
    return ReportOccurrence(
        id=str(occurrence.id),
        analysis_run_id=str(occurrence.analysis_run_id),
        source=occurrence.source,
        scanner=occurrence.scanner,
        raw_reference=occurrence.raw_reference,
        fix_version=occurrence.fix_version,
        evidence=evidence,
    )


def _report_occurrences(
    *,
    evidence: FindingDecisionEvidenceV2 | None,
    occurrences: list[FindingOccurrence],
) -> tuple[ReportOccurrence, ...]:
    if evidence is not None:
        return tuple(
            ReportOccurrence(
                id=occurrence.occurrence_id,
                analysis_run_id=occurrence.analysis_run_id,
                source=occurrence.source,
                scanner=occurrence.scanner,
                raw_reference=occurrence.raw_reference,
                fix_version=occurrence.fix_version,
                evidence=occurrence.to_jsonable(),
            )
            for occurrence in evidence.occurrences
        )
    return tuple(_occurrence_payload(occurrence) for occurrence in occurrences)


def _finding_explanation(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None,
) -> dict[str, Any]:
    _ = finding
    if evidence is None:
        return {}
    explanation = dict(evidence.priority_evidence.raw)
    attack_context = evidence.attack.to_jsonable()
    explanation["attack_context"] = attack_context
    if evidence.attack.technique_ids and not explanation.get("attack_techniques"):
        explanation["attack_techniques"] = list(evidence.attack.technique_ids)
    return explanation


def _finding_data_quality(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None,
) -> dict[str, Any]:
    _ = finding
    return evidence.governance.data_quality if evidence is not None else {}


def _data_quality_confidence(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> str | None:
    _ = finding
    if evidence is not None:
        return evidence.priority_evidence.data_quality_confidence
    return None


def _data_quality_flags(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> list[str]:
    if evidence is not None:
        flags = _flag_items(evidence.priority_evidence.data_quality_flags)
        flags.extend(_flag_items(evidence.governance.data_quality.get("flags")))
    else:
        flags = []
    _ = finding
    deduped: list[str] = []
    for flag in flags:
        if flag not in deduped:
            deduped.append(flag)
    return deduped


def _decision_guidance(
    finding: Finding,
    *,
    evidence: FindingDecisionEvidenceV2 | None = None,
) -> dict[str, Any]:
    _ = finding
    if evidence is not None:
        remediation = evidence.remediation.to_jsonable()
        raw = dict(remediation.pop("raw", {}) or {})
        return {**remediation, **raw}
    return {}


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
        if hasattr(item, "model_dump"):
            dumped = item.model_dump(mode="json", exclude_none=True)
            item = dumped if isinstance(dumped, dict) else {"message": str(dumped)}
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
    "_finding_payload_from_decision_view",
    "_flag_items",
    "_governance_decision_statement",
    "_governance_detail_clause",
    "_occurrence_payload",
    "_provider_snapshot_payload",
    "_vulnerability_export",
    "_vulnerability_payload",
]
