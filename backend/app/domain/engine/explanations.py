"""Structured priority explanations for findings."""

from __future__ import annotations

from app.domain.engine.models import (
    ExplanationNote,
    ExplanationReason,
    PrioritizedFinding,
    PriorityExplanation,
    PriorityPolicy,
)


def build_priority_explanation(
    finding: PrioritizedFinding,
    policy: PriorityPolicy | None = None,
) -> PriorityExplanation:
    """Build machine-readable and human-readable reasons for a priority decision."""
    active_policy = policy or PriorityPolicy()
    reasons = _priority_reasons(finding, active_policy)
    notes = _explanation_notes(finding)
    summary = _summary(finding, reasons)
    human_readable = _human_readable(finding, summary, notes)

    return PriorityExplanation(
        cve_id=finding.cve_id,
        priority_label=finding.priority_label,
        priority_state=finding.priority_state or finding.priority_label,
        operational_score=finding.operational_score,
        data_quality_confidence=finding.data_quality_confidence,
        summary=summary,
        human_readable=human_readable,
        reason_codes=[reason.code for reason in reasons],
        reasons=reasons,
        notes=notes,
        recommended_action=finding.recommended_action,
    )


def _priority_reasons(
    finding: PrioritizedFinding,
    policy: PriorityPolicy,
) -> list[ExplanationReason]:
    reasons: list[ExplanationReason] = []
    drivers = finding.priority_drivers or ["default-low"]

    for driver in drivers:
        if driver == "kev":
            reasons.append(
                ExplanationReason(
                    code="priority.kev.known_exploited",
                    source="CISA KEV",
                    signal="known_exploited",
                    value="listed",
                    threshold="listed == true",
                    message="CISA KEV lists this CVE as known exploited in the wild.",
                )
            )
        elif driver == "critical-epss-cvss":
            reasons.append(
                ExplanationReason(
                    code="priority.critical.epss_cvss",
                    source="FIRST EPSS + NVD CVSS",
                    signal="epss_cvss_threshold",
                    value=_epss_cvss_value(finding),
                    threshold=(
                        f"EPSS >= {policy.critical_epss_threshold:.2f} and "
                        f"CVSS >= {policy.critical_cvss_threshold:.1f}"
                    ),
                    message="EPSS and CVSS meet the Critical escalation threshold.",
                )
            )
        elif driver == "high-epss":
            reasons.append(
                ExplanationReason(
                    code="priority.high.epss",
                    source="FIRST EPSS",
                    signal="epss",
                    value=_format_optional_float(finding.epss, 3),
                    threshold=f"EPSS >= {policy.high_epss_threshold:.2f}",
                    message="EPSS meets the High escalation threshold.",
                )
            )
        elif driver == "high-cvss":
            reasons.append(
                ExplanationReason(
                    code="priority.high.cvss",
                    source="NVD CVSS",
                    signal="cvss",
                    value=_format_optional_float(finding.cvss_base_score, 1),
                    threshold=f"CVSS >= {policy.high_cvss_threshold:.1f}",
                    message="CVSS meets the High severity threshold.",
                )
            )
        elif driver == "medium-epss":
            reasons.append(
                ExplanationReason(
                    code="priority.medium.epss",
                    source="FIRST EPSS",
                    signal="epss",
                    value=_format_optional_float(finding.epss, 3),
                    threshold=f"EPSS >= {policy.medium_epss_threshold:.2f}",
                    message="EPSS meets the Medium escalation threshold.",
                )
            )
        elif driver == "medium-cvss":
            reasons.append(
                ExplanationReason(
                    code="priority.medium.cvss",
                    source="NVD CVSS",
                    signal="cvss",
                    value=_format_optional_float(finding.cvss_base_score, 1),
                    threshold=f"CVSS >= {policy.medium_cvss_threshold:.1f}",
                    message="CVSS meets the Medium severity threshold.",
                )
            )
        elif driver == "default-low":
            reasons.append(
                ExplanationReason(
                    code="priority.low.default",
                    source="Decision Engine",
                    signal="default_low",
                    value="no threshold matched",
                    threshold="No KEV, EPSS, or CVSS escalation rule matched",
                    message=(
                        "No configured escalation threshold matched, so the base priority is Low."
                    ),
                )
            )

    if not reasons:
        reasons.append(
            ExplanationReason(
                code="priority.fallback",
                source="Decision Engine",
                signal="fallback",
                value=finding.priority_label,
                threshold=None,
                message="The decision engine produced a priority without a specific driver.",
            )
        )

    asset_reason = _asset_context_reason(finding)
    if asset_reason is not None:
        reasons.append(asset_reason)

    vex_reason = _vex_reason(finding)
    if vex_reason is not None:
        reasons.append(vex_reason)

    if finding.operational_score_reasons:
        reasons.append(
            ExplanationReason(
                code="operational.score",
                source="Decision Engine",
                signal="operational_score",
                value=str(finding.operational_score),
                threshold="0 <= score <= 100",
                message="Operational score reasons: "
                + "; ".join(finding.operational_score_reasons),
            )
        )

    return reasons


def _vex_reason(finding: PrioritizedFinding) -> ExplanationReason | None:
    statuses = finding.provenance.vex_statuses
    if not statuses:
        return None

    status_label = ", ".join(f"{status}: {count}" for status, count in sorted(statuses.items()))
    evidence_parts: list[str] = []
    for occurrence in finding.provenance.occurrences:
        if not occurrence.vex_status:
            continue
        detail_parts = [f"status={occurrence.vex_status}"]
        if occurrence.vex_justification:
            detail_parts.append(f"justification={occurrence.vex_justification}")
        if occurrence.vex_action_statement:
            detail_parts.append(f"action={occurrence.vex_action_statement}")
        if occurrence.vex_match_type:
            detail_parts.append(f"match={occurrence.vex_match_type}")
        evidence_parts.append("; ".join(detail_parts))

    message = f"Matched VEX status distribution: {status_label}."
    if evidence_parts:
        message += " " + " | ".join(evidence_parts[:3])

    return ExplanationReason(
        code="governance.vex_status",
        source="VEX",
        signal="vex_status",
        value=status_label,
        threshold="not_affected/fixed suppress only when every known occurrence is suppressed",
        message=message,
    )


def _explanation_notes(finding: PrioritizedFinding) -> list[ExplanationNote]:
    notes: list[ExplanationNote] = []
    if finding.cvss_base_score is None:
        notes.append(
            ExplanationNote(
                code="missing.nvd_cvss",
                source="NVD CVSS",
                severity="warning",
                message="NVD CVSS data is unavailable or not yet analyzed.",
            )
        )
    if finding.epss is None:
        notes.append(
            ExplanationNote(
                code="missing.first_epss",
                source="FIRST EPSS",
                severity="warning",
                message="FIRST EPSS data is unavailable.",
            )
        )
    for flag in finding.data_quality_flags:
        notes.append(
            ExplanationNote(
                code=f"data_quality.{flag.code}",
                source=flag.source,
                severity=flag.severity,
                message=flag.message,
            )
        )
    if finding.suppressed_by_vex:
        notes.append(
            ExplanationNote(
                code="governance.vex_suppressed",
                source="VEX",
                message="Matching VEX statements suppress this finding by default.",
            )
        )
    if finding.waived:
        notes.append(
            ExplanationNote(
                code="governance.accepted_risk",
                source="Waiver",
                message="An active or review-due waiver records accepted risk for this finding.",
            )
        )
    if finding.attack_mapped:
        notes.append(
            ExplanationNote(
                code="attack.context",
                source="MITRE ATT&CK",
                message=(
                    "ATT&CK context is reported separately from base priority and does not "
                    "change the hard priority label."
                ),
            )
        )
    if finding.attack_context.low_confidence:
        notes.append(
            ExplanationNote(
                code="attack.low_confidence",
                source="MITRE ATT&CK",
                severity="warning",
                message=(
                    "Low-confidence ATT&CK context is retained for review and does not change "
                    "base priority."
                ),
            )
        )
    if _asset_context_unknown(finding):
        notes.append(
            ExplanationNote(
                code="asset.context_unknown",
                source="Asset Context",
                severity="warning",
                message=(
                    "Asset context is unknown and must be validated; unknown context is not "
                    "treated as safe."
                ),
            )
        )
    return notes


def _summary(finding: PrioritizedFinding, reasons: list[ExplanationReason]) -> str:
    reason_codes = ", ".join(reason.code for reason in reasons[:4])
    return (
        f"{finding.cve_id} is {finding.priority_state or finding.priority_label} because "
        f"{reason_codes}."
    )


def _human_readable(
    finding: PrioritizedFinding,
    summary: str,
    notes: list[ExplanationNote],
) -> str:
    asset_text = _asset_context_sentence(finding)
    note_text = ""
    if notes:
        note_text = " Notes: " + " ".join(note.message for note in notes[:4])
    return f"{summary} Recommended action: {finding.recommended_action}{asset_text}{note_text}"


def _asset_context_reason(finding: PrioritizedFinding) -> ExplanationReason | None:
    summary = _asset_context_summary(finding)
    if summary is None:
        return None
    return ExplanationReason(
        code="asset.context",
        source="Asset Context",
        signal="asset_context",
        value=summary,
        threshold="explicit asset context; unknown context is not treated as safe",
        message=(
            "Asset context contributes to the operational score and work-queue rank when "
            "exposure, environment, criticality, service, or owner data is supplied."
        ),
    )


def _asset_context_sentence(finding: PrioritizedFinding) -> str:
    summary = _asset_context_summary(finding)
    if summary:
        return f" Asset context: {summary}."
    if _asset_context_unknown(finding):
        return " Asset context: unknown, not treated as safe."
    return ""


def _asset_context_summary(finding: PrioritizedFinding) -> str | None:
    parts: list[str] = []
    if finding.provenance.highest_asset_exposure:
        parts.append(f"exposure={finding.provenance.highest_asset_exposure}")
    environments = _asset_environments(finding)
    if environments:
        parts.append("environment=" + _summarize_values(environments))
    criticality = finding.highest_asset_criticality or finding.provenance.highest_asset_criticality
    if criticality:
        parts.append(f"criticality={criticality}")
    services = _asset_business_services(finding)
    if services:
        parts.append("business_service=" + _summarize_values(services))
    owners = _asset_owners(finding)
    if owners:
        parts.append("owner=" + _summarize_values(owners))
    if finding.provenance.asset_count:
        parts.append(f"mapped_assets={finding.provenance.asset_count}")
    if not parts:
        return None
    return "; ".join(parts)


def _summarize_values(values: list[str], *, limit: int = 3) -> str:
    if len(values) <= limit:
        return ", ".join(values)
    shown = ", ".join(values[:limit])
    return f"{shown}, +{len(values) - limit} more"


def _asset_environments(finding: PrioritizedFinding) -> list[str]:
    if finding.provenance.asset_environments:
        return finding.provenance.asset_environments
    return sorted(
        {
            occurrence.asset_environment
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_environment
        }
    )


def _asset_business_services(finding: PrioritizedFinding) -> list[str]:
    if finding.provenance.asset_business_services:
        return finding.provenance.asset_business_services
    return sorted(
        {
            occurrence.asset_business_service
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_business_service
        }
    )


def _asset_owners(finding: PrioritizedFinding) -> list[str]:
    if finding.provenance.asset_owners:
        return finding.provenance.asset_owners
    return sorted(
        {
            occurrence.asset_owner
            for occurrence in finding.provenance.occurrences
            if occurrence.asset_owner
        }
    )


def _asset_context_unknown(finding: PrioritizedFinding) -> bool:
    provenance = finding.provenance
    if provenance.occurrence_count == 0 and not provenance.occurrences:
        return False
    if (
        provenance.asset_ids
        or provenance.highest_asset_criticality
        or provenance.highest_asset_exposure
        or provenance.asset_environments
        or provenance.asset_owners
        or provenance.asset_business_services
        or finding.highest_asset_criticality
    ):
        return False
    return not any(
        occurrence.asset_id
        or occurrence.asset_criticality
        or occurrence.asset_exposure
        or occurrence.asset_environment
        or occurrence.asset_owner
        or occurrence.asset_business_service
        for occurrence in provenance.occurrences
    )


def _epss_cvss_value(finding: PrioritizedFinding) -> str:
    return (
        f"EPSS={_format_optional_float(finding.epss, 3)}, "
        f"CVSS={_format_optional_float(finding.cvss_base_score, 1)}"
    )


def _format_optional_float(value: float | None, decimals: int) -> str:
    if value is None:
        return "missing"
    return f"{value:.{decimals}f}"
