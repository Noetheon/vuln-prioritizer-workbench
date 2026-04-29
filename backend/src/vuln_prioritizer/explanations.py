"""Structured priority explanations for findings."""

from __future__ import annotations

from vuln_prioritizer.models import (
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
    note_text = ""
    if notes:
        note_text = " Notes: " + " ".join(note.message for note in notes[:4])
    return f"{summary} Recommended action: {finding.recommended_action}{note_text}"


def _epss_cvss_value(finding: PrioritizedFinding) -> str:
    return (
        f"EPSS={_format_optional_float(finding.epss, 3)}, "
        f"CVSS={_format_optional_float(finding.cvss_base_score, 1)}"
    )


def _format_optional_float(value: float | None, decimals: int) -> str:
    if value is None:
        return "missing"
    return f"{value:.{decimals}f}"
