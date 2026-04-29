"""Priority logic and deterministic rationale generation."""

from __future__ import annotations

from vuln_prioritizer.config import PRIORITY_RANKS, PRIORITY_RECOMMENDATIONS
from vuln_prioritizer.models import (
    AttackData,
    EpssData,
    FindingProvenance,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityLabel,
    PriorityPolicy,
)

OPERATIONAL_SCORE_MIN = 0
OPERATIONAL_SCORE_MAX = 100


def determine_priority(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
) -> tuple[PriorityLabel, int]:
    """Apply the fixed MVP priority rules."""
    active_policy = policy or PriorityPolicy()
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev or (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        label = PriorityLabel.CRITICAL
    elif (epss_score is not None and epss_score >= active_policy.high_epss_threshold) or (
        cvss is not None and cvss >= active_policy.high_cvss_threshold
    ):
        label = PriorityLabel.HIGH
    elif (cvss is not None and cvss >= active_policy.medium_cvss_threshold) or (
        epss_score is not None and epss_score >= active_policy.medium_epss_threshold
    ):
        label = PriorityLabel.MEDIUM
    else:
        label = PriorityLabel.LOW

    return label, PRIORITY_RANKS[label]


def build_priority_drivers(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    policy: PriorityPolicy | None = None,
) -> list[str]:
    """Return structured priority rules that matched for this finding."""
    active_policy = policy or PriorityPolicy()
    drivers: list[str] = []
    cvss = nvd.cvss_base_score
    epss_score = epss.epss

    if kev.in_kev:
        drivers.append("kev")
    if (
        epss_score is not None
        and epss_score >= active_policy.critical_epss_threshold
        and cvss is not None
        and cvss >= active_policy.critical_cvss_threshold
    ):
        drivers.append("critical-epss-cvss")
    if epss_score is not None and epss_score >= active_policy.high_epss_threshold:
        drivers.append("high-epss")
    if cvss is not None and cvss >= active_policy.high_cvss_threshold:
        drivers.append("high-cvss")
    if cvss is not None and cvss >= active_policy.medium_cvss_threshold:
        drivers.append("medium-cvss")
    if epss_score is not None and epss_score >= active_policy.medium_epss_threshold:
        drivers.append("medium-epss")
    if not drivers:
        drivers.append("default-low")
    return drivers


def determine_cvss_only_priority(cvss_base_score: float | None) -> tuple[PriorityLabel, int]:
    """Apply the comparison baseline that only uses CVSS severity bands."""
    if cvss_base_score is not None and cvss_base_score >= 9.0:
        label = PriorityLabel.CRITICAL
    elif cvss_base_score is not None and cvss_base_score >= 7.0:
        label = PriorityLabel.HIGH
    elif cvss_base_score is not None and cvss_base_score >= 4.0:
        label = PriorityLabel.MEDIUM
    else:
        label = PriorityLabel.LOW

    return label, PRIORITY_RANKS[label]


def determine_priority_state(finding: PrioritizedFinding) -> PriorityLabel:
    """Return the effective priority enum including governance terminal states."""
    if finding.suppressed_by_vex:
        statuses = {status.lower() for status in finding.provenance.vex_statuses}
        if statuses and statuses <= {"fixed"}:
            return PriorityLabel.FIXED
        return PriorityLabel.SUPPRESSED
    if finding.waived and finding.waiver_status in {"active", "review_due"}:
        return PriorityLabel.ACCEPTED
    try:
        return PriorityLabel(finding.priority_label)
    except ValueError:
        return PriorityLabel.LOW


def build_operational_score(
    finding: PrioritizedFinding,
    policy: PriorityPolicy | None = None,
) -> tuple[int, list[str]]:
    """Build an explainable 0-100 operational risk score from explicit rules."""
    priority_state = determine_priority_state(finding)
    if priority_state == PriorityLabel.FIXED:
        return OPERATIONAL_SCORE_MIN, ["fixed VEX state clamps operational score to 0"]
    if priority_state == PriorityLabel.SUPPRESSED:
        return OPERATIONAL_SCORE_MIN, ["suppressed VEX state clamps operational score to 0"]

    active_policy = policy or PriorityPolicy()
    score = 0
    reasons: list[str] = []

    base_scores = {
        PriorityLabel.CRITICAL: 70,
        PriorityLabel.HIGH: 50,
        PriorityLabel.MEDIUM: 30,
        PriorityLabel.LOW: 10,
        PriorityLabel.ACCEPTED: 25,
    }
    base_score = base_scores.get(priority_state, base_scores[PriorityLabel.LOW])
    score += base_score
    reasons.append(f"base {priority_state.value} priority: +{base_score}")

    if finding.in_kev:
        score += 15
        reasons.append("CISA KEV-listed: +15")

    if (
        finding.epss is not None
        and finding.epss >= active_policy.critical_epss_threshold
        and finding.cvss_base_score is not None
        and finding.cvss_base_score >= active_policy.critical_cvss_threshold
    ):
        score += 8
        reasons.append("critical EPSS/CVSS threshold: +8")
    elif finding.epss is not None and finding.epss >= active_policy.high_epss_threshold:
        score += 5
        reasons.append("high EPSS threshold: +5")
    elif finding.epss is not None and finding.epss >= active_policy.medium_epss_threshold:
        score += 2
        reasons.append("medium EPSS threshold: +2")

    if (
        finding.cvss_base_score is not None
        and finding.cvss_base_score >= active_policy.high_cvss_threshold
    ):
        score += 5
        reasons.append("high CVSS threshold: +5")
    elif (
        finding.cvss_base_score is not None
        and finding.cvss_base_score >= active_policy.medium_cvss_threshold
    ):
        score += 2
        reasons.append("medium CVSS threshold: +2")

    if _is_internet_facing(finding.provenance):
        score += 8
        reasons.append("internet-facing asset context: +8")
    if _is_production(finding.provenance):
        score += 5
        reasons.append("production asset context: +5")

    criticality_points = {
        "critical": 7,
        "high": 4,
        "medium": 2,
    }.get((finding.highest_asset_criticality or "").lower(), 0)
    if criticality_points:
        score += criticality_points
        reasons.append(
            f"{finding.highest_asset_criticality} asset criticality: +{criticality_points}"
        )

    extra_occurrences = max(finding.provenance.active_occurrence_count - 1, 0)
    if extra_occurrences:
        occurrence_points = min(extra_occurrences, 5)
        score += occurrence_points
        reasons.append(
            f"{finding.provenance.active_occurrence_count} active occurrences: +{occurrence_points}"
        )

    if priority_state == PriorityLabel.ACCEPTED:
        if finding.waiver_status == "review_due":
            score -= 5
            reasons.append("accepted risk review due: -5")
        else:
            score -= 20
            reasons.append("active accepted-risk waiver: -20")

    clamped_score = clamp_operational_score(score)
    if clamped_score != score:
        reasons.append(f"clamped to {clamped_score}")
    return clamped_score, reasons


def clamp_operational_score(score: int) -> int:
    return max(OPERATIONAL_SCORE_MIN, min(OPERATIONAL_SCORE_MAX, score))


def _is_internet_facing(provenance: FindingProvenance) -> bool:
    highest_exposure = provenance.highest_asset_exposure
    if highest_exposure and highest_exposure.lower() == "internet-facing":
        return True
    return any(
        occurrence.asset_exposure and occurrence.asset_exposure.lower() == "internet-facing"
        for occurrence in provenance.occurrences
    )


def _is_production(provenance: FindingProvenance) -> bool:
    return any(
        occurrence.asset_environment
        and occurrence.asset_environment.lower() in {"prod", "production"}
        for occurrence in provenance.occurrences
    )


def build_rationale(
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData | None = None,
    provenance: FindingProvenance | None = None,
    *,
    context_summary: str | None = None,
    suppressed_by_vex: bool = False,
    under_investigation: bool = False,
) -> str:
    """Build a deterministic rationale string from the available signals."""
    parts: list[str] = []

    if kev.in_kev:
        parts.append("CISA KEV lists this CVE as known exploited in the wild.")

    if nvd.cvss_base_score is not None:
        severity = f" ({nvd.cvss_severity})" if nvd.cvss_severity else ""
        version_note = f" via CVSS v{nvd.cvss_version}" if nvd.cvss_version else ""
        parts.append(f"NVD reports CVSS {nvd.cvss_base_score:.1f}{severity}{version_note}.")
    else:
        parts.append("NVD CVSS data is unavailable or not yet analyzed.")

    if epss.epss is not None:
        percentile_note = ""
        if epss.percentile is not None:
            percentile_note = f" (percentile {epss.percentile:.3f})"
        parts.append(f"FIRST EPSS is {epss.epss:.3f}{percentile_note}.")
    else:
        parts.append("FIRST EPSS data is unavailable.")

    if attack and attack.mapped:
        parts.append(
            "ATT&CK context "
            f"({attack.attack_relevance}) maps this CVE to "
            f"{len(attack.attack_techniques)} technique(s): "
            + ", ".join(attack.attack_techniques)
            + "."
        )
        if attack.mapping_types:
            parts.append("CTID mapping types: " + ", ".join(attack.mapping_types) + ".")
        if attack.attack_rationale:
            parts.append(attack.attack_rationale.rstrip(".") + ".")
    if attack and attack.attack_note:
        parts.append(f"ATT&CK mapping note: {attack.attack_note.rstrip('.')}.")

    if provenance and provenance.occurrence_count:
        parts.append(
            f"Input provenance includes {provenance.occurrence_count} occurrence(s) from "
            + ", ".join(provenance.source_formats)
            + "."
        )
        if provenance.components:
            parts.append(
                "Affected components include: "
                + ", ".join(provenance.components[:5])
                + ("." if len(provenance.components) <= 5 else ", ...")
            )
    if context_summary:
        parts.append(context_summary.rstrip(".") + ".")
    if suppressed_by_vex:
        parts.append(
            "Matching VEX statements mark all known occurrences as not affected or fixed, so the "
            "finding is suppressed by default."
        )
    elif under_investigation:
        parts.append(
            "At least one matching VEX statement is still under investigation, so the finding "
            "remains visible."
        )

    return " ".join(parts)


def build_comparison_reason(
    finding: PrioritizedFinding,
    *,
    cvss_only_label: str,
    cvss_only_rank: int,
) -> str:
    """Explain why the enriched result differs from or matches the CVSS-only baseline."""
    if finding.suppressed_by_vex:
        return (
            "VEX marks all matched occurrences as not affected or fixed; the finding remains "
            "available only when suppressed results are requested."
        )

    if finding.waived:
        return (
            "An active waiver is recorded for this finding; enriched prioritization stays visible, "
            "but governance has accepted the risk until the waiver expires."
        )

    if finding.priority_rank < cvss_only_rank:
        if finding.in_kev:
            return (
                f"KEV membership raises this CVE from the CVSS-only {cvss_only_label} baseline "
                f"to {finding.priority_label}."
            )
        if finding.epss is not None:
            return (
                f"EPSS {finding.epss:.3f} raises this CVE from the CVSS-only "
                f"{cvss_only_label} baseline to {finding.priority_label}."
            )
        return (
            f"Additional enrichment raises this CVE from the CVSS-only {cvss_only_label} "
            f"baseline to {finding.priority_label}."
        )

    if finding.priority_rank > cvss_only_rank:
        return (
            f"CVSS alone would rate this CVE as {cvss_only_label}, but the enriched model "
            f"lowers it to {finding.priority_label} because KEV is absent and EPSS stays below "
            "the escalation thresholds."
        )

    if finding.cvss_base_score is None and finding.epss is None and not finding.in_kev:
        return "Missing CVSS and EPSS data leave both baseline and enriched views at Low."

    if finding.cvss_base_score is None:
        return (
            f"Missing CVSS keeps the baseline at {cvss_only_label}, and the available "
            "enrichment signals do not change the result."
        )

    if not finding.in_kev and (finding.epss is None or finding.epss < 0.10):
        return (
            f"CVSS alone already yields {cvss_only_label}, and EPSS/KEV do not change the result."
        )

    return f"CVSS and enrichment both support the same {finding.priority_label} outcome."


def recommended_action(priority_label: str) -> str:
    """Return the action text for a priority label."""
    return PRIORITY_RECOMMENDATIONS[priority_label]
