"""Deterministic scoring rationale and comparison text helpers."""

from __future__ import annotations

from vuln_prioritizer.config import PRIORITY_RECOMMENDATIONS
from vuln_prioritizer.models import (
    AttackData,
    EpssData,
    FindingProvenance,
    KevData,
    NvdData,
    PrioritizedFinding,
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
        parts.append(_kev_rationale_part())
    parts.append(_nvd_rationale_part(nvd))
    parts.append(_epss_rationale_part(epss))
    parts.extend(_attack_rationale_parts(attack))
    parts.extend(_provenance_rationale_parts(provenance))
    parts.extend(_context_rationale_parts(context_summary, suppressed_by_vex, under_investigation))

    return " ".join(parts)


def _kev_rationale_part() -> str:
    return "CISA KEV lists this CVE as known exploited in the wild."


def _nvd_rationale_part(nvd: NvdData) -> str:
    if nvd.cvss_base_score is None:
        return "NVD CVSS data is unavailable or not yet analyzed."
    severity = f" ({nvd.cvss_severity})" if nvd.cvss_severity else ""
    version_note = f" via CVSS v{nvd.cvss_version}" if nvd.cvss_version else ""
    return f"NVD reports CVSS {nvd.cvss_base_score:.1f}{severity}{version_note}."


def _epss_rationale_part(epss: EpssData) -> str:
    if epss.epss is None:
        return "FIRST EPSS data is unavailable."
    percentile_note = ""
    if epss.percentile is not None:
        percentile_note = f" (percentile {epss.percentile:.3f})"
    return f"FIRST EPSS is {epss.epss:.3f}{percentile_note}."


def _attack_rationale_parts(attack: AttackData | None) -> list[str]:
    parts: list[str] = []
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
    return parts


def _provenance_rationale_parts(provenance: FindingProvenance | None) -> list[str]:
    if not provenance or not provenance.occurrence_count:
        return []
    parts = [
        f"Input provenance includes {provenance.occurrence_count} occurrence(s) from "
        + ", ".join(provenance.source_formats)
        + "."
    ]
    if provenance.components:
        parts.append(
            "Affected components include: "
            + ", ".join(provenance.components[:5])
            + ("." if len(provenance.components) <= 5 else ", ...")
        )
    return parts


def _context_rationale_parts(
    context_summary: str | None,
    suppressed_by_vex: bool,
    under_investigation: bool,
) -> list[str]:
    parts: list[str] = []
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
    return parts


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
