"""Analysis filter normalization helpers."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from vuln_prioritizer.services.analysis_models import _enum_value

PRIORITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def normalize_priority_filters(priority_filters: Sequence[StrEnum | str] | None) -> set[str]:
    if not priority_filters:
        return set()
    return {PRIORITY_LABELS[_enum_value(item)] for item in priority_filters}


def build_active_filters(
    *,
    priority_filters: Sequence[StrEnum | str] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    show_suppressed: bool = False,
    hide_waived: bool = False,
) -> list[str]:
    active_filters: list[str] = []

    if priority_filters:
        ordered_labels = []
        for item in priority_filters:
            label = PRIORITY_LABELS[_enum_value(item)]
            if label not in ordered_labels:
                ordered_labels.append(label)
        active_filters.append("priority=" + ",".join(ordered_labels))
    if kev_only:
        active_filters.append("kev-only")
    if min_cvss is not None:
        active_filters.append(f"min-cvss>={min_cvss:.1f}")
    if min_epss is not None:
        active_filters.append(f"min-epss>={min_epss:.3f}")
    if show_suppressed:
        active_filters.append("show-suppressed")
    if hide_waived:
        active_filters.append("hide-waived")

    return active_filters
