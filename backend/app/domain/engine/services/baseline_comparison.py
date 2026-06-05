"""CVSS-only baseline comparison helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from app.domain.engine.models import ComparisonFinding, PrioritizedFinding, PriorityPolicy
from app.domain.engine.services.prioritization import PrioritizationService

PRIORITY_ORDER = ("Critical", "High", "Medium", "Low")
BASELINE_THRESHOLDS = {
    "Critical": "CVSS >= 9.0",
    "High": "7.0 <= CVSS < 9.0",
    "Medium": "4.0 <= CVSS < 7.0",
    "Low": "CVSS < 4.0 or missing CVSS",
}
METHODOLOGY_LIMITATION = (
    "This comparison is a decision-support view, not an absolute truth. "
    "It shows how the current enriched policy differs from a CVSS-only baseline "
    "and still requires asset-owner validation."
)


def build_cvss_baseline_comparison_payload(
    findings: Sequence[PrioritizedFinding],
    *,
    project_id: str | None = None,
    policy: PriorityPolicy | None = None,
    top_change_limit: int = 10,
    include_comparisons: bool = True,
) -> dict[str, Any]:
    """Build a JSON-ready CVSS-only vs enriched comparison payload."""
    comparisons = PrioritizationService(policy=policy).build_comparison(list(findings))
    changed = [row for row in comparisons if row.changed]
    payload: dict[str, Any] = {
        "project_id": project_id,
        "methodology": {
            "baseline": "cvss-only",
            "baseline_thresholds": BASELINE_THRESHOLDS,
            "enriched": (
                "Rule-based priority using CVSS, FIRST EPSS, CISA KEV, and supplied "
                "context such as ATT&CK, VEX, waivers, and asset metadata when present."
            ),
            "limitations": METHODOLOGY_LIMITATION,
        },
        "summary": {
            "total": len(comparisons),
            "changed": len(changed),
            "up": sum(1 for row in changed if row.delta_rank > 0),
            "down": sum(1 for row in changed if row.delta_rank < 0),
            "unchanged": len(comparisons) - len(changed),
        },
        "counts": {
            "cvss_only": _counts_by_priority(comparisons, "cvss_only_label"),
            "enriched": _counts_by_priority(comparisons, "enriched_label"),
        },
        "top_changes": [
            _top_change_payload(row) for row in _top_changes(changed, limit=top_change_limit)
        ],
    }
    if include_comparisons:
        payload["comparisons"] = [row.model_dump() for row in comparisons]
    return payload


def _counts_by_priority(
    comparisons: Sequence[ComparisonFinding],
    attribute: str,
) -> dict[str, int]:
    counts = Counter(str(getattr(row, attribute)) for row in comparisons)
    return {priority: counts.get(priority, 0) for priority in PRIORITY_ORDER}


def _top_changes(
    changed: Sequence[ComparisonFinding],
    *,
    limit: int,
) -> list[ComparisonFinding]:
    if limit <= 0:
        return []
    return sorted(
        changed,
        key=lambda row: (
            -abs(row.delta_rank),
            row.enriched_rank,
            row.cvss_only_rank,
            row.cve_id,
        ),
    )[:limit]


def _top_change_payload(row: ComparisonFinding) -> dict[str, Any]:
    return {
        "cve_id": row.cve_id,
        "old_priority": row.cvss_only_label,
        "old_rank": row.cvss_only_rank,
        "new_priority": row.enriched_label,
        "new_rank": row.enriched_rank,
        "delta_rank": row.delta_rank,
        "direction": _direction(row.delta_rank),
        "reason": row.change_reason,
        "cvss": row.cvss_base_score,
        "epss": row.epss,
        "in_kev": row.in_kev,
        "operational_rank": row.operational_rank,
    }


def _direction(delta_rank: int) -> str:
    if delta_rank > 0:
        return "up"
    if delta_rank < 0:
        return "down"
    return "unchanged"
