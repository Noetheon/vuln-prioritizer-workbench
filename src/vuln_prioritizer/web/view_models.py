"""View-model helpers for the Workbench templates."""

from __future__ import annotations

from collections import Counter
from typing import Any

from vuln_prioritizer.services.workbench_attack import top_technique_rows


def dashboard_model(
    project: Any,
    findings: list[Any],
    runs: list[Any],
    *,
    provider_status: dict[str, Any] | None = None,
    attack_contexts: list[Any] | None = None,
) -> dict[str, Any]:
    counts = Counter(finding.priority for finding in findings)
    top_services = Counter(
        finding.asset.business_service
        for finding in findings
        if finding.asset is not None and finding.asset.business_service
    )
    return {
        "project": project,
        "runs": runs[:5],
        "findings": findings[:10],
        "counts": {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
            "KEV": sum(1 for finding in findings if finding.in_kev),
            "Open": sum(1 for finding in findings if finding.status == "open"),
            "VEX suppressed": sum(1 for finding in findings if finding.suppressed_by_vex),
            "Under investigation": sum(1 for finding in findings if finding.under_investigation),
            "Waived": sum(1 for finding in findings if finding.waived),
            "Waiver review due": sum(
                1 for finding in findings if finding.waiver_status == "review_due"
            ),
            "Expired waivers": sum(1 for finding in findings if finding.waiver_status == "expired"),
        },
        "top_services": top_services.most_common(6),
        "top_techniques": top_technique_rows(attack_contexts or [], limit=6),
        "attack_mapped_count": sum(1 for context in attack_contexts or [] if context.mapped),
        "provider_status": provider_status or {},
    }


def findings_model(
    project: Any,
    findings: list[Any],
    *,
    filters: dict[str, Any] | None = None,
    total: int | None = None,
) -> dict[str, Any]:
    active_filters = filters or {}
    limit = int(active_filters.get("limit") or 50)
    offset = int(active_filters.get("offset") or 0)
    total_count = len(findings) if total is None else total
    return {
        "project": project,
        "findings": findings,
        "filters": active_filters,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "previous_offset": max(offset - limit, 0),
        "next_offset": offset + limit if offset + limit < total_count else None,
    }


def reports_model(
    run: Any,
    reports: list[Any],
    bundles: list[Any],
    *,
    project: Any | None = None,
) -> dict[str, Any]:
    return {"project": project, "run": run, "reports": reports, "bundles": bundles}
