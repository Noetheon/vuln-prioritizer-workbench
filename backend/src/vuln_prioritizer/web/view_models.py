"""View-model helpers for the Workbench templates."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

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
        "latest_run": runs[0] if runs else None,
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
        "previous_href": _findings_page_href(active_filters, max(offset - limit, 0))
        if offset > 0
        else None,
        "next_href": _findings_page_href(active_filters, offset + limit)
        if offset + limit < total_count
        else None,
    }


def reports_model(
    run: Any,
    reports: list[Any],
    bundles: list[Any],
    *,
    project: Any | None = None,
) -> dict[str, Any]:
    payload = run.summary_json if isinstance(run.summary_json, dict) else {}
    raw_metadata = payload.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    raw_attack_summary = payload.get("attack_summary")
    attack_summary: dict[str, Any] = (
        raw_attack_summary if isinstance(raw_attack_summary, dict) else {}
    )
    raw_findings = payload.get("findings")
    findings: list[Any] = raw_findings if isinstance(raw_findings, list) else []
    raw_counts = metadata.get("counts_by_priority")
    counts_by_priority: dict[str, Any] | Counter[str] = (
        raw_counts
        if isinstance(raw_counts, dict)
        else Counter(str(finding.get("priority_label") or "Unprioritized") for finding in findings)
    )
    findings_count = int(metadata.get("findings_count") or len(findings) or 0)
    return {
        "project": project,
        "run": run,
        "reports": reports,
        "bundles": bundles,
        "report_formats": ["json", "markdown", "html", "csv", "sarif"],
        "report_status": {
            "findings": findings_count,
            "critical": int(counts_by_priority.get("Critical", 0) or 0),
            "high": int(counts_by_priority.get("High", 0) or 0),
            "kev": int(metadata.get("kev_hits") or _count_truthy(findings, "in_kev")),
            "attack_mapped": int(
                attack_summary.get("mapped_cves") or _count_truthy(findings, "attack_mapped")
            ),
            "reports": len(reports),
            "bundles": len(bundles),
        },
        "run_context": {
            "input_format": metadata.get("input_format") or run.input_type,
            "input_path": metadata.get("input_path") or run.input_filename or "Not available",
            "generated_at": _format_timestamp(run.finished_at or run.started_at),
            "status": run.status,
            "snapshot": metadata.get("provider_snapshot_hash")
            or metadata.get("provider_snapshot_file")
            or "Not supplied",
        },
    }


def _findings_page_href(filters: dict[str, Any], offset: int) -> str:
    params: list[tuple[str, str]] = []
    for key in (
        "q",
        "priority",
        "status",
        "kev",
        "owner",
        "service",
        "min_epss",
        "min_cvss",
        "sort",
        "limit",
    ):
        value = filters.get(key)
        if key == "kev":
            if value is True:
                params.append((key, "true"))
            elif value is False:
                params.append((key, "false"))
            continue
        if value is None or value == "":
            continue
        params.append((key, str(value)))
    params.append(("offset", str(offset)))
    return f"?{urlencode(params)}"


def _count_truthy(items: list[Any], key: str) -> int:
    return sum(1 for item in items if isinstance(item, dict) and item.get(key))


def _format_timestamp(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M")
    raw_value = str(value)
    normalized = raw_value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return raw_value.replace("T", " ").split(".")[0]
    return parsed.strftime("%Y-%m-%d %H:%M")
