"""View-model helpers for the Workbench templates."""

from __future__ import annotations

from collections import Counter
from typing import Any


def dashboard_model(project: Any, findings: list[Any], runs: list[Any]) -> dict[str, Any]:
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
        },
        "top_services": top_services.most_common(6),
    }


def findings_model(project: Any, findings: list[Any]) -> dict[str, Any]:
    return {"project": project, "findings": findings}


def reports_model(run: Any, reports: list[Any], bundles: list[Any]) -> dict[str, Any]:
    return {"run": run, "reports": reports, "bundles": bundles}
