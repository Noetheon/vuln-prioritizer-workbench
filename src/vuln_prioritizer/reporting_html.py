"""HTML report renderer facade."""

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive import render_executive_report_html


def generate_html_report(report_payload: dict[str, Any]) -> str:
    """Render the executive HTML report from a JSON analysis payload."""
    return render_executive_report_html(report_payload)
