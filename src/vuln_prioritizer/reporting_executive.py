"""Executive report public facade."""

from __future__ import annotations

from vuln_prioritizer.reporting_executive_constants import (
    EXECUTIVE_REPORT_CSS,
    PRIORITY_ORDER,
    PRIORITY_TONES,
    SECTION_NAV,
)
from vuln_prioritizer.reporting_executive_model import build_executive_report_model
from vuln_prioritizer.reporting_executive_renderer import render_executive_report_html

__all__ = [
    "EXECUTIVE_REPORT_CSS",
    "PRIORITY_ORDER",
    "PRIORITY_TONES",
    "SECTION_NAV",
    "build_executive_report_model",
    "render_executive_report_html",
]
