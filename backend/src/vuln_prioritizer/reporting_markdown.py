"""Markdown report renderer facade."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

# ruff: noqa: F403

from vuln_prioritizer.reporting_markdown_analysis import (
    _baseline_comparison_section,
    _business_impact,
    _decision_sla,
    _decision_statement,
    _decision_template,
    _decision_visibility,
    generate_markdown_report,
)
from vuln_prioritizer.reporting_markdown_compare import generate_compare_markdown
from vuln_prioritizer.reporting_markdown_explain import generate_explain_markdown

__all__ = [
    "_baseline_comparison_section",
    "_business_impact",
    "_decision_sla",
    "_decision_statement",
    "_decision_template",
    "_decision_visibility",
    "generate_compare_markdown",
    "generate_explain_markdown",
    "generate_markdown_report",
]
