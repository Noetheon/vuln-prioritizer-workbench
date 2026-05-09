"""Scatter plot HTML helpers for executive sections."""

from __future__ import annotations

from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_utils import _score, _text


def _coverage_average(items: list[dict[str, Any]]) -> str:
    if not items:
        return "not available"
    return f"{round(sum(item['pct'] for item in items) / len(items))}%"


def _scatter_svg(points: list[dict[str, Any]]) -> str:
    point_html = []
    for point in points:
        tone = escape(point["tone"])
        stroke = "#dc2626" if point["kev"] else "#ffffff"
        insight = escape(_scatter_point_insight(point))
        point_html.append(
            f'<circle class="er-dot {tone}" cx="{point["x"]:.1f}" cy="{point["y"]:.1f}" '
            f'r="4.5" stroke="{stroke}" data-insight="{insight}" '
            f'aria-label="{insight}"><title>{escape(point["cve"])}</title></circle>'
        )
    if not point_html:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<svg class="er-scatter" viewBox="0 0 420 240" role="img" '
        'aria-label="CVSS versus EPSS scatter plot">'
        '<rect x="36" y="16" width="360" height="198" class="er-plot-bg"></rect>'
        '<line x1="36" y1="115" x2="396" y2="115" class="er-plot-line"></line>'
        '<line x1="216" y1="16" x2="216" y2="214" class="er-plot-line"></line>'
        '<text x="36" y="232">CVSS 0</text><text x="356" y="232">CVSS 10</text>'
        '<text x="4" y="22">EPSS 1.0</text><text x="8" y="214">0.0</text>'
        + "".join(point_html)
        + "</svg>"
    )


def _quadrant_scatter_svg(points: list[dict[str, Any]]) -> str:
    if not points:
        return '<p class="er-empty">not supplied</p>'
    point_html = []
    for point in points:
        tone = escape(point["tone"])
        stroke = "#dc2626" if point["kev"] else "#ffffff"
        insight = escape(_scatter_point_insight(point))
        point_html.append(
            f'<circle class="er-dot {tone}" cx="{point["x"]:.1f}" cy="{point["y"]:.1f}" '
            f'r="5" stroke="{stroke}" data-insight="{insight}" '
            f'aria-label="{insight}"><title>{escape(point["cve"])}</title></circle>'
        )
    return (
        '<svg class="er-quadrant-scatter" viewBox="0 0 420 250" role="img" '
        'aria-label="CVSS versus EPSS priority quadrant scatter plot">'
        '<rect x="36" y="16" width="360" height="198" fill="#f8fbff" stroke="#d7e3f3"></rect>'
        '<rect x="216" y="16" width="180" height="99" fill="#fff1f2" opacity="0.86"></rect>'
        '<rect x="36" y="16" width="180" height="99" fill="#eff6ff" opacity="0.86"></rect>'
        '<rect x="216" y="115" width="180" height="99" fill="#fff7ed" opacity="0.78"></rect>'
        '<rect x="36" y="115" width="180" height="99" fill="#f8fafc" opacity="0.86"></rect>'
        '<line x1="36" y1="115" x2="396" y2="115" class="er-plot-line"></line>'
        '<line x1="216" y1="16" x2="216" y2="214" class="er-plot-line"></line>'
        '<text x="232" y="35" fill="#dc2626">High EPSS / High CVSS</text>'
        '<text x="48" y="35" fill="#0b63f6">High EPSS / Low CVSS</text>'
        '<text x="232" y="202" fill="#f97316">Low EPSS / High CVSS</text>'
        '<text x="48" y="202" fill="#64748b">Low EPSS / Low CVSS</text>'
        '<text x="36" y="238">CVSS 0</text><text x="356" y="238">CVSS 10</text>'
        '<text x="4" y="22">EPSS 1.0</text><text x="8" y="214">0.0</text>'
        + "".join(point_html)
        + "</svg>"
    )


def _scatter_point_insight(point: dict[str, Any]) -> str:
    kev = "KEV-listed" if point.get("kev") else "not KEV-listed"
    return (
        f"{_text(point.get('cve'), default='CVE')}: "
        f"CVSS {_score(point.get('cvss'), digits=1)}, "
        f"EPSS {_score(point.get('epss'), digits=3)}, {kev}"
    )


__all__ = [
    "_coverage_average",
    "_quadrant_scatter_svg",
    "_scatter_point_insight",
    "_scatter_svg",
]
