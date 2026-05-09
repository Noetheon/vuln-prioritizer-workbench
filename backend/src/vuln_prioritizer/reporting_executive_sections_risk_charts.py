"""Risk and priority chart helpers for executive HTML sections."""

from __future__ import annotations

from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_utils import _float_value, _pct


def _coverage_card(item: dict[str, Any]) -> str:
    return (
        '<article class="er-signal-card">'
        f"<span>{escape(item['label'])}</span>"
        f"<strong>{escape(str(item['count']))}/{escape(str(item['total']))}</strong>"
        f'<progress class="er-progress" value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        "</article>"
    )


def _severity_signal_chart(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    palette = {
        "info": "#0b63f6",
        "success": "#059669",
        "critical": "#dc2626",
        "accent": "#6d28d9",
    }
    max_value = max(
        (sum(segment["count"] for segment in row["segments"]) for row in rows), default=1
    )
    svg_rows: list[str] = []
    for index, row in enumerate(rows):
        y = 32 + index * 42
        x_cursor = 104.0
        svg_rows.append(f'<text x="12" y="{y + 13}">{escape(row["label"])}</text>')
        for segment in row["segments"]:
            count = segment["count"]
            width = (count / max_value) * 260 if max_value else 0
            color = palette.get(segment["tone"], "#0b63f6")
            if width > 0:
                svg_rows.append(
                    f'<rect x="{x_cursor:.1f}" y="{y}" width="{max(width, 4):.1f}" '
                    f'height="18" rx="4" fill="{color}"><title>'
                    f"{escape(segment['label'])}: {count}</title></rect>"
                )
            x_cursor += width
        svg_rows.append(
            f'<text x="382" y="{y + 13}" text-anchor="end">'
            f"{sum(segment['count'] for segment in row['segments'])}</text>"
        )
    legend = (
        '<div class="er-threshold-legend">'
        '<span data-tone="info">NVD severity</span>'
        '<span data-tone="success">EPSS elevated</span>'
        '<span data-tone="critical">KEV flagged</span>'
        '<span data-tone="accent">ATT&amp;CK mapped</span>'
        "</div>"
    )
    return (
        '<svg class="er-stacked-chart" viewBox="0 0 400 210" role="img" '
        'aria-label="Findings by severity and signal">'
        '<line x1="104" y1="18" x2="104" y2="188" class="er-plot-line"></line>'
        + "".join(svg_rows)
        + "</svg>"
        + legend
    )


def _threshold_legend_html() -> str:
    return (
        '<div class="er-threshold-legend" aria-label="Priority threshold legend">'
        '<span data-tone="critical">High EPSS / high CVSS</span>'
        '<span data-tone="success">High EPSS / low CVSS</span>'
        '<span data-tone="high">Low EPSS / high CVSS</span>'
        '<span data-tone="low">Low EPSS / low CVSS</span>'
        "</div>"
    )


def _asset_signal_panel(rows: list[dict[str, Any]]) -> str:
    if not rows:
        body = '<p class="er-empty">not supplied</p>'
    else:
        body = (
            '<div class="er-bar-stack">'
            + "".join(
                '<div class="er-bar-row">'
                f"<span>{escape(item['label'])}</span>"
                f'<progress class="er-progress" value="{item["pct"]}" max="100">'
                f"{item['pct']}%</progress>"
                f"<strong>{escape(str(item['count']))}</strong>"
                "</div>"
                for item in rows
            )
            + "</div>"
        )
    return (
        '<article class="er-panel"><h3>Top Asset Groups by Weighted Risk</h3>'
        f"{body}"
        '<p class="er-muted">Signal-weighted view built from priority, CVSS, EPSS, KEV, '
        "exposure, and criticality fields supplied in the run.</p></article>"
    )


def _driver_row(item: dict[str, Any]) -> str:
    return (
        '<div class="er-driver-row">'
        f'<span class="er-driver-dot" data-tone="{escape(item["tone"])}"></span>'
        f"<span>{escape(item['label'])}</span>"
        f'<progress class="er-progress" data-tone="{escape(item["tone"])}" '
        f'value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        f"<strong>{escape(str(item['count']))}</strong>"
        "</div>"
    )


def _business_exposure_panel(rows: list[dict[str, Any]]) -> str:
    if not rows:
        body = '<p class="er-empty">not supplied</p>'
    else:
        body = (
            '<div class="er-exposure-grid">'
            + "".join(
                f'<article class="er-exposure-tile" data-tone="{escape(item["tone"])}">'
                f"<strong>{escape(item['label'])}</strong>"
                f"<span>{escape(str(item['count']))} finding(s)</span>"
                f"<small>{escape(item['criticality'])} / {escape(item['exposure'])}</small>"
                "</article>"
                for item in rows
            )
            + "</div>"
        )
    return f'<article class="er-panel"><h3>Business Exposure</h3>{body}</article>'


def _ranked_finding_bars(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">No visible findings matched this export.</p>'
    rows = []
    for item in items:
        score = _float_value(item.get("cvss"))
        pct = _pct(round(score * 10), 100) if score >= 0 else 0
        rows.append(
            '<div class="er-ranked-row">'
            f"<span>{escape(str(item['rank']))}</span>"
            f"<strong>{escape(item['cve'])}</strong>"
            f'<progress class="er-rank-progress" data-tone="{escape(item["tone"])}" '
            f'value="{pct}" max="100">{pct}%</progress>'
            f"<em>{escape(item['cvss'])}</em>"
            "</div>"
        )
    return '<div class="er-ranked-list">' + "".join(rows) + "</div>"


def _priority_interpretation_html(items: list[dict[str, str]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-interpretation-panel">'
        + "".join(
            f"<p><strong>{escape(item['title'])}</strong><br>{escape(item['body'])}</p>"
            for item in items
        )
        + "</div>"
    )


def _signal_donut(items: list[dict[str, Any]]) -> str:
    active = [item for item in items if item["count"] > 0]
    total = sum(item["count"] for item in active)
    if total <= 0:
        return '<p class="er-empty">not supplied</p>'
    palette = {
        "critical": "#dc2626",
        "high": "#f97316",
        "medium": "#d99a07",
        "low": "#64748b",
        "success": "#059669",
        "accent": "#6d28d9",
        "info": "#0b63f6",
    }
    cursor = 0.0
    segments: list[str] = []
    for item in active:
        pct = (item["count"] / total) * 100
        color = palette.get(item["tone"], "#0b63f6")
        segments.append(
            '<circle class="er-donut-segment" cx="60" cy="60" r="40" '
            f'data-insight="{escape(item["label"])}: {escape(str(item["count"]))} '
            f'signal(s), {escape(str(item["pct"]))}%" '
            'fill="none" stroke-width="18" pathLength="100" '
            f'stroke="{color}" stroke-dasharray="{pct:.2f} {100 - pct:.2f}" '
            f'stroke-dashoffset="{-cursor:.2f}" transform="rotate(-90 60 60)"></circle>'
        )
        cursor += pct
    legend = "".join(
        '<div class="er-donut-legend-row">'
        f'<span class="er-driver-dot" data-tone="{escape(item["tone"])}"></span>'
        f"<strong>{escape(item['label'])}</strong><em>{item['pct']}%</em>"
        "</div>"
        for item in active
    )
    return (
        '<div class="er-donut-wrap">'
        '<svg class="er-donut-svg" viewBox="0 0 120 120" role="img" '
        'aria-label="Priority signal mix">'
        '<circle class="er-donut-bg" cx="60" cy="60" r="40"></circle>'
        + "".join(segments)
        + f'<text x="60" y="56" class="er-donut-total">{total}</text>'
        '<text x="60" y="73" class="er-donut-caption">signals</text>'
        "</svg>"
        f'<div class="er-donut-legend">{legend}</div>'
        "</div>"
    )


__all__ = [
    "_asset_signal_panel",
    "_business_exposure_panel",
    "_coverage_card",
    "_driver_row",
    "_priority_interpretation_html",
    "_ranked_finding_bars",
    "_severity_signal_chart",
    "_signal_donut",
    "_threshold_legend_html",
]
