"""Small executive report HTML components."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_utils import (
    _pct,
)


def _compact_findings_table(items: list[dict[str, Any]]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{escape(str(item['rank']))}</td>"
        f"<td><strong>{escape(item['cve'])}</strong></td>"
        f'<td><span class="er-badge" data-tone="{escape(item["tone"])}">'
        f"{escape(item['priority'])}</span></td>"
        f"<td>{escape(item['cvss'])}</td>"
        f"<td>{escape(item['epss'])}</td>"
        f"<td>{escape(item['kev'])}</td>"
        f"<td>{escape(item['attack'])}</td>"
        "</tr>"
        for item in items
    )
    if not rows:
        rows = (
            '<tr><td colspan="7" class="er-empty">'
            "No visible findings matched this export.</td></tr>"
        )
    return (
        '<div class="er-table-wrap"><table class="er-table er-table-compact">'
        "<thead><tr><th>#</th><th>CVE</th><th>Priority</th><th>CVSS</th>"
        "<th>EPSS</th><th>KEV</th><th>ATT&amp;CK</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )


def _provider_cards_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    cards = "".join(
        f'<article class="er-provider-card" data-tone="{escape(item["tone"])}">'
        f"<strong>{escape(item['label'])}</strong>"
        f"<span>{escape(str(item['count']))}/{escape(str(item['total']))} covered</span>"
        f'<progress class="er-progress" value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        f"<p>{escape(item['description'])}</p>"
        "</article>"
        for item in items
    )
    return f'<div class="er-provider-cards">{cards}</div>'


def _kpi_card(item: dict[str, str]) -> str:
    return (
        f'<article class="er-kpi" data-tone="{escape(item["tone"])}">'
        f"<span>{escape(item['label'])}</span>"
        f"<strong>{escape(item['value'])}</strong>"
        f"<small>{escape(item['detail'])}</small>"
        "</article>"
    )


def _mini_metric(label: str, value: Any) -> str:
    return (
        '<article class="er-kpi mini">'
        f"<span>{escape(label)}</span><strong>{escape(str(value))}</strong>"
        "</article>"
    )


def _decision_item(item: dict[str, Any]) -> str:
    return (
        '<article class="er-decision-item">'
        f'<span class="er-badge" data-tone="{escape(item["tone"])}">'
        f"{escape(item['priority'])}</span>"
        f"<div><strong>{escape(item['cve'])}</strong>"
        f"<p>{escape(item['action'])}</p></div>"
        "</article>"
    )


def _bar_row(item: dict[str, Any]) -> str:
    return (
        '<div class="er-bar-row">'
        f"<span>{escape(item['label'])}</span>"
        f'<progress class="er-progress" data-tone="{escape(item["tone"])}" '
        f'value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        f"<strong>{item['count']}</strong>"
        "</div>"
    )


def _coverage_row(item: dict[str, Any]) -> str:
    return (
        '<div class="er-bar-row">'
        f"<span>{escape(item['label'])}</span>"
        f'<progress class="er-progress" value="{item["pct"]}" max="100">'
        f"{item['pct']}%</progress>"
        f"<strong>{item['count']}/{item['total']}</strong>"
        "</div>"
    )


def _distribution_rows(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return "".join(
        _coverage_row(
            item
            | {
                "label": f"{item['label']} ({item['count']})",
                "total": item["count"],
            }
        )
        for item in items
    )


def _rollup_panel(title: str, rows: list[dict[str, Any]]) -> str:
    row_html = "".join(_coverage_row(item | {"total": item["count"]}) for item in rows)
    if not row_html:
        row_html = '<p class="er-empty">not supplied</p>'
    return (
        f'<article class="er-panel"><h3>{escape(title)}</h3>'
        f'<div class="er-bar-stack">{row_html}</div></article>'
    )


def _finding_table_row(item: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td>{escape(str(item['rank']))}</td>"
        f"<td><strong>{escape(item['cve'])}</strong></td>"
        f'<td><span class="er-badge" data-tone="{escape(item["tone"])}">'
        f"{escape(item['priority'])}</span></td>"
        f"<td>{escape(item['kev'])}</td>"
        f"<td>{escape(item['epss'])}</td>"
        f"<td>{escape(item['cvss'])}</td>"
        f"<td>{escape(item['attack'])}</td>"
        f"<td>{escape(item['asset_service'])}</td>"
        f"<td>{escape(item['owner'])}</td>"
        f"<td>{escape(item['status'])}<br><small>{escape(item['baseline_delta'])}</small></td>"
        f"<td>{escape(item['action'])}</td>"
        "</tr>"
    )


def _status_segment(label: str, value: int, total: int, tone: str) -> str:
    pct = _pct(value, max(total, 1))
    return (
        f'<div class="er-status-segment" data-tone="{escape(tone)}">'
        f"<strong>{value}</strong><span>{escape(label)}</span>"
        f'<progress class="er-status-progress" value="{pct}" max="100">{pct}%</progress>'
        "</div>"
    )


def _detail_pair(label: str, value: Any) -> str:
    text = str(value) if value not in (None, "") else "not available"
    return f"<dt>{escape(label)}</dt><dd>{escape(text)}</dd>"


def _artifact_row(item: dict[str, str]) -> str:
    return (
        '<a class="er-artifact" href="'
        + escape(item["url"])
        + f'"><span>{escape(item["label"])}</span><strong>{escape(item["detail"])}</strong></a>'
    )


def _method_card(item: dict[str, str]) -> str:
    return (
        '<article class="er-method-card">'
        f"<h4>{escape(item['title'])}</h4><p>{escape(item['body'])}</p>"
        "</article>"
    )


__all__ = [
    "_artifact_row",
    "_bar_row",
    "_compact_findings_table",
    "_coverage_row",
    "_decision_item",
    "_detail_pair",
    "_distribution_rows",
    "_finding_table_row",
    "_kpi_card",
    "_method_card",
    "_mini_metric",
    "_provider_cards_html",
    "_rollup_panel",
    "_status_segment",
]
