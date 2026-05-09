"""ATT&CK and detection-coverage HTML helpers for executive sections."""

from __future__ import annotations

import math
from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_sections_components import _mini_metric
from vuln_prioritizer.reporting_executive_utils import _int_value, _truncate


def _attack_heatmap(
    techniques: list[dict[str, Any]],
    tactics: list[dict[str, Any]],
) -> str:
    if not techniques and not tactics:
        return '<p class="er-empty">not supplied</p>'
    cells = []
    for item in techniques[:6] + tactics[:6]:
        intensity = max(1, min(4, math.ceil(item["pct"] / 25)))
        insight = f"{escape(item['label'])}: {escape(str(item['count']))} mapped finding(s)"
        cells.append(
            f'<div class="er-heat-cell er-heat-{intensity}" '
            f'data-insight="{insight}">'
            f"<strong>{escape(item['label'])} "
            f"({escape(str(item['count']))})</strong>"
            f"<span>{escape(str(item['count']))}</span>"
            "</div>"
        )
    return "".join(cells)


def _attack_asset_matrix_html(attack: dict[str, Any]) -> str:
    matrix = attack.get("asset_matrix", {})
    columns = matrix.get("columns", []) if isinstance(matrix, dict) else []
    rows = matrix.get("rows", []) if isinstance(matrix, dict) else []
    if not columns or not rows:
        return (
            '<p class="er-empty">Asset or service context was not supplied for enough '
            "ATT&amp;CK-mapped findings.</p>"
        )
    max_count = max(
        (cell.get("count", 0) for row in rows for cell in row.get("cells", [])),
        default=1,
    )
    header = '<span class="er-heat-head">Tactic</span>' + "".join(
        f'<span class="er-heat-head">{escape(group)}</span>' for group in columns
    )
    body = ""
    for row in rows:
        body += f'<span class="er-heat-label">{escape(row["label"])}</span>'
        for column, cell in zip(columns, row["cells"], strict=False):
            count = _int_value(cell.get("count"))
            intensity = max(1, min(4, math.ceil((count / max_count) * 4))) if count else 0
            insight = (
                f' data-insight="{escape(row["label"])} / {escape(str(column))}: '
                f'{escape(str(count))} mapped finding(s)"'
                if count
                else ""
            )
            body += (
                f'<span class="er-heat-cell er-heat-{intensity}"{insight}>'
                f"{escape(str(count)) if count else ''}</span>"
            )
    return (
        '<div class="er-heatmap er-attack-matrix" '
        'style="grid-template-columns:minmax(120px, 1fr) '
        f'repeat({len(columns)}, minmax(90px, 1fr));">' + header + body + "</div>"
    )


def _attack_mapped_findings_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    body = "".join(
        "<tr>"
        f"<td><strong>{escape(item['cve'])}</strong></td>"
        f"<td>{escape(item['technique'])}</td>"
        f"<td>{escape(item['tactic'])}</td>"
        f"<td>{escape(item['route'])}</td>"
        f'<td><span class="er-badge" data-tone="{escape(item["tone"])}">'
        f"{escape(item['priority'])}</span></td>"
        "</tr>"
        for item in rows
    )
    return (
        '<div class="er-table-wrap"><table class="er-table er-table-compact">'
        "<thead><tr><th>CVE</th><th>ATT&amp;CK ID</th><th>Tactic</th>"
        "<th>Asset / Service</th><th>Priority</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _technique_strip_html(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-technique-strip">'
        + "".join(
            f'<span data-tone="accent">{escape(item["label"])} '
            f"({escape(str(item['count']))})</span>"
            for item in rows
        )
        + "</div>"
    )


def _detection_coverage_html(coverage: dict[str, Any]) -> str:
    summary = coverage.get("summary", {}) if isinstance(coverage, dict) else {}
    weak_items = coverage.get("weak_items", []) if isinstance(coverage, dict) else []
    weak_items = [item for item in weak_items if isinstance(item, dict)]
    metric_html = (
        '<div class="er-kpi-grid compact">'
        + _mini_metric("Partial", summary.get("partial", 0))
        + _mini_metric("No coverage", summary.get("not_covered", 0))
        + _mini_metric("Unknown", summary.get("unknown", 0))
        + _mini_metric("Technique rows", coverage.get("total", 0))
        + "</div>"
    )
    if weak_items:
        rendered_rows = []
        for item in weak_items:
            action = _truncate(str(item.get("recommended_action") or "Review coverage."), 180)
            rendered_rows.append(
                "<tr>"
                f"<td><strong>{escape(str(item.get('technique_id', 'N.A.')))}</strong></td>"
                f"<td>{escape(str(item.get('name') or 'N.A.'))}</td>"
                f"<td>{escape(str(item.get('coverage_level') or 'unknown'))}</td>"
                f"<td>{escape(str(item.get('finding_count') or 0))}</td>"
                f"<td>{escape(str(item.get('owner') or 'Unassigned'))}</td>"
                f"<td>{escape(action)}</td>"
                "</tr>"
            )
        rows = "".join(rendered_rows)
        table = (
            '<div class="er-table-wrap"><table class="er-table er-table-compact">'
            "<thead><tr><th>Technique</th><th>Name</th><th>Coverage</th>"
            "<th>Findings</th><th>Owner</th><th>Action</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    else:
        table = '<p class="er-empty">No partial, missing, or unknown coverage rows supplied.</p>'
    return (
        metric_html + table + f'<p class="er-muted">{escape(str(coverage.get("note") or ""))}</p>'
    )


def _ttp_chain(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    chain = items[:5]
    return (
        '<div class="er-ttp-chain">'
        + "".join(f"<span>{escape(item['label'])}</span>" for item in chain)
        + "</div>"
    )


__all__ = [
    "_attack_asset_matrix_html",
    "_attack_heatmap",
    "_attack_mapped_findings_table",
    "_detection_coverage_html",
    "_technique_strip_html",
    "_ttp_chain",
]
