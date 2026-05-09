"""Executive report evidence HTML helpers."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

import math
from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_model import _kpi_value
from vuln_prioritizer.reporting_executive_utils import (
    _float_value,
    _int_value,
    _pct,
    _score,
    _text,
    _truncate,
)

# ruff: noqa: F403,F405

from vuln_prioritizer.reporting_executive_sections_components import *


def _finding_dossiers_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">No visible findings matched this export.</p>'
    cards: list[str] = []
    for item in items:
        technique_text = ", ".join(item["techniques"]) if item["techniques"] else "not supplied"
        tactic_text = ", ".join(item["tactics"]) if item["tactics"] else "not supplied"
        provider_rows = "".join(
            _detail_pair(row["label"], row["value"]) for row in item["provider"]
        )
        cards.append(
            '<article class="er-dossier-card">'
            '<div class="er-dossier-head">'
            "<div>"
            f'<span class="er-badge" data-tone="{escape(item["tone"])}">'
            f"{escape(item['priority'])}</span>"
            f"<h4>{escape(item['cve'])}</h4>"
            f"<p>{escape(item['action'])}</p>"
            "</div>"
            '<dl class="er-dossier-score">'
            f"{_detail_pair('CVSS', item['cvss'])}"
            f"{_detail_pair('EPSS', item['epss'])}"
            f"{_detail_pair('KEV', item['kev'])}"
            "</dl>"
            "</div>"
            '<div class="er-dossier-grid">'
            '<div><p class="er-eyebrow">Routing</p><dl class="er-detail-list compact">'
            f"{_detail_pair('Route', item['route'])}"
            f"{_detail_pair('Service', item['service'])}"
            f"{_detail_pair('Owner', item['owner'])}"
            f"{_detail_pair('Asset', item['asset'])}"
            f"{_detail_pair('Exposure', item['exposure'])}"
            f"{_detail_pair('Criticality', item['criticality'])}"
            "</dl></div>"
            '<div><p class="er-eyebrow">ATT&amp;CK &amp; Governance</p>'
            '<dl class="er-detail-list compact">'
            f"{_detail_pair('ATT&CK', item['attack'])}"
            f"{_detail_pair('Techniques', technique_text)}"
            f"{_detail_pair('Tactics', tactic_text)}"
            f"{_detail_pair('Status', item['status'])}"
            f"{_detail_pair('VEX', item['vex'])}"
            f"{_detail_pair('CVSS-only baseline delta', item['baseline_delta'])}"
            "</dl></div>"
            '<div><p class="er-eyebrow">Provider evidence</p>'
            f'<dl class="er-detail-list compact">{provider_rows}</dl></div>'
            "</div>"
            '<details class="er-dossier-details">'
            "<summary>Rationale and context recommendation</summary>"
            f"<p>{escape(item['rationale'])}</p>"
            f"<p>{escape(item['context_recommendation'])}</p>"
            "</details>"
            "</article>"
        )
    return '<div class="er-dossier-list">' + "".join(cards) + "</div>"


def _input_sources_html(rows: list[dict[str, str]]) -> str:
    body = "".join(
        "<tr>"
        f"<td>{escape(row['input'])}</td>"
        f"<td>{escape(row['format'])}</td>"
        f"<td>{escape(row['rows'])}</td>"
        f"<td>{escape(row['occurrences'])}</td>"
        f"<td>{escape(row['cves'])}</td>"
        "</tr>"
        for row in rows
    )
    return (
        '<div class="er-table-wrap"><table class="er-table er-input-table">'
        "<thead><tr><th>Input</th><th>Format</th><th>Rows</th>"
        "<th>Occurrences</th><th>Unique CVEs</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _provider_transparency_html(model: dict[str, Any]) -> str:
    facts = model.get("facts", []) if isinstance(model, dict) else []
    diagnostics = model.get("diagnostics", []) if isinstance(model, dict) else []
    notes = model.get("notes", []) if isinstance(model, dict) else []
    commands = model.get("commands", []) if isinstance(model, dict) else []
    return (
        '<div class="er-provider-transparency">'
        '<dl class="er-detail-list compact">'
        + "".join(_detail_pair(item["label"], item["value"]) for item in facts)
        + "</dl>"
        + (
            '<div><p class="er-eyebrow">NVD diagnostics</p><dl class="er-detail-list compact">'
            + "".join(_detail_pair(item["label"], item["value"]) for item in diagnostics)
            + "</dl></div>"
            if diagnostics
            else ""
        )
        + (
            '<div><p class="er-eyebrow">Provider notes</p><div class="er-warning-list">'
            + "".join(f"<p>{escape(note)}</p>" for note in notes)
            + "</div></div>"
            if notes
            else ""
        )
        + '<div><p class="er-eyebrow">Reproducibility inputs</p><div class="er-command-list">'
        + "".join(f"<code>{escape(command)}</code>" for command in commands)
        + "</div></div></div>"
    )


def _provider_freshness_table(rows: list[dict[str, str]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    body = "".join(
        "<tr>"
        f"<td><strong>{escape(row['provider'])}</strong></td>"
        f"<td>{escape(row['last_sync'])}</td>"
        f"<td>{escape(row['source_status'])}</td>"
        f"<td>{escape(row['freshness'])}</td>"
        "</tr>"
        for row in rows
    )
    return (
        '<div class="er-table-wrap"><table class="er-table er-table-compact">'
        "<thead><tr><th>Provider</th><th>Last sync</th><th>Source status</th>"
        "<th>Freshness</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _quality_matrix_html(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-quality-matrix">'
        + "".join(
            "<article>"
            f"<strong>{escape(str(item['value']))}</strong>"
            f"<span>{escape(item['label'])}</span>"
            f"<small>{escape(str(item['pct']))}% of findings</small>"
            "</article>"
            for item in rows
        )
        + "</div>"
    )


def _quality_notes_html(items: list[str]) -> str:
    if not items:
        return (
            '<div class="er-warning-list"><p>No provider or input warnings were recorded.</p></div>'
        )
    return (
        '<div class="er-warning-list">'
        + "".join(f"<p>{escape(item)}</p>" for item in items)
        + "</div>"
    )


def _mapping_confidence_html(model: dict[str, Any]) -> str:
    rows = model.get("rows", []) if isinstance(model, dict) else []
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    if not model.get("available"):
        return (
            '<div class="er-confidence-layout">'
            '<p class="er-empty">not supplied</p>'
            '<div class="er-warning-list">'
            + "".join(f"<p>{escape(item['detail'])}</p>" for item in rows)
            + "</div></div>"
        )
    return (
        '<div class="er-confidence-layout">'
        f'<strong class="er-donut-total">{escape(str(model.get("total", 0)))}</strong>'
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
        + "</div></div>"
    )


def _evidence_contents_html(model: dict[str, Any]) -> str:
    items = model.get("items", []) if isinstance(model, dict) else []
    if not items:
        return '<p class="er-empty">not supplied</p>'
    intro = (
        '<p class="er-muted">Bundle has not been generated for this run yet. '
        "These contents become available after creating the evidence bundle.</p>"
        if not model.get("generated")
        else ""
    )
    return (
        intro
        + '<ul class="er-evidence-file-list">'
        + "".join(
            "<li>"
            f"<code>{escape(item['name'])}</code>"
            f"<span>{escape(item['size'])}</span>"
            f"<small>{escape(item['detail'])}</small>"
            "</li>"
            for item in items
        )
        + "</ul>"
    )


def _governance_state_html(model: dict[str, Any]) -> str:
    rows = model.get("rows", []) if isinstance(model, dict) else []
    cards = "".join(
        '<article class="er-governance-item" data-tone="'
        + escape(_text(row.get("tone")))
        + '">'
        + f"<strong>{escape(str(row.get('value', 0)))}</strong>"
        + f"<span>{escape(_text(row.get('label')))}</span>"
        + f"<p>{escape(_text(row.get('detail')))}</p>"
        + "</article>"
        for row in rows
        if isinstance(row, dict)
    )
    waiver_file = escape(_text(model.get("waiver_file") if isinstance(model, dict) else None))
    return (
        '<div class="er-governance-grid">'
        + cards
        + "</div>"
        + f'<p class="er-muted"><strong>Waiver file:</strong> {waiver_file}</p>'
    )


def _missing_context_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-missing-context">'
        + "".join(
            '<article class="er-missing-item">'
            "<div>"
            f"<strong>{escape(item['label'])}</strong>"
            f"<p>{escape(item['detail'])}</p>"
            "</div>"
            f"<span>{escape(str(item['value']))}</span>"
            f'<progress class="er-progress" data-tone="{escape(item["tone"])}" '
            f'value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
            "</article>"
            for item in items
        )
        + "</div>"
    )


__all__ = [
    "_evidence_contents_html",
    "_finding_dossiers_html",
    "_governance_state_html",
    "_input_sources_html",
    "_mapping_confidence_html",
    "_missing_context_html",
    "_provider_freshness_table",
    "_provider_transparency_html",
    "_quality_matrix_html",
    "_quality_notes_html",
]
