"""Remediation and decision HTML helpers for executive sections."""

from __future__ import annotations

from html import escape
from typing import Any


def _remediation_priority_chart(rows: list[dict[str, Any]]) -> str:
    rendered = []
    for item in rows:
        total = max(item["total"], 1)
        rendered.append(
            '<div class="er-remed-row">'
            f"<strong>{escape(item['label'])}</strong>"
            '<div class="er-remed-bars">'
            f'<span><b>Open</b><progress data-tone="critical" value="{item["open"]}" '
            f'max="{total}">{item["open"]}</progress></span>'
            f'<span><b>Accepted</b><progress data-tone="low" value="{item["accepted"]}" '
            f'max="{total}">{item["accepted"]}</progress></span>'
            f'<span><b>Suppressed</b><progress data-tone="medium" '
            f'value="{item["suppressed"]}" max="{total}">{item["suppressed"]}</progress></span>'
            "</div>"
            f"<em>{item['total']}</em>"
            "</div>"
        )
    return '<div class="er-remed-chart">' + "".join(rendered) + "</div>"


def _waterfall_html(remediation: dict[str, Any]) -> str:
    if remediation.get("projected_risk_reduction") == "not supplied":
        return (
            '<div class="er-waterfall er-empty-state">'
            "<strong>not supplied</strong>"
            "<p>No remediation outcome model, SLA history, or projected risk-reduction "
            "series was supplied with this run.</p>"
            "</div>"
        )
    return '<p class="er-empty">not supplied</p>'


def _next_steps_html(items: list[dict[str, str]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<ol class="er-action-list er-next-steps er-next-steps-vertical">'
        + "".join(
            f'<li data-tone="{escape(item["tone"])}"><strong>{escape(item["title"])}</strong>'
            f"<span>{escape(item['body'])}</span></li>"
            for item in items
        )
        + "</ol>"
    )


def _owner_action_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    body = "".join(
        "<tr>"
        f"<td><strong>{escape(item['owner'])}</strong></td>"
        f"<td>{escape(str(item['critical']))}</td>"
        f"<td>{escape(str(item['kev']))}</td>"
        f"<td>{escape(str(item['epss']))}</td>"
        f"<td>{escape(item['due'])}</td>"
        f"<td>{escape(item['status'])}</td>"
        "</tr>"
        for item in rows
    )
    return (
        '<div class="er-table-wrap"><table class="er-table er-table-compact">'
        "<thead><tr><th>Owner</th><th>Critical</th><th>KEV</th><th>EPSS elevated</th>"
        "<th>Due date</th><th>Status</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _focus_cards_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-provider-cards er-focus-card-grid">'
        + "".join(
            f'<article class="er-focus-card" data-tone="{escape(item["tone"])}">'
            f"<strong>{escape(item['label'])}</strong>"
            f"<p>{escape(item['body'])}</p>"
            "<ul>"
            + "".join(f"<li>{escape(action)}</li>" for action in item["actions"])
            + "</ul></article>"
            for item in items
        )
        + "</div>"
    )


def _decision_principles_html() -> str:
    items = [
        {
            "title": "Focus on the right risks, not just the loud ones.",
            "body": "Prioritize exploitation likelihood and business impact alongside severity.",
            "tone": "info",
        },
        {
            "title": "CVSS alone is not sufficient.",
            "body": "KEV, EPSS, asset exposure, and governance state change the real order.",
            "tone": "accent",
        },
        {
            "title": "ATT&CK improves defensive review.",
            "body": (
                "Mapped tactics help reviewers understand source-backed behavior categories "
                "and likely impact without claiming active exploitation."
            ),
            "tone": "success",
        },
    ]
    return (
        '<div class="er-provider-cards er-section-table">'
        + "".join(
            f'<article class="er-focus-card" data-tone="{escape(item["tone"])}">'
            f"<strong>{escape(item['title'])}</strong><p>{escape(item['body'])}</p></article>"
            for item in items
        )
        + "</div>"
    )


__all__ = [
    "_decision_principles_html",
    "_focus_cards_html",
    "_next_steps_html",
    "_owner_action_table",
    "_remediation_priority_chart",
    "_waterfall_html",
]
