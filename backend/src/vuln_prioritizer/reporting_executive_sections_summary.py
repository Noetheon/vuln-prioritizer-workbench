"""Executive report summary HTML helpers."""
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


def _prioritization_flow_html(model: dict[str, Any]) -> str:
    source_counts = {
        item["label"]: f"{item['count']}/{item['total']}" for item in model["source_coverage"]
    }
    return (
        '<div class="er-flow-map">'
        '<div class="er-flow-source">'
        "<strong>Source Signals</strong>"
        f"<span>NVD {escape(source_counts.get('NVD', '0/0'))}</span>"
        f"<span>EPSS {escape(source_counts.get('FIRST EPSS', '0/0'))}</span>"
        f"<span>KEV {escape(source_counts.get('CISA KEV', '0/0'))}</span>"
        f"<span>Asset context {escape(source_counts.get('Asset context', '0/0'))}</span>"
        "</div>"
        '<div class="er-flow-engine">'
        "<strong>Priority Engine</strong>"
        "<span>Deterministic scoring and governance normalization</span>"
        "</div>"
        '<div class="er-flow-output">'
        "<strong>Prioritized Findings</strong>"
        f"<span>{escape(_kpi_value(model, 'Findings'))} visible finding(s)</span>"
        f"<span>{escape(_kpi_value(model, 'KEV'))} KEV-listed</span>"
        f"<span>{escape(str(model['attack']['mapped_cves']))} ATT&amp;CK-mapped</span>"
        "<span>Focus on what matters first</span>"
        "</div>"
        "</div>"
    )


def _pipeline_html() -> str:
    steps = [
        ("Inputs", "Findings, assets, VEX, waivers"),
        ("Normalize", "Deduplicate and resolve CVEs"),
        ("Enrich", "NVD, EPSS, KEV"),
        ("Context", "Assets and ATT&CK"),
        ("Prioritize", "Transparent rules"),
        ("Report", "HTML and evidence"),
    ]
    return (
        '<div class="er-pipeline">'
        + "".join(
            '<div class="er-pipeline-step">'
            f'<span class="er-step-icon">{index}</span>'
            f"<strong>{escape(title)}</strong>"
            f"<small>{escape(body)}</small>"
            "</div>"
            for index, (title, body) in enumerate(steps, start=1)
        )
        + "</div>"
    )


def _summary_items(model: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "title": f"{_kpi_value(model, 'KEV')} KEV-listed finding(s)",
            "body": "Treat known exploited vulnerabilities as urgent regardless of CVSS alone.",
            "tone": "critical",
        },
        {
            "title": f"{_kpi_value(model, 'EPSS ≥ 0.5')} EPSS elevated finding(s)",
            "body": "High exploit likelihood should pull remediation earlier in the queue.",
            "tone": "success",
        },
        {
            "title": f"{_kpi_value(model, 'ATT&CK mapped')} ATT&CK mapped finding(s)",
            "body": "Use mapped techniques to understand adversary behavior and likely impact.",
            "tone": "accent",
        },
        {
            "title": f"{_kpi_value(model, 'VEX suppressed')} VEX suppressed finding(s)",
            "body": "Suppressed findings remain visible as governance evidence.",
            "tone": "low",
        },
    ]


def _leadership_items(model: dict[str, Any]) -> list[dict[str, str]]:
    critical = _kpi_value(model, "Critical")
    kev = _kpi_value(model, "KEV")
    epss = _kpi_value(model, "EPSS ≥ 0.5")
    return [
        {
            "title": f"{kev} known exploited",
            "body": "KEV entries represent exploitation observed in the wild.",
            "tone": "critical",
        },
        {
            "title": f"{epss} elevated likelihood",
            "body": "EPSS highlights findings with higher near-term exploitation probability.",
            "tone": "success",
        },
        {
            "title": f"{critical} critical priority",
            "body": "Focus engineering capacity on the priority queue before broad cleanup.",
            "tone": "accent",
        },
    ]


def _attack_value_items() -> list[dict[str, str]]:
    return [
        {
            "title": "Adds defensive behavior context",
            "body": (
                "Maps prioritized findings to ATT&CK behavior categories for detection "
                "and remediation review."
            ),
            "tone": "accent",
        },
        {
            "title": "Improves defensive sequence review",
            "body": (
                "Shows source-backed tactics and techniques that may need coverage review; "
                "it is not exploit proof."
            ),
            "tone": "success",
        },
        {
            "title": "Keeps mappings reviewable",
            "body": "Only supplied source mappings are rendered; no CVE-to-ATT&CK guesses.",
            "tone": "high",
        },
    ]


def _summary_item(item: dict[str, str]) -> str:
    return (
        f'<article class="er-summary-item" data-tone="{escape(item["tone"])}">'
        f"<strong>{escape(item['title'])}</strong>"
        f"<p>{escape(item['body'])}</p>"
        "</article>"
    )


__all__ = [
    "_attack_value_items",
    "_leadership_items",
    "_pipeline_html",
    "_prioritization_flow_html",
    "_summary_item",
    "_summary_items",
]
