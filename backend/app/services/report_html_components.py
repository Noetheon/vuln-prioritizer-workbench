"""Small HTML components for executive reports."""

from __future__ import annotations

from app.services.report_formatting import safe_html as _safe_html


def _metric_tone(label: str, value: object | None = None) -> str:
    normalized = label.casefold()
    value_normalized = str(value or "").casefold()

    if "provider freshness" in normalized:
        if value_normalized == "fresh":
            return "success"
        if value_normalized == "warning":
            return "warning"
        if value_normalized == "stale":
            return "critical"
        return "info"

    critical_terms = ["open actionable", "kev backed", "emergency", "internet", "critical"]
    if any(x in normalized for x in critical_terms):
        return "critical"
    if any(x in normalized for x in ["accepted", "review due", "expiring", "freshness", "warning"]):
        return "warning"
    if any(x in normalized for x in ["fixed", "resolved", "bundle", "success"]):
        return "success"
    return "info"


def _html_metric(label: str, value: object) -> str:
    return (
        f'<div class="metric" data-tone="{_metric_tone(label, value)}">'
        f"<span>{_safe_html(label)}</span>"
        f"<strong>{_safe_html(value)}</strong>"
        "</div>"
    )


__all__ = ["_html_metric"]
