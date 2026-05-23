"""Small HTML components for executive reports."""

from __future__ import annotations

from app.services.report_formatting import safe_html as _safe_html


def _metric_tone(label: str) -> str:
    normalized = label.casefold()
    if "critical" in normalized or "expired" in normalized:
        return "critical"
    if "high" in normalized or "review due" in normalized or "expiring" in normalized:
        return "warning"
    if "vex" in normalized or "accepted" in normalized:
        return "info"
    if "fixed" in normalized or "resolved" in normalized:
        return "success"
    return "neutral"


def _html_metric(label: str, value: object) -> str:
    return (
        f'<div class="metric" data-tone="{_metric_tone(label)}">'
        f"<span>{_safe_html(label)}</span>"
        f"<strong>{_safe_html(value)}</strong>"
        "</div>"
    )


__all__ = ["_html_metric"]
