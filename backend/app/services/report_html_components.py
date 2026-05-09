"""Small HTML components for executive reports."""

from __future__ import annotations

from app.services.report_formatting import safe_html as _safe_html


def _html_metric(label: str, value: object) -> str:
    return (
        '<div class="metric">'
        f"<span>{_safe_html(label)}</span>"
        f"<strong>{_safe_html(value)}</strong>"
        "</div>"
    )


__all__ = ["_html_metric"]
