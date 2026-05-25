"""Governed evidence state HTML helpers."""

from __future__ import annotations

from collections import Counter

from app.services.report_formatting import safe_html as _safe_html


def html_governed_state_summary(
    actionability: Counter[str],
    under_investigation: int,
) -> str:
    """Html governed state summary function."""
    rows = [
        ("Accepted risk", actionability.get("accepted", 0), "Review owner, expiry and sign-off."),
        ("VEX suppressed", actionability.get("suppressed", 0), "Retain VEX evidence and scope."),
        ("Fixed findings", actionability.get("fixed", 0), "Keep validation evidence visible."),
        ("Under investigation", under_investigation, "Complete investigation before closure."),
    ]
    row_html = "\n".join(
        "            <tr>"
        f"<td>{_safe_html(label)}</td>"
        f"<td>{_safe_html(count)}</td>"
        f"<td>{_safe_html(action)}</td>"
        "</tr>"
        for label, count, action in rows
    )
    return (
        "      <h3>Governed Evidence States</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table class='compact-table'>\n"
        "          <thead><tr><th>State</th><th>Findings</th>"
        "<th>Required Governance Action</th></tr></thead>\n"
        f"          <tbody>\n{row_html}\n          </tbody>\n"
        "        </table>\n"
        "      </div>"
    )


__all__ = ["html_governed_state_summary"]
