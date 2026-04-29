"""Executive report HTML document renderer."""

from __future__ import annotations

from html import escape
from typing import Any

from vuln_prioritizer.reporting_executive_constants import EXECUTIVE_REPORT_CSS
from vuln_prioritizer.reporting_executive_model import build_executive_report_model
from vuln_prioritizer.reporting_executive_sections import (
    _attack_context_section,
    _evidence_section,
    _nav_link,
    _overview_section,
    _priority_findings_section,
    _remediation_section,
    _risk_posture_section,
    _workspace_app_header_html,
    _workspace_nav_html,
)


def render_executive_report_html(
    report_payload_or_model: dict[str, Any],
    *,
    stylesheet_href: str | None = None,
    script_href: str | None = None,
    include_inline_styles: bool = True,
    back_href: str | None = None,
) -> str:
    """Render a static executive report HTML document."""
    model = (
        report_payload_or_model
        if "kpis" in report_payload_or_model and "priority_findings" in report_payload_or_model
        else build_executive_report_model(report_payload_or_model)
    )
    style_block = f"<style>{EXECUTIVE_REPORT_CSS}</style>" if include_inline_styles else ""
    link_block = (
        f'<link rel="stylesheet" href="{escape(stylesheet_href)}">'
        if stylesheet_href and not include_inline_styles
        else ""
    )
    script_block = f'<script src="{escape(script_href)}"></script>' if script_href else ""
    back_link = (
        f'<a class="er-button" href="{escape(back_href)}">Back to run artifacts</a>'
        if back_href
        else ""
    )
    workspace_nav = _workspace_nav_html(model.get("workspace_nav"), interactive=bool(script_href))
    app_header = _workspace_app_header_html() if workspace_nav else ""
    layout_class = "er-app-layout has-workspace-nav" if workspace_nav else "er-app-layout"
    compatibility = " ".join(escape(label) for label in model["compatibility_labels"])
    generated_at_display = escape(model.get("generated_at_display", model["generated_at"]))
    report_period_display = escape(model.get("report_period_display", model["report_period"]))
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(model["title"])} · Executive Report</title>
    {script_block}
    {link_block}
    {style_block}
  </head>
  <body class="executive-report-page">
    {app_header}
    <div class="{layout_class}">
      {workspace_nav}
    <main class="er-shell">
      <header class="er-report-header">
        <div class="er-compat-heading"><h1>Vulnerability prioritization report</h1></div>
        <div class="er-page-title">
          <p class="er-eyebrow">Executive report</p>
          <h1>Executive Report</h1>
          <p class="er-report-intro">
            Prioritized security story for <strong>{escape(model["title"])}</strong>.
            Review source signals, ATT&amp;CK context, remediation actions, and
            evidence quality from this analysis run.
          </p>
        </div>
        <div class="er-report-meta" aria-label="Report metadata">
          <span><em>Project</em><strong>{escape(model["title"])}</strong></span>
          <span><em>Input</em><strong>{escape(model["input_filename"])}</strong></span>
          <span><em>Generated</em><strong>{generated_at_display}</strong></span>
          <span><em>Report period</em><strong>{report_period_display}</strong></span>
          {back_link}
        </div>
      </header>

      <nav class="er-section-nav" aria-label="Report sections">
        {"".join(_nav_link(item) for item in model["nav"])}
      </nav>

      <p class="er-sr-note">{compatibility}</p>

      {_overview_section(model)}
      {_risk_posture_section(model)}
      {_priority_findings_section(model)}
      {_attack_context_section(model)}
      {_remediation_section(model)}
      {_evidence_section(model)}
    </main>
    </div>
  </body>
</html>
"""
