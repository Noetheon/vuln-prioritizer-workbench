"""Executive report model and HTML renderer."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from html import escape
from typing import Any

from vuln_prioritizer.scoring import determine_cvss_only_priority

PRIORITY_ORDER = ("Critical", "High", "Medium", "Low")
PRIORITY_TONES = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}
SECTION_NAV = [
    ("executive-brief", "Executive Security Overview"),
    ("risk-posture", "Risk Posture and Source Signals"),
    ("priority-findings", "Priority Findings"),
    ("attack-context", "MITRE ATT&CK Threat Context"),
    ("remediation-plan", "Executive Actions and Remediation Plan"),
    ("evidence-quality", "Evidence, Data Quality and Methodology"),
]


def build_executive_report_model(
    report_payload: dict[str, Any],
    *,
    project_name: str | None = None,
    project_id: str | None = None,
    run_id: str | None = None,
    input_filename: str | None = None,
    reports: list[Any] | None = None,
    evidence_bundles: list[Any] | None = None,
    provider_snapshot: Any | None = None,
) -> dict[str, Any]:
    """Build a deterministic executive report view model from an analysis payload."""
    metadata = _dict_value(report_payload.get("metadata"))
    attack_summary = _dict_value(report_payload.get("attack_summary"))
    findings = [item for item in report_payload.get("findings", []) if isinstance(item, dict)]
    counts_by_priority = _priority_counts(metadata, findings)
    sorted_findings = sorted(findings, key=_finding_sort_key)
    valid_input = _positive_int(metadata.get("valid_input")) or len(findings)
    total_findings = _positive_int(metadata.get("findings_count")) or len(findings)
    title = project_name or _basename(metadata.get("input_path")) or "Vuln Prioritizer"
    generated_at = _text(metadata.get("generated_at"), default="not available")
    report_period = _report_period(metadata, generated_at)
    display_input = input_filename or _basename(metadata.get("input_path")) or "not available"
    source_coverage = _source_coverage(metadata, findings, attack_summary, valid_input)
    risk_drivers = _risk_driver_model(findings, attack_summary)
    business_exposure = _business_exposure_model(findings)
    attack = _attack_model(metadata, attack_summary, findings)
    remediation = _remediation_model(findings)
    evidence = _evidence_model(
        metadata,
        findings,
        reports or [],
        evidence_bundles or [],
        provider_snapshot,
    )

    return {
        "title": title,
        "subtitle": "Executive security overview",
        "run_id": run_id,
        "input_filename": display_input,
        "generated_at": generated_at,
        "generated_at_display": _format_report_timestamp(generated_at),
        "report_period": report_period,
        "report_period_display": _format_report_timestamp(report_period),
        "nav": [{"id": key, "label": label} for key, label in SECTION_NAV],
        "workspace_nav": _workspace_nav(project_id, run_id, title),
        "summary": _executive_summary(metadata, findings, counts_by_priority, attack_summary),
        "kpis": _kpis(metadata, findings, counts_by_priority, attack_summary),
        "overview_metrics": _overview_metrics(metadata, findings, attack, remediation),
        "priority_distribution": _priority_distribution(counts_by_priority, total_findings),
        "risk_drivers": risk_drivers,
        "source_coverage": source_coverage,
        "provider_cards": _provider_cards(source_coverage),
        "severity_signal_rows": _severity_signal_rows(findings),
        "scatter_points": _scatter_points(sorted_findings[:80]),
        "business_exposure": business_exposure,
        "top_services": _counter_rows(_service_counter(findings), total_findings),
        "top_owners": _counter_rows(_owner_counter(findings), total_findings),
        "top_assets": _counter_rows(_asset_counter(findings), total_findings),
        "asset_risk_rows": _asset_risk_rows(findings),
        "priority_kpis": _priority_kpis(findings, sorted_findings, attack),
        "priority_interpretation": _priority_interpretation(findings, attack),
        "priority_findings": [_finding_row(finding) for finding in sorted_findings[:15]],
        "finding_dossiers": [_finding_dossier_model(finding) for finding in sorted_findings[:8]],
        "attack": attack,
        "remediation": remediation,
        "governance": _governance_model(metadata, findings),
        "missing_context": _missing_context_model(metadata, findings, attack_summary),
        "evidence": evidence,
        "input_sources": _input_sources_model(metadata, findings),
        "provider_transparency": _provider_transparency_model(
            metadata, findings, provider_snapshot
        ),
        "methodology": _methodology_model(metadata),
        "compatibility_labels": [
            "How to Read This Report",
            "Key Signals",
            "Coverage & Context",
            "Decision & Action",
            "ATT&CK & Governance",
            "Priority Queue",
            "Finding Dossiers",
            "Provider transparency",
            "Action plan",
            "CVSS-only baseline delta",
            "Provider evidence",
            "Suppressed by VEX",
            "Known exploited",
            "Critical / KEV",
            "Known exploited (KEV)",
            "vuln-prioritizer analyze --attack-source ctid-json",
            "vuln-prioritizer analyze --waiver-file waivers.yml",
        ],
    }


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


def _overview_section(model: dict[str, Any]) -> str:
    return f"""
<section class="er-section" id="executive-brief" data-section="executive-brief">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">01</p>
      <h2>Executive Security Overview</h2>
    </div>
    <p>{escape(model["summary"])}</p>
  </div>
  <div class="er-kpi-grid er-overview-kpis">
    {"".join(_kpi_card(item) for item in model["overview_metrics"])}
  </div>
  <div class="er-overview-layout">
    <div class="er-overview-main">
      <article class="er-panel">
        <h3>How Prioritization Works</h3>
        {_prioritization_flow_html(model)}
      </article>
      <article class="er-panel">
        <h3>Top Priority Findings</h3>
        {_compact_findings_table(model["priority_findings"][:5])}
      </article>
    </div>
    <div class="er-overview-side">
      <article class="er-panel">
        <h3>Top Risk Drivers</h3>
        <div class="er-bar-stack">
          {"".join(_driver_row(item) for item in model["risk_drivers"])}
        </div>
        <p class="er-muted">Signal distribution from CVSS, EPSS, KEV, exposure,
        and ATT&amp;CK context.</p>
      </article>
      <article class="er-panel er-panel-accent">
        <h3>Executive Summary</h3>
        <div class="er-summary-list">
          {"".join(_summary_item(item) for item in _summary_items(model))}
        </div>
      </article>
    </div>
  </div>
</section>
"""


def _risk_posture_section(model: dict[str, Any]) -> str:
    return f"""
<section class="er-section" id="risk-posture" data-section="key-signals">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">02</p>
      <h2>Risk Posture and Source Signals</h2>
    </div>
    <p>Where risk is concentrated and which source signals are shaping the queue.</p>
  </div>
  <article class="er-panel er-coverage-context-panel">
    <h3>Coverage &amp; Context</h3>
    <p class="er-muted">Provider, asset, VEX, and ATT&amp;CK enrichment coverage against
    the findings in this run.</p>
    <div class="er-signal-card-row">
      {"".join(_coverage_card(item) for item in model["source_coverage"][:6])}
    </div>
  </article>
  <div class="er-two-col er-risk-chart-grid">
    <article class="er-panel">
      <h3>Findings by Severity and Signal</h3>
      {_severity_signal_chart(model["severity_signal_rows"])}
      <p class="er-muted">Stacked counts show source signals per severity band.
      Signals can overlap.</p>
    </article>
    <article class="er-panel">
      <h3>CVSS vs EPSS</h3>
      {_quadrant_scatter_svg(model["scatter_points"])}
      {_threshold_legend_html()}
      <p class="er-muted">Each point represents a finding.
      Red outlines mark KEV-listed findings.</p>
    </article>
  </div>
  <article class="er-panel er-section-table er-provider-signal-panel">
    <h3>Provider Signals</h3>
    {_provider_cards_html(model["provider_cards"])}
  </article>
  <div class="er-three-col er-top-rollups">
    {_asset_signal_panel(model["asset_risk_rows"])}
    {_business_exposure_panel(model["business_exposure"])}
    <article class="er-panel">
      <h3>What Leadership Should Know</h3>
      <div class="er-summary-list">
        {"".join(_summary_item(item) for item in _leadership_items(model))}
      </div>
    </article>
  </div>
</section>
"""


def _priority_findings_section(model: dict[str, Any]) -> str:
    rows = "".join(_finding_table_row(item) for item in model["priority_findings"])
    if not rows:
        rows = (
            '<tr><td colspan="11" class="er-empty">'
            "No visible findings matched this export.</td></tr>"
        )
    return f"""
<section class="er-section" id="priority-findings" data-section="priority-findings">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">03</p>
      <h2>Priority Findings</h2>
    </div>
    <p>Which vulnerabilities should be fixed first and why.</p>
  </div>
  <div class="er-kpi-grid compact">
    {"".join(_kpi_card(item) for item in model["priority_kpis"])}
  </div>
  <div class="er-three-col er-priority-analysis-grid">
    <article class="er-panel">
      <h3>Top Prioritized Vulnerabilities</h3>
      {_ranked_finding_bars(model["priority_findings"][:10])}
    </article>
    <article class="er-panel">
      <h3>Priority Logic</h3>
      {_quadrant_scatter_svg(model["scatter_points"])}
      {_threshold_legend_html()}
      <p class="er-muted">High EPSS plus high CVSS/KEV moves findings into the urgent queue.</p>
    </article>
    <article class="er-panel er-panel-accent">
      <h3>Why Findings Became Priority</h3>
      {_signal_donut(model["risk_drivers"])}
      {_priority_interpretation_html(model["priority_interpretation"])}
    </article>
  </div>
  <div class="er-priority-subhead">
    <p class="er-eyebrow">Priority Queue</p>
    <h3>Actionable queue with preserved routing context</h3>
  </div>
  <div class="er-table-wrap er-section-table">
    <table class="er-table">
      <thead>
        <tr>
          <th>#</th><th>CVE</th><th>Priority</th><th>KEV</th><th>EPSS</th>
          <th>CVSS</th><th>ATT&amp;CK</th><th>Asset / Service</th><th>Owner</th>
          <th>Status</th><th>Action</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <article class="er-panel er-section-table">
    <h3>Finding Dossiers</h3>
    <p class="er-muted">Detailed CVE views with decision context, provider evidence,
    ATT&amp;CK signals, governance state, and CVSS-only baseline delta.</p>
    {_finding_dossiers_html(model["finding_dossiers"])}
  </article>
</section>
"""


def _attack_context_section(model: dict[str, Any]) -> str:
    attack = model["attack"]
    return f"""
<section class="er-section" id="attack-context" data-section="attack-governance">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">04</p>
      <h2>MITRE ATT&amp;CK Threat Context</h2>
    </div>
    <p>How prioritized findings map to adversary behavior. Context only; no heuristic mappings.</p>
  </div>
  <div class="er-kpi-grid compact er-attack-kpis">
    {_mini_metric("Mapped CVEs", attack["mapped_cves"])}
    {_mini_metric("Unmapped CVEs", attack["unmapped_cves"])}
    {_mini_metric("Techniques", attack["technique_count"])}
    {_mini_metric("Tactics", attack["tactic_count"])}
    {"".join(_mini_metric(item["label"], item["value"]) for item in attack["related_counts"])}
  </div>
  <div class="er-three-col er-attack-summary-grid">
    <article class="er-panel">
      <h3>Mapped Findings by Tactic</h3>
      <div class="er-bar-stack">{_distribution_rows(attack["top_tactics"])}</div>
    </article>
    <article class="er-panel">
      <h3>Technique and Tactic Density</h3>
      <div class="er-heatmap">
        {_attack_heatmap(attack["top_techniques"], attack["top_tactics"])}
      </div>
    </article>
    <article class="er-panel er-panel-accent">
      <h3>Why ATT&amp;CK Context Matters</h3>
      <div class="er-summary-list">
        {"".join(_summary_item(item) for item in _attack_value_items())}
      </div>
    </article>
  </div>
  <div class="er-two-col er-section-table">
    <article class="er-panel">
      <h3>Technique Density by Tactic and Asset Group</h3>
      {_attack_asset_matrix_html(attack)}
    </article>
    <article class="er-panel">
      <h3>Top ATT&amp;CK-Mapped Findings</h3>
      {_attack_mapped_findings_table(attack["top_mapped_findings"])}
    </article>
  </div>
  <div class="er-two-col er-section-table">
    <article class="er-panel">
      <h3>Illustrative TTP Chain</h3>
      {_ttp_chain(attack["top_techniques"])}
      <p class="er-muted">Illustrative example only. Not a guaranteed attack path.</p>
    </article>
    <article class="er-panel">
      <h3>Mapping Evidence</h3>
      <p class="er-muted">{escape(attack["note"])}</p>
      <div class="er-warning-list">
        {"".join(f"<p>{escape(_truncate(item, 260))}</p>" for item in attack["finding_notes"])}
      </div>
      <dl class="er-detail-list">
        <dt>Source</dt><dd>{escape(attack["source"])}</dd>
        <dt>Version</dt><dd>{escape(attack["version"])}</dd>
        <dt>Mapping hash</dt><dd>{escape(attack["mapping_hash"])}</dd>
      </dl>
    </article>
  </div>
  <article class="er-panel er-section-table">
    <h3>Most common techniques in current priority set</h3>
    {_technique_strip_html(attack["technique_strip"])}
  </article>
  <div class="er-two-col er-section-table">
    <article class="er-panel">
      <h3>Governance state</h3>
      {_governance_state_html(model["governance"])}
    </article>
    <article class="er-panel">
      <h3>Missing context</h3>
      {_missing_context_html(model["missing_context"])}
    </article>
  </div>
</section>
"""


def _remediation_section(model: dict[str, Any]) -> str:
    remediation = model["remediation"]
    return f"""
<section class="er-section" id="remediation-plan" data-section="remediation-plan">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">05</p>
      <h2>Executive Actions and Remediation Plan</h2>
    </div>
    <p>What should happen next across security and engineering.</p>
  </div>
  <div class="er-kpi-grid compact er-action-kpis">
    {_mini_metric("Open action items", remediation["open"])}
    {_mini_metric("Open KEV action items", remediation["kev_open"])}
    {_mini_metric("Waiver review due", remediation["review_due"])}
    {_mini_metric("Median time to remediate", remediation["median_ttr"])}
    {_mini_metric("Projected risk reduction", remediation["projected_risk_reduction"])}
  </div>
  <div class="er-remediation-board">
    <div class="er-remediation-main">
      <div class="er-two-col er-remediation-charts">
        <article class="er-panel">
          <h3>Remediation by Priority</h3>
          {_remediation_priority_chart(remediation["priority_status"])}
          <p class="er-muted">Counts reflect current finding status, waiver, and VEX state.</p>
        </article>
        <article class="er-panel">
          <h3>Projected Weighted Risk Reduction</h3>
          {_waterfall_html(remediation)}
        </article>
      </div>
      <div class="er-two-col er-section-table er-action-detail-grid">
        <article class="er-panel">
          <h3>Owner Action List</h3>
          {_owner_action_table(remediation["owner_action_rows"])}
        </article>
        <article class="er-panel">
          <h3>Remediation Focus Areas</h3>
          {_focus_cards_html(remediation["focus_cards"])}
        </article>
      </div>
    </div>
    <article class="er-panel er-panel-accent er-next-actions-panel">
      <p class="er-eyebrow">Decision &amp; Action</p>
      <h3>Next 30 Days</h3>
      {_next_steps_html(remediation["next_steps"])}
    </article>
  </div>
  {_decision_principles_html()}
</section>
"""


def _evidence_section(model: dict[str, Any]) -> str:
    evidence = model["evidence"]
    methodology = model["methodology"]
    return f"""
<section class="er-section" id="evidence-quality" data-section="evidence-quality">
  <div class="er-section-head">
    <div>
      <p class="er-eyebrow">06</p>
      <h2>Evidence, Data Quality and Methodology</h2>
    </div>
    <p>How the analysis was produced and how trustworthy the results are.</p>
  </div>
  <div class="er-kpi-grid compact">
    {_mini_metric("Imported findings", _kpi_value(model, "Findings"))}
    {_mini_metric("Provider coverage", _coverage_average(model["source_coverage"][:3]))}
    {_mini_metric("Mappings reviewed", model["attack"]["mapped_cves"])}
    {_mini_metric("Evidence bundle", "available" if evidence["artifacts"] else "not generated")}
  </div>
  <article class="er-panel er-pipeline-panel">
    <h3>Analysis Pipeline</h3>
    {_pipeline_html()}
  </article>
  <div class="er-two-col er-evidence-core-grid">
    <article class="er-panel">
      <h3>Provider Freshness Matrix</h3>
      {_provider_freshness_table(evidence["provider_rows"])}
    </article>
    <article class="er-panel">
      <h3>Data Quality Summary</h3>
      {_quality_matrix_html(evidence["quality_rows"])}
      {_quality_notes_html(evidence["quality_notes"])}
    </article>
  </div>
  <div class="er-three-col er-evidence-support-grid">
    <article class="er-panel">
      <h3>Mapping Confidence</h3>
      {_mapping_confidence_html(evidence["mapping_confidence"])}
    </article>
    <article class="er-panel">
      <h3>Evidence Bundle Contents</h3>
      {_evidence_contents_html(evidence["bundle_contents"])}
    </article>
    <article class="er-panel">
      <h3>How to Read This Report</h3>
      <div class="er-method-grid compact">
        {"".join(_method_card(item) for item in methodology)}
      </div>
    </article>
  </div>
  <div class="er-two-col er-section-table er-evidence-lower-grid">
    <article class="er-panel">
      <h3>Input and preservation</h3>
      {_input_sources_html(model["input_sources"])}
    </article>
    <article class="er-panel">
      <h3>Provider transparency</h3>
      {_provider_transparency_html(model["provider_transparency"])}
    </article>
  </div>
</section>
"""


def _overview_metrics(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack: dict[str, Any],
    remediation: dict[str, Any],
) -> list[dict[str, str]]:
    assets = len(_asset_counter(findings))
    asset_value = f"{assets:,}" if assets else "not supplied"
    asset_detail = "Asset context supplied" if assets else "Asset context not supplied"
    epss_elevated = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    return [
        {"label": "Assets assessed", "value": asset_value, "detail": asset_detail, "tone": "info"},
        _kpi("Open findings", remediation["open"], "Actionable after VEX/waiver state", "info"),
        _kpi("KEV findings", _int_value(metadata.get("kev_hits")), "Known exploited", "critical"),
        _kpi("EPSS elevated", epss_elevated, "EPSS >= 0.5", "success"),
        _kpi("ATT&CK mapped", attack["mapped_cves"], "Supplied threat context", "accent"),
    ]


def _provider_cards(source_coverage: list[dict[str, Any]]) -> list[dict[str, Any]]:
    descriptions = {
        "NVD": "Standard vulnerability intelligence including CVSS, CPE, CWE, and references.",
        "FIRST EPSS": (
            "Predictive exploitation likelihood. Elevated EPSS highlights near-term risk."
        ),
        "CISA KEV": "Known Exploited Vulnerabilities observed being exploited in the wild.",
        "MITRE ATT&CK": "Maps findings to adversary techniques when source mappings are supplied.",
        "Asset context": (
            "Business routing, exposure, criticality, owner, service, and environment."
        ),
        "VEX": "Governance evidence for suppressed or under-investigation findings.",
    }
    tones = {
        "NVD": "info",
        "FIRST EPSS": "success",
        "CISA KEV": "critical",
        "MITRE ATT&CK": "accent",
        "Asset context": "high",
        "VEX": "low",
    }
    return [
        item
        | {
            "description": descriptions.get(item["label"], "Source coverage for this analysis."),
            "tone": tones.get(item["label"], "info"),
        }
        for item in source_coverage
    ]


def _severity_signal_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label in PRIORITY_ORDER:
        scoped = [item for item in findings if _priority_label(item) == label]
        rows.append(
            {
                "label": label,
                "tone": PRIORITY_TONES[label],
                "total": len(scoped),
                "segments": [
                    {
                        "label": "NVD severity",
                        "count": sum(
                            1 for item in scoped if _float_value(item.get("cvss_base_score")) >= 0
                        ),
                        "tone": "info",
                    },
                    {
                        "label": "EPSS elevated",
                        "count": sum(1 for item in scoped if _float_value(item.get("epss")) >= 0.5),
                        "tone": "success",
                    },
                    {
                        "label": "KEV flagged",
                        "count": sum(1 for item in scoped if item.get("in_kev")),
                        "tone": "critical",
                    },
                    {
                        "label": "ATT&CK mapped",
                        "count": sum(1 for item in scoped if item.get("attack_mapped")),
                        "tone": "accent",
                    },
                ],
            }
        )
    return rows


def _asset_risk_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            label = "Missing asset context"
        row = grouped.setdefault(label, {"label": label, "count": 0, "score": 0.0})
        row["count"] += 1
        row["score"] += _finding_signal_score(finding)
    max_score = max((item["score"] for item in grouped.values()), default=0.0)
    rows = []
    for item in grouped.values():
        rows.append(
            {
                "label": item["label"],
                "count": round(item["score"], 1),
                "findings": item["count"],
                "pct": _pct(round(item["score"] * 10), round(max_score * 10) or 1),
            }
        )
    return sorted(rows, key=lambda item: (-float(item["count"]), item["label"]))[:6]


def _priority_kpis(
    findings: list[dict[str, Any]],
    sorted_findings: list[dict[str, Any]],
    attack: dict[str, Any],
) -> list[dict[str, str]]:
    top_20 = sorted_findings[:20]
    internet_facing = sum(
        1 for item in findings if _finding_exposure(item).lower() == "internet-facing"
    )
    critical_assets = {
        _finding_asset(item)
        for item in findings
        if _finding_criticality(item).lower() in {"critical", "high"}
        and _finding_asset(item) != "not supplied"
    }
    return [
        _kpi(
            "Critical queue",
            sum(1 for item in findings if _priority_label(item) == "Critical"),
            "Highest urgency findings",
            "critical",
        ),
        _kpi(
            "KEV in top 20",
            sum(1 for item in top_20 if item.get("in_kev")),
            "Known exploited priority items",
            "critical",
        ),
        _kpi(
            "EPSS > 0.7",
            sum(1 for item in findings if _float_value(item.get("epss")) > 0.7),
            "High exploit likelihood",
            "success",
        ),
        _kpi(
            "Internet-facing assets",
            internet_facing,
            "Exposure supplied by asset context",
            "info",
        ),
        _kpi(
            "ATT&CK mapped findings",
            attack["mapped_cves"],
            "Adversary context available",
            "accent",
        ),
        _kpi(
            "Critical systems affected",
            len(critical_assets),
            "From supplied asset criticality",
            "high",
        ),
    ]


def _priority_interpretation(
    findings: list[dict[str, Any]],
    attack: dict[str, Any],
) -> list[dict[str, str]]:
    kev = sum(1 for item in findings if item.get("in_kev"))
    epss = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    exposed = sum(1 for item in findings if _finding_exposure(item) != "not supplied")
    return [
        {
            "title": "KEV and EPSS move work forward",
            "body": (
                f"{kev} finding(s) are KEV-listed and {epss} finding(s) have EPSS >= 0.5. "
                "These signals can outweigh a CVSS-only ordering."
            ),
        },
        {
            "title": "Exposure and ATT&CK add context",
            "body": (
                f"{exposed} finding(s) include supplied exposure context and "
                f"{attack['mapped_cves']} finding(s) include supplied ATT&CK mappings."
            ),
        },
    ]


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
            "title": "Adds adversary context",
            "body": "Maps prioritized findings to attacker behaviors and real-world techniques.",
            "tone": "accent",
        },
        {
            "title": "Improves attack path review",
            "body": "Shows where weaknesses can be chained into broader compromise.",
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


def _coverage_card(item: dict[str, Any]) -> str:
    return (
        '<article class="er-signal-card">'
        f"<span>{escape(item['label'])}</span>"
        f"<strong>{escape(str(item['count']))}/{escape(str(item['total']))}</strong>"
        f'<progress class="er-progress" value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        "</article>"
    )


def _severity_signal_chart(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return '<p class="er-empty">not supplied</p>'
    palette = {
        "info": "#0b63f6",
        "success": "#059669",
        "critical": "#dc2626",
        "accent": "#6d28d9",
    }
    max_value = max(
        (sum(segment["count"] for segment in row["segments"]) for row in rows), default=1
    )
    svg_rows: list[str] = []
    for index, row in enumerate(rows):
        y = 32 + index * 42
        x_cursor = 104.0
        svg_rows.append(f'<text x="12" y="{y + 13}">{escape(row["label"])}</text>')
        for segment in row["segments"]:
            count = segment["count"]
            width = (count / max_value) * 260 if max_value else 0
            color = palette.get(segment["tone"], "#0b63f6")
            if width > 0:
                svg_rows.append(
                    f'<rect x="{x_cursor:.1f}" y="{y}" width="{max(width, 4):.1f}" '
                    f'height="18" rx="4" fill="{color}"><title>'
                    f"{escape(segment['label'])}: {count}</title></rect>"
                )
            x_cursor += width
        svg_rows.append(
            f'<text x="382" y="{y + 13}" text-anchor="end">'
            f"{sum(segment['count'] for segment in row['segments'])}</text>"
        )
    legend = (
        '<div class="er-threshold-legend">'
        '<span data-tone="info">NVD severity</span>'
        '<span data-tone="success">EPSS elevated</span>'
        '<span data-tone="critical">KEV flagged</span>'
        '<span data-tone="accent">ATT&amp;CK mapped</span>'
        "</div>"
    )
    return (
        '<svg class="er-stacked-chart" viewBox="0 0 400 210" role="img" '
        'aria-label="Findings by severity and signal">'
        '<line x1="104" y1="18" x2="104" y2="188" class="er-plot-line"></line>'
        + "".join(svg_rows)
        + "</svg>"
        + legend
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


def _threshold_legend_html() -> str:
    return (
        '<div class="er-threshold-legend" aria-label="Priority threshold legend">'
        '<span data-tone="critical">High EPSS / high CVSS</span>'
        '<span data-tone="success">High EPSS / low CVSS</span>'
        '<span data-tone="high">Low EPSS / high CVSS</span>'
        '<span data-tone="low">Low EPSS / low CVSS</span>'
        "</div>"
    )


def _asset_signal_panel(rows: list[dict[str, Any]]) -> str:
    if not rows:
        body = '<p class="er-empty">not supplied</p>'
    else:
        body = (
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
            + "</div>"
        )
    return (
        '<article class="er-panel"><h3>Top Asset Groups by Weighted Risk</h3>'
        f"{body}"
        '<p class="er-muted">Signal-weighted view built from priority, CVSS, EPSS, KEV, '
        "exposure, and criticality fields supplied in the run.</p></article>"
    )


def _driver_row(item: dict[str, Any]) -> str:
    return (
        '<div class="er-driver-row">'
        f'<span class="er-driver-dot" data-tone="{escape(item["tone"])}"></span>'
        f"<span>{escape(item['label'])}</span>"
        f'<progress class="er-progress" data-tone="{escape(item["tone"])}" '
        f'value="{item["pct"]}" max="100">{item["pct"]}%</progress>'
        f"<strong>{escape(str(item['count']))}</strong>"
        "</div>"
    )


def _business_exposure_panel(rows: list[dict[str, Any]]) -> str:
    if not rows:
        body = '<p class="er-empty">not supplied</p>'
    else:
        body = (
            '<div class="er-exposure-grid">'
            + "".join(
                f'<article class="er-exposure-tile" data-tone="{escape(item["tone"])}">'
                f"<strong>{escape(item['label'])}</strong>"
                f"<span>{escape(str(item['count']))} finding(s)</span>"
                f"<small>{escape(item['criticality'])} / {escape(item['exposure'])}</small>"
                "</article>"
                for item in rows
            )
            + "</div>"
        )
    return f'<article class="er-panel"><h3>Business Exposure</h3>{body}</article>'


def _ranked_finding_bars(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">No visible findings matched this export.</p>'
    rows = []
    for item in items:
        score = _float_value(item.get("cvss"))
        pct = _pct(round(score * 10), 100) if score >= 0 else 0
        rows.append(
            '<div class="er-ranked-row">'
            f"<span>{escape(str(item['rank']))}</span>"
            f"<strong>{escape(item['cve'])}</strong>"
            f'<progress class="er-rank-progress" data-tone="{escape(item["tone"])}" '
            f'value="{pct}" max="100">{pct}%</progress>'
            f"<em>{escape(item['cvss'])}</em>"
            "</div>"
        )
    return '<div class="er-ranked-list">' + "".join(rows) + "</div>"


def _priority_interpretation_html(items: list[dict[str, str]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<div class="er-interpretation-panel">'
        + "".join(
            f"<p><strong>{escape(item['title'])}</strong><br>{escape(item['body'])}</p>"
            for item in items
        )
        + "</div>"
    )


def _signal_donut(items: list[dict[str, Any]]) -> str:
    active = [item for item in items if item["count"] > 0]
    total = sum(item["count"] for item in active)
    if total <= 0:
        return '<p class="er-empty">not supplied</p>'
    palette = {
        "critical": "#dc2626",
        "high": "#f97316",
        "medium": "#d99a07",
        "low": "#64748b",
        "success": "#059669",
        "accent": "#6d28d9",
        "info": "#0b63f6",
    }
    cursor = 0.0
    segments: list[str] = []
    for item in active:
        pct = (item["count"] / total) * 100
        color = palette.get(item["tone"], "#0b63f6")
        segments.append(
            '<circle class="er-donut-segment" cx="60" cy="60" r="40" '
            f'data-insight="{escape(item["label"])}: {escape(str(item["count"]))} '
            f'signal(s), {escape(str(item["pct"]))}%" '
            'fill="none" stroke-width="18" pathLength="100" '
            f'stroke="{color}" stroke-dasharray="{pct:.2f} {100 - pct:.2f}" '
            f'stroke-dashoffset="{-cursor:.2f}" transform="rotate(-90 60 60)"></circle>'
        )
        cursor += pct
    legend = "".join(
        '<div class="er-donut-legend-row">'
        f'<span class="er-driver-dot" data-tone="{escape(item["tone"])}"></span>'
        f"<strong>{escape(item['label'])}</strong><em>{item['pct']}%</em>"
        "</div>"
        for item in active
    )
    return (
        '<div class="er-donut-wrap">'
        '<svg class="er-donut-svg" viewBox="0 0 120 120" role="img" '
        'aria-label="Priority signal mix">'
        '<circle class="er-donut-bg" cx="60" cy="60" r="40"></circle>'
        + "".join(segments)
        + f'<text x="60" y="56" class="er-donut-total">{total}</text>'
        '<text x="60" y="73" class="er-donut-caption">signals</text>'
        "</svg>"
        f'<div class="er-donut-legend">{legend}</div>'
        "</div>"
    )


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


def _ttp_chain(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="er-empty">not supplied</p>'
    chain = items[:5]
    return (
        '<div class="er-ttp-chain">'
        + "".join(f"<span>{escape(item['label'])}</span>" for item in chain)
        + "</div>"
    )


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
            "title": "ATT&CK improves decision quality.",
            "body": (
                "Mapped tactics help reviewers understand adversary behavior and likely impact."
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


def _coverage_average(items: list[dict[str, Any]]) -> str:
    if not items:
        return "not available"
    return f"{round(sum(item['pct'] for item in items) / len(items))}%"


def _kpi_value(model: dict[str, Any], label: str) -> str:
    for item in model["kpis"]:
        if item["label"] == label:
            return str(item["value"])
    return "0"


def _kpis(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    counts_by_priority: dict[str, int],
    attack_summary: dict[str, Any],
) -> list[dict[str, str]]:
    epss_elevated = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    attack_mapped = _int_value(attack_summary.get("mapped_cves"))
    if attack_mapped == 0:
        attack_mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    return [
        _kpi("Findings", len(findings), "Imported and visible", "info"),
        _kpi("Critical", counts_by_priority.get("Critical", 0), "Highest priority", "critical"),
        _kpi("High", counts_by_priority.get("High", 0), "Elevated queue", "high"),
        _kpi("KEV", _int_value(metadata.get("kev_hits")), "Known exploited", "critical"),
        _kpi("EPSS ≥ 0.5", epss_elevated, "Elevated likelihood", "success"),
        _kpi("ATT&CK mapped", attack_mapped, "Context available", "accent"),
        _kpi("VEX suppressed", _int_value(metadata.get("suppressed_by_vex")), "Governed", "low"),
        _kpi(
            "Review due",
            _int_value(metadata.get("waiver_review_due_count")),
            "Waiver pressure",
            "high",
        ),
    ]


def _priority_distribution(
    counts_by_priority: dict[str, int],
    total_findings: int,
) -> list[dict[str, Any]]:
    total = max(total_findings, sum(counts_by_priority.values()), 1)
    return [
        {
            "label": label,
            "count": counts_by_priority.get(label, 0),
            "pct": _pct(counts_by_priority.get(label, 0), total),
            "tone": PRIORITY_TONES[label],
        }
        for label in PRIORITY_ORDER
    ]


def _source_coverage(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
    valid_input: int,
) -> list[dict[str, Any]]:
    finding_total = max(len(findings), 1)
    asset_hits = sum(1 for item in findings if _finding_asset(item) != "not supplied")
    vex_hits = sum(1 for item in findings if _vex_status(item) != "not supplied")
    attack_hits = _int_value(metadata.get("attack_hits")) or _int_value(
        attack_summary.get("mapped_cves")
    )
    rows = [
        ("NVD", _int_value(metadata.get("nvd_hits")), valid_input),
        ("FIRST EPSS", _int_value(metadata.get("epss_hits")), valid_input),
        ("CISA KEV", _int_value(metadata.get("kev_hits")), valid_input),
        ("MITRE ATT&CK", attack_hits, valid_input),
        ("Asset context", asset_hits, finding_total),
        ("VEX", vex_hits, finding_total),
    ]
    return [
        {"label": label, "count": count, "total": total, "pct": _pct(count, max(total, 1))}
        for label, count, total in rows
    ]


def _risk_driver_model(
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    drivers: list[dict[str, Any]] = [
        {
            "label": "Severity",
            "count": sum(
                1 for item in findings if _float_value(item.get("cvss_base_score")) >= 7.0
            ),
            "tone": "critical",
        },
        {
            "label": "Exploit likelihood",
            "count": sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5),
            "tone": "info",
        },
        {
            "label": "Known exploitation",
            "count": sum(1 for item in findings if item.get("in_kev")),
            "tone": "critical",
        },
        {
            "label": "Exposure",
            "count": sum(1 for item in findings if _finding_exposure(item) != "not supplied"),
            "tone": "high",
        },
        {"label": "ATT&CK context", "count": mapped, "tone": "accent"},
    ]
    total = max(sum(item["count"] for item in drivers), 1)
    return [item | {"pct": _pct(item["count"], total)} for item in drivers]


def _business_exposure_model(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            continue
        row = grouped.setdefault(
            label,
            {
                "label": label,
                "count": 0,
                "criticality": "not supplied",
                "exposure": "not supplied",
            },
        )
        row["count"] += 1
        criticality = _finding_criticality(finding)
        exposure = _finding_exposure(finding)
        if _criticality_rank(criticality) > _criticality_rank(row["criticality"]):
            row["criticality"] = criticality
        if exposure != "not supplied":
            row["exposure"] = exposure
    total = max(len(findings), 1)
    for row in grouped.values():
        tone = "critical" if row["exposure"] == "internet-facing" else "success"
        if row["criticality"] in {"critical", "high"}:
            tone = "critical" if row["criticality"] == "critical" else "high"
        rows.append(row | {"pct": _pct(row["count"], total), "tone": tone})
    return sorted(rows, key=lambda item: (-item["count"], item["label"]))[:6]


def _scatter_points(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        cvss = _float_value(finding.get("cvss_base_score"))
        epss = _float_value(finding.get("epss"))
        if cvss < 0 or epss < 0:
            continue
        base_x = 6.0 + (cvss / 10.0) * 388.0
        base_y = 214.0 - epss * 208.0
        jitter_x = ((index % 3) - 1) * 12.0
        jitter_y = (((index // 3) % 3) - 1) * 10.0
        points.append(
            {
                "cve": _text(finding.get("cve_id"), default="CVE"),
                "cvss": cvss,
                "epss": epss,
                "x": max(8.0, min(392.0, base_x + jitter_x)),
                "y": max(8.0, min(212.0, base_y + jitter_y)),
                "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
                "kev": bool(finding.get("in_kev")),
            }
        )
    return points


def _attack_model(
    metadata: dict[str, Any],
    attack_summary: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    technique_counter = _distribution_counter(attack_summary.get("technique_distribution"))
    tactic_counter = _distribution_counter(attack_summary.get("tactic_distribution"))
    if not technique_counter:
        for finding in findings:
            technique_counter.update(str(item) for item in finding.get("attack_techniques", []))
    if not tactic_counter:
        for finding in findings:
            tactic_counter.update(str(item) for item in finding.get("attack_tactics", []))
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if bool(item.get("attack_mapped")))
    unmapped = _int_value(attack_summary.get("unmapped_cves"))
    if unmapped == 0 and findings:
        unmapped = max(len(findings) - mapped, 0)
    enabled = bool(metadata.get("attack_enabled"))
    asset_matrix = _attack_asset_matrix_model(findings, tactic_counter)
    return {
        "enabled": enabled,
        "mapped_cves": mapped,
        "unmapped_cves": unmapped,
        "technique_count": len(technique_counter),
        "tactic_count": len(tactic_counter),
        "top_techniques": _distribution_model(technique_counter),
        "top_tactics": _distribution_model(tactic_counter),
        "related_counts": [
            {
                "label": "Initial Access related",
                "value": _related_tactic_count(tactic_counter, "initial access"),
            },
            {
                "label": "Privilege Escalation related",
                "value": _related_tactic_count(tactic_counter, "privilege escalation"),
            },
            {
                "label": "Execution related",
                "value": _related_tactic_count(tactic_counter, "execution"),
            },
        ],
        "asset_matrix": asset_matrix,
        "top_mapped_findings": _attack_top_mapped_findings(findings),
        "technique_strip": _distribution_model(technique_counter, limit=5),
        "finding_notes": _attack_finding_notes(findings),
        "source": _text(metadata.get("attack_source"), default="not supplied"),
        "version": _text(metadata.get("attack_version"), default="not available"),
        "mapping_hash": _text(metadata.get("attack_mapping_file_sha256"), default="not available"),
        "note": (
            "ATT&CK context is enabled and shown as adversary behavior context only."
            if enabled
            else "ATT&CK context was not supplied for this run."
        ),
    }


def _related_tactic_count(counter: Counter[str], label: str) -> int:
    target = label.replace("-", " ").lower()
    return sum(count for key, count in counter.items() if key.replace("-", " ").lower() == target)


def _attack_asset_matrix_model(
    findings: list[dict[str, Any]],
    tactic_counter: Counter[str],
) -> dict[str, Any]:
    mapped_findings = [item for item in findings if item.get("attack_mapped")]
    groups: Counter[str] = Counter()
    tactic_labels = [label for label, _ in tactic_counter.most_common(8)]
    cell_counts: Counter[tuple[str, str]] = Counter()
    for finding in mapped_findings:
        group = _finding_service(finding)
        if group == "not supplied":
            group = _finding_asset(finding)
        if group == "not supplied":
            continue
        groups[group] += 1
        for tactic in _list_values(finding.get("attack_tactics"), limit=20):
            cell_counts[(tactic, group)] += 1
    columns = [label for label, _ in groups.most_common(4)]
    rows = []
    for tactic in tactic_labels:
        rows.append(
            {
                "label": tactic,
                "cells": [
                    {
                        "group": group,
                        "count": cell_counts[(tactic, group)],
                    }
                    for group in columns
                ],
            }
        )
    return {"columns": columns, "rows": rows}


def _attack_top_mapped_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in sorted(findings, key=_finding_sort_key):
        if not finding.get("attack_mapped"):
            continue
        techniques = _list_values(finding.get("attack_techniques"), limit=1)
        tactics = _list_values(finding.get("attack_tactics"), limit=1)
        rows.append(
            {
                "cve": _text(finding.get("cve_id"), default="CVE"),
                "technique": techniques[0] if techniques else "not supplied",
                "tactic": tactics[0] if tactics else "not supplied",
                "route": _route_label(finding),
                "priority": _priority_label(finding),
                "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
            }
        )
        if len(rows) >= 6:
            break
    return rows


def _remediation_model(findings: list[dict[str, Any]]) -> dict[str, Any]:
    open_count = sum(1 for item in findings if _status(item) == "open")
    accepted = sum(1 for item in findings if _status(item) == "accepted")
    suppressed = sum(1 for item in findings if _status(item) == "suppressed")
    kev_open = sum(1 for item in findings if item.get("in_kev") and _status(item) == "open")
    review_due = sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "review_due"
    )
    total = max(len(findings), 1)
    return {
        "total": total,
        "open": open_count,
        "accepted": accepted,
        "suppressed": suppressed,
        "kev_open": kev_open,
        "review_due": review_due,
        "median_ttr": "not supplied",
        "projected_risk_reduction": "not supplied",
        "priority_status": _priority_status_rows(findings),
        "owner_rows": _counter_rows(_owner_counter(findings), len(findings)),
        "service_rows": _counter_rows(_service_counter(findings), len(findings)),
        "owner_action_rows": _owner_action_rows(findings),
        "next_steps": _next_step_rows(findings, kev_open, review_due),
        "focus_cards": _focus_cards(findings),
    }


def _owner_action_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        owner = _finding_owner(finding)
        if owner == "not supplied":
            owner = "Unassigned"
        grouped.setdefault(owner, []).append(finding)
    rows = []
    for owner, items in grouped.items():
        due_dates = [
            _kev_due_date(item)
            for item in items
            if item.get("in_kev") and _kev_due_date(item) != "not available"
        ]
        review_due = sum(
            1 for item in items if _text(item.get("waiver_status"), default="") == "review_due"
        )
        rows.append(
            {
                "owner": owner,
                "open": sum(1 for item in items if _status(item) == "open"),
                "critical": sum(1 for item in items if _priority_label(item) == "Critical"),
                "kev": sum(1 for item in items if item.get("in_kev")),
                "epss": sum(1 for item in items if _float_value(item.get("epss")) >= 0.5),
                "due": min(due_dates) if due_dates else "not supplied",
                "status": (
                    "Needs owner"
                    if owner == "Unassigned"
                    else "Review due"
                    if review_due
                    else "Ready"
                ),
            }
        )
    return sorted(rows, key=lambda item: (-item["critical"], -item["kev"], item["owner"]))


def _next_step_rows(
    findings: list[dict[str, Any]],
    kev_open: int,
    review_due: int,
) -> list[dict[str, str]]:
    internet_facing = sum(
        1 for item in findings if _finding_exposure(item).lower() == "internet-facing"
    )
    epss = sum(1 for item in findings if _float_value(item.get("epss")) >= 0.5)
    mapped = sum(1 for item in findings if item.get("attack_mapped"))
    return [
        {
            "title": "Eliminate KEV vulnerabilities first",
            "body": f"{kev_open} open KEV-listed finding(s) require urgent owner action.",
            "tone": "critical",
        },
        {
            "title": "Secure internet-facing assets",
            "body": f"{internet_facing} finding(s) include internet-facing exposure context.",
            "tone": "info",
        },
        {
            "title": "Reduce EPSS-elevated findings",
            "body": f"{epss} finding(s) have EPSS >= 0.5 and should be reviewed early.",
            "tone": "success",
        },
        {
            "title": "Review governance exceptions",
            "body": f"{review_due} waiver review(s) are due in the supplied governance data.",
            "tone": "high",
        },
        {
            "title": "Use ATT&CK context for sequencing",
            "body": f"{mapped} finding(s) have supplied ATT&CK context for attack-path review.",
            "tone": "accent",
        },
    ]


def _focus_cards(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        label = _finding_service(finding)
        if label == "not supplied":
            label = _finding_asset(finding)
        if label == "not supplied":
            label = "Missing asset context"
        grouped.setdefault(label, []).append(finding)
    cards = []
    for label, items in sorted(grouped.items(), key=lambda entry: (-len(entry[1]), entry[0]))[:3]:
        actions = []
        for finding in sorted(items, key=_finding_sort_key)[:3]:
            action = _text(finding.get("recommended_action"), default="Review finding.")
            actions.append(
                f"{_text(finding.get('cve_id'), default='CVE')}: {_truncate(action, 118)}"
            )
        tone = "critical" if any(item.get("in_kev") for item in items) else "info"
        cards.append(
            {
                "label": label,
                "body": f"{len(items)} finding(s) require remediation or governance review.",
                "actions": actions,
                "tone": tone,
            }
        )
    return cards


def _governance_model(metadata: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    suppressed = _int_value(metadata.get("suppressed_by_vex")) or sum(
        1 for item in findings if item.get("suppressed_by_vex")
    )
    under_investigation = _int_value(metadata.get("under_investigation_count")) or sum(
        1 for item in findings if item.get("under_investigation")
    )
    waived = _int_value(metadata.get("waived_count")) or sum(
        1 for item in findings if item.get("waived")
    )
    review_due = _int_value(metadata.get("waiver_review_due_count")) or sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "review_due"
    )
    expired = _int_value(metadata.get("expired_waiver_count")) or sum(
        1 for item in findings if _text(item.get("waiver_status"), default="") == "expired"
    )
    return {
        "rows": [
            {
                "label": "Suppressed by VEX",
                "value": suppressed,
                "detail": "Not exploitable or otherwise suppressed by supplied VEX evidence.",
                "tone": "low",
            },
            {
                "label": "Under investigation",
                "value": under_investigation,
                "detail": "VEX or finding state still needs validation.",
                "tone": "medium",
            },
            {
                "label": "Waived findings",
                "value": waived,
                "detail": "Accepted risk remains visible for audit review.",
                "tone": "low",
            },
            {
                "label": "Waiver review due",
                "value": review_due,
                "detail": "Requires owner review before the next governance cycle.",
                "tone": "high",
            },
            {
                "label": "Expired waivers",
                "value": expired,
                "detail": "Accepted risk is no longer current.",
                "tone": "critical",
            },
        ],
        "waiver_file": _text(metadata.get("waiver_file"), default="not supplied"),
    }


def _missing_context_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    attack_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    total = max(len(findings), 1)
    missing_cvss = sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0)
    missing_epss = sum(1 for item in findings if _float_value(item.get("epss")) < 0)
    missing_attack = sum(1 for item in findings if not item.get("attack_mapped"))
    missing_asset = sum(1 for item in findings if _finding_asset(item) == "not supplied")
    missing_owner = sum(
        1
        for item in findings
        if _finding_owner(item) == "not supplied" and _finding_service(item) == "not supplied"
    )
    warnings = len([item for item in metadata.get("warnings", []) if item])
    if (
        not bool(metadata.get("attack_enabled"))
        and _int_value(attack_summary.get("mapped_cves")) == 0
    ):
        attack_detail = "ATT&CK source not supplied for this run."
    else:
        attack_detail = "No supplied ATT&CK mapping for these findings."
    return [
        {
            "label": "Missing CVSS",
            "value": missing_cvss,
            "pct": _pct(missing_cvss, total),
            "detail": "Provider severity was not available.",
            "tone": "critical",
        },
        {
            "label": "Missing EPSS",
            "value": missing_epss,
            "pct": _pct(missing_epss, total),
            "detail": "Exploit likelihood was not available.",
            "tone": "high",
        },
        {
            "label": "Without ATT&CK context",
            "value": missing_attack,
            "pct": _pct(missing_attack, total),
            "detail": attack_detail,
            "tone": "accent",
        },
        {
            "label": "Without asset context",
            "value": missing_asset,
            "pct": _pct(missing_asset, total),
            "detail": "No matching asset ID or occurrence metadata was supplied.",
            "tone": "medium",
        },
        {
            "label": "Without owner or service",
            "value": missing_owner,
            "pct": _pct(missing_owner, total),
            "detail": "Routing needs asset owner or business service data.",
            "tone": "low",
        },
        {
            "label": "Input warnings",
            "value": warnings,
            "pct": 100 if warnings else 0,
            "detail": "Warnings recorded during import or enrichment.",
            "tone": "high" if warnings else "low",
        },
    ]


def _priority_status_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for priority in PRIORITY_ORDER:
        priority_findings = [item for item in findings if _priority_label(item) == priority]
        rows.append(
            {
                "label": priority,
                "tone": PRIORITY_TONES[priority],
                "open": sum(1 for item in priority_findings if _status(item) == "open"),
                "accepted": sum(1 for item in priority_findings if _status(item) == "accepted"),
                "suppressed": sum(1 for item in priority_findings if _status(item) == "suppressed"),
                "total": len(priority_findings),
            }
        )
    return rows


def _evidence_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    reports: list[Any],
    evidence_bundles: list[Any],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    freshness = [
        {"label": "Provider snapshot", "value": _text(metadata.get("provider_snapshot_file"))},
        {
            "label": "Locked provider data",
            "value": "yes" if metadata.get("locked_provider_data") else "no",
        },
        {"label": "NVD last sync", "value": _provider_value(provider_snapshot, "nvd_last_sync")},
        {"label": "EPSS date", "value": _provider_value(provider_snapshot, "epss_date")},
        {
            "label": "KEV catalog",
            "value": _provider_value(provider_snapshot, "kev_catalog_version"),
        },
    ]
    warnings = [str(item) for item in metadata.get("warnings", []) if item]
    provider_notes = _provider_evidence_notes(findings)
    source_formats = sorted(
        {
            str(source)
            for finding in findings
            for source in _dict_value(finding.get("provenance")).get("source_formats", [])
            if source
        }
    )
    quality_notes = warnings + [
        f"Duplicate CVEs collapsed: {_int_value(metadata.get('duplicate_cve_count'))}",
        f"Asset-context conflicts: {_int_value(metadata.get('asset_match_conflict_count'))}",
        f"VEX conflicts: {_int_value(metadata.get('vex_conflict_count'))}",
    ]
    if source_formats:
        quality_notes.append("Source formats: " + ", ".join(source_formats))
    quality_notes.extend(provider_notes)
    artifacts = _artifact_model(reports, evidence_bundles)
    return {
        "freshness": freshness,
        "quality_notes": quality_notes,
        "artifacts": artifacts,
        "provider_rows": _provider_freshness_rows(metadata, provider_snapshot),
        "quality_rows": _quality_rows(metadata, findings),
        "mapping_confidence": _mapping_confidence_model(findings),
        "bundle_contents": _bundle_contents_model(artifacts),
    }


def _provider_freshness_rows(
    metadata: dict[str, Any],
    provider_snapshot: Any | None,
) -> list[dict[str, str]]:
    locked = "locked" if metadata.get("locked_provider_data") else "not locked"
    return [
        {
            "provider": "NVD",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "nvd_last_sync")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "FIRST EPSS",
            "last_sync": _short_provider_date(_provider_value(provider_snapshot, "epss_date")),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "CISA KEV",
            "last_sync": _short_provider_date(
                _provider_value(provider_snapshot, "kev_catalog_version")
            ),
            "source_status": locked,
            "freshness": "snapshot locked"
            if metadata.get("locked_provider_data")
            else "live source",
        },
        {
            "provider": "MITRE ATT&CK",
            "last_sync": "ATT&CK " + _text(metadata.get("attack_version"), default="not supplied"),
            "source_status": "enabled" if metadata.get("attack_enabled") else "not supplied",
            "freshness": _text(metadata.get("attack_domain"), default="not supplied"),
        },
    ]


def _quality_rows(metadata: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = max(len(findings), 1)
    return [
        {
            "label": "Missing CVSS",
            "value": sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
            "pct": _pct(
                sum(1 for item in findings if _float_value(item.get("cvss_base_score")) < 0),
                total,
            ),
        },
        {
            "label": "Missing EPSS",
            "value": sum(1 for item in findings if _float_value(item.get("epss")) < 0),
            "pct": _pct(sum(1 for item in findings if _float_value(item.get("epss")) < 0), total),
        },
        {
            "label": "Findings without ATT&CK",
            "value": sum(1 for item in findings if not item.get("attack_mapped")),
            "pct": _pct(sum(1 for item in findings if not item.get("attack_mapped")), total),
        },
        {
            "label": "Suppressed by VEX",
            "value": _int_value(metadata.get("suppressed_by_vex"))
            or sum(1 for item in findings if item.get("suppressed_by_vex")),
            "pct": _pct(
                _int_value(metadata.get("suppressed_by_vex"))
                or sum(1 for item in findings if item.get("suppressed_by_vex")),
                total,
            ),
        },
        {
            "label": "Active waivers",
            "value": _int_value(metadata.get("waived_count"))
            or sum(1 for item in findings if item.get("waived")),
            "pct": _pct(
                _int_value(metadata.get("waived_count"))
                or sum(1 for item in findings if item.get("waived")),
                total,
            ),
        },
        {
            "label": "Input warnings",
            "value": len([item for item in metadata.get("warnings", []) if item]),
            "pct": 100 if metadata.get("warnings") else 0,
        },
    ]


def _mapping_confidence_model(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for finding in findings:
        mappings = finding.get("attack_mappings")
        if not isinstance(mappings, list):
            continue
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            confidence = _text(mapping.get("confidence"), default="")
            if confidence:
                counts[confidence.title()] += 1
    if not counts:
        return {
            "available": False,
            "total": sum(1 for item in findings if item.get("attack_mapped")),
            "rows": [
                {
                    "label": "Confidence scoring",
                    "count": "not supplied",
                    "detail": "The supplied ATT&CK mappings did not include confidence buckets.",
                }
            ],
        }
    total = sum(counts.values())
    return {
        "available": True,
        "total": total,
        "rows": [
            {
                "label": label,
                "count": count,
                "pct": _pct(count, total),
                "detail": f"{count} reviewed mapping(s)",
            }
            for label, count in counts.most_common()
        ],
    }


def _bundle_contents_model(artifacts: list[dict[str, str]]) -> dict[str, Any]:
    if not artifacts:
        return {
            "generated": False,
            "items": [
                {
                    "name": "analysis.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "summary.md",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "provider-snapshot.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "sha256-manifest.txt",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
            ],
        }
    return {
        "generated": True,
        "items": [
            {"name": item["label"], "detail": item["detail"], "size": "downloadable"}
            for item in artifacts
        ],
    }


def _input_sources_model(
    metadata: dict[str, Any], findings: list[dict[str, Any]]
) -> list[dict[str, str]]:
    sources = metadata.get("input_sources")
    rows: list[dict[str, str]] = []
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            rows.append(
                {
                    "input": _basename(source.get("input_path") or source.get("path")),
                    "format": _text(source.get("input_format") or source.get("format")),
                    "rows": _text(source.get("total_rows"), default="not supplied"),
                    "occurrences": _text(source.get("occurrence_count"), default="not supplied"),
                    "cves": _text(source.get("unique_cves"), default="not supplied"),
                }
            )
    if not rows:
        rows.append(
            {
                "input": _basename(metadata.get("input_path")) or "not supplied",
                "format": _text(metadata.get("input_format")),
                "rows": _text(metadata.get("total_input"), default="not supplied"),
                "occurrences": str(sum(len(_occurrences(item)) for item in findings)),
                "cves": _text(metadata.get("valid_input"), default=str(len(findings))),
            }
        )
    return rows


def _provider_transparency_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    diagnostics = _dict_value(metadata.get("nvd_diagnostics"))
    sources = metadata.get("provider_snapshot_sources") or metadata.get("data_sources") or []
    source_text = (
        ", ".join(str(item) for item in sources if item) if isinstance(sources, list) else ""
    )
    nvd_diag = []
    for label, key in (
        ("Requested", "requested"),
        ("Cache hits", "cache_hits"),
        ("Network fetches", "network_fetches"),
        ("Failures", "failures"),
        ("Content hits", "content_hits"),
    ):
        if key in diagnostics:
            nvd_diag.append({"label": label, "value": str(_int_value(diagnostics.get(key)))})
    return {
        "facts": [
            {
                "label": "Selected sources",
                "value": source_text or "not supplied",
            },
            {
                "label": "Provider snapshot",
                "value": _text(metadata.get("provider_snapshot_file")),
            },
            {
                "label": "Locked provider data",
                "value": "yes" if metadata.get("locked_provider_data") else "no",
            },
            {
                "label": "NVD last sync",
                "value": _provider_value(provider_snapshot, "nvd_last_sync"),
            },
            {
                "label": "EPSS date",
                "value": _provider_value(provider_snapshot, "epss_date"),
            },
            {
                "label": "KEV catalog",
                "value": _provider_value(provider_snapshot, "kev_catalog_version"),
            },
        ],
        "diagnostics": nvd_diag,
        "notes": _provider_evidence_notes(findings),
        "commands": [
            "vuln-prioritizer analyze --attack-source ctid-json",
            "vuln-prioritizer analyze --waiver-file waivers.yml",
        ],
    }


def _methodology_model(metadata: dict[str, Any]) -> list[dict[str, str]]:
    policy = _dict_value(metadata.get("priority_policy"))
    profile = _text(metadata.get("policy_profile"), default="default")
    high_epss = _text(policy.get("high_epss_threshold"), default="0.50")
    critical_cvss = _text(policy.get("critical_cvss_threshold"), default="9.0")
    return [
        {
            "title": "Transparent priority rules",
            "body": (
                f"Policy profile {profile}; CVSS, EPSS, and KEV determine the base priority. "
                f"Critical CVSS threshold: {critical_cvss}; high EPSS threshold: {high_epss}."
            ),
        },
        {
            "title": "Locked provider evidence",
            "body": (
                "Provider snapshots and hashes document which NVD, EPSS, and KEV data "
                "powered the run."
            ),
        },
        {
            "title": "ATT&CK as context",
            "body": (
                "ATT&CK mappings are optional, source-controlled, and never generated "
                "heuristically."
            ),
        },
        {
            "title": "Reviewable governance",
            "body": (
                "VEX and waiver states are displayed separately so accepted risk stays auditable."
            ),
        },
    ]


def _finding_row(finding: dict[str, Any]) -> dict[str, Any]:
    service = _finding_service(finding)
    asset = _finding_asset(finding)
    if service != "not supplied" and asset != "not supplied":
        asset_service = f"{service} / {asset}"
    elif service != "not supplied":
        asset_service = service
    elif asset != "not supplied":
        asset_service = asset
    else:
        asset_service = "not supplied"
    return {
        "rank": _int_value(finding.get("operational_rank"))
        or _int_value(finding.get("priority_rank")),
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "epss": _score(finding.get("epss"), digits=3),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "attack": _attack_label(finding),
        "route": _route_label(finding),
        "asset_service": asset_service,
        "owner": _finding_owner(finding),
        "status": _status_label(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "action": _text(finding.get("recommended_action"), default="Review finding."),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
    }


def _finding_dossier_model(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = _dict_value(finding.get("provider_evidence"))
    nvd = _dict_value(evidence.get("nvd"))
    epss = _dict_value(evidence.get("epss"))
    kev = _dict_value(evidence.get("kev"))
    references = nvd.get("references")
    reference_count = len(references) if isinstance(references, list) else 0
    return {
        "cve": _text(finding.get("cve_id"), default="CVE"),
        "priority": _priority_label(finding),
        "tone": PRIORITY_TONES.get(_priority_label(finding), "low"),
        "cvss": _score(finding.get("cvss_base_score"), digits=1),
        "epss": _score(finding.get("epss"), digits=3),
        "kev": "Yes" if finding.get("in_kev") else "No",
        "route": _route_label(finding),
        "service": _finding_service(finding),
        "owner": _finding_owner(finding),
        "asset": _finding_asset(finding),
        "exposure": _finding_exposure(finding),
        "criticality": _finding_criticality(finding),
        "status": _status_label(finding),
        "vex": _vex_status(finding),
        "baseline_delta": _baseline_delta_label(finding),
        "action": _text(finding.get("recommended_action"), default="Review finding."),
        "rationale": _text(finding.get("rationale"), default="No rationale supplied."),
        "context_recommendation": _text(
            finding.get("context_recommendation"),
            default="No context-specific recommendation supplied.",
        ),
        "attack": _attack_label(finding),
        "techniques": _list_values(finding.get("attack_techniques")),
        "tactics": _list_values(finding.get("attack_tactics")),
        "provider": [
            {"label": "Published", "value": _text(nvd.get("published"), default="not available")},
            {
                "label": "Last modified",
                "value": _text(nvd.get("last_modified"), default="not available"),
            },
            {"label": "NVD references", "value": str(reference_count)},
            {"label": "Score date", "value": _text(epss.get("date"), default="not available")},
            {"label": "KEV due date", "value": _text(kev.get("due_date"), default="not available")},
            {
                "label": "KEV action",
                "value": _text(kev.get("required_action"), default="not available"),
            },
        ],
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, int, float, float, str]:
    operational = _int_value(finding.get("operational_rank")) or 9999
    priority = _int_value(finding.get("priority_rank")) or 99
    kev_rank = 0 if finding.get("in_kev") else 1
    epss_rank = -_float_value(finding.get("epss"))
    cvss_rank = -_float_value(finding.get("cvss_base_score"))
    return (operational, priority, kev_rank, epss_rank, cvss_rank, _text(finding.get("cve_id")))


def _finding_signal_score(finding: dict[str, Any]) -> float:
    priority_weight = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0}.get(
        _priority_label(finding),
        1.0,
    )
    cvss = max(_float_value(finding.get("cvss_base_score")), 0.0) / 10.0
    epss = max(_float_value(finding.get("epss")), 0.0)
    kev = 1.5 if finding.get("in_kev") else 0.0
    attack = 0.75 if finding.get("attack_mapped") else 0.0
    exposure = 0.75 if _finding_exposure(finding).lower() == "internet-facing" else 0.0
    criticality = 0.5 if _finding_criticality(finding).lower() in {"critical", "high"} else 0.0
    return round(priority_weight + cvss + epss + kev + attack + exposure + criticality, 2)


def _executive_summary(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    counts_by_priority: dict[str, int],
    attack_summary: dict[str, Any],
) -> str:
    critical = counts_by_priority.get("Critical", 0)
    high = counts_by_priority.get("High", 0)
    kev = _int_value(metadata.get("kev_hits"))
    mapped = _int_value(attack_summary.get("mapped_cves"))
    if mapped == 0:
        mapped = sum(1 for item in findings if item.get("attack_mapped"))
    return (
        f"{len(findings)} visible finding(s) are included in this report, with {critical} Critical "
        f"and {high} High priority findings. {kev} findings are KEV-listed and should be "
        f"treated as urgent regardless of CVSS alone. ATT&CK context is available for "
        f"{mapped} mapped finding(s) where supplied."
    )


def _provider_evidence_notes(findings: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for finding in findings[:1]:
        evidence = _dict_value(finding.get("provider_evidence"))
        nvd = _dict_value(evidence.get("nvd"))
        epss = _dict_value(evidence.get("epss"))
        kev = _dict_value(evidence.get("kev"))
        if nvd.get("published"):
            notes.append(f"Published: {nvd['published']}")
        if epss.get("date"):
            notes.append(f"Score date: {epss['date']}")
        if kev.get("due_date"):
            notes.append(f"Due date: {kev['due_date']}")
    return notes


def _kev_due_date(finding: dict[str, Any]) -> str:
    evidence = _dict_value(finding.get("provider_evidence"))
    kev = _dict_value(evidence.get("kev"))
    return _text(kev.get("due_date"), default="not available")


def _priority_counts(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    raw = metadata.get("counts_by_priority")
    counts: dict[str, int] = {}
    if isinstance(raw, dict):
        counts.update({str(key): _int_value(value) for key, value in raw.items()})
    if not counts:
        counter = Counter(_priority_label(finding) for finding in findings)
        counts.update(dict(counter))
    return {label: counts.get(label, 0) for label in PRIORITY_ORDER}


def _service_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_service(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _owner_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_owner(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _asset_counter(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for finding in findings:
        value = _finding_asset(finding)
        if value != "not supplied":
            counter[value] += 1
    return counter


def _finding_service(finding: dict[str, Any]) -> str:
    return _first_occurrence_field(finding, "asset_business_service")


def _finding_owner(finding: dict[str, Any]) -> str:
    return _first_occurrence_field(finding, "asset_owner")


def _finding_asset(finding: dict[str, Any]) -> str:
    direct = _list_first(_dict_value(finding.get("provenance")).get("asset_ids"))
    return direct or _first_occurrence_field(finding, "asset_id")


def _finding_exposure(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    direct = _text(provenance.get("highest_asset_exposure"), default="")
    if direct:
        return direct
    return _first_occurrence_field(finding, "asset_exposure")


def _finding_criticality(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    direct = _text(
        finding.get("highest_asset_criticality") or provenance.get("highest_asset_criticality"),
        default="",
    )
    if direct:
        return direct
    return _first_occurrence_field(finding, "asset_criticality")


def _criticality_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value.lower(), 0)


def _first_occurrence_field(finding: dict[str, Any], field: str) -> str:
    for occurrence in _occurrences(finding):
        value = _text(occurrence.get(field), default="")
        if value:
            return value
    return "not supplied"


def _occurrences(finding: dict[str, Any]) -> list[dict[str, Any]]:
    provenance = _dict_value(finding.get("provenance"))
    return [item for item in provenance.get("occurrences", []) if isinstance(item, dict)]


def _route_label(finding: dict[str, Any]) -> str:
    service = _finding_service(finding)
    owner = _finding_owner(finding)
    if service != "not supplied" and owner != "not supplied":
        return f"{service} / {owner}"
    if service != "not supplied":
        return service
    if owner != "not supplied":
        return owner
    return "not supplied"


def _status(finding: dict[str, Any]) -> str:
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    if finding.get("waived"):
        return "accepted"
    return str(finding.get("status") or "open")


def _status_label(finding: dict[str, Any]) -> str:
    if finding.get("waiver_status"):
        label = "Waiver " + str(finding["waiver_status"]).replace("_", " ")
        if finding.get("waiver_owner"):
            label += f" owner={finding['waiver_owner']}"
        return label
    if finding.get("under_investigation"):
        return "Under investigation"
    return _status(finding).replace("_", " ").title()


def _attack_finding_notes(findings: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for finding in findings:
        note = _text(finding.get("attack_note") or finding.get("attack_rationale"), default="")
        if note and note not in notes:
            notes.append(note)
        if len(notes) >= 3:
            break
    return notes


def _vex_status(finding: dict[str, Any]) -> str:
    provenance = _dict_value(finding.get("provenance"))
    raw = provenance.get("vex_statuses")
    if isinstance(raw, dict) and raw:
        return ", ".join(str(key) for key in raw)
    if finding.get("under_investigation"):
        return "under_investigation"
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    return "not supplied"


def _counter_rows(counter: Counter[str], total: int, *, limit: int = 6) -> list[dict[str, Any]]:
    denominator = max(total, sum(counter.values()), 1)
    return [
        {"label": label, "count": count, "pct": _pct(count, denominator)}
        for label, count in counter.most_common(limit)
    ]


def _distribution_counter(value: Any) -> Counter[str]:
    counter: Counter[str] = Counter()
    if isinstance(value, dict):
        for key, raw_count in value.items():
            label = str(key).strip()
            if label:
                counter[label] = _int_value(raw_count)
    return counter


def _distribution_model(counter: Counter[str], *, limit: int = 6) -> list[dict[str, Any]]:
    total = max(sum(counter.values()), 1)
    return [
        {"label": label, "count": count, "pct": _pct(count, total)}
        for label, count in counter.most_common(limit)
    ]


def _artifact_model(reports: list[Any], bundles: list[Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for report in reports:
        report_id = _attr(report, "id")
        if not report_id:
            continue
        items.append(
            {
                "label": f"{_attr(report, 'kind') or 'report'} ({_attr(report, 'format')})",
                "url": f"/api/reports/{report_id}/download",
                "detail": _sha_preview(_attr(report, "sha256")),
            }
        )
    for bundle in bundles:
        bundle_id = _attr(bundle, "id")
        if not bundle_id:
            continue
        items.append(
            {
                "label": "Evidence ZIP",
                "url": f"/api/evidence-bundles/{bundle_id}/download",
                "detail": _sha_preview(_attr(bundle, "sha256")),
            }
        )
        items.append(
            {
                "label": "Verify evidence bundle",
                "url": f"/evidence-bundles/{bundle_id}/verify",
                "detail": "integrity check",
            }
        )
    return items


def _workspace_nav(
    project_id: str | None, run_id: str | None, project_name: str
) -> dict[str, Any] | None:
    if not project_id:
        return None
    project_base = f"/projects/{project_id}"
    groups = [
        {
            "label": "Analyze",
            "links": [
                {"label": "Dashboard", "href": f"{project_base}/dashboard", "active": False},
                {"label": "Import", "href": f"{project_base}/imports/new", "active": False},
                {"label": "Findings", "href": f"{project_base}/findings", "active": False},
                {
                    "label": "Intelligence",
                    "href": f"{project_base}/vulnerabilities",
                    "active": False,
                },
            ],
        },
        {
            "label": "Context",
            "links": [
                {"label": "Governance", "href": f"{project_base}/governance", "active": False},
                {"label": "Assets", "href": f"{project_base}/assets", "active": False},
                {"label": "Waivers", "href": f"{project_base}/waivers", "active": False},
                {"label": "Coverage", "href": f"{project_base}/coverage", "active": False},
            ],
        },
    ]
    if run_id:
        groups.append(
            {
                "label": "Run",
                "links": [
                    {
                        "label": "Run artifacts",
                        "href": f"/analysis-runs/{run_id}/reports",
                        "active": False,
                    },
                    {
                        "label": "Executive Report",
                        "href": f"/analysis-runs/{run_id}/executive-report",
                        "active": True,
                    },
                ],
            }
        )
    groups.append(
        {
            "label": "Operate",
            "links": [
                {"label": "Settings", "href": f"{project_base}/settings", "active": False},
            ],
        }
    )
    return {"project": project_name, "groups": groups}


def _kpi(label: str, value: int, detail: str, tone: str) -> dict[str, str]:
    return {"label": label, "value": f"{value:,}", "detail": detail, "tone": tone}


def _workspace_app_header_html() -> str:
    return (
        '<header class="er-app-header">'
        '<a class="er-app-brand" href="/">'
        f'<span class="er-app-brand-logo">{_shield_logo_svg()}</span>'
        "<span>Vuln Prioritizer Workbench</span></a></header>"
    )


def _workspace_nav_html(nav: Any, *, interactive: bool = False) -> str:
    if not isinstance(nav, dict):
        return ""
    groups = nav.get("groups")
    if not isinstance(groups, list):
        return ""
    group_html: list[str] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        links = group.get("links")
        if not isinstance(links, list):
            continue
        link_html = []
        for link in links:
            if not isinstance(link, dict):
                continue
            label = _text(link.get("label"))
            href = _text(link.get("href"), default="#")
            active = ' aria-current="page"' if link.get("active") else ""
            link_html.append(
                f'<a href="{escape(href)}" title="{escape(label)}"{active}>'
                '<span class="nav-icon" aria-hidden="true">'
                f"{_workspace_nav_icon(label)}</span>"
                f'<span class="nav-label">{escape(label)}</span></a>'
            )
        group_html.append(
            '<div class="er-workspace-nav-group side-nav-group">'
            f"<p>{escape(_text(group.get('label')))}</p>" + "".join(link_html) + "</div>"
        )
    if not group_html:
        return ""
    toggle = (
        '<button class="sidebar-toggle" type="button" data-sidebar-toggle '
        'aria-label="Collapse navigation" aria-pressed="false">'
        '<span class="sidebar-toggle-icon" aria-hidden="true"></span>'
        '<span class="sidebar-toggle-text">Collapse</span></button>'
        if interactive
        else ""
    )
    return (
        '<aside class="er-workspace-sidebar app-sidebar" aria-label="Project navigation">'
        f"{toggle}"
        '<div class="er-workspace-project sidebar-project">'
        f'<span class="project-emblem" aria-hidden="true">{_shield_logo_svg()}</span>'
        '<span class="project-copy"><span>Project</span>'
        f"<strong>{escape(_text(nav.get('project')))}</strong></span></div>"
        '<nav class="er-workspace-nav side-nav">' + "".join(group_html) + "</nav></aside>"
    )


def _nav_link(item: dict[str, str]) -> str:
    return f'<a href="#{escape(item["id"])}">{escape(item["label"])}</a>'


def _shield_logo_svg() -> str:
    return (
        '<svg class="shield-logo" viewBox="0 0 48 56" focusable="false" aria-hidden="true">'
        '<path class="shield-logo-fill" '
        'd="M24 3 43 10.2v15.3c0 12.3-7.6 21.7-19 26.5C12.6 47.2 5 37.8 5 25.5V10.2L24 3z"/>'
        '<path class="shield-logo-check" d="m15.2 28.2 6.1 6.1 12.8-14.1"/>'
        "</svg>"
    )


def _workspace_nav_icon(label: str) -> str:
    icon_name = {
        "dashboard": "dashboard",
        "import": "import",
        "findings": "findings",
        "intelligence": "intelligence",
        "governance": "governance",
        "assets": "assets",
        "waivers": "waivers",
        "coverage": "coverage",
        "run artifacts": "artifacts",
        "executive report": "report",
        "settings": "settings",
    }.get(label.strip().lower(), "dashboard")
    return _nav_icon_svg(icon_name)


def _nav_icon_svg(name: str) -> str:
    paths = {
        "dashboard": "M4 4h7v7H4V4zm9 0h7v7h-7V4zM4 13h7v7H4v-7zm9 0h7v7h-7v-7z",
        "import": "M11 4h2v8l3-3 1.4 1.4L12 15.8l-5.4-5.4L8 9l3 3V4zM5 18h14v2H5v-2z",
        "findings": "M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z",
        "intelligence": (
            "M10.5 4a6.5 6.5 0 014.9 10.8l4.4 4.4-1.4 1.4-4.4-4.4"
            "A6.5 6.5 0 1110.5 4zm0 2a4.5 4.5 0 100 9 4.5 4.5 0 000-9z"
        ),
        "governance": (
            "M12 3l7 3v6c0 4-2.8 7.2-7 9-4.2-1.8-7-5-7-9V6l7-3zm-1 5v5l4 2 .9-1.8-2.9-1.4V8h-2z"
        ),
        "assets": "M4 5h16v5H4V5zm2 2v1h2V7H6zm-2 5h16v7H4v-7zm2 2v3h12v-3H6z",
        "waivers": (
            "M12 3a9 9 0 100 18 9 9 0 000-18zm4.7 7.7-5.4 5.4-3-3 1.4-1.4 1.6 1.6 4-4 1.4 1.4z"
        ),
        "coverage": (
            "M11 2h2v3.1A7 7 0 0118.9 11H22v2h-3.1A7 7 0 0113 18.9"
            "V22h-2v-3.1A7 7 0 015.1 13H2v-2h3.1A7 7 0 0111 5.1V2zm1 5"
            "a5 5 0 100 10 5 5 0 000-10zm0 3a2 2 0 110 4 2 2 0 010-4z"
        ),
        "artifacts": "M4 5h6l2 2h8v12H4V5zm2 4v8h12V9H6z",
        "report": "M6 3h9l3 3v15H6V3zm8 2v3h3l-3-3zM8 10h8v2H8v-2zm0 4h8v2H8v-2z",
        "settings": (
            "M13 2l.6 2.5a7.8 7.8 0 011.7.7l2.2-1.3 2 3.4-2 1.5"
            "c.1.4.1.8.1 1.2s0 .8-.1 1.2l2 1.5-2 3.4-2.2-1.3"
            "c-.5.3-1.1.5-1.7.7L13 22h-4l-.6-2.5a7.8 7.8 0 01-1.7-.7"
            "l-2.2 1.3-2-3.4 2-1.5A8 8 0 014.4 14c0-.4 0-.8.1-1.2"
            "l-2-1.5 2-3.4 2.2 1.3c.5-.3 1.1-.5 1.7-.7L9 2h4zm-2 7"
            "a3 3 0 100 6 3 3 0 000-6z"
        ),
    }
    return f'<svg viewBox="0 0 24 24" focusable="false"><path d="{paths[name]}"/></svg>'


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


def _scatter_svg(points: list[dict[str, Any]]) -> str:
    point_html = []
    for point in points:
        tone = escape(point["tone"])
        stroke = "#dc2626" if point["kev"] else "#ffffff"
        insight = escape(_scatter_point_insight(point))
        point_html.append(
            f'<circle class="er-dot {tone}" cx="{point["x"]:.1f}" cy="{point["y"]:.1f}" '
            f'r="4.5" stroke="{stroke}" data-insight="{insight}" '
            f'aria-label="{insight}"><title>{escape(point["cve"])}</title></circle>'
        )
    if not point_html:
        return '<p class="er-empty">not supplied</p>'
    return (
        '<svg class="er-scatter" viewBox="0 0 420 240" role="img" '
        'aria-label="CVSS versus EPSS scatter plot">'
        '<rect x="36" y="16" width="360" height="198" class="er-plot-bg"></rect>'
        '<line x1="36" y1="115" x2="396" y2="115" class="er-plot-line"></line>'
        '<line x1="216" y1="16" x2="216" y2="214" class="er-plot-line"></line>'
        '<text x="36" y="232">CVSS 0</text><text x="356" y="232">CVSS 10</text>'
        '<text x="4" y="22">EPSS 1.0</text><text x="8" y="214">0.0</text>'
        + "".join(point_html)
        + "</svg>"
    )


def _quadrant_scatter_svg(points: list[dict[str, Any]]) -> str:
    if not points:
        return '<p class="er-empty">not supplied</p>'
    point_html = []
    for point in points:
        tone = escape(point["tone"])
        stroke = "#dc2626" if point["kev"] else "#ffffff"
        insight = escape(_scatter_point_insight(point))
        point_html.append(
            f'<circle class="er-dot {tone}" cx="{point["x"]:.1f}" cy="{point["y"]:.1f}" '
            f'r="5" stroke="{stroke}" data-insight="{insight}" '
            f'aria-label="{insight}"><title>{escape(point["cve"])}</title></circle>'
        )
    return (
        '<svg class="er-quadrant-scatter" viewBox="0 0 420 250" role="img" '
        'aria-label="CVSS versus EPSS priority quadrant scatter plot">'
        '<rect x="36" y="16" width="360" height="198" fill="#f8fbff" stroke="#d7e3f3"></rect>'
        '<rect x="216" y="16" width="180" height="99" fill="#fff1f2" opacity="0.86"></rect>'
        '<rect x="36" y="16" width="180" height="99" fill="#eff6ff" opacity="0.86"></rect>'
        '<rect x="216" y="115" width="180" height="99" fill="#fff7ed" opacity="0.78"></rect>'
        '<rect x="36" y="115" width="180" height="99" fill="#f8fafc" opacity="0.86"></rect>'
        '<line x1="36" y1="115" x2="396" y2="115" class="er-plot-line"></line>'
        '<line x1="216" y1="16" x2="216" y2="214" class="er-plot-line"></line>'
        '<text x="232" y="35" fill="#dc2626">High EPSS / High CVSS</text>'
        '<text x="48" y="35" fill="#0b63f6">High EPSS / Low CVSS</text>'
        '<text x="232" y="202" fill="#f97316">Low EPSS / High CVSS</text>'
        '<text x="48" y="202" fill="#64748b">Low EPSS / Low CVSS</text>'
        '<text x="36" y="238">CVSS 0</text><text x="356" y="238">CVSS 10</text>'
        '<text x="4" y="22">EPSS 1.0</text><text x="8" y="214">0.0</text>'
        + "".join(point_html)
        + "</svg>"
    )


def _scatter_point_insight(point: dict[str, Any]) -> str:
    kev = "KEV-listed" if point.get("kev") else "not KEV-listed"
    return (
        f"{_text(point.get('cve'), default='CVE')}: "
        f"CVSS {_score(point.get('cvss'), digits=1)}, "
        f"EPSS {_score(point.get('epss'), digits=3)}, {kev}"
    )


def _score(value: Any, *, digits: int) -> str:
    number = _float_value(value)
    if number < 0:
        return "N.A."
    return f"{number:.{digits}f}"


def _priority_label(finding: dict[str, Any]) -> str:
    return _text(finding.get("priority_label") or finding.get("priority"), default="Low")


def _attack_label(finding: dict[str, Any]) -> str:
    relevance = _text(finding.get("attack_relevance"), default="Unmapped")
    if finding.get("attack_mapped"):
        return f"ATT&CK {relevance}"
    return relevance


def _baseline_delta_label(finding: dict[str, Any]) -> str:
    cvss = _float_value(finding.get("cvss_base_score"))
    cvss_value = None if cvss < 0 else cvss
    _, cvss_rank = determine_cvss_only_priority(cvss_value)
    priority_rank = _int_value(finding.get("priority_rank")) or cvss_rank
    delta = cvss_rank - priority_rank
    if delta > 0:
        return f"Raised by {delta}"
    if delta < 0:
        return f"Lowered by {abs(delta)}"
    return "No change"


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_value(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _positive_int(value: Any) -> int:
    number = _int_value(value)
    return number if number > 0 else 0


def _float_value(value: Any) -> float:
    if isinstance(value, bool) or value is None:
        return -1.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return -1.0
    if math.isnan(number) or math.isinf(number):
        return -1.0
    return number


def _pct(value: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(100, round((value / total) * 100)))


def _text(value: Any, *, default: str = "not supplied") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _basename(value: Any) -> str:
    text = _text(value, default="")
    if not text:
        return ""
    return text.replace("\\", "/").rsplit("/", 1)[-1]


def _report_period(metadata: dict[str, Any], generated_at: str) -> str:
    sources = metadata.get("input_sources")
    if isinstance(sources, list) and len(sources) > 1:
        return f"{len(sources)} input sources"
    return generated_at


def _format_report_timestamp(value: Any) -> str:
    text = _text(value, default="not available")
    if text in {"", "not available"}:
        return "not available"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text

    date_label = f"{parsed.strftime('%b')} {parsed.day}, {parsed.year}"
    time_label = parsed.strftime("%H:%M")
    zone_label = parsed.tzname() or ""
    return f"{date_label} {time_label} {zone_label}".strip()


def _list_first(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            text = _text(item, default="")
            if text:
                return text
    return ""


def _list_values(value: Any, *, limit: int = 5) -> list[str]:
    if not isinstance(value, list):
        return []
    values: list[str] = []
    for item in value:
        text = _text(item, default="")
        if text and text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return values


def _provider_value(provider_snapshot: Any | None, attr_name: str) -> str:
    if provider_snapshot is None:
        return "not available"
    return _text(getattr(provider_snapshot, attr_name, None), default="not available")


def _short_provider_date(value: str) -> str:
    if not value or value == "not available":
        return "not available"
    if "T" in value:
        date_part, time_part = value.split("T", 1)
        return f"{date_part} {time_part[:5]}"
    return value


def _attr(value: Any, name: str) -> str:
    return _text(getattr(value, name, None), default="")


def _sha_preview(value: str) -> str:
    return value[:10] if value else "no checksum"


def _truncate(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --er-bg: #f5f7fb;
  --er-surface: #ffffff;
  --er-text: #07183d;
  --er-muted: #52627a;
  --er-line: #d9e2ef;
  --er-blue: #0b63f6;
  --er-critical: #dc2626;
  --er-high: #f97316;
  --er-medium: #d99a07;
  --er-low: #64748b;
  --er-success: #059669;
  --er-accent: #6d28d9;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

* { box-sizing: border-box; }

.executive-report-page {
  min-width: 0;
  margin: 0;
  background:
    linear-gradient(180deg, rgba(234, 242, 255, 0.72), rgba(245, 247, 251, 0) 260px),
    var(--er-bg);
  color: var(--er-text);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

.er-app-header {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  min-height: 66px;
  align-items: center;
  padding: 0 32px;
  border-bottom: 1px solid rgba(217, 226, 239, 0.92);
  background: rgba(255, 255, 255, 0.94);
  box-shadow: 0 10px 28px rgba(7, 24, 61, 0.035);
  backdrop-filter: blur(14px);
}

.er-app-brand {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: 12px;
  color: var(--er-text);
  font-size: 16px;
  font-weight: 900;
  overflow-wrap: anywhere;
  text-decoration: none;
}

.er-app-brand-logo,
.project-emblem,
.nav-icon {
  display: inline-grid;
  flex: 0 0 auto;
  place-items: center;
  color: var(--er-blue);
}

.er-app-brand-logo {
  width: 38px;
  height: 44px;
}

.er-app-brand-logo svg {
  width: 38px;
  height: 44px;
}

.shield-logo {
  display: block;
  overflow: visible;
}

.shield-logo-fill {
  fill: currentColor;
  filter: drop-shadow(0 8px 15px rgba(11, 99, 246, 0.16));
}

.shield-logo-check {
  fill: none;
  stroke: #ffffff;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 5.2;
}

.er-shell {
  width: min(1440px, calc(100vw - 40px));
  margin: 0 auto;
  max-width: 100%;
  overflow-x: hidden;
  padding: 28px 0 56px;
}

.er-app-layout {
  width: min(1660px, calc(100vw - 32px));
  margin: 0 auto;
  max-width: 100%;
}

.er-app-layout.has-workspace-nav {
  display: grid;
  grid-template-columns: 230px minmax(0, 1fr);
  gap: 26px;
  align-items: start;
  transition:
    grid-template-columns 180ms ease,
    gap 180ms ease;
}

.sidebar-collapsed .er-app-layout.has-workspace-nav {
  grid-template-columns: 76px minmax(0, 1fr);
  gap: 20px;
}

.er-app-layout.has-workspace-nav .er-shell {
  width: 100%;
  min-width: 0;
}

.er-workspace-sidebar {
  position: sticky;
  top: 82px;
  display: grid;
  max-height: calc(100vh - 98px);
  overflow-y: auto;
  padding: 22px 12px 32px;
  transition: padding 180ms ease;
}

.sidebar-collapsed .er-workspace-sidebar {
  padding-inline: 8px;
}

.sidebar-toggle {
  display: flex;
  width: 100%;
  min-height: 38px;
  align-items: center;
  justify-content: flex-start;
  gap: 10px;
  margin: 0 0 12px;
  padding: 0 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
  color: #405373;
  font: inherit;
  font-size: 13px;
  font-weight: 850;
  line-height: 1;
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
  cursor: pointer;
}

.sidebar-toggle:hover {
  border-color: var(--er-blue);
  background: #eaf2ff;
  color: var(--er-blue);
}

.sidebar-toggle-icon {
  position: relative;
  display: inline-block;
  width: 20px;
  height: 20px;
  flex: 0 0 auto;
}

.sidebar-toggle-icon::before,
.sidebar-toggle-icon::after {
  content: "";
  position: absolute;
  inset: 4px 5px;
  border: solid currentColor;
  border-width: 0 2px 2px 0;
  transform: rotate(135deg);
}

.sidebar-toggle-icon::after {
  inset: 4px 10px 4px 0;
  opacity: 0.45;
}

.sidebar-collapsed .sidebar-toggle {
  justify-content: center;
  padding: 0;
}

.sidebar-collapsed .sidebar-toggle-icon::before,
.sidebar-collapsed .sidebar-toggle-icon::after {
  transform: rotate(-45deg);
}

.sidebar-collapsed .sidebar-toggle-text,
.sidebar-collapsed .nav-label,
.sidebar-collapsed .project-copy {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}

.er-workspace-project {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
  margin-bottom: 18px;
  padding: 12px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.72);
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
}

.project-emblem {
  width: 30px;
  height: 34px;
}

.project-emblem .shield-logo {
  width: 30px;
  height: 34px;
}

.project-copy {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.project-copy span,
.er-workspace-nav-group p {
  margin: 0;
  color: var(--er-muted);
  font-size: 0.72rem;
  font-weight: 850;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.project-copy strong {
  min-width: 0;
  color: var(--er-text);
  overflow-wrap: anywhere;
  font-size: 0.94rem;
  line-height: 1.25;
}

.sidebar-collapsed .er-workspace-project {
  justify-content: center;
  padding: 12px 0;
}

.er-workspace-nav,
.er-workspace-nav-group {
  display: grid;
}

.er-workspace-nav {
  gap: 18px;
}

.er-workspace-nav-group {
  gap: 5px;
}

.sidebar-collapsed .er-workspace-nav-group {
  gap: 7px;
}

.sidebar-collapsed .er-workspace-nav-group p {
  height: 1px;
  margin: 4px 12px;
  padding: 0;
  overflow: hidden;
  background: var(--er-line);
  color: transparent;
}

.er-workspace-nav-group a {
  position: relative;
  display: flex;
  min-height: 39px;
  min-width: 0;
  align-items: center;
  gap: 10px;
  padding: 0 10px;
  border-radius: 7px;
  color: #405373;
  font-size: 0.88rem;
  font-weight: 800;
  text-decoration: none;
}

.nav-icon {
  width: 24px;
  height: 24px;
}

.nav-icon svg {
  width: 20px;
  height: 20px;
  fill: currentColor;
}

.nav-label {
  min-width: 0;
  overflow-wrap: anywhere;
}

.er-workspace-nav-group a:hover,
.er-workspace-nav-group a[aria-current="page"] {
  background: #eaf2ff;
  color: var(--er-blue);
}

.er-workspace-nav-group a[aria-current="page"]::before {
  content: "";
  position: absolute;
  inset: 8px auto 8px 0;
  width: 3px;
  border-radius: 999px;
  background: var(--er-blue);
}

.sidebar-collapsed .er-workspace-nav-group a {
  justify-content: center;
  min-height: 44px;
  padding: 0;
}

.sidebar-collapsed .er-workspace-nav-group a[aria-current="page"]::before {
  inset: 9px auto 9px 0;
}

.er-hero,
.er-section,
.er-panel,
.er-kpi {
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: var(--er-surface);
}

.er-hero {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) minmax(250px, 340px);
  gap: 22px;
  padding: 28px;
}

.er-brand-mark {
  display: grid;
  width: 64px;
  height: 64px;
  place-items: center;
  border: 5px solid var(--er-blue);
  border-radius: 18px;
  color: var(--er-blue);
  font-size: 34px;
  font-weight: 900;
}

.er-eyebrow,
.er-muted,
.er-kpi span,
.er-kpi small,
.er-meta-panel span,
.er-table th {
  color: var(--er-muted);
}

.er-eyebrow {
  margin: 0 0 6px;
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.er-hero h1 {
  margin: 0;
  font-size: clamp(2.2rem, 5vw, 4.6rem);
  line-height: 0.95;
  letter-spacing: 0;
}

.er-subtitle {
  margin: 8px 0;
  color: var(--er-blue);
  font-size: 1.25rem;
  font-weight: 750;
}

.er-summary {
  max-width: 900px;
  margin: 14px 0 0;
  color: #23395f;
  line-height: 1.55;
}

.er-meta-panel {
  display: grid;
  align-content: start;
  gap: 8px;
  padding: 18px;
  border-left: 1px solid var(--er-line);
}

.er-meta-panel strong {
  overflow-wrap: anywhere;
}

.er-button,
.er-section-nav a,
.er-artifact {
  color: inherit;
  text-decoration: none;
}

.er-button {
  display: inline-flex;
  width: fit-content;
  min-height: 36px;
  align-items: center;
  margin-top: 8px;
  padding: 0 12px;
  border: 1px solid var(--er-line);
  border-radius: 6px;
  background: #eef5ff;
  color: var(--er-blue);
  font-weight: 750;
}

.er-section-nav {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 16px 0;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.96);
  contain: layout paint;
}

.er-section-nav a {
  padding: 8px 10px;
  border-radius: 6px;
  color: #25405f;
  font-size: 0.86rem;
  font-weight: 700;
}

.er-section-nav a:hover { background: #eef5ff; }

.er-sr-note {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}

.er-section {
  margin-top: 16px;
  padding: 22px;
  scroll-margin-top: 76px;
}

.er-section-head {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--er-line);
  padding-bottom: 12px;
}

.er-section h2,
.er-panel h3,
.er-panel h4 {
  margin: 0;
  letter-spacing: 0;
}

.er-section h2 { font-size: clamp(1.4rem, 3vw, 2rem); }

.er-kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}

.er-kpi-grid.compact {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.er-kpi {
  min-width: 0;
  padding: 16px;
}

.er-kpi span,
.er-kpi small {
  display: block;
  font-size: 0.8rem;
  font-weight: 750;
}

.er-kpi strong {
  display: block;
  margin: 8px 0;
  color: var(--er-blue);
  font-size: 2rem;
  line-height: 1;
}

.er-kpi[data-tone="critical"] strong,
.er-badge[data-tone="critical"] { color: var(--er-critical); }
.er-kpi[data-tone="high"] strong,
.er-badge[data-tone="high"] { color: var(--er-high); }
.er-kpi[data-tone="medium"] strong,
.er-badge[data-tone="medium"] { color: var(--er-medium); }
.er-kpi[data-tone="success"] strong { color: var(--er-success); }
.er-kpi[data-tone="accent"] strong { color: var(--er-accent); }

.er-two-col,
.er-three-col {
  display: grid;
  gap: 14px;
}

.er-two-col { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
.er-three-col { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.er-top-rollups { margin-top: 14px; }

.er-panel {
  min-width: 0;
  padding: 18px;
}

.er-panel-accent {
  background: linear-gradient(180deg, #ffffff 0%, #f2f7ff 100%);
}

.er-panel p {
  line-height: 1.5;
}

.er-mini-list,
.er-bar-stack,
.er-artifact-list,
.er-warning-list {
  display: grid;
  gap: 10px;
}

.er-decision-item {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 10px;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: #fbfdff;
}

.er-decision-item p { margin: 4px 0 0; }

.er-badge {
  display: inline-flex;
  min-height: 26px;
  align-items: center;
  justify-content: center;
  padding: 0 9px;
  border-radius: 6px;
  background: #eef2f7;
  font-size: 0.82rem;
  font-weight: 850;
}

.er-bar-row {
  display: grid;
  grid-template-columns: minmax(100px, 1fr) minmax(80px, 2fr) auto;
  gap: 10px;
  align-items: center;
  font-size: 0.9rem;
}

.er-progress {
  width: 100%;
  height: 10px;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: #edf2f8;
}

.er-progress::-webkit-progress-bar {
  border-radius: 999px;
  background: #edf2f8;
}

.er-progress::-webkit-progress-value {
  border-radius: 999px;
  background: var(--er-blue);
}

.er-progress::-moz-progress-bar {
  border-radius: 999px;
  background: var(--er-blue);
}

.er-progress[data-tone="critical"]::-webkit-progress-value { background: var(--er-critical); }
.er-progress[data-tone="high"]::-webkit-progress-value { background: var(--er-high); }
.er-progress[data-tone="medium"]::-webkit-progress-value { background: var(--er-medium); }
.er-progress[data-tone="low"]::-webkit-progress-value { background: var(--er-low); }
.er-progress[data-tone="critical"]::-moz-progress-bar { background: var(--er-critical); }
.er-progress[data-tone="high"]::-moz-progress-bar { background: var(--er-high); }
.er-progress[data-tone="medium"]::-moz-progress-bar { background: var(--er-medium); }
.er-progress[data-tone="low"]::-moz-progress-bar { background: var(--er-low); }

.er-scatter {
  width: 100%;
  min-height: 220px;
  color: var(--er-muted);
  font-size: 12px;
}

.er-plot-bg { fill: #f8fbff; stroke: var(--er-line); }
.er-plot-line { stroke: #b8c7da; stroke-dasharray: 4 4; }
.er-dot { stroke-width: 2; }
.er-dot.critical { fill: var(--er-critical); }
.er-dot.high { fill: var(--er-high); }
.er-dot.medium { fill: var(--er-medium); }
.er-dot.low { fill: var(--er-blue); }

.er-table-wrap {
  max-width: 100%;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  scrollbar-gutter: stable;
  contain: layout paint;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-table {
  width: 100%;
  min-width: min(980px, 100%);
  border-collapse: collapse;
  background: var(--er-surface);
}

.er-table th,
.er-table td {
  padding: 10px 11px;
  border-bottom: 1px solid var(--er-line);
  text-align: left;
  vertical-align: top;
  font-size: 0.88rem;
  line-height: 1.32;
}

.er-two-mini {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}

.er-detail-list {
  display: grid;
  grid-template-columns: minmax(120px, 0.7fr) minmax(0, 1fr);
  gap: 8px 12px;
}

.er-detail-list dt {
  color: var(--er-muted);
  font-weight: 750;
}

.er-detail-list dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.er-status-strip {
  display: flex;
  min-height: 76px;
  overflow: hidden;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-status-segment {
  display: grid;
  min-width: 72px;
  place-items: center;
  padding: 10px;
  background: #eef5ff;
  color: var(--er-blue);
  text-align: center;
}

.er-status-segment[data-tone="critical"] { background: #fff1f2; color: var(--er-critical); }
.er-status-segment[data-tone="medium"] { background: #fffbeb; color: var(--er-medium); }
.er-status-segment[data-tone="low"] { background: #f1f5f9; color: var(--er-low); }

.er-status-progress {
  width: 100%;
  height: 6px;
  border: 0;
  border-radius: 999px;
}

.er-action-list {
  margin: 10px 0 0;
  padding-left: 1.3rem;
  line-height: 1.7;
}

.er-artifact {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 10px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
}

.er-method-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.er-method-card {
  min-width: 0;
  padding: 12px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: #fbfdff;
}

.er-empty { color: var(--er-muted); }

@media (max-width: 960px) {
  .er-shell { width: min(100% - 24px, 720px); }
  .er-hero,
  .er-two-col,
  .er-three-col,
  .er-method-grid {
    grid-template-columns: 1fr;
  }
  .er-meta-panel { border-left: 0; border-top: 1px solid var(--er-line); }
  .er-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 560px) {
  .er-shell { width: min(100% - 16px, 420px); padding-top: 12px; }
  .er-hero { padding: 18px; }
  .er-brand-mark { width: 52px; height: 52px; }
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-two-mini {
    grid-template-columns: 1fr;
  }
  .er-bar-row { grid-template-columns: 1fr; }
  .er-section-nav { position: static; }
}

@media print {
  .er-section-nav,
  .er-button,
  .er-workspace-sidebar {
    display: none;
  }
  .er-app-layout.has-workspace-nav {
    display: block;
    width: auto;
  }
  .executive-report-page,
  .er-shell {
    background: white;
  }
  .er-section {
    break-before: page;
    page-break-before: always;
  }
}

/* Executive report v2 layout */
.executive-report-page {
  background: #f3f6fb;
  font-size: 15px;
}

.er-shell {
  width: min(1480px, calc(100vw - 32px));
  padding: 22px 0 48px;
}

.er-report-header {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(340px, 460px);
  gap: 24px;
  align-items: start;
  margin-bottom: 16px;
  padding: 4px 0 20px;
  border-bottom: 1px solid var(--er-line);
}

.er-compat-heading {
  display: none;
}

.er-report-header h1 {
  margin: 0;
  color: #07183d;
  font-size: clamp(2rem, 3vw, 2.75rem);
  line-height: 1.06;
  letter-spacing: 0;
}

.er-page-title {
  min-width: 0;
}

.er-report-intro {
  max-width: 760px;
  margin: 10px 0 0;
  color: #405373;
  font-size: 1rem;
  line-height: 1.45;
}

.er-report-intro strong {
  color: var(--er-text);
  font-weight: 850;
}

.er-report-meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 11px 16px;
  min-width: 0;
  padding: 14px;
  border: 1px solid var(--er-line);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.82);
  box-shadow: 0 10px 24px rgba(7, 24, 61, 0.04);
  color: #405373;
}

.er-report-meta span {
  display: block;
  max-width: 100%;
  min-width: 0;
}

.er-report-meta em {
  display: block;
  color: var(--er-muted);
  font-size: 0.74rem;
  font-style: normal;
  font-weight: 850;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.er-report-meta strong {
  display: block;
  margin-top: 3px;
  overflow-wrap: anywhere;
  color: var(--er-text);
  font-size: 0.92rem;
  font-weight: 900;
}

.er-button {
  display: inline-flex;
  justify-content: center;
  align-items: center;
  min-height: 32px;
  margin-top: 2px;
  background: #ffffff;
}

.er-report-meta .er-button {
  grid-column: 1 / -1;
  width: 100%;
  margin-top: 0;
}

.er-section-nav {
  position: static;
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  margin: 0 0 14px;
  padding: 8px;
  overflow: visible;
  flex-wrap: wrap;
}

.er-section-nav a {
  flex: 0 0 auto;
  text-align: center;
  white-space: normal;
}

.er-section {
  margin-top: 14px;
  padding: 18px;
  box-shadow: 0 10px 28px rgba(7, 24, 61, 0.04);
}

.er-section-head {
  display: grid;
  grid-template-columns: minmax(220px, auto) minmax(0, 0.92fr);
  align-items: end;
}

.er-section-head > p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
  text-align: right;
}

.er-section h2 {
  font-size: clamp(1.35rem, 2vw, 1.9rem);
}

.er-kpi-grid {
  grid-template-columns: repeat(4, minmax(150px, 1fr));
}

.er-kpi-grid.compact {
  grid-template-columns: repeat(4, minmax(150px, 1fr));
}

.er-kpi-grid.compact.er-action-kpis {
  grid-template-columns: repeat(5, minmax(150px, 1fr));
}

.er-overview-kpis {
  grid-template-columns: repeat(5, minmax(140px, 1fr));
}

.er-kpi {
  display: grid;
  min-height: 104px;
  align-content: center;
  padding: 14px 16px;
  border-color: #cfdbea;
  box-shadow: 0 8px 18px rgba(7, 24, 61, 0.04);
}

.er-kpi strong {
  margin: 7px 0;
  font-size: clamp(1.65rem, 2.4vw, 2.35rem);
}

.er-kpi.mini {
  min-height: 86px;
}

.er-overview-grid {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 14px;
  align-items: start;
}

.er-overview-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(310px, 0.46fr);
  gap: 14px;
  align-items: start;
}

.er-overview-main,
.er-overview-side {
  display: grid;
  gap: 14px;
}

.er-span-3 { grid-column: span 3; }
.er-span-6 { grid-column: span 6; }
.er-span-12 { grid-column: 1 / -1; }

.er-panel {
  padding: 16px;
  border-color: #cfdbea;
  box-shadow: 0 6px 18px rgba(7, 24, 61, 0.035);
}

.er-panel h3 {
  margin-bottom: 12px;
  font-size: 1.02rem;
  line-height: 1.22;
}

.er-panel h4 {
  font-size: 0.92rem;
}

.er-pipeline {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
  align-items: stretch;
}

.er-pipeline-step {
  position: relative;
  display: grid;
  gap: 6px;
  min-height: 118px;
  align-content: center;
  justify-items: center;
  padding: 12px 8px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #f8fbff;
  text-align: center;
}

.er-step-icon {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-pipeline-step small {
  color: var(--er-muted);
  line-height: 1.25;
}

.er-summary-list {
  display: grid;
  gap: 10px;
}

.er-summary-item {
  position: relative;
  padding: 10px 10px 10px 42px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-summary-item::before {
  content: "";
  position: absolute;
  top: 13px;
  left: 12px;
  width: 18px;
  height: 18px;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-summary-item[data-tone="critical"]::before { background: var(--er-critical); }
.er-summary-item[data-tone="high"]::before { background: var(--er-high); }
.er-summary-item[data-tone="success"]::before { background: var(--er-success); }
.er-summary-item[data-tone="accent"]::before { background: var(--er-accent); }
.er-summary-item[data-tone="low"]::before { background: var(--er-low); }

.er-summary-item p {
  margin: 4px 0 0;
  color: #405373;
  line-height: 1.35;
}

.er-signal-card-row {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}

.er-signal-card {
  display: grid;
  gap: 8px;
  padding: 13px;
  border: 1px solid #cfdbea;
  border-radius: 8px;
  background: #ffffff;
}

.er-signal-card span {
  color: var(--er-muted);
  font-weight: 800;
}

.er-signal-card strong {
  color: var(--er-blue);
  font-size: 1.3rem;
}

.er-driver-row,
.er-ranked-row,
.er-remed-row {
  display: grid;
  gap: 9px;
  align-items: center;
}

.er-driver-row {
  grid-template-columns: auto minmax(110px, 1fr) minmax(90px, 1.4fr) auto;
}

.er-driver-dot {
  display: inline-block;
  width: 11px;
  height: 11px;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-driver-dot[data-tone="critical"] { background: var(--er-critical); }
.er-driver-dot[data-tone="high"] { background: var(--er-high); }
.er-driver-dot[data-tone="medium"] { background: var(--er-medium); }
.er-driver-dot[data-tone="success"] { background: var(--er-success); }
.er-driver-dot[data-tone="accent"] { background: var(--er-accent); }
.er-driver-dot[data-tone="low"] { background: var(--er-low); }

.er-three-col {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: start;
}

.er-two-col {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
}

.er-risk-chart-grid,
.er-evidence-core-grid {
  grid-template-columns: repeat(2, minmax(360px, 1fr));
}

.er-priority-analysis-grid {
  grid-template-columns: minmax(360px, 0.95fr) minmax(410px, 1.05fr) minmax(360px, 0.95fr);
}

.er-attack-summary-grid,
.er-remediation-grid {
  grid-template-columns: minmax(320px, 0.95fr) minmax(360px, 1fr) minmax(340px, 0.95fr);
}

.er-remediation-board {
  display: grid;
  grid-template-columns: minmax(0, 2.15fr) minmax(310px, 0.85fr);
  gap: 14px;
  align-items: start;
}

.er-remediation-main {
  display: grid;
  gap: 14px;
  min-width: 0;
}

.er-remediation-charts,
.er-action-detail-grid {
  margin-top: 0;
}

.er-action-detail-grid {
  grid-template-columns: 1fr;
}

.er-next-actions-panel {
  align-self: start;
}

.er-evidence-support-grid {
  grid-template-columns: minmax(280px, 0.85fr) minmax(320px, 0.95fr) minmax(420px, 1.2fr);
}

.er-evidence-lower-grid {
  grid-template-columns: 1fr;
  align-items: start;
}

.er-section-table {
  margin-top: 14px;
}

.er-table th {
  background: #f6f9fd;
  color: #23395f;
  font-size: 0.78rem;
  text-transform: uppercase;
}

.er-table td {
  color: #132646;
}

.er-table td:nth-child(2) strong {
  white-space: nowrap;
}

.er-table td:last-child {
  max-width: 440px;
}

.er-table-compact {
  min-width: 720px;
}

.er-bar-row {
  grid-template-columns: minmax(110px, 1fr) minmax(100px, 1.8fr) minmax(44px, auto);
}

.er-scatter {
  min-height: 190px;
  max-height: 220px;
}

.er-exposure-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.er-exposure-tile {
  display: grid;
  gap: 5px;
  min-height: 96px;
  align-content: center;
  padding: 12px;
  border-radius: 8px;
  background: linear-gradient(135deg, #dc2626, #f97316);
  color: #ffffff;
}

.er-exposure-tile[data-tone="high"] { background: linear-gradient(135deg, #f97316, #d99a07); }
.er-exposure-tile[data-tone="success"] { background: linear-gradient(135deg, #059669, #8bcf9c); }

.er-exposure-tile small {
  opacity: 0.86;
}

.er-ranked-list {
  display: grid;
  gap: 9px;
}

.er-ranked-row {
  grid-template-columns: 24px minmax(145px, 1.15fr) minmax(110px, 1.55fr) 38px;
  font-size: 0.88rem;
}

.er-ranked-row strong {
  white-space: nowrap;
}

.er-ranked-row > span {
  display: grid;
  height: 24px;
  place-items: center;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-rank-progress {
  width: 100%;
  height: 10px;
  overflow: hidden;
  border: 0;
  border-radius: 999px;
  background: #edf2f8;
}

.er-rank-progress::-webkit-progress-bar {
  border-radius: inherit;
  background: #edf2f8;
}

.er-rank-progress::-webkit-progress-value {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-rank-progress::-moz-progress-bar {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-rank-progress[data-tone="critical"]::-webkit-progress-value { background: var(--er-critical); }
.er-rank-progress[data-tone="high"]::-webkit-progress-value { background: var(--er-high); }
.er-rank-progress[data-tone="medium"]::-webkit-progress-value { background: var(--er-medium); }

.er-ranked-row em,
.er-remed-row em,
.er-donut-legend-row em {
  color: var(--er-muted);
  font-style: normal;
  font-weight: 800;
}

.er-donut-wrap {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 14px;
  align-items: center;
}

.er-donut-svg {
  width: 150px;
  height: 150px;
}

.er-donut-bg {
  fill: none;
  stroke: #e8eef6;
  stroke-width: 18;
}

.er-donut-total {
  fill: var(--er-text);
  font-size: 1.45rem;
  font-weight: 900;
  text-anchor: middle;
}

.er-donut-caption {
  fill: var(--er-muted);
  font-size: 0.65rem;
  font-weight: 800;
  text-anchor: middle;
}

.er-donut-legend {
  display: grid;
  gap: 8px;
}

.er-donut-legend-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
}

.er-heatmap {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 6px;
}

.er-heat-cell {
  display: grid;
  min-height: 54px;
  align-content: center;
  padding: 8px;
  border-radius: 6px;
  background: #fde2e2;
  color: #07183d;
}

.er-heat-cell.er-heat-2 { background: #ffc9c9; }
.er-heat-cell.er-heat-3 { background: #ff9b9b; }
.er-heat-cell.er-heat-4 { background: #f87171; }

.er-heat-cell span {
  color: #405373;
}

.er-ttp-chain {
  display: flex;
  flex-wrap: wrap;
  gap: 22px;
  align-items: center;
}

.er-ttp-chain span {
  position: relative;
  display: inline-flex;
  min-height: 42px;
  align-items: center;
  padding: 0 12px;
  border-radius: 999px;
  background: #eaf2ff;
  color: var(--er-blue);
  font-weight: 900;
}

.er-ttp-chain span:not(:last-child)::after {
  content: ">";
  position: absolute;
  right: -16px;
  color: #7d8da6;
}

.er-remed-chart {
  display: grid;
  gap: 12px;
}

.er-remed-row {
  grid-template-columns: 68px minmax(130px, 1fr) 34px;
}

.er-remed-bars {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.er-remed-bars span {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.er-remed-bars b {
  color: var(--er-muted);
  font-size: 0.68rem;
}

.er-remed-bars progress {
  width: 100%;
  height: 8px;
  border: 0;
  border-radius: 999px;
}

.er-remed-bars progress::-webkit-progress-bar {
  border-radius: inherit;
  background: #edf2f8;
}

.er-remed-bars progress::-webkit-progress-value {
  border-radius: inherit;
  background: var(--er-blue);
}

.er-remed-bars progress[data-tone="critical"]::-webkit-progress-value {
  background: var(--er-critical);
}

.er-remed-bars progress[data-tone="low"]::-webkit-progress-value {
  background: var(--er-low);
}

.er-remed-bars progress[data-tone="medium"]::-webkit-progress-value {
  background: var(--er-medium);
}

.er-pipeline-panel {
  margin-bottom: 14px;
}

.er-coverage-context-panel {
  margin-bottom: 14px;
}

.er-coverage-context-panel .er-signal-card-row {
  margin: 12px 0 0;
}

.er-priority-subhead {
  margin-top: 16px;
  padding: 4px 0;
}

.er-priority-subhead h3 {
  margin: 0;
  font-size: 1.05rem;
}

.er-dossier-list {
  display: grid;
  gap: 12px;
  margin-top: 12px;
}

.er-dossier-card {
  display: grid;
  gap: 14px;
  padding: 14px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-dossier-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(180px, 0.32fr);
  gap: 14px;
  align-items: start;
}

.er-dossier-head h4 {
  margin: 8px 0 4px;
  color: var(--er-blue);
  font-size: 1.15rem;
}

.er-dossier-head p,
.er-dossier-details p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
}

.er-dossier-score {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 6px 10px;
  margin: 0;
  padding: 10px;
  border-radius: 8px;
  background: #ffffff;
}

.er-dossier-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.er-detail-list.compact {
  grid-template-columns: minmax(90px, 0.7fr) minmax(0, 1fr);
  font-size: 0.82rem;
}

.er-dossier-details {
  border-top: 1px solid #d7e3f3;
  padding-top: 10px;
}

.er-dossier-details summary {
  cursor: pointer;
  color: var(--er-blue);
  font-weight: 850;
}

.er-dossier-details[open] {
  display: grid;
  gap: 8px;
}

.er-input-table {
  min-width: min(620px, 100%);
}

.er-provider-transparency,
.er-command-list,
.er-governance-grid,
.er-missing-context {
  display: grid;
  gap: 10px;
}

.er-command-list code {
  display: block;
  padding: 8px 10px;
  border: 1px solid #d7e3f3;
  border-radius: 7px;
  background: #f6f9fd;
  color: #132646;
  font-size: 0.8rem;
  overflow-wrap: anywhere;
}

.er-governance-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.er-governance-item {
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-governance-item strong {
  display: block;
  color: var(--er-blue);
  font-size: 1.45rem;
}

.er-governance-item[data-tone="critical"] strong { color: var(--er-critical); }
.er-governance-item[data-tone="high"] strong { color: var(--er-high); }
.er-governance-item[data-tone="medium"] strong { color: var(--er-medium); }
.er-governance-item[data-tone="low"] strong { color: var(--er-low); }

.er-governance-item span {
  font-weight: 850;
}

.er-governance-item p {
  margin: 5px 0 0;
  color: #405373;
  font-size: 0.84rem;
}

.er-missing-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 6px 12px;
  padding: 10px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-missing-item p {
  margin: 3px 0 0;
  color: #405373;
  font-size: 0.83rem;
}

.er-missing-item > span {
  color: var(--er-blue);
  font-weight: 900;
}

.er-missing-item .er-progress {
  grid-column: 1 / -1;
}

.er-flow-map {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(110px, 0.55fr) minmax(0, 1fr);
  gap: 12px;
  align-items: stretch;
}

.er-flow-source,
.er-flow-engine,
.er-flow-output {
  position: relative;
  display: grid;
  min-width: 0;
  min-height: 112px;
  align-content: start;
  gap: 8px;
  padding: 14px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-flow-engine {
  justify-items: center;
  align-content: center;
  background: #eaf2ff;
  color: var(--er-blue);
  text-align: center;
}

.er-flow-source::after,
.er-flow-engine::after {
  content: "";
  position: absolute;
  top: 50%;
  right: -13px;
  width: 13px;
  border-top: 2px solid #b8c7da;
}

.er-flow-source strong,
.er-flow-engine strong,
.er-flow-output strong,
.er-provider-card strong,
.er-focus-card strong,
.er-quality-matrix strong {
  overflow-wrap: anywhere;
}

.er-flow-source span,
.er-flow-output span,
.er-provider-card span,
.er-threshold-legend span,
.er-evidence-file-list span {
  color: var(--er-muted);
  font-size: 0.8rem;
  font-weight: 800;
}

.er-quadrant-scatter,
.er-stacked-chart,
.er-waterfall {
  display: block;
  width: 100%;
  max-width: 100%;
  min-height: 220px;
  overflow: visible;
}

.er-quadrant-scatter {
  color: var(--er-muted);
  font-size: 0.72rem;
}

.er-stacked-chart,
.er-waterfall {
  color: #405373;
}

.er-provider-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.er-provider-signal-panel .er-provider-cards {
  grid-template-columns: repeat(3, minmax(240px, 1fr));
}

.er-focus-card-grid {
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

.er-provider-card,
.er-focus-card {
  display: grid;
  min-width: 0;
  gap: 8px;
  padding: 13px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-provider-card p {
  margin: 0;
  color: #405373;
  font-size: 0.86rem;
  line-height: 1.4;
}

.er-provider-card {
  border-top: 4px solid var(--er-blue);
  min-height: 0;
}

.er-provider-card[data-tone="critical"],
.er-focus-card[data-tone="critical"] {
  border-color: #fecaca;
  border-top-color: var(--er-critical);
  background: #fff7f7;
}

.er-provider-card[data-tone="high"],
.er-focus-card[data-tone="high"] {
  border-color: #fed7aa;
  border-top-color: var(--er-high);
  background: #fff9f2;
}

.er-provider-card[data-tone="medium"],
.er-focus-card[data-tone="medium"] {
  border-color: #fde68a;
  border-top-color: var(--er-medium);
  background: #fffdf2;
}

.er-provider-card[data-tone="success"],
.er-focus-card[data-tone="success"] {
  border-color: #bbf7d0;
  border-top-color: var(--er-success);
  background: #f3fcf7;
}

.er-threshold-legend,
.er-technique-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.er-threshold-legend span,
.er-technique-strip span {
  display: inline-flex;
  min-width: 0;
  min-height: 28px;
  align-items: center;
  gap: 7px;
  padding: 0 10px;
  border: 1px solid #d7e3f3;
  border-radius: 999px;
  background: #f8fbff;
  color: #25405f;
  overflow-wrap: anywhere;
}

.er-threshold-legend span::before,
.er-technique-strip span::before {
  content: "";
  width: 9px;
  height: 9px;
  flex: 0 0 auto;
  border-radius: 999px;
  background: var(--er-blue);
}

.er-threshold-legend span[data-tone="critical"]::before,
.er-technique-strip span[data-tone="critical"]::before { background: var(--er-critical); }
.er-threshold-legend span[data-tone="high"]::before,
.er-technique-strip span[data-tone="high"]::before { background: var(--er-high); }
.er-threshold-legend span[data-tone="medium"]::before,
.er-technique-strip span[data-tone="medium"]::before { background: var(--er-medium); }
.er-threshold-legend span[data-tone="success"]::before,
.er-technique-strip span[data-tone="success"]::before { background: var(--er-success); }
.er-threshold-legend span[data-tone="low"]::before,
.er-technique-strip span[data-tone="low"]::before { background: var(--er-low); }

.er-interpretation-panel {
  display: grid;
  gap: 10px;
  padding: 14px;
  border: 1px solid #cfdbea;
  border-left: 4px solid var(--er-blue);
  border-radius: 8px;
  background: #f8fbff;
}

.er-interpretation-panel p {
  margin: 0;
  color: #405373;
  line-height: 1.45;
}

.er-next-steps {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.er-next-steps-vertical {
  grid-template-columns: 1fr;
}

.er-next-steps li {
  display: grid;
  min-width: 0;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-next-steps li::before {
  display: none;
}

.er-next-steps span {
  color: #405373;
  font-size: 0.82rem;
  line-height: 1.4;
}

.er-focus-card {
  border-left: 4px solid var(--er-blue);
}

.er-focus-card p {
  margin: 0;
  color: #405373;
  line-height: 1.42;
}

.er-focus-card ul {
  display: grid;
  gap: 5px;
  margin: 0;
  padding-left: 18px;
  color: #405373;
  font-size: 0.82rem;
}

.er-empty-state {
  display: grid;
  align-content: center;
  gap: 8px;
  min-height: 220px;
  padding: 16px;
  border: 1px dashed #cfdbea;
  border-radius: 8px;
  background: #f8fbff;
  color: #405373;
}

.er-empty-state strong {
  color: var(--er-blue);
  font-size: 1.1rem;
}

.er-empty-state p {
  margin: 0;
}

.er-confidence-layout {
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
  gap: 14px;
  align-items: start;
}

.er-attack-matrix {
  grid-template-columns: minmax(120px, 1fr) repeat(3, minmax(80px, 1fr));
}

.er-heat-head,
.er-heat-label {
  min-width: 0;
  padding: 7px 8px;
  color: #405373;
  font-size: 0.78rem;
  font-weight: 900;
  overflow-wrap: anywhere;
}

.er-heat-head {
  background: #eef5ff;
}

.er-heat-label {
  background: #ffffff;
}

.er-evidence-file-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.er-evidence-file-list li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px 12px;
  align-items: center;
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid #d7e3f3;
  border-radius: 7px;
  background: #ffffff;
}

.er-evidence-file-list code {
  min-width: 0;
  color: #132646;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

.er-quality-matrix {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.er-quality-matrix > * {
  display: grid;
  min-width: 0;
  min-height: 76px;
  align-content: center;
  gap: 4px;
  padding: 10px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-quality-matrix strong {
  color: var(--er-blue);
  font-size: 1.2rem;
}

.er-quality-matrix span {
  color: var(--er-muted);
  font-size: 0.76rem;
  font-weight: 800;
}

.er-evidence-core-grid .er-table-compact {
  min-width: 620px;
}

.er-quality-matrix + .er-warning-list {
  margin-top: 12px;
}

.er-method-grid.compact {
  grid-template-columns: repeat(2, minmax(210px, 1fr));
}

.er-warning-list p {
  margin: 0;
  padding: 9px 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
  color: #23395f;
  line-height: 1.4;
}

.er-provider-transparency {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
}

.er-provider-transparency > .er-detail-list {
  grid-column: 1 / -1;
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #fbfdff;
}

.er-provider-transparency > div {
  min-width: 0;
  padding: 11px;
  border: 1px solid #d7e3f3;
  border-radius: 8px;
  background: #ffffff;
}

.er-provider-transparency .er-eyebrow {
  margin-bottom: 8px;
}

.er-section-nav a.is-active {
  background: #eaf2ff;
  color: var(--er-blue);
  box-shadow: inset 0 -2px 0 var(--er-blue);
}

.er-interactive-target {
  cursor: pointer;
  transition:
    border-color 160ms ease,
    box-shadow 160ms ease,
    transform 160ms ease,
    background-color 160ms ease,
    opacity 160ms ease;
}

.er-provider-card.er-interactive-target:hover,
.er-signal-card.er-interactive-target:hover,
.er-quality-matrix > article.er-interactive-target:hover,
.er-summary-item.er-interactive-target:hover,
.er-ranked-row.er-interactive-target:hover,
.er-bar-row.er-interactive-target:hover,
.er-driver-row.er-interactive-target:hover,
.er-remed-row.er-interactive-target:hover,
.er-heat-cell.er-interactive-target:hover,
.er-donut-legend-row.er-interactive-target:hover,
.er-focus-card.er-interactive-target:hover,
.er-method-card.er-interactive-target:hover,
.er-pipeline-step.er-interactive-target:hover,
.er-evidence-file-list li.er-interactive-target:hover,
.er-exposure-tile.er-interactive-target:hover,
.er-status-segment.er-interactive-target:hover {
  border-color: #94bfff;
  box-shadow: 0 12px 26px rgba(11, 99, 246, 0.13);
  transform: translateY(-2px);
}

.er-interactive-target:focus-visible {
  outline: 3px solid rgba(11, 99, 246, 0.28);
  outline-offset: 3px;
}

.er-stacked-chart rect.er-interactive-target,
.er-quadrant-scatter .er-dot,
.er-donut-segment {
  transform-box: fill-box;
  transform-origin: center;
  transition:
    filter 160ms ease,
    opacity 160ms ease,
    stroke-width 160ms ease,
    transform 160ms ease;
}

.er-stacked-chart rect.er-interactive-target:hover,
.er-stacked-chart rect.er-interactive-target:focus-visible,
.er-quadrant-scatter .er-dot:hover,
.er-quadrant-scatter .er-dot:focus-visible,
.er-donut-segment:hover,
.er-donut-segment:focus-visible {
  filter: drop-shadow(0 5px 8px rgba(7, 24, 61, 0.28));
  opacity: 0.92;
  transform: scale(1.08);
}

.er-donut-segment:hover,
.er-donut-segment:focus-visible {
  stroke-width: 21;
}

.er-live-insight {
  display: grid;
  grid-template-columns: minmax(120px, auto) minmax(0, 1fr);
  gap: 4px 12px;
  align-items: center;
  margin: -2px 0 14px;
  padding: 10px 12px;
  border: 1px solid #bfdbfe;
  border-left: 4px solid var(--er-blue);
  border-radius: 8px;
  background: linear-gradient(90deg, #eff6ff, #ffffff);
}

.er-live-insight[hidden] {
  display: none;
}

.er-live-insight span {
  color: var(--er-muted);
  font-size: 0.72rem;
  font-weight: 900;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.er-live-insight strong {
  min-width: 0;
  color: var(--er-blue);
  overflow-wrap: anywhere;
}

.er-live-insight p {
  grid-column: 2;
  margin: 0;
  color: #405373;
  font-size: 0.82rem;
}

.er-floating-tip {
  position: fixed;
  z-index: 1000;
  display: none;
  max-width: min(320px, calc(100vw - 24px));
  padding: 9px 11px;
  border: 1px solid #bfdbfe;
  border-radius: 8px;
  background: rgba(7, 24, 61, 0.96);
  box-shadow: 0 18px 40px rgba(7, 24, 61, 0.22);
  color: #ffffff;
  font-size: 0.82rem;
  font-weight: 760;
  line-height: 1.35;
  pointer-events: none;
}

.er-floating-tip.is-visible {
  display: block;
}

.is-selected {
  border-color: #0b63f6 !important;
  box-shadow: 0 0 0 2px rgba(11, 99, 246, 0.18), 0 12px 26px rgba(11, 99, 246, 0.12);
}

.er-cve-spotlight {
  outline: 2px solid rgba(249, 115, 22, 0.55);
  outline-offset: 2px;
}

.er-table tr.er-cve-spotlight td {
  background: #fff7ed;
}

@media (prefers-reduced-motion: reduce) {
  .er-interactive-target,
  .er-stacked-chart rect.er-interactive-target,
  .er-quadrant-scatter .er-dot,
  .er-donut-segment {
    transition: none;
  }
}

@media (max-width: 1120px) {
  .er-app-header {
    position: static;
    min-height: 60px;
    padding: 0 16px;
  }
  .er-app-layout.has-workspace-nav {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .sidebar-collapsed .er-app-layout.has-workspace-nav {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .er-workspace-sidebar {
    position: static;
    max-height: none;
    padding: 16px 0 14px;
  }
  .sidebar-collapsed .er-workspace-sidebar {
    padding: 16px 0 14px;
  }
  .sidebar-collapsed .sidebar-toggle {
    justify-content: flex-start;
    padding: 0 10px;
  }
  .sidebar-collapsed .sidebar-toggle-text,
  .sidebar-collapsed .nav-label,
  .sidebar-collapsed .project-copy {
    position: static;
    width: auto;
    height: auto;
    overflow: visible;
    clip: auto;
    clip-path: none;
    white-space: normal;
  }
  .sidebar-collapsed .sidebar-toggle-icon::before,
  .sidebar-collapsed .sidebar-toggle-icon::after {
    transform: rotate(135deg);
  }
  .sidebar-collapsed .er-workspace-project {
    justify-content: flex-start;
    padding: 12px;
  }
  .er-workspace-nav {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }
  .sidebar-collapsed .er-workspace-nav-group a {
    justify-content: flex-start;
    min-height: 39px;
    padding: 0 10px;
  }
  .sidebar-collapsed .er-workspace-nav-group p {
    height: auto;
    margin: 0 0 4px;
    padding: 0 10px;
    overflow: visible;
    background: transparent;
    color: var(--er-muted);
  }
  .er-report-header {
    grid-template-columns: 1fr;
  }
  .er-report-meta {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    width: 100%;
  }
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-signal-card-row {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-kpi-grid.compact.er-action-kpis {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-overview-grid {
    grid-template-columns: repeat(6, minmax(0, 1fr));
  }
  .er-overview-layout {
    grid-template-columns: 1fr;
  }
  .er-span-3,
  .er-span-6 {
    grid-column: span 3;
  }
  .er-span-12 {
    grid-column: 1 / -1;
  }
  .er-pipeline {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .er-provider-cards,
  .er-next-steps {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-risk-chart-grid,
  .er-priority-analysis-grid,
  .er-attack-summary-grid,
  .er-remediation-grid,
  .er-evidence-core-grid,
  .er-evidence-support-grid,
  .er-evidence-lower-grid {
    grid-template-columns: 1fr;
  }
  .er-remediation-board,
  .er-remediation-charts,
  .er-action-detail-grid {
    grid-template-columns: 1fr;
  }
  .er-provider-signal-panel .er-provider-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-confidence-layout {
    grid-template-columns: 1fr;
  }
  .er-provider-transparency {
    grid-template-columns: 1fr;
  }
  .er-quality-matrix {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-three-col {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
  .er-app-layout {
    width: min(100% - 20px, 760px);
  }
  .er-workspace-nav {
    grid-template-columns: 1fr 1fr;
  }
  .er-shell {
    width: min(100% - 20px, 760px);
    padding-top: 12px;
  }
  .er-report-header {
    gap: 14px;
    padding-bottom: 12px;
  }
  .er-report-header h1 {
    font-size: clamp(1.8rem, 8vw, 2.35rem);
  }
  .er-report-intro {
    font-size: 0.94rem;
  }
  .er-report-meta,
  .er-kpi-grid,
  .er-kpi-grid.compact,
  .er-signal-card-row,
  .er-flow-map,
  .er-provider-cards,
  .er-next-steps,
  .er-two-col,
  .er-risk-chart-grid,
  .er-priority-analysis-grid,
  .er-attack-summary-grid,
  .er-remediation-grid,
  .er-remediation-board,
  .er-remediation-charts,
  .er-action-detail-grid,
  .er-evidence-core-grid,
  .er-evidence-support-grid,
  .er-evidence-lower-grid,
  .er-dossier-head,
  .er-dossier-grid,
  .er-governance-grid,
  .er-method-grid,
  .er-pipeline,
  .er-exposure-grid {
    grid-template-columns: 1fr;
  }
  .er-section-head {
    grid-template-columns: 1fr;
  }
  .er-section-head > p {
    text-align: left;
  }
  .er-flow-source,
  .er-flow-engine,
  .er-flow-output {
    min-height: 0;
  }
  .er-flow-source::after,
  .er-flow-engine::after {
    top: auto;
    right: 50%;
    bottom: -13px;
    width: 0;
    height: 13px;
    border-top: 0;
    border-left: 2px solid #b8c7da;
  }
  .er-overview-grid {
    grid-template-columns: 1fr;
  }
  .er-overview-layout {
    grid-template-columns: 1fr;
  }
  .er-span-3,
  .er-span-6,
  .er-span-12 {
    grid-column: 1 / -1;
  }
  .er-donut-wrap {
    grid-template-columns: 1fr;
    justify-items: center;
  }
  .er-driver-row,
  .er-bar-row {
    grid-template-columns: auto minmax(0, 1fr) auto;
  }
  .er-driver-row .er-progress {
    grid-column: 2 / -1;
  }
  .er-heatmap {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .er-evidence-file-list li,
  .er-quality-matrix,
  .er-method-grid.compact,
  .er-provider-transparency,
  .er-live-insight {
    grid-template-columns: 1fr;
  }
  .er-live-insight p {
    grid-column: 1;
  }
  .er-section-nav {
    display: grid;
    grid-template-columns: 1fr;
    overflow-x: visible;
  }
  .er-section-nav a {
    white-space: normal;
  }
  .er-table,
  .er-table-compact,
  .er-input-table {
    min-width: 680px;
    table-layout: auto;
  }
  .er-table th,
  .er-table td {
    padding: 8px;
    font-size: 0.78rem;
  }
  .er-table td:last-child {
    max-width: none;
  }
}

"""
