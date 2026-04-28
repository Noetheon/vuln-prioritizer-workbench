"""Executive report section and HTML fragment rendering."""

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
