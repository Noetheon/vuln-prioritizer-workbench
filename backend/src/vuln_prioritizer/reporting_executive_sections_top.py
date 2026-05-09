"""Top-level executive report HTML sections."""
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

from vuln_prioritizer.reporting_executive_sections_charts import *
from vuln_prioritizer.reporting_executive_sections_chrome import *
from vuln_prioritizer.reporting_executive_sections_components import *
from vuln_prioritizer.reporting_executive_sections_evidence import *
from vuln_prioritizer.reporting_executive_sections_summary import *


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
      <h3>Illustrative Defensive TTP Sequence</h3>
      {_ttp_chain(attack["top_techniques"])}
      <p class="er-muted">
        Defensive review sequence only. Not a confirmed attack path and not procedure guidance.
      </p>
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
  <article class="er-panel er-section-table">
    <h3>Detection Coverage Gaps</h3>
    {_detection_coverage_html(attack["detection_coverage"])}
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


__all__ = [
    "_attack_context_section",
    "_evidence_section",
    "_overview_section",
    "_priority_findings_section",
    "_remediation_section",
    "_risk_posture_section",
]
