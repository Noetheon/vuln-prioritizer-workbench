"""Risk posture projection helpers for executive HTML reports."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from math import floor

from app.services.report_formatting import safe_html as _safe_html
from app.services.report_html_common import (
    _is_actionable_finding,
    _pluralize,
    _short_list,
)
from app.services.report_models import MarkdownReportFinding, RiskPosture

_REDUCER_LIMIT = 4
_RISK_INDEX_BANDS: dict[str, tuple[str, str]] = {
    "critical": ("Critical band, immediate action", "critical"),
    "elevated": ("Elevated band, prioritized remediation", "warning"),
    "low": ("Low band, routine handling", "success"),
    "none": ("No open actionable findings to score", "neutral"),
}


@dataclass(frozen=True)
class _RiskReducer:
    """One evidence-backed remediation group that can reduce actionable risk."""

    id: str
    title: str
    cve_id: str
    component: str | None
    recommended_action: str
    expected_reduction: float
    finding_count: int
    assets: tuple[str, ...]
    services: tuple[str, ...]
    owners: tuple[str, ...]
    max_epss: float | None
    max_cvss: float | None
    in_kev: bool


@dataclass(frozen=True)
class _ProjectionStep:
    """One static report projection step."""

    key: str
    label: str
    value: float
    reduction: float
    mode: str


@dataclass(frozen=True)
class _RiskProjection:
    """Prepared static risk posture projection."""

    current_risk: float
    current_index: float | None
    target_index: float | None
    plan_index: float | None
    planned_reduction_index: float | None
    actionable_count: int
    reducers: tuple[_RiskReducer, ...]
    steps: tuple[_ProjectionStep, ...]


def _html_risk_scenario_panel_helper(
    findings: Sequence[MarkdownReportFinding],
    risk_posture: RiskPosture,
) -> str:
    """Render a dashboard-aligned static risk posture projection."""
    projection = _risk_projection_helper(findings)
    label, tone = _risk_index_label_and_tone(projection, risk_posture)
    index_html = _risk_index_value_html(projection)
    gauge_html = _risk_index_gauge_html(projection)
    foot = _risk_index_footnote(projection)
    planned_reduction = (
        _format_score(projection.planned_reduction_index)
        if projection.planned_reduction_index is not None
        else "0"
    )
    chart_html = _html_projection_chart(projection)
    reducers_html = _html_top_reducers(projection)
    return (
        '      <div class="risk-scenario" data-tone="'
        f'{_safe_html(tone)}">\n'
        '        <section class="risk-scenario-index" aria-label="Risk index summary">\n'
        '          <span class="status-label">Risk index - avg open findings</span>\n'
        f"          {index_html}\n"
        f'          <p class="risk-index-band">{_safe_html(label)}</p>\n'
        '          <p class="risk-scenario-change">'
        f"<strong>{_safe_html(planned_reduction)}</strong> index reduction planned</p>\n"
        f"          {gauge_html}\n"
        '          <div class="risk-gauge-scale"><span>0</span><span>moderate</span>'
        "<span>100</span></div>\n"
        f'          <p class="risk-index-foot">{_safe_html(foot)}</p>\n'
        "        </section>\n"
        f"{chart_html}\n"
        f"{reducers_html}\n"
        "      </div>"
    )


def _risk_projection_helper(
    findings: Sequence[MarkdownReportFinding],
) -> _RiskProjection:
    """Build the same static reducer model used by the report visual."""
    actionable = [finding for finding in findings if _is_actionable_finding(finding)]
    actionable_count = len(actionable)
    current_risk = _round_score(sum(_risk_score(finding) for finding in actionable))
    current_index = _index_from_score(current_risk, actionable_count)
    reducers = tuple(_risk_reducers(actionable, current_risk=current_risk)[:_REDUCER_LIMIT])

    top_one = _reduction_for_first(reducers, 1)
    top_three = _reduction_for_first(reducers, 3)
    plan = _reduction_for_first(reducers, len(reducers))
    steps = tuple(
        _ProjectionStep(
            key=key,
            label=label,
            value=_index_from_score(max(current_risk - reduction, 0.0), actionable_count) or 0.0,
            reduction=_round_score(reduction),
            mode=mode,
        )
        for key, label, reduction, mode in (
            ("current", "Now", 0.0, "actual"),
            ("top-1", "Top 1", top_one, "projected"),
            ("top-3", "Top 3", top_three, "projected"),
            ("plan", "Plan", plan, "projected"),
        )
    )
    plan_index = steps[-1].value if reducers else current_index
    target_index = _round_index(current_index * 0.5) if current_index is not None else None
    planned_reduction_index = (
        _round_index(max(current_index - (plan_index or 0.0), 0.0))
        if current_index is not None and plan_index is not None
        else None
    )
    return _RiskProjection(
        current_risk=current_risk,
        current_index=current_index,
        target_index=target_index,
        plan_index=plan_index,
        planned_reduction_index=planned_reduction_index,
        actionable_count=actionable_count,
        reducers=reducers,
        steps=steps,
    )


def _risk_reducers(
    findings: Sequence[MarkdownReportFinding],
    *,
    current_risk: float,
) -> list[_RiskReducer]:
    grouped: dict[tuple[str, str, str], list[MarkdownReportFinding]] = {}
    for finding in findings:
        grouped.setdefault(_reducer_key(finding), []).append(finding)

    reducers = [
        _risk_reducer_for_findings(key=key, findings=items, current_risk=current_risk)
        for key, items in grouped.items()
    ]
    reducers.sort(
        key=lambda item: (
            -item.expected_reduction,
            0 if item.in_kev else 1,
            -float(item.max_epss or 0.0),
            -float(item.max_cvss or 0.0),
            item.cve_id.casefold(),
            (item.component or "").casefold(),
            item.title.casefold(),
        )
    )
    return reducers


def _risk_reducer_for_findings(
    *,
    key: tuple[str, str, str],
    findings: Sequence[MarkdownReportFinding],
    current_risk: float,
) -> _RiskReducer:
    cve_id, component_key, action_key = key
    component = _first_present(finding.component for finding in findings)
    action = _first_present(finding.recommended_action for finding in findings)
    recommended_action = action or "Review with asset owner and record remediation path."
    expected_reduction = min(
        _round_score(sum(_risk_score(finding) for finding in findings)),
        current_risk,
    )
    return _RiskReducer(
        id="|".join((cve_id, component_key, action_key)),
        title=_reducer_title(cve_id, component, recommended_action),
        cve_id=cve_id,
        component=component,
        recommended_action=recommended_action,
        expected_reduction=expected_reduction,
        finding_count=len(findings),
        assets=_unique_labels(finding.asset for finding in findings),
        services=_unique_labels(finding.business_service for finding in findings),
        owners=_unique_labels(finding.owner for finding in findings),
        max_epss=_max_optional(finding.epss for finding in findings),
        max_cvss=_max_optional(finding.cvss_base_score for finding in findings),
        in_kev=any(finding.in_kev for finding in findings),
    )


def _html_projection_chart(projection: _RiskProjection) -> str:
    if not projection.reducers or projection.current_index is None:
        return (
            '        <section class="risk-scenario-chart" aria-label="Scenario projection">\n'
            '          <div class="risk-scenario-section-head">\n'
            '            <span class="status-label">Scenario projection</span>\n'
            "          </div>\n"
            '          <p class="empty-state">No open remediation reducer can be derived '
            "from this run.</p>\n"
            "        </section>"
        )

    view_width = 920
    chart_top = 48
    chart_bottom = 238
    plot_height = chart_bottom - chart_top
    chart_left = 66
    chart_right = 900
    today_gap = 42
    slot = (chart_right - chart_left - today_gap) / len(projection.steps)
    bar_width = 78
    tick_values = (100, 75, 50, 25, 0)
    grid = []
    for tick in tick_values:
        y = chart_bottom - tick * plot_height / 100
        grid.append(
            f'<line class="risk-projection-grid-line" x1="{chart_left}" '
            f'x2="{chart_right}" y1="{_fmt_coord(y)}" y2="{_fmt_coord(y)}" />'
            f'<text class="risk-projection-axis-label" x="{chart_left - 10}" '
            f'y="{_fmt_coord(y + 4)}">{tick}</text>'
        )

    target_y = chart_bottom - (projection.target_index or 0) * plot_height / 100
    divider_x = chart_left + slot + today_gap / 2
    bars = []
    for index, step in enumerate(projection.steps):
        center = chart_left + slot * index + slot / 2
        if index > 0:
            center += today_gap
        value = max(0.0, min(step.value, 100.0))
        height = value * plot_height / 100
        top = chart_bottom - height
        bar_class = _projection_bar_tone(step, projection.target_index)
        bars.append(
            '<g class="risk-projection-bar" data-tone="'
            f'{_safe_html(bar_class)}">'
            f'<rect class="risk-projection-bar-fill" x="{_fmt_coord(center - bar_width / 2)}" '
            f'y="{_fmt_coord(top)}" width="{bar_width}" height="{_fmt_coord(height)}" '
            'rx="3" ry="3" />'
            f'<rect class="risk-projection-bar-cap" x="{_fmt_coord(center - bar_width / 2)}" '
            f'y="{_fmt_coord(top)}" width="{bar_width}" height="5" rx="2.5" ry="2.5" />'
            f'<text class="risk-projection-bar-value" x="{_fmt_coord(center)}" '
            f'y="{_fmt_coord(top - 11)}">{_safe_html(_format_score(value))}</text>'
            f'<text class="risk-projection-bar-label" x="{_fmt_coord(center)}" '
            f'y="{chart_bottom + 30}">{_safe_html(step.label.upper())}</text>'
            f'<text class="risk-projection-bar-detail" x="{_fmt_coord(center)}" '
            f'y="{chart_bottom + 50}">{_safe_html(_step_detail(step))}</text>'
            "</g>"
        )

    return (
        '        <section class="risk-scenario-chart" aria-label="Scenario projection">\n'
        '          <div class="risk-scenario-section-head">\n'
        '            <span class="status-label">Scenario projection</span>\n'
        '            <span class="risk-scenario-legend"><b class="legend-actual"></b>'
        'actual <b class="legend-projected"></b>projected plan <b class="legend-target"></b>'
        "target</span>\n"
        "          </div>\n"
        '          <svg class="risk-projection-svg" role="img" '
        'aria-label="Static projection of risk index after top remediation reducers" '
        f'viewBox="0 0 {view_width} 314" preserveAspectRatio="xMidYMin meet">\n'
        "            <defs>\n"
        '              <linearGradient id="risk-report-grad-critical" '
        'x1="0" x2="0" y1="0" y2="1">\n'
        '                <stop offset="0" stop-color="#c40000" stop-opacity="0.34" />\n'
        '                <stop offset="1" stop-color="#c40000" stop-opacity="0.05" />\n'
        "              </linearGradient>\n"
        '              <linearGradient id="risk-report-grad-elevated" '
        'x1="0" x2="0" y1="0" y2="1">\n'
        '                <stop offset="0" stop-color="#b54708" stop-opacity="0.31" />\n'
        '                <stop offset="1" stop-color="#b54708" stop-opacity="0.06" />\n'
        "              </linearGradient>\n"
        '              <linearGradient id="risk-report-grad-low" x1="0" x2="0" y1="0" y2="1">\n'
        '                <stop offset="0" stop-color="#047857" stop-opacity="0.22" />\n'
        '                <stop offset="1" stop-color="#047857" stop-opacity="0.05" />\n'
        "              </linearGradient>\n"
        '              <linearGradient id="risk-report-grad-projected" '
        'x1="0" x2="0" y1="0" y2="1">\n'
        '                <stop offset="0" stop-color="#047857" stop-opacity="0.22" />\n'
        '                <stop offset="1" stop-color="#047857" stop-opacity="0.05" />\n'
        "              </linearGradient>\n"
        '              <linearGradient id="risk-report-grad-success" x1="0" x2="0" y1="0" y2="1">\n'
        '                <stop offset="0" stop-color="#047857" stop-opacity="0.28" />\n'
        '                <stop offset="1" stop-color="#047857" stop-opacity="0.06" />\n'
        "              </linearGradient>\n"
        "            </defs>\n"
        f"            {''.join(grid)}\n"
        f'            <line class="risk-projection-today" x1="{_fmt_coord(divider_x)}" '
        f'x2="{_fmt_coord(divider_x)}" y1="{chart_top - 10}" y2="{chart_bottom}" />\n'
        f'            <text class="risk-projection-today-label" x="{_fmt_coord(divider_x)}" '
        f'y="{chart_top - 18}">TODAY</text>\n'
        f'            <line class="risk-projection-target" x1="{chart_left}" '
        f'x2="{chart_right}" y1="{_fmt_coord(target_y)}" y2="{_fmt_coord(target_y)}" />\n'
        f'            <text class="risk-projection-target-label" x="{chart_right - 2}" '
        f'y="{_fmt_coord(target_y - 7)}">TARGET '
        f"{_safe_html(_format_score(projection.target_index))}</text>\n"
        f"            {''.join(bars)}\n"
        "          </svg>\n"
        f"{_html_projection_readout(projection)}\n"
        '          <p class="risk-scenario-note">Static what-if simulation from this run: '
        "current open actionable findings minus the shown remediation reducers. It is not "
        "a measured run-history curve.</p>\n"
        "        </section>"
    )


def _html_projection_readout(projection: _RiskProjection) -> str:
    final_index = projection.plan_index
    current_index = projection.current_index
    if current_index is None or final_index is None:
        return ""

    drop_percent = _projection_drop_percent(current_index, final_index)
    reached_step = _target_reached_step(projection)
    if reached_step is None:
        outcome = (
            '<strong class="risk-scenario-readout-warn">target not reached</strong>; '
            "add more reducers"
        )
    else:
        outcome = f"target reached <strong>{_safe_html(_readout_step_label(reached_step))}</strong>"

    reducer_count = len(projection.reducers)
    action_label = "action" if reducer_count == 1 else "actions"
    return (
        '          <div class="risk-scenario-readout">'
        f'<span class="risk-scenario-readout-chip">{reducer_count} '
        f"{action_label} planned</span>"
        '<span class="risk-scenario-readout-text">Completing the shown plan takes '
        "the index "
        f"<strong>{_safe_html(_format_score(current_index))} -&gt; "
        f"{_safe_html(_format_score(final_index))}</strong> "
        f"(-{drop_percent}%) - {outcome}</span>"
        "</div>"
    )


def _html_top_reducers(projection: _RiskProjection) -> str:
    if not projection.reducers:
        return (
            '        <section class="risk-scenario-reducers" aria-label="Top risk reducers">\n'
            '          <div class="risk-scenario-section-head">\n'
            '            <span class="status-label">Top risk reducers</span>\n'
            "          </div>\n"
            '          <p class="empty-state">No open remediation groups are available.</p>\n'
            "        </section>"
        )

    max_reduction = max(
        (reducer.expected_reduction for reducer in projection.reducers),
        default=0.0,
    )
    rows = []
    for index, reducer in enumerate(projection.reducers):
        reduction_index = _index_from_score(reducer.expected_reduction, projection.actionable_count)
        meta = _reducer_meta(reducer)
        context = _reducer_context(reducer)
        tags = _reducer_signal_tags(reducer)
        width = _reducer_width(reducer.expected_reduction, max_reduction)
        biggest = '<span class="risk-reducer-tag">biggest lever</span>' if index == 0 else ""
        rows.append(
            '<li class="risk-scenario-reducer">'
            '<div class="risk-scenario-reducer-main">'
            f'<span class="risk-scenario-reducer-title">{_safe_html(reducer.title)}</span>'
            f"<strong>-{_safe_html(_format_score(reduction_index))}</strong>"
            "</div>"
            '<div class="risk-scenario-reducer-meta">'
            f"{biggest}<span>{_safe_html(meta)}</span>{tags}</div>"
            f'<span class="risk-scenario-reducer-context">{_safe_html(context)}</span>'
            '<span class="risk-scenario-reducer-track">'
            f'<span style="width:{_safe_html(width)}%;"></span>'
            "</span>"
            "</li>"
        )

    return (
        '        <section class="risk-scenario-reducers" aria-label="Top risk reducers">\n'
        '          <div class="risk-scenario-section-head">\n'
        '            <span class="status-label">Top risk reducers</span>\n'
        "          </div>\n"
        '          <p class="risk-scenario-reducer-lede">'
        "Expected index reduction if completed.</p>\n"
        f"          <ol>{''.join(rows)}</ol>\n"
        "        </section>"
    )


def _risk_index_label_and_tone(
    projection: _RiskProjection,
    risk_posture: RiskPosture,
) -> tuple[str, str]:
    if projection.current_index is None:
        return _RISK_INDEX_BANDS["none"]
    band = _band_for_index(projection.current_index)
    fallback = _RISK_INDEX_BANDS.get(risk_posture.risk_index_band, _RISK_INDEX_BANDS["none"])
    return _RISK_INDEX_BANDS.get(band, fallback)


def _risk_index_value_html(projection: _RiskProjection) -> str:
    if projection.current_index is None:
        return '<span class="risk-scenario-index-value">N/A</span>'
    return (
        '<span class="risk-scenario-index-value">'
        f"{_safe_html(_format_score(projection.current_index))}"
        '<span class="risk-index-max">/100</span></span>'
    )


def _risk_index_gauge_html(projection: _RiskProjection) -> str:
    if projection.current_index is None:
        return '<div class="risk-gauge"></div>'
    needle = max(0.0, min(projection.current_index, 100.0))
    return (
        '<div class="risk-gauge"><span class="risk-gauge-needle" '
        f'style="left:{_safe_html(_format_score(needle))}%;"></span></div>'
    )


def _risk_index_footnote(projection: _RiskProjection) -> str:
    if projection.current_index is None:
        return "No open, non-accepted finding carries actionable risk for this run."
    return (
        "Mean risk score across "
        f"{_pluralize(projection.actionable_count, 'open, non-accepted finding')}. "
        "Accepted risk, VEX suppressed and fixed-evidence findings are excluded."
    )


def _reducer_key(finding: MarkdownReportFinding) -> tuple[str, str, str]:
    return (
        finding.cve_id,
        _slug(finding.component or "unknown-component"),
        _slug(finding.recommended_action or "review-and-remediate"),
    )


def _reducer_title(cve_id: str, component: str | None, action: str) -> str:
    clean_action = action.rstrip(".").strip()
    if (
        clean_action
        and len(clean_action) <= 58
        and not clean_action.casefold().startswith("cisa kev")
    ):
        return clean_action
    if component:
        return f"Patch {component}"
    return cve_id


def _reducer_meta(reducer: _RiskReducer) -> str:
    parts = [_pluralize(reducer.finding_count, "finding")]
    if reducer.services:
        parts.append(_pluralize(len(reducer.services), "service"))
    return " - ".join(parts)


def _reducer_context(reducer: _RiskReducer) -> str:
    if reducer.services:
        return _short_list(reducer.services, limit=2, noun="service")
    if reducer.owners:
        return _short_list(reducer.owners, limit=2, noun="owner")
    if reducer.assets:
        return _short_list(reducer.assets, limit=2, noun="asset")
    return "Unassigned"


def _reducer_signal_tags(reducer: _RiskReducer) -> str:
    tags = []
    if reducer.in_kev:
        tags.append('<span class="risk-reducer-tag risk-reducer-tag--kev">KEV</span>')
    if reducer.max_epss is not None:
        tags.append(
            '<span class="risk-reducer-tag risk-reducer-tag--epss">'
            f"EPSS {_safe_html(_format_percent(reducer.max_epss))}</span>"
        )
    if reducer.max_cvss is not None:
        tags.append(
            '<span class="risk-reducer-tag risk-reducer-tag--cvss">'
            f"CVSS {_safe_html(_format_score(reducer.max_cvss))}</span>"
        )
    return "".join(tags)


def _projection_bar_tone(step: _ProjectionStep, target_index: float | None) -> str:
    if step.mode == "actual":
        return _band_for_index(step.value)
    if target_index is not None and step.value <= target_index:
        return "success"
    return "projected"


def _projection_drop_percent(current_index: float, final_index: float) -> int:
    if current_index <= 0:
        return 0
    return max(0, round(((current_index - final_index) / current_index) * 100))


def _target_reached_step(projection: _RiskProjection) -> _ProjectionStep | None:
    if projection.target_index is None:
        return None
    return next(
        (step for step in projection.steps if step.value <= (projection.target_index or 0)),
        None,
    )


def _readout_step_label(step: _ProjectionStep) -> str:
    if step.key == "current":
        return "already"
    if step.key == "top-1":
        return "after top 1"
    if step.key == "top-3":
        return "after top 3"
    return "after full plan"


def _step_detail(step: _ProjectionStep) -> str:
    if step.reduction <= 0:
        return "open risk"
    return f"-{_format_score(step.reduction)} score"


def _band_for_index(value: float) -> str:
    if value >= 70:
        return "critical"
    if value >= 40:
        return "elevated"
    return "low"


def _risk_score(finding: MarkdownReportFinding) -> float:
    return max(float(finding.risk_score or 0.0), 0.0)


def _index_from_score(score: float, finding_count: int) -> float | None:
    if finding_count <= 0:
        return None
    return _round_index(min(max(score, 0.0) / finding_count, 100.0))


def _reduction_for_first(reducers: Sequence[_RiskReducer], count: int) -> float:
    return _round_score(sum(reducer.expected_reduction for reducer in reducers[:count]))


def _reducer_width(reduction: float, max_reduction: float) -> str:
    if max_reduction <= 0 or reduction <= 0:
        return "0"
    return _format_score(max(4.0, min((reduction / max_reduction) * 100.0, 100.0)))


def _format_score(value: float | None) -> str:
    if value is None:
        return "N/A"
    rounded = _round_index(float(value))
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.1f}"


def _format_percent(value: float) -> str:
    return f"{floor(float(value) * 1000 + 0.5) / 10:g}%"


def _fmt_coord(value: float) -> str:
    rounded = round(float(value), 2)
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:g}"


def _round_score(value: float) -> float:
    return round(float(value), 3)


def _round_index(value: float) -> float:
    return floor(float(value) * 10 + 0.5) / 10


def _unique_labels(values: Iterable[str | None]) -> tuple[str, ...]:
    return tuple(sorted({label for value in values if (label := _clean_label(value))}))


def _first_present(values: Iterable[str | None]) -> str | None:
    for value in values:
        if cleaned := _clean_label(value):
            return cleaned
    return None


def _max_optional(values: Iterable[float | None]) -> float | None:
    numbers = [float(value) for value in values if value is not None]
    return _round_score(max(numbers)) if numbers else None


def _clean_label(value: object | None) -> str | None:
    text = str(value or "").strip()
    return text or None


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug[:96] or "unknown"


__all__ = [
    "_html_risk_scenario_panel_helper",
    "_risk_projection_helper",
]
