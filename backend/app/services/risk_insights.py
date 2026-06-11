"""Risk posture insights: per-run risk trend, top driver, and mitigation levers."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from hashlib import sha256

from app.decision_core.readmodels import (
    SUCCESSFUL_RUN_STATUSES,
    DecisionFindingView,
    decision_views_for_findings,
)
from app.models import (
    AnalysisRun,
    Finding,
    FindingAttackContext,
    FindingDecisionEvidence,
    MitigationAttackTechniquePublic,
    MitigationLeverPublic,
    ProjectRiskInsightsPublic,
    RiskTopDriverPublic,
    RiskTrendPointPublic,
)
from app.models.base import get_datetime_utc
from app.repositories.evidence import EvidenceRepository
from app.repositories.findings import FindingRepository
from app.repositories.runs import RunRepository
from app.services.attack_support import latest_contexts_by_finding, technique_candidates
from app.services.decisions import OPEN_WORK_STATUSES, PRIORITY_LABELS

PROVIDER_UPDATE_INPUT_TYPE = "provider_update"

LEVER_KIND_COMPONENT_UPGRADE = "component_upgrade"
LEVER_KIND_RECOMMENDED_ACTION = "recommended_action"
LEVER_KIND_CVE = "cve"

_TOP_CVE_LIMIT = 3
_TOP_ATTACK_TECHNIQUE_LIMIT = 3
RISK_TARGET_SCORE = 30.0


def build_project_risk_insights_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding | DecisionFindingView],
    runs: Sequence[AnalysisRun],
    evidence_repository: EvidenceRepository,
    attack_contexts: Sequence[FindingAttackContext] = (),
    lever_limit: int = 6,
) -> ProjectRiskInsightsPublic:
    """Build the one-call risk insights aggregate from loaded domain rows."""
    bounded_lever_limit = max(1, min(lever_limit, 10))
    finding_views = _decision_views(findings)
    open_views = open_decision_views(finding_views)
    open_scores = [_view_score(view) for view in open_views]
    baseline_average = _rounded_average(open_scores)
    baseline_total = round(sum(open_scores), 1)
    mitigation_levers = build_mitigation_levers(
        open_views,
        attack_contexts=attack_contexts,
        baseline_average=baseline_average,
        baseline_total_risk_score=baseline_total,
        limit=bounded_lever_limit,
    )
    return ProjectRiskInsightsPublic(
        project_id=project_id,
        generated_at=get_datetime_utc(),
        baseline_average_risk_score=baseline_average,
        baseline_open_finding_count=len(open_views),
        baseline_total_risk_score=baseline_total,
        risk_target_score=RISK_TARGET_SCORE,
        recommended_lever_id=mitigation_levers[0].lever_id if mitigation_levers else None,
        trend=build_risk_trend_points(runs, evidence_repository=evidence_repository),
        top_driver=build_top_risk_driver(open_views),
        mitigation_levers=mitigation_levers,
    )


def build_project_risk_insights_payload_from_repositories(
    *,
    project_id: uuid.UUID,
    finding_repository: FindingRepository,
    run_repository: RunRepository,
    evidence_repository: EvidenceRepository,
    attack_contexts: Sequence[FindingAttackContext] = (),
    run_limit: int = 30,
    lever_limit: int = 6,
) -> ProjectRiskInsightsPublic:
    """Build the risk insights aggregate from bounded repository queries."""
    bounded_run_limit = max(1, min(run_limit, 30))
    return build_project_risk_insights_payload(
        project_id=project_id,
        findings=finding_repository.list_project_findings(project_id),
        runs=run_repository.list_analysis_runs(project_id, limit=bounded_run_limit),
        evidence_repository=evidence_repository,
        attack_contexts=attack_contexts,
        lever_limit=lever_limit,
    )


def build_risk_trend_points(
    runs: Sequence[AnalysisRun],
    *,
    evidence_repository: EvidenceRepository,
) -> list[RiskTrendPointPublic]:
    """Build per-run aggregate points oldest-first for the risk trend chart."""
    scan_runs = [
        run
        for run in runs
        if run.status in SUCCESSFUL_RUN_STATUSES and run.input_type != PROVIDER_UPDATE_INPUT_TYPE
    ]
    evidence_run_ids = evidence_repository.analysis_evidence_run_ids([run.id for run in scan_runs])
    scan_runs = [run for run in scan_runs if run.id in evidence_run_ids]
    rows_by_run = _evidence_rows_by_run(
        evidence_repository.finding_decision_evidence_rows_for_runs([run.id for run in scan_runs])
    )
    points = [_trend_point(run, rows_by_run.get(run.id, [])) for run in scan_runs]
    # Run repositories return runs newest-first; the chart reads oldest-first.
    points.reverse()
    return points


def build_top_risk_driver(
    open_views: Sequence[DecisionFindingView],
) -> RiskTopDriverPublic | None:
    """Return the open finding with the highest operational risk."""
    if not open_views:
        return None
    view = min(open_views, key=_driver_sort_key)
    score_reasons = (
        list(view.evidence.priority_evidence.operational_score_reasons)
        if view.evidence is not None
        else []
    )
    return RiskTopDriverPublic(
        finding_id=view.finding_id,
        cve_id=view.cve_id,
        priority=view.priority_label,
        risk_score=view.risk_score,
        in_kev=view.in_kev,
        epss=view.epss,
        component_label=view.component_label,
        asset_label=view.asset_label,
        recommended_action=view.recommended_action,
        score_reasons=score_reasons,
    )


def build_mitigation_levers(
    open_views: Sequence[DecisionFindingView],
    *,
    attack_contexts: Sequence[FindingAttackContext] = (),
    baseline_average: float | None,
    baseline_total_risk_score: float | None = None,
    limit: int = 6,
) -> list[MitigationLeverPublic]:
    """Rank remediation actions by the total open risk they would eliminate."""
    if not open_views:
        return []
    total_score = sum(_view_score(view) for view in open_views)
    total_risk_score = (
        baseline_total_risk_score if baseline_total_risk_score is not None else total_score
    )
    total_count = len(open_views)
    contexts_by_finding = latest_contexts_by_finding(attack_contexts)
    groups: dict[tuple[str, str], _LeverGroup] = {}
    for view in open_views:
        kind, identity = _lever_group_key(view)
        group = groups.get((kind, identity))
        if group is None:
            group = _LeverGroup(kind=kind, identity=identity)
            groups[(kind, identity)] = group
        group.add(view, attack_context=contexts_by_finding.get(view.finding_id))

    levers: list[MitigationLeverPublic] = []
    for group in groups.values():
        remaining_count = total_count - group.finding_count
        projected_average = (
            round((total_score - group.score_sum) / remaining_count, 1)
            if remaining_count > 0
            else None
        )
        average_delta = (
            round(baseline_average - projected_average, 1)
            if baseline_average is not None and projected_average is not None
            else None
        )
        share = _risk_share_percent(group.score_sum, total_risk_score)
        roadmap_lane, roadmap_reason = _roadmap_lane(
            group,
            average_delta=average_delta,
            risk_score_share_percent=share,
            top_impact=False,
        )
        nist_function, nist_reason = _nist_csf_function(group)
        levers.append(
            MitigationLeverPublic(
                lever_id=group.lever_id(),
                action_label=group.action_label(),
                kind=group.kind,
                component_name=group.component_name,
                component_version=group.component_version,
                target_version=group.target_version(),
                resolved_finding_count=group.finding_count,
                resolved_kev_count=group.kev_count,
                risk_score_sum=round(group.score_sum, 1),
                risk_score_share_percent=share,
                projected_average_risk_score=projected_average,
                average_delta=average_delta,
                top_cve_ids=group.top_cve_ids(),
                roadmap_lane=roadmap_lane,
                roadmap_reason=roadmap_reason,
                nist_csf_function=nist_function,
                nist_csf_reason=nist_reason,
                attack_techniques=group.attack_techniques(),
                attack_tactics=group.attack_tactics(),
            )
        )
    levers.sort(
        key=lambda lever: (
            -lever.risk_score_sum,
            -lever.resolved_finding_count,
            lever.action_label.casefold(),
        )
    )
    selected = levers[: max(1, limit)]
    if selected:
        first = selected[0]
        if first.roadmap_lane != "now":
            selected[0] = first.model_copy(
                update={
                    "roadmap_lane": "now",
                    "roadmap_reason": (
                        "Largest evidence-backed risk reduction in the current queue."
                    ),
                }
            )
    return selected


def open_decision_views(
    views: Iterable[DecisionFindingView],
) -> list[DecisionFindingView]:
    """Return findings that still carry open operational risk."""
    return [
        view
        for view in views
        if str(view.status) in OPEN_WORK_STATUSES and not view.suppressed_by_vex
    ]


@dataclass
class _LeverTechniqueGroup:
    """Accumulator for reviewed ATT&CK technique context attached to one lever."""

    technique_id: str
    name: str | None = None
    tactics: set[str] = field(default_factory=set)
    finding_ids: set[uuid.UUID] = field(default_factory=set)

    def add(
        self,
        *,
        finding_id: uuid.UUID,
        name: str | None,
        tactics: Sequence[str],
    ) -> None:
        self.finding_ids.add(finding_id)
        if not self.name and name:
            self.name = name
        self.tactics.update(tactic for tactic in tactics if tactic)


@dataclass
class _LeverGroup:
    """Accumulator for findings resolved by one remediation action."""

    kind: str
    identity: str
    component_name: str | None = None
    component_version: str | None = None
    recommended_action: str | None = None
    cve_id: str | None = None
    finding_count: int = 0
    kev_count: int = 0
    score_sum: float = 0.0
    fix_versions: Counter[str] = field(default_factory=Counter)
    scored_cves: list[tuple[float, str]] = field(default_factory=list)
    attack_technique_groups: dict[str, _LeverTechniqueGroup] = field(default_factory=dict)

    def add(
        self,
        view: DecisionFindingView,
        *,
        attack_context: FindingAttackContext | None = None,
    ) -> None:
        self.finding_count += 1
        self.score_sum += _view_score(view)
        if view.in_kev:
            self.kev_count += 1
        self.scored_cves.append((_view_score(view), view.cve_id))
        component = view.finding.component
        if self.kind == LEVER_KIND_COMPONENT_UPGRADE and component is not None:
            self.component_name = self.component_name or component.name
            self.component_version = self.component_version or component.version
            for fix in _view_fix_versions(view):
                self.fix_versions[fix] += 1
        if self.kind == LEVER_KIND_RECOMMENDED_ACTION and self.recommended_action is None:
            self.recommended_action = (view.recommended_action or "").strip() or None
        if self.kind == LEVER_KIND_CVE and self.cve_id is None:
            self.cve_id = view.cve_id
        self._add_attack_context(view.finding_id, attack_context)

    def lever_id(self) -> str:
        digest = sha256(f"{self.kind}:{self.identity}".encode()).hexdigest()
        return f"{self.kind}-{digest[:12]}"

    def target_version(self) -> str | None:
        if not self.fix_versions:
            return None
        return max(
            self.fix_versions,
            key=lambda fix: (self.fix_versions[fix], fix),
        )

    def action_label(self) -> str:
        if self.kind == LEVER_KIND_COMPONENT_UPGRADE:
            component = " ".join(
                part for part in (self.component_name, self.component_version) if part
            )
            target = self.target_version()
            if target:
                return f"Upgrade {component} to {target}"
            return f"Upgrade {component} to a fixed version"
        if self.kind == LEVER_KIND_RECOMMENDED_ACTION and self.recommended_action:
            return self.recommended_action
        return f"Remediate {self.cve_id or self.identity}"

    def top_cve_ids(self) -> list[str]:
        ordered = sorted(self.scored_cves, key=lambda item: (-item[0], item[1]))
        unique: list[str] = []
        for _score, cve_id in ordered:
            if cve_id not in unique:
                unique.append(cve_id)
            if len(unique) >= _TOP_CVE_LIMIT:
                break
        return unique

    def attack_techniques(self) -> list[MitigationAttackTechniquePublic]:
        ordered = sorted(
            self.attack_technique_groups.values(),
            key=lambda item: (-len(item.finding_ids), item.technique_id),
        )
        return [
            MitigationAttackTechniquePublic(
                technique_id=item.technique_id,
                name=item.name,
                tactics=sorted(item.tactics),
                finding_count=len(item.finding_ids),
            )
            for item in ordered[:_TOP_ATTACK_TECHNIQUE_LIMIT]
        ]

    def attack_tactics(self) -> list[str]:
        tactics: set[str] = set()
        for item in self.attack_technique_groups.values():
            tactics.update(item.tactics)
        return sorted(tactics)

    def _add_attack_context(
        self,
        finding_id: uuid.UUID,
        attack_context: FindingAttackContext | None,
    ) -> None:
        if (
            attack_context is None
            or not bool(attack_context.mapped)
            or str(attack_context.review_status) != "reviewed"
        ):
            return
        for candidate in technique_candidates(attack_context):
            group = self.attack_technique_groups.get(candidate.technique_id)
            if group is None:
                group = _LeverTechniqueGroup(technique_id=candidate.technique_id)
                self.attack_technique_groups[candidate.technique_id] = group
            group.add(
                finding_id=finding_id,
                name=candidate.name,
                tactics=candidate.tactics,
            )


def _lever_group_key(view: DecisionFindingView) -> tuple[str, str]:
    component = view.finding.component
    if component is not None and component.name:
        identity = component.purl or f"{component.name}@{component.version or 'unknown'}"
        return (LEVER_KIND_COMPONENT_UPGRADE, identity.casefold())
    action = (view.recommended_action or "").strip()
    if action:
        return (LEVER_KIND_RECOMMENDED_ACTION, action.casefold())
    return (LEVER_KIND_CVE, view.cve_id.casefold())


def _risk_share_percent(score_sum: float, total_risk_score: float | None) -> int:
    if total_risk_score is None or total_risk_score <= 0:
        return 0
    return min(100, max(0, round((score_sum / total_risk_score) * 100)))


def _roadmap_lane(
    group: _LeverGroup,
    *,
    average_delta: float | None,
    risk_score_share_percent: int,
    top_impact: bool,
) -> tuple[str, str]:
    if top_impact:
        return ("now", "Largest evidence-backed risk reduction in the current queue.")
    if group.kev_count > 0:
        return ("now", "Addresses open KEV exposure.")
    if average_delta is not None and average_delta >= 10:
        return ("now", "Materially lowers the projected average risk score.")
    if risk_score_share_percent >= 30:
        return ("now", "Removes a large share of current open risk.")
    if risk_score_share_percent >= 10 or group.finding_count > 1:
        return ("next", "Useful risk reduction after the highest-impact work.")
    return ("later", "Lower relative impact based on the current evidence set.")


def _nist_csf_function(group: _LeverGroup) -> tuple[str, str]:
    if group.kind == LEVER_KIND_COMPONENT_UPGRADE:
        return ("Protect", "Patch or upgrade work reduces exposure in affected components.")
    label = group.action_label().casefold()
    keyword_rules: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        (
            "Govern",
            "Governance, policy, or risk-management wording in the action.",
            (
                "policy",
                "policies",
                "governance",
                "risk management",
                "third party",
                "third-party",
                "vendor",
                "supplier",
                "compliance",
                "kpi",
                "reporting",
                "isms",
            ),
        ),
        (
            "Identify",
            "Asset, inventory, ownership, or configuration context in the action.",
            (
                "asset",
                "inventory",
                "configuration",
                "cmdb",
                "owner",
                "ownership",
                "context",
                "classif",
                "discovery",
            ),
        ),
        (
            "Detect",
            "Monitoring, vulnerability management, or detection wording in the action.",
            (
                "monitor",
                "logging",
                "detection",
                "detect",
                "vulnerability management",
                "scan",
                "scanning",
                "threat intelligence",
                "telemetry",
                "alert",
            ),
        ),
        (
            "Respond",
            "Incident response or triage wording in the action.",
            (
                "incident",
                "response",
                "triage",
                "forensic",
                "rehearsal",
                "playbook",
            ),
        ),
        (
            "Recover",
            "Recovery, backup, or continuity wording in the action.",
            (
                "backup",
                "restore",
                "recovery",
                "recover",
                "continuity",
                "disaster",
            ),
        ),
        (
            "Protect",
            "Protection, patching, access-control, or hardening wording in the action.",
            (
                "patch",
                "update",
                "upgrade",
                "fixed version",
                "credential",
                "rotate",
                "access",
                "authentication",
                "harden",
                "encrypt",
                "certificate",
                "device",
                "endpoint",
                "disable stale",
                "system security",
            ),
        ),
    )
    for function, reason, keywords in keyword_rules:
        if any(keyword in label for keyword in keywords):
            return (function, reason)
    return ("Unclassified", "No clear control category from current evidence.")


def _view_fix_versions(view: DecisionFindingView) -> list[str]:
    if view.evidence is None:
        return []
    versions: list[str] = []
    for occurrence in view.evidence.occurrences:
        if occurrence.fix_version:
            versions.append(occurrence.fix_version)
        for fix in occurrence.fix_versions or []:
            if fix:
                versions.append(fix)
    return versions


def _driver_sort_key(view: DecisionFindingView) -> tuple[object, ...]:
    return (
        view.operational_rank or 999_999,
        view.priority_rank,
        -_view_score(view),
        view.cve_id.casefold(),
        str(view.finding_id),
    )


def _view_score(view: DecisionFindingView) -> float:
    return float(view.risk_score) if view.risk_score is not None else 0.0


def _trend_point(
    run: AnalysisRun,
    rows: Sequence[FindingDecisionEvidence],
) -> RiskTrendPointPublic:
    open_rows = [row for row in rows if _row_is_open(row)]
    scores = [_row_score(row) for row in open_rows]
    priority_counts = Counter(_priority_display_label(row.priority) for row in open_rows)
    return RiskTrendPointPublic(
        run_id=run.id,
        started_at=run.started_at,
        finished_at=run.finished_at,
        status=run.status,
        average_risk_score=_rounded_average(scores),
        max_risk_score=round(max(scores), 1) if scores else None,
        open_finding_count=len(open_rows),
        counts_by_priority={label: priority_counts.get(label, 0) for label in PRIORITY_LABELS},
        kev_count=sum(1 for row in open_rows if _row_in_kev(row)),
    )


def _evidence_rows_by_run(
    rows: Iterable[FindingDecisionEvidence],
) -> dict[uuid.UUID, list[FindingDecisionEvidence]]:
    rows_by_run: dict[uuid.UUID, list[FindingDecisionEvidence]] = {}
    for row in rows:
        rows_by_run.setdefault(row.analysis_run_id, []).append(row)
    return rows_by_run


def _row_is_open(row: FindingDecisionEvidence) -> bool:
    if row.status not in OPEN_WORK_STATUSES:
        return False
    return not bool(_row_payload(row).get("suppressed_by_vex"))


def _row_score(row: FindingDecisionEvidence) -> float:
    value = _row_payload(row).get("risk_score")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value)


def _row_in_kev(row: FindingDecisionEvidence) -> bool:
    return bool(_row_payload(row).get("in_kev"))


def _row_payload(row: FindingDecisionEvidence) -> dict[str, object]:
    payload = row.payload_json
    return payload if isinstance(payload, dict) else {}


def _priority_display_label(value: str) -> str:
    normalized = str(value).split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _rounded_average(scores: Sequence[float]) -> float | None:
    if not scores:
        return None
    return round(sum(scores) / len(scores), 1)


def _decision_views(
    findings: Sequence[Finding | DecisionFindingView],
) -> list[DecisionFindingView]:
    if not findings:
        return []
    if isinstance(findings[0], DecisionFindingView):
        return [view for view in findings if isinstance(view, DecisionFindingView)]
    return decision_views_for_findings(
        [finding for finding in findings if isinstance(finding, Finding)]
    )
