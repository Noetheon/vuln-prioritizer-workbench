"""ATT&CK dashboard summary helpers for the Workbench."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import cast

from app.models import (
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    FindingAttackContext,
    ProjectAttackSummaryPublic,
    ProjectAttackTacticSummaryPublic,
    ProjectAttackTechniqueSummaryPublic,
)
from app.services.attack_navigator import build_attack_navigator_layer_payload
from app.services.attack_support import (
    ATTACK_NAVIGATOR_FILTERS,
    CONFIDENCE_BUCKETS,
    REVIEW_STATUS_BUCKETS,
    AttackSummaryFindingLike,
)
from app.services.attack_support import (
    TacticSummaryAccumulator as _TacticSummaryAccumulator,
)
from app.services.attack_support import (
    TechniqueSummaryAccumulator as _TechniqueSummaryAccumulator,
)
from app.services.attack_support import (
    confidence_label as _confidence_label,
)
from app.services.attack_support import (
    context_confidence as _context_confidence,
)
from app.services.attack_support import (
    latest_contexts_by_finding as _latest_contexts_by_finding,
)
from app.services.attack_support import (
    ordered_counts as _ordered_counts,
)
from app.services.attack_support import (
    review_status_label as _review_status_label,
)
from app.services.attack_support import (
    technique_candidates as _technique_candidates,
)

__all__ = [
    "ATTACK_NAVIGATOR_FILTERS",
    "build_attack_navigator_layer_payload",
    "build_project_attack_summary_payload",
    "build_project_attack_summary_payload_from_rows",
]


def build_project_attack_summary_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[AttackSummaryFindingLike],
    attack_contexts: Sequence[FindingAttackContext],
    top_limit: int = 5,
) -> ProjectAttackSummaryPublic:
    """Build a defensive ATT&CK dashboard summary from persisted finding contexts."""
    finding_by_id = {finding.id: finding for finding in findings}
    latest_contexts = _latest_contexts_by_finding(attack_contexts)
    confidence_distribution: Counter[str] = Counter()
    review_status_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    technique_summaries: dict[str, _TechniqueSummaryAccumulator] = {}
    tactic_summaries: dict[str, _TacticSummaryAccumulator] = {}
    mapped_finding_ids: set[uuid.UUID] = set()

    for context in latest_contexts.values():
        finding = finding_by_id.get(context.finding_id)
        if finding is None or not context.mapped:
            continue

        candidates = _technique_candidates(context)
        if not candidates:
            continue

        mapped_finding_ids.add(context.finding_id)
        context_confidence = _context_confidence(candidates)
        review_status = _review_status_label(context.review_status)
        source = context.source or "none"
        risk_score = float(finding.risk_score or 0.0)
        confidence_distribution[context_confidence] += 1
        review_status_counts[review_status] += 1
        source_counts[source] += 1

        seen_techniques: set[str] = set()
        seen_tactics: set[str] = set()
        for candidate in candidates:
            if candidate.technique_id in seen_techniques:
                continue
            seen_techniques.add(candidate.technique_id)
            summary = technique_summaries.setdefault(
                candidate.technique_id,
                _TechniqueSummaryAccumulator(candidate.technique_id),
            )
            summary.name = summary.name or candidate.name
            summary.tactics.update(candidate.tactics)
            summary.finding_count += 1
            summary.risk_score_total += risk_score
            summary.highest_risk_score = max(summary.highest_risk_score, risk_score)
            summary.confidence_counts[_confidence_label(candidate.confidence)] += 1
            summary.review_status_counts[review_status] += 1
            summary.source_counts[source] += 1

            for tactic in candidate.tactics:
                if not tactic:
                    continue
                tactic_summary = tactic_summaries.setdefault(
                    tactic,
                    _TacticSummaryAccumulator(tactic),
                )
                tactic_summary.technique_ids.add(candidate.technique_id)
                if tactic not in seen_tactics:
                    tactic_summary.finding_count += 1
                    tactic_summary.risk_score_total += risk_score
                    seen_tactics.add(tactic)

    finding_count = len(findings)
    mapped_finding_count = len(mapped_finding_ids)
    return ProjectAttackSummaryPublic(
        project_id=project_id,
        finding_count=finding_count,
        mapped_finding_count=mapped_finding_count,
        unmapped_finding_count=max(finding_count - mapped_finding_count, 0),
        mapped_coverage_percent=round(
            (mapped_finding_count / finding_count) * 100,
            1,
        )
        if finding_count
        else 0.0,
        top_techniques=_top_technique_rows(technique_summaries.values(), top_limit),
        top_tactics=_top_tactic_rows(tactic_summaries.values(), top_limit),
        confidence_distribution=_ordered_counts(confidence_distribution, CONFIDENCE_BUCKETS),
        review_status_counts=_ordered_counts(review_status_counts, REVIEW_STATUS_BUCKETS),
        source_counts=dict(sorted(source_counts.items())),
    )


def build_project_attack_summary_payload_from_rows(
    *,
    project_id: uuid.UUID,
    findings: Sequence[AttackSummaryFindingRow],
    attack_contexts: Sequence[AttackSummaryContextRow],
    top_limit: int = 5,
) -> ProjectAttackSummaryPublic:
    """Build a defensive ATT&CK dashboard summary from lightweight SQL rows."""
    return build_project_attack_summary_payload(
        project_id=project_id,
        findings=cast(Sequence[AttackSummaryFindingLike], findings),
        attack_contexts=cast(Sequence[FindingAttackContext], attack_contexts),
        top_limit=top_limit,
    )


def _top_technique_rows(
    summaries: Iterable[_TechniqueSummaryAccumulator],
    top_limit: int,
) -> list[ProjectAttackTechniqueSummaryPublic]:
    ordered = sorted(
        summaries,
        key=lambda item: (-item.finding_count, -item.risk_score_total, item.technique_id),
    )
    return [
        ProjectAttackTechniqueSummaryPublic(
            technique_id=summary.technique_id,
            name=summary.name,
            tactics=sorted(summary.tactics),
            finding_count=summary.finding_count,
            risk_score_total=round(summary.risk_score_total, 2),
            highest_risk_score=round(summary.highest_risk_score, 2),
            confidence_counts=_ordered_counts(summary.confidence_counts, CONFIDENCE_BUCKETS),
            review_status_counts=_ordered_counts(
                summary.review_status_counts,
                REVIEW_STATUS_BUCKETS,
            ),
            source_counts=dict(sorted(summary.source_counts.items())),
        )
        for summary in ordered[:top_limit]
    ]


def _top_tactic_rows(
    summaries: Iterable[_TacticSummaryAccumulator],
    top_limit: int,
) -> list[ProjectAttackTacticSummaryPublic]:
    ordered = sorted(
        summaries,
        key=lambda item: (-item.finding_count, -item.risk_score_total, item.tactic),
    )
    return [
        ProjectAttackTacticSummaryPublic(
            tactic=summary.tactic,
            finding_count=summary.finding_count,
            technique_count=len(summary.technique_ids),
            risk_score_total=round(summary.risk_score_total, 2),
        )
        for summary in ordered[:top_limit]
    ]
