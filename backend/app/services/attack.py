"""ATT&CK dashboard summary helpers for the template Workbench."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.models import (
    Finding,
    FindingAttackContext,
    ProjectAttackSummaryPublic,
    ProjectAttackTacticSummaryPublic,
    ProjectAttackTechniqueSummaryPublic,
)

CONFIDENCE_BUCKETS = ("high", "medium", "low", "unknown")
REVIEW_STATUS_BUCKETS = ("reviewed", "needs_review", "unreviewed", "stale", "rejected")


@dataclass
class _TechniqueCandidate:
    technique_id: str
    name: str | None
    tactics: list[str]
    confidence: str


@dataclass
class _TechniqueSummaryAccumulator:
    technique_id: str
    name: str | None = None
    tactics: set[str] = field(default_factory=set)
    finding_count: int = 0
    risk_score_total: float = 0.0
    highest_risk_score: float = 0.0
    confidence_counts: Counter[str] = field(default_factory=Counter)
    review_status_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)


@dataclass
class _TacticSummaryAccumulator:
    tactic: str
    technique_ids: set[str] = field(default_factory=set)
    finding_count: int = 0
    risk_score_total: float = 0.0


def build_project_attack_summary_payload(
    *,
    project_id: uuid.UUID,
    findings: Sequence[Finding],
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


def _latest_contexts_by_finding(
    attack_contexts: Sequence[FindingAttackContext],
) -> dict[uuid.UUID, FindingAttackContext]:
    latest: dict[uuid.UUID, FindingAttackContext] = {}
    for context in attack_contexts:
        current = latest.get(context.finding_id)
        if current is None or context.created_at > current.created_at:
            latest[context.finding_id] = context
    return latest


def _technique_candidates(context: FindingAttackContext) -> list[_TechniqueCandidate]:
    candidates: list[_TechniqueCandidate] = []
    seen_from_mappings: set[str] = set()
    for mapping in _records(context.mappings_json):
        technique = _record(mapping.get("technique"))
        technique_id = (
            _text(mapping.get("attack_object_id"))
            or _text(mapping.get("technique_id"))
            or _text(technique.get("attack_object_id"))
        )
        if technique_id is None:
            continue
        seen_from_mappings.add(technique_id)
        candidates.append(
            _TechniqueCandidate(
                technique_id=technique_id,
                name=(
                    _text(mapping.get("attack_object_name"))
                    or _text(mapping.get("technique_name"))
                    or _text(technique.get("name"))
                ),
                tactics=_strings(mapping.get("tactics")) or _strings(technique.get("tactics")),
                confidence=_confidence_label(mapping.get("confidence")),
            )
        )

    for technique_id in context.technique_ids_json:
        if technique_id not in seen_from_mappings:
            candidates.append(
                _TechniqueCandidate(
                    technique_id=technique_id,
                    name=None,
                    tactics=list(context.tactic_ids_json),
                    confidence="unknown",
                )
            )
    return candidates


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


def _context_confidence(candidates: Sequence[_TechniqueCandidate]) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
    labels = [_confidence_label(candidate.confidence) for candidate in candidates]
    return min(labels, key=lambda label: order[label]) if labels else "unknown"


def _confidence_label(value: object) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized if normalized in CONFIDENCE_BUCKETS else "unknown"
    if isinstance(value, int | float):
        if value >= 0.75:
            return "high"
        if value >= 0.4:
            return "medium"
        return "low"
    return "unknown"


def _review_status_label(value: str | None) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else ""
    return normalized if normalized in REVIEW_STATUS_BUCKETS else "unreviewed"


def _ordered_counts(counter: Counter[str], buckets: Sequence[str]) -> dict[str, int]:
    values = {bucket: counter.get(bucket, 0) for bucket in buckets}
    for key, value in sorted(counter.items()):
        if key not in values:
            values[key] = value
    return values


def _records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _record(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _text(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return None
