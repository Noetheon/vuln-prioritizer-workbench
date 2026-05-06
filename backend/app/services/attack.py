"""ATT&CK dashboard summary helpers for the Workbench."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models import (
    Finding,
    FindingAttackContext,
    ProjectAttackSummaryPublic,
    ProjectAttackTacticSummaryPublic,
    ProjectAttackTechniqueSummaryPublic,
)

CONFIDENCE_BUCKETS = ("high", "medium", "low", "unknown")
REVIEW_STATUS_BUCKETS = ("reviewed", "needs_review", "unreviewed", "stale", "rejected")
ATTACK_NAVIGATOR_FILTERS = ("all", "critical-high", "kev", "no-coverage")


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


@dataclass
class _NavigatorTechniqueAccumulator:
    technique_id: str
    name: str | None = None
    tactics: set[str] = field(default_factory=set)
    finding_ids: set[uuid.UUID] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    kev_cves: set[str] = field(default_factory=set)
    risk_score_total: float = 0.0
    highest_risk_score: float = 0.0
    confidence_counts: Counter[str] = field(default_factory=Counter)
    review_status_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)
    priority_counts: Counter[str] = field(default_factory=Counter)


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


def build_attack_navigator_layer_payload(
    *,
    project_id: uuid.UUID,
    project_name: str,
    run_id: uuid.UUID,
    findings: Sequence[Finding],
    attack_contexts: Sequence[FindingAttackContext],
    filter_value: str = "all",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a defensive MITRE ATT&CK Navigator layer from persisted mappings."""
    normalized_filter = _navigator_filter_label(filter_value)
    latest_contexts = _latest_contexts_by_finding(attack_contexts)
    technique_rows: dict[str, _NavigatorTechniqueAccumulator] = {}
    filter_finding_count = 0
    mapped_finding_ids: set[uuid.UUID] = set()

    for finding in findings:
        if not _finding_matches_navigator_filter(finding, normalized_filter):
            continue
        filter_finding_count += 1
        context = latest_contexts.get(finding.id)
        if context is None or not context.mapped:
            continue
        candidates = _technique_candidates(context)
        if not candidates:
            continue

        mapped_finding_ids.add(finding.id)
        seen_techniques: set[str] = set()
        risk_score = float(finding.risk_score or 0.0)
        priority = _finding_priority_label(finding)
        review_status = _review_status_label(context.review_status)
        source = context.source or "none"
        for candidate in candidates:
            if candidate.technique_id in seen_techniques:
                continue
            seen_techniques.add(candidate.technique_id)
            row = technique_rows.setdefault(
                candidate.technique_id,
                _NavigatorTechniqueAccumulator(candidate.technique_id),
            )
            row.name = row.name or candidate.name
            row.tactics.update(candidate.tactics)
            row.finding_ids.add(finding.id)
            row.cves.add(finding.cve_id)
            if finding.in_kev:
                row.kev_cves.add(finding.cve_id)
            row.risk_score_total += risk_score
            row.highest_risk_score = max(row.highest_risk_score, risk_score)
            row.confidence_counts[_confidence_label(candidate.confidence)] += 1
            row.review_status_counts[review_status] += 1
            row.source_counts[source] += 1
            row.priority_counts[priority] += 1

    techniques = [_navigator_technique_payload(row) for row in technique_rows.values()]
    techniques.sort(
        key=lambda item: (
            -float(item["score"]),
            -int(_metadata_value(item, "Finding count")),
            str(item["techniqueID"]),
        )
    )
    max_score = max((float(item["score"]) for item in techniques), default=1.0)
    unmapped_count = max(filter_finding_count - len(mapped_finding_ids), 0)
    metadata = [
        {"name": "Project", "value": project_name},
        {"name": "Project ID", "value": str(project_id)},
        {"name": "Analysis run", "value": str(run_id)},
        {"name": "Filter", "value": normalized_filter},
        {"name": "Findings considered", "value": str(filter_finding_count)},
        {"name": "Mapped findings included", "value": str(len(mapped_finding_ids))},
        {"name": "Unmapped findings omitted", "value": str(unmapped_count)},
        {"name": "Coverage model", "value": "not assessed placeholder"},
    ]
    if generated_at is not None:
        metadata.append({"name": "Generated at", "value": generated_at.isoformat()})

    return {
        "name": f"{project_name} ATT&CK Navigator ({normalized_filter})",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": (
            "Defensive Navigator layer generated from persisted Workbench ATT&CK "
            f"context for analysis run {run_id}. Filter: {normalized_filter}. "
            "Unmapped findings are omitted rather than inferred."
        ),
        "gradient": {
            "colors": ["#dfe7fd", "#ffd166", "#c1121f"],
            "minValue": 0,
            "maxValue": round(max_score, 2),
        },
        "techniques": techniques,
        "metadata": metadata,
        "legendItems": [
            {"label": "Mapped technique", "color": "#ffd166"},
            {"label": "Highest risk technique", "color": "#c1121f"},
        ],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }


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


def _navigator_technique_payload(row: _NavigatorTechniqueAccumulator) -> dict[str, Any]:
    finding_count = len(row.finding_ids)
    score = round(row.highest_risk_score if row.highest_risk_score else float(finding_count), 2)
    confidence = _counts_label(row.confidence_counts)
    review_status = _counts_label(row.review_status_counts)
    priorities = _counts_label(row.priority_counts)
    sources = _counts_label(row.source_counts)
    kev_label = ", ".join(sorted(row.kev_cves)) if row.kev_cves else "none"
    metadata = [
        {"name": "Technique name", "value": row.name or row.technique_id},
        {"name": "Findings", "value": ", ".join(sorted(row.cves))},
        {"name": "Finding count", "value": str(finding_count)},
        {"name": "KEV findings", "value": kev_label},
        {"name": "Priorities", "value": priorities},
        {"name": "Confidence", "value": confidence},
        {"name": "Review status", "value": review_status},
        {"name": "Source", "value": sources},
        {"name": "Coverage", "value": "not assessed"},
        {"name": "Risk score total", "value": _format_score(row.risk_score_total)},
        {"name": "Highest risk score", "value": _format_score(row.highest_risk_score)},
    ]
    if row.tactics:
        metadata.append({"name": "Tactics", "value": ", ".join(sorted(row.tactics))})
    return {
        "techniqueID": row.technique_id,
        "score": score,
        "comment": (
            f"Findings: {', '.join(sorted(row.cves))}. "
            f"KEV: {len(row.kev_cves)} finding(s). "
            "Coverage: not assessed; placeholder until detection coverage is configured. "
            f"Confidence: {confidence}. Review: {review_status}."
        ),
        "metadata": metadata,
        "enabled": True,
    }


def _metadata_value(item: dict[str, Any], key: str) -> str:
    metadata = item.get("metadata")
    if not isinstance(metadata, list):
        return "0"
    for entry in metadata:
        if isinstance(entry, dict) and entry.get("name") == key:
            value = entry.get("value")
            return str(value) if value is not None else "0"
    return "0"


def _counts_label(counter: Counter[str]) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{key}:{value}" for key, value in sorted(counter.items()))


def _format_score(value: float) -> str:
    rounded = round(value, 2)
    return str(int(rounded)) if rounded.is_integer() else str(rounded)


def _navigator_filter_label(value: str) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else "all"
    return normalized if normalized in ATTACK_NAVIGATOR_FILTERS else "all"


def _finding_matches_navigator_filter(finding: Finding, filter_value: str) -> bool:
    if filter_value == "critical-high":
        return _finding_priority_label(finding) in {"critical", "high"}
    if filter_value == "kev":
        return finding.in_kev
    return True


def _finding_priority_label(finding: Finding) -> str:
    value = getattr(finding.priority, "value", finding.priority)
    return str(value).strip().lower()


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
