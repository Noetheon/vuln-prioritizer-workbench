"""Shared support helpers for Workbench ATT&CK summary payloads."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.models import Finding, FindingAttackContext

CONFIDENCE_BUCKETS = ("high", "medium", "low", "unknown")
REVIEW_STATUS_BUCKETS = ("reviewed", "needs_review", "unreviewed", "stale", "rejected")
ATTACK_NAVIGATOR_FILTERS = ("all", "critical-high", "kev", "no-coverage")


@dataclass
class TechniqueCandidate:
    """Normalized candidate ATT&CK technique extracted from a finding context."""

    technique_id: str
    name: str | None
    tactics: list[str]
    confidence: str


@dataclass
class TechniqueSummaryAccumulator:
    """Mutable accumulator for project-level ATT&CK technique summaries."""

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
class TacticSummaryAccumulator:
    """Mutable accumulator for project-level ATT&CK tactic summaries."""

    tactic: str
    technique_ids: set[str] = field(default_factory=set)
    finding_count: int = 0
    risk_score_total: float = 0.0


@dataclass
class NavigatorTechniqueAccumulator:
    """Mutable accumulator for Navigator layer technique rows."""

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


def metadata_value(item: dict[str, Any], key: str) -> str:
    """Return a Navigator metadata value as text."""
    metadata = item.get("metadata")
    if not isinstance(metadata, list):
        return "0"
    for entry in metadata:
        if isinstance(entry, dict) and entry.get("name") == key:
            value = entry.get("value")
            return str(value) if value is not None else "0"
    return "0"


def counts_label(counter: Counter[str]) -> str:
    """Format a counter as a compact deterministic label."""
    if not counter:
        return "none"
    return ", ".join(f"{key}:{value}" for key, value in sorted(counter.items()))


def format_score(value: float) -> str:
    """Format risk scores without unnecessary decimal zeros."""
    rounded = round(value, 2)
    return str(int(rounded)) if rounded.is_integer() else str(rounded)


def navigator_filter_label(value: str) -> str:
    """Normalize a Navigator filter value to the supported filter set."""
    normalized = value.strip().lower() if isinstance(value, str) else "all"
    return normalized if normalized in ATTACK_NAVIGATOR_FILTERS else "all"


def finding_matches_navigator_filter(finding: Finding, filter_value: str) -> bool:
    """Return whether a finding belongs in the requested Navigator filter."""
    if filter_value == "critical-high":
        return finding_priority_label(finding) in {"critical", "high"}
    if filter_value == "kev":
        return finding.in_kev
    return True


def finding_priority_label(finding: Finding) -> str:
    """Return the normalized priority label for a finding."""
    value = getattr(finding.priority, "value", finding.priority)
    return str(value).strip().lower()


def context_confidence(candidates: list[TechniqueCandidate]) -> str:
    """Return the weakest mapped confidence label for one finding context."""
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
    labels = [confidence_label(candidate.confidence) for candidate in candidates]
    return min(labels, key=lambda label: order[label]) if labels else "unknown"


def latest_contexts_by_finding(
    attack_contexts: Sequence[FindingAttackContext],
) -> dict[uuid.UUID, FindingAttackContext]:
    """Return the newest ATT&CK context per finding."""
    latest: dict[uuid.UUID, FindingAttackContext] = {}
    for context in attack_contexts:
        current = latest.get(context.finding_id)
        if current is None or context.created_at > current.created_at:
            latest[context.finding_id] = context
    return latest


def technique_candidates(context: FindingAttackContext) -> list[TechniqueCandidate]:
    """Return normalized technique candidates for one finding context."""
    candidates: list[TechniqueCandidate] = []
    seen_from_mappings: set[str] = set()
    for mapping in records(context.mappings_json):
        technique = record(mapping.get("technique"))
        technique_id = (
            text(mapping.get("attack_object_id"))
            or text(mapping.get("technique_id"))
            or text(technique.get("attack_object_id"))
        )
        if technique_id is None:
            continue
        seen_from_mappings.add(technique_id)
        candidates.append(
            TechniqueCandidate(
                technique_id=technique_id,
                name=(
                    text(mapping.get("attack_object_name"))
                    or text(mapping.get("technique_name"))
                    or text(technique.get("name"))
                ),
                tactics=strings(mapping.get("tactics")) or strings(technique.get("tactics")),
                confidence=confidence_label(mapping.get("confidence")),
            )
        )

    for technique_id in context.technique_ids_json:
        if technique_id not in seen_from_mappings:
            candidates.append(
                TechniqueCandidate(
                    technique_id=technique_id,
                    name=None,
                    tactics=list(context.tactic_ids_json),
                    confidence="unknown",
                )
            )
    return candidates


def confidence_label(value: object) -> str:
    """Normalize confidence values from mapping payloads."""
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


def review_status_label(value: str | None) -> str:
    """Normalize mapping review status labels."""
    normalized = value.strip().lower() if isinstance(value, str) else ""
    return normalized if normalized in REVIEW_STATUS_BUCKETS else "unreviewed"


def ordered_counts(counter: Counter[str], buckets: tuple[str, ...]) -> dict[str, int]:
    """Return bucketed counts while preserving unexpected labels at the end."""
    values = {bucket: counter.get(bucket, 0) for bucket in buckets}
    for key, value in sorted(counter.items()):
        if key not in values:
            values[key] = value
    return values


def records(value: object) -> list[dict[str, object]]:
    """Return dictionary records from an untrusted JSON-like list value."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def record(value: object) -> dict[str, object]:
    """Return a dictionary record or an empty fallback."""
    return value if isinstance(value, dict) else {}


def strings(value: object) -> list[str]:
    """Return non-empty strings from an untrusted JSON-like list value."""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def text(value: object) -> str | None:
    """Return a non-empty stripped string or None."""
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return None
