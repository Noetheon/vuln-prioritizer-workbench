"""ATT&CK Navigator layer payload helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.models import FindingAttackContext
from app.services.attack_support import (
    AttackNavigatorFindingLike,
    NavigatorTechniqueAccumulator,
    confidence_label,
    counts_label,
    finding_matches_navigator_filter,
    finding_priority_label,
    format_score,
    latest_contexts_by_finding,
    metadata_value,
    navigator_filter_label,
    review_status_label,
    technique_candidates,
)


def build_attack_navigator_layer_payload(
    *,
    project_id: uuid.UUID,
    project_name: str,
    run_id: uuid.UUID,
    findings: Sequence[AttackNavigatorFindingLike],
    attack_contexts: Sequence[FindingAttackContext],
    filter_value: str = "all",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a defensive MITRE ATT&CK Navigator layer from persisted mappings."""
    normalized_filter = navigator_filter_label(filter_value)
    latest_contexts = latest_contexts_by_finding(attack_contexts)
    technique_rows: dict[str, NavigatorTechniqueAccumulator] = {}
    filter_finding_count = 0
    mapped_finding_ids: set[uuid.UUID] = set()

    for finding in findings:
        if not finding_matches_navigator_filter(finding, normalized_filter):
            continue
        filter_finding_count += 1
        context = latest_contexts.get(finding.id)
        if context is None or not context.mapped:
            continue
        candidates = technique_candidates(context)
        if not candidates:
            continue

        mapped_finding_ids.add(finding.id)
        seen_techniques: set[str] = set()
        risk_score = float(finding.risk_score or 0.0)
        priority = finding_priority_label(finding)
        review_status = review_status_label(context.review_status)
        source = context.source or "none"
        for candidate in candidates:
            if candidate.technique_id in seen_techniques:
                continue
            seen_techniques.add(candidate.technique_id)
            row = technique_rows.setdefault(
                candidate.technique_id,
                NavigatorTechniqueAccumulator(candidate.technique_id),
            )
            row.name = row.name or candidate.name
            row.tactics.update(candidate.tactics)
            row.finding_ids.add(finding.id)
            row.cves.add(finding.cve_id)
            if finding.in_kev:
                row.kev_cves.add(finding.cve_id)
            row.risk_score_total += risk_score
            row.highest_risk_score = max(row.highest_risk_score, risk_score)
            row.confidence_counts[confidence_label(candidate.confidence)] += 1
            row.review_status_counts[review_status] += 1
            row.source_counts[source] += 1
            row.priority_counts[priority] += 1

    techniques = [_navigator_technique_payload(row) for row in technique_rows.values()]
    techniques.sort(
        key=lambda item: (
            -float(item["score"]),
            -int(metadata_value(item, "Finding count")),
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
        {"name": "Coverage model", "value": "not assessed by Workbench export"},
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


def _navigator_technique_payload(row: NavigatorTechniqueAccumulator) -> dict[str, Any]:
    finding_count = len(row.finding_ids)
    score = round(row.highest_risk_score if row.highest_risk_score else float(finding_count), 2)
    confidence = counts_label(row.confidence_counts)
    review_status = counts_label(row.review_status_counts)
    priorities = counts_label(row.priority_counts)
    sources = counts_label(row.source_counts)
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
        {"name": "Risk score total", "value": format_score(row.risk_score_total)},
        {"name": "Highest risk score", "value": format_score(row.highest_risk_score)},
    ]
    if row.tactics:
        metadata.append({"name": "Tactics", "value": ", ".join(sorted(row.tactics))})
    return {
        "techniqueID": row.technique_id,
        "score": score,
        "comment": (
            f"Findings: {', '.join(sorted(row.cves))}. "
            f"KEV: {len(row.kev_cves)} finding(s). "
            "Coverage: not assessed by this Workbench export. "
            f"Confidence: {confidence}. Review: {review_status}."
        ),
        "metadata": metadata,
        "enabled": True,
    }
