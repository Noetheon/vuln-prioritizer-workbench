"""Workbench ATT&CK validation and persistence helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vuln_prioritizer.attack_sources import (
    ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER,
    ATTACK_SOURCE_NONE,
    WORKBENCH_ALLOWED_MAPPING_SOURCES,
    WORKBENCH_ATTACK_SOURCE_CTID,
    WORKBENCH_ATTACK_SOURCE_LOCAL_CURATED,
    WORKBENCH_ATTACK_SOURCE_MANUAL,
    WORKBENCH_DISALLOWED_MAPPING_SOURCE_PREFIXES,
    WORKBENCH_DISALLOWED_MAPPING_SOURCES,
)
from vuln_prioritizer.models import AttackData, AttackMapping, AttackTechnique


class WorkbenchAttackValidationError(ValueError):
    """Raised when Workbench ATT&CK inputs violate source guardrails."""


def validate_workbench_attack_source(source: str) -> None:
    normalized = source.strip().lower()
    if normalized in WORKBENCH_DISALLOWED_MAPPING_SOURCES or normalized.startswith(
        WORKBENCH_DISALLOWED_MAPPING_SOURCE_PREFIXES
    ):
        raise WorkbenchAttackValidationError(
            "Heuristic or LLM-generated CVE-to-ATT&CK mappings are not accepted."
        )
    if normalized not in WORKBENCH_ALLOWED_MAPPING_SOURCES:
        raise WorkbenchAttackValidationError(
            f"Unsupported Workbench ATT&CK mapping source: {source}."
        )


def workbench_mapping_source(analysis_attack_source: str) -> str:
    if analysis_attack_source == ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER:
        return WORKBENCH_ATTACK_SOURCE_CTID
    if analysis_attack_source in {
        WORKBENCH_ATTACK_SOURCE_LOCAL_CURATED,
        WORKBENCH_ATTACK_SOURCE_MANUAL,
    }:
        return analysis_attack_source
    if analysis_attack_source == ATTACK_SOURCE_NONE:
        return ATTACK_SOURCE_NONE
    raise WorkbenchAttackValidationError(
        f"Unsupported Workbench ATT&CK mapping source: {analysis_attack_source}."
    )


def validate_attack_artifact_path(path: Path, *, label: str) -> None:
    if path.suffix.lower() != ".json":
        raise WorkbenchAttackValidationError(f"{label} must be a JSON file.")


def threat_context_rank(attack: AttackData) -> int:
    rank_by_relevance = {"High": 1, "Medium": 2, "Low": 3, "Unmapped": 99}
    return rank_by_relevance.get(attack.attack_relevance, 99)


def review_status_for_source(source: str, *, mapped: bool) -> str:
    if not mapped:
        return "not_applicable"
    if source == WORKBENCH_ATTACK_SOURCE_CTID:
        return "source_reviewed"
    return "needs_review"


def confidence_for_source(source: str) -> float | None:
    if source == WORKBENCH_ATTACK_SOURCE_CTID:
        return 1.0
    if source == WORKBENCH_ATTACK_SOURCE_MANUAL:
        return 0.8
    if source == WORKBENCH_ATTACK_SOURCE_LOCAL_CURATED:
        return 0.7
    return None


def mapping_rationale(mapping: AttackMapping, attack: AttackData) -> str:
    if mapping.comments:
        return mapping.comments
    if mapping.capability_description:
        return mapping.capability_description
    if attack.attack_rationale:
        return attack.attack_rationale
    return "ATT&CK mapping imported from an approved local source."


def attack_mapping_payload(mapping: AttackMapping) -> dict[str, Any]:
    return mapping.model_dump()


def attack_technique_payload(technique: AttackTechnique) -> dict[str, Any]:
    return technique.model_dump()


def top_technique_rows(contexts: list[Any], *, limit: int = 10) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for context in contexts:
        for technique in context.techniques_json or []:
            technique_id = str(technique.get("attack_object_id") or "").strip()
            if not technique_id:
                continue
            row = counts.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": technique.get("name") or technique_id,
                    "tactics": technique.get("tactics") or [],
                    "url": technique.get("url"),
                    "count": 0,
                    "cves": set(),
                },
            )
            row["count"] += 1
            row["cves"].add(context.cve_id)

    rows = sorted(
        counts.values(),
        key=lambda item: (-int(item["count"]), item["technique_id"]),
    )[:limit]
    for row in rows:
        row["cves"] = sorted(row["cves"])
    return rows


def navigator_layer_from_contexts(
    contexts: list[Any],
    *,
    layer_name: str = "vuln-prioritizer Workbench ATT&CK coverage",
) -> dict[str, Any]:
    technique_rows = top_technique_rows(contexts, limit=10_000)
    max_score = max((int(row["count"]) for row in technique_rows), default=1)
    return {
        "name": layer_name,
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": (
            "Navigator layer generated from approved Workbench ATT&CK mappings. "
            "It is context only and does not change base priority."
        ),
        "gradient": {
            "colors": ["#dfe7fd", "#4c6ef5"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "techniques": [
            {
                "techniqueID": row["technique_id"],
                "score": row["count"],
                "comment": "Observed for " + ", ".join(row["cves"]) + ".",
            }
            for row in technique_rows
        ],
        "legendItems": [{"label": "Mapped technique", "color": "#4c6ef5"}],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }
