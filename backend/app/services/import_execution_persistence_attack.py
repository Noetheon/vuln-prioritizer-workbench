"""ATT&CK context persistence helpers for Workbench imports."""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlmodel import Session

from app.domain.import_asset_context import string_evidence as _string_evidence
from app.models import FindingAttackContext
from app.services import WorkbenchAnalysisResult
from vuln_prioritizer.models import PrioritizedFinding


def _attack_context_enabled(
    analysis_result: WorkbenchAnalysisResult,
    decision: PrioritizedFinding,
) -> bool:
    return analysis_result.context.attack_source != "none" or decision.attack_context.mapped


def _persist_workbench_finding_attack_context(
    *,
    session: Session,
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    decision: PrioritizedFinding,
) -> None:
    context = decision.attack_context
    mappings = _attack_mapping_payloads(context.mappings, context.techniques)
    techniques = [technique.model_dump() for technique in context.techniques]
    technique_ids = _technique_ids_from_context(techniques, mappings, context.techniques)
    session.add(
        FindingAttackContext(
            finding_id=finding_id,
            analysis_run_id=run_id,
            cve_id=decision.cve_id,
            mapped=context.mapped,
            source=context.source or "none",
            review_status=_attack_context_review_status(
                getattr(context, "review_status", None),
                context.mapped,
                mappings,
            ),
            defensive_note=_attack_context_defensive_note(context.mapped),
            rationale=context.rationale,
            technique_ids_json=technique_ids,
            tactic_ids_json=_valid_attack_tactic_ids(context.tactics),
            mappings_json=mappings,
        )
    )


def _attack_mapping_payloads(mappings: list[Any], techniques: list[Any]) -> list[dict[str, Any]]:
    techniques_by_id = {
        technique.attack_object_id: technique.model_dump()
        for technique in techniques
        if getattr(technique, "attack_object_id", None)
    }
    payloads: list[dict[str, Any]] = []
    for mapping in mappings:
        payload = mapping.model_dump()
        technique = techniques_by_id.get(payload.get("attack_object_id"))
        if technique:
            payload["technique"] = technique
            payload["tactics"] = technique.get("tactics", [])
            payload["technique_url"] = technique.get("url")
        payloads.append(payload)
    return payloads


def _technique_ids_from_context(
    techniques: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    technique_models: list[Any],
) -> list[str]:
    ids: list[str] = []
    for technique in techniques:
        candidate = _string_evidence(technique, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for mapping in mappings:
        candidate = _string_evidence(mapping, "attack_object_id")
        if candidate and candidate not in ids:
            ids.append(candidate)
    for technique in technique_models:
        candidate = getattr(technique, "attack_object_id", None)
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    return ids


def _valid_attack_tactic_ids(values: list[str]) -> list[str]:
    return [value for value in values if re.fullmatch(r"TA\d{4}", value)]


def _attack_context_review_status(
    review_status: str | None,
    mapped: bool,
    mappings: list[dict[str, Any]],
) -> str:
    mapping_statuses = {
        status
        for mapping in mappings
        if isinstance(status := mapping.get("review_status"), str)
        and status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}
    }
    for status in ("needs_review", "stale", "rejected", "unreviewed"):
        if status in mapping_statuses:
            return status
    if review_status in {"unreviewed", "needs_review", "reviewed", "rejected", "stale"}:
        return review_status
    return "reviewed" if mapped else "unreviewed"


def _attack_context_defensive_note(mapped: bool) -> str:
    if mapped:
        return (
            "Use this ATT&CK context only for defensive triage, detection coverage, "
            "and mitigation review."
        )
    return "No reviewed ATT&CK mapping is stored for this finding."
