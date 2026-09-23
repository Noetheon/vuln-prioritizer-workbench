"""Compact queue ordering and rank presentation, independent of decision history."""

from __future__ import annotations

import re
from typing import Any

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.projection_evaluation import (
    _projection_scope_sort_key,
    _stored_projection_decision,
)
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key

_RANK_PREFIX = re.compile(r"^Top finding #\d+: ")


def decision_sort_key(evidence: FindingDecisionEvidenceV2) -> list[Any] | None:
    """Materialize the canonical key only for complete, evaluated current inputs."""
    if evidence.evaluation_input is None or any(
        flag.code == "asset_context_rescore_needed"
        for flag in evidence.priority_evidence.data_quality_flags
    ):
        return None
    return _json_key(
        global_operational_sort_key(
            _stored_projection_decision(evidence), _projection_scope_sort_key(evidence)
        )
    )


def _json_key(values: tuple[Any, ...]) -> list[Any]:
    return [_json_key(value) if isinstance(value, tuple) else value for value in values]


def with_current_rank(payload: dict[str, Any], rank: int) -> dict[str, Any]:
    """
    Return a path-copied view with current rank wording; never change its source.

    Ranking affects only the number and the optional top-five prefix. In particular
    it must not regenerate recommendations from a newer engine or provider state.
    The same transform removes current rank differences before storing an overlay.
    """
    if payload.get("operational_rank") == rank:
        return dict(payload)
    result = {**payload, "operational_rank": rank}
    priority = dict(payload.get("priority_evidence") or {})
    raw = dict(priority.get("raw") or {})
    if "operational_rank" in raw:
        raw["operational_rank"] = rank
    if isinstance(raw.get("decision_guidance"), dict):
        raw["decision_guidance"] = _ranked_guidance(raw["decision_guidance"], rank)
    priority["raw"] = raw
    result["priority_evidence"] = priority
    remediation = _ranked_guidance(dict(payload.get("remediation") or {}), rank)
    if isinstance(remediation.get("raw"), dict):
        remediation["raw"] = _ranked_guidance(remediation["raw"], rank)
    result["remediation"] = remediation
    return result


def _ranked_guidance(guidance: dict[str, Any], rank: int) -> dict[str, Any]:
    result = dict(guidance)
    statement = result.get("decision_statement")
    if isinstance(statement, str) and statement:
        prefix = f"Top finding #{rank}: " if 0 < rank <= 5 else ""
        result["decision_statement"] = prefix + _RANK_PREFIX.sub("", statement)
    return result
