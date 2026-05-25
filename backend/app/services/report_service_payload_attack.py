"""ATT&CK context projection for report payloads."""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

from sqlmodel import Session, col, select

from app.models import AnalysisRun, FindingAttackContext
from app.services.report_models import MarkdownReportFinding


def run_attack_contexts_by_finding(
    session: Session,
    run: AnalysisRun,
) -> dict[uuid.UUID, FindingAttackContext]:
    """Return the newest finding ATT&CK context for the run."""
    statement = (
        select(FindingAttackContext)
        .where(FindingAttackContext.analysis_run_id == run.id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    contexts: dict[uuid.UUID, FindingAttackContext] = {}
    for context in session.exec(statement).all():
        contexts.setdefault(context.finding_id, context)
    return contexts


def merge_attack_context(
    finding: MarkdownReportFinding,
    context: FindingAttackContext | None,
) -> MarkdownReportFinding:
    """Attach reviewed ATT&CK context details to the renderer payload."""
    if context is None:
        return finding
    attack_context = {
        "mapped": context.mapped,
        "source": context.source,
        "review_status": context.review_status,
        "defensive_note": context.defensive_note,
        "rationale": context.rationale,
        "technique_ids": list(context.technique_ids_json or []),
        "tactic_ids": list(context.tactic_ids_json or []),
        "mappings": list(context.mappings_json or []),
    }
    explanation: dict[str, Any] = {
        **finding.explanation,
        "attack_context": attack_context,
    }
    if context.technique_ids_json and not explanation.get("attack_techniques"):
        explanation["attack_techniques"] = list(context.technique_ids_json)
    return replace(
        finding, attack_mapped=context.mapped or finding.attack_mapped, explanation=explanation
    )


__all__ = ["merge_attack_context", "run_attack_contexts_by_finding"]
