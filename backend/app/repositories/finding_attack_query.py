"""SQL-backed finding ATT&CK query helpers."""

from __future__ import annotations

import uuid

from sqlmodel import Session, col, select

from app.models import (
    AttackSummaryContextRow,
    Finding,
    FindingAttackContext,
)


def list_project_attack_contexts(
    session: Session,
    project_id: uuid.UUID,
) -> list[FindingAttackContext]:
    """Return ATT&CK contexts for findings in one project, newest rows first."""
    statement = (
        select(FindingAttackContext)
        .join(Finding, col(FindingAttackContext.finding_id) == col(Finding.id))
        .where(Finding.project_id == project_id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    return list(session.exec(statement).all())


def list_project_attack_summary_contexts(
    session: Session,
    project_id: uuid.UUID,
) -> list[AttackSummaryContextRow]:
    """Return lightweight ATT&CK context rows needed for dashboard summaries."""
    statement = (
        select(FindingAttackContext)
        .join(Finding, col(FindingAttackContext.finding_id) == col(Finding.id))
        .where(Finding.project_id == project_id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    context_rows = [
        AttackSummaryContextRow(
            finding_id=context.finding_id,
            mapped=bool(context.mapped),
            technique_ids_json=list(context.technique_ids_json or []),
            tactic_ids_json=list(context.tactic_ids_json or []),
            mappings_json=list(context.mappings_json or []),
            review_status=str(context.review_status),
            source=context.source,
            created_at=context.created_at,
        )
        for context in session.exec(statement).all()
    ]
    return context_rows
