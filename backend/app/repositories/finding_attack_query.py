"""SQL-backed finding ATT&CK query helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session, col, select

from app.models import (
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
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


def list_project_attack_summary_inputs(
    session: Session,
    project_id: uuid.UUID,
) -> tuple[list[AttackSummaryFindingRow], list[AttackSummaryContextRow]]:
    """Return lightweight rows needed for the ATT&CK dashboard summary."""
    finding_columns: list[Any] = [Finding.id, Finding.risk_score]
    finding_rows = [
        AttackSummaryFindingRow(id=finding_id, risk_score=risk_score)
        for finding_id, risk_score in session.exec(
            select(*finding_columns).where(Finding.project_id == project_id)
        ).all()
    ]
    context_columns: list[Any] = [
        FindingAttackContext.finding_id,
        FindingAttackContext.mapped,
        FindingAttackContext.technique_ids_json,
        FindingAttackContext.tactic_ids_json,
        FindingAttackContext.mappings_json,
        FindingAttackContext.review_status,
        FindingAttackContext.source,
        FindingAttackContext.created_at,
    ]
    context_rows = [
        AttackSummaryContextRow(
            finding_id=finding_id,
            mapped=bool(mapped),
            technique_ids_json=list(technique_ids_json or []),
            tactic_ids_json=list(tactic_ids_json or []),
            mappings_json=list(mappings_json or []),
            review_status=str(review_status),
            source=source,
            created_at=created_at,
        )
        for (
            finding_id,
            mapped,
            technique_ids_json,
            tactic_ids_json,
            mappings_json,
            review_status,
            source,
            created_at,
        ) in session.exec(
            select(*context_columns)
            .join(Finding, col(FindingAttackContext.finding_id) == col(Finding.id))
            .where(Finding.project_id == project_id)
            .order_by(col(FindingAttackContext.created_at).desc())
        ).all()
    ]
    return finding_rows, context_rows
