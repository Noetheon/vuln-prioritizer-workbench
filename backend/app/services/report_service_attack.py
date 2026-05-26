"""ATT&CK Navigator helpers for Workbench reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.models import AnalysisRun, Finding, FindingAttackContext, Project
from app.services.attack import build_attack_navigator_layer_payload


def run_attack_contexts(
    session: Session,
    run: AnalysisRun,
) -> list[FindingAttackContext]:
    """Run attack contexts function."""
    statement = (
        select(FindingAttackContext)
        .where(FindingAttackContext.analysis_run_id == run.id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    return list(session.exec(statement).all())


def attack_navigator_layer(
    *,
    run: AnalysisRun,
    project: Project,
    findings: list[Finding],
    attack_contexts: list[FindingAttackContext],
    generated_at: datetime,
    filter_value: str,
    include_empty: bool,
) -> dict[str, Any] | None:
    """Attack navigator layer function."""
    layer = build_attack_navigator_layer_payload(
        project_id=project.id,
        project_name=project.name,
        run_id=run.id,
        findings=findings,
        attack_contexts=attack_contexts,
        filter_value=filter_value,
        generated_at=generated_at,
    )
    return layer if include_empty or layer.get("techniques") else None


__all__ = ["attack_navigator_layer", "run_attack_contexts"]
