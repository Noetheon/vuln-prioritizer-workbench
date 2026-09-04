"""ATT&CK Navigator helpers for Workbench reports."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.decision_core.readmodels import DecisionFindingView
from app.models import AnalysisRun, FindingAttackContext, Project
from app.services.attack import build_attack_navigator_layer_payload


def run_attack_contexts(
    session: Session,
    run: AnalysisRun,
    *,
    findings: Sequence[DecisionFindingView] | None = None,
) -> list[FindingAttackContext]:
    """Return typed run evidence contexts, with relational data only as legacy fallback."""
    typed_contexts: list[FindingAttackContext] = []
    legacy_finding_ids: set[uuid.UUID] | None = None
    if findings is not None:
        evaluated_at = run.finished_at or run.started_at
        typed_contexts = [
            _attack_context_from_evidence(finding, evaluated_at=evaluated_at)
            for finding in findings
            if finding.evidence is not None
        ]
        legacy_finding_ids = {finding.id for finding in findings if finding.evidence is None}
        if not legacy_finding_ids:
            return typed_contexts
    statement = (
        select(FindingAttackContext)
        .where(FindingAttackContext.analysis_run_id == run.id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    relational_contexts = list(session.exec(statement).all())
    if legacy_finding_ids is None:
        return relational_contexts
    return typed_contexts + [
        context for context in relational_contexts if context.finding_id in legacy_finding_ids
    ]


def _attack_context_from_evidence(
    finding: DecisionFindingView,
    *,
    evaluated_at: datetime,
) -> FindingAttackContext:
    evidence = finding.evidence
    if evidence is None:  # pragma: no cover - guarded by the caller
        raise ValueError("Finding decision evidence is required for typed ATT&CK projection.")
    attack = evidence.attack
    return FindingAttackContext.model_construct(
        id=uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"vpw-report-attack:{evidence.analysis_run_id}:{evidence.finding_id}",
        ),
        finding_id=uuid.UUID(evidence.finding_id),
        analysis_run_id=uuid.UUID(evidence.analysis_run_id),
        cve_id=evidence.cve_id,
        mapped=attack.mapped,
        source=attack.source,
        review_status=attack.review_status,
        defensive_note=attack.defensive_note or "",
        rationale=attack.rationale,
        technique_ids_json=list(attack.technique_ids),
        tactic_ids_json=list(attack.tactic_ids),
        mappings_json=list(attack.mappings),
        created_at=evaluated_at,
        updated_at=evaluated_at,
    )


def attack_navigator_layer(
    *,
    run: AnalysisRun,
    project: Project,
    findings: Sequence[DecisionFindingView],
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
