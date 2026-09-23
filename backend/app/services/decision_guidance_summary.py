"""Summarize stored guidance without recreating policy in presentation code."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable
from itertools import islice

from pydantic import ValidationError
from sqlmodel import Session, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.domain.engine.models_decision import FindingDecisionGuidance, SlaTarget
from app.models.decision_summary import ExecutiveFindingDecisionPublic, RunDecisionSummaryPublic
from app.models.evidence import FindingDecisionEvidence
from app.repositories.evidence_payloads import EvidencePayloadStore

ACTIONABLE_STATUSES = frozenset({"open", "in_review", "remediating"})


def run_decision_summary(session: Session, run_id: uuid.UUID) -> RunDecisionSummaryPublic:
    """Read immutable run payloads in bounded batches for executive guidance."""
    rows = session.exec(
        select(FindingDecisionEvidence)
        .where(FindingDecisionEvidence.analysis_run_id == run_id)
        .execution_options(yield_per=100)
    )
    store = EvidencePayloadStore(session.connection())

    def contracts() -> Iterable[FindingDecisionEvidenceV2]:
        while batch := tuple(islice(rows, 100)):
            for payload in store.load_records(batch).values():
                yield FindingDecisionEvidenceV2.model_validate(payload)

    return summarize_decision_guidance(contracts())


def summarize_decision_guidance(
    evidence_items: Iterable[FindingDecisionEvidenceV2],
) -> RunDecisionSummaryPublic:
    """Keep bounded leading decisions while counting all recorded recommendations."""
    count = 0
    actionable_count = 0
    with_guidance = 0
    recommendations: Counter[str] = Counter()
    shortest_sla: SlaTarget | None = None
    leading: list[tuple[tuple[bool, int, str], ExecutiveFindingDecisionPublic]] = []
    for evidence in evidence_items:
        count += 1
        actionable = (
            evidence.status in ACTIONABLE_STATUSES
            and not evidence.suppressed_by_vex
            and not evidence.waived
        )
        actionable_count += int(actionable)
        try:
            guidance = FindingDecisionGuidance.model_validate(evidence.remediation.raw)
        except (ValidationError, TypeError, ValueError):
            continue
        with_guidance += 1
        recommendations[guidance.recommendation_label] += 1
        hours = guidance.sla.target_hours
        if (
            actionable
            and hours is not None
            and (
                shortest_sla is None
                or shortest_sla.target_hours is None
                or hours < shortest_sla.target_hours
            )
        ):
            shortest_sla = guidance.sla
        scope = evidence.occurrence_scope
        item = ExecutiveFindingDecisionPublic(
            finding_id=uuid.UUID(evidence.finding_id),
            cve_id=evidence.cve_id,
            component=scope.component_name if scope else None,
            target=(scope.target_ref or scope.asset_id) if scope else None,
            status=evidence.status,
            guidance=guidance,
        )
        leading.append(
            ((not actionable, evidence.operational_rank or 999_999, evidence.finding_id), item)
        )
        leading.sort(key=lambda row: row[0])
        del leading[3:]
    return RunDecisionSummaryPublic(
        finding_count=count,
        actionable_finding_count=actionable_count,
        findings_with_guidance=with_guidance,
        missing_guidance_count=count - with_guidance,
        recommendation_counts=dict(sorted(recommendations.items())),
        shortest_actionable_sla=shortest_sla,
        top_decisions=[item for _, item in leading],
    )
