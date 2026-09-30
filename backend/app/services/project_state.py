"""Record a project's current decision state so reports can describe it."""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from dataclasses import dataclass

from sqlmodel import Session, select

from app.decision_core.contracts import (
    AnalysisEvidenceV2,
    AnalysisSemanticsV2,
    AnalysisServiceEvidenceV2,
    EvaluationMetadataV1,
    ProviderEvidenceV2,
    RunCountsV2,
)
from app.decision_core.evaluation import EVALUATION_ENGINE_VERSION
from app.decision_core.identity import FINDING_SCOPE_KEY_VERSION
from app.models import (
    PROJECT_STATE_INPUT_TYPE,
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunStatus,
    FindingCurrentProjection,
    Project,
)
from app.models.base import get_datetime_utc
from app.repositories.evidence import EvidenceRepository
from app.repositories.runs import RunRepository
from app.services.risk_reduction import project_risk_index_from_projection

PROJECT_STATE_CAUSE = "project_state_report"
_UNRANKED = 999_999


class ProjectStateError(ValueError):
    """The project state cannot be recorded or no longer matches a recording."""


@dataclass(frozen=True)
class ProjectState:
    """The findings of a project in report order, and a fingerprint of their decisions."""

    fingerprint: str
    finding_ids: list[uuid.UUID]
    records: list[FindingCurrentProjection]


def current_project_state(session: Session, project_id: uuid.UUID) -> ProjectState:
    """
    Read the current decision of every finding in the project.

    The fingerprint changes whenever any finding's decision, status, or rank
    changes, and when findings are added or removed.
    """
    records = list(
        session.exec(
            select(FindingCurrentProjection).where(
                FindingCurrentProjection.project_id == project_id
            )
        ).all()
    )
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: str(item.finding_id)):
        digest.update(
            (
                f"{record.finding_id}|{record.revision}|{record.projection_payload_sha256}|"
                f"{record.status}|{record.operational_rank}\n"
            ).encode()
        )
    ordered = sorted(
        records,
        key=lambda item: (
            item.operational_rank or _UNRANKED,
            item.priority_rank,
            item.cve_id,
            str(item.finding_id),
        ),
    )
    return ProjectState(
        fingerprint=digest.hexdigest(),
        finding_ids=[record.finding_id for record in ordered],
        records=ordered,
    )


def record_project_state(session: Session, project: Project) -> AnalysisRun:
    """
    Record the project's current state as a completed `project_state` run.

    The run carries a run-wide evidence envelope with counts and the state
    fingerprint, but no per-finding evidence: reports read the current
    decisions and refuse to render when the fingerprint no longer matches.
    The caller commits.
    """
    state = current_project_state(session, project.id)
    if not state.records:
        raise ProjectStateError("This project has no findings to report on yet.")
    now = get_datetime_utc()
    records = state.records
    run = RunRepository(session).create_analysis_run(
        project_id=project.id,
        input_type=PROJECT_STATE_INPUT_TYPE,
        status=AnalysisRunStatus.COMPLETED,
    )
    run.started_at = now
    run.finished_at = now
    cve_count = len({record.cve_id for record in records})
    evidence = AnalysisEvidenceV2(
        analysis_run_id=str(run.id),
        project_id=str(project.id),
        input_type=PROJECT_STATE_INPUT_TYPE,
        status=AnalysisRunStatus.COMPLETED.value,
        counts=RunCountsV2(
            finding_count=len(records),
            counts_by_priority=dict(Counter(record.priority for record in records)),
            kev_hits=sum(record.in_kev for record in records),
            epss_hits=sum(record.epss is not None for record in records),
            nvd_hits=sum(record.cvss_base_score is not None for record in records),
            suppressed_by_vex=sum(record.suppressed_by_vex for record in records),
            under_investigation_count=sum(record.under_investigation for record in records),
            attack_mapped_cves=len({record.cve_id for record in records if record.attack_mapped}),
        ),
        provider=ProviderEvidenceV2(),
        analysis_service=AnalysisServiceEvidenceV2(
            pipeline="project_state_snapshot",
            engine=EVALUATION_ENGINE_VERSION,
            kernel="decision-core.v2",
        ),
        analysis_semantics=AnalysisSemanticsV2(
            analysis_decision_scope="finding_scope_first",
            persistence_scope="project_state_snapshot",
            finding_dedup_key_version=FINDING_SCOPE_KEY_VERSION,
            cve_count=cve_count,
            finding_count=len(records),
        ),
        evaluation=EvaluationMetadataV1(
            cause=PROJECT_STATE_CAUSE,
            evaluated_at=now.isoformat(),
            engine_version=EVALUATION_ENGINE_VERSION,
            input_sha256=state.fingerprint,
            replay_status="legacy_unavailable",
        ),
    )
    EvidenceRepository(session).upsert_analysis_evidence(
        project_id=project.id,
        analysis_run_id=run.id,
        provider_snapshot_id=None,
        evidence=evidence,
    )
    run.risk_index = project_risk_index_from_projection(session, project.id)
    session.add(run)
    session.flush()
    return run


def is_project_state_run(run: AnalysisRun) -> bool:
    """Tell recorded project states apart from imports and re-evaluations."""
    return run.input_type == PROJECT_STATE_INPUT_TYPE


def recorded_state_fingerprint(run: AnalysisRunPublic) -> str | None:
    """Return the state fingerprint a recorded project state was taken with."""
    evidence = run.evidence
    if evidence is None or evidence.evaluation is None:
        return None
    return evidence.evaluation.input_sha256
