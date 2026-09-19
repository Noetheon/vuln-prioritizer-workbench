"""Append evaluated decisions to the existing Ledger in the caller's transaction."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

from sqlmodel import Session

from app.decision_core.contracts import (
    AnalysisEvidenceV2,
    AnalysisSemanticsV2,
    AnalysisServiceEvidenceV2,
    EvaluationMetadataV1,
    FindingDecisionEvidenceV2,
    ProviderEvidenceV2,
    RunCountsV2,
)
from app.decision_core.evaluation import EVALUATION_ENGINE_VERSION
from app.decision_core.identity import FINDING_SCOPE_KEY_VERSION
from app.decision_core.ledger import DecisionLedgerInvariantError, canonical_payload_sha256
from app.models import AnalysisRun, AnalysisRunStatus, Finding, FindingStatus
from app.models.base import get_datetime_utc
from app.repositories.evidence import EvidenceRepository
from app.repositories.runs import RunRepository
from app.services.risk_reduction import project_risk_index_from_projection


def publish_evaluation_run(
    session: Session,
    *,
    project_id: uuid.UUID,
    payloads: dict[uuid.UUID, dict[str, Any]],
    cause: str,
    run: AnalysisRun | None = None,
    base_project_revision: int | None = None,
) -> AnalysisRun:
    """
    Publish already ranked decisions; the caller owns fencing and commit.

    No occurrences, observation timestamps, finding identities or old evidence are
    rewritten. This is shared by queued and immediate context/waiver evaluations.
    """
    if not payloads:
        raise ValueError("An evaluation must contain at least one decision.")
    if run is not None and (run.project_id != project_id or run.input_type != "reevaluation"):
        raise DecisionLedgerInvariantError("Evaluation run does not match its project envelope.")
    now = get_datetime_utc()
    records: list[tuple[Finding, FindingDecisionEvidenceV2]] = []
    for finding_id, payload in payloads.items():
        item = FindingDecisionEvidenceV2.model_validate(payload)
        finding = session.get(Finding, finding_id)
        if finding is None or (
            finding.project_id != project_id
            or item.project_id != str(project_id)
            or item.finding_id != str(finding_id)
            or item.cve_id != finding.cve_id
            or item.dedup_key != finding.dedup_key
        ):
            raise DecisionLedgerInvariantError("Evaluation changed finding persistence identity.")
        records.append((finding, item))

    snapshots = {item.provider.provider_snapshot_id for _, item in records}
    only_snapshot = next(iter(snapshots)) if len(snapshots) == 1 else None
    snapshot_id = uuid.UUID(only_snapshot) if only_snapshot is not None else None
    run = run or RunRepository(session).create_analysis_run(
        project_id=project_id,
        input_type="reevaluation",
        status=AnalysisRunStatus.RUNNING,
        provider_snapshot_id=snapshot_id,
    )
    run.provider_snapshot_id = snapshot_id
    items: list[FindingDecisionEvidenceV2] = []
    for finding, item in records:
        inputs = item.evaluation_input
        metadata = EvaluationMetadataV1(
            cause=cause,
            evaluated_at=now.isoformat(),
            observed_at=finding.last_seen_at.isoformat(),
            engine_version=inputs.engine_version
            if inputs is not None
            else EVALUATION_ENGINE_VERSION,
            input_sha256=inputs.fingerprint() if inputs is not None else None,
            base_project_revision=base_project_revision,
            replay_status="available" if inputs is not None else "legacy_unavailable",
        )
        items.append(
            item.model_copy(update={"analysis_run_id": str(run.id), "evaluation": metadata})
        )
        finding.status = FindingStatus(item.status)
        finding.updated_at = now
        session.add(finding)

    provider = (
        items[0].provider.model_copy(
            update={"provider_evidence": {}, "provider_data_quality_flags": {}}
        )
        if len(snapshots) == 1
        else ProviderEvidenceV2()
    )
    provider = provider.model_copy(
        update={
            "provider_degraded": any(item.provider.provider_degraded for item in items),
            "nvd_hits": sum(item.cvss_base_score is not None for item in items),
            "epss_hits": sum(item.epss is not None for item in items),
            "kev_hits": sum(item.in_kev for item in items),
        }
    )
    fingerprints = {
        item.finding_id: item.evaluation.input_sha256 for item in items if item.evaluation
    }
    run_metadata = EvaluationMetadataV1(
        cause=cause,
        evaluated_at=now.isoformat(),
        engine_version=EVALUATION_ENGINE_VERSION,
        input_sha256=canonical_payload_sha256(fingerprints),
        base_project_revision=base_project_revision,
        replay_status="available"
        if all(item.evaluation_input is not None for item in items)
        else "legacy_unavailable",
    )
    evidence = AnalysisEvidenceV2(
        analysis_run_id=str(run.id),
        project_id=str(project_id),
        input_type="reevaluation",
        status=AnalysisRunStatus.COMPLETED.value,
        counts=RunCountsV2(
            updated_findings=len(items),
            finding_count=len(items),
            counts_by_priority=dict(Counter(item.priority for item in items)),
            kev_hits=sum(item.in_kev for item in items),
            suppressed_by_vex=sum(item.suppressed_by_vex for item in items),
            attack_mapped_cves=len({item.cve_id for item in items if item.attack_mapped}),
        ),
        provider=provider,
        analysis_service=AnalysisServiceEvidenceV2(
            pipeline="native_reevaluation",
            engine=EVALUATION_ENGINE_VERSION,
            kernel="decision-core.v2",
        ),
        analysis_semantics=AnalysisSemanticsV2(
            analysis_decision_scope="finding_scope_first",
            persistence_scope="evaluation_revision",
            finding_dedup_key_version=FINDING_SCOPE_KEY_VERSION,
            cve_count=len({item.cve_id for item in items}),
            finding_count=len(items),
        ),
        evaluation=run_metadata,
    )
    repository = EvidenceRepository(session)
    envelope = repository.upsert_analysis_evidence(
        project_id=project_id,
        analysis_run_id=run.id,
        provider_snapshot_id=snapshot_id,
        evidence=evidence,
    )
    repository.replace_finding_decision_evidence(
        analysis_evidence_id=envelope.id,
        project_id=project_id,
        analysis_run_id=run.id,
        evidence_items=items,
    )
    run.status = AnalysisRunStatus.COMPLETED
    run.finished_at = now
    run.error_message = None
    run.risk_index = project_risk_index_from_projection(session, project_id)
    session.add(run)
    session.flush()
    return run
