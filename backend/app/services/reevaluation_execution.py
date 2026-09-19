"""Offline native evaluation of existing observation scopes with fenced publication."""

from __future__ import annotations

import hashlib
import json
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from app.core.config import Settings
from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.decision_core.evaluation import ScopeEvaluationInput
from app.decision_core.projection_evaluation import (
    _apply_recomputed_decision,
    _projection_scope_sort_key,
    _recompute_projection_decision,
    _stored_projection_decision,
    evaluate_evidence_payload,
)
from app.domain.engine.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderDataQualityFlag,
    ProviderEvidence,
    ProviderSnapshotItem,
    ProviderSnapshotReport,
)
from app.domain.engine.provider_snapshot import _validate_explicit_provider_snapshot_v1
from app.domain.engine.services.decision_guidance import DecisionGuidanceService
from app.domain.engine.services.prioritization_ranking import global_operational_sort_key
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    ProviderSnapshot,
    Waiver,
    WorkflowRun,
)
from app.models.base import get_datetime_utc
from app.models.evaluations import EvaluationCreate
from app.repositories import EvidenceRepository, WorkflowRepository
from app.repositories.assets import _clear_decision_evidence_rescore_needed
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.repositories.waivers import (
    _apply_effective_waiver,
    _restore_source_waiver_state,
    _selected_waiver,
    _waiver_selection_sort_key,
)
from app.services.decision_scope_lock import lock_project_decision_scope, project_decision_revision
from app.services.evaluation_publication import publish_evaluation_run
from app.services.workflow_execution import WorkflowExecutionContext


class ReevaluationConflict(ValueError):
    """Requested evidence cannot honestly be replayed or adopted."""


def project_evaluation_inputs(
    session: Session,
    project_id: uuid.UUID,
    finding_ids: list[uuid.UUID] | None,
) -> tuple[dict[uuid.UUID, FindingDecisionEvidenceV2], set[uuid.UUID]]:
    """Read canonical current scopes and reject missing/legacy requested findings."""
    ids = list(session.exec(select(Finding.id).where(Finding.project_id == project_id)).all())
    selected = set(ids if finding_ids is None else finding_ids)
    if not selected:
        raise ReevaluationConflict("No existing findings are available for reevaluation.")
    if not selected.issubset(ids):
        raise ReevaluationConflict("Every selected finding must belong to this project.")
    current = FindingCurrentProjectionRepository(session).evidence_for_findings(ids)
    if any(value not in current or current[value].evaluation_input is None for value in selected):
        raise ReevaluationConflict(
            "legacy_unavailable: selected evidence has no canonical evaluation inputs; "
            "reimport its source first."
        )
    return current, selected


def load_verified_snapshot(
    snapshot: ProviderSnapshot, settings: Settings
) -> ProviderSnapshotReport:
    """Parse exactly the bytes bound by the stored snapshot digest, without providers."""
    metadata = snapshot.source_metadata_json
    value = (
        metadata.get("snapshot_file") or metadata.get("source_path") or metadata.get("output_path")
    )
    if not isinstance(value, str) or not value or value == "[REDACTED]":
        raise ReevaluationConflict("Provider snapshot has no reusable artifact.")
    root = settings.provider_snapshot_dir_path.resolve()
    bundled = Path(__file__).resolve().parents[1] / "resources" / "demo_provider_snapshot.json"
    path = Path(value)
    candidate = (path if path.is_absolute() else root / path).resolve()
    if candidate != bundled.resolve() and not candidate.is_relative_to(root):
        raise ReevaluationConflict(
            "Provider snapshot artifact is outside the managed snapshot directory."
        )
    try:
        document = candidate.read_bytes()
        if (
            not snapshot.content_hash
            or hashlib.sha256(document).hexdigest() != snapshot.content_hash
        ):
            raise ReevaluationConflict(
                "Provider snapshot content hash does not match its recorded artifact."
            )
        payload = json.loads(document)
        _validate_explicit_provider_snapshot_v1(payload, path=Path("provider-snapshot.json"))
        report = ProviderSnapshotReport.model_validate(payload)
    except (OSError, ValueError) as exc:
        raise ReevaluationConflict(f"Provider snapshot cannot be adopted: {exc}") from exc
    if len({item.cve_id for item in report.items}) != len(report.items):
        raise ReevaluationConflict("Provider snapshot contains duplicate CVE identities.")
    if any(
        fact is not None and fact.cve_id != item.cve_id
        for item in report.items
        for fact in (item.nvd, item.epss, item.kev)
    ):
        raise ReevaluationConflict("Provider snapshot contains mismatched CVE evidence.")
    return report


def _adopt_snapshot(
    inputs: ScopeEvaluationInput,
    report: ProviderSnapshotReport,
    items_by_cve: dict[str, ProviderSnapshotItem],
) -> ScopeEvaluationInput:
    item = items_by_cve.get(inputs.cve_id)
    sources = set(report.metadata.selected_sources)
    nvd = item.nvd if item is not None and "nvd" in sources else None
    epss = item.epss if item is not None and "epss" in sources else None
    kev = item.kev if item is not None and "kev" in sources else None
    flags = [
        flag
        for flag in inputs.data_quality_flags
        if flag.source not in {"nvd", "epss", "kev", "provider_snapshot"}
    ]
    for source, missing in (
        ("nvd", nvd is None or nvd.cvss_base_score is None),
        ("epss", epss is None or epss.epss is None),
        ("kev", kev is None),
    ):
        if missing:
            flags.append(
                ProviderDataQualityFlag(
                    source=source,
                    code=f"{source}_missing",
                    cve_id=inputs.cve_id,
                    message=f"Snapshot lacks usable {source.upper()} evidence for this finding.",
                )
            )
    flags.append(
        ProviderDataQualityFlag(
            source="provider_snapshot",
            code="snapshot_locked",
            severity="info",
            message="Evaluation uses a content-verified immutable provider snapshot.",
        )
    )
    return inputs.model_copy(
        update={
            "provider_evidence": ProviderEvidence(
                nvd=nvd or NvdData(cve_id=inputs.cve_id),
                epss=epss or EpssData(cve_id=inputs.cve_id),
                kev=kev or KevData(cve_id=inputs.cve_id),
                defensive_contexts=inputs.defensive_contexts,
            ),
            "data_quality_flags": flags,
            "data_quality_confidence": "low"
            if any(flag.severity == "error" for flag in flags)
            else "medium"
            if any(flag.code != "snapshot_locked" for flag in flags)
            else "high",
        }
    )


def ranked_evaluation_payloads(
    current: dict[uuid.UUID, FindingDecisionEvidenceV2],
    evaluated: dict[uuid.UUID, dict[str, Any]],
) -> dict[uuid.UUID, dict[str, Any]]:
    """Rank the project once; include selected decisions and changed peer ranks."""
    candidates = []
    for finding_id, previous in current.items():
        evidence = FindingDecisionEvidenceV2.model_validate(
            evaluated.get(finding_id, previous.to_jsonable())
        )
        decision = (
            _stored_projection_decision(evidence)
            if evidence.evaluation_input is not None
            else _recompute_projection_decision(evidence.to_jsonable())
        )
        candidates.append(
            (
                global_operational_sort_key(decision, _projection_scope_sort_key(evidence)),
                finding_id,
                evidence,
                decision,
            )
        )
    candidates.sort(key=lambda item: (*item[0], str(item[1])))
    result = dict(evaluated)
    guidance = DecisionGuidanceService()
    for rank, (_, finding_id, evidence, decision) in enumerate(candidates, 1):
        if finding_id not in evaluated and rank == evidence.operational_rank:
            continue
        decision = decision.model_copy(update={"operational_rank": rank})
        ranked_guidance = guidance.build(decision)
        if finding_id not in evaluated:
            # A peer's rank changing is not authorization to recompute its stored
            # decision from incomplete legacy inputs or stale relational context.
            payload = evidence.to_jsonable()
            payload["operational_rank"] = rank
            if "operational_rank" in payload["priority_evidence"]["raw"]:
                payload["priority_evidence"]["raw"]["operational_rank"] = rank
            payload["priority_evidence"]["raw"]["decision_guidance"] = ranked_guidance.model_dump(
                mode="json"
            )
            payload["remediation"].update(
                {
                    "decision_statement": ranked_guidance.decision_statement,
                    "recommendation": ranked_guidance.recommendation,
                    "recommendation_label": ranked_guidance.recommendation_label,
                    "business_impact": ranked_guidance.business_impact.text,
                    "sla": ranked_guidance.sla.model_dump(mode="json"),
                    "raw": ranked_guidance.model_dump(mode="json"),
                }
            )
            result[finding_id] = payload
            continue
        decision = decision.model_copy(update={"decision_guidance": ranked_guidance})
        result[finding_id] = _apply_recomputed_decision(evidence.to_jsonable(), decision)
    return result


def _fresh_scope_payloads(
    session: Session,
    project_id: uuid.UUID,
    current: dict[uuid.UUID, FindingDecisionEvidenceV2],
    selected: set[uuid.UUID],
) -> dict[uuid.UUID, dict[str, Any]]:
    """Capture mutable context as explicit inputs before ending the read transaction."""
    now = get_datetime_utc()
    waivers = sorted(
        session.exec(select(Waiver).where(Waiver.project_id == project_id)).all(),
        key=lambda waiver: _waiver_selection_sort_key(waiver, today=now.date()),
    )
    result = {}
    for finding_id in selected:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        evidence = current[finding_id]
        assert evidence.evaluation_input is not None
        payload = _restore_source_waiver_state(evidence.to_jsonable(), source_evidence=evidence)
        asset = finding.asset
        if asset is not None:
            payload, _ = _clear_decision_evidence_rescore_needed(
                payload, asset=asset, recalculated_at=now
            )
        payload = _apply_effective_waiver(
            payload, _selected_waiver(waivers, finding), today=now.date()
        )
        result[finding_id] = payload
    return result


def execute_reevaluation_workflow(
    session: Session,
    *,
    settings: Settings,
    workflow: WorkflowRun,
    context: WorkflowExecutionContext | None = None,
) -> None:
    """Compute from recorded inputs, then atomically append a fenced revision."""
    context = context or WorkflowExecutionContext.for_workflow(
        WorkflowRepository(session), workflow.id
    )
    run = session.get(AnalysisRun, workflow.analysis_run_id)
    if run is None or run.input_type != "reevaluation" or run.project_id != workflow.project_id:
        raise ReevaluationConflict("Reevaluation workflow has no matching analysis run.")
    run_id, project_id = run.id, run.project_id
    request = EvaluationCreate.model_validate(workflow.payload_json)
    run.status = AnalysisRunStatus.RUNNING
    session.add(run)
    context.start(stage="evaluate", message="Evaluating existing observation scopes.")
    context.begin_compute()
    revision = project_decision_revision(session, project_id)
    current, selected = project_evaluation_inputs(session, project_id, request.finding_ids)
    fresh = _fresh_scope_payloads(session, project_id, current, selected)
    snapshot = (
        session.get(ProviderSnapshot, request.provider_snapshot_id)
        if request.provider_snapshot_id
        else None
    )
    if request.provider_snapshot_id and snapshot is None:
        raise ReevaluationConflict("Provider snapshot is no longer available.")
    snapshot_id = snapshot.id if snapshot is not None else None
    snapshot_hash = snapshot.content_hash if snapshot is not None else None
    report = load_verified_snapshot(snapshot, settings) if snapshot is not None else None
    snapshot_items = {item.cve_id: item for item in report.items} if report else {}
    context.checkpoint()
    evaluated: dict[uuid.UUID, dict[str, Any]] = {}
    today = get_datetime_utc().date()
    for index, finding_id in enumerate(sorted(selected, key=str), 1):
        evidence = FindingDecisionEvidenceV2.model_validate(fresh[finding_id])
        assert evidence.evaluation_input is not None
        inputs = evidence.evaluation_input.model_copy(update={"evaluation_date": today})
        if report is not None:
            inputs = _adopt_snapshot(inputs, report, snapshot_items)
        payload, _ = evaluate_evidence_payload(evidence.to_jsonable(), inputs=inputs)
        if snapshot_id is not None:
            provider = deepcopy(payload["provider"])
            provider.update(
                {
                    "provider_snapshot_id": str(snapshot_id),
                    "provider_snapshot_hash": snapshot_hash,
                    "provider_snapshot_file": None,
                    "locked_provider_data": True,
                    "provider_degraded": inputs.data_quality_confidence != "high",
                    "provider_data_quality_flags": {},
                }
            )
            for flag in inputs.data_quality_flags:
                provider["provider_data_quality_flags"].setdefault(flag.source, []).append(
                    flag.model_dump(mode="json")
                )
            payload["provider"] = provider
        evaluated[finding_id] = payload
        if index % 100 == 0:
            context.progress(
                stage="evaluate",
                message="Evaluating recorded inputs.",
                progress_current=index,
                progress_total=len(selected),
            )
    payloads = ranked_evaluation_payloads(current, evaluated)
    context.begin_publication()
    lock_project_decision_scope(session, project_id, expected_revision=revision)
    run = session.get(AnalysisRun, run_id)
    assert run is not None
    publish_evaluation_run(
        session,
        project_id=project_id,
        payloads=payloads,
        cause="provider_snapshot" if snapshot_id is not None else "manual",
        run=run,
        base_project_revision=revision,
    )
    envelope = EvidenceRepository(session).get_analysis_evidence_record(run.id)
    assert envelope is not None
    context.succeed(
        message="Decision revisions published.",
        result={
            "schema_version": "workflow-result-ref.v2",
            "analysis_evidence_id": str(envelope.id),
            "artifact_refs": [],
        },
        details={"selected_findings": len(selected), "published_findings": len(payloads)},
    )
    session.commit()
