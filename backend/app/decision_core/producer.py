"""Typed Decision/Evidence Kernel for successful Workbench imports."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.decision_core.builders import workflow_ref_payload
from app.decision_core.contracts import (
    AnalysisEvidenceUploadsV2,
    AnalysisEvidenceV2,
    AnalysisSemanticsV2,
    AnalysisServiceEvidenceV2,
    AttackEvidenceV2,
    DedupSummaryV2,
    EvidenceUploadRef,
    FindingDecisionEvidenceV2,
    ProviderDataQualityFlagEvidenceV2,
    ProviderEvidenceV2,
    RunCountsV2,
    WorkflowArtifactRefV2,
    WorkflowResultRefV2,
)
from app.models import AnalysisRun

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")


class _DecisionUploadPayload(Protocol):  # pragma: no cover
    """Upload payload shape consumed by the decision core."""

    @property
    def content_type(self) -> str | None:
        raise NotImplementedError


class _DecisionSidecarUpload(Protocol):  # pragma: no cover
    """Sidecar upload shape consumed by the decision core."""

    @property
    def payload(self) -> _DecisionUploadPayload | None:
        raise NotImplementedError

    @property
    def original_filename(self) -> str | None:
        raise NotImplementedError

    @property
    def stored_filename(self) -> str | None:
        raise NotImplementedError

    @property
    def content(self) -> bytes | None:
        raise NotImplementedError

    @property
    def sha256(self) -> str | None:
        raise NotImplementedError

    @property
    def summary_input_type(self) -> str:
        raise NotImplementedError


class _DecisionPreparedImportUpload(Protocol):  # pragma: no cover
    """Prepared import upload shape consumed by the decision core."""

    @property
    def input_type(self) -> str:
        raise NotImplementedError

    @property
    def file(self) -> _DecisionUploadPayload:
        raise NotImplementedError

    @property
    def original_filename(self) -> str:
        raise NotImplementedError

    @property
    def stored_filename(self) -> str:
        raise NotImplementedError

    @property
    def upload_bytes(self) -> bytes:
        raise NotImplementedError

    @property
    def upload_sha256(self) -> str:
        raise NotImplementedError

    @property
    def asset_context(self) -> _DecisionSidecarUpload:
        raise NotImplementedError

    @property
    def vex(self) -> _DecisionSidecarUpload:
        raise NotImplementedError


class _DecisionStoredImportArtifacts(Protocol):  # pragma: no cover
    """Stored import artifact refs consumed by the decision core."""

    @property
    def upload_ref(self) -> str:
        raise NotImplementedError

    @property
    def asset_context_ref(self) -> str | None:
        raise NotImplementedError

    @property
    def vex_ref(self) -> str | None:
        raise NotImplementedError


class _DecisionAnalysisContext(Protocol):  # pragma: no cover
    """Analysis context shape consumed by the decision core."""

    @property
    def counts_by_priority(self) -> dict[str, int]:
        raise NotImplementedError

    @property
    def kev_hits(self) -> int:
        raise NotImplementedError

    @property
    def epss_hits(self) -> int:
        raise NotImplementedError

    @property
    def nvd_hits(self) -> int:
        raise NotImplementedError

    @property
    def suppressed_by_vex(self) -> int:
        raise NotImplementedError

    @property
    def under_investigation_count(self) -> int:
        raise NotImplementedError

    @property
    def vex_conflict_count(self) -> int:
        raise NotImplementedError

    @property
    def attack_hits(self) -> int:
        raise NotImplementedError

    @property
    def provider_degraded(self) -> bool:
        raise NotImplementedError

    @property
    def provider_data_quality_flags(self) -> dict[str, list[Any]]:
        raise NotImplementedError

    @property
    def warnings(self) -> list[str]:
        raise NotImplementedError

    @property
    def attack_source(self) -> Any:
        raise NotImplementedError


class _DecisionAnalysisResult(Protocol):  # pragma: no cover
    """Analysis result shape consumed by the decision core."""

    @property
    def context(self) -> _DecisionAnalysisContext:
        raise NotImplementedError

    @property
    def provider_snapshot_id(self) -> uuid.UUID | None:
        raise NotImplementedError

    @property
    def provider_snapshot_hash(self) -> str | None:
        raise NotImplementedError

    @property
    def provider_snapshot_file(self) -> str | None:
        raise NotImplementedError

    @property
    def locked_provider_data(self) -> bool:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class DecisionSummaryCounts:
    """Stable counters produced by one persisted decision run."""

    created_findings: int
    updated_findings: int
    ignored_lines: int
    rows_read: int
    occurrence_count: int
    finding_count: int
    counts_by_priority: dict[str, int]
    kev_hits: int
    epss_hits: int
    nvd_hits: int
    suppressed_by_vex: int
    under_investigation_count: int
    vex_conflict_count: int
    attack_mapped_cves: int

    def to_contract(self) -> RunCountsV2:
        """Return the public v2 run-count contract."""
        return RunCountsV2(
            created_findings=self.created_findings,
            updated_findings=self.updated_findings,
            ignored_lines=self.ignored_lines,
            rows_read=self.rows_read,
            occurrence_count=self.occurrence_count,
            finding_count=self.finding_count,
            counts_by_priority=dict(self.counts_by_priority),
            kev_hits=self.kev_hits,
            epss_hits=self.epss_hits,
            nvd_hits=self.nvd_hits,
            suppressed_by_vex=self.suppressed_by_vex,
            under_investigation_count=self.under_investigation_count,
            vex_conflict_count=self.vex_conflict_count,
            attack_mapped_cves=self.attack_mapped_cves,
        )

    def to_workflow_details(self) -> dict[str, int]:
        """Return small workflow event metadata, not semantic result state."""
        return {
            "finding_count": self.finding_count,
            "occurrence_count": self.occurrence_count,
            "created_findings": self.created_findings,
            "updated_findings": self.updated_findings,
        }


@dataclass(frozen=True, slots=True)
class DecisionPersistencePlan:
    """Typed summary of records persisted for one decision run."""

    analysis_evidence_id: uuid.UUID
    counts: DecisionSummaryCounts
    analysis_semantics: AnalysisSemanticsV2
    dedup_summary: DedupSummaryV2
    finding_evidence: list[FindingDecisionEvidenceV2]

    @classmethod
    def from_summary(
        cls,
        *,
        analysis_evidence_id: uuid.UUID,
        ignored_lines: int,
        analysis_result: _DecisionAnalysisResult,
        summary: dict[str, Any],
    ) -> DecisionPersistencePlan:
        """Validate and type the persistence summary produced by repositories."""
        finding_evidence = [
            item
            if isinstance(item, FindingDecisionEvidenceV2)
            else FindingDecisionEvidenceV2.model_validate(item)
            for item in _list_value(summary.get("finding_evidence"))
        ]
        counts = DecisionSummaryCounts(
            created_findings=_int_value(summary.get("created_findings")),
            updated_findings=_int_value(summary.get("updated_findings")),
            ignored_lines=ignored_lines,
            rows_read=_int_value(summary.get("rows_read")),
            occurrence_count=_int_value(summary.get("occurrence_count")),
            finding_count=_int_value(summary.get("finding_count")),
            counts_by_priority=_counts_by_priority(analysis_result.context.counts_by_priority),
            kev_hits=int(analysis_result.context.kev_hits),
            epss_hits=int(analysis_result.context.epss_hits),
            nvd_hits=int(analysis_result.context.nvd_hits),
            suppressed_by_vex=int(analysis_result.context.suppressed_by_vex),
            under_investigation_count=int(analysis_result.context.under_investigation_count),
            vex_conflict_count=int(analysis_result.context.vex_conflict_count),
            attack_mapped_cves=int(analysis_result.context.attack_hits),
        )
        return cls(
            analysis_evidence_id=analysis_evidence_id,
            counts=counts,
            analysis_semantics=AnalysisSemanticsV2.model_validate(
                _dict_value(summary.get("analysis_semantics"))
            ),
            dedup_summary=DedupSummaryV2.model_validate(_dict_value(summary.get("dedup_summary"))),
            finding_evidence=finding_evidence,
        )


@dataclass(frozen=True, slots=True)
class DecisionKernelInput:
    """Typed input needed to produce the run-wide evidence graph."""

    project_id: uuid.UUID
    run: AnalysisRun
    prepared: _DecisionPreparedImportUpload
    artifacts: _DecisionStoredImportArtifacts
    analysis_result: _DecisionAnalysisResult
    asset_context_summary: dict[str, Any] | None = None
    vex_summary: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DecisionRunResult:
    """Single typed output for a successful decision run."""

    analysis_evidence: AnalysisEvidenceV2
    finding_evidence: list[FindingDecisionEvidenceV2]
    summary_counts: DecisionSummaryCounts
    workflow_result: WorkflowResultRefV2
    workflow_details: dict[str, int]
    artifact_refs: list[WorkflowArtifactRefV2]


def build_run_result(
    *,
    kernel_input: DecisionKernelInput,
    persistence_plan: DecisionPersistencePlan,
) -> DecisionRunResult:
    """Build the v2 evidence source of truth for a successful import."""
    analysis_result = kernel_input.analysis_result
    counts = persistence_plan.counts
    evidence = AnalysisEvidenceV2(
        analysis_evidence_id=str(persistence_plan.analysis_evidence_id),
        analysis_run_id=str(kernel_input.run.id),
        project_id=str(kernel_input.project_id),
        input_type=kernel_input.run.input_type,
        filename=kernel_input.run.filename,
        status=str(kernel_input.run.status),
        input_sha256=kernel_input.prepared.upload_sha256,
        counts=counts.to_contract(),
        uploads=_uploads(kernel_input.prepared, kernel_input.artifacts),
        provider=ProviderEvidenceV2(
            provider_snapshot_id=str(analysis_result.provider_snapshot_id)
            if analysis_result.provider_snapshot_id is not None
            else None,
            provider_snapshot_hash=analysis_result.provider_snapshot_hash,
            provider_snapshot_file=_public_path_label(analysis_result.provider_snapshot_file),
            locked_provider_data=analysis_result.locked_provider_data,
            provider_degraded=bool(analysis_result.context.provider_degraded),
            provider_data_quality_flags=_provider_quality_flags(
                analysis_result.context.provider_data_quality_flags
            ),
            kev_hits=counts.kev_hits,
            epss_hits=counts.epss_hits,
            nvd_hits=counts.nvd_hits,
        ),
        warnings=list(analysis_result.context.warnings),
        parse_errors=[],
        analysis_service=AnalysisServiceEvidenceV2(
            pipeline="parse-persist-enrich-score-explain",
            engine="app.domain.engine.prepare_analysis",
            kernel="app.decision_core.producer",
        ),
        analysis_semantics=persistence_plan.analysis_semantics,
        asset_context=_dict_or_none(kernel_input.asset_context_summary),
        vex=_dict_or_none(kernel_input.vex_summary),
        dedup_summary=persistence_plan.dedup_summary,
        attack=AttackEvidenceV2(
            mapped=counts.attack_mapped_cves > 0,
            source=str(analysis_result.context.attack_source or "none"),
            technique_ids=_finding_technique_ids(persistence_plan.finding_evidence),
        ),
    )
    artifact_refs: list[WorkflowArtifactRefV2] = []
    return DecisionRunResult(
        analysis_evidence=evidence,
        finding_evidence=list(persistence_plan.finding_evidence),
        summary_counts=counts,
        workflow_result=workflow_ref_payload(
            analysis_evidence_id=persistence_plan.analysis_evidence_id,
            artifact_refs=artifact_refs,
        ),
        workflow_details=counts.to_workflow_details(),
        artifact_refs=artifact_refs,
    )


def _uploads(
    prepared: _DecisionPreparedImportUpload,
    artifacts: _DecisionStoredImportArtifacts,
) -> AnalysisEvidenceUploadsV2:
    return AnalysisEvidenceUploadsV2(
        input=EvidenceUploadRef(
            input_type=prepared.input_type,
            original_filename=prepared.original_filename,
            stored_filename=prepared.stored_filename,
            content_type=prepared.file.content_type,
            size_bytes=len(prepared.upload_bytes),
            sha256=prepared.upload_sha256,
            path=artifacts.upload_ref,
            storage_ref=artifacts.upload_ref,
        ),
        asset_context=_sidecar_upload_ref(
            input_type=prepared.asset_context.summary_input_type,
            original_filename=prepared.asset_context.original_filename,
            stored_filename=prepared.asset_context.stored_filename,
            content_type=prepared.asset_context.payload.content_type
            if prepared.asset_context.payload is not None
            else None,
            size_bytes=len(prepared.asset_context.content)
            if prepared.asset_context.content is not None
            else None,
            sha256=prepared.asset_context.sha256,
            storage_ref=artifacts.asset_context_ref,
        ),
        vex=_sidecar_upload_ref(
            input_type=prepared.vex.summary_input_type,
            original_filename=prepared.vex.original_filename,
            stored_filename=prepared.vex.stored_filename,
            content_type=prepared.vex.payload.content_type
            if prepared.vex.payload is not None
            else None,
            size_bytes=len(prepared.vex.content) if prepared.vex.content is not None else None,
            sha256=prepared.vex.sha256,
            storage_ref=artifacts.vex_ref,
        ),
    )


def _sidecar_upload_ref(
    *,
    input_type: str,
    original_filename: str | None,
    stored_filename: str | None,
    content_type: str | None,
    size_bytes: int | None,
    sha256: str | None,
    storage_ref: str | None,
) -> EvidenceUploadRef | None:
    if stored_filename is None and storage_ref is None:
        return None
    return EvidenceUploadRef(
        input_type=input_type,
        original_filename=original_filename,
        stored_filename=stored_filename,
        content_type=content_type,
        size_bytes=size_bytes,
        sha256=sha256,
        path=storage_ref,
        storage_ref=storage_ref,
    )


def _finding_technique_ids(items: list[FindingDecisionEvidenceV2]) -> list[str]:
    technique_ids: list[str] = []
    for item in items:
        for technique_id in item.attack.technique_ids:
            if technique_id not in technique_ids:
                technique_ids.append(technique_id)
    return technique_ids


def _counts_by_priority(raw_counts: dict[str, int]) -> dict[str, int]:
    return {label: int(raw_counts.get(label, 0)) for label in PRIORITY_LABELS}


def _provider_quality_flags(
    raw_flags: dict[str, list[Any]],
) -> dict[str, list[ProviderDataQualityFlagEvidenceV2]]:
    def serialize_flag(item: Any) -> ProviderDataQualityFlagEvidenceV2:
        if hasattr(item, "model_dump"):
            dumped = item.model_dump()
            if isinstance(dumped, dict):
                return ProviderDataQualityFlagEvidenceV2.model_validate(dumped)
        if isinstance(item, dict):
            return ProviderDataQualityFlagEvidenceV2.model_validate(item)
        return ProviderDataQualityFlagEvidenceV2(
            source="unknown",
            code="unstructured_provider_flag",
            message=str(item),
            severity="warning",
        )

    return {source: [serialize_flag(item) for item in flags] for source, flags in raw_flags.items()}


def _public_path_label(value: str | Path | None) -> str | None:
    if value is None:
        return None
    return Path(value).name


def _dict_or_none(value: dict[str, Any] | None) -> dict[str, Any] | None:
    return dict(value) if value else None


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _list_value(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0
