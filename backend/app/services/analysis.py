"""Workbench analysis orchestration backed by the core engine."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError
from sqlmodel import Session

from app.core.config import Settings
from app.decision_core.decision_graph import (
    DecisionGraph,
    ScopedFindingDecision,
    SharedCveFacts,
    build_scoped_decision_graph,
)
from app.domain.engine.config import DEFAULT_CACHE_TTL_HOURS
from app.domain.engine.inputs.loader import InputSpec
from app.domain.engine.models import (
    AnalysisContext,
    AttackData,
    EpssData,
    KevData,
    NvdData,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    ProviderEvidence,
)
from app.domain.engine.options import AttackSource, InputFormat, OutputFormat, SortBy
from app.domain.engine.provider_snapshot import load_provider_snapshot
from app.domain.engine.services.analysis import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    load_analysis_waiver_rules,
)
from app.domain.engine.services.analysis_pipeline import EnrichedAnalysis, prepare_enriched_analysis
from app.domain.engine.services.analysis_quality import (
    _finding_data_quality_confidence,
    _finding_data_quality_flags,
)
from app.repositories import RunRepository

DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT = "demo_provider_snapshot.json"
REPO_ROOT = Path(__file__).resolve().parents[3]


class WorkbenchAnalysisError(RuntimeError):
    """Raised when a Workbench import cannot complete decision analysis."""


@dataclass(frozen=True, slots=True)
class WorkbenchAnalysisResult:
    """Decision state produced for a Workbench import before persistence."""

    findings_by_cve: dict[str, PrioritizedFinding]
    context: AnalysisContext
    provider_snapshot_id: uuid.UUID | None
    provider_snapshot_hash: str | None
    provider_snapshot_file: str | None
    locked_provider_data: bool
    decision_graph: DecisionGraph | None = None

    @property
    def scoped_decisions(self) -> Sequence[ScopedFindingDecision]:
        """Return the lazy scope-first decision sequence without full materialization."""
        if self.decision_graph is None:
            return ()
        return self.decision_graph.scoped_decisions


class AnalysisService:
    """Coordinate Workbench import decision analysis through the shared core pipeline."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def analyze_import(
        self,
        *,
        input_path: Path,
        input_type: str,
        asset_context_file: Path | None = None,
        provider_snapshot_file: Path | None = None,
        locked_provider_data: bool = False,
        attack_source: AttackSource | str = AttackSource.none,
        attack_mapping_file: Path | None = None,
        attack_technique_metadata_file: Path | None = None,
        waiver_file: Path | None = None,
        vex_files: list[Path] | None = None,
        parsed_input: ParsedInput | None = None,
        persist_snapshot: bool = True,
    ) -> WorkbenchAnalysisResult:
        """Run parse/enrich/score/explain for one uploaded Workbench import."""
        snapshot_path = provider_snapshot_file or self.default_provider_snapshot_file()
        use_locked_snapshot = locked_provider_data
        normalized_attack_source = AttackSource(attack_source)
        try:
            waiver_rules = load_analysis_waiver_rules(waiver_file)
        except (OSError, ValidationError, ValueError, AnalysisInputError) as exc:
            raise WorkbenchAnalysisError(str(exc)) from exc
        request = AnalysisRequest(
            input_specs=[InputSpec(path=input_path, input_format=InputFormat(input_type).value)],
            parsed_input=parsed_input,
            output=None,
            format=OutputFormat.json,
            provider_snapshot_file=snapshot_path,
            locked_provider_data=use_locked_snapshot,
            no_attack=normalized_attack_source == AttackSource.none,
            attack_source=normalized_attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=None,
            defensive_context_file=None,
            priority_filters=None,
            kev_only=False,
            min_cvss=None,
            min_epss=None,
            sort_by=SortBy.operational,
            policy=PriorityPolicy(),
            policy_profile="default",
            policy_file=None,
            waiver_file=waiver_file,
            asset_context=asset_context_file,
            target_kind="generic",
            target_ref=None,
            vex_files=vex_files or [],
            show_suppressed=True,
            hide_waived=False,
            fail_on_provider_error=False,
            max_cves=None,
            offline_kev_file=None,
            nvd_api_key_env=self.settings.NVD_API_KEY_ENV,
            no_cache=False,
            cache_dir=self.settings.provider_cache_dir_path,
            cache_ttl_hours=DEFAULT_CACHE_TTL_HOURS,
            preloaded_waiver_rules=tuple(waiver_rules),
        )
        try:
            enriched = prepare_enriched_analysis(request)
        except (
            OSError,
            ValidationError,
            ValueError,
            AnalysisInputError,
            AnalysisNoFindingsError,
        ) as exc:
            raise WorkbenchAnalysisError(str(exc)) from exc

        context = enriched.context
        graph_occurrences = list(enriched.inputs.parsed_input.occurrences)
        try:
            decision_graph = build_scoped_decision_graph(
                shared_facts_by_cve=_shared_cve_facts(enriched),
                occurrences=graph_occurrences,
                context=context,
                context_profile=enriched.inputs.context_profile,
                waiver_rules=list(enriched.inputs.waiver_rules),
            )
        except (ValidationError, ValueError) as exc:
            raise WorkbenchAnalysisError(str(exc)) from exc
        context = context.model_copy(
            update={
                "findings_count": decision_graph.decision_count,
                "counts_by_priority": dict(decision_graph.counts_by_priority),
                "suppressed_by_vex": decision_graph.suppressed_by_vex_count,
                "under_investigation_count": decision_graph.under_investigation_count,
                "waived_count": decision_graph.waived_count,
                "waiver_review_due_count": decision_graph.waiver_review_due_count,
                "expired_waiver_count": decision_graph.expired_waiver_count,
                "warnings": _replace_superseded_waiver_warnings(
                    context.warnings,
                    superseded=decision_graph.superseded_waiver_warnings,
                    scoped=decision_graph.waiver_warnings,
                ),
            }
        )
        snapshot_id = (
            self.persist_provider_snapshot(snapshot_path, locked_provider_data=use_locked_snapshot)
            if persist_snapshot
            else None
        )
        return WorkbenchAnalysisResult(
            findings_by_cve={},
            context=context,
            provider_snapshot_id=snapshot_id,
            provider_snapshot_hash=context.provider_snapshot_hash,
            provider_snapshot_file=str(snapshot_path) if snapshot_path is not None else None,
            locked_provider_data=use_locked_snapshot,
            decision_graph=decision_graph,
        )

    def default_provider_snapshot_file(self) -> Path | None:
        """Return the local demo snapshot only when demo replay is explicitly enabled."""
        if not self.settings.DEMO_PROVIDER_SNAPSHOT_ENABLED:
            return None
        candidate = self.settings.provider_snapshot_dir_path / DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT
        if candidate.exists():
            return candidate
        if not self.settings.provider_snapshot_dir_path.is_absolute():
            repo_candidate = (
                REPO_ROOT
                / self.settings.provider_snapshot_dir_path
                / DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT
            )
            return repo_candidate if repo_candidate.exists() else None
        return None

    def persist_provider_snapshot(
        self,
        snapshot_path: Path | None,
        *,
        locked_provider_data: bool,
    ) -> uuid.UUID | None:
        """Persist provider snapshot metadata in the Workbench SQLModel database."""
        if snapshot_path is None:
            return None
        content_hash = _file_sha256(snapshot_path)
        try:
            report = load_provider_snapshot(snapshot_path)
        except ValueError as exc:
            if locked_provider_data:
                raise WorkbenchAnalysisError(str(exc)) from exc
            snapshot = RunRepository(self.session).get_or_create_provider_snapshot(
                content_hash=content_hash,
                source_hashes_json={"provider_snapshot": content_hash},
                source_metadata_json={
                    "source_path": str(snapshot_path),
                    "locked_provider_data": locked_provider_data,
                    "missing": True,
                    "validation_error": str(exc),
                },
            )
            return snapshot.id

        epss_dates = sorted(
            {
                item.epss.date
                for item in report.items
                if item.epss is not None and item.epss.date is not None
            }
        )
        kev_dates = sorted(
            {
                item.kev.date_added
                for item in report.items
                if item.kev is not None and item.kev.date_added is not None
            }
        )
        nvd_dates = sorted(
            {
                item.nvd.last_modified
                for item in report.items
                if item.nvd is not None and item.nvd.last_modified is not None
            }
        )
        metadata_json = report.metadata.model_dump()
        metadata_json.update(
            {
                "source_path": str(snapshot_path),
                "locked_provider_data": locked_provider_data,
                "item_count": len(report.items),
                "warnings": report.warnings,
                "missing": False,
                "selected_sources": list(report.metadata.selected_sources),
            }
        )
        snapshot = RunRepository(self.session).get_or_create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_dates[-1] if nvd_dates else None,
            epss_date=epss_dates[-1] if epss_dates else None,
            kev_catalog_version=kev_dates[-1] if kev_dates else None,
            source_hashes_json={"provider_snapshot": content_hash},
            source_metadata_json=metadata_json,
        )
        return snapshot.id


def _shared_cve_facts(prepared: EnrichedAnalysis) -> dict[str, SharedCveFacts]:
    """Translate provider records into evaluator inputs without preliminary scoring."""
    enrichment = prepared.enrichment
    all_flags = [
        flag for flags in enrichment.provider_data_quality_flags.values() for flag in flags
    ]
    facts: dict[str, SharedCveFacts] = {}
    for cve_id in prepared.inputs.parsed_input.unique_cves:
        flags = _finding_data_quality_flags(cve_id=cve_id, flags=all_flags)
        defensive_contexts = list(enrichment.defensive_contexts.get(cve_id, ()))
        facts[cve_id] = SharedCveFacts(
            cve_id=cve_id,
            provider_evidence=ProviderEvidence(
                nvd=enrichment.nvd.get(cve_id, NvdData(cve_id=cve_id)),
                epss=enrichment.epss.get(cve_id, EpssData(cve_id=cve_id)),
                kev=enrichment.kev.get(cve_id, KevData(cve_id=cve_id, in_kev=False)),
                defensive_contexts=defensive_contexts,
            ),
            attack_data=enrichment.attack.get(cve_id, AttackData(cve_id=cve_id)),
            data_quality_flags=flags,
            data_quality_confidence=_finding_data_quality_confidence(flags),
            defensive_contexts=defensive_contexts,
        )
    return facts


def _replace_superseded_waiver_warnings(
    warnings: Sequence[str],
    *,
    superseded: Sequence[str],
    scoped: Sequence[str],
) -> list[str]:
    """Replace CVE-aggregate waiver diagnostics with scope-accurate diagnostics."""
    superseded_set = set(superseded)
    result = [warning for warning in warnings if warning not in superseded_set]
    for warning in scoped:
        if warning not in result:
            result.append(warning)
    return result


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
