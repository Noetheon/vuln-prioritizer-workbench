"""Workbench analysis orchestration backed by the core engine."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlmodel import Session

from app.core.config import Settings
from app.repositories import RunRepository
from vuln_prioritizer.cli_options import AttackSource, InputFormat, OutputFormat, SortBy
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.inputs.loader import InputSpec
from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.provider_snapshot import load_provider_snapshot
from vuln_prioritizer.security_redaction import redact_value
from vuln_prioritizer.services.analysis import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    prepare_analysis,
)

DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT = "demo_provider_snapshot.json"
PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
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

    @property
    def summary_json(self) -> dict[str, Any]:
        """Return run-summary fields that prove enrichment, scoring, and explanation."""
        summary = {
            "analysis_service": {
                "pipeline": "parse-persist-enrich-score-explain",
                "engine": "vuln_prioritizer.prepare_analysis",
            },
            "provider_snapshot_id": str(self.provider_snapshot_id)
            if self.provider_snapshot_id is not None
            else None,
            "provider_snapshot_hash": self.provider_snapshot_hash,
            "provider_snapshot_file": _public_path_label(self.provider_snapshot_file),
            "locked_provider_data": self.locked_provider_data,
            "findings_count": self.context.findings_count,
            "counts_by_priority": _counts_by_priority(self.context.counts_by_priority),
            "kev_hits": self.context.kev_hits,
            "epss_hits": self.context.epss_hits,
            "nvd_hits": self.context.nvd_hits,
            "provider_degraded": self.context.provider_degraded,
            "attack_enabled": self.context.attack_enabled,
            "attack_source": self.context.attack_source,
            "attack_mapped_cves": self.context.attack_hits,
            "attack_mapping_file": _public_path_label(self.context.attack_mapping_file),
            "attack_mapping_file_sha256": self.context.attack_mapping_file_sha256,
            "attack_technique_metadata_file": _public_path_label(
                self.context.attack_technique_metadata_file
            ),
            "attack_technique_metadata_file_sha256": (
                self.context.attack_technique_metadata_file_sha256
            ),
            "provider_data_quality_flags": _provider_quality_flags(
                self.context.provider_data_quality_flags
            ),
            "warnings": list(self.context.warnings),
            "suppressed_by_vex": self.context.suppressed_by_vex,
            "under_investigation_count": self.context.under_investigation_count,
            "vex_conflict_count": self.context.vex_conflict_count,
        }
        redacted, _paths = redact_value(summary)
        return redacted if isinstance(redacted, dict) else summary


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
        vex_files: list[Path] | None = None,
    ) -> WorkbenchAnalysisResult:
        """Run parse/enrich/score/explain for one uploaded Workbench import."""
        snapshot_path = provider_snapshot_file or self.default_provider_snapshot_file()
        use_locked_snapshot = locked_provider_data or snapshot_path is not None
        normalized_attack_source = AttackSource(attack_source)
        request = AnalysisRequest(
            input_specs=[InputSpec(path=input_path, input_format=InputFormat(input_type).value)],
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
            waiver_file=None,
            asset_context=asset_context_file,
            target_kind="generic",
            target_ref=None,
            vex_files=vex_files or [],
            show_suppressed=True,
            hide_waived=False,
            fail_on_provider_error=False,
            max_cves=None,
            offline_kev_file=None,
            nvd_api_key_env="NVD_API_KEY",
            no_cache=False,
            cache_dir=self.settings.provider_cache_dir_path,
            cache_ttl_hours=DEFAULT_CACHE_TTL_HOURS,
        )
        try:
            findings, context = prepare_analysis(request)
        except (
            OSError,
            ValidationError,
            ValueError,
            AnalysisInputError,
            AnalysisNoFindingsError,
        ) as exc:
            raise WorkbenchAnalysisError(str(exc)) from exc

        findings_by_cve = {finding.cve_id: finding for finding in findings}
        if len(findings_by_cve) != len(findings):
            raise WorkbenchAnalysisError("Decision analysis produced duplicate CVE keys.")
        snapshot_id = self.persist_provider_snapshot(
            snapshot_path,
            locked_provider_data=use_locked_snapshot,
        )
        return WorkbenchAnalysisResult(
            findings_by_cve=findings_by_cve,
            context=context,
            provider_snapshot_id=snapshot_id,
            provider_snapshot_hash=context.provider_snapshot_hash,
            provider_snapshot_file=str(snapshot_path) if snapshot_path is not None else None,
            locked_provider_data=use_locked_snapshot,
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
                "selected_sources": ["nvd", "epss", "kev"],
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


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _public_path_label(value: str | Path | None) -> str | None:
    if value is None:
        return None
    return Path(value).name


def _counts_by_priority(raw_counts: dict[str, int]) -> dict[str, int]:
    return {label: int(raw_counts.get(label, 0)) for label in PRIORITY_LABELS}


def _provider_quality_flags(raw_flags: dict[str, list[Any]]) -> dict[str, list[dict[str, Any]]]:
    def _serialize_flag(item: Any) -> dict[str, Any]:
        if hasattr(item, "model_dump"):
            dumped = item.model_dump()
            return dict(dumped) if isinstance(dumped, dict) else {"value": dumped}
        if isinstance(item, dict):
            return dict(item)
        return {"value": item}

    return {
        source: [_serialize_flag(item) for item in flags] for source, flags in raw_flags.items()
    }


# Compatibility aliases retained for older local tests or scripts that imported
# template-era names before the runtime was fully Workbench-branded.
DEFAULT_TEMPLATE_PROVIDER_SNAPSHOT = DEFAULT_WORKBENCH_PROVIDER_SNAPSHOT
TemplateAnalysisError = WorkbenchAnalysisError
TemplateAnalysisResult = WorkbenchAnalysisResult
